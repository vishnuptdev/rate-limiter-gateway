package admin

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"ratelimitergateway/internal/model"
)

// ref names an object that references another (for 409 responses).
type ref struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// kind describes one config collection for the generic CRUD handlers.
type kind[T any] struct {
	singular, plural string
	items            func(*model.Snapshot) *[]T
	id               func(*T) string
	name             func(*T) string
	setID            func(*T, string)
	stamp            func(t *T, created, updated time.Time)
	created          func(*T) time.Time
	// prepare normalises a client-supplied object; old is nil on create.
	prepare func(nu *T, old *T)
	// referrers lists objects that would dangle if id were deleted.
	referrers func(s *model.Snapshot, id string) []ref
}

var policyKind = kind[model.Policy]{
	singular: "policy", plural: "policies",
	items:   func(s *model.Snapshot) *[]model.Policy { return &s.Policies },
	id:      func(p *model.Policy) string { return p.ID },
	name:    func(p *model.Policy) string { return p.Name },
	setID:   func(p *model.Policy, id string) { p.ID = id },
	stamp:   func(p *model.Policy, c, u time.Time) { p.CreatedAt, p.UpdatedAt = c, u },
	created: func(p *model.Policy) time.Time { return p.CreatedAt },
	prepare: func(p, _ *model.Policy) {
		if p.KeyBy == nil {
			p.KeyBy = []string{}
		}
	},
	referrers: func(s *model.Snapshot, id string) []ref {
		var out []ref
		if slices.Contains(s.Settings.GlobalPolicyIDs, id) {
			out = append(out, ref{Type: "settings", ID: "global_policy_ids"})
		}
		for _, r := range s.Routes {
			if slices.Contains(r.PolicyIDs, id) {
				out = append(out, ref{"route", r.ID, r.Name})
			}
		}
		for _, p := range s.Plans {
			if _, ok := p.Overrides[id]; ok {
				out = append(out, ref{"plan", p.ID, p.Name})
			}
		}
		for _, c := range s.Consumers {
			if _, ok := c.Overrides[id]; ok {
				out = append(out, ref{"consumer", c.ID, c.Name})
			}
		}
		return out
	},
}

var routeKind = kind[model.Route]{
	singular: "route", plural: "routes",
	items:   func(s *model.Snapshot) *[]model.Route { return &s.Routes },
	id:      func(r *model.Route) string { return r.ID },
	name:    func(r *model.Route) string { return r.Name },
	setID:   func(r *model.Route, id string) { r.ID = id },
	stamp:   func(r *model.Route, c, u time.Time) { r.CreatedAt, r.UpdatedAt = c, u },
	created: func(r *model.Route) time.Time { return r.CreatedAt },
	prepare: func(r, _ *model.Route) {
		if r.PolicyIDs == nil {
			r.PolicyIDs = []string{}
		}
	},
	referrers: func(*model.Snapshot, string) []ref { return nil },
}

var planKind = kind[model.Plan]{
	singular: "plan", plural: "plans",
	items:   func(s *model.Snapshot) *[]model.Plan { return &s.Plans },
	id:      func(p *model.Plan) string { return p.ID },
	name:    func(p *model.Plan) string { return p.Name },
	setID:   func(p *model.Plan, id string) { p.ID = id },
	stamp:   func(p *model.Plan, c, u time.Time) { p.CreatedAt, p.UpdatedAt = c, u },
	created: func(p *model.Plan) time.Time { return p.CreatedAt },
	prepare: func(p, _ *model.Plan) {
		if p.Overrides == nil {
			p.Overrides = map[string]model.LimitOverride{}
		}
	},
	referrers: func(s *model.Snapshot, id string) []ref {
		var out []ref
		for _, c := range s.Consumers {
			if c.PlanID == id {
				out = append(out, ref{"consumer", c.ID, c.Name})
			}
		}
		return out
	},
}

var consumerKind = kind[model.Consumer]{
	singular: "consumer", plural: "consumers",
	items:   func(s *model.Snapshot) *[]model.Consumer { return &s.Consumers },
	id:      func(c *model.Consumer) string { return c.ID },
	name:    func(c *model.Consumer) string { return c.Name },
	setID:   func(c *model.Consumer, id string) { c.ID = id },
	stamp:   func(c *model.Consumer, cr, u time.Time) { c.CreatedAt, c.UpdatedAt = cr, u },
	created: func(c *model.Consumer) time.Time { return c.CreatedAt },
	// Keys are managed only via the key endpoints: client-supplied keys are
	// discarded on create and the stored keys are preserved on update.
	prepare: func(c, old *model.Consumer) {
		if old == nil {
			c.Keys = []model.APIKey{}
		} else {
			c.Keys = old.Keys
		}
	},
	referrers: func(*model.Snapshot, string) []ref { return nil },
}

func find[T any](k kind[T], s *model.Snapshot, id string) int {
	items := *k.items(s)
	for i := range items {
		if k.id(&items[i]) == id {
			return i
		}
	}
	return -1
}

func registerCRUD[T any](s *Server, mux *http.ServeMux, k kind[T]) {
	base := "/api/" + k.plural
	mux.Handle("GET "+base, s.guard(levelViewer, func(w http.ResponseWriter, r *http.Request, _ *principal) {
		writeJSON(w, http.StatusOK, *k.items(s.mgr.current()))
	}))
	mux.Handle("GET "+base+"/{id}", s.guard(levelViewer, func(w http.ResponseWriter, r *http.Request, _ *principal) {
		snap := s.mgr.current()
		i := find(k, snap, r.PathValue("id"))
		if i < 0 {
			writeErr(w, notFound(k.singular))
			return
		}
		writeJSON(w, http.StatusOK, (*k.items(snap))[i])
	}))
	mux.Handle("POST "+base, s.guard(levelEditor, func(w http.ResponseWriter, r *http.Request, p *principal) {
		var obj T
		if e := decodeJSON(w, r, &obj, maxBody, false); e != nil {
			writeErr(w, e)
			return
		}
		var created T
		_, err := s.mgr.mutate(r.Context(), func(next *model.Snapshot, now time.Time) error {
			id := strings.TrimSpace(k.id(&obj))
			if id == "" {
				for range 5 {
					id = slugID(k.name(&obj), k.singular)
					if find(k, next, id) < 0 {
						break
					}
				}
			}
			if find(k, next, id) >= 0 {
				return conflict(k.singular + " " + id + " already exists")
			}
			k.setID(&obj, id)
			k.prepare(&obj, nil)
			k.stamp(&obj, now, now)
			*k.items(next) = append(*k.items(next), obj)
			created = obj
			return nil
		})
		if err != nil {
			writeErr(w, err)
			return
		}
		s.record(r, p, k.singular+".create", k.singular, k.id(&created), "created "+k.singular+" "+quote(k.name(&created)))
		writeJSON(w, http.StatusCreated, created)
	}))
	mux.Handle("PUT "+base+"/{id}", s.guard(levelEditor, func(w http.ResponseWriter, r *http.Request, p *principal) {
		id := r.PathValue("id")
		var obj T
		if e := decodeJSON(w, r, &obj, maxBody, false); e != nil {
			writeErr(w, e)
			return
		}
		if bid := k.id(&obj); bid != "" && bid != id {
			writeErr(w, badRequest("id in body does not match URL (ids are immutable)"))
			return
		}
		var updated T
		_, err := s.mgr.mutate(r.Context(), func(next *model.Snapshot, now time.Time) error {
			items := k.items(next)
			i := find(k, next, id)
			if i < 0 {
				return notFound(k.singular)
			}
			old := (*items)[i]
			k.setID(&obj, id)
			k.prepare(&obj, &old)
			k.stamp(&obj, k.created(&old), now)
			(*items)[i] = obj
			updated = obj
			return nil
		})
		if err != nil {
			writeErr(w, err)
			return
		}
		s.record(r, p, k.singular+".update", k.singular, id, "updated "+k.singular+" "+quote(k.name(&updated)))
		writeJSON(w, http.StatusOK, updated)
	}))
	mux.Handle("DELETE "+base+"/{id}", s.guard(levelEditor, func(w http.ResponseWriter, r *http.Request, p *principal) {
		id := r.PathValue("id")
		var name string
		_, err := s.mgr.mutate(r.Context(), func(next *model.Snapshot, _ time.Time) error {
			items := k.items(next)
			i := find(k, next, id)
			if i < 0 {
				return notFound(k.singular)
			}
			if refs := k.referrers(next, id); len(refs) > 0 {
				e := conflict(k.singular + " is still referenced")
				e.Code = "referenced"
				e.Extra = map[string]any{"referrers": refs}
				return e
			}
			name = k.name(&(*items)[i])
			*items = slices.Delete(*items, i, i+1)
			return nil
		})
		if err != nil {
			writeErr(w, err)
			return
		}
		s.record(r, p, k.singular+".delete", k.singular, id, "deleted "+k.singular+" "+quote(name))
		w.WriteHeader(http.StatusNoContent)
	}))
}

func quote(s string) string {
	if len(s) > 100 {
		s = s[:100] + "…"
	}
	return `"` + s + `"`
}

// ---------------------------------------------------------------------
// Consumer API keys
// ---------------------------------------------------------------------

const maxKeysPerConsumer = 100

func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request, p *principal) {
	cid := r.PathValue("id")
	var req struct {
		Name      string     `json:"name"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if e := decodeJSON(w, r, &req, maxBody, true); e != nil {
		writeErr(w, e)
		return
	}
	if len(req.Name) > 100 {
		writeErr(w, badRequest("name must be at most 100 characters"))
		return
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(s.now()) {
		writeErr(w, badRequest("expires_at must be in the future"))
		return
	}
	plain := "rlg_live_" + randomBase62(32)
	var key model.APIKey
	_, err := s.mgr.mutate(r.Context(), func(next *model.Snapshot, now time.Time) error {
		i := find(consumerKind, next, cid)
		if i < 0 {
			return notFound("consumer")
		}
		c := &next.Consumers[i]
		active := 0
		for _, k := range c.Keys {
			if !k.Revoked {
				active++
			}
		}
		if len(c.Keys) >= maxKeysPerConsumer*2 || active >= maxKeysPerConsumer {
			return conflict("too many keys for this consumer; revoke or delete old keys")
		}
		key = model.APIKey{
			ID:        "key_" + randomFrom(lowerAlnum, 12),
			Prefix:    plain[:12],
			Hash:      sha256Hex(plain),
			Name:      strings.TrimSpace(req.Name),
			CreatedAt: now,
			ExpiresAt: req.ExpiresAt,
		}
		c.Keys = append(c.Keys, key)
		c.UpdatedAt = now
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.record(r, p, "consumer.key_create", "consumer", cid, "issued API key "+key.ID+" ("+key.Prefix+"…)")
	// The plaintext is returned exactly once and never stored or logged.
	writeJSON(w, http.StatusCreated, map[string]any{"key": plain, "api_key": key})
}

func (s *Server) handleRevokeKey(w http.ResponseWriter, r *http.Request, p *principal) {
	cid, kid := r.PathValue("id"), r.PathValue("keyId")
	var key model.APIKey
	_, err := s.mgr.mutate(r.Context(), func(next *model.Snapshot, now time.Time) error {
		i := find(consumerKind, next, cid)
		if i < 0 {
			return notFound("consumer")
		}
		c := &next.Consumers[i]
		for j := range c.Keys {
			if c.Keys[j].ID == kid {
				c.Keys[j].Revoked = true
				c.UpdatedAt = now
				key = c.Keys[j]
				return nil
			}
		}
		return notFound("key")
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.record(r, p, "consumer.key_revoke", "consumer", cid, "revoked API key "+kid+" ("+key.Prefix+"…)")
	writeJSON(w, http.StatusOK, map[string]any{"api_key": key})
}

// ---------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request, _ *principal) {
	writeJSON(w, http.StatusOK, s.mgr.current().Settings)
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request, p *principal) {
	var st model.Settings
	if e := decodeJSON(w, r, &st, maxBody, false); e != nil {
		writeErr(w, e)
		return
	}
	next, err := s.mgr.mutate(r.Context(), func(next *model.Snapshot, _ time.Time) error {
		next.Settings = st
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.record(r, p, "settings.update", "settings", "settings", "updated settings")
	writeJSON(w, http.StatusOK, next.Settings)
}

// ---------------------------------------------------------------------
// Export / import
// ---------------------------------------------------------------------

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, p *principal) {
	snap := s.mgr.current()
	w.Header().Set("Content-Disposition", `attachment; filename="rateguard-config-v`+itoa64(snap.Version)+`.json"`)
	s.record(r, p, "config.export", "config", itoa64(snap.Version), "exported configuration")
	writeJSON(w, http.StatusOK, snap)
}

type kindDiff struct {
	Added   int `json:"added"`
	Removed int `json:"removed"`
	Changed int `json:"changed"`
}

func diffKind[T any](k kind[T], a, b *model.Snapshot) kindDiff {
	var d kindDiff
	old := map[string]string{}
	for _, it := range *k.items(a) {
		old[k.id(&it)] = mustJSON(it)
	}
	seen := map[string]bool{}
	for _, it := range *k.items(b) {
		id := k.id(&it)
		seen[id] = true
		prev, ok := old[id]
		switch {
		case !ok:
			d.Added++
		case prev != mustJSON(it):
			d.Changed++
		}
	}
	for id := range old {
		if !seen[id] {
			d.Removed++
		}
	}
	return d
}

func snapshotDiff(a, b *model.Snapshot) map[string]any {
	settings := kindDiff{}
	if mustJSON(a.Settings) != mustJSON(b.Settings) {
		settings.Changed = 1
	}
	return map[string]any{
		"policies":  diffKind(policyKind, a, b),
		"routes":    diffKind(routeKind, a, b),
		"plans":     diffKind(planKind, a, b),
		"consumers": diffKind(consumerKind, a, b),
		"settings":  settings,
	}
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request, p *principal) {
	var req struct {
		Snapshot *model.Snapshot `json:"snapshot"`
		DryRun   bool            `json:"dry_run"`
	}
	if e := decodeJSON(w, r, &req, maxImportBody, false); e != nil {
		writeErr(w, e)
		return
	}
	if req.Snapshot == nil {
		writeErr(w, badRequest("snapshot is required"))
		return
	}
	in := req.Snapshot
	normalizeSnapshot(in)
	cur := s.mgr.current()
	diff := snapshotDiff(cur, in)
	if req.DryRun {
		resp := map[string]any{"ok": true, "dry_run": true, "diff": diff, "validated": s.o.Validate != nil}
		if s.o.Validate != nil {
			cand := in.Clone()
			cand.Version = cur.Version + 1
			if err := s.mgr.check(cand); err != nil {
				ve := err.(*apiError)
				resp["ok"] = false
				resp["message"] = ve.Message
				if ve.Problems != nil {
					resp["problems"] = ve.Problems
				}
			}
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	next, err := s.mgr.replace(r.Context(), in)
	if err != nil {
		if ae, ok := err.(*apiError); ok && ae.Status == http.StatusUnprocessableEntity {
			ae.Extra = map[string]any{"ok": false, "diff": diff}
		}
		writeErr(w, err)
		return
	}
	s.record(r, p, "config.import", "config", itoa64(next.Version), "imported configuration")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "dry_run": false, "diff": diff, "version": next.Version})
}
