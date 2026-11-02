package admin

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"ratelimitergateway/internal/model"
)

// TestRoleMatrix checks every /api route against every kind of principal.
func TestRoleMatrix(t *testing.T) {
	policy := map[string]any{"name": "New", "algorithm": "fixed_window", "limit": 1, "window": "1s", "key_by": []string{"ip"}, "mode": "enforce", "fail_mode": "open", "enabled": true}
	route := map[string]any{"name": "R", "upstream": "http://u", "policy_ids": []string{}, "match": map[string]any{"path_prefix": "/x"}}
	rows := []struct {
		method, path string
		body         any
		lvl          level
	}{
		{"GET", "/api/auth/me", nil, levelSelf},
		{"GET", "/api/system", nil, levelViewer},
		{"GET", "/api/overview", nil, levelViewer},
		{"GET", "/api/timeseries?range=15m", nil, levelViewer},
		{"GET", "/api/logs?limit=5", nil, levelViewer},
		{"GET", "/api/policies", nil, levelViewer},
		{"GET", "/api/policies/p1", nil, levelViewer},
		{"POST", "/api/policies", policy, levelEditor},
		{"PUT", "/api/policies/p1", policy, levelEditor},
		{"DELETE", "/api/policies/p2", nil, levelEditor},
		{"GET", "/api/routes", nil, levelViewer},
		{"GET", "/api/routes/r1", nil, levelViewer},
		{"POST", "/api/routes", route, levelEditor},
		{"PUT", "/api/routes/r1", route, levelEditor},
		{"DELETE", "/api/routes/r1", nil, levelEditor},
		{"GET", "/api/plans", nil, levelViewer},
		{"GET", "/api/plans/pl1", nil, levelViewer},
		{"POST", "/api/plans", map[string]any{"name": "Gold"}, levelEditor},
		{"PUT", "/api/plans/pl1", map[string]any{"name": "Gold"}, levelEditor},
		{"DELETE", "/api/plans/pl2", nil, levelEditor},
		{"GET", "/api/consumers", nil, levelViewer},
		{"GET", "/api/consumers/c1", nil, levelViewer},
		{"POST", "/api/consumers", map[string]any{"name": "Beta"}, levelEditor},
		{"PUT", "/api/consumers/c1", map[string]any{"name": "Acme 2", "plan_id": "pl1"}, levelEditor},
		{"DELETE", "/api/consumers/c1", nil, levelEditor},
		{"POST", "/api/consumers/c1/keys", map[string]any{"name": "ci"}, levelEditor},
		{"DELETE", "/api/consumers/c1/keys/k1", nil, levelEditor},
		{"GET", "/api/settings", nil, levelViewer},
		{"PUT", "/api/settings", model.DefaultSettings(), levelAdmin},
		{"POST", "/api/simulate", model.SimRequest{Method: "GET", Path: "/api"}, levelViewer},
		{"POST", "/api/simulate", model.SimRequest{Method: "GET", Path: "/api", Consume: true}, levelEditor},
		{"GET", "/api/limits?policy_id=p1&key=1.2.3.4", nil, levelViewer},
		{"POST", "/api/limits/reset", map[string]any{"policy_id": "p1", "key": "1.2.3.4"}, levelEditor},
		{"GET", "/api/config/export", nil, levelAdmin},
		{"POST", "/api/config/import", map[string]any{"snapshot": seedSnapshot(), "dry_run": true}, levelAdmin},
		{"GET", "/api/audit", nil, levelAdmin},
		{"GET", "/api/users", nil, levelAdmin},
		{"POST", "/api/users", map[string]any{"username": "zed", "role": "viewer", "password": "zed-password-123"}, levelAdmin},
		{"PUT", "/api/users/viewer", map[string]any{"role": "editor"}, levelAdmin},
		{"DELETE", "/api/users/editor", nil, levelAdmin},
		{"GET", "/api/tokens", nil, levelAdmin},
		{"POST", "/api/tokens", map[string]any{"name": "x", "scopes": []string{"read"}}, levelAdmin},
		{"DELETE", "/api/tokens/{tok}", nil, levelAdmin},
		{"GET", "/metrics", nil, levelViewer},
	}
	principals := []struct {
		name string
		rank int // 0 = anonymous / check-only
		anon bool
		mk   func(e *env) cred
	}{
		{"anonymous", rankNone, true, func(*env) cred { return cred{} }},
		{"viewer", rankViewer, false, func(e *env) cred { return e.login("viewer", "viewer-password-123") }},
		{"editor", rankEditor, false, func(e *env) cred { return e.login("editor", "editor-password-123") }},
		{"admin", rankAdmin, false, func(e *env) cred { return e.login("admin", adminPW) }},
		{"token:read", rankViewer, false, func(e *env) cred { return cred{bearer: e.token("r", ScopeRead)} }},
		{"token:admin", rankAdmin, false, func(e *env) cred { return cred{bearer: e.token("a", ScopeAdmin)} }},
		{"token:check", rankNone, false, func(e *env) cred { return cred{bearer: e.token("c", ScopeCheck)} }},
	}
	for _, row := range rows {
		for _, pr := range principals {
			t.Run(row.method+" "+row.path+" as "+pr.name, func(t *testing.T) {
				e := newEnv(t)
				e.addUser("viewer", RoleViewer)
				e.addUser("editor", RoleEditor)
				e.token("spare", ScopeRead)
				var spareID string
				for _, tv := range e.s.auth.listTokens() {
					if tv.Name == "spare" {
						spareID = tv.ID
					}
				}
				c := pr.mk(e)
				path := strings.ReplaceAll(row.path, "{tok}", spareID)
				rec := e.req(row.method, path, row.body, c)
				need := row.lvl.rank()
				if row.lvl == levelSelf {
					need = rankViewer
				}
				allowed := !pr.anon && pr.rank >= need
				switch {
				case allowed && (rec.Code == 401 || rec.Code == 403):
					t.Fatalf("should be allowed, got %d %s", rec.Code, rec.Body)
				case allowed && rec.Code >= 400:
					t.Fatalf("allowed but failed: %d %s", rec.Code, rec.Body)
				case !allowed && pr.anon && rec.Code != 401:
					t.Fatalf("anonymous: want 401, got %d %s", rec.Code, rec.Body)
				case !allowed && !pr.anon && rec.Code != 403:
					t.Fatalf("want 403, got %d %s", rec.Code, rec.Body)
				}
			})
		}
	}
}

func TestEveryAPIRouteIsGuarded(t *testing.T) {
	// Any /api path not explicitly registered is a JSON 404 and never the SPA.
	e := newEnv(t, func(o *Options) { o.StaticFS = fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}} })
	for _, p := range []string{"/api", "/api/", "/api/nope", "/api/policies/p1/extra", "/api/auth"} {
		rec := e.req("GET", p, nil, cred{})
		if rec.Code != 404 || !strings.Contains(rec.Header().Get("Content-Type"), "json") {
			t.Errorf("%s: %d %q", p, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
}

func TestPolicyCRUDAndIDs(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin", adminPW)
	body := map[string]any{"name": "Free Tier!", "algorithm": "token_bucket", "limit": 100, "window": "1m", "key_by": []string{"consumer"}, "mode": "enforce", "fail_mode": "open", "enabled": true}
	rec := e.req("POST", "/api/policies", body, c)
	if rec.Code != 201 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	p := decode[model.Policy](t, rec)
	if !regexp.MustCompile(`^free-tier-[a-z0-9]{4}$`).MatchString(p.ID) || p.CreatedAt.IsZero() {
		t.Fatalf("id/timestamps: %+v", p)
	}
	snap := e.rt.Current()
	if snap.Version != 2 || e.store.saved == nil || e.store.saved.Version != 2 {
		t.Fatalf("version not bumped/saved: %d", snap.Version)
	}
	// Explicit duplicate id → 409.
	body["id"] = "p1"
	if rec := e.req("POST", "/api/policies", body, c); rec.Code != 409 {
		t.Fatalf("dup: %d", rec.Code)
	}
	// PUT keeps created_at, rejects id change.
	e.clock.Advance(time.Hour)
	body["id"] = p.ID
	body["limit"] = 200
	rec = e.req("PUT", "/api/policies/"+p.ID, body, c)
	up := decode[model.Policy](t, rec)
	if rec.Code != 200 || up.Limit != 200 || !up.CreatedAt.Equal(p.CreatedAt) || !up.UpdatedAt.After(p.UpdatedAt) {
		t.Fatalf("update: %d %+v", rec.Code, up)
	}
	body["id"] = "other"
	if rec := e.req("PUT", "/api/policies/"+p.ID, body, c); rec.Code != 400 {
		t.Fatalf("id change: %d", rec.Code)
	}
	if rec := e.req("PUT", "/api/policies/missing", map[string]any{"name": "x"}, c); rec.Code != 404 {
		t.Fatalf("missing: %d", rec.Code)
	}
	if rec := e.req("GET", "/api/policies/missing", nil, c); rec.Code != 404 {
		t.Fatal(rec.Code)
	}
	if rec := e.req("DELETE", "/api/policies/"+p.ID, nil, c); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	list := decode[[]model.Policy](t, e.req("GET", "/api/policies", nil, c))
	if len(list) != 2 {
		t.Fatalf("list: %d", len(list))
	}
}

func TestDeleteReferenced(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin", adminPW)
	// p1 is used by route r1; add more references.
	snap := e.rt.Current().Clone()
	snap.Settings.GlobalPolicyIDs = []string{"p1"}
	snap.Plans[0].Overrides["p1"] = model.LimitOverride{Limit: 5}
	e.rt.Apply(snap)
	cases := []struct {
		path      string
		referrers []string
	}{
		{"/api/policies/p1", []string{"settings:global_policy_ids", "route:r1", "plan:pl1"}},
		{"/api/plans/pl1", []string{"consumer:c1"}},
	}
	for _, tc := range cases {
		rec := e.req("DELETE", tc.path, nil, c)
		if rec.Code != 409 || errCode(t, rec) != "referenced" {
			t.Fatalf("%s: %d %s", tc.path, rec.Code, rec.Body)
		}
		var got []string
		for _, r := range decode[map[string]any](t, rec)["referrers"].([]any) {
			m := r.(map[string]any)
			got = append(got, m["type"].(string)+":"+m["id"].(string))
		}
		if strings.Join(got, ",") != strings.Join(tc.referrers, ",") {
			t.Fatalf("%s referrers %v", tc.path, got)
		}
	}
	if e.rt.Current().Version != snap.Version {
		t.Fatal("409 must not change config")
	}
	// Unreferenced deletes succeed.
	for _, p := range []string{"/api/routes/r1", "/api/plans/pl2", "/api/policies/p2"} {
		if rec := e.req("DELETE", p, nil, c); rec.Code != 204 {
			t.Fatalf("%s: %d", p, rec.Code)
		}
	}
}

func TestConsumerKeys(t *testing.T) {
	e := newEnv(t)
	e.addUser("editor", RoleEditor)
	c := e.login("editor", "editor-password-123")

	rec := e.req("POST", "/api/consumers/c1/keys", map[string]any{"name": "prod"}, c)
	if rec.Code != 201 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	out := decode[struct {
		Key    string       `json:"key"`
		APIKey model.APIKey `json:"api_key"`
	}](t, rec)
	if !regexp.MustCompile(`^rlg_live_[0-9A-Za-z]{32}$`).MatchString(out.Key) {
		t.Fatalf("key format %q", out.Key)
	}
	sum := sha256.Sum256([]byte(out.Key))
	stored := e.rt.Current().Consumers[0].Keys[1]
	if stored.ID != out.APIKey.ID || stored.Hash != hex.EncodeToString(sum[:]) || out.APIKey.Hash != "" || out.APIKey.Prefix != out.Key[:12] {
		t.Fatalf("hash/prefix: stored %+v response %+v", stored, out.APIKey)
	}
	// Stored config has the hash only; plaintext appears nowhere afterwards.
	saved, _ := json.Marshal(e.store.saved)
	get := e.req("GET", "/api/consumers/c1", nil, c).Body.String()
	auditRaw, _ := os.ReadFile(filepath.Join(e.dir, "audit.jsonl"))
	for name, s := range map[string]string{"store": string(saved), "get": get, "audit": string(auditRaw)} {
		if strings.Contains(s, out.Key) {
			t.Fatalf("plaintext key leaked via %s", name)
		}
	}
	if !strings.Contains(string(saved), stored.Hash) {
		t.Fatal("hash not stored")
	}
	// No body is fine too.
	if rec := e.req("POST", "/api/consumers/c1/keys", nil, c); rec.Code != 201 {
		t.Fatalf("empty body: %d %s", rec.Code, rec.Body)
	}
	if rec := e.req("POST", "/api/consumers/nope/keys", nil, c); rec.Code != 404 {
		t.Fatal(rec.Code)
	}
	if rec := e.req("POST", "/api/consumers/c1/keys", map[string]any{"expires_at": e.clock.Now().Add(-time.Minute)}, c); rec.Code != 400 {
		t.Fatal("past expiry accepted")
	}
	// PUT ignores keys; POST discards client keys.
	rec = e.req("PUT", "/api/consumers/c1", map[string]any{"name": "Acme", "plan_id": "pl1", "keys": []any{}}, c)
	if got := decode[model.Consumer](t, rec); len(got.Keys) != 3 {
		t.Fatalf("PUT dropped keys: %d", len(got.Keys))
	}
	rec = e.req("POST", "/api/consumers", map[string]any{"name": "Evil", "keys": []map[string]any{{"id": "x", "hash": strings.Repeat("b", 64)}}}, c)
	if got := decode[model.Consumer](t, rec); rec.Code != 201 || len(got.Keys) != 0 {
		t.Fatalf("POST accepted client keys: %+v", got)
	}
	// Revoke.
	rec = e.req("DELETE", "/api/consumers/c1/keys/"+out.APIKey.ID, nil, c)
	if rec.Code != 200 || !decode[struct {
		APIKey model.APIKey `json:"api_key"`
	}](t, rec).APIKey.Revoked {
		t.Fatalf("revoke %d %s", rec.Code, rec.Body)
	}
	if rec := e.req("DELETE", "/api/consumers/c1/keys/nope", nil, c); rec.Code != 404 {
		t.Fatal(rec.Code)
	}
}

func TestValidationErrors(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Validate = fakeValidate })
	c := e.login("admin", adminPW)
	before := e.rt.Current()
	rec := e.req("POST", "/api/policies", map[string]any{"name": "Bad", "algorithm": "fixed_window", "limit": 0}, c)
	if rec.Code != 422 || errCode(t, rec) != "validation_failed" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	probs := decode[map[string]any](t, rec)["problems"].([]any)
	if probs[0].(map[string]any)["field"] != "policies[2].limit" {
		t.Fatalf("problems: %v", probs)
	}
	if e.rt.Current() != before || e.store.saves != 0 {
		t.Fatal("invalid config applied or saved")
	}
	// Errors from Runtime.Apply (wrapped) are also 422 with problems.
	e2 := newEnv(t)
	e2.rt.applyErr = func(*model.Snapshot) error {
		return errors.Join(errors.New("compile"), &fakeValidationError{Problems: []fakeProblem{{"routes[0].upstream", "bad"}}})
	}
	c2 := e2.login("admin", adminPW)
	rec = e2.req("PUT", "/api/routes/r1", map[string]any{"name": "R", "upstream": "nope"}, c2)
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "routes[0].upstream") {
		t.Fatalf("apply error: %d %s", rec.Code, rec.Body)
	}
}

func TestStoreFailureReverts(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin", adminPW)
	before := e.rt.Current()
	e.store.failSave = true
	rec := e.req("DELETE", "/api/policies/p2", nil, c)
	if rec.Code != 500 || errCode(t, rec) != "store_error" || strings.Contains(rec.Body.String(), "/secret/path") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if e.rt.Current() != before {
		t.Fatal("runtime not reverted")
	}
	if len(e.s.audit.query(100, "")) == 0 {
		t.Fatal("audit missing login")
	}
	for _, a := range e.s.audit.query(100, "") {
		if a.Action == "policy.delete" {
			t.Fatal("failed mutation audited")
		}
	}
}

func TestImport(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Validate = fakeValidate })
	c := e.login("admin", adminPW)
	in := seedSnapshot()
	in.Version = 999 // ignored
	in.Policies = in.Policies[:1]
	in.Policies[0].Limit = 77
	in.Routes = append(in.Routes, model.Route{ID: "r2", Name: "R2", Upstream: "http://x"})
	in.Settings.LegacyHeaders = false

	ver := e.rt.Current().Version
	rec := e.req("POST", "/api/config/import", map[string]any{"snapshot": in, "dry_run": true}, c)
	out := decode[map[string]any](t, rec)
	if rec.Code != 200 || out["ok"] != true {
		t.Fatalf("dry run: %d %s", rec.Code, rec.Body)
	}
	diff := out["diff"].(map[string]any)
	want := map[string]string{"policies": "0/1/1", "routes": "1/0/0", "plans": "0/0/0", "consumers": "0/0/0", "settings": "0/0/1"}
	for k, w := range want {
		d := diff[k].(map[string]any)
		got := itoa64(int64(d["added"].(float64))) + "/" + itoa64(int64(d["removed"].(float64))) + "/" + itoa64(int64(d["changed"].(float64)))
		if got != w {
			t.Errorf("diff %s = %s want %s", k, got, w)
		}
	}
	if e.rt.Current().Version != ver || e.store.saves != 0 {
		t.Fatal("dry run applied")
	}
	// Dry run of an invalid snapshot reports problems, still no apply.
	bad := in.Clone()
	bad.Policies[0].Limit = 0
	rec = e.req("POST", "/api/config/import", map[string]any{"snapshot": bad, "dry_run": true}, c)
	if out := decode[map[string]any](t, rec); out["ok"] != false || out["problems"] == nil {
		t.Fatalf("invalid dry run: %s", rec.Body)
	}
	// Real invalid import: 422.
	if rec := e.req("POST", "/api/config/import", map[string]any{"snapshot": bad}, c); rec.Code != 422 {
		t.Fatalf("invalid import: %d", rec.Code)
	}
	// Unknown fields are rejected everywhere, including nested.
	if rec := e.req("POST", "/api/config/import", `{"snapshot":{"policies":[{"id":"x","bogus":1}]}}`, c); rec.Code != 400 {
		t.Fatalf("unknown nested field: %d", rec.Code)
	}
	// Real import.
	rec = e.req("POST", "/api/config/import", map[string]any{"snapshot": in}, c)
	if rec.Code != 200 {
		t.Fatalf("import: %d %s", rec.Code, rec.Body)
	}
	cur := e.rt.Current()
	if cur.Version != ver+1 || len(cur.Routes) != 2 || cur.Policies[0].Limit != 77 || e.store.saved.Version != ver+1 {
		t.Fatalf("import result: %+v", cur)
	}
	// Export round-trips.
	rec = e.req("GET", "/api/config/export", nil, c)
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatal("export not a download")
	}
	if exp := decode[model.Snapshot](t, rec); exp.Version != cur.Version || len(exp.Routes) != 2 {
		t.Fatal("export mismatch")
	}
}

func TestDefaultValidatorIsStoreValidate(t *testing.T) {
	e := newEnv(t) // Options.Validate left nil
	c := e.login("admin", adminPW)
	bad := seedSnapshot()
	bad.Policies[0].Algorithm = "nope"
	rec := e.req("POST", "/api/config/import", map[string]any{"snapshot": bad, "dry_run": true}, c)
	out := decode[map[string]any](t, rec)
	if out["ok"] != false || !strings.Contains(rec.Body.String(), "policies[0].algorithm") {
		t.Fatalf("store.Validate not applied by default: %s", rec.Body)
	}
	rec = e.req("POST", "/api/policies", map[string]any{"name": "Bad", "algorithm": "fixed_window", "limit": 0, "window": "1s"}, c)
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), `"field":"policies[2].limit"`) {
		t.Fatalf("422 problems via store.ValidationError.ProblemsJSON: %d %s", rec.Code, rec.Body)
	}
	if rec := e.req("POST", "/api/config/import", map[string]any{"snapshot": seedSnapshot(), "dry_run": true}, c); decode[map[string]any](t, rec)["ok"] != true {
		t.Fatalf("seed invalid under store.Validate: %s", rec.Body)
	}
}

func TestKeyHashesRedacted(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin", adminPW)
	tok := e.token("root", ScopeAdmin)
	hash := strings.Repeat("a", 64) // seed key k1
	for _, rec := range []*httptest.ResponseRecorder{
		e.req("GET", "/api/consumers", nil, c),
		e.req("GET", "/api/consumers/c1", nil, c),
		e.req("GET", "/api/consumers/c1", nil, cred{bearer: tok}),
		e.req("PUT", "/api/consumers/c1", map[string]any{"name": "Acme", "plan_id": "pl1"}, c),
		e.req("POST", "/api/consumers/c1/keys", nil, c),
		e.req("DELETE", "/api/consumers/c1/keys/k1", nil, c),
	} {
		if rec.Code >= 300 || strings.Contains(rec.Body.String(), hash) || regexp.MustCompile(`"hash":"[0-9a-f]+`).MatchString(rec.Body.String()) {
			t.Fatalf("hash exposed or failed: %d %s", rec.Code, rec.Body)
		}
	}
	// Redaction is response-only: stored config and admin export keep hashes.
	if e.rt.Current().Consumers[0].Keys[0].Hash != hash || !strings.Contains(e.req("GET", "/api/config/export", nil, c).Body.String(), hash) {
		t.Fatal("hash lost from stored config / export")
	}
}

func TestSystemHidesEngineError(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Engine = &sickEngine{} })
	rec := e.req("GET", "/api/system", nil, e.login("admin", adminPW))
	eng := decode[map[string]any](t, rec)["engine"].(map[string]any)
	if eng["healthy"] != false || eng["error"] != "unhealthy" || strings.Contains(rec.Body.String(), "10.9.9.9") {
		t.Fatalf("engine: %s", rec.Body)
	}
}

type sickEngine struct{ fakeEngine }

func (*sickEngine) Healthy(context.Context) error {
	return errors.New("dial tcp 10.9.9.9:6379: NOAUTH secret-ish detail")
}

func TestAuditLog(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin", adminPW)
	e.req("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "wrong-password!!"}, cred{})
	e.req("POST", "/api/auth/login", map[string]string{"username": "pw-typed-as-username", "password": "x"}, cred{})
	e.req("DELETE", "/api/policies/p2", nil, c)
	e.req("POST", "/api/limits/reset", map[string]any{"policy_id": "p1", "key": "9.9.9.9"}, c)
	tok := decode[struct{ Token string }](t, e.req("POST", "/api/tokens", map[string]any{"name": "ci", "scopes": []string{"admin"}}, c)).Token
	e.req("DELETE", "/api/routes/r1", nil, cred{bearer: tok})
	e.req("PUT", "/api/settings", model.DefaultSettings(), c)

	rec := e.req("GET", "/api/audit?limit=100", nil, c)
	entries := decode[struct{ Entries []AuditEntry }](t, rec).Entries
	var actions []string
	for _, a := range entries {
		actions = append(actions, a.Action)
	}
	want := "settings.update,route.delete,token.create,limits.reset,policy.delete,auth.login_failed,auth.login_failed,auth.login,user.bootstrap"
	if strings.Join(actions, ",") != want {
		t.Fatalf("actions:\n got %s\nwant %s", strings.Join(actions, ","), want)
	}
	if entries[1].ActorType != "token" || !strings.HasPrefix(entries[1].Actor, "ci (tok_") || entries[1].IP != "192.0.2.10" || entries[1].TargetID != "r1" {
		t.Fatalf("token entry: %+v", entries[1])
	}
	if entries[4].Actor != "admin" || entries[4].ActorType != "user" || entries[4].TargetType != "policy" {
		t.Fatalf("user entry: %+v", entries[4])
	}
	// IDs sortable newest-first and cursor works.
	page := decode[struct{ Entries []AuditEntry }](t, e.req("GET", "/api/audit?limit=2&before="+entries[1].ID, nil, c)).Entries
	if len(page) != 2 || page[0].ID != entries[2].ID {
		t.Fatalf("cursor: %+v", page)
	}
	// Persisted, 0600, no secrets, reloaded on restart.
	path := filepath.Join(e.dir, "audit.jsonl")
	fi, _ := os.Stat(path)
	raw, _ := os.ReadFile(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm %v", fi.Mode().Perm())
	}
	for _, secret := range []string{tok, adminPW, "wrong-password!!", "pw-typed-as-username"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("audit leaks %q", secret)
		}
	}
	s2, err := New(Options{DataDir: e.dir, Store: e.store, Runtime: e.rt})
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.audit.query(100, ""); len(got) != len(entries) || got[0].ID != entries[0].ID {
		t.Fatalf("reload: %d entries", len(got))
	}
}

func TestAuditRingBounded(t *testing.T) {
	a, _ := newAuditLog("", newClock().Now)
	for i := range auditMemory + 10 {
		_ = a.add(AuditEntry{Action: "x", TargetID: itoa64(int64(i))})
	}
	all := a.query(10000, "")
	if len(all) != auditMemory || all[0].TargetID != itoa64(auditMemory+9) || all[len(all)-1].TargetID != "10" {
		t.Fatalf("ring: len=%d first=%s last=%s", len(all), all[0].TargetID, all[len(all)-1].TargetID)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin", adminPW)
	for _, tc := range []struct {
		path    string
		c       cred
		noStore bool
	}{
		{"/", cred{}, false}, {"/routes", cred{}, false}, {"/api/system", c, true}, {"/api/system", cred{}, true}, {"/api/nope", cred{}, true},
	} {
		rec := e.req("GET", tc.path, nil, tc.c)
		h := rec.Header()
		for k, v := range map[string]string{
			"Content-Security-Policy":    csp,
			"X-Content-Type-Options":     "nosniff",
			"Referrer-Policy":            "no-referrer",
			"X-Frame-Options":            "DENY",
			"Cross-Origin-Opener-Policy": "same-origin",
		} {
			if h.Get(k) != v {
				t.Errorf("%s %s = %q", tc.path, k, h.Get(k))
			}
		}
		if (h.Get("Cache-Control") == "no-store") != tc.noStore {
			t.Errorf("%s cache-control %q", tc.path, h.Get("Cache-Control"))
		}
		if h.Get("Strict-Transport-Security") != "" {
			t.Errorf("%s HSTS on plain http", tc.path)
		}
	}
	// HSTS only with TLS (or trusted X-Forwarded-Proto).
	rec := e.req("GET", "/", nil, cred{}, withHeader("X-Forwarded-Proto", "https"))
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("untrusted X-Forwarded-Proto honoured")
	}
	e2 := newEnv(t, func(o *Options) { o.TrustProxyHeaders = true })
	if rec := e2.req("GET", "/", nil, cred{}, withHeader("X-Forwarded-Proto", "https")); rec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("trusted proxy https: no HSTS")
	}
	r := httptest.NewRequest("GET", "https://admin.local/", nil)
	rec2 := httptest.NewRecorder()
	e.h.ServeHTTP(rec2, r)
	if rec2.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("TLS: no HSTS")
	}
}

func TestClientIPTrust(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 1.2.3.4")
	if ip := (&Server{}).clientIP(r); ip != "10.0.0.1" {
		t.Fatalf("untrusted: %s", ip)
	}
	if ip := (&Server{o: Options{TrustProxyHeaders: true}}).clientIP(r); ip != "1.2.3.4" {
		t.Fatalf("trusted: %s", ip)
	}
}

func TestBodyLimits(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin", adminPW)
	big := `{"name":"` + strings.Repeat("a", maxBody) + `"}`
	cases := []struct {
		name, method, path string
		body               any
		opts               []reqOpt
		want               int
	}{
		{"too large", "POST", "/api/policies", big, nil, 413},
		{"unknown field", "POST", "/api/policies", `{"name":"x","admin":true}`, nil, 400},
		{"trailing data", "POST", "/api/plans", `{"name":"x"}{"name":"y"}`, nil, 400},
		{"malformed", "POST", "/api/plans", `{"name":`, nil, 400},
		{"empty", "POST", "/api/plans", "", nil, 400},
		{"wrong content type", "POST", "/api/plans", `{"name":"x"}`, []reqOpt{withHeader("Content-Type", "text/plain")}, 415},
		{"json with charset ok", "POST", "/api/plans", `{"name":"x"}`, []reqOpt{withHeader("Content-Type", "application/json; charset=utf-8")}, 201},
		{"import allows >1MiB", "POST", "/api/config/import", `{"dry_run":true,"snapshot":{"policies":[{"id":"x","name":"` + strings.Repeat("a", 2<<20) + `"}]}}`, nil, 200},
		{"import capped at 10MiB", "POST", "/api/config/import", `{"snapshot":{"policies":[{"id":"` + strings.Repeat("a", 11<<20) + `"}]}}`, nil, 413},
	}
	for _, tc := range cases {
		if rec := e.req(tc.method, tc.path, tc.body, c, tc.opts...); rec.Code != tc.want {
			t.Errorf("%s: %d %s", tc.name, rec.Code, truncate(rec.Body.String()))
		}
	}
}

func truncate(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

func TestSPA(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html":    {Data: []byte("<html>spa</html>")},
		"app.js":        {Data: []byte("console.log(1)")},
		"css/style.css": {Data: []byte("body{}")},
	}
	e := newEnv(t, func(o *Options) { o.StaticFS = fsys })
	cases := []struct {
		path string
		code int
		body string
	}{
		{"/", 200, "<html>spa</html>"},
		{"/index.html", 200, "<html>spa</html>"},
		{"/logs", 200, "<html>spa</html>"},
		{"/policies/p1", 200, "<html>spa</html>"},
		{"/css", 200, "<html>spa</html>"}, // directory → SPA, no listing
		{"/app.js", 200, "console.log(1)"},
		{"/css/style.css", 200, "body{}"},
		{"/missing.js", 404, ""},
		{"/../../etc/passwd", 301, ""},           // mux canonicalises to /etc/passwd ...
		{"/etc/passwd", 200, "<html>spa</html>"}, // ... which never escapes the FS
	}
	for _, tc := range cases {
		rec := e.req("GET", tc.path, nil, cred{})
		if rec.Code != tc.code || (tc.body != "" && rec.Body.String() != tc.body) {
			t.Errorf("%s: %d %q", tc.path, rec.Code, truncate(rec.Body.String()))
		}
	}
	if rec := e.req("POST", "/logs", "{}", cred{}); rec.Code != 405 {
		t.Errorf("POST to SPA: %d", rec.Code)
	}
	// nil StaticFS → placeholder.
	e2 := newEnv(t)
	if rec := e2.req("GET", "/anything", nil, cred{}); rec.Code != 200 || !strings.Contains(rec.Body.String(), "RateGuard") {
		t.Fatalf("placeholder: %d", rec.Code)
	}
}

func TestMetricsAuth(t *testing.T) {
	e := newEnv(t)
	e.addUser("viewer", RoleViewer)
	cases := []struct {
		name string
		c    cred
		want int
	}{
		{"anonymous", cred{}, 401},
		{"viewer session", e.login("viewer", "viewer-password-123"), 200},
		{"read token", cred{bearer: e.token("prom", ScopeRead)}, 200},
		{"admin token", cred{bearer: e.token("adm", ScopeAdmin)}, 200},
		{"check token", cred{bearer: e.token("chk", ScopeCheck)}, 403},
		{"bad token", cred{bearer: "rgt_x"}, 401},
	}
	for _, tc := range cases {
		rec := e.req("GET", "/metrics", nil, tc.c)
		if rec.Code != tc.want {
			t.Errorf("%s: %d", tc.name, rec.Code)
		}
		if tc.want == 200 && (!strings.Contains(rec.Body.String(), "rateguard_log_buffer_entries") || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain")) {
			t.Errorf("%s: body %q", tc.name, rec.Body)
		}
	}
	pub := newEnv(t, func(o *Options) { o.MetricsPublic = true })
	if rec := pub.req("GET", "/metrics", nil, cred{}); rec.Code != 200 {
		t.Fatalf("public: %d", rec.Code)
	}
}

func TestReadEndpoints(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin", adminPW)

	sys := decode[map[string]any](t, e.req("GET", "/api/system", nil, c))
	for _, k := range []string{"version", "go_version", "instance_id", "started_at", "uptime_s", "engine", "store", "config_version", "data_plane_addr", "admin_addr"} {
		if _, ok := sys[k]; !ok {
			t.Errorf("system missing %s", k)
		}
	}
	if sys["engine"].(map[string]any)["healthy"] != true || sys["store"].(map[string]any)["name"] != "fake" {
		t.Errorf("system: %v", sys)
	}

	ov := decode[map[string]any](t, e.req("GET", "/api/overview", nil, c))
	if ov["requests"] != float64(42) || ov["counts"].(map[string]any)["policies"] != float64(2) {
		t.Errorf("overview: %v", ov)
	}

	if rec := e.req("GET", "/api/timeseries?range=7d", nil, c); rec.Code != 400 {
		t.Errorf("bad range: %d", rec.Code)
	}
	if rec := e.req("GET", "/api/timeseries", nil, c); rec.Code != 200 {
		t.Errorf("default range: %d", rec.Code)
	}

	rec := e.req("GET", "/api/logs?decision=limited&route_id=r1&consumer_id=c1&policy_id=p1&status_min=400&status_max=499&q=foo&before=abc&limit=5000", nil, c)
	if rec.Code != 200 || len(decode[struct{ Entries []model.LogEntry }](t, rec).Entries) != 1 {
		t.Fatalf("logs: %d %s", rec.Code, rec.Body)
	}
	want := model.LogQuery{Decision: "limited", RouteID: "r1", ConsumerID: "c1", PolicyID: "p1", StatusMin: 400, StatusMax: 499, Search: "foo", Before: "abc", Limit: 1000}
	if e.tel.last != want {
		t.Fatalf("query: %+v", e.tel.last)
	}
	if rec := e.req("GET", "/api/logs?status_min=abc", nil, c); rec.Code != 400 {
		t.Errorf("bad status_min: %d", rec.Code)
	}

	// Simulator passes through.
	rec = e.req("POST", "/api/simulate", model.SimRequest{Method: "GET", Path: "/api/x"}, c)
	if rec.Code != 200 || len(e.rt.sims) != 1 || e.rt.sims[0].Path != "/api/x" {
		t.Fatalf("simulate: %d", rec.Code)
	}
}

func TestLimits(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin", adminPW)
	rec := e.req("GET", "/api/limits?policy_id=p1&key=1.2.3.4", nil, c)
	out := decode[map[string]any](t, rec)
	if rec.Code != 200 || out["engine_key"] != "p1:1.2.3.4" || out["exists"] != true || out["limit"] != float64(10) || out["remaining"] != float64(7) || out["reset_s"] != float64(2) {
		t.Fatalf("peek: %d %v", rec.Code, out)
	}
	if p := e.eng.params[0]; p.Algorithm != model.AlgoTokenBucket || p.Limit != 10 || p.Window != time.Minute {
		t.Fatalf("params: %+v", p)
	}
	for _, q := range []string{"?policy_id=p1", "?key=x", "?policy_id=nope&key=x", "?policy_id=p1&key=" + strings.Repeat("k", 2000)} {
		if rec := e.req("GET", "/api/limits"+q, nil, c); rec.Code != 400 && rec.Code != 404 {
			t.Errorf("%s: %d", q, rec.Code)
		}
	}
	rec = e.req("POST", "/api/limits/reset", map[string]any{"policy_id": "p1", "key": "1.2.3.4"}, c)
	if rec.Code != 200 || len(e.eng.resets) != 1 || e.eng.resets[0] != "p1:1.2.3.4" {
		t.Fatalf("reset: %d %v", rec.Code, e.eng.resets)
	}
	noEng := newEnv(t, func(o *Options) { o.Engine = nil })
	if rec := noEng.req("GET", "/api/limits?policy_id=p1&key=x", nil, noEng.login("admin", adminPW)); rec.Code != 503 {
		t.Fatalf("no engine: %d", rec.Code)
	}
}

func TestWatchAppliesNewer(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.s.Start(ctx)
	older := seedSnapshot()
	older.Version = 1
	e.store.watch <- older
	newer := seedSnapshot()
	newer.Version = 5
	e.store.watch <- newer
	e.store.watch <- older // sync point: previous callbacks completed
	if e.rt.Current().Version != 5 || e.rt.applies != 1 {
		t.Fatalf("version %d applies %d", e.rt.Current().Version, e.rt.applies)
	}
}

func TestConcurrentMutations(t *testing.T) {
	e := newEnv(t)
	tok := e.token("ci", ScopeAdmin)
	var wg sync.WaitGroup
	for i := range 25 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := e.req("POST", "/api/plans", map[string]any{"name": "plan " + itoa64(int64(i))}, cred{bearer: tok})
			if rec.Code != 201 {
				t.Errorf("%d %s", rec.Code, rec.Body)
			}
		}()
	}
	wg.Wait()
	cur := e.rt.Current()
	if len(cur.Plans) != 27 || cur.Version != 26 || e.store.saves != 25 {
		t.Fatalf("plans=%d version=%d saves=%d", len(cur.Plans), cur.Version, e.store.saves)
	}
}

func TestSlugID(t *testing.T) {
	for in, prefix := range map[string]string{"Free Tier": "free-tier-", "  ##Pro!! plan ": "pro-plan-", "": "policy-", "日本": "policy-", strings.Repeat("ab ", 40): strings.Repeat("ab-", 16) + "ab-"} {
		got := slugID(in, "policy")
		if !strings.HasPrefix(got, prefix) || !regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`).MatchString(got) {
			t.Errorf("%q → %q", in, got)
		}
	}
}

// ---- SSE ----

func TestLogStream(t *testing.T) {
	e := newEnv(t)
	e.s.heartbeat = 20 * time.Millisecond
	srv := httptest.NewServer(e.h)
	defer srv.Close()
	c := e.login("admin", adminPW)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/logs/stream?decision=limited", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.cookie})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" || resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("headers: %d %v", resp.StatusCode, resp.Header)
	}
	waitFor(t, func() bool { return e.tel.subscribers() == 1 })
	e.tel.publish(model.LogEntry{ID: "a", Decision: "allowed", Path: "/skip"})
	e.tel.publish(model.LogEntry{ID: "b", Decision: "limited", Path: "/hit"})

	br := bufio.NewReader(resp.Body)
	var event, data string
	sawHeartbeat := false
	for data == "" {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimSpace(line[7:])
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimSpace(line[6:])
		case strings.HasPrefix(line, ": heartbeat"):
			sawHeartbeat = true
		}
	}
	var got model.LogEntry
	if event != "log" || json.Unmarshal([]byte(data), &got) != nil || got.ID != "b" {
		t.Fatalf("event=%q data=%q", event, data)
	}
	for !sawHeartbeat {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		sawHeartbeat = strings.HasPrefix(line, ": heartbeat")
	}
	// Client disconnect unsubscribes (handler honours request context).
	cancel()
	waitFor(t, func() bool { return e.tel.subscribers() == 0 })
}

func TestLogStreamEndsOnLogout(t *testing.T) {
	e := newEnv(t)
	e.s.heartbeat = 10 * time.Millisecond
	srv := httptest.NewServer(e.h)
	defer srv.Close()
	c := e.login("admin", adminPW)
	req, _ := http.NewRequest("GET", srv.URL+"/api/logs/stream", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.cookie})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	waitFor(t, func() bool { return e.tel.subscribers() == 1 })
	if rec := e.req("POST", "/api/auth/logout", nil, c); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	waitFor(t, func() bool { return e.tel.subscribers() == 0 })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestMatchesFilter(t *testing.T) {
	e := model.LogEntry{Decision: "limited", RouteID: "r1", ConsumerID: "c1", PolicyID: "p1", Status: 429, Path: "/v1/Orders", ClientIP: "1.2.3.4", ConsumerName: "Acme"}
	cases := []struct {
		q    model.LogQuery
		want bool
	}{
		{model.LogQuery{}, true},
		{model.LogQuery{Decision: "allowed"}, false},
		{model.LogQuery{RouteID: "r1", PolicyID: "p1", ConsumerID: "c1"}, true},
		{model.LogQuery{StatusMin: 500}, false},
		{model.LogQuery{StatusMax: 428}, false},
		{model.LogQuery{StatusMin: 400, StatusMax: 499}, true},
		{model.LogQuery{Search: "orders"}, true},
		{model.LogQuery{Search: "acme"}, true},
		{model.LogQuery{Search: "1.2.3"}, true},
		{model.LogQuery{Search: "zzz"}, false},
	}
	for i, c := range cases {
		if matches(c.q, e) != c.want {
			t.Errorf("case %d: %+v", i, c.q)
		}
	}
}

func TestLogStreamPerPrincipalCap(t *testing.T) {
	e := newEnv(t)
	srv := httptest.NewServer(e.h)
	defer srv.Close()
	c := e.login("admin", adminPW)
	open := func(cookie, bearer string) *http.Response {
		req, _ := http.NewRequest("GET", srv.URL+"/api/logs/stream", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	var held []*http.Response
	defer func() {
		for _, r := range held {
			r.Body.Close()
		}
	}()
	for i := range maxSSEStreamsPerPrincipal {
		r := open(c.cookie, "")
		held = append(held, r)
		if r.StatusCode != 200 {
			t.Fatalf("stream %d: %d", i, r.StatusCode)
		}
	}
	// Another session of the same user counts toward the same cap.
	if r := open(e.login("admin", adminPW).cookie, ""); r.StatusCode != 429 {
		r.Body.Close()
		t.Fatalf("5th stream: %d", r.StatusCode)
	}
	// A different principal is unaffected.
	r := open("", e.token("ro", ScopeRead))
	held = append(held, r)
	if r.StatusCode != 200 {
		t.Fatalf("other principal: %d", r.StatusCode)
	}
	// Closing a stream frees a slot.
	held[0].Body.Close()
	held = held[1:]
	waitFor(t, func() bool { return e.tel.subscribers() == maxSSEStreamsPerPrincipal })
	r = open(c.cookie, "")
	held = append(held, r)
	if r.StatusCode != 200 {
		t.Fatalf("after close: %d", r.StatusCode)
	}
}
