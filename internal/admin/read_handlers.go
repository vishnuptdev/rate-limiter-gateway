package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"net/http"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/ratelimit"
)

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func ceilSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(math.Ceil(d.Seconds()))
}

var errNoTelemetry = &apiError{Status: http.StatusServiceUnavailable, Code: "telemetry_unavailable", Message: "telemetry is not configured"}

// ---------------------------------------------------------------------
// System / overview / timeseries / logs
// ---------------------------------------------------------------------

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request, _ *principal) {
	engine := map[string]any{"name": "", "healthy": false}
	if s.o.Engine != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		err := s.o.Engine.Healthy(ctx)
		cancel()
		engine["name"] = s.o.Engine.Name()
		engine["healthy"] = err == nil
		if err != nil {
			// Raw backend errors (addresses, auth failures) stay in the log.
			engine["error"] = "unhealthy"
			s.log.Warn("engine health check failed", "err", err)
		}
	}
	now := s.now()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":         s.o.Version,
		"go_version":      runtime.Version(),
		"instance_id":     s.o.InstanceID,
		"started_at":      s.started.UTC(),
		"uptime_s":        int64(now.Sub(s.started).Seconds()),
		"engine":          engine,
		"store":           map[string]any{"name": s.o.Store.Name()},
		"config_version":  s.mgr.current().Version,
		"data_plane_addr": s.o.DataPlaneAddr,
		"admin_addr":      s.o.AdminAddr,
	})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request, _ *principal) {
	var ov model.Overview
	if s.o.Telemetry != nil {
		ov = s.o.Telemetry.Overview()
	}
	out := map[string]any{}
	_ = json.Unmarshal([]byte(mustJSON(ov)), &out)
	snap := s.mgr.current()
	out["counts"] = map[string]int{
		"routes": len(snap.Routes), "policies": len(snap.Policies),
		"plans": len(snap.Plans), "consumers": len(snap.Consumers),
	}
	writeJSON(w, http.StatusOK, out)
}

var timeseriesRanges = map[string]time.Duration{"15m": 15 * time.Minute, "1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour}

func (s *Server) handleTimeseries(w http.ResponseWriter, r *http.Request, _ *principal) {
	if s.o.Telemetry == nil {
		writeErr(w, errNoTelemetry)
		return
	}
	rs := r.URL.Query().Get("range")
	if rs == "" {
		rs = "1h"
	}
	rng, ok := timeseriesRanges[rs]
	if !ok {
		writeErr(w, badRequest("range must be one of 15m, 1h, 6h, 24h"))
		return
	}
	writeJSON(w, http.StatusOK, s.o.Telemetry.Timeseries(rng, r.URL.Query().Get("route_id")))
}

// parseLogQuery maps query parameters to a LogQuery (limit capped at 1000).
func parseLogQuery(r *http.Request) (model.LogQuery, *apiError) {
	q := r.URL.Query()
	lq := model.LogQuery{
		Decision:   q.Get("decision"),
		RouteID:    q.Get("route_id"),
		ConsumerID: q.Get("consumer_id"),
		PolicyID:   q.Get("policy_id"),
		Search:     q.Get("q"),
		Before:     q.Get("before"),
	}
	if len(lq.Search) > 256 {
		return lq, badRequest("q too long")
	}
	for _, f := range []struct {
		name string
		dst  *int
	}{{"status_min", &lq.StatusMin}, {"status_max", &lq.StatusMax}, {"limit", &lq.Limit}} {
		if v := q.Get(f.name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return lq, badRequest(f.name + " must be a non-negative integer")
			}
			*f.dst = n
		}
	}
	if lq.Limit == 0 {
		lq.Limit = 100
	}
	lq.Limit = min(lq.Limit, 1000)
	return lq, nil
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request, _ *principal) {
	if s.o.Telemetry == nil {
		writeErr(w, errNoTelemetry)
		return
	}
	lq, e := parseLogQuery(r)
	if e != nil {
		writeErr(w, e)
		return
	}
	entries := s.o.Telemetry.QueryLogs(lq)
	if entries == nil {
		entries = []model.LogEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// matches applies a LogQuery's filters to a single live entry.
func matches(q model.LogQuery, e model.LogEntry) bool {
	if q.Decision != "" && e.Decision != q.Decision ||
		q.RouteID != "" && e.RouteID != q.RouteID ||
		q.ConsumerID != "" && e.ConsumerID != q.ConsumerID ||
		q.PolicyID != "" && e.PolicyID != q.PolicyID ||
		q.StatusMin > 0 && e.Status < q.StatusMin ||
		q.StatusMax > 0 && e.Status > q.StatusMax {
		return false
	}
	if q.Search != "" {
		needle := strings.ToLower(q.Search)
		for _, h := range []string{e.Path, e.ClientIP, e.RateKey, e.ConsumerName} {
			if strings.Contains(strings.ToLower(h), needle) {
				return true
			}
		}
		return false
	}
	return true
}

func (s *Server) handleLogStream(w http.ResponseWriter, r *http.Request, p *principal) {
	if s.o.Telemetry == nil {
		writeErr(w, errNoTelemetry)
		return
	}
	lq, e := parseLogQuery(r)
	if e != nil {
		writeErr(w, e)
		return
	}
	select {
	case s.sseSem <- struct{}{}:
		defer func() { <-s.sseSem }()
	default:
		writeErr(w, &apiError{Status: http.StatusServiceUnavailable, Code: "too_many_streams", Message: "too many live log streams"})
		return
	}
	pid := p.kind + ":" + p.name
	if p.kind == "token" {
		pid = "token:" + p.tokenID
	}
	if !s.acquireStream(pid) {
		writeErr(w, &apiError{Status: http.StatusTooManyRequests, Code: "too_many_streams", Message: "too many live log streams for this user"})
		return
	}
	defer s.releaseStream(pid)
	rc := http.NewResponseController(w)
	ch, cancel := s.o.Telemetry.Subscribe(256)
	defer cancel()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	write := func(b []byte) bool {
		// Per-write deadline: the admin server's WriteTimeout must not kill
		// a healthy stream, but a stuck client must not hold it forever.
		_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := w.Write(b); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !write([]byte("retry: 3000\n: connected\n\n")) {
		return
	}
	tick := time.NewTicker(s.heartbeat)
	defer tick.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			// Re-check credentials so logout/revocation ends the stream.
			if !s.still(p) || !write([]byte(": heartbeat\n\n")) {
				return
			}
		case ent, ok := <-ch:
			if !ok {
				return
			}
			if !matches(lq, ent) {
				continue
			}
			b, err := json.Marshal(ent)
			if err != nil {
				continue
			}
			msg := make([]byte, 0, len(b)+20)
			msg = append(msg, "event: log\ndata: "...)
			msg = append(msg, b...)
			msg = append(msg, "\n\n"...)
			if !write(msg) {
				return
			}
		}
	}
}

func (s *Server) acquireStream(pid string) bool {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	if s.sseByID[pid] >= maxSSEStreamsPerPrincipal {
		return false
	}
	s.sseByID[pid]++
	return true
}

func (s *Server) releaseStream(pid string) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	if s.sseByID[pid]--; s.sseByID[pid] <= 0 {
		delete(s.sseByID, pid)
	}
}

// ---------------------------------------------------------------------
// Simulator and limits inspector
// ---------------------------------------------------------------------

func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request, p *principal) {
	var req model.SimRequest
	if e := decodeJSON(w, r, &req, maxBody, false); e != nil {
		writeErr(w, e)
		return
	}
	if req.Consume && p.rank < rankEditor {
		writeErr(w, &apiError{Status: http.StatusForbidden, Code: "forbidden", Message: "consume=true requires the editor role"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.o.Runtime.Simulate(ctx, req))
}

const maxLimitKey = 1024

func (s *Server) limitTarget(policyID, key string) (model.Policy, ratelimit.Params, string, *apiError) {
	if s.o.Engine == nil {
		return model.Policy{}, ratelimit.Params{}, "", &apiError{Status: http.StatusServiceUnavailable, Code: "engine_unavailable", Message: "rate-limit engine is not configured"}
	}
	if policyID == "" || key == "" {
		return model.Policy{}, ratelimit.Params{}, "", badRequest("policy_id and key are required")
	}
	if len(key) > maxLimitKey {
		return model.Policy{}, ratelimit.Params{}, "", badRequest("key too long")
	}
	snap := s.mgr.current()
	i := find(policyKind, snap, policyID)
	if i < 0 {
		return model.Policy{}, ratelimit.Params{}, "", notFound("policy")
	}
	pol := snap.Policies[i]
	params := ratelimit.Params{Algorithm: pol.Algorithm, Limit: pol.Limit, Window: pol.Window.D(), Burst: pol.Burst, Cost: pol.Cost}
	return pol, params, s.o.Runtime.EngineKey(pol.ID, key), nil
}

func (s *Server) handlePeekLimit(w http.ResponseWriter, r *http.Request, _ *principal) {
	q := r.URL.Query()
	pol, params, ekey, e := s.limitTarget(q.Get("policy_id"), q.Get("key"))
	if e != nil {
		writeErr(w, e)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	d, exists, err := s.o.Engine.Peek(ctx, ekey, params)
	if err != nil {
		s.log.Error("engine peek failed", "err", err)
		writeErr(w, &apiError{Status: http.StatusBadGateway, Code: "engine_error", Message: "rate-limit engine error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policy_id": pol.ID, "key": q.Get("key"), "engine_key": ekey, "exists": exists,
		"limit": d.Limit, "remaining": d.Remaining, "reset_s": ceilSeconds(d.ResetAfter),
	})
}

func (s *Server) handleResetLimit(w http.ResponseWriter, r *http.Request, p *principal) {
	var req struct {
		PolicyID string `json:"policy_id"`
		Key      string `json:"key"`
	}
	if e := decodeJSON(w, r, &req, maxBody, false); e != nil {
		writeErr(w, e)
		return
	}
	pol, params, ekey, e := s.limitTarget(req.PolicyID, req.Key)
	if e != nil {
		writeErr(w, e)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.o.Engine.Reset(ctx, ekey, params); err != nil {
		s.log.Error("engine reset failed", "err", err)
		writeErr(w, &apiError{Status: http.StatusBadGateway, Code: "engine_error", Message: "rate-limit engine error"})
		return
	}
	s.record(r, p, "limits.reset", "policy", pol.ID, "reset limit for key "+quote(req.Key))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "policy_id": pol.ID, "key": req.Key, "engine_key": ekey})
}

// ---------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, _ *principal) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeErr(w, badRequest("limit must be a positive integer"))
			return
		}
		limit = min(n, 1000)
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.audit.query(limit, r.URL.Query().Get("before"))})
}

// ---------------------------------------------------------------------
// Prometheus
// ---------------------------------------------------------------------

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.o.MetricsPublic {
		p, aerr := s.authenticate(r)
		if aerr != nil {
			writeErr(w, aerr)
			return
		}
		if p == nil {
			writeErr(w, errUnauthenticated)
			return
		}
		if p.mustChange || p.rank < rankViewer {
			writeErr(w, &apiError{Status: http.StatusForbidden, Code: "forbidden", Message: "insufficient permissions"})
			return
		}
	}
	if s.o.Telemetry == nil {
		writeErr(w, errNoTelemetry)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.o.Telemetry.WritePrometheus(w)
}

// ---------------------------------------------------------------------
// Dashboard (SPA)
// ---------------------------------------------------------------------

const placeholderHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>RateGuard</title></head>
<body><h1>RateGuard admin</h1><p>The dashboard assets are not bundled in this build. The API is available under /api.</p></body></html>
`

func (s *Server) staticHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.o.StaticFS == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			_, _ = w.Write([]byte(placeholderHTML))
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name != "" && name != "index.html" {
			if fi, err := fs.Stat(s.o.StaticFS, name); err == nil && !fi.IsDir() {
				http.ServeFileFS(w, r, s.o.StaticFS, name)
				return
			} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			// Missing asset-like paths (with an extension) are real 404s so a
			// broken <script src> does not silently receive HTML.
			if path.Ext(name) != "" {
				http.NotFound(w, r)
				return
			}
		}
		// SPA fallback: serve index.html for client-side routes.
		b, err := fs.ReadFile(s.o.StaticFS, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(b)
	})
}
