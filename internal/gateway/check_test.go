package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ratelimitergateway/internal/model"
)

func checkEnv(t *testing.T) *env {
	up := upstream(t, "u")
	return newEnv(t, func(s *model.Snapshot) {
		authSnapshot(up.URL)(s)
		sh := pol("sh", model.AlgoFixedWindow, 1, "ip")
		sh.Mode = model.ModeShadow
		s.Policies = []model.Policy{
			pol("p", model.AlgoFixedWindow, 3, "consumer"),
			pol("conc", model.AlgoConcurrency, 1, "global"),
			sh,
		}
		s.Routes = []model.Route{
			{ID: "api", Name: "API", Match: model.RouteMatch{Host: "api.acme.com", PathPrefix: "/v1"}, Upstream: up.URL, PolicyIDs: []string{"p", "conc"}, Enabled: true},
			{ID: "shadowed", Name: "S", Match: model.RouteMatch{PathPrefix: "/shadow"}, Upstream: up.URL, PolicyIDs: []string{"sh"}, Enabled: true},
			{ID: "needkey", Name: "N", Match: model.RouteMatch{PathPrefix: "/needkey"}, Upstream: up.URL, PolicyIDs: []string{"p"}, RequireAPIKey: true, Enabled: true},
		}
	})
}

func (e *env) check(t *testing.T, token string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	switch b := body.(type) {
	case string:
		buf.WriteString(b)
	default:
		json.NewEncoder(&buf).Encode(b)
	}
	r := httptest.NewRequest("POST", "/_rlg/v1/check", &buf)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	e.g.ServeHTTP(rr, r)
	var m map[string]any
	json.Unmarshal(rr.Body.Bytes(), &m)
	return rr, m
}

func TestCheckAuth(t *testing.T) {
	e := checkEnv(t)
	for _, tc := range []struct {
		name, token string
	}{{"no token", ""}, {"unknown token", "nope"}, {"wrong scope", "adm"}} {
		t.Run(tc.name, func(t *testing.T) {
			rr, m := e.check(t, tc.token, map[string]any{"path": "/v1/x"})
			if rr.Code != 401 || m["error"] != "unauthorized" {
				t.Errorf("got %d %s", rr.Code, rr.Body)
			}
		})
	}
	// Non-Bearer scheme is rejected.
	r := httptest.NewRequest("POST", "/_rlg/v1/check", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Basic chk")
	rr := httptest.NewRecorder()
	e.g.ServeHTTP(rr, r)
	if rr.Code != 401 {
		t.Errorf("basic auth: %d", rr.Code)
	}
	// No verifier configured => nobody is allowed.
	g := New(Options{Engine: newFake()})
	g.Apply(model.NewSnapshot())
	rr = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/_rlg/v1/check", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer chk")
	g.ServeHTTP(rr, r)
	if rr.Code != 401 {
		t.Errorf("nil verifier: %d", rr.Code)
	}
	// Method + bad body + disabled.
	rr = e.do("GET", "/_rlg/v1/check")
	if rr.Code != 405 {
		t.Errorf("GET: %d", rr.Code)
	}
	if rr, _ := e.check(t, "chk", "{not json"); rr.Code != 400 {
		t.Errorf("bad json: %d", rr.Code)
	}
	if rr, _ := e.check(t, "chk", map[string]any{"cost": -1}); rr.Code != 400 {
		t.Errorf("negative cost: %d", rr.Code)
	}
	if rr, _ := e.check(t, "chk", map[string]any{"ip": "not-an-ip"}); rr.Code != 400 {
		t.Errorf("bad ip: %d", rr.Code)
	}
	s := e.g.Current().Clone()
	s.Settings.CheckAPIEnabled = false
	s.Version++
	e.g.Apply(s)
	if rr, _ := e.check(t, "chk", map[string]any{"path": "/v1/x"}); rr.Code != 404 {
		t.Errorf("disabled: %d", rr.Code)
	}
}

func TestCheckDecisions(t *testing.T) {
	e := checkEnv(t)
	const alice = "rlg_live_alice0000000000000000000000"
	req := map[string]any{"method": "GET", "host": "api.acme.com", "path": "/v1/orders?x=1", "api_key": alice, "ip": "1.2.3.4"}

	rr, m := e.check(t, "chk", req)
	if rr.Code != 200 || m["allowed"] != true || m["decision"] != "allowed" || m["route_id"] != "api" || m["consumer_id"] != "alice" ||
		m["policy_id"] != "p" || m["limit"] != 3.0 || m["remaining"] != 2.0 || m["reset_s"] != 30.0 {
		t.Fatalf("first: %d %s", rr.Code, rr.Body)
	}
	h := m["headers"].(map[string]any)
	if h["RateLimit-Limit"] != "3" || h["RateLimit-Remaining"] != "2" || h["RateLimit-Policy"] != "3;w=60" {
		t.Errorf("headers %v", h)
	}
	res := m["results"].([]any)
	if len(res) != 1 {
		t.Fatalf("concurrency policies must be skipped, results=%v", res)
	}
	if e.eng.callCount() != 1 {
		t.Errorf("engine calls %v", e.eng.calls)
	}
	// Default cost is 1; cost=2 consumes 2 (remaining 2 -> 0).
	req["cost"] = 2
	_, m = e.check(t, "chk", req)
	if m["remaining"] != 0.0 || m["allowed"] != true {
		t.Errorf("cost 2: %v", m)
	}
	delete(req, "cost")
	rr, m = e.check(t, "chk", req)
	if rr.Code != 200 {
		t.Fatalf("limited responses are still HTTP 200, got %d", rr.Code)
	}
	if m["allowed"] != false || m["decision"] != "limited" || m["remaining"] != 0.0 || m["retry_after_s"] != 3.0 {
		t.Errorf("limited: %v", m)
	}
	h = m["headers"].(map[string]any)
	if h["Retry-After"] != "3" || h["RateLimit-Remaining"] != "0" || h["RateLimit-Reset"] != "10" {
		t.Errorf("limited headers %v", h)
	}
	res = m["results"].([]any)
	if r0 := res[0].(map[string]any); r0["policy_id"] != "p" || r0["allowed"] != false || r0["shadow"] != false {
		t.Errorf("results %v", res)
	}
	if l := e.rec.last(t); l.Source != "check_api" || l.Decision != model.DecisionLimited || l.Status != 429 || strings.Contains(l.RateKey, alice) {
		t.Errorf("log %+v", l)
	}
}

func TestCheckRoutingAndEdgeCases(t *testing.T) {
	e := checkEnv(t)
	cases := []struct {
		name     string
		req      map[string]any
		decision string
		route    string
		allowed  bool
	}{
		{"explicit route_id", map[string]any{"route_id": "shadowed"}, "allowed", "shadowed", true},
		{"unknown route_id", map[string]any{"route_id": "zzz"}, "no_route", "", false},
		{"no match", map[string]any{"path": "/elsewhere"}, "no_route", "", false},
		{"host mismatch", map[string]any{"host": "evil.com", "path": "/v1/x"}, "no_route", "", false},
		{"missing required key", map[string]any{"route_id": "needkey"}, "unauthorized", "needkey", false},
		{"invalid key on optional route", map[string]any{"route_id": "api", "api_key": "bogus"}, "unauthorized", "api", false},
		{"key from headers", map[string]any{"host": "api.acme.com", "path": "/v1/z", "headers": map[string]string{"x-api-key": "rlg_live_alice0000000000000000000000"}}, "allowed", "api", true},
		{"bearer from headers", map[string]any{"route_id": "needkey", "headers": map[string]string{"Authorization": "Bearer rlg_live_alice0000000000000000000000"}}, "allowed", "needkey", true},
		{"method default GET; path default /", map[string]any{"route_id": "api"}, "allowed", "api", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr, m := e.check(t, "chk", tc.req)
			if rr.Code != 200 {
				t.Fatalf("status %d %s", rr.Code, rr.Body)
			}
			if m["decision"] != tc.decision || m["allowed"] != tc.allowed {
				t.Errorf("got %v", m)
			}
			if r, _ := m["route_id"].(string); r != tc.route {
				t.Errorf("route %q want %q", r, tc.route)
			}
			if _, ok := m["results"].([]any); !ok {
				t.Errorf("results must be an array: %v", m["results"])
			}
		})
	}
}

func TestCheckShadowAndFailClosed(t *testing.T) {
	e := checkEnv(t)
	e.check(t, "chk", map[string]any{"route_id": "shadowed", "ip": "9.9.9.9"})
	_, m := e.check(t, "chk", map[string]any{"route_id": "shadowed", "ip": "9.9.9.9"})
	if m["allowed"] != true || m["decision"] != "shadow_limited" {
		t.Errorf("shadow: %v", m)
	}
	if r0 := m["results"].([]any)[0].(map[string]any); r0["shadow"] != true || r0["allowed"] != false {
		t.Errorf("shadow result %v", r0)
	}
	e.eng.setErr(http.ErrHandlerTimeout)
	rr, m := e.check(t, "chk", map[string]any{"route_id": "api"})
	if rr.Code != 200 || m["allowed"] != false || m["decision"] != "error" || m["error"] != "limiter_unavailable" {
		t.Errorf("fail closed: %d %v", rr.Code, m)
	}
}

// ---------------------------------------------------------------------
// Simulator
// ---------------------------------------------------------------------

func TestSimulate(t *testing.T) {
	e := checkEnv(t)
	const alice = "rlg_live_alice0000000000000000000000"
	ctx := t.Context()

	if r := e.g.Simulate(ctx, model.SimRequest{Path: "/elsewhere"}); r.Matched || r.Decision != model.DecisionNoRoute || r.Policies == nil {
		t.Errorf("no route: %+v", r)
	}
	if r := e.g.Simulate(ctx, model.SimRequest{Path: "/needkey"}); r.AuthError == "" || r.Decision != model.DecisionUnauthorized || !r.Matched {
		t.Errorf("auth: %+v", r)
	}
	if r := e.g.Simulate(ctx, model.SimRequest{Path: "/v1/x", Host: "api.acme.com", Headers: map[string]string{"X-API-Key": "bad"}}); r.AuthError == "" {
		t.Errorf("invalid key: %+v", r)
	}

	before := e.eng.callCount()
	r := e.g.Simulate(ctx, model.SimRequest{Method: "get", Host: "api.acme.com:80", Path: "/v1/x", IP: "5.6.7.8", Headers: map[string]string{"x-api-key": alice}})
	if e.eng.callCount() != before {
		t.Error("non-consume simulation must not touch the engine")
	}
	if !r.Matched || r.RouteID != "api" || r.ConsumerID != "alice" || r.Decision != model.DecisionAllowed || len(r.Policies) != 2 || len(r.Notes) == 0 {
		t.Fatalf("resolve: %+v", r)
	}
	if p := r.Policies[0]; p.PolicyID != "p" || p.Limit != 3 || p.RateKey != "alice" || p.Allowed != nil || p.LimitFrom != "policy" {
		t.Errorf("policy result %+v", p)
	}

	req := model.SimRequest{Host: "api.acme.com", Path: "/v1/x", Consume: true, Headers: map[string]string{"X-API-Key": alice}}
	for i := 0; i < 3; i++ {
		r = e.g.Simulate(ctx, req)
		if r.Decision != model.DecisionAllowed || r.Policies[0].Allowed == nil || !*r.Policies[0].Allowed || r.Policies[0].Remaining != 2-i {
			t.Fatalf("consume %d: %+v", i, r)
		}
	}
	if e.eng.usedOf("conc:global") != 0 {
		t.Error("simulation leaked a concurrency slot")
	}
	r = e.g.Simulate(ctx, req)
	if r.Decision != model.DecisionLimited || *r.Policies[0].Allowed || r.Policies[0].RetryAfterMs != 2500 {
		t.Errorf("limited: %+v", r)
	}
	if r.Policies[1].Allowed != nil || len(r.Notes) == 0 {
		t.Errorf("policies after the deny must be resolve-only with a note: %+v", r)
	}
	e.eng.setErr(http.ErrHandlerTimeout)
	if r = e.g.Simulate(ctx, req); r.Decision != model.DecisionError {
		t.Errorf("fail closed: %+v", r)
	}

	g := New(Options{Engine: newFake()})
	if r := g.Simulate(ctx, model.SimRequest{}); r.Decision != model.DecisionError {
		t.Errorf("unconfigured: %+v", r)
	}
}
