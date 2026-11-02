package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
)

const aliceKey = "rlg_live_alice0000000000000000000000"

func authEnv(t *testing.T, mut ...func(*model.Snapshot)) *env {
	up := upstream(t, "u")
	return newEnv(t, func(s *model.Snapshot) {
		authSnapshot(up.URL)(s)
		s.Policies = append(s.Policies, pol("ip2", model.AlgoFixedWindow, 2, "ip"))
		s.Routes = append(s.Routes,
			route("lim", up.URL, "/lim", "ip2"),
			route("other", up.URL, "/other", "ip2"))
		s.Settings.TrustedProxies = []string{"10.0.0.0/8"}
		for _, m := range mut {
			m(s)
		}
	})
}

func (e *env) auth(target string, mut ...func(*http.Request)) *httptest.ResponseRecorder {
	return e.do("GET", target, mut...)
}

func fwd(method, uri string) func(*http.Request) {
	return func(r *http.Request) {
		r.Header.Set("X-Forwarded-Method", method)
		r.Header.Set("X-Forwarded-Uri", uri)
	}
}

func TestForwardAuthDecisions(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		mut      []func(*http.Request)
		want     int
		consumer string
	}{
		{"allowed with key", "/_rlg/v1/auth", []func(*http.Request){fwd("GET", "/req/x"), hdr("X-API-Key", aliceKey)}, 200, "alice"},
		{"allowed no key optional route", "/_rlg/v1/auth", []func(*http.Request){fwd("GET", "/opt/x")}, 200, ""},
		{"missing key", "/_rlg/v1/auth", []func(*http.Request){fwd("GET", "/req/x")}, 401, ""},
		{"bad key", "/_rlg/v1/auth", []func(*http.Request){fwd("GET", "/req/x"), hdr("X-API-Key", "rlg_live_nope")}, 401, ""},
		{"no route", "/_rlg/v1/auth", []func(*http.Request){fwd("GET", "/nothing")}, 404, ""},
		{"bad path encoded slash", "/_rlg/v1/auth", []func(*http.Request){fwd("GET", "/opt%2Fx")}, 400, ""},
		{"bad path backslash", "/_rlg/v1/auth", []func(*http.Request){fwd("GET", `/opt\x`)}, 400, ""},
		{"traversal normalised", "/_rlg/v1/auth", []func(*http.Request){fwd("GET", "/opt/../req/x"), hdr("X-API-Key", aliceKey)}, 200, "alice"},
		{"traversal to unmatched", "/_rlg/v1/auth", []func(*http.Request){fwd("GET", "/opt/../../nothing")}, 404, ""},
		{"x-original-uri alias", "/_rlg/v1/auth", []func(*http.Request){hdr("X-Original-URI", "/req/x"), hdr("X-API-Key", aliceKey)}, 200, "alice"},
		{"default uri is /", "/_rlg/v1/auth", nil, 404, ""},
		{"route_id override", "/_rlg/v1/auth?route_id=opt", []func(*http.Request){fwd("GET", "/nothing")}, 200, ""},
		{"route_id unknown", "/_rlg/v1/auth?route_id=zzz", []func(*http.Request){fwd("GET", "/opt/x")}, 404, ""},
		{"authorization bearer key", "/_rlg/v1/auth", []func(*http.Request){fwd("GET", "/req"), hdr("Authorization", "Bearer "+aliceKey)}, 200, "alice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := authEnv(t)
			rr := e.auth(tc.target, tc.mut...)
			if rr.Code != tc.want {
				t.Fatalf("got %d %s, want %d", rr.Code, rr.Body, tc.want)
			}
			if tc.want == 200 {
				if rr.Body.Len() != 0 {
					t.Errorf("200 body must be empty, got %q", rr.Body)
				}
				if got := rr.Header().Get("X-RateGuard-Consumer"); got != tc.consumer {
					t.Errorf("consumer header = %q, want %q", got, tc.consumer)
				}
				if rr.Header().Get("RateLimit-Limit") == "" || rr.Header().Get("RateLimit-Remaining") == "" {
					t.Errorf("missing RateLimit headers: %v", rr.Header())
				}
			}
			if tc.want == 400 {
				return // rejected before routing, like the proxy: not logged
			}
			if le := e.rec.last(t); le.Source != "forward_auth" {
				t.Errorf("source = %q", le.Source)
			}
		})
	}
}

func TestForwardAuthEnvoyPrefixForm(t *testing.T) {
	e := authEnv(t)
	// Envoy ext_authz: original method+path appended to path_prefix.
	rr := e.do("POST", "/_rlg/v1/auth/req/x?a=1", hdr("X-API-Key", aliceKey))
	if rr.Code != 200 || rr.Header().Get("X-RateGuard-Consumer") != "alice" {
		t.Fatalf("got %d %v", rr.Code, rr.Header())
	}
	if le := e.rec.last(t); le.Method != "POST" || le.Path != "/req/x" {
		t.Errorf("log %+v", le)
	}
	// A client-controlled query string must not pick the route.
	if rr := e.do("GET", "/_rlg/v1/auth/req/x?route_id=opt"); rr.Code != 401 {
		t.Errorf("route_id must be ignored in prefix form: %d", rr.Code)
	}
	if rr := e.do("GET", "/_rlg/v1/auth/%2e%2e/%2e%2e/nothing"); rr.Code != 404 && rr.Code != 400 {
		t.Errorf("got %d", rr.Code)
	}
}

func TestForwardAuthMethodHostPassthrough(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		s.Policies = []model.Policy{pol("p", model.AlgoFixedWindow, 100, "global")}
		s.Routes = []model.Route{{ID: "post", Name: "P", Match: model.RouteMatch{Host: "api.acme.com", PathPrefix: "/w", Methods: []string{"POST"}},
			Upstream: up.URL, PolicyIDs: []string{"p"}, Enabled: true}}
	})
	if rr := e.auth("/_rlg/v1/auth", fwd("GET", "/w/x"), hdr("X-Forwarded-Host", "api.acme.com")); rr.Code != 404 {
		t.Errorf("GET should not match POST route: %d", rr.Code)
	}
	if rr := e.auth("/_rlg/v1/auth", fwd("POST", "/w/x")); rr.Code != 404 {
		t.Errorf("host should not match: %d", rr.Code)
	}
	rr := e.do("PUT", "/_rlg/v1/auth", fwd("post", "/w/x"), hdr("X-Forwarded-Host", "api.acme.com"))
	if rr.Code != 200 {
		t.Errorf("POST via forwarded host: %d %s", rr.Code, rr.Body)
	}
	if le := e.rec.last(t); le.Method != "POST" || le.Host != "api.acme.com" || le.Path != "/w/x" {
		t.Errorf("log entry %+v", le)
	}
}

func TestForwardAuthLimited(t *testing.T) {
	e := authEnv(t)
	for i := 0; i < 2; i++ {
		if rr := e.auth("/_rlg/v1/auth", fwd("GET", "/lim")); rr.Code != 200 {
			t.Fatalf("req %d: %d", i, rr.Code)
		}
	}
	rr := e.auth("/_rlg/v1/auth", fwd("GET", "/lim"))
	if rr.Code != 429 {
		t.Fatalf("got %d", rr.Code)
	}
	m := jsonBody(t, rr)
	if m["error"] != "rate_limited" {
		t.Errorf("body %v", m)
	}
	if rr.Header().Get("Retry-After") == "" || rr.Header().Get("RateLimit-Remaining") != "0" {
		t.Errorf("headers %v", rr.Header())
	}
	if le := e.rec.last(t); le.Decision != model.DecisionLimited || le.Source != "forward_auth" || le.Status != 429 {
		t.Errorf("log %+v", le)
	}
}

func TestForwardAuthClientIP(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		xff    string
		realIP string
		// second request from "other" client: allowed only if ip keys differ
		wantIP string
	}{
		{"untrusted peer ignores XFF", "192.0.2.10:1", "198.51.100.7", "", "192.0.2.10"},
		{"untrusted peer ignores X-Real-IP", "192.0.2.10:1", "", "198.51.100.7", "192.0.2.10"},
		{"trusted peer uses XFF", "10.1.1.1:1", "198.51.100.7", "", "198.51.100.7"},
		{"trusted peer XFF chain skips trusted hop", "10.1.1.1:1", "198.51.100.7, 10.2.2.2", "", "198.51.100.7"},
		{"trusted peer uses X-Real-IP", "10.1.1.1:1", "", "198.51.100.9", "198.51.100.9"},
		{"trusted peer no headers", "10.1.1.1:1", "", "", "10.1.1.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := authEnv(t)
			muts := []func(*http.Request){fwd("GET", "/lim"), remote(tc.remote)}
			if tc.xff != "" {
				muts = append(muts, hdr("X-Forwarded-For", tc.xff))
			}
			if tc.realIP != "" {
				muts = append(muts, hdr("X-Real-IP", tc.realIP))
			}
			if rr := e.auth("/_rlg/v1/auth", muts...); rr.Code != 200 {
				t.Fatal(rr.Code)
			}
			if le := e.rec.last(t); le.ClientIP != tc.wantIP {
				t.Errorf("client ip = %q, want %q", le.ClientIP, tc.wantIP)
			}
		})
	}
}

func TestForwardAuthToken(t *testing.T) {
	cases := []struct {
		name    string
		require bool
		token   string
		want    int
	}{
		{"not required, none", false, "", 200},
		{"not required, garbage ignored", false, "nope", 200},
		{"required, none", true, "", 401},
		{"required, bad", true, "nope", 401},
		{"required, wrong scope", true, "adm", 401},
		{"required, good", true, "chk", 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := authEnv(t, func(s *model.Snapshot) { s.Settings.ForwardAuthRequireToken = tc.require })
			var muts []func(*http.Request)
			muts = append(muts, fwd("GET", "/opt/x"))
			if tc.token != "" {
				muts = append(muts, hdr("X-RateGuard-Auth-Token", tc.token))
			}
			if rr := e.auth("/_rlg/v1/auth", muts...); rr.Code != tc.want {
				t.Errorf("got %d %s", rr.Code, rr.Body)
			}
		})
	}
}

func TestForwardAuthDisabled(t *testing.T) {
	e := authEnv(t, func(s *model.Snapshot) { s.Settings.ForwardAuthDisabled = true })
	if rr := e.auth("/_rlg/v1/auth", fwd("GET", "/opt/x")); rr.Code != 404 {
		t.Errorf("got %d", rr.Code)
	}
}

func TestForwardAuthSkipsConcurrency(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		s.Policies = []model.Policy{pol("conc", model.AlgoConcurrency, 1, "global")}
		s.Routes = []model.Route{route("r", up.URL, "/", "conc")}
	})
	for i := 0; i < 3; i++ {
		if rr := e.auth("/_rlg/v1/auth", fwd("GET", "/x")); rr.Code != 200 {
			t.Fatalf("req %d: %d", i, rr.Code)
		}
	}
}

func TestForwardAuthLeakyWaits(t *testing.T) {
	e := newShapeEnv(t, leaky("lb", 10, time.Second, 3)) // 1 per 100ms
	do := func(ctx context.Context) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/_rlg/v1/auth", nil).WithContext(ctx)
		r.Header.Set("X-Forwarded-Uri", "/x")
		r.RemoteAddr = "192.0.2.10:5555"
		rr := httptest.NewRecorder()
		e.g.ServeHTTP(rr, r)
		return rr
	}
	start := time.Now()
	for i := 0; i < 3; i++ {
		if rr := do(context.Background()); rr.Code != 200 {
			t.Fatalf("req %d: %d %s", i, rr.Code, rr.Body)
		}
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Errorf("leaky bucket should delay server-side, took %v", d)
	}
	if e.g.shapeWaiters.Load() != 0 {
		t.Errorf("waiter slots leaked: %d", e.g.shapeWaiters.Load())
	}
	// A cancelled caller is not admitted and gives its slot back.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 3; i++ {
		do(ctx)
	}
	if e.g.shapeWaiters.Load() != 0 {
		t.Errorf("waiter slots leaked after cancel: %d", e.g.shapeWaiters.Load())
	}
}
