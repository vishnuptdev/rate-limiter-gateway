package gateway

import (
	"net/http/httptest"
	"testing"
)

func TestForwardAuthDenyStatus(t *testing.T) {
	for _, tc := range []struct {
		query string
		want  int
	}{{"", 429}, {"?deny_status=429", 429}, {"?deny_status=403", 403}, {"?deny_status=401", 401}, {"?deny_status=500", 400}} {
		t.Run(tc.query, func(t *testing.T) {
			e := authEnv(t)
			var rr *httptest.ResponseRecorder
			for i := 0; i < 3; i++ {
				rr = e.auth("/_rlg/v1/auth"+tc.query, fwd("GET", "/lim"))
			}
			if rr.Code != tc.want {
				t.Fatalf("got %d, want %d", rr.Code, tc.want)
			}
			if tc.want != 400 && (rr.Header().Get("Retry-After") == "" || rr.Header().Get("RateLimit-Limit") == "") {
				t.Errorf("headers missing: %v", rr.Header())
			}
		})
	}
	// Envoy form: the client's query string must not choose the deny status.
	e := authEnv(t)
	var rr *httptest.ResponseRecorder
	for i := 0; i < 3; i++ {
		rr = e.do("GET", "/_rlg/v1/auth/lim?deny_status=403")
	}
	if rr.Code != 429 {
		t.Errorf("deny_status must be ignored in prefix form: %d", rr.Code)
	}
}

func TestForwardAuthPrefixTraversal(t *testing.T) {
	e := authEnv(t)
	// ".." segments are resolved before routing, so they cannot climb out of
	// the reserved prefix into another reserved endpoint or leave it.
	for _, p := range []string{"/_rlg/v1/auth/../../lim", "/_rlg/v1/auth/%2e%2e/%2e%2e/lim", "/_rlg/v1/auth/a/../../../lim"} {
		rr := e.do("GET", p)
		for _, le := range e.rec.all() {
			if le.Source == "forward_auth" {
				t.Errorf("%s reached forward auth: %d", p, rr.Code)
			}
		}
		if rr.Code == 200 {
			t.Errorf("%s: got 200", p)
		}
	}
	// Inside the prefix, the path is cleaned before matching.
	if rr := e.do("GET", "/_rlg/v1/auth/lim/../req"); rr.Code != 401 {
		t.Errorf("want 401 for /req (key required), got %d", rr.Code)
	}
}
