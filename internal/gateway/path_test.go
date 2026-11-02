package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"ratelimitergateway/internal/model"
)

func TestPathNormalisation(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		authSnapshot(up.URL)(s)
		pub := route("pub", up.URL+"/mnt", "/public")
		pub.StripPrefix = true
		adm := route("adm", up.URL, "/admin", "p")
		adm.RequireAPIKey = true
		s.Routes = []model.Route{pub, adm}
	})
	cases := []struct {
		name, target string
		code         int
		wantPath     string // path seen by upstream when 200
	}{
		{"dotdot to protected route", "/public/../admin", 401, ""},
		{"encoded dotdot", "/public/%2e%2e/admin", 401, ""},
		{"encoded dotdot upper", "/public/%2E%2E/admin/x", 401, ""},
		{"escape upstream mount", "/public/../../etc", 404, ""},
		{"double slash", "//public//x", 200, "/mnt/x"},
		{"double slash admin", "/public//../admin", 401, ""},
		{"dot segment", "/public/./x", 200, "/mnt/x"},
		{"trailing slash kept", "/public/x/", 200, "/mnt/x/"},
		{"strip to root", "/public/", 200, "/mnt/"},
		{"encoded slash rejected", "/public/a%2Fb", 400, ""},
		{"encoded slash lower", "/public/a%2fb", 400, ""},
		{"nul rejected", "/public/a%00b", 400, ""},
		{"literal backslash rejected", "/public/a\\b", 400, ""},
		{"encoded backslash rejected", "/public/a%5Cb", 400, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := e.do("GET", tc.target)
			if rr.Code != tc.code {
				t.Fatalf("status %d want %d body %s", rr.Code, tc.code, rr.Body)
			}
			if tc.code == 400 && jsonBody(t, rr)["error"] != "bad_request" {
				t.Errorf("body %s", rr.Body)
			}
			if tc.code == 200 {
				if got := decodeEcho(t, rr).Path; got != tc.wantPath {
					t.Errorf("upstream path %q want %q", got, tc.wantPath)
				}
			}
		})
	}
	// Traversal into the reserved namespace is handled, never proxied.
	if rr := e.do("GET", "/public/../_rlg/healthz"); rr.Code != 200 || rr.Header().Get("X-Upstream") != "" {
		t.Errorf("reserved via traversal: %d", rr.Code)
	}
	// "path" KeyBy sees the cleaned path.
	e2 := newEnv(t, func(s *model.Snapshot) {
		s.Policies = []model.Policy{pol("k", model.AlgoFixedWindow, 5, "path")}
		s.Routes = []model.Route{route("r", up.URL, "/", "k")}
	})
	e2.do("GET", "/a/../b")
	if e2.eng.calls[0] != "k:/b" {
		t.Errorf("key %q", e2.eng.calls[0])
	}
}

func TestPathNormalisationCheckAndSim(t *testing.T) {
	e := checkEnv(t)
	_, m := e.check(t, "chk", map[string]any{"host": "api.acme.com", "path": "/v1/../elsewhere"})
	if m["decision"] != "no_route" {
		t.Errorf("check traversal: %v", m)
	}
	rr, _ := e.check(t, "chk", map[string]any{"path": "/v1/a%2Fb"})
	if rr.Code != 400 {
		t.Errorf("check encoded slash: %d", rr.Code)
	}
	if r := e.g.Simulate(t.Context(), model.SimRequest{Host: "api.acme.com", Path: "/v1/../elsewhere"}); r.Matched {
		t.Errorf("sim traversal matched: %+v", r)
	}
	if r := e.g.Simulate(t.Context(), model.SimRequest{Host: "api.acme.com", Path: "/v1/a%2Fb"}); r.Decision != model.DecisionError {
		t.Errorf("sim encoded slash: %+v", r)
	}
}

func TestUnderscoreHeaderSpoofing(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["X-Rateguard_Leak"] = []string{"1"}
		w.Header().Set("X-RateGuard-Leak2", "1")
		for k := range r.Header {
			if isRGHeader(k) {
				w.Header().Add("X-Seen", k)
			}
		}
	}))
	defer up.Close()
	e := newEnv(t, func(s *model.Snapshot) { s.Routes = []model.Route{route("r", up.URL, "/")} })
	rr := e.do("GET", "/x", func(r *http.Request) {
		r.Header["X-Rateguard_Consumer"] = []string{"admin"}
		r.Header["X-Rateguard_Evil"] = []string{"1"}
	})
	if seen := rr.Header().Values("X-Seen"); len(seen) != 0 {
		t.Errorf("underscore spoof reached upstream: %v", seen)
	}
	for k := range rr.Header() {
		if isRGHeader(k) {
			t.Errorf("upstream %s leaked to client", k)
		}
	}
}
