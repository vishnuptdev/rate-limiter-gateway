package gateway

import (
	"testing"

	"ratelimitergateway/internal/model"
)

func uriEnv(t *testing.T) *env {
	up := upstream(t, "u")
	return newEnv(t, func(s *model.Snapshot) {
		s.Policies = []model.Policy{pol("p", model.AlgoFixedWindow, 100, "global")}
		s.Routes = []model.Route{
			{ID: "admin", Name: "A", Match: model.RouteMatch{PathPrefix: "/admin"}, Upstream: up.URL, PolicyIDs: []string{"p"}, RequireAPIKey: true, Enabled: true},
			{ID: "open", Name: "O", Match: model.RouteMatch{PathPrefix: "/secret"}, Upstream: up.URL, PolicyIDs: []string{"p"}, Enabled: true},
			{ID: "x", Name: "X", Match: model.RouteMatch{PathPrefix: "/x"}, Upstream: up.URL, PolicyIDs: []string{"p"}, Enabled: true},
			{ID: "a", Name: "A2", Match: model.RouteMatch{PathPrefix: "/a"}, Upstream: up.URL, PolicyIDs: []string{"p"}, Enabled: true},
			{ID: "pct", Name: "P", Match: model.RouteMatch{PathPrefix: "/pct"}, Upstream: up.URL, PolicyIDs: []string{"p"}, Enabled: true},
		}
	})
}

func TestForwardAuthURIParsing(t *testing.T) {
	cases := []struct {
		name, uri string
		wantCode  int
		wantRoute string
		wantPath  string
	}{
		{"double slash is a path not authority", "//admin/secret", 401, "admin", "/admin/secret"},
		{"triple slash", "///x", 200, "x", "/x"},
		{"inner double slash", "/a//b", 200, "a", "/a/b"},
		{"query kept apart", "/x?q=1", 200, "x", "/x"},
		{"encoded question mark in path", "/pct/a%3Fb", 200, "pct", "/pct/a?b"},
		{"encoded percent", "/pct/100%25", 200, "pct", "/pct/100%"},
		{"bad percent escape", "/pct/%zz", 400, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := uriEnv(t)
			rr := e.auth("/_rlg/v1/auth", fwd("GET", tc.uri))
			if rr.Code != tc.wantCode {
				t.Fatalf("got %d %s", rr.Code, rr.Body)
			}
			if tc.wantCode == 400 {
				return
			}
			if le := e.rec.last(t); le.RouteID != tc.wantRoute || le.Path != tc.wantPath {
				t.Errorf("route=%q path=%q, want %q %q", le.RouteID, le.Path, tc.wantRoute, tc.wantPath)
			}
		})
	}
}

func TestForwardAuthEnvoyEncodedPath(t *testing.T) {
	cases := []struct {
		name, target string
		wantCode     int
		wantPath     string
	}{
		{"encoded question mark", "/_rlg/v1/auth/pct/a%3Fb", 200, "/pct/a?b"},
		{"encoded hash", "/_rlg/v1/auth/pct/a%23b", 200, "/pct/a#b"},
		{"encoded percent", "/_rlg/v1/auth/pct/100%25", 200, "/pct/100%"},
		{"real query not part of path", "/_rlg/v1/auth/x?k=v", 200, "/x"},
		{"double slash after prefix", "/_rlg/v1/auth//admin/secret", 401, "/admin/secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := uriEnv(t)
			rr := e.do("GET", tc.target)
			if rr.Code != tc.wantCode {
				t.Fatalf("got %d %s", rr.Code, rr.Body)
			}
			if le := e.rec.last(t); le.Path != tc.wantPath || le.Source != "forward_auth" {
				t.Errorf("log %+v, want path %q", le, tc.wantPath)
			}
		})
	}
}

func TestForwardAuthXOriginalURL(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		s.Policies = []model.Policy{pol("p", model.AlgoFixedWindow, 100, "global")}
		s.Routes = []model.Route{{ID: "h", Name: "H", Match: model.RouteMatch{Host: "api.acme.com", PathPrefix: "/v1"},
			Upstream: up.URL, PolicyIDs: []string{"p"}, Enabled: true}}
	})
	rr := e.auth("/_rlg/v1/auth", hdr("X-Original-URL", "https://api.acme.com/v1/items?x=1"), hdr("X-Original-Method", "GET"))
	if rr.Code != 200 {
		t.Fatalf("got %d %s", rr.Code, rr.Body)
	}
	if le := e.rec.last(t); le.Host != "api.acme.com" || le.Path != "/v1/items" {
		t.Errorf("log %+v", le)
	}
	// Scheme-relative style tricks in the URL's path are still just a path.
	rr = e.auth("/_rlg/v1/auth", hdr("X-Original-URL", "https://api.acme.com//v1/items"))
	if rr.Code != 200 {
		t.Errorf("double slash: %d", rr.Code)
	}
	// X-Forwarded-Host wins over the URL's host.
	rr = e.auth("/_rlg/v1/auth", hdr("X-Original-URL", "https://other.com/v1/items"), hdr("X-Forwarded-Host", "api.acme.com"))
	if rr.Code != 200 {
		t.Errorf("forwarded host precedence: %d", rr.Code)
	}
	if rr = e.auth("/_rlg/v1/auth", hdr("X-Original-URL", "https://other.com/v1/items")); rr.Code != 404 {
		t.Errorf("other host: %d", rr.Code)
	}
}
