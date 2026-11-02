package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/ratelimit"
	"ratelimitergateway/internal/store"
)

// ---------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------

// fakeEngine counts per key. Non-concurrency: deny once used+cost > limit
// (counters never reset). Concurrency: in-flight counter.
type fakeEngine struct {
	mu        sync.Mutex
	used      map[string]int
	calls     []string
	released  []string
	err       error
	unhealthy error
}

func newFake() *fakeEngine { return &fakeEngine{used: map[string]int{}} }

func (f *fakeEngine) Allow(_ context.Context, key string, p ratelimit.Params) (ratelimit.Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, key)
	if f.err != nil {
		return ratelimit.Decision{}, f.err
	}
	cost := p.Cost
	if cost == 0 {
		cost = 1
	}
	if p.Algorithm == model.AlgoConcurrency {
		cost = 1
	}
	if f.used[key]+cost > p.Limit {
		return ratelimit.Decision{Allowed: false, Limit: p.Limit, Remaining: 0, ResetAfter: 10 * time.Second, RetryAfter: 2500 * time.Millisecond}, nil
	}
	f.used[key] += cost
	return ratelimit.Decision{Allowed: true, Limit: p.Limit, Remaining: p.Limit - f.used[key], ResetAfter: 30*time.Second - time.Millisecond}, nil
}
func (f *fakeEngine) Peek(context.Context, string, ratelimit.Params) (ratelimit.Decision, bool, error) {
	return ratelimit.Decision{}, false, nil
}
func (f *fakeEngine) Release(_ context.Context, key string, _ ratelimit.Params) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.used[key]--
	f.released = append(f.released, key)
	return nil
}
func (f *fakeEngine) Reset(context.Context, string, ratelimit.Params) error { return nil }
func (f *fakeEngine) Name() string                                          { return "fake" }
func (f *fakeEngine) Healthy(context.Context) error                         { return f.unhealthy }
func (f *fakeEngine) Close() error                                          { return nil }
func (f *fakeEngine) setErr(e error)                                        { f.mu.Lock(); f.err = e; f.mu.Unlock() }
func (f *fakeEngine) usedOf(k string) int                                   { f.mu.Lock(); defer f.mu.Unlock(); return f.used[k] }
func (f *fakeEngine) callCount() int                                        { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

type recorder struct {
	mu sync.Mutex
	es []model.LogEntry
}

func (r *recorder) Record(e model.LogEntry) { r.mu.Lock(); r.es = append(r.es, e); r.mu.Unlock() }
func (r *recorder) all() []model.LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]model.LogEntry(nil), r.es...)
}
func (r *recorder) last(t *testing.T) model.LogEntry {
	t.Helper()
	es := r.all()
	if len(es) == 0 {
		t.Fatal("no log entries recorded")
	}
	return es[len(es)-1]
}

type tokens map[string]string // token -> scope

func (t tokens) Verify(tok, scope string) bool { s, ok := t[tok]; return ok && s == scope }

// upstream echoes request details as JSON and the name in X-Upstream.
func upstream(t *testing.T, name string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", name)
		w.Header().Set("X-RateGuard-Leak", "from-upstream")
		w.Header().Set("RateLimit-Limit", "9999")
		hdr := map[string]string{}
		for k, v := range r.Header {
			hdr[k] = strings.Join(v, ",")
		}
		json.NewEncoder(w).Encode(map[string]any{"name": name, "path": r.URL.Path, "query": r.URL.RawQuery, "host": r.Host, "headers": hdr})
	}))
	t.Cleanup(s.Close)
	return s
}

type echo struct {
	Name    string            `json:"name"`
	Path    string            `json:"path"`
	Query   string            `json:"query"`
	Host    string            `json:"host"`
	Headers map[string]string `json:"headers"`
}

func decodeEcho(t *testing.T, rr *httptest.ResponseRecorder) echo {
	t.Helper()
	var e echo
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil {
		t.Fatalf("body %q: %v", rr.Body.String(), err)
	}
	return e
}

func pol(id string, algo model.Algorithm, limit int, keyBy ...string) model.Policy {
	return model.Policy{ID: id, Name: "Policy " + id, Algorithm: algo, Limit: limit, Window: model.Duration(time.Minute),
		KeyBy: keyBy, Mode: model.ModeEnforce, FailMode: model.FailClosed, Enabled: true}
}

func route(id, up string, prefix string, policies ...string) model.Route {
	return model.Route{ID: id, Name: "Route " + id, Match: model.RouteMatch{PathPrefix: prefix}, Upstream: up, PolicyIDs: policies, Enabled: true}
}

func consumer(id, key string, mut ...func(*model.Consumer)) model.Consumer {
	c := model.Consumer{ID: id, Name: "Consumer " + id, Keys: []model.APIKey{{ID: id + "-k", Prefix: key[:4], Hash: hashHex(key)}}}
	for _, m := range mut {
		m(&c)
	}
	return c
}

type env struct {
	g   *Gateway
	eng *fakeEngine
	rec *recorder
}

func newEnv(t *testing.T, mut func(s *model.Snapshot)) *env {
	t.Helper()
	e := &env{eng: newFake(), rec: &recorder{}}
	e.g = New(Options{Engine: e.eng, Recorder: e.rec, Tokens: tokens{"chk": "check", "adm": "admin"}})
	s := model.NewSnapshot()
	s.Version = 1
	mut(s)
	if err := e.g.Apply(s); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return e
}

func (e *env) do(method, target string, mut ...func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = "192.0.2.10:5555"
	for _, m := range mut {
		m(r)
	}
	rr := httptest.NewRecorder()
	e.g.ServeHTTP(rr, r)
	return rr
}

func hdr(k, v string) func(*http.Request) { return func(r *http.Request) { r.Header.Set(k, v) } }
func remote(a string) func(*http.Request) { return func(r *http.Request) { r.RemoteAddr = a } }

func jsonBody(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("bad json %q: %v", rr.Body.String(), err)
	}
	return m
}

// ---------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------

func TestRouting(t *testing.T) {
	names := []string{"api", "apiv2", "hi", "host", "wild", "post", "tieA", "tieB", "root"}
	ups := map[string]*httptest.Server{}
	for _, n := range names {
		ups[n] = upstream(t, n)
	}
	e := newEnv(t, func(s *model.Snapshot) {
		mk := func(id, name, host, prefix string, prio int, methods ...string) model.Route {
			r := route(id, ups[name].URL, prefix)
			r.Match.Host, r.Match.Methods, r.Priority = host, methods, prio
			return r
		}
		s.Routes = []model.Route{
			mk("r-api", "api", "", "/api", 0),
			mk("r-apiv2", "apiv2", "", "/api/v2", 0),
			mk("r-hi", "hi", "", "/hi", 5),
			mk("r-hi-long", "host", "", "/hi/very/long", 1), // longer prefix but lower priority
			mk("r-host", "host", "exact.example.com", "/h", 0),
			mk("r-wild", "wild", "*.wild.io", "/w", 0),
			mk("r-post", "post", "", "/p", 0, "POST"),
			mk("r-tie-b", "tieB", "", "/tie", 0),
			mk("r-tie-a", "tieA", "", "/tie", 0),
			mk("r-root", "root", "", "/", -1),
		}
		dis := mk("r-disabled", "api", "", "/off", 100)
		dis.Enabled = false
		s.Routes = append(s.Routes, dis)
	})
	cases := []struct {
		name, method, host, path string
		want                     string // upstream name, "" => 404 no_route
	}{
		{"exact prefix", "GET", "x.com", "/api", "api"},
		{"sub path", "GET", "x.com", "/api/x", "api"},
		{"trailing slash", "GET", "x.com", "/api/", "api"},
		{"not a segment match", "GET", "x.com", "/apix", "root"},
		{"longer prefix wins", "GET", "x.com", "/api/v2/users", "apiv2"},
		{"v2 boundary", "GET", "x.com", "/api/v2x", "api"},
		{"priority beats prefix length", "GET", "x.com", "/hi/very/long/path", "hi"},
		{"exact host", "GET", "exact.example.com:8080", "/h/1", "host"},
		{"exact host case", "GET", "EXACT.Example.com", "/h", "host"},
		{"exact host mismatch falls to root", "GET", "other.example.com", "/h", "root"},
		{"wildcard host", "GET", "a.wild.io", "/w", "wild"},
		{"wildcard deep", "GET", "a.b.wild.io:99", "/w/x", "wild"},
		{"wildcard needs a label", "GET", "wild.io", "/w", "root"},
		{"method matches", "POST", "x.com", "/p", "post"},
		{"method mismatch", "GET", "x.com", "/p", "root"},
		{"tie broken by ID", "GET", "x.com", "/tie", "tieA"},
		{"disabled route ignored", "GET", "x.com", "/off", "root"},
		{"root fallback", "GET", "x.com", "/zzz", "root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := e.do(tc.method, "http://"+tc.host+tc.path)
			if rr.Code != 200 {
				t.Fatalf("status %d body %s", rr.Code, rr.Body)
			}
			if got := rr.Header().Get("X-Upstream"); got != tc.want {
				t.Errorf("routed to %q want %q", got, tc.want)
			}
		})
	}
}

func TestNoRoute(t *testing.T) {
	e := newEnv(t, func(s *model.Snapshot) {
		s.Routes = []model.Route{route("r", "http://127.0.0.1:1", "/only")}
	})
	rr := e.do("GET", "/nope")
	if rr.Code != 404 || strings.TrimSpace(rr.Body.String()) != `{"error":"no_route"}` {
		t.Fatalf("got %d %q", rr.Code, rr.Body)
	}
	if l := e.rec.last(t); l.Decision != model.DecisionNoRoute || l.Status != 404 {
		t.Errorf("log %+v", l)
	}
}

func TestNotReadyBeforeApply(t *testing.T) {
	g := New(Options{Engine: newFake()})
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))
	if rr.Code != 503 {
		t.Errorf("status %d", rr.Code)
	}
	if g.Current() != nil {
		t.Error("Current should be nil")
	}
	rr = httptest.NewRecorder()
	g.ServeHTTP(rr, httptest.NewRequest("GET", "/_rlg/readyz", nil))
	if rr.Code != 503 {
		t.Errorf("readyz %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	g.ServeHTTP(rr, httptest.NewRequest("GET", "/_rlg/healthz", nil))
	if rr.Code != 200 {
		t.Errorf("healthz %d", rr.Code)
	}
}

func TestReservedPaths(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		s.Routes = []model.Route{route("all", up.URL, "/")}
	})
	if rr := e.do("GET", "/_rlg/healthz"); rr.Code != 200 {
		t.Errorf("healthz %d", rr.Code)
	}
	if rr := e.do("POST", "/_rlg/healthz"); rr.Code != 405 {
		t.Errorf("healthz POST %d", rr.Code)
	}
	if rr := e.do("GET", "/_rlg/readyz"); rr.Code != 200 {
		t.Errorf("readyz %d", rr.Code)
	}
	e.eng.unhealthy = errors.New("down")
	if rr := e.do("GET", "/_rlg/readyz"); rr.Code != 503 {
		t.Errorf("readyz unhealthy %d", rr.Code)
	}
	rr := e.do("GET", "/_rlg/unknown")
	if rr.Code != 404 || rr.Header().Get("X-Upstream") != "" {
		t.Errorf("unknown reserved path must 404 and not proxy: %d", rr.Code)
	}
}

// ---------------------------------------------------------------------
// Client IP
// ---------------------------------------------------------------------

func TestClientIP(t *testing.T) {
	g := New(Options{Engine: newFake()})
	s := model.NewSnapshot()
	s.Settings.TrustedProxies = []string{"10.0.0.0/8", "192.168.1.1", "fd00::/8"}
	if err := g.Apply(s); err != nil {
		t.Fatal(err)
	}
	cfg := g.cfg.Load()
	cases := []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"untrusted peer ignores XFF", "203.0.113.5:1000", []string{"1.2.3.4"}, "203.0.113.5"},
		{"trusted peer, single hop", "10.1.1.1:1000", []string{"1.2.3.4"}, "1.2.3.4"},
		{"skips trusted hops right-to-left", "10.1.1.1:1", []string{"1.2.3.4, 10.0.0.2, 192.168.1.1"}, "1.2.3.4"},
		{"spoofed left entry not used", "10.1.1.1:1", []string{"6.6.6.6, 1.2.3.4"}, "1.2.3.4"},
		{"multiple header lines", "10.1.1.1:1", []string{"6.6.6.6", "1.2.3.4, 10.0.0.9"}, "1.2.3.4"},
		{"all trusted => leftmost", "10.1.1.1:1", []string{"10.0.0.3, 10.0.0.2"}, "10.0.0.3"},
		{"no XFF => peer", "10.1.1.1:1", nil, "10.1.1.1"},
		{"garbage entry stops walk", "10.1.1.1:1", []string{"1.2.3.4, bogus, 10.0.0.2"}, "10.0.0.2"},
		{"single IP trust entry", "192.168.1.1:1", []string{"9.9.9.9"}, "9.9.9.9"},
		{"ipv6 trusted", "[fd00::1]:80", []string{"2001:db8::1"}, "2001:db8::1"},
		{"v4-mapped peer", "[::ffff:10.1.1.1]:80", []string{"7.7.7.7"}, "7.7.7.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cfg.clientIP(tc.remote, tc.xff); got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestClientIPEndToEnd(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		s.Settings.TrustedProxies = []string{"10.0.0.0/8"}
		s.Policies = []model.Policy{pol("p", model.AlgoFixedWindow, 100, "ip")}
		s.Routes = []model.Route{route("r", up.URL, "/", "p")}
	})
	// Untrusted peer: XFF is attacker input, replaced upstream, ignored for keying.
	rr := e.do("GET", "/a", hdr("X-Forwarded-For", "6.6.6.6"), hdr("X-Forwarded-Proto", "https"), hdr("X-Forwarded-Host", "evil"))
	got := decodeEcho(t, rr)
	if got.Headers["X-Forwarded-For"] != "192.0.2.10" || got.Headers["X-Forwarded-Proto"] != "http" || got.Headers["X-Forwarded-Host"] == "evil" {
		t.Errorf("untrusted forwarded headers not sanitised: %v", got.Headers)
	}
	if l := e.rec.last(t); l.ClientIP != "192.0.2.10" || l.RateKey != "192.0.2.10" {
		t.Errorf("log %+v", l)
	}
	if e.eng.usedOf("p:192.0.2.10") != 1 {
		t.Errorf("engine keys: %v", e.eng.calls)
	}
	// Trusted peer: chain preserved and extended.
	rr = e.do("GET", "/a", remote("10.9.9.9:1"), hdr("X-Forwarded-For", "1.2.3.4"), hdr("X-Forwarded-Proto", "https"))
	got = decodeEcho(t, rr)
	if got.Headers["X-Forwarded-For"] != "1.2.3.4, 10.9.9.9" || got.Headers["X-Forwarded-Proto"] != "https" {
		t.Errorf("trusted forwarded headers: %v", got.Headers)
	}
	if l := e.rec.last(t); l.ClientIP != "1.2.3.4" {
		t.Errorf("client ip %q", l.ClientIP)
	}
}

// ---------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------

func authSnapshot(up string) func(s *model.Snapshot) {
	return func(s *model.Snapshot) {
		past := time.Now().Add(-time.Hour)
		future := time.Now().Add(time.Hour)
		s.Policies = []model.Policy{pol("p", model.AlgoFixedWindow, 100, "consumer")}
		s.Consumers = []model.Consumer{
			consumer("alice", "rlg_live_alice0000000000000000000000"),
			consumer("revoked", "rlg_live_revoked00000000000000000000", func(c *model.Consumer) { c.Keys[0].Revoked = true }),
			consumer("expired", "rlg_live_expired00000000000000000000", func(c *model.Consumer) { c.Keys[0].ExpiresAt = &past }),
			consumer("future", "rlg_live_future000000000000000000000", func(c *model.Consumer) { c.Keys[0].ExpiresAt = &future }),
			consumer("disabled", "rlg_live_disabled0000000000000000000", func(c *model.Consumer) { c.Disabled = true }),
		}
		req := route("req", up, "/req", "p")
		req.RequireAPIKey = true
		s.Routes = []model.Route{req, route("opt", up, "/opt", "p")}
	}
}

func TestAPIKeyAuth(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, authSnapshot(up.URL))
	const alice = "rlg_live_alice0000000000000000000000"
	cases := []struct {
		name     string
		path     string
		mut      func(*http.Request)
		wantCode int
		consumer string
	}{
		{"required, missing", "/req", nil, 401, ""},
		{"required, valid header", "/req", hdr("X-API-Key", alice), 200, "alice"},
		{"required, valid bearer", "/req", hdr("Authorization", "Bearer "+alice), 200, "alice"},
		{"bearer scheme case-insensitive", "/req", hdr("Authorization", "bearer "+alice), 200, "alice"},
		{"required, wrong key", "/req", hdr("X-API-Key", "rlg_live_nope"), 401, ""},
		{"optional, missing => anonymous", "/opt", nil, 200, ""},
		{"optional, valid", "/opt", hdr("X-API-Key", alice), 200, "alice"},
		{"optional, invalid => 401 never anon", "/opt", hdr("X-API-Key", "garbage"), 401, ""},
		{"optional, invalid bearer => 401", "/opt", hdr("Authorization", "Bearer garbage"), 401, ""},
		{"revoked", "/opt", hdr("X-API-Key", "rlg_live_revoked00000000000000000000"), 401, ""},
		{"expired", "/opt", hdr("X-API-Key", "rlg_live_expired00000000000000000000"), 401, ""},
		{"not yet expired", "/opt", hdr("X-API-Key", "rlg_live_future000000000000000000000"), 200, "future"},
		{"consumer disabled", "/opt", hdr("X-API-Key", "rlg_live_disabled0000000000000000000"), 401, ""},
		{"header wins over bearer", "/req", func(r *http.Request) {
			r.Header.Set("X-API-Key", alice)
			r.Header.Set("Authorization", "Bearer garbage")
		}, 200, "alice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mut []func(*http.Request)
			if tc.mut != nil {
				mut = append(mut, tc.mut)
			}
			rr := e.do("GET", tc.path, mut...)
			if rr.Code != tc.wantCode {
				t.Fatalf("status %d want %d body %s", rr.Code, tc.wantCode, rr.Body)
			}
			if tc.wantCode == 401 {
				b := jsonBody(t, rr)
				if b["error"] != "unauthorized" || b["message"] == "" {
					t.Errorf("body %v", b)
				}
				if l := e.rec.last(t); l.Decision != model.DecisionUnauthorized || l.Status != 401 {
					t.Errorf("log %+v", l)
				}
				return
			}
			if got := decodeEcho(t, rr).Headers["X-Rateguard-Consumer"]; got != tc.consumer {
				t.Errorf("upstream consumer header %q want %q", got, tc.consumer)
			}
		})
	}
}

func TestCustomAPIKeyHeaderAndNoKeyInRateKey(t *testing.T) {
	up := upstream(t, "u")
	const key = "rlg_live_alice0000000000000000000000"
	e := newEnv(t, func(s *model.Snapshot) {
		authSnapshot(up.URL)(s)
		s.Settings.APIKeyHeader = "X-Token"
		s.Policies = []model.Policy{pol("p", model.AlgoFixedWindow, 100, "api_key", "header:X-Token", "header:Authorization", "consumer")}
		s.Routes = []model.Route{route("r", up.URL, "/", "p")}
	})
	if rr := e.do("GET", "/a", hdr("X-API-Key", key)); rr.Code != 200 { // old header is now just a header, anonymous
		t.Fatalf("status %d", rr.Code)
	}
	rr := e.do("GET", "/a", hdr("X-Token", key), hdr("Authorization", "Basic c2VjcmV0"))
	if rr.Code != 200 {
		t.Fatalf("status %d %s", rr.Code, rr.Body)
	}
	l := e.rec.last(t)
	if strings.Contains(l.RateKey, key) || strings.Contains(l.RateKey, "c2VjcmV0") {
		t.Errorf("RateKey leaks secret: %q", l.RateKey)
	}
	parts := strings.Split(l.RateKey, "|")
	if len(parts) != 4 || parts[0] != hashHex(key)[:16] || !strings.HasPrefix(parts[1], "h:") || !strings.HasPrefix(parts[2], "h:") || parts[3] != "alice" {
		t.Errorf("RateKey parts %v", parts)
	}
	for _, k := range e.eng.calls {
		if strings.Contains(k, key) {
			t.Errorf("engine key leaks raw key: %s", k)
		}
	}
}

// ---------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------

func TestKeyBy(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		authSnapshot(up.URL)(s)
		s.Policies = []model.Policy{
			pol("k", model.AlgoFixedWindow, 100, "ip", "header:X-Tenant", "query:q", "path", "method", "route", "global"),
			pol("c", model.AlgoFixedWindow, 100, "consumer"),
			pol("e", model.AlgoFixedWindow, 100),
		}
		s.Routes = []model.Route{route("rt", up.URL, "/", "k", "c", "e")}
	})
	e.do("POST", "/p/x?q=hello", hdr("X-Tenant", "t1"))
	want := []string{"k:192.0.2.10|t1|hello|/p/x|POST|rt|global", "c:ip:192.0.2.10", "e:global"}
	for i, w := range want {
		if e.eng.calls[i] != w {
			t.Errorf("call %d = %q want %q", i, e.eng.calls[i], w)
		}
	}
	e.eng.calls = nil
	e.do("GET", "/p", hdr("X-API-Key", "rlg_live_alice0000000000000000000000"))
	if e.eng.calls[0] != "k:192.0.2.10|-|-|/p|GET|rt|global" || e.eng.calls[1] != "c:alice" {
		t.Errorf("calls %v", e.eng.calls)
	}
	if g := e.g.EngineKey("pid", "a|b"); g != "pid:a|b" {
		t.Errorf("EngineKey %q", g)
	}
	// Attacker-controlled parts are bounded.
	e.eng.calls = nil
	e.do("GET", "/p", hdr("X-Tenant", strings.Repeat("a", 5000)))
	if len(e.eng.calls[0]) > 400 {
		t.Errorf("engine key unbounded: %d", len(e.eng.calls[0]))
	}
}

// ---------------------------------------------------------------------
// Policies: overrides, shadow, fail modes, headers, 429
// ---------------------------------------------------------------------

func TestOverridesPrecedence(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		s.Policies = []model.Policy{pol("p", model.AlgoFixedWindow, 5, "consumer")}
		s.Plans = []model.Plan{{ID: "pro", Name: "Pro", Overrides: map[string]model.LimitOverride{"p": {Limit: 3}}}}
		s.Consumers = []model.Consumer{
			consumer("plain", "rlg_live_plain0000000000000000000000"),
			consumer("onplan", "rlg_live_onplan000000000000000000000", func(c *model.Consumer) { c.PlanID = "pro" }),
			consumer("override", "rlg_live_override0000000000000000000", func(c *model.Consumer) {
				c.PlanID = "pro"
				c.Overrides = map[string]model.LimitOverride{"p": {Limit: 2}}
			}),
		}
		s.Routes = []model.Route{route("r", up.URL, "/", "p")}
	})
	cases := []struct {
		consumer, key string
		wantLimit     int
	}{
		{"plain", "rlg_live_plain0000000000000000000000", 5},
		{"onplan", "rlg_live_onplan000000000000000000000", 3},
		{"override", "rlg_live_override0000000000000000000", 2},
	}
	for _, tc := range cases {
		t.Run(tc.consumer, func(t *testing.T) {
			ok := 0
			for i := 0; i < 8; i++ {
				rr := e.do("GET", "/x", hdr("X-API-Key", tc.key))
				if rr.Code == 200 {
					ok++
				}
				if rr.Code == 429 && rr.Header().Get("RateLimit-Limit") != strconv.Itoa(tc.wantLimit) {
					t.Errorf("429 limit header %q", rr.Header().Get("RateLimit-Limit"))
				}
			}
			if ok != tc.wantLimit {
				t.Errorf("allowed %d want %d", ok, tc.wantLimit)
			}
		})
	}
	// Partial override keeps the policy's other numbers; LimitFrom reports the layer.
	sim := e.g.Simulate(context.Background(), model.SimRequest{Path: "/x", Headers: map[string]string{"x-api-key": "rlg_live_onplan000000000000000000000"}})
	if p := sim.Policies[0]; p.Limit != 3 || p.LimitFrom != "plan:pro" || p.Window.D() != time.Minute {
		t.Errorf("sim %+v", p)
	}
	sim = e.g.Simulate(context.Background(), model.SimRequest{Path: "/x", Headers: map[string]string{"X-API-Key": "rlg_live_override0000000000000000000"}})
	if p := sim.Policies[0]; p.Limit != 2 || p.LimitFrom != "consumer" {
		t.Errorf("sim %+v", p)
	}
	sim = e.g.Simulate(context.Background(), model.SimRequest{Path: "/x"})
	if p := sim.Policies[0]; p.Limit != 5 || p.LimitFrom != "policy" {
		t.Errorf("sim %+v", p)
	}
}

func TestPolicyChainSelection(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		off := pol("off", model.AlgoFixedWindow, 1, "global")
		off.Enabled = false
		s.Policies = []model.Policy{pol("g", model.AlgoFixedWindow, 100, "global"), pol("a", model.AlgoFixedWindow, 100, "global"), off}
		s.Settings.GlobalPolicyIDs = []string{"g"}
		s.Routes = []model.Route{route("r", up.URL, "/", "a", "g", "off")}
	})
	e.do("GET", "/x")
	if len(e.eng.calls) != 2 || e.eng.calls[0] != "g:global" || e.eng.calls[1] != "a:global" {
		t.Errorf("order/dedupe/disabled: %v", e.eng.calls)
	}
}

func TestStopAtFirstEnforceDeny(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		s.Policies = []model.Policy{pol("first", model.AlgoFixedWindow, 1, "global"), pol("second", model.AlgoFixedWindow, 100, "global")}
		s.Routes = []model.Route{route("r", up.URL, "/", "first", "second")}
	})
	e.do("GET", "/x")
	rr := e.do("GET", "/x")
	if rr.Code != 429 {
		t.Fatalf("status %d", rr.Code)
	}
	if e.eng.usedOf("second:global") != 1 {
		t.Errorf("second bucket burned on denied request: %d", e.eng.usedOf("second:global"))
	}
	if l := e.rec.last(t); l.PolicyID != "first" || l.Decision != model.DecisionLimited || l.Status != 429 {
		t.Errorf("log %+v", l)
	}
}

func TestHeadersAnd429Body(t *testing.T) {
	up := upstream(t, "u")
	mk := func(legacy, expose bool) *env {
		return newEnv(t, func(s *model.Snapshot) {
			wide := pol("wide", model.AlgoFixedWindow, 100, "global")
			tight := pol("tight", model.AlgoFixedWindow, 2, "global")
			tight.Window = model.Duration(10 * time.Second)
			s.Policies = []model.Policy{wide, tight}
			s.Routes = []model.Route{route("r", up.URL, "/", "wide", "tight")}
			s.Settings.LegacyHeaders, s.Settings.ExposeDecision = legacy, expose
		})
	}
	e := mk(true, true)
	rr := e.do("GET", "/x")
	want := map[string]string{"RateLimit-Limit": "2", "RateLimit-Remaining": "1", "RateLimit-Reset": "30", "RateLimit-Policy": "2;w=10",
		"X-RateLimit-Limit": "2", "X-RateLimit-Remaining": "1", "X-RateGuard-Route": "r", "X-RateGuard-Policy": "tight"}
	for k, v := range want {
		if got := rr.Header().Get(k); got != v {
			t.Errorf("%s = %q want %q", k, got, v)
		}
	}
	if reset, _ := strconv.ParseInt(rr.Header().Get("X-RateLimit-Reset"), 10, 64); reset < time.Now().Unix()+25 || reset > time.Now().Unix()+35 {
		t.Errorf("legacy reset should be unix seconds ~now+30: %d", reset)
	}
	if rr.Header().Get("Retry-After") != "" {
		t.Error("Retry-After only on 429")
	}
	// Upstream-provided duplicates / X-RateGuard-* are not forwarded to the client.
	if v := rr.Header().Values("RateLimit-Limit"); len(v) != 1 {
		t.Errorf("duplicate RateLimit-Limit: %v", v)
	}
	if rr.Header().Get("X-RateGuard-Leak") != "" {
		t.Error("upstream X-RateGuard-* leaked to client")
	}
	e.do("GET", "/x")
	rr = e.do("GET", "/x")
	if rr.Code != 429 {
		t.Fatalf("status %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") != "3" || rr.Header().Get("RateLimit-Remaining") != "0" || rr.Header().Get("RateLimit-Reset") != "10" {
		t.Errorf("429 headers: %v", rr.Header())
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("content type %q", rr.Header().Get("Content-Type"))
	}
	b := jsonBody(t, rr)
	wantBody := map[string]any{"error": "rate_limited", "message": "Rate limit exceeded", "policy": "Policy tight",
		"limit": 2.0, "remaining": 0.0, "retry_after_s": 3.0, "reset_s": 10.0}
	for k, v := range wantBody {
		if b[k] != v {
			t.Errorf("body[%s] = %v want %v", k, b[k], v)
		}
	}
	// Legacy/expose off.
	e = mk(false, false)
	rr = e.do("GET", "/x")
	for _, k := range []string{"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "X-RateGuard-Route", "X-RateGuard-Policy"} {
		if rr.Header().Get(k) != "" {
			t.Errorf("%s should be absent", k)
		}
	}
	if rr.Header().Get("RateLimit-Limit") == "" {
		t.Error("IETF headers always present")
	}
}

func TestRetryAfterMinimumOne(t *testing.T) {
	cfg := &compiled{}
	r := &polResult{cp: &cpolicy{}, params: ratelimit.Params{Limit: 1, Window: time.Second}, dec: ratelimit.Decision{RetryAfter: 10 * time.Millisecond}}
	if h := rateHeaders(cfg, r, time.Now(), true); h["Retry-After"] != "1" {
		t.Errorf("Retry-After %q", h["Retry-After"])
	}
}

func TestShadowMode(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		p := pol("sh", model.AlgoFixedWindow, 1, "global")
		p.Mode = model.ModeShadow
		s.Policies = []model.Policy{p, pol("real", model.AlgoFixedWindow, 100, "global")}
		s.Routes = []model.Route{route("r", up.URL, "/", "sh", "real")}
	})
	e.do("GET", "/x")
	rr := e.do("GET", "/x")
	if rr.Code != 200 {
		t.Fatalf("shadow must not block: %d", rr.Code)
	}
	if rr.Header().Get("RateLimit-Policy") != "100;w=60" {
		t.Errorf("headers should come from enforce policies only: %v", rr.Header())
	}
	l := e.rec.last(t)
	if l.Decision != model.DecisionShadowLimited || l.PolicyID != "sh" || l.Status != 200 {
		t.Errorf("log %+v", l)
	}
	if e.eng.usedOf("real:global") != 2 {
		t.Errorf("evaluation must continue after a shadow deny")
	}
}

func TestFailModes(t *testing.T) {
	up := upstream(t, "u")
	for _, tc := range []struct {
		mode     model.FailMode
		wantCode int
		decision string
	}{{model.FailOpen, 200, model.DecisionAllowed}, {model.FailClosed, 503, model.DecisionError}, {"", 200, model.DecisionAllowed}} {
		t.Run(string(tc.mode), func(t *testing.T) {
			e := newEnv(t, func(s *model.Snapshot) {
				p := pol("p", model.AlgoFixedWindow, 1, "global")
				p.FailMode = tc.mode
				s.Policies = []model.Policy{p}
				s.Routes = []model.Route{route("r", up.URL, "/", "p")}
			})
			e.eng.setErr(errors.New("redis down"))
			rr := e.do("GET", "/x")
			if rr.Code != tc.wantCode {
				t.Fatalf("status %d want %d", rr.Code, tc.wantCode)
			}
			if tc.wantCode == 503 {
				if jsonBody(t, rr)["error"] != "limiter_unavailable" {
					t.Errorf("body %s", rr.Body)
				}
				if strings.Contains(rr.Body.String(), "redis down") {
					t.Error("backend error detail leaked to client")
				}
			}
			if l := e.rec.last(t); l.Decision != tc.decision {
				t.Errorf("decision %q want %q", l.Decision, tc.decision)
			}
		})
	}
}

func TestFailClosedReleasesEarlierSlots(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		c := pol("conc", model.AlgoConcurrency, 5, "global")
		bad := pol("bad", model.AlgoFixedWindow, 1, "global")
		s.Policies = []model.Policy{c, bad}
		s.Routes = []model.Route{route("r", up.URL, "/", "conc", "bad")}
	})
	e.eng.mu.Lock()
	e.eng.used["bad:global"] = 1 // next Allow on `bad` denies
	e.eng.mu.Unlock()
	rr := e.do("GET", "/x")
	if rr.Code != 429 {
		t.Fatalf("status %d", rr.Code)
	}
	if e.eng.usedOf("conc:global") != 0 {
		t.Errorf("concurrency slot leaked after a later policy denied: %d", e.eng.usedOf("conc:global"))
	}
}

// ---------------------------------------------------------------------
// Concurrency policies
// ---------------------------------------------------------------------

func TestConcurrencyRelease(t *testing.T) {
	started := make(chan struct{}, 4)
	unblock := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-unblock
		io.WriteString(w, "done")
	}))
	defer slow.Close()
	e := newEnv(t, func(s *model.Snapshot) {
		s.Policies = []model.Policy{pol("conc", model.AlgoConcurrency, 1, "global")}
		s.Routes = []model.Route{route("r", slow.URL, "/", "conc")}
	})
	done := make(chan *httptest.ResponseRecorder)
	go func() { done <- e.do("GET", "/slow") }()
	<-started
	rr := e.do("GET", "/slow")
	if rr.Code != 429 {
		t.Fatalf("second concurrent request: %d", rr.Code)
	}
	if len(e.eng.released) != 0 {
		t.Error("slot released before response completed")
	}
	close(unblock)
	if first := <-done; first.Code != 200 {
		t.Fatalf("first: %d", first.Code)
	}
	if e.eng.usedOf("conc:global") != 0 || len(e.eng.released) != 1 {
		t.Errorf("slot not released exactly once: used=%d released=%v", e.eng.usedOf("conc:global"), e.eng.released)
	}
	// Third request now fits (released slot).
	go func() { <-started }()
	if rr := e.do("GET", "/slow"); rr.Code != 200 {
		t.Errorf("after release: %d", rr.Code)
	}
}

func TestConcurrencyReleasedOnUpstreamError(t *testing.T) {
	e := newEnv(t, func(s *model.Snapshot) {
		s.Policies = []model.Policy{pol("conc", model.AlgoConcurrency, 1, "global")}
		s.Routes = []model.Route{route("r", "http://127.0.0.1:1", "/", "conc")}
	})
	rr := e.do("GET", "/x")
	if rr.Code != 502 || strings.TrimSpace(rr.Body.String()) != `{"error":"bad_gateway"}` {
		t.Fatalf("got %d %s", rr.Code, rr.Body)
	}
	if e.eng.usedOf("conc:global") != 0 {
		t.Error("slot leaked on upstream error")
	}
	if l := e.rec.last(t); l.Decision != model.DecisionError || l.Status != 502 || l.Error == "" {
		t.Errorf("log %+v", l)
	}
}

// ---------------------------------------------------------------------
// Proxy behaviour
// ---------------------------------------------------------------------

func TestProxyStripPrefixAndSpoofing(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		r := route("r", up.URL+"/base", "/svc")
		r.StripPrefix = true
		s.Routes = []model.Route{r}
	})
	cases := []struct{ in, wantPath string }{
		{"/svc/users?a=1", "/base/users"},
		{"/svc", "/base/"},
		{"/svc/", "/base/"},
	}
	for _, tc := range cases {
		rr := e.do("GET", tc.in, hdr("X-RateGuard-Consumer", "admin"), hdr("X-RateGuard-Evil", "1"))
		got := decodeEcho(t, rr)
		if got.Path != tc.wantPath {
			t.Errorf("%s -> %q want %q", tc.in, got.Path, tc.wantPath)
		}
		if _, ok := got.Headers["X-Rateguard-Consumer"]; ok {
			t.Errorf("spoofed X-RateGuard-Consumer reached upstream: %v", got.Headers)
		}
		if _, ok := got.Headers["X-Rateguard-Evil"]; ok {
			t.Errorf("spoofed X-RateGuard-Evil reached upstream")
		}
	}
	if rr := e.do("GET", "/svc/users?a=1"); decodeEcho(t, rr).Query != "a=1" {
		t.Error("query lost")
	}
	// Without StripPrefix the full path is forwarded.
	e2 := newEnv(t, func(s *model.Snapshot) { s.Routes = []model.Route{route("r", up.URL, "/svc")} })
	if got := decodeEcho(t, e2.do("GET", "/svc/a")).Path; got != "/svc/a" {
		t.Errorf("path %q", got)
	}
	// The API key header is forwarded (upstreams may need it).
	e3 := newEnv(t, authSnapshot(up.URL))
	got := decodeEcho(t, e3.do("GET", "/opt", hdr("X-API-Key", "rlg_live_alice0000000000000000000000")))
	if got.Headers["X-Api-Key"] == "" {
		t.Error("API key header should be forwarded")
	}
}

func TestUpstreamTimeout(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defer slow.Close()
	e := newEnv(t, func(s *model.Snapshot) {
		r := route("r", slow.URL, "/")
		r.Timeout = model.Duration(80 * time.Millisecond)
		s.Routes = []model.Route{r}
	})
	start := time.Now()
	rr := e.do("GET", "/x")
	if rr.Code != 502 || time.Since(start) > 2*time.Second {
		t.Errorf("status %d after %v", rr.Code, time.Since(start))
	}
}

func TestMaxBodyBytes(t *testing.T) {
	var got int64
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		got = n
		if err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		}
	}))
	defer sink.Close()
	e := newEnv(t, func(s *model.Snapshot) {
		s.Settings.MaxBodyBytes = 10
		s.Routes = []model.Route{route("r", sink.URL, "/")}
	})
	post := func(body string, cl bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/x", strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1"
		if !cl {
			r.ContentLength = -1
		}
		rr := httptest.NewRecorder()
		e.g.ServeHTTP(rr, r)
		return rr
	}
	if rr := post("0123456789", true); rr.Code != 200 || got != 10 {
		t.Errorf("at limit: %d %d", rr.Code, got)
	}
	if rr := post("0123456789ABC", true); rr.Code != 413 {
		t.Errorf("declared too large: %d", rr.Code)
	}
	if rr := post("0123456789ABC", false); rr.Code != 413 {
		t.Errorf("unknown length too large: %d", rr.Code)
	}
}

func TestProxyCacheAcrossApply(t *testing.T) {
	up := upstream(t, "u")
	other := upstream(t, "o")
	e := newEnv(t, func(s *model.Snapshot) {
		s.Routes = []model.Route{route("a", up.URL, "/a"), route("b", up.URL, "/b"), route("c", other.URL, "/c")}
	})
	c1 := e.g.cfg.Load()
	if c1.byID["a"].proxy != c1.byID["b"].proxy {
		t.Error("routes sharing an upstream should share a proxy")
	}
	if c1.byID["a"].proxy == c1.byID["c"].proxy {
		t.Error("different upstreams must not share a proxy")
	}
	s2 := e.g.Current().Clone()
	s2.Version++
	s2.Routes = s2.Routes[:2]
	if err := e.g.Apply(s2); err != nil {
		t.Fatal(err)
	}
	c2 := e.g.cfg.Load()
	if c2 == c1 || c2.byID["a"].proxy != c1.byID["a"].proxy {
		t.Error("proxy not reused across Apply")
	}
	if len(e.g.proxies) != 1 {
		t.Errorf("unused proxies not pruned: %d", len(e.g.proxies))
	}
}

// ---------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------

func TestApplyValidates(t *testing.T) {
	e := newEnv(t, func(s *model.Snapshot) {})
	prev := e.g.Current()
	bad := model.NewSnapshot()
	bad.Policies = []model.Policy{{ID: "BAD", Name: "x"}}
	err := e.g.Apply(bad)
	var ve *store.ValidationError
	if !errors.As(err, &ve) || len(ve.Problems) == 0 {
		t.Fatalf("want *store.ValidationError, got %v", err)
	}
	if e.g.Current() != prev {
		t.Error("failed Apply must keep previous config")
	}
	if e.g.Apply(nil) == nil {
		t.Error("nil must fail")
	}
}

func TestConcurrentApplyAndServe(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		s.Policies = []model.Policy{pol("p", model.AlgoFixedWindow, 1_000_000, "ip")}
		s.Routes = []model.Route{route("r", up.URL, "/", "p")}
	})
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			s := e.g.Current().Clone()
			s.Version++
			e.g.Apply(s)
		}
	}()
	var cw sync.WaitGroup
	for i := 0; i < 8; i++ {
		cw.Add(1)
		go func() {
			defer cw.Done()
			for j := 0; j < 50; j++ {
				if rr := e.do("GET", "/x"); rr.Code != 200 {
					t.Errorf("status %d", rr.Code)
					return
				}
			}
		}()
	}
	cw.Wait()
	close(stop)
	wg.Wait()
}

// ---------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------

func TestLogEntryAndSampling(t *testing.T) {
	up := upstream(t, "u")
	build := func(sample float64) *env {
		return newEnv(t, func(s *model.Snapshot) {
			authSnapshot(up.URL)(s)
			s.Settings.LogSampleAllowed = sample
		})
	}
	e := build(1)
	e.do("GET", "/opt?x=1", hdr("X-API-Key", "rlg_live_alice0000000000000000000000"), hdr("User-Agent", "ua/1"))
	l := e.rec.last(t)
	if l.Decision != model.DecisionAllowed || l.Status != 200 || l.Source != "proxy" || l.RouteID != "opt" || l.ConsumerID != "alice" ||
		l.ConsumerName != "Consumer alice" || l.Method != "GET" || l.Path != "/opt" || l.UserAgent != "ua/1" || l.BytesOut == 0 ||
		l.Limit != 100 || l.Remaining != 99 || l.PolicyID != "p" || l.ClientIP != "192.0.2.10" || l.LatencyMs <= 0 || l.UpstreamMs <= 0 {
		t.Errorf("log %+v", l)
	}
	e = build(0)
	for i := 0; i < 5; i++ {
		e.do("GET", "/opt")
	}
	e.do("GET", "/req") // 401: always logged
	e.do("GET", "/nope")
	if es := e.rec.all(); len(es) != 2 || es[0].Decision != model.DecisionUnauthorized {
		t.Errorf("sample=0 should log only non-allowed: %+v", es)
	}
	e = newEnv(t, func(s *model.Snapshot) {
		authSnapshot(up.URL)(s)
		s.Policies[0].Limit = 1_000_000
		s.Settings.LogSampleAllowed = 0.5
	})
	for i := 0; i < 400; i++ {
		e.do("GET", "/opt")
	}
	if n := len(e.rec.all()); n < 120 || n > 280 {
		t.Errorf("sample=0.5 logged %d/400", n)
	}
}

func TestNilRecorderAndEngine(t *testing.T) {
	up := upstream(t, "u")
	g := New(Options{})
	s := model.NewSnapshot()
	s.Policies = []model.Policy{pol("p", model.AlgoFixedWindow, 1, "global")}
	s.Routes = []model.Route{route("r", up.URL, "/", "p")}
	if err := g.Apply(s); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))
	if rr.Code != 503 { // missing engine behaves like a failing backend (policy is fail_closed)
		t.Errorf("status %d", rr.Code)
	}
}
