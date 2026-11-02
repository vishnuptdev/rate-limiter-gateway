package gateway

// Regression tests for the pre-release security hardening pass (SA1..SA8).
// Each test names the item it covers; see docs/SECURITY.md "Hardening".

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
)

// SA1: the forwarded-URI precedence the integration docs rely on. The proxy
// must SET X-Forwarded-Uri (and -Method/-Host), because that header wins
// over any X-Original-* value; a client-supplied X-Original-URI/-URL is
// therefore ignored whenever the proxy sets X-Forwarded-Uri.
func TestHardenForwardAuthURIPrecedence(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		admin := route("admin", up.URL, "/admin")
		admin.RequireAPIKey = true
		s.Routes = []model.Route{admin, route("pub", up.URL, "/pub")}
	})
	// Proxy-set X-Forwarded-Uri describes /admin; the client tried to steer
	// the decision with its own X-Original-URI / X-Original-URL.
	rr := e.do("GET", "/_rlg/v1/auth",
		hdr("X-Forwarded-Uri", "/admin/users"),
		hdr("X-Original-Uri", "/pub/x"),
		hdr("X-Original-Url", "https://h/pub/x"))
	if rr.Code != http.StatusUnauthorized || e.rec.last(t).RouteID != "admin" {
		t.Fatalf("got %d route=%s, want 401 on admin", rr.Code, e.rec.last(t).RouteID)
	}
	// The same holds for the method.
	rr = e.do("GET", "/_rlg/v1/auth", hdr("X-Forwarded-Uri", "/pub/x"),
		hdr("X-Forwarded-Method", "DELETE"), hdr("X-Original-Method", "GET"))
	if rr.Code != http.StatusOK || e.rec.last(t).Method != "DELETE" {
		t.Fatalf("got %d method=%s", rr.Code, e.rec.last(t).Method)
	}
}

// SA2: an "ip" key part masks IPv6 clients to Settings.IPv6PrefixLen.
func TestHardenIPv6PrefixKey(t *testing.T) {
	up := upstream(t, "u")
	mk := func(bits int) *env {
		return newEnv(t, func(s *model.Snapshot) {
			s.Policies = []model.Policy{pol("ip1", model.AlgoFixedWindow, 1, "ip")}
			s.Routes = []model.Route{route("login", up.URL, "/login", "ip1")}
			s.Settings.IPv6PrefixLen = bits
		})
	}
	allowed := func(e *env, addrs ...string) int {
		n := 0
		for _, a := range addrs {
			if e.do("POST", "/login", remote(a)).Code == http.StatusOK {
				n++
			}
		}
		return n
	}
	var same64 []string
	for i := 1; i <= 20; i++ {
		same64 = append(same64, fmt.Sprintf("[2001:db8:1:2::%x]:443", i))
	}

	for _, bits := range []int{0, 64} { // 0 => default 64
		e := mk(bits)
		if n := allowed(e, same64...); n != 1 {
			t.Fatalf("bits=%d: %d requests allowed from one /64 (limit 1)", bits, n)
		}
		if k := e.rec.last(t).RateKey; k != "2001:db8:1:2::/64" {
			t.Fatalf("bits=%d: rate key %q", bits, k)
		}
		// A different /64 is a different bucket.
		if n := allowed(e, "[2001:db8:1:3::1]:443"); n != 1 {
			t.Fatalf("bits=%d: other /64 limited", bits)
		}
		// IPv4 and IPv4-mapped stay per address.
		if n := allowed(e, "198.51.100.1:1", "198.51.100.2:1", "[::ffff:198.51.100.3]:1"); n != 3 {
			t.Fatalf("bits=%d: IPv4 clients share a bucket (%d allowed)", bits, n)
		}
		if k := e.rec.last(t).RateKey; k != "198.51.100.3" {
			t.Fatalf("bits=%d: mapped key %q", bits, k)
		}
	}
	// /128 restores per-address keys; /48 widens the bucket.
	if n := allowed(mk(128), same64[:5]...); n != 5 {
		t.Fatalf("bits=128: %d of 5 allowed", n)
	}
	if n := allowed(mk(48), "[2001:db8:1:2::1]:1", "[2001:db8:1:ffff::1]:1"); n != 1 {
		t.Fatalf("bits=48: %d allowed within one /48", n)
	}
	// Composite keys mask only the ip part.
	e := newEnv(t, func(s *model.Snapshot) {
		s.Policies = []model.Policy{pol("p", model.AlgoFixedWindow, 5, "ip", "method")}
		s.Routes = []model.Route{route("r", up.URL, "/", "p")}
	})
	e.do("GET", "/x", remote("[2001:db8::7]:1"))
	if k := e.rec.last(t).RateKey; k != "2001:db8::/64|GET" {
		t.Fatalf("composite key %q", k)
	}
}

// SA2: the anonymous fallback of a "consumer" key part ("ip:<addr>") masks
// IPv6 clients the same way as the "ip" part.
func TestHardenIPv6PrefixConsumerFallback(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		s.Policies = []model.Policy{pol("pc", model.AlgoFixedWindow, 1, "consumer")}
		s.Routes = []model.Route{route("r", up.URL, "/", "pc")}
	})
	n := 0
	for i := 1; i <= 10; i++ {
		if e.do("GET", "/x", remote(fmt.Sprintf("[2001:db8:1:2::%x]:1", i))).Code == http.StatusOK {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d anonymous requests allowed from one /64 (limit 1)", n)
	}
	if k := e.rec.last(t).RateKey; k != "ip:2001:db8:1:2::/64" {
		t.Fatalf("rate key %q", k)
	}
	if e.do("GET", "/x", remote("198.51.100.1:1")).Code != http.StatusOK {
		t.Fatal("IPv4 client limited")
	}
	if k := e.rec.last(t).RateKey; k != "ip:198.51.100.1" {
		t.Fatalf("IPv4 rate key %q", k)
	}
}

// SA3: the dashboard session cookie never reaches upstreams through the
// data plane (browsers send it to every port of the same host).
func TestHardenAdminSessionCookieNotForwarded(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) { s.Routes = []model.Route{route("x", up.URL, "/")} })
	for _, c := range []struct{ in, want string }{
		{"rg_session=SECRET", ""},
		{"a=1; rg_session=SECRET; b=2", "a=1; b=2"},
		{"rg_session=SECRET;theme=dark", "theme=dark"},
		{"a=1; b=2", "a=1; b=2"},
		{"x=rg_session=no; y=2", "x=rg_session=no; y=2"}, // value, not a name
		{"rg_session_pref=keep", "rg_session_pref=keep"},
	} {
		ec := decodeEcho(t, e.do("GET", "/p", hdr("Cookie", c.in)))
		if got := ec.Headers["Cookie"]; got != c.want {
			t.Errorf("Cookie %q: upstream got %q, want %q", c.in, got, c.want)
		}
	}
}

// upgradeBackend answers any request with 101 and then serves HTTP/1.1
// requests on the raw connection (a stand-in for an h2c backend or any
// protocol multiplexed over the tunnel). It counts upgrades.
func upgradeBackend(t *testing.T) (addr string, upgrades func() int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	n := 0
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				io.Copy(io.Discard, req.Body)
				if req.Header.Get("Upgrade") == "" {
					fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Saw-Http2-Settings: %s\r\n\r\nplain", req.Header.Get("Http2-Settings"))
					return
				}
				mu.Lock()
				n++
				mu.Unlock()
				fmt.Fprintf(c, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", req.Header.Get("Upgrade"))
				for {
					r2, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(r2.URL.Path), r2.URL.Path)
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() int { mu.Lock(); defer mu.Unlock(); return n }
}

// rawUpgrade sends an upgrade request on a fresh connection to the gateway
// and returns the response and the connection (left open).
func rawUpgrade(t *testing.T, gw *httptest.Server, path, upHdr string, extra ...string) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", gw.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	req := "GET " + path + " HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: " + upHdr + "\r\n"
	for _, h := range extra {
		req += h + "\r\n"
	}
	fmt.Fprint(c, req+"\r\n")
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp, c, br
}

// SA4: h2c is always refused; other upgrades need Route.AllowUpgrade and
// count as one request. (Concurrency policies cannot be combined with
// AllowUpgrade; store.Validate rejects that.)
func TestHardenUpgrade(t *testing.T) {
	addr, upgrades := upgradeBackend(t)
	e := newEnv(t, func(s *model.Snapshot) {
		s.Policies = []model.Policy{
			pol("ip1", model.AlgoFixedWindow, 1000, "ip"),
			pol("open1", model.AlgoFixedWindow, 2, "ip"),
		}
		closed := route("closed", "http://"+addr, "/closed", "ip1")
		ws := route("ws", "http://"+addr, "/ws", "ip1", "open1")
		ws.AllowUpgrade = true
		s.Routes = []model.Route{closed, ws}
	})
	gw := httptest.NewServer(e.g)
	defer gw.Close()

	// h2c: rejected even on a route that allows upgrades, before the engine.
	for _, p := range []string{"/closed", "/ws"} {
		for _, up := range []string{"h2c", "H2C", "websocket, h2c"} {
			resp, _, _ := rawUpgrade(t, gw, p, up, "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA")
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s Upgrade %q: %s", p, up, resp.Status)
			}
		}
	}
	// h2c without Connection: Upgrade is refused too.
	rr := e.do("GET", "/ws/x", hdr("Upgrade", "h2c"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bare Upgrade: h2c: %d", rr.Code)
	}
	if upgrades() != 0 || e.eng.callCount() != 0 {
		t.Fatalf("h2c reached backend (%d) or engine (%d)", upgrades(), e.eng.callCount())
	}

	// websocket on a route without AllowUpgrade.
	resp, _, _ := rawUpgrade(t, gw, "/closed", "websocket")
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "upgrade_not_allowed") {
		t.Fatalf("closed route upgrade: %s %s", resp.Status, b)
	}
	if upgrades() != 0 {
		t.Fatal("upgrade reached backend")
	}
	if l := e.rec.last(t); l.RouteID != "closed" || l.Status != http.StatusBadRequest {
		t.Fatalf("log entry %+v", l)
	}

	// HTTP2-Settings is stripped from ordinary requests.
	rr = e.do("GET", "/closed/x", hdr("HTTP2-Settings", "AAMAAABk"))
	if rr.Code != http.StatusOK || rr.Header().Get("X-Saw-Http2-Settings") != "" {
		t.Fatalf("plain request: %d, upstream saw HTTP2-Settings=%q", rr.Code, rr.Header().Get("X-Saw-Http2-Settings"))
	}

	// Allowed websocket upgrade: one engine call per policy, the tunnel works.
	before := e.eng.callCount()
	resp, c1, br1 := rawUpgrade(t, gw, "/ws", "websocket")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("allowed upgrade: %s", resp.Status)
	}
	for i := 0; i < 5; i++ {
		fmt.Fprintf(c1, "GET /inner-%d HTTP/1.1\r\nHost: x\r\n\r\n", i)
		r2, err := http.ReadResponse(br1, nil)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, r2.Body)
	}
	if got := e.eng.callCount() - before; got != 2 { // ip1 + open1, once
		t.Fatalf("engine calls for one upgrade = %d, want 2", got)
	}
	c1.Close()
	// Connection opens are rate limited like requests (open1: 2 per minute).
	resp, _, _ = rawUpgrade(t, gw, "/ws", "websocket")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("second upgrade: %s", resp.Status)
	}
	resp, _, _ = rawUpgrade(t, gw, "/ws", "websocket")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third upgrade within the limit window: %s", resp.Status)
	}
}

// I4: an upgraded tunnel outlives the route timeout (which bounds only the
// handshake) and is closed at Route.UpgradeMaxDuration.
func TestHardenUpgradeMaxDuration(t *testing.T) {
	addr, _ := upgradeBackend(t)
	// A backend that accepts the upgrade request but never answers it.
	hang, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hang.Close() })
	go func() {
		for {
			c, err := hang.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(io.Discard, c) }(c)
		}
	}()
	const routeTimeout, maxDur = 150 * time.Millisecond, 700 * time.Millisecond
	e := newEnv(t, func(s *model.Snapshot) {
		ws := route("ws", "http://"+addr, "/ws")
		slow := route("slow", "http://"+hang.Addr().String(), "/slow")
		for _, r := range []*model.Route{&ws, &slow} {
			r.AllowUpgrade = true
			r.Timeout = model.Duration(routeTimeout)
			r.UpgradeMaxDuration = model.Duration(maxDur)
		}
		s.Routes = []model.Route{ws, slow}
	})
	gw := httptest.NewServer(e.g)
	defer gw.Close()

	// The handshake is bounded by the route timeout.
	t0 := time.Now()
	resp, _, _ := rawUpgrade(t, gw, "/slow", "websocket")
	if resp.StatusCode == http.StatusSwitchingProtocols || time.Since(t0) > maxDur {
		t.Fatalf("hung handshake: %s after %v", resp.Status, time.Since(t0))
	}

	t0 = time.Now()
	resp, c, br := rawUpgrade(t, gw, "/ws", "websocket")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %s", resp.Status)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	// Past the route timeout the tunnel still works.
	time.Sleep(2 * routeTimeout)
	fmt.Fprint(c, "GET /alive HTTP/1.1\r\nHost: x\r\n\r\n")
	r2, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("tunnel closed at the route timeout (after %v): %v", time.Since(t0), err)
	}
	io.Copy(io.Discard, r2.Body)
	// At the upgrade max duration the gateway closes it.
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("unexpected data on the tunnel")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("tunnel not closed at the upgrade max duration")
	}
	if d := time.Since(t0); d < maxDur-50*time.Millisecond || d > maxDur+2*time.Second {
		t.Fatalf("tunnel closed after %v, want ~%v", d, maxDur)
	}
}

// SA5: request trailers cannot smuggle X-RateGuard-*, hop-by-hop or
// client-IP headers to the upstream.
func TestHardenTrailers(t *testing.T) {
	type seen struct{ tr http.Header }
	ch := make(chan seen, 1)
	capSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		ch <- seen{r.Trailer.Clone()}
	}))
	defer capSrv.Close()
	e := newEnv(t, func(s *model.Snapshot) { s.Routes = []model.Route{route("x", capSrv.URL, "/")} })
	gw := httptest.NewServer(e.g)
	defer gw.Close()
	c, err := net.Dial("tcp", gw.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	bad := []string{"X-RateGuard-Consumer", "X-Rateguard_Consumer", "Keep-Alive", "Proxy-Authorization", "Te", "Upgrade",
		"X-Forwarded-For", "X-Real-Ip", "Forwarded", "X_Forwarded_For"}
	fmt.Fprintf(c, "POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTrailer: %s, X-Checksum\r\n\r\n2\r\nhi\r\n0\r\n", strings.Join(bad, ", "))
	for _, k := range bad {
		fmt.Fprintf(c, "%s: spoof\r\n", k)
	}
	fmt.Fprint(c, "X-Checksum: abc\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %s", resp.Status)
	}
	got := (<-ch).tr
	for k := range got {
		norm := strings.ReplaceAll(strings.ToLower(k), "_", "-")
		for _, b := range bad {
			if norm == strings.ReplaceAll(strings.ToLower(b), "_", "-") {
				t.Errorf("upstream saw trailer %q (all: %v)", k, got)
			}
		}
	}
	if _, ok := got["X-Checksum"]; !ok {
		t.Errorf("benign trailer declaration dropped: %v", got)
	}
}

// SA6: an untrusted peer's X-Real-IP / Forwarded / X-Forwarded-For never
// reach the upstream; X-Real-IP carries the client IP RateGuard used.
func TestHardenClientIPHeaders(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		s.Routes = []model.Route{route("x", up.URL, "/")}
		s.Settings.TrustedProxies = []string{"10.0.0.0/8"}
	})
	spoof := []func(*http.Request){hdr("X-Real-IP", "10.9.9.9"), hdr("Forwarded", "for=10.9.9.9"), hdr("X-Forwarded-For", "10.9.9.9, 10.8.8.8")}

	ec := decodeEcho(t, e.do("GET", "/a", spoof...)) // untrusted peer 192.0.2.10
	if ec.Headers["X-Real-Ip"] != "192.0.2.10" || ec.Headers["Forwarded"] != "" || ec.Headers["X-Forwarded-For"] != "192.0.2.10" {
		t.Fatalf("untrusted peer: X-Real-Ip=%q Forwarded=%q XFF=%q", ec.Headers["X-Real-Ip"], ec.Headers["Forwarded"], ec.Headers["X-Forwarded-For"])
	}

	// Trusted peer: the XFF chain is kept and X-Real-IP is the client IP
	// computed from it. Forwarded is never passed on (ReverseProxy's Rewrite
	// hook drops it; RateGuard does not parse it).
	ec = decodeEcho(t, e.do("GET", "/a", append(spoof, remote("10.0.0.5:1"), hdr("X-Forwarded-For", "203.0.113.7"))...))
	if ec.Headers["X-Real-Ip"] != "203.0.113.7" || ec.Headers["Forwarded"] != "" || ec.Headers["X-Forwarded-For"] != "203.0.113.7, 10.0.0.5" {
		t.Fatalf("trusted peer: X-Real-Ip=%q Forwarded=%q XFF=%q", ec.Headers["X-Real-Ip"], ec.Headers["Forwarded"], ec.Headers["X-Forwarded-For"])
	}
}

// SA6: underscore spellings of the client-IP headers (which CGI-style
// servers read as HTTP_X_REAL_IP etc.) never reach the upstream.
func TestHardenClientIPHeaderUnderscores(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) { s.Routes = []model.Route{route("x", up.URL, "/")} })
	bad := []string{"X_Real_IP", "x_forwarded_for", "X-Forwarded_Host", "X_FORWARDED_PROTO"}
	var opts []func(*http.Request)
	for _, k := range bad {
		k := k
		opts = append(opts, func(r *http.Request) { r.Header[k] = []string{"7.7.7.7"} })
	}
	opts = append(opts, hdr("X_Custom_Thing", "keep"))
	ec := decodeEcho(t, e.do("GET", "/a", opts...))
	for k, v := range ec.Headers {
		n := strings.ReplaceAll(strings.ToLower(k), "_", "-")
		if strings.Contains(k, "_") && (n == "x-real-ip" || n == "x-forwarded-for" || n == "x-forwarded-host" || n == "x-forwarded-proto") {
			t.Errorf("upstream saw %s: %s", k, v)
		}
		if v == "7.7.7.7" {
			t.Errorf("spoofed value reached upstream in %s", k)
		}
	}
	if ec.Headers["X-Real-Ip"] != "192.0.2.10" {
		t.Fatalf("X-Real-Ip=%q", ec.Headers["X-Real-Ip"])
	}
	if ec.Headers["X_custom_thing"] != "keep" && ec.Headers["X_Custom_Thing"] != "keep" {
		t.Fatalf("unrelated underscore header dropped: %v", ec.Headers)
	}
}

// SA7: host matching ignores case, a port and a trailing dot (in the request
// and in the route); paths stay case-sensitive.
func TestHardenHostMatchVariants(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		strict := route("strict", up.URL, "/api/login")
		strict.Match.Host = "API.example.com."
		strict.Priority = 10
		wild := route("wild", up.URL, "/")
		wild.Match.Host = "*.Example.org."
		wild.Priority = 5
		s.Routes = []model.Route{strict, wild, route("all", up.URL, "/")}
	})
	cases := []struct{ host, path, want string }{
		{"api.example.com", "/api/login", "strict"},
		{"API.EXAMPLE.COM", "/api/login", "strict"},
		{"api.example.com.", "/api/login", "strict"},
		{"api.example.com.:8443", "/api/login", "strict"},
		{"api.example.com:8443", "/api/login", "strict"},
		{"a.example.org.", "/x", "wild"},
		{"A.EXAMPLE.ORG:80", "/x", "wild"},
		{"example.org.", "/x", "all"},
		{"api.example.com", "/API/LOGIN", "all"}, // paths are case-sensitive (documented)
		{"other.test", "/api/login", "all"},
	}
	for _, c := range cases {
		e.do("GET", c.path, func(r *http.Request) { r.Host = c.host })
		if got := e.rec.last(t).RouteID; got != c.want {
			t.Errorf("Host %q %s -> %s, want %s", c.host, c.path, got, c.want)
		}
	}
}

// SA8: an allowed anonymous forward-auth answer carries an empty
// X-RateGuard-Consumer, so proxies that copy it overwrite a client value.
func TestHardenForwardAuthAnonymousConsumerHeader(t *testing.T) {
	up := upstream(t, "u")
	e := newEnv(t, func(s *model.Snapshot) {
		s.Routes = []model.Route{route("pub", up.URL, "/")}
		s.Consumers = []model.Consumer{consumer("acme", "rlg_live_acmekey")}
	})
	for _, target := range []string{"/_rlg/v1/auth/orders", "/_rlg/v1/auth"} {
		rr := e.do("GET", target, hdr("X-RateGuard-Consumer", "acme"), hdr("X-Forwarded-Uri", "/orders"))
		v, ok := rr.Header()["X-Rateguard-Consumer"]
		if rr.Code != http.StatusOK || !ok || len(v) != 1 || v[0] != "" {
			t.Fatalf("%s: %d X-RateGuard-Consumer=%q present=%v", target, rr.Code, v, ok)
		}
	}
	rr := e.do("GET", "/_rlg/v1/auth", hdr("X-API-Key", "rlg_live_acmekey"))
	if rr.Code != http.StatusOK || rr.Header().Get("X-RateGuard-Consumer") != "acme" {
		t.Fatalf("keyed: %d %q", rr.Code, rr.Header().Get("X-RateGuard-Consumer"))
	}
}
