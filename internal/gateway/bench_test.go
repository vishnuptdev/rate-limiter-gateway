package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/ratelimit"
)

// Gateway overhead benchmarks. The upstream is an in-process RoundTripper
// stub, so only RateGuard's own work is measured (no sockets): routing, key
// auth (sha256), key building, the memory engine, headers, ReverseProxy
// plumbing and the log entry.

type stubTransport struct{}

func (stubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {"text/plain"}}, Body: http.NoBody, ContentLength: 0, Request: r,
	}, nil
}

type nopRecorder struct{}

func (nopRecorder) Record(model.LogEntry) {}

const benchKey = "rlg_live_bench00000000000000000000000"

// benchGateway builds a gateway on the real memory engine with three
// routes: /open (per-IP, huge limit), /keyed (per-consumer, API key
// required, huge limit) and /limited (global, limit 1: every request after
// the first is a 429).
func benchGateway(b *testing.B, mut ...func(*model.Snapshot)) *Gateway {
	b.Helper()
	eng := ratelimit.NewMemory(ratelimit.MemoryOptions{})
	b.Cleanup(func() { eng.Close() })
	g := New(Options{Engine: eng, Recorder: nopRecorder{}, Tokens: tokens{"chk": "check"}})
	g.transport.RegisterProtocol("http", stubTransport{}) // never dial
	const up = "http://upstream.invalid"
	s := model.NewSnapshot()
	s.Version = 1
	big := pol("big", model.AlgoTokenBucket, 1_000_000_000)
	big.Window = model.Duration(time.Second)
	bigIP := big
	bigIP.ID, bigIP.KeyBy = "bigip", []string{"ip"}
	bigC := big
	bigC.ID, bigC.KeyBy = "bigc", []string{"consumer"}
	one := pol("one", model.AlgoFixedWindow, 1, "global")
	one.Window = model.Duration(time.Hour)
	s.Policies = []model.Policy{bigIP, bigC, one}
	s.Consumers = []model.Consumer{consumer("bench", benchKey)}
	keyed := route("keyed", up, "/keyed", "bigc")
	keyed.RequireAPIKey = true
	s.Routes = []model.Route{route("open", up, "/open", "bigip"), keyed, route("limited", up, "/limited", "one")}
	for _, m := range mut {
		m(s)
	}
	if err := g.Apply(s); err != nil {
		b.Fatal(err)
	}
	return g
}

func benchRequest(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = "192.0.2.10:5555"
	r.Header.Set("User-Agent", "bench/1.0")
	r.Header.Set("Accept", "*/*")
	return r
}

func runServe(b *testing.B, g *Gateway, mk func() *http.Request, want int) {
	g.ServeHTTP(httptest.NewRecorder(), mk()) // warm up (and use up /limited's single slot)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		r := mk()
		for pb.Next() {
			rr := httptest.NewRecorder()
			g.ServeHTTP(rr, r)
			if rr.Code != want {
				b.Errorf("status %d, want %d: %s", rr.Code, want, rr.Body.String())
				return
			}
		}
	})
}

func BenchmarkGatewayProxyAllowed(b *testing.B) {
	g := benchGateway(b)
	runServe(b, g, func() *http.Request { return benchRequest("GET", "/open/items?id=1") }, 200)
}

func BenchmarkGatewayProxyAllowedAPIKey(b *testing.B) {
	g := benchGateway(b)
	runServe(b, g, func() *http.Request {
		r := benchRequest("GET", "/keyed/items")
		r.Header.Set("X-API-Key", benchKey)
		return r
	}, 200)
}

func BenchmarkGatewayLimited(b *testing.B) {
	g := benchGateway(b)
	runServe(b, g, func() *http.Request { return benchRequest("GET", "/limited/x") }, 429)
}

func BenchmarkForwardAuthAllowed(b *testing.B) {
	g := benchGateway(b)
	runServe(b, g, func() *http.Request {
		r := benchRequest("GET", "/_rlg/v1/auth")
		r.Header.Set("X-Forwarded-Method", "GET")
		r.Header.Set("X-Forwarded-Uri", "/keyed/items?id=7")
		r.Header.Set("X-API-Key", benchKey)
		return r
	}, 200)
}

func BenchmarkCheckAPI(b *testing.B) {
	g := benchGateway(b)
	body := []byte(`{"method":"GET","path":"/keyed/items","api_key":"` + benchKey + `","ip":"192.0.2.10"}`)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r := httptest.NewRequest("POST", "/_rlg/v1/check", bytes.NewReader(body))
			r.Header.Set("Authorization", "Bearer chk")
			rr := httptest.NewRecorder()
			g.ServeHTTP(rr, r)
			if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"allowed":true`) {
				b.Errorf("check: %d %s", rr.Code, rr.Body.String())
				return
			}
		}
	})
}
