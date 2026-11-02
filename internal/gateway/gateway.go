// Package gateway is the RateGuard data plane: route matching, API key auth,
// policy evaluation, reverse proxying, the check API and the simulator.
//
// Concurrency model: Apply compiles a snapshot into an immutable struct and
// swaps it in with an atomic pointer; request handling only does atomic loads
// and reads from that struct, so the hot path takes no gateway-wide locks.
package gateway

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/ratelimit"
	"ratelimitergateway/internal/store"
)

// Recorder receives one LogEntry per request (allowed ones sampled).
type Recorder interface{ Record(model.LogEntry) }

// TokenVerifier authenticates check-API bearer tokens.
type TokenVerifier interface {
	Verify(token, scope string) bool
}

type Options struct {
	Engine   ratelimit.Engine // required; nil behaves as an always-failing backend
	Recorder Recorder         // optional
	Tokens   TokenVerifier    // optional; nil => check API rejects every caller
	Logger   *slog.Logger     // optional
}

type Gateway struct {
	engine   ratelimit.Engine
	recorder Recorder
	tokens   TokenVerifier
	log      *slog.Logger
	now      func() time.Time // overridable in tests

	cfg atomic.Pointer[compiled]

	// Upstream proxy cache, keyed by upstream URL. Touched only by Apply
	// (under proxyMu) -- never on the request path, where each route holds a
	// direct pointer to its proxy.
	proxyMu   sync.Mutex
	proxies   map[string]*httputil.ReverseProxy
	transport *http.Transport
}

func New(o Options) *Gateway {
	g := &Gateway{
		engine: o.Engine, recorder: o.Recorder, tokens: o.Tokens, log: o.Logger,
		now: time.Now, proxies: map[string]*httputil.ReverseProxy{},
	}
	if g.engine == nil {
		g.engine = noEngine{}
	}
	if g.log == nil {
		g.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 64
	t.MaxIdleConns = 512
	g.transport = t
	return g
}

// noEngine is used when Options.Engine is nil.
type noEngine struct{}

func (noEngine) Allow(context.Context, string, ratelimit.Params) (ratelimit.Decision, error) {
	return ratelimit.Decision{}, errNoEngine
}
func (noEngine) Peek(context.Context, string, ratelimit.Params) (ratelimit.Decision, bool, error) {
	return ratelimit.Decision{}, false, errNoEngine
}
func (noEngine) Release(context.Context, string, ratelimit.Params) error { return nil }
func (noEngine) Reset(context.Context, string, ratelimit.Params) error   { return errNoEngine }
func (noEngine) Name() string                                            { return "none" }
func (noEngine) Healthy(context.Context) error                           { return errNoEngine }
func (noEngine) Close() error                                            { return nil }

// Apply validates (store.Validate), compiles and atomically installs s. The
// snapshot must not be mutated afterwards (callers Clone to edit).
func (g *Gateway) Apply(s *model.Snapshot) error {
	if err := store.Validate(s); err != nil {
		return err
	}
	g.cfg.Store(g.compile(s))
	return nil
}

// Current returns the applied snapshot, or nil before the first Apply.
func (g *Gateway) Current() *model.Snapshot {
	if c := g.cfg.Load(); c != nil {
		return c.snap
	}
	return nil
}

// EngineKey is the full engine key for a policy's composite bucket key.
func (g *Gateway) EngineKey(policyID, composite string) string { return policyID + ":" + composite }

// proxyFor returns the cached ReverseProxy for an upstream URL, creating it
// on first use. Timeouts and prefix stripping are per request, so one proxy
// per upstream URL is shareable between routes and across Apply calls.
func (g *Gateway) proxyFor(key string, target *url.URL) *httputil.ReverseProxy {
	g.proxyMu.Lock()
	defer g.proxyMu.Unlock()
	if p, ok := g.proxies[key]; ok {
		return p
	}
	p := &httputil.ReverseProxy{
		Rewrite:        rewriteRequest(target),
		Transport:      g.transport,
		FlushInterval:  -1, // stream (SSE, chunked) responses straight through
		ModifyResponse: modifyResponse,
		ErrorHandler:   proxyError,
		ErrorLog:       slog.NewLogLogger(g.log.Handler(), slog.LevelDebug),
	}
	g.proxies[key] = p
	return p
}

func (g *Gateway) pruneProxies(used map[string]bool) {
	g.proxyMu.Lock()
	defer g.proxyMu.Unlock()
	for k := range g.proxies {
		if !used[k] {
			delete(g.proxies, k)
		}
	}
}

// ---------------------------------------------------------------------
// HTTP entry point
// ---------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", strconv.Itoa(len(b)+1))
	w.WriteHeader(status)
	w.Write(b)
	w.Write([]byte{'\n'})
}

func errBody(code, msg string) map[string]string {
	if msg == "" {
		return map[string]string{"error": code}
	}
	return map[string]string{"error": code, "message": msg}
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/_rlg/") {
		g.serveReserved(w, r)
		return
	}
	g.serveProxy(w, r)
}

// Reserved paths are never proxied, even when no config is loaded.
func (g *Gateway) serveReserved(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/_rlg/healthz":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeJSON(w, http.StatusMethodNotAllowed, errBody("method_not_allowed", ""))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case "/_rlg/readyz":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeJSON(w, http.StatusMethodNotAllowed, errBody("method_not_allowed", ""))
			return
		}
		if g.cfg.Load() == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "error": "config not loaded"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := g.engine.Healthy(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "error": "engine unhealthy"})
			g.log.Warn("readyz: engine unhealthy", "err", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case "/_rlg/v1/check":
		g.serveCheck(w, r)
	default:
		writeJSON(w, http.StatusNotFound, errBody("not_found", ""))
	}
}

// statusWriter records status and bytes. Unwrap lets http.ResponseController
// (used by ReverseProxy for Flush/Hijack) reach the real writer.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 && code >= 200 || code == http.StatusSwitchingProtocols { // ignore 1xx informational
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// reqState travels in the request context to the proxy callbacks.
type reqState struct {
	consumerID  string
	clientIP    string
	xff         string
	proto       string
	host        string
	rlHeaders   bool
	upstreamDur time.Duration
	upstreamErr error
	started     time.Time
}

type ctxKey struct{}

func (g *Gateway) serveProxy(w http.ResponseWriter, r *http.Request) {
	start := g.now()
	sw := &statusWriter{ResponseWriter: w}
	w = sw
	cfg := g.cfg.Load()
	le := model.LogEntry{
		Time: start, Method: r.Method, Host: r.Host, Path: r.URL.Path,
		UserAgent: trunc(r.UserAgent()), Source: "proxy", Decision: model.DecisionAllowed,
	}
	var out *outcome
	var st *reqState
	defer func() {
		if out != nil {
			g.releaseSlots(out.held)
		}
		le.Status = sw.status
		if le.Status == 0 {
			le.Status = http.StatusOK
		}
		le.BytesOut = sw.bytes
		le.LatencyMs = float64(g.now().Sub(start)) / float64(time.Millisecond)
		if st != nil {
			le.UpstreamMs = float64(st.upstreamDur) / float64(time.Millisecond)
			if st.upstreamErr != nil {
				le.Decision = model.DecisionError
				le.Error = "upstream: " + st.upstreamErr.Error()
			}
		}
		g.record(cfg, le)
	}()

	if cfg == nil {
		le.Decision, le.Error = model.DecisionError, "config not loaded"
		writeJSON(w, http.StatusServiceUnavailable, errBody("not_ready", "configuration not loaded"))
		return
	}

	xff := r.Header.Values("X-Forwarded-For")
	ip := cfg.clientIP(r.RemoteAddr, xff)
	le.ClientIP = ip
	route := cfg.match(r.Host, r.URL.Path, r.Method)
	if route == nil {
		le.Decision = model.DecisionNoRoute
		writeJSON(w, http.StatusNotFound, errBody("no_route", ""))
		return
	}
	le.RouteID, le.RouteName = route.r.ID, route.r.Name
	if cfg.exposeDecision {
		w.Header().Set("X-RateGuard-Route", route.r.ID)
	}

	ri := &reqInfo{method: r.Method, host: r.Host, path: r.URL.Path, ip: ip, route: route, header: r.Header.Get}
	var q url.Values
	ri.query = func(name string) string {
		if q == nil {
			q = r.URL.Query()
		}
		return q.Get(name)
	}
	ri.apiKey = cfg.extractKey(r.Header.Get)
	cons, reason := cfg.authenticate(ri.apiKey, start)
	if reason != "" || (cons == nil && route.r.RequireAPIKey) {
		msg := "A valid API key is required"
		if reason != "" {
			le.Error = reason // detail for operators only; the client sees a generic message
		}
		le.Decision = model.DecisionUnauthorized
		w.Header().Set("WWW-Authenticate", `Bearer realm="rateguard"`)
		writeJSON(w, http.StatusUnauthorized, errBody("unauthorized", msg))
		return
	}
	ri.consumer = cons
	if cons != nil {
		le.ConsumerID, le.ConsumerName = cons.c.ID, cons.c.Name
	}

	if cfg.maxBody > 0 {
		if r.ContentLength > cfg.maxBody {
			le.Decision = model.DecisionError
			le.Error = "request body too large"
			writeJSON(w, http.StatusRequestEntityTooLarge, errBody("payload_too_large", ""))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, cfg.maxBody)
	}

	ectx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	out = g.evaluate(ectx, ri, evalOpts{costMul: 1})
	cancel()
	for _, s := range out.soft {
		g.log.Warn("limiter error, failing open", "route", route.r.ID, "detail", s)
	}
	if b := out.best; b != nil {
		le.PolicyID, le.RateKey = b.cp.p.ID, b.composite
		le.Limit, le.Remaining = limitOf(b), b.dec.Remaining
	}
	switch {
	case out.failed != nil:
		f := out.failed
		le.PolicyID, le.RateKey = f.cp.p.ID, f.composite
		le.Decision, le.Error = model.DecisionError, "limiter unavailable: "+f.err.Error()
		g.log.Error("limiter unavailable, failing closed", "policy", f.cp.p.ID, "err", f.err)
		if cfg.exposeDecision {
			w.Header().Set("X-RateGuard-Policy", f.cp.p.ID)
		}
		writeJSON(w, http.StatusServiceUnavailable, errBody("limiter_unavailable", "Rate limiter backend unavailable"))
		return
	case out.denier != nil:
		d := out.denier
		le.Decision = model.DecisionLimited
		hdrs := rateHeaders(cfg, d, start, true)
		for k, v := range hdrs {
			w.Header().Set(k, v)
		}
		if cfg.exposeDecision {
			w.Header().Set("X-RateGuard-Policy", d.cp.p.ID)
		}
		retry := retryAfterSeconds(d.dec)
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "rate_limited", "message": "Rate limit exceeded", "policy": d.cp.p.Name,
			"limit": limitOf(d), "remaining": 0, "retry_after_s": retry, "reset_s": ceilSeconds(d.dec.ResetAfter),
		})
		return
	case out.shadow:
		le.Decision = model.DecisionShadowLimited
		for i := range out.results {
			if res := &out.results[i]; res.denied && res.cp.mode == model.ModeShadow {
				le.PolicyID, le.RateKey = res.cp.p.ID, res.composite
				le.Limit, le.Remaining = limitOf(res), res.dec.Remaining
				break
			}
		}
	}

	st = &reqState{consumerID: le.ConsumerID, clientIP: ip, started: g.now()}
	st.xff, st.proto, st.host = forwardedFor(cfg, r, xff)
	if b := out.best; b != nil {
		for k, v := range rateHeaders(cfg, b, start, false) {
			w.Header().Set(k, v)
		}
		st.rlHeaders = true
		if cfg.exposeDecision {
			w.Header().Set("X-RateGuard-Policy", b.cp.p.ID)
		}
	}

	// Per-request copy so StripPrefix never mutates the caller's URL.
	ctx, cancelUp := context.WithTimeout(context.WithValue(r.Context(), ctxKey{}, st), route.timeout)
	defer cancelUp()
	r2 := r.WithContext(ctx)
	u := *r.URL
	r2.URL = &u
	if route.r.StripPrefix && route.prefix != "" {
		p := strings.TrimPrefix(u.Path, route.prefix)
		if p == "" || p[0] != '/' {
			p = "/" + p
		}
		u.Path, u.RawPath = p, ""
	}
	route.proxy.ServeHTTP(w, r2)
}

// record applies sampling: only allowed, non-error requests are sampled.
func (g *Gateway) record(cfg *compiled, le model.LogEntry) {
	if g.recorder == nil {
		return
	}
	if le.Decision == model.DecisionAllowed && le.Status < 500 && cfg != nil {
		if cfg.sample <= 0 || (cfg.sample < 1 && rand.Float64() >= cfg.sample) {
			return
		}
	}
	g.recorder.Record(le)
}

func limitOf(r *polResult) int {
	if r.dec.Limit > 0 {
		return r.dec.Limit
	}
	return r.params.Limit
}

func ceilSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(math.Ceil(d.Seconds()))
}

func retryAfterSeconds(d ratelimit.Decision) int {
	s := ceilSeconds(d.RetryAfter)
	if s < 1 {
		s = 1
	}
	return s
}

// rateHeaders builds the IETF (and optionally legacy) headers for r.
func rateHeaders(cfg *compiled, r *polResult, now time.Time, limited bool) map[string]string {
	reset := ceilSeconds(r.dec.ResetAfter)
	h := map[string]string{
		"RateLimit-Limit":     strconv.Itoa(limitOf(r)),
		"RateLimit-Remaining": strconv.Itoa(r.dec.Remaining),
		"RateLimit-Reset":     strconv.Itoa(reset),
	}
	if !r.cp.conc {
		w := ceilSeconds(r.params.Window)
		if w < 1 {
			w = 1
		}
		h["RateLimit-Policy"] = strconv.Itoa(r.params.Limit) + ";w=" + strconv.Itoa(w)
	}
	if cfg.legacyHeaders {
		h["X-RateLimit-Limit"] = h["RateLimit-Limit"]
		h["X-RateLimit-Remaining"] = h["RateLimit-Remaining"]
		h["X-RateLimit-Reset"] = strconv.FormatInt(now.Add(time.Duration(reset)*time.Second).Unix(), 10)
	}
	if limited {
		h["Retry-After"] = strconv.Itoa(retryAfterSeconds(r.dec))
	}
	return h
}

// ---------------------------------------------------------------------
// Reverse proxy plumbing
// ---------------------------------------------------------------------

// forwardedFor computes the X-Forwarded-* values sent upstream. When the
// immediate peer is a trusted proxy its inbound values are preserved/appended;
// otherwise they are replaced so clients cannot spoof them.
func forwardedFor(cfg *compiled, r *http.Request, inboundXFF []string) (xff, proto, host string) {
	peer := r.RemoteAddr
	if h, _, err := net.SplitHostPort(peer); err == nil {
		peer = h
	}
	proto = "http"
	if r.TLS != nil {
		proto = "https"
	}
	host = r.Host
	trusted := false
	if len(cfg.trusted) > 0 {
		if a, err := parseAddr(peer); err == nil {
			trusted = cfg.isTrusted(a)
		}
	}
	xff = peer
	if trusted {
		if len(inboundXFF) > 0 {
			xff = strings.Join(inboundXFF, ", ") + ", " + peer
		}
		if p := r.Header.Get("X-Forwarded-Proto"); p == "http" || p == "https" {
			proto = p
		}
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			host = h
		}
	}
	return
}

func rewriteRequest(target *url.URL) func(*httputil.ProxyRequest) {
	return func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		out := pr.Out
		// Spoof protection: never forward client-supplied X-RateGuard-*.
		for k := range out.Header {
			if strings.HasPrefix(k, "X-Rateguard-") {
				delete(out.Header, k)
			}
		}
		if st, _ := pr.In.Context().Value(ctxKey{}).(*reqState); st != nil {
			out.Header.Set("X-Forwarded-For", st.xff)
			out.Header.Set("X-Forwarded-Proto", st.proto)
			out.Header.Set("X-Forwarded-Host", st.host)
			if st.consumerID != "" {
				out.Header.Set("X-RateGuard-Consumer", st.consumerID)
			}
		}
	}
}

func modifyResponse(resp *http.Response) error {
	st, _ := resp.Request.Context().Value(ctxKey{}).(*reqState)
	if st == nil {
		return nil
	}
	st.upstreamDur = time.Since(st.started)
	h := resp.Header
	for k := range h {
		// Our headers are authoritative; also never leak X-RateGuard-* from upstream.
		if strings.HasPrefix(k, "X-Rateguard-") {
			delete(h, k)
		}
	}
	if st.rlHeaders {
		for _, k := range []string{"Ratelimit-Limit", "Ratelimit-Remaining", "Ratelimit-Reset", "Ratelimit-Policy",
			"X-Ratelimit-Limit", "X-Ratelimit-Remaining", "X-Ratelimit-Reset", "Retry-After"} {
			if k == "Retry-After" && resp.StatusCode != http.StatusTooManyRequests {
				continue
			}
			delete(h, k)
		}
	}
	return nil
}

func proxyError(w http.ResponseWriter, r *http.Request, err error) {
	if st, _ := r.Context().Value(ctxKey{}).(*reqState); st != nil {
		st.upstreamErr = err
		st.upstreamDur = time.Since(st.started)
	}
	var mbe *http.MaxBytesError
	if asMaxBytes(err, &mbe) {
		writeJSON(w, http.StatusRequestEntityTooLarge, errBody("payload_too_large", ""))
		return
	}
	writeJSON(w, http.StatusBadGateway, errBody("bad_gateway", ""))
}
