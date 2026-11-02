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
	pathpkg "path"
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
	// MaxShapingWaiters caps how many requests may wait in leaky-bucket
	// queues at once, across all keys; default 10000. Beyond it requests get
	// 429 instead of parking another goroutine.
	MaxShapingWaiters int
}

const defaultMaxShapingWaiters = 10000

type Gateway struct {
	engine   ratelimit.Engine
	recorder Recorder
	tokens   TokenVerifier
	log      *slog.Logger
	now      func() time.Time // overridable in tests

	engineLocal bool // engine never does I/O: skip the per-call deadline

	shapeWaiters    atomic.Int64
	maxShapeWaiters int64

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
	g.maxShapeWaiters = int64(o.MaxShapingWaiters)
	if g.maxShapeWaiters <= 0 {
		g.maxShapeWaiters = defaultMaxShapingWaiters
	}
	if g.engine == nil {
		g.engine = noEngine{}
	}
	if l, ok := g.engine.(inProcessEngine); ok {
		g.engineLocal = l.InProcess()
	}
	if g.log == nil {
		g.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	g.transport = newTransport()
	return g
}

// newTransport is the upstream transport shared by every route. Keep-alive
// pools are sized so a busy upstream does not churn connections (each
// extra dial costs a loopback/LAN round trip plus TIME_WAIT state); HTTP/2
// is negotiated for TLS upstreams.
func newTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 2048
	t.MaxIdleConnsPerHost = 512
	t.IdleConnTimeout = 90 * time.Second
	t.ForceAttemptHTTP2 = true
	return t
}

// bufferPool recycles the 32KB copy buffers ReverseProxy would otherwise
// allocate for every proxied response body (the dominant allocation on the
// proxy path). httputil.BufferPool hands buffers over as []byte, so the
// pool stores *[proxyBufSize]byte (a single pointer: no extra allocation
// per Put) and converts back with a slice expression.
type bufferPool struct{ p sync.Pool }

const proxyBufSize = 32 << 10

func (b *bufferPool) Get() []byte {
	if v, ok := b.p.Get().(*[proxyBufSize]byte); ok {
		return v[:]
	}
	return new([proxyBufSize]byte)[:]
}

func (b *bufferPool) Put(buf []byte) {
	if cap(buf) != proxyBufSize {
		return
	}
	b.p.Put((*[proxyBufSize]byte)(buf[:proxyBufSize]))
}

var proxyBuffers = &bufferPool{}

// inProcessEngine is implemented by engines that never block on I/O (the
// memory engine), for which a per-request deadline is pure overhead (a
// timer and a context allocation per request).
type inProcessEngine interface{ InProcess() bool }

const engineTimeout = 5 * time.Second

func nopCancel() {}

// engineCtx bounds an engine call: 5s for networked engines; in-process
// engines get the request context unchanged.
func (g *Gateway) engineCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if g.engineLocal {
		return ctx, nopCancel
	}
	return context.WithTimeout(ctx, engineTimeout)
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
		BufferPool:     proxyBuffers,
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
	p, ok := cleanPath(r.URL)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", ""))
		return
	}
	if strings.HasPrefix(p, "/_rlg/") {
		g.serveReserved(w, r, p)
		return
	}
	g.serveProxy(w, r, p)
}

// cleanPath normalises the decoded request path once, at entry: path.Clean
// (resolving "." / ".." / "//", also after percent-decoding), always
// leading "/", trailing slash preserved. It reports false for paths that are
// ambiguous between layers: an encoded slash (%2F), NUL, or a backslash.
// The result is what is matched, keyed on and forwarded.
func cleanPath(u *url.URL) (string, bool) {
	esc := u.EscapedPath()
	if strings.Contains(esc, "%2f") || strings.Contains(esc, "%2F") || strings.Contains(esc, "\\") ||
		strings.ContainsRune(u.Path, 0) || strings.Contains(esc, "%00") || strings.Contains(u.Path, "\\") {
		return "", false
	}
	p := u.Path
	if p == "" {
		return "/", true
	}
	trailing := strings.HasSuffix(p, "/")
	if p[0] != '/' {
		p = "/" + p
	}
	p = pathpkg.Clean(p) // allocation-free when p is already clean
	if trailing && p != "/" {
		p += "/"
	}
	return p, true
}

// Reserved paths are never proxied, even when no config is loaded.
func (g *Gateway) serveReserved(w http.ResponseWriter, r *http.Request, p string) {
	switch p {
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
		if p == authPath || strings.HasPrefix(p, authPath+"/") {
			g.serveAuth(w, r, p)
			return
		}
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

func (g *Gateway) serveProxy(w http.ResponseWriter, r *http.Request, cleaned string) {
	start := g.now()
	sw := &statusWriter{ResponseWriter: w}
	w = sw
	cfg := g.cfg.Load()
	le := model.LogEntry{
		Time: start, Method: r.Method, Host: r.Host, Path: cleaned,
		UserAgent: trunc(r.UserAgent()), Source: "proxy", Decision: model.DecisionAllowed,
	}
	var out *outcome
	var st *reqState
	reserved := false // holds one global shaping-waiter slot
	defer func() {
		if reserved {
			g.shapeWaiters.Add(-1)
		}
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
	// h2c would turn the connection into an HTTP/2 tunnel whose streams
	// bypass per-request routing and limiting: refused on every route.
	if isH2CUpgrade(r.Header) {
		le.Decision, le.Error = model.DecisionError, "h2c upgrade refused"
		writeJSON(w, http.StatusBadRequest, errBody("upgrade_not_allowed", "h2c upgrades are not supported"))
		return
	}
	route := cfg.match(r.Host, cleaned, r.Method)
	if route == nil {
		le.Decision = model.DecisionNoRoute
		writeJSON(w, http.StatusNotFound, errBody("no_route", ""))
		return
	}
	le.RouteID, le.RouteName = route.r.ID, route.r.Name
	// Any other upgrade (WebSocket) is a tunnel limited only as its one
	// opening request, so a route must opt in.
	if !route.r.AllowUpgrade && upgradeType(r.Header) != "" {
		le.Decision, le.Error = model.DecisionError, "upgrade not allowed on route"
		writeJSON(w, http.StatusBadRequest, errBody("upgrade_not_allowed", "this route does not accept protocol upgrades"))
		return
	}
	if cfg.exposeDecision {
		w.Header().Set("X-RateGuard-Route", route.r.ID)
	}

	ri := &reqInfo{method: r.Method, host: r.Host, path: cleaned, ip: ip, route: route, header: r.Header.Get}
	var q url.Values
	ri.query = func(name string) string {
		if q == nil {
			q = r.URL.Query()
		}
		return q.Get(name)
	}
	ri.apiKey = cfg.extractKey(r.Header.Get)
	cons, reason := ri.authenticate(cfg, start)
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

	// Routes with an enforcing leaky bucket reserve a global waiter slot
	// BEFORE the engine is consulted: a rejection after Allow would already
	// have advanced the bucket (phantom backlog charged to retrying clients).
	if route.shaper != nil {
		res, ok := g.reserveShaper(ri, route)
		if !ok {
			le.PolicyID, le.RateKey, le.Limit = route.shaper.p.ID, res.composite, res.dec.Limit
			le.Decision, le.Error = model.DecisionLimited, "shaping_queue_full"
			g.writeLimited(w, cfg, res, start)
			return
		}
		reserved = true
	}

	ectx, cancel := g.engineCtx(r.Context())
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
		g.writeLimited(w, cfg, d, start)
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

	// Leaky-bucket shaping: hold the admitted request until its queue slot
	// comes up. A client that disconnects while queued is not proxied; its
	// concurrency slots (if any) are released by the deferred releaseSlots.
	wait, tooLongSrc, tooLong := out.shapingDelay()
	if tooLong {
		// Defensive only: store.Validate bounds the delay below the ceiling.
		// Allow has already consumed the slot and nothing refunds it; this is
		// acceptable because the path is unreachable for validated config, and
		// releasing the request early would break the shaping rate.
		le.PolicyID, le.RateKey, le.Limit = tooLongSrc.cp.p.ID, tooLongSrc.composite, limitOf(tooLongSrc)
		le.Decision, le.Error = model.DecisionLimited, "shaping_delay_too_long"
		g.writeLimited(w, cfg, tooLongSrc, start)
		return
	}
	if wait <= 0 && reserved {
		reserved = false
		g.shapeWaiters.Add(-1)
	}
	if wait > 0 {
		if !waitShaping(r.Context(), wait) {
			le.Decision, le.Error = model.DecisionError, "client_closed"
			w.WriteHeader(499) // nginx convention: client closed request
			return
		}
		reserved = false
		g.shapeWaiters.Add(-1)
	}

	st = &reqState{consumerID: le.ConsumerID, clientIP: ip, started: g.now()}
	st.xff, st.proto, st.host = forwardedFor(cfg, r, xff)
	if b := out.best; b != nil {
		setRateHeaders(w.Header(), cfg, b, start, false)
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
	u.Path, u.RawPath = cleaned, ""
	if route.r.StripPrefix && route.prefix != "" {
		p := strings.TrimPrefix(cleaned, route.prefix)
		if p == "" || p[0] != '/' {
			p = "/" + p
		}
		u.Path = p
	}
	route.proxy.ServeHTTP(w, r2)
}

// reserveShaper takes one global shaping-waiter slot for a route with an
// enforcing leaky bucket. When the queue cap is reached it returns false and a
// synthetic limited result for the 429; on success the caller owns the slot
// and must give it back (shapeWaiters.Add(-1)).
func (g *Gateway) reserveShaper(ri *reqInfo, route *croute) (*polResult, bool) {
	if g.shapeWaiters.Add(1) <= g.maxShapeWaiters {
		return nil, true
	}
	g.shapeWaiters.Add(-1)
	prm, _ := ri.effective(route.shaper, 1)
	res := &polResult{cp: route.shaper, params: prm, composite: ri.composite(route.shaper),
		dec: ratelimit.Decision{Limit: prm.Burst, ResetAfter: time.Second, RetryAfter: time.Second}}
	if res.dec.Limit == 0 {
		res.dec.Limit = prm.Limit
	}
	return res, false
}

// waitShaping sleeps for d, reporting false if ctx ends first.
func waitShaping(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
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

// writeLimited writes the standard 429 response for a denied (or shaping
// rejected) policy result: RateLimit-* headers, Retry-After and the JSON body.
func (g *Gateway) writeLimited(w http.ResponseWriter, cfg *compiled, d *polResult, start time.Time) {
	g.writeLimitedAs(w, http.StatusTooManyRequests, cfg, d, start)
}

// writeLimitedAs is writeLimited with a caller-chosen status (forward auth's
// deny_status); headers and body are identical.
func (g *Gateway) writeLimitedAs(w http.ResponseWriter, status int, cfg *compiled, d *polResult, start time.Time) {
	setRateHeaders(w.Header(), cfg, d, start, true)
	if cfg.exposeDecision {
		w.Header().Set("X-RateGuard-Policy", d.cp.p.ID)
	}
	b := limitedBody(d)
	h := w.Header()
	h["Content-Type"] = jsonContentType
	h["Content-Length"] = []string{strconv.Itoa(len(b))}
	w.WriteHeader(status)
	w.Write(b)
}

var jsonContentType = []string{"application/json"}

// limitedBody renders the 429 JSON body byte-for-byte as
// writeJSON(map[string]any{...}) would (sorted keys, trailing newline),
// without reflection; the policy name is JSON-encoded once at compile time.
func limitedBody(d *polResult) []byte {
	name := d.cp.nameJSON
	if name == "" { // cpolicy built outside compile (tests)
		nb, _ := json.Marshal(d.cp.p.Name)
		name = string(nb)
	}
	b := make([]byte, 0, 128+len(name))
	b = append(b, `{"error":"rate_limited","limit":`...)
	b = strconv.AppendInt(b, int64(limitOf(d)), 10)
	b = append(b, `,"message":"Rate limit exceeded","policy":`...)
	b = append(b, name...)
	b = append(b, `,"remaining":0,"reset_s":`...)
	b = strconv.AppendInt(b, int64(ceilSeconds(d.dec.ResetAfter)), 10)
	b = append(b, `,"retry_after_s":`...)
	b = strconv.AppendInt(b, int64(retryAfterSeconds(d.dec)), 10)
	b = append(b, "}\n"...)
	return b
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
		h["RateLimit-Policy"] = policyHeader(r.params)
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

// setRateHeaders writes exactly the headers rateHeaders describes into h
// (same names after canonicalisation, same values, replacing any existing
// value like Header.Set) without building an intermediate map: the
// canonical names are constants, all values share one backing array, and
// the RateLimit-Policy value is precomputed per policy at compile time when
// no plan/consumer override changed the numbers.
func setRateHeaders(h http.Header, cfg *compiled, r *polResult, now time.Time, limited bool) {
	n := 5
	if cfg.legacyHeaders {
		n = 8
	}
	vals := make([]string, n)
	put := func(i int, k, v string) {
		vals[i] = v
		h[k] = vals[i : i+1 : i+1]
	}
	reset := ceilSeconds(r.dec.ResetAfter)
	lim, rem := strconv.Itoa(limitOf(r)), strconv.Itoa(r.dec.Remaining)
	put(0, "Ratelimit-Limit", lim)
	put(1, "Ratelimit-Remaining", rem)
	put(2, "Ratelimit-Reset", strconv.Itoa(reset))
	if !r.cp.conc {
		pv := r.cp.policyHdr
		if r.params.Limit != r.cp.p.Limit || r.params.Window != r.cp.p.Window.D() {
			pv = policyHeader(r.params)
		}
		put(3, "Ratelimit-Policy", pv)
	}
	if limited {
		put(4, "Retry-After", strconv.Itoa(retryAfterSeconds(r.dec)))
	}
	if cfg.legacyHeaders {
		put(5, "X-Ratelimit-Limit", lim)
		put(6, "X-Ratelimit-Remaining", rem)
		put(7, "X-Ratelimit-Reset", strconv.FormatInt(now.Add(time.Duration(reset)*time.Second).Unix(), 10))
	}
}

// policyHeader is the RateLimit-Policy value ("<limit>;w=<window seconds>").
func policyHeader(p ratelimit.Params) string {
	w := ceilSeconds(p.Window)
	if w < 1 {
		w = 1
	}
	return strconv.Itoa(p.Limit) + ";w=" + strconv.Itoa(w)
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
			if isRGHeader(k) {
				delete(out.Header, k)
			}
		}
		// Not hop-by-hop, but only meaningful for an h2c upgrade (refused).
		delete(out.Header, "Http2-Settings")
		if len(out.Trailer) > 0 {
			stripTrailers(out)
		}
		if len(out.Header["Cookie"]) > 0 {
			stripCookie(out.Header, adminSessionCookie)
		}
		if st, _ := pr.In.Context().Value(ctxKey{}).(*reqState); st != nil {
			// ReverseProxy's Rewrite hook has already removed inbound
			// Forwarded / X-Forwarded-*; X-Real-IP is replaced the same way
			// (by the client IP the limits were evaluated with) so an
			// untrusted client cannot choose it.
			out.Header.Set("X-Forwarded-For", st.xff)
			out.Header.Set("X-Forwarded-Proto", st.proto)
			out.Header.Set("X-Forwarded-Host", st.host)
			out.Header.Set("X-Real-Ip", st.clientIP)
			if st.consumerID != "" {
				out.Header.Set("X-RateGuard-Consumer", st.consumerID)
			}
		}
	}
}

// adminSessionCookie is the dashboard's session cookie name (admin package,
// sessionCookie). Browsers send cookies to every port of a host, so when the
// dashboard and the data plane share a host name the admin session would
// otherwise be forwarded to upstreams.
const adminSessionCookie = "rg_session"

// stripCookie removes the named cookie from every Cookie header value,
// dropping values that become empty. Other cookies pass through unchanged.
func stripCookie(h http.Header, name string) {
	vals := h["Cookie"]
	var out []string
	changed := false
	for _, v := range vals {
		if !strings.Contains(v, name) {
			out = append(out, v)
			continue
		}
		parts := strings.Split(v, ";")
		kept := parts[:0]
		for _, p := range parts {
			n, _, _ := strings.Cut(p, "=")
			if strings.TrimSpace(n) == name {
				changed = true
				continue
			}
			if p = strings.TrimSpace(p); p != "" {
				kept = append(kept, p)
			}
		}
		if len(kept) > 0 {
			out = append(out, strings.Join(kept, "; "))
		}
	}
	if !changed {
		return
	}
	if len(out) == 0 {
		delete(h, "Cookie")
		return
	}
	h["Cookie"] = out
}

// trailerDenied lists request trailer names (lower case, "_" read as "-")
// that are never forwarded: hop-by-hop headers and the client-IP headers
// RateGuard rewrites. X-RateGuard-* is matched by isRGHeader.
var trailerDenied = map[string]bool{
	"connection": true, "proxy-connection": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-authorization": true, "te": true, "trailer": true, "transfer-encoding": true, "upgrade": true,
	"http2-settings": true, "host": true, "content-length": true,
	"x-forwarded-for": true, "x-forwarded-host": true, "x-forwarded-proto": true, "x-real-ip": true, "forwarded": true,
}

// stripTrailers drops request trailers (and so their Trailer declaration,
// which the transport rebuilds from out.Trailer) that could smuggle
// X-RateGuard-*, hop-by-hop or client-IP headers to the upstream.
func stripTrailers(out *http.Request) {
	for k := range out.Trailer {
		if isRGHeader(k) || trailerDenied[strings.ReplaceAll(strings.ToLower(k), "_", "-")] {
			delete(out.Trailer, k)
		}
	}
	if len(out.Trailer) == 0 {
		out.Trailer = nil
	}
	delete(out.Header, "Trailer")
}

// headerHasToken reports whether any comma-separated element of the named
// header equals tok, ignoring ASCII case.
func headerHasToken(h http.Header, name, tok string) bool {
	for _, v := range h[name] {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), tok) {
				return true
			}
		}
	}
	return false
}

// upgradeType mirrors httputil.ReverseProxy: a request is an upgrade (and
// becomes a tunnel on 101) when Connection lists "upgrade"; the protocol is
// the Upgrade header. Without the Connection token the proxy just drops
// Upgrade as a hop-by-hop header.
func upgradeType(h http.Header) string {
	if len(h["Upgrade"]) == 0 || !headerHasToken(h, "Connection", "upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

// isH2CUpgrade reports an h2c upgrade offer, with or without Connection.
func isH2CUpgrade(h http.Header) bool {
	return len(h["Upgrade"]) > 0 && headerHasToken(h, "Upgrade", "h2c")
}

var ownRateHeaders = []string{"Ratelimit-Limit", "Ratelimit-Remaining", "Ratelimit-Reset", "Ratelimit-Policy",
	"X-Ratelimit-Limit", "X-Ratelimit-Remaining", "X-Ratelimit-Reset", "Retry-After"}

func modifyResponse(resp *http.Response) error {
	st, _ := resp.Request.Context().Value(ctxKey{}).(*reqState)
	if st == nil {
		return nil
	}
	st.upstreamDur = time.Since(st.started)
	h := resp.Header
	for k := range h {
		// Our headers are authoritative; also never leak X-RateGuard-* from upstream.
		if isRGHeader(k) {
			delete(h, k)
		}
	}
	if st.rlHeaders {
		for _, k := range ownRateHeaders {
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

// isRGHeader reports whether a header name is in the reserved X-RateGuard-*
// namespace, treating "_" as "-" so CGI/WSGI-style aliases
// (X-Rateguard_Consumer) cannot slip through.
//
// It runs for every header in both directions, so it compares in place
// instead of building a lower-cased copy. Only ASCII is folded: no
// non-ASCII rune lower-cases to a character of the prefix, so this is
// equivalent to strings.ToLower + ReplaceAll.
func isRGHeader(k string) bool {
	const prefix = "x-rateguard-"
	if len(k) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := k[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		} else if c == '_' {
			c = '-'
		}
		if c != prefix[i] {
			return false
		}
	}
	return true
}
