package gateway

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"ratelimitergateway/internal/model"
)

const authPath = "/_rlg/v1/auth"

// firstHeader returns the first non-empty value among the given headers.
func firstHeader(r *http.Request, names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(r.Header.Get(n)); v != "" {
			return v
		}
	}
	return ""
}

// serveAuth implements /_rlg/v1/auth, the "forward auth" contract used by
// NGINX auth_request, Traefik ForwardAuth, Caddy forward_auth, Envoy ext_authz
// (HTTP) and ingress-nginx auth-url. The original request is described by
// X-Forwarded-* / X-Original-* headers. 200 (empty body) means "let it
// through"; any other status is relayed to the client by the proxy. It never
// proxies anything itself.
func (g *Gateway) serveAuth(w http.ResponseWriter, r *http.Request, reserved string) {
	start := g.now()
	cfg := g.cfg.Load()
	if cfg == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody("not_ready", "configuration not loaded"))
		return
	}
	if cfg.fwdDisabled {
		writeJSON(w, http.StatusNotFound, errBody("not_found", ""))
		return
	}
	if cfg.fwdRequireTok {
		tok := strings.TrimSpace(r.Header.Get("X-RateGuard-Auth-Token"))
		if tok == "" || g.tokens == nil || !g.tokens.Verify(tok, "check") {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized", "A valid forward-auth token is required"))
			return
		}
	}

	method := strings.ToUpper(firstHeader(r, "X-Forwarded-Method", "X-Original-Method"))
	rawURI := firstHeader(r, "X-Forwarded-Uri", "X-Original-Uri")
	origHost := ""
	if rawURI == "" {
		// ingress-nginx sends the full original URL.
		if full := firstHeader(r, "X-Original-Url"); full != "" {
			rest := full
			if k := strings.Index(rest, "://"); k >= 0 {
				rest = rest[k+3:]
			}
			if k := strings.IndexAny(rest, "/?"); k >= 0 {
				origHost, rawURI = rest[:k], rest[k:]
			} else {
				origHost = rest
			}
		}
	}
	// Envoy ext_authz (HTTP) sends the original request as-is under
	// path_prefix: /_rlg/v1/auth/<original path>?<query> with the original
	// method. Used only when no forwarded-URI header was given. The encoded
	// path is kept as sent so %3F, %23 and %25 survive.
	if rawURI == "" && strings.HasPrefix(reserved, authPath+"/") {
		esc := r.URL.EscapedPath()
		if !strings.HasPrefix(esc, authPath+"/") {
			writeJSON(w, http.StatusBadRequest, errBody("bad_request", "forwarded URI is not valid"))
			return
		}
		rawURI = strings.TrimPrefix(esc, authPath)
		if r.URL.RawQuery != "" {
			rawURI += "?" + r.URL.RawQuery
		}
		if method == "" {
			method = r.Method
		}
	}
	if method == "" {
		method = http.MethodGet
	}
	u, err := parseOriginalURI(rawURI)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "forwarded URI is not valid"))
		return
	}
	path, ok := cleanPath(u)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "forwarded URI is not valid"))
		return
	}
	host := firstHeader(r, "X-Forwarded-Host")
	if host == "" {
		host = origHost
	}
	if host == "" {
		host = r.Host
	}
	xff := r.Header.Values("X-Forwarded-For")
	if len(xff) == 0 {
		// X-Real-IP is honoured like XFF: only through clientIP's trusted-peer check.
		if rip := strings.TrimSpace(r.Header.Get("X-Real-IP")); rip != "" {
			xff = []string{rip}
		}
	}
	ip := cfg.clientIP(r.RemoteAddr, xff)

	le := model.LogEntry{Time: start, Method: method, Host: host, Path: path, ClientIP: ip,
		UserAgent: trunc(r.Header.Get("User-Agent")), Source: "forward_auth", Decision: model.DecisionAllowed}
	slot := false
	status := http.StatusOK
	defer func() {
		if slot {
			g.shapeWaiters.Add(-1)
		}
		le.Status = status
		le.LatencyMs = float64(g.now().Sub(start)) / float64(time.Millisecond)
		g.record(cfg, le)
	}()

	var route *croute
	// route_id and deny_status are operator-configured on the auth URL; in the Envoy form the
	// query string belongs to the end client, so it is never honoured there.
	id := ""
	denyStatus := http.StatusTooManyRequests
	if reserved == authPath {
		qv := r.URL.Query()
		id = qv.Get("route_id")
		switch qv.Get("deny_status") {
		case "", "429":
		case "401":
			denyStatus = http.StatusUnauthorized
		case "403":
			denyStatus = http.StatusForbidden
		default:
			status = http.StatusBadRequest
			writeJSON(w, status, errBody("bad_request", "deny_status must be 401, 403 or 429"))
			return
		}
	}
	if id != "" {
		route = cfg.byID[id]
	} else {
		route = cfg.match(host, path, method)
	}
	if route == nil {
		le.Decision, status = model.DecisionNoRoute, http.StatusNotFound
		writeJSON(w, status, errBody("no_route", ""))
		return
	}
	le.RouteID, le.RouteName = route.r.ID, route.r.Name

	get := func(n string) string { return r.Header.Get(n) }
	var q url.Values
	ri := &reqInfo{method: method, host: host, path: path, ip: ip, route: route, header: get,
		query: func(n string) string {
			if q == nil {
				q = u.Query()
			}
			return q.Get(n)
		}}
	ri.apiKey = cfg.extractKey(get)
	cons, reason := ri.authenticate(cfg, start)
	if reason != "" || (cons == nil && route.r.RequireAPIKey) {
		if reason != "" {
			le.Error = reason
		}
		le.Decision, status = model.DecisionUnauthorized, http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", `Bearer realm="rateguard"`)
		writeJSON(w, status, errBody("unauthorized", "A valid API key is required"))
		return
	}
	ri.consumer = cons
	if cons != nil {
		le.ConsumerID, le.ConsumerName = cons.c.ID, cons.c.Name
	}

	if route.shaper != nil {
		res, ok := g.reserveShaper(ri, route)
		if !ok {
			le.PolicyID, le.RateKey, le.Limit = route.shaper.p.ID, res.composite, res.dec.Limit
			le.Decision, le.Error, status = model.DecisionLimited, "shaping_queue_full", denyStatus
			g.writeLimitedAs(w, denyStatus, cfg, res, start)
			return
		}
		slot = true
	}

	ectx, cancel := g.engineCtx(r.Context())
	out := g.evaluate(ectx, ri, evalOpts{skipConcurrency: true, costMul: 1})
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
		status = http.StatusServiceUnavailable
		g.log.Error("limiter unavailable, failing closed", "policy", f.cp.p.ID, "err", f.err)
		writeJSON(w, status, errBody("limiter_unavailable", "Rate limiter backend unavailable"))
		return
	case out.denier != nil:
		le.Decision, status = model.DecisionLimited, denyStatus
		g.writeLimitedAs(w, denyStatus, cfg, out.denier, start)
		return
	case out.shadow:
		le.Decision = model.DecisionShadowLimited
	}

	wait, tooLongSrc, tooLong := out.shapingDelay()
	if tooLong {
		le.PolicyID, le.RateKey, le.Limit = tooLongSrc.cp.p.ID, tooLongSrc.composite, limitOf(tooLongSrc)
		le.Decision, le.Error, status = model.DecisionLimited, "shaping_delay_too_long", denyStatus
		g.writeLimitedAs(w, denyStatus, cfg, tooLongSrc, start)
		return
	}
	if wait > 0 && !waitShaping(r.Context(), wait) {
		le.Decision, le.Error, status = model.DecisionError, "client_closed", 499
		w.WriteHeader(status)
		return
	}
	if slot {
		slot = false
		g.shapeWaiters.Add(-1)
	}

	if b := out.best; b != nil {
		setRateHeaders(w.Header(), cfg, b, start, false)
		if cfg.exposeDecision {
			w.Header().Set("X-RateGuard-Policy", b.cp.p.ID)
		}
	}
	// Always present (empty when anonymous): proxies that copy it onto the
	// upstream request (auth_request_set, authResponseHeaders,
	// allowed_upstream_headers) then overwrite a client-supplied value
	// instead of keeping it.
	consumerID := ""
	if cons != nil {
		consumerID = cons.c.ID
	}
	w.Header()["X-Rateguard-Consumer"] = []string{consumerID}
	w.WriteHeader(http.StatusOK)
}

// parseOriginalURI turns an origin-form request target (path[?query]) into a
// URL without ever treating a leading "//" as a scheme-relative authority:
// the target is split on the first '?' by hand and the path is only
// percent-decoded, so "//admin/secret" stays a path (cleaned to
// "/admin/secret") rather than becoming host "admin" with path "/secret".
func parseOriginalURI(raw string) (*url.URL, error) {
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	p, q, _ := strings.Cut(raw, "?")
	if p == "" || p[0] != '/' {
		p = "/" + p
	}
	dec, err := url.PathUnescape(p)
	if err != nil {
		return nil, err
	}
	return &url.URL{Path: dec, RawPath: p, RawQuery: q}, nil
}
