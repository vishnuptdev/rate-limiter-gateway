package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"ratelimitergateway/internal/model"
)

func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	return a.Unmap(), err
}

func asMaxBytes(err error, target **http.MaxBytesError) bool { return errors.As(err, target) }

type checkRequest struct {
	RouteID string            `json:"route_id"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Host    string            `json:"host"`
	APIKey  string            `json:"api_key"`
	IP      string            `json:"ip"`
	Headers map[string]string `json:"headers"`
	// Cost multiplies each policy's own cost (default 1): "this call counts
	// as N requests".
	Cost int `json:"cost"`
}

type checkResult struct {
	PolicyID  string `json:"policy_id"`
	Allowed   bool   `json:"allowed"`
	Limit     int    `json:"limit"`
	Remaining int    `json:"remaining"`
	Shadow    bool   `json:"shadow"`
}

type checkResponse struct {
	Allowed     bool   `json:"allowed"`
	Decision    string `json:"decision"`
	RouteID     string `json:"route_id,omitempty"`
	ConsumerID  string `json:"consumer_id,omitempty"`
	PolicyID    string `json:"policy_id,omitempty"`
	Limit       int    `json:"limit"`
	Remaining   int    `json:"remaining"`
	ResetS      int    `json:"reset_s"`
	RetryAfterS int    `json:"retry_after_s,omitempty"`
	// DelayMs is how long the caller should hold the request before
	// proceeding (leaky-bucket shaping). The check API never sleeps itself.
	DelayMs int64             `json:"delay_ms"`
	Error   string            `json:"error,omitempty"`
	Headers map[string]string `json:"headers"`
	Results []checkResult     `json:"results"`
}

const maxCheckBody = 64 << 10

// serveCheck implements POST /_rlg/v1/check. Decisions (including limited,
// unauthorized-key and no-route) are returned with HTTP 200; transport-level
// problems use 400/401/404/405/503.
func (g *Gateway) serveCheck(w http.ResponseWriter, r *http.Request) {
	start := g.now()
	cfg := g.cfg.Load()
	if cfg == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody("not_ready", "configuration not loaded"))
		return
	}
	if !cfg.checkEnabled {
		writeJSON(w, http.StatusNotFound, errBody("not_found", ""))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, errBody("method_not_allowed", ""))
		return
	}
	tok := ""
	if a := r.Header.Get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		tok = strings.TrimSpace(a[7:])
	}
	if tok == "" || g.tokens == nil || !g.tokens.Verify(tok, "check") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="rateguard-check"`)
		writeJSON(w, http.StatusUnauthorized, errBody("unauthorized", "A valid check token is required"))
		return
	}

	var req checkRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCheckBody)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "invalid JSON body"))
		return
	}
	if req.Cost < 0 || req.Cost > 1_000_000_000 {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "cost must be between 0 and 1e9"))
		return
	}
	if req.Cost == 0 {
		req.Cost = 1
	}
	ip := "-"
	if req.IP != "" {
		a, err := parseAddr(req.IP)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody("bad_request", "ip is not a valid address"))
			return
		}
		ip = a.String()
	}
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	rawPath := req.Path
	if rawPath == "" {
		rawPath = "/"
	}
	u, err := url.Parse(rawPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "path is not valid"))
		return
	}
	path, okPath := cleanPath(u)
	if !okPath {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "path is not valid"))
		return
	}
	hdr := make(map[string]string, len(req.Headers))
	for k, v := range req.Headers {
		hdr[http.CanonicalHeaderKey(k)] = v
	}
	get := func(n string) string { return hdr[n] }
	var q url.Values
	ri := &reqInfo{method: method, host: req.Host, path: path, ip: ip, header: get,
		query: func(n string) string {
			if q == nil {
				q = u.Query()
			}
			return q.Get(n)
		}}
	ri.apiKey = req.APIKey
	if ri.apiKey == "" {
		ri.apiKey = cfg.extractKey(get)
	}

	le := model.LogEntry{Time: start, Method: method, Host: req.Host, Path: path, ClientIP: ip, Source: "check_api"}
	resp := checkResponse{Headers: map[string]string{}, Results: []checkResult{}}
	finish := func(status int) {
		le.Status = status
		le.Decision = resp.Decision
		le.LatencyMs = float64(g.now().Sub(start)) / float64(time.Millisecond)
		g.record(cfg, le)
		writeJSON(w, http.StatusOK, resp)
	}

	var route *croute
	if req.RouteID != "" {
		route = cfg.byID[req.RouteID]
	} else {
		route = cfg.match(req.Host, path, method)
	}
	if route == nil {
		resp.Decision = model.DecisionNoRoute
		finish(http.StatusNotFound)
		return
	}
	ri.route = route
	resp.RouteID = route.r.ID
	le.RouteID, le.RouteName = route.r.ID, route.r.Name

	cons, reason := cfg.authenticate(ri.apiKey, start)
	if reason != "" || (cons == nil && route.r.RequireAPIKey) {
		if reason == "" {
			reason = "API key required"
		}
		resp.Decision, resp.Error, le.Error = model.DecisionUnauthorized, reason, reason
		finish(http.StatusUnauthorized)
		return
	}
	ri.consumer = cons
	if cons != nil {
		resp.ConsumerID = cons.c.ID
		le.ConsumerID, le.ConsumerName = cons.c.ID, cons.c.Name
	}

	ectx, cancel := g.engineCtx(r.Context())
	out := g.evaluate(ectx, ri, evalOpts{skipConcurrency: true, costMul: req.Cost})
	cancel()
	for _, s := range out.soft {
		g.log.Warn("limiter error, failing open", "route", route.r.ID, "detail", s)
	}
	for i := range out.results {
		x := &out.results[i]
		resp.Results = append(resp.Results, checkResult{
			PolicyID: x.cp.p.ID, Allowed: !x.denied && !(x.err != nil && x.cp.failMode == model.FailClosed),
			Limit: limitOf(x), Remaining: x.dec.Remaining, Shadow: x.cp.mode == model.ModeShadow,
		})
	}
	if b := out.best; b != nil {
		resp.PolicyID, resp.Limit, resp.Remaining = b.cp.p.ID, limitOf(b), b.dec.Remaining
		resp.ResetS = ceilSeconds(b.dec.ResetAfter)
		le.PolicyID, le.RateKey, le.Limit, le.Remaining = b.cp.p.ID, b.composite, resp.Limit, resp.Remaining
		resp.Headers = rateHeaders(cfg, b, start, out.denier != nil)
	}
	_, tooLongSrc, _ := out.shapingDelay()
	switch {
	case out.failed != nil:
		f := out.failed
		resp.Decision, resp.Error = model.DecisionError, "limiter_unavailable"
		resp.PolicyID = f.cp.p.ID
		le.PolicyID, le.RateKey, le.Error = f.cp.p.ID, f.composite, "limiter unavailable: "+f.err.Error()
		finish(http.StatusServiceUnavailable)
	case out.denier != nil:
		resp.Decision = model.DecisionLimited
		resp.RetryAfterS = retryAfterSeconds(out.denier.dec)
		finish(http.StatusTooManyRequests)
	case tooLongSrc != nil:
		// Defensive: validation keeps shaping delays under the ceiling.
		resp.Decision = model.DecisionLimited
		resp.RetryAfterS = retryAfterSeconds(tooLongSrc.dec)
		le.Error = "shaping_delay_too_long"
		finish(http.StatusTooManyRequests)
	case out.shadow:
		resp.Allowed, resp.Decision = true, model.DecisionShadowLimited
		resp.DelayMs = shapeMs(out)
		finish(http.StatusOK)
	default:
		resp.Allowed, resp.Decision = true, model.DecisionAllowed
		resp.DelayMs = shapeMs(out)
		finish(http.StatusOK)
	}
}

func shapeMs(o *outcome) int64 {
	d, _, _ := o.shapingDelay()
	return d.Milliseconds()
}
