package gateway

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ratelimitergateway/internal/model"
)

// Simulate answers "what would the gateway do with this request?". Without
// Consume it only resolves the effective configuration (route, consumer,
// per-policy limits and their origin, bucket keys) and never touches the
// engine. With Consume it performs a real check; concurrency slots taken by
// the simulation are released immediately.
func (g *Gateway) Simulate(ctx context.Context, req model.SimRequest) model.SimResult {
	res := model.SimResult{Policies: []model.SimPolicyResult{}}
	cfg := g.cfg.Load()
	if cfg == nil {
		res.Decision = model.DecisionError
		res.Notes = []string{"configuration not loaded"}
		return res
	}
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	path := req.Path
	if path == "" {
		path = "/"
	}
	if pu, err := url.Parse(path); err == nil {
		if cp, ok := cleanPath(pu); ok {
			path = cp
		} else {
			res.Decision, res.Notes = model.DecisionError, []string{"path rejected: encoded slash, NUL or backslash"}
			return res
		}
	}
	hdr := make(map[string]string, len(req.Headers))
	for k, v := range req.Headers {
		hdr[http.CanonicalHeaderKey(k)] = v
	}
	get := func(n string) string { return hdr[n] }
	ip := req.IP
	if ip == "" {
		ip = "-"
	} else if a, err := parseAddr(ip); err == nil {
		ip = a.String()
	}

	route := cfg.match(req.Host, path, method)
	if route == nil {
		res.Decision = model.DecisionNoRoute
		return res
	}
	res.Matched, res.RouteID, res.RouteName, res.Upstream = true, route.r.ID, route.r.Name, route.r.Upstream

	ri := &reqInfo{method: method, host: req.Host, path: path, ip: ip, route: route, header: get,
		query: func(n string) string { return req.Query[n] }}
	ri.apiKey = cfg.extractKey(get)
	now := g.now()
	cons, reason := cfg.authenticate(ri.apiKey, now)
	if reason == "" && cons == nil && route.r.RequireAPIKey {
		reason = "API key required"
	}
	if reason != "" {
		res.AuthError, res.Decision = reason, model.DecisionUnauthorized
		return res
	}
	ri.consumer = cons
	if cons != nil {
		res.ConsumerID, res.ConsumerName = cons.c.ID, cons.c.Name
	}

	plan := g.evaluate(ctx, ri, evalOpts{costMul: 1, dryRun: true})
	for i := range plan.results {
		x := &plan.results[i]
		res.Policies = append(res.Policies, model.SimPolicyResult{
			PolicyID: x.cp.p.ID, PolicyName: x.cp.p.Name, Algorithm: x.cp.p.Algorithm, Mode: x.cp.mode,
			Limit: x.params.Limit, Window: model.Duration(x.params.Window), Burst: x.params.Burst,
			LimitFrom: x.from, RateKey: x.composite,
		})
	}
	res.Decision = model.DecisionAllowed
	if !req.Consume {
		res.Notes = append(res.Notes, "limits were not consumed; the decision assumes every bucket has capacity")
		return res
	}

	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	run := g.evaluate(cctx, ri, evalOpts{costMul: 1})
	g.releaseSlots(run.held)
	for i := range run.results {
		x := &run.results[i]
		if x.err != nil {
			res.Notes = append(res.Notes, "policy "+x.cp.p.ID+": backend error: "+x.err.Error())
			continue
		}
		allowed := !x.denied
		p := &res.Policies[i]
		p.Allowed, p.Remaining = &allowed, x.dec.Remaining
		if x.denied {
			p.RetryAfterMs = x.dec.RetryAfter.Milliseconds()
		}
	}
	if len(run.results) < len(res.Policies) {
		res.Notes = append(res.Notes, "evaluation stopped at the first enforcing deny or fail-closed error; later policies were not checked")
	}
	switch {
	case run.failed != nil:
		res.Decision = model.DecisionError
	case run.denier != nil:
		res.Decision = model.DecisionLimited
	case run.shadow:
		res.Decision = model.DecisionShadowLimited
	}
	return res
}
