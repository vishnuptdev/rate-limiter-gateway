package telemetry

import (
	"bufio"
	"io"
	"sort"
	"strconv"
	"strings"

	"ratelimitergateway/internal/model"
)

const (
	maxLabelValues = 500
	otherLabel     = "_other"
	noRouteLabel   = "_none"
)

// promBounds are the histogram upper bounds in seconds.
var promBounds = [...]float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

type promHist struct {
	counts [len(promBounds) + 1]uint64 // non-cumulative; last = +Inf
	sum    float64
	count  uint64
}

func (p *promHist) observe(sec float64) {
	i := 0
	for i < len(promBounds) && sec > promBounds[i] {
		i++
	}
	p.counts[i]++
	p.sum += sec
	p.count++
}

type reqKey struct{ route, decision, class string }

// promState holds cumulative metric state. Guarded by Hub.mu.
type promState struct {
	routes, policies map[string]struct{} // admitted label values (cardinality cap)
	requests         map[reqKey]uint64
	limited          map[string]uint64 // by policy
	reqDur, upDur    map[string]*promHist
}

func newPromState() promState {
	return promState{
		routes:   map[string]struct{}{},
		policies: map[string]struct{}{},
		requests: map[reqKey]uint64{},
		limited:  map[string]uint64{},
		reqDur:   map[string]*promHist{},
		upDur:    map[string]*promHist{},
	}
}

// label applies the cardinality cap: new values beyond maxLabelValues
// distinct ones are folded into "_other".
func capLabel(set map[string]struct{}, v string) string {
	if _, ok := set[v]; ok {
		return v
	}
	if len(set) >= maxLabelValues {
		return otherLabel
	}
	set[v] = struct{}{}
	return v
}

func decisionLabel(d string, kind int) string {
	if kind == kOther {
		return "other"
	}
	return d
}

func classLabel(cls int) string {
	if cls < 0 {
		return "other"
	}
	return classNames[cls]
}

func (p *promState) observe(e *model.LogEntry, kind, cls int, latMs float64) {
	route := noRouteLabel
	if e.RouteID != "" {
		route = capLabel(p.routes, e.RouteID)
	}
	p.requests[reqKey{route, decisionLabel(e.Decision, kind), classLabel(cls)}]++
	if kind == kLimited {
		pol := noRouteLabel
		if e.PolicyID != "" {
			pol = capLabel(p.policies, e.PolicyID)
		}
		p.limited[pol]++
	}
	h := p.reqDur[route]
	if h == nil {
		h = new(promHist)
		p.reqDur[route] = h
	}
	h.observe(latMs / 1000)
	if e.UpstreamMs > 0 { // only proxied requests have an upstream phase
		u := p.upDur[route]
		if u == nil {
			u = new(promHist)
			p.upDur[route] = u
		}
		u.observe(e.UpstreamMs / 1000)
	}
}

// promSnapshot is a deep copy taken under the lock and formatted outside it.
type promSnapshot struct {
	requests      map[reqKey]uint64
	limited       map[string]uint64
	reqDur, upDur map[string]promHist
}

func (p *promState) snapshot() promSnapshot {
	s := promSnapshot{
		requests: make(map[reqKey]uint64, len(p.requests)),
		limited:  make(map[string]uint64, len(p.limited)),
		reqDur:   make(map[string]promHist, len(p.reqDur)),
		upDur:    make(map[string]promHist, len(p.upDur)),
	}
	for k, v := range p.requests {
		s.requests[k] = v
	}
	for k, v := range p.limited {
		s.limited[k] = v
	}
	for k, v := range p.reqDur {
		s.reqDur[k] = *v
	}
	for k, v := range p.upDur {
		s.upDur[k] = *v
	}
	return s
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func fmtFloat(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

func (s promSnapshot) write(w io.Writer, logLen int) {
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	str := bw.WriteString

	str("# HELP rateguard_requests_total Requests handled by the gateway.\n")
	str("# TYPE rateguard_requests_total counter\n")
	keys := make([]reqKey, 0, len(s.requests))
	for k := range s.requests {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.route != b.route {
			return a.route < b.route
		}
		if a.decision != b.decision {
			return a.decision < b.decision
		}
		return a.class < b.class
	})
	for _, k := range keys {
		str(`rateguard_requests_total{route="` + labelEscaper.Replace(k.route) + `",decision="` +
			labelEscaper.Replace(k.decision) + `",status_class="` + k.class + `"} ` +
			strconv.FormatUint(s.requests[k], 10) + "\n")
	}

	str("# HELP rateguard_rate_limited_total Requests rejected by a policy.\n")
	str("# TYPE rateguard_rate_limited_total counter\n")
	for _, k := range sortedKeys(s.limited) {
		str(`rateguard_rate_limited_total{policy="` + labelEscaper.Replace(k) + `"} ` +
			strconv.FormatUint(s.limited[k], 10) + "\n")
	}

	writeHist(bw, "rateguard_request_duration_seconds", "Total time spent in the gateway per request.", s.reqDur)
	writeHist(bw, "rateguard_upstream_duration_seconds", "Time spent waiting on the upstream (proxied requests only).", s.upDur)

	str("# HELP rateguard_log_buffer_entries Entries currently held in the request log buffer.\n")
	str("# TYPE rateguard_log_buffer_entries gauge\n")
	str("rateguard_log_buffer_entries " + strconv.Itoa(logLen) + "\n")
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func writeHist(bw *bufio.Writer, name, help string, hs map[string]promHist) {
	bw.WriteString("# HELP " + name + " " + help + "\n")
	bw.WriteString("# TYPE " + name + " histogram\n")
	for _, route := range sortedKeys(hs) {
		h := hs[route]
		lbl := `route="` + labelEscaper.Replace(route) + `"`
		var cum uint64
		for i, b := range promBounds {
			cum += h.counts[i]
			bw.WriteString(name + `_bucket{` + lbl + `,le="` + fmtFloat(b) + `"} ` + strconv.FormatUint(cum, 10) + "\n")
		}
		cum += h.counts[len(promBounds)]
		bw.WriteString(name + `_bucket{` + lbl + `,le="+Inf"} ` + strconv.FormatUint(cum, 10) + "\n")
		bw.WriteString(name + `_sum{` + lbl + `} ` + fmtFloat(h.sum) + "\n")
		bw.WriteString(name + `_count{` + lbl + `} ` + strconv.FormatUint(h.count, 10) + "\n")
	}
}
