package store

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"ratelimitergateway/internal/model"
)

// Problem is one validation failure. Field is a path such as
// "policies[2].limit".
type Problem struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError is returned by Validate and carries every problem found.
type ValidationError struct {
	Problems []Problem `json:"problems"`
}

func (e *ValidationError) Error() string {
	if e == nil || len(e.Problems) == 0 {
		return "invalid configuration"
	}
	parts := make([]string, 0, len(e.Problems))
	for i, p := range e.Problems {
		if i == 5 {
			parts = append(parts, fmt.Sprintf("... and %d more", len(e.Problems)-5))
			break
		}
		parts = append(parts, p.Field+": "+p.Message)
	}
	return "invalid configuration: " + strings.Join(parts, "; ")
}

var (
	idRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	hashRe    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	headerRe  = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	validVerb = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true,
		"DELETE": true, "OPTIONS": true, "CONNECT": true, "TRACE": true}
)

const (
	maxName   = 100
	maxLimit  = 1_000_000_000
	maxWindow = 365 * 24 * time.Hour
	maxBurst  = 1_000_000
	// maxShapingDelay bounds a leaky bucket's queue wait, (burst-1)*window/limit,
	// so the gateway never parks a request for longer than this.
	maxShapingDelay = 30 * time.Second
)

type validator struct{ probs []Problem }

func (v *validator) add(field, format string, a ...any) {
	v.probs = append(v.probs, Problem{Field: field, Message: fmt.Sprintf(format, a...)})
}

// Validate checks a snapshot against the rules in docs/ARCHITECTURE.md.
// It returns nil or a *ValidationError listing every problem.
//
// Choices where the spec was silent: an empty Mode defaults to enforce and an
// empty FailMode to open (the gateway applies the same defaults); an empty
// KeyBy is allowed and behaves as "global"; override numbers must be >= 0
// (0 keeps the policy value); duplicate API key hashes across consumers are
// rejected because lookup would be ambiguous.
func Validate(s *model.Snapshot) error {
	if s == nil {
		return &ValidationError{Problems: []Problem{{Field: "", Message: "snapshot is nil"}}}
	}
	v := &validator{}
	policyIDs := map[string]bool{}
	planIDs := map[string]bool{}

	checkID := func(field, id string, seen map[string]bool) {
		switch {
		case id == "":
			v.add(field, "id is required")
		case !idRe.MatchString(id):
			v.add(field, "id %q must match ^[a-z0-9][a-z0-9_-]{0,63}$", id)
		case seen[id]:
			v.add(field, "duplicate id %q", id)
		}
		seen[id] = true
	}
	checkName := func(field, name string) {
		if strings.TrimSpace(name) == "" {
			v.add(field, "name is required")
		} else if len([]rune(name)) > maxName {
			v.add(field, "name must be at most %d characters", maxName)
		}
	}

	for i, p := range s.Policies {
		f := fmt.Sprintf("policies[%d]", i)
		checkID(f+".id", p.ID, policyIDs)
		checkName(f+".name", p.Name)
		known := false
		for _, a := range model.Algorithms {
			if a == p.Algorithm {
				known = true
			}
		}
		if !known {
			v.add(f+".algorithm", "unknown algorithm %q", p.Algorithm)
		}
		if p.Limit < 1 || p.Limit > maxLimit {
			v.add(f+".limit", "must be between 1 and %d", maxLimit)
		}
		if p.Algorithm != model.AlgoConcurrency {
			w := p.Window.D()
			if w < time.Millisecond || w > maxWindow {
				v.add(f+".window", "must be between 1ms and 365d")
			}
		}
		if p.Burst < 0 || p.Burst > maxBurst {
			v.add(f+".burst", "must be between 0 and %d", maxBurst)
		}
		if p.Cost < 0 || (p.Limit >= 1 && p.Cost > p.Limit) {
			v.add(f+".cost", "must be between 0 and limit")
		}
		for j, k := range p.KeyBy {
			if !validKeyBy(k) {
				v.add(fmt.Sprintf("%s.key_by[%d]", f, j), "invalid key_by %q", k)
			}
		}
		switch p.Mode {
		case "", model.ModeEnforce, model.ModeShadow:
		default:
			v.add(f+".mode", "must be \"enforce\" or \"shadow\"")
		}
		switch p.FailMode {
		case "", model.FailOpen, model.FailClosed:
		default:
			v.add(f+".fail_mode", "must be \"open\" or \"closed\"")
		}
	}

	for i, p := range s.Plans {
		f := fmt.Sprintf("plans[%d]", i)
		checkID(f+".id", p.ID, planIDs)
		checkName(f+".name", p.Name)
		v.overrides(f+".overrides", p.Overrides, policyIDs)
	}

	routeIDs := map[string]bool{}
	for i, r := range s.Routes {
		f := fmt.Sprintf("routes[%d]", i)
		checkID(f+".id", r.ID, routeIDs)
		checkName(f+".name", r.Name)
		if u, err := url.Parse(r.Upstream); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			v.add(f+".upstream", "must be an absolute http or https URL with a host")
		}
		if pp := r.Match.PathPrefix; pp != "" && !strings.HasPrefix(pp, "/") {
			v.add(f+".match.path_prefix", "must start with \"/\"")
		}
		if h := r.Match.Host; h != "" {
			bare := strings.TrimPrefix(h, "*.")
			if bare == "" || strings.ContainsAny(bare, "/*? ") {
				v.add(f+".match.host", "must be a host name or \"*.suffix\"")
			}
		}
		for j, m := range r.Match.Methods {
			if !validVerb[m] {
				v.add(fmt.Sprintf("%s.match.methods[%d]", f, j), "%q is not an uppercase HTTP method", m)
			}
		}
		for j, id := range r.PolicyIDs {
			if !policyIDs[id] {
				v.add(fmt.Sprintf("%s.policy_ids[%d]", f, j), "unknown policy %q", id)
			}
		}
		if r.Timeout.D() < 0 {
			v.add(f+".timeout", "must be >= 0")
		}
	}

	consumerIDs := map[string]bool{}
	hashOwner := map[string]string{}
	for i, c := range s.Consumers {
		f := fmt.Sprintf("consumers[%d]", i)
		checkID(f+".id", c.ID, consumerIDs)
		checkName(f+".name", c.Name)
		if c.PlanID != "" && !planIDs[c.PlanID] {
			v.add(f+".plan_id", "unknown plan %q", c.PlanID)
		}
		v.overrides(f+".overrides", c.Overrides, policyIDs)
		for j, k := range c.Keys {
			kf := fmt.Sprintf("%s.keys[%d]", f, j)
			if !hashRe.MatchString(k.Hash) {
				v.add(kf+".hash", "must be 64 hex characters")
				continue
			}
			h := strings.ToLower(k.Hash)
			if owner, dup := hashOwner[h]; dup {
				v.add(kf+".hash", "duplicate key hash (also on %s)", owner)
			}
			hashOwner[h] = c.ID
		}
	}

	st := s.Settings
	if st.APIKeyHeader != "" && !headerRe.MatchString(st.APIKeyHeader) {
		v.add("settings.api_key_header", "must be a valid header name")
	}
	for i, t := range st.TrustedProxies {
		if !validProxy(t) {
			v.add(fmt.Sprintf("settings.trusted_proxies[%d]", i), "%q is not a valid CIDR or IP", t)
		}
	}
	for i, id := range st.GlobalPolicyIDs {
		if !policyIDs[id] {
			v.add(fmt.Sprintf("settings.global_policy_ids[%d]", i), "unknown policy %q", id)
		}
	}
	if st.MaxBodyBytes < 0 {
		v.add("settings.max_body_bytes", "must be >= 0")
	}
	if !(st.LogSampleAllowed >= 0 && st.LogSampleAllowed <= 1) { // also rejects NaN
		v.add("settings.log_sample_allowed", "must be between 0 and 1")
	}

	v.shaping(s)

	if len(v.probs) == 0 {
		return nil
	}
	return &ValidationError{Problems: v.probs}
}

func (v *validator) overrides(field string, m map[string]model.LimitOverride, policies map[string]bool) {
	for id, o := range m {
		f := fmt.Sprintf("%s[%s]", field, id)
		if !policies[id] {
			v.add(f, "unknown policy %q", id)
		}
		if o.Limit < 0 || o.Limit > maxLimit {
			v.add(f+".limit", "must be between 0 and %d", maxLimit)
		}
		if o.Burst < 0 || o.Burst > maxBurst {
			v.add(f+".burst", "must be between 0 and %d", maxBurst)
		}
		if o.Window.D() < 0 || o.Window.D() > maxWindow {
			v.add(f+".window", "must be between 0 and 365d")
		}
	}
}

func validKeyBy(k string) bool {
	switch k {
	case "consumer", "api_key", "ip", "path", "method", "route", "global":
		return true
	}
	if n, ok := strings.CutPrefix(k, "header:"); ok {
		return headerRe.MatchString(n)
	}
	if n, ok := strings.CutPrefix(k, "query:"); ok {
		return n != "" && len(n) <= 128
	}
	return false
}

func validProxy(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// ProblemsJSON exposes the problem list to packages (admin) that render it
// without importing store's concrete types.
func (e *ValidationError) ProblemsJSON() any { return e.Problems }

// shaping rejects leaky bucket configurations whose maximum queue delay,
// (burst-1)*window/limit, exceeds maxShapingDelay. The check covers the
// policy itself and every effective combination reachable through plan and
// consumer overrides (merged exactly like the gateway: plan, then consumer).
func (v *validator) shaping(s *model.Snapshot) {
	plans := map[string]model.Plan{}
	for _, pl := range s.Plans {
		plans[pl.ID] = pl
	}
	merge := func(l int, w time.Duration, b int, o model.LimitOverride) (int, time.Duration, int) {
		if o.Limit > 0 {
			l = o.Limit
		}
		if o.Window > 0 {
			w = o.Window.D()
		}
		if o.Burst > 0 {
			b = o.Burst
		}
		return l, w, b
	}
	check := func(field string, l int, w time.Duration, b int) {
		if l < 1 || w <= 0 || b < 0 || b > maxBurst {
			return // reported elsewhere
		}
		if b == 0 {
			b = l
		}
		if d := float64(b-1) * float64(w) / float64(l); d > float64(maxShapingDelay) {
			v.add(field, "leaky_bucket queue delay (burst-1)*window/limit = %s exceeds the %s maximum; lower burst or window, or raise limit",
				time.Duration(d).Round(time.Millisecond), maxShapingDelay)
		}
	}
	for i, p := range s.Policies {
		if p.Algorithm != model.AlgoLeakyBucket {
			continue
		}
		f := fmt.Sprintf("policies[%d]", i)
		check(f+".burst", p.Limit, p.Window.D(), p.Burst)
		for j, pl := range s.Plans {
			if o, ok := pl.Overrides[p.ID]; ok {
				l, w, b := merge(p.Limit, p.Window.D(), p.Burst, o)
				check(fmt.Sprintf("plans[%d].overrides[%s].burst", j, p.ID), l, w, b)
			}
		}
		for j, c := range s.Consumers {
			l, w, b := p.Limit, p.Window.D(), p.Burst
			if pl, ok := plans[c.PlanID]; ok {
				l, w, b = merge(l, w, b, pl.Overrides[p.ID])
			}
			if o, ok := c.Overrides[p.ID]; ok {
				l, w, b = merge(l, w, b, o)
				check(fmt.Sprintf("consumers[%d].overrides[%s].burst", j, p.ID), l, w, b)
			}
		}
	}
}
