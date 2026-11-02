package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/ratelimit"
)

// compiled is the immutable, request-ready form of a Snapshot. It is built
// once per Apply and swapped atomically; the hot path only reads it.
type compiled struct {
	snap      *model.Snapshot
	routes    []*croute // sorted: priority desc, prefix length desc, id asc
	byID      map[string]*croute
	keys      map[string]*ckey      // lower-case sha256 hex -> key
	keysBin   map[[32]byte]*ckey    // same entries keyed by the raw digest (hot path)
	consumers map[string]*cconsumer // by ID
	plans     map[string]*model.Plan
	trusted   []netip.Prefix
	keyHeader string // canonical API key header name
	secretHdr map[string]bool

	legacyHeaders  bool
	exposeDecision bool
	maxBody        int64
	sample         float64
	checkEnabled   bool
	fwdDisabled    bool
	fwdRequireTok  bool
	ipv6Bits       int // prefix length the "ip" key part keeps of IPv6 clients
}

type croute struct {
	r        *model.Route
	host     string // lower-case; "" any
	wildcard bool   // host was "*.suffix"; host holds ".suffix"
	prefix   string // normalised: no trailing slash; "" matches everything
	methods  map[string]bool
	policies []*cpolicy
	shaper   *cpolicy // first enforcing leaky bucket policy in the chain, or nil
	target   *url.URL
	proxy    *httputil.ReverseProxy
	timeout  time.Duration
	// upgradeMax bounds an upgraded tunnel's lifetime (AllowUpgrade only);
	// timeout then bounds just the handshake.
	upgradeMax time.Duration
}

type cconsumer struct {
	c    *model.Consumer
	plan *model.Plan // nil when none
}

type ckey struct {
	k        *model.APIKey
	consumer *cconsumer
}

const (
	partConsumer = iota
	partAPIKey
	partIP
	partHeader
	partQuery
	partPath
	partMethod
	partRoute
	partGlobal
)

type keyPart struct {
	kind int
	name string // header / query name
	// hashVal: header values of credential-bearing headers are hashed so
	// secrets never land in engine keys, logs or Redis.
	hashVal bool
	// bits (partIP): IPv6 clients are keyed by their /bits prefix, so one
	// client cannot rotate addresses inside its allocation.
	bits int
}

type cpolicy struct {
	p        *model.Policy
	parts    []keyPart
	mode     model.Mode
	failMode model.FailMode
	cost     int
	conc     bool
	// policyHdr is the precomputed RateLimit-Policy value for the policy's
	// own Limit/Window (overrides recompute it).
	policyHdr string
	nameJSON  string // json.Marshal(p.Name), for the 429 body
}

var credentialHeaders = map[string]bool{
	"Authorization": true, "Proxy-Authorization": true, "Cookie": true, "Set-Cookie": true,
	"X-Api-Key": true, "X-Auth-Token": true,
}

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// compile converts an already-validated snapshot. It resolves proxies via the
// gateway's per-upstream cache.
func (g *Gateway) compile(s *model.Snapshot) *compiled {
	c := &compiled{
		snap:           s,
		byID:           map[string]*croute{},
		keys:           map[string]*ckey{},
		keysBin:        map[[32]byte]*ckey{},
		consumers:      map[string]*cconsumer{},
		plans:          map[string]*model.Plan{},
		legacyHeaders:  s.Settings.LegacyHeaders,
		exposeDecision: s.Settings.ExposeDecision,
		maxBody:        s.Settings.MaxBodyBytes,
		sample:         s.Settings.LogSampleAllowed,
		checkEnabled:   s.Settings.CheckAPIEnabled,
		fwdDisabled:    s.Settings.ForwardAuthDisabled,
		fwdRequireTok:  s.Settings.ForwardAuthRequireToken,
		secretHdr:      map[string]bool{},
		ipv6Bits:       s.Settings.IPv6PrefixLen,
	}
	if c.ipv6Bits <= 0 {
		c.ipv6Bits = 64
	}
	hdr := s.Settings.APIKeyHeader
	if hdr == "" {
		hdr = "X-API-Key"
	}
	c.keyHeader = http.CanonicalHeaderKey(hdr)
	for k := range credentialHeaders {
		c.secretHdr[k] = true
	}
	c.secretHdr[c.keyHeader] = true

	for _, t := range s.Settings.TrustedProxies {
		if p, err := netip.ParsePrefix(t); err == nil {
			c.trusted = append(c.trusted, p.Masked())
		} else if a, err := netip.ParseAddr(t); err == nil {
			c.trusted = append(c.trusted, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		}
	}

	policies := map[string]*cpolicy{}
	for i := range s.Policies {
		p := &s.Policies[i]
		policies[p.ID] = compilePolicy(p, c)
	}
	for i := range s.Plans {
		c.plans[s.Plans[i].ID] = &s.Plans[i]
	}
	for i := range s.Consumers {
		co := &s.Consumers[i]
		cc := &cconsumer{c: co, plan: c.plans[co.PlanID]}
		c.consumers[co.ID] = cc
		for j := range co.Keys {
			ck := &ckey{k: &co.Keys[j], consumer: cc}
			c.keys[strings.ToLower(co.Keys[j].Hash)] = ck
			// A stored hash that is not 64 hex digits can never equal a
			// sha256 hex digest, so it can never match either way.
			var d [32]byte
			if b, err := hex.DecodeString(co.Keys[j].Hash); err == nil && len(b) == len(d) {
				copy(d[:], b)
				c.keysBin[d] = ck
			}
		}
	}

	// Policy chain per route: global first, then route policies; dedupe,
	// skip disabled / missing.
	chain := func(ids ...[]string) []*cpolicy {
		var out []*cpolicy
		seen := map[string]bool{}
		for _, list := range ids {
			for _, id := range list {
				cp := policies[id]
				if cp == nil || !cp.p.Enabled || seen[id] {
					continue
				}
				seen[id] = true
				out = append(out, cp)
			}
		}
		return out
	}

	used := map[string]bool{}
	for i := range s.Routes {
		r := &s.Routes[i]
		if !r.Enabled {
			continue
		}
		cr := &croute{r: r, methods: map[string]bool{}, timeout: r.Timeout.D()}
		if cr.timeout <= 0 {
			cr.timeout = 30 * time.Second
		}
		if r.AllowUpgrade {
			if cr.upgradeMax = r.UpgradeMaxDuration.D(); cr.upgradeMax <= 0 {
				cr.upgradeMax = time.Hour
			}
		}
		if h := trimHostDot(strings.ToLower(r.Match.Host)); h != "" {
			if strings.HasPrefix(h, "*.") {
				cr.wildcard, cr.host = true, h[1:]
			} else {
				cr.host = h
			}
		}
		if pp := strings.TrimRight(r.Match.PathPrefix, "/"); pp != "" {
			cr.prefix = pp
		}
		for _, m := range r.Match.Methods {
			cr.methods[strings.ToUpper(m)] = true
		}
		cr.policies = chain(s.Settings.GlobalPolicyIDs, r.PolicyIDs)
		for _, cp := range cr.policies {
			if cp.p.Algorithm == model.AlgoLeakyBucket && cp.mode != model.ModeShadow {
				cr.shaper = cp
				break
			}
		}
		cr.target, _ = url.Parse(r.Upstream)
		cr.proxy = g.proxyFor(r.Upstream, cr.target)
		used[r.Upstream] = true
		c.routes = append(c.routes, cr)
		c.byID[r.ID] = cr
	}
	g.pruneProxies(used)

	sort.SliceStable(c.routes, func(i, j int) bool {
		a, b := c.routes[i], c.routes[j]
		if a.r.Priority != b.r.Priority {
			return a.r.Priority > b.r.Priority
		}
		if len(a.prefix) != len(b.prefix) {
			return len(a.prefix) > len(b.prefix)
		}
		return a.r.ID < b.r.ID
	})
	return c
}

func compilePolicy(p *model.Policy, c *compiled) *cpolicy {
	cp := &cpolicy{p: p, mode: p.Mode, failMode: p.FailMode, cost: p.Cost, conc: p.Algorithm == model.AlgoConcurrency}
	if cp.mode == "" {
		cp.mode = model.ModeEnforce
	}
	if cp.failMode == "" {
		cp.failMode = model.FailOpen
	}
	if cp.cost <= 0 {
		cp.cost = 1
	}
	cp.policyHdr = policyHeader(ratelimit.Params{Limit: p.Limit, Window: p.Window.D()})
	nb, _ := json.Marshal(p.Name)
	cp.nameJSON = string(nb)
	for _, k := range p.KeyBy {
		switch {
		case k == "consumer":
			cp.parts = append(cp.parts, keyPart{kind: partConsumer, bits: c.ipv6Bits}) // anonymous fallback is a masked IP
		case k == "api_key":
			cp.parts = append(cp.parts, keyPart{kind: partAPIKey})
		case k == "ip":
			cp.parts = append(cp.parts, keyPart{kind: partIP, bits: c.ipv6Bits})
		case k == "path":
			cp.parts = append(cp.parts, keyPart{kind: partPath})
		case k == "method":
			cp.parts = append(cp.parts, keyPart{kind: partMethod})
		case k == "route":
			cp.parts = append(cp.parts, keyPart{kind: partRoute})
		case k == "global":
			cp.parts = append(cp.parts, keyPart{kind: partGlobal})
		case strings.HasPrefix(k, "header:"):
			name := http.CanonicalHeaderKey(k[len("header:"):])
			cp.parts = append(cp.parts, keyPart{kind: partHeader, name: name, hashVal: c.secretHdr[name]})
		case strings.HasPrefix(k, "query:"):
			cp.parts = append(cp.parts, keyPart{kind: partQuery, name: k[len("query:"):]})
		}
	}
	if len(cp.parts) == 0 {
		cp.parts = []keyPart{{kind: partGlobal}} // empty KeyBy => single shared bucket
	}
	return cp
}

// match returns the best route for the request, or nil.
func (c *compiled) match(host, path, method string) *croute {
	host = normHost(host)
	for _, r := range c.routes { // pre-sorted by precedence
		if r.matches(host, path, method) {
			return r
		}
	}
	return nil
}

func (r *croute) matches(host, path, method string) bool {
	if r.host != "" {
		if r.wildcard {
			// "*.example.com" needs at least one label before the suffix.
			if len(host) <= len(r.host) || !strings.HasSuffix(host, r.host) {
				return false
			}
		} else if host != r.host {
			return false
		}
	}
	if r.prefix != "" && path != r.prefix && !strings.HasPrefix(path, r.prefix+"/") {
		return false
	}
	if len(r.methods) > 0 && !r.methods[method] {
		return false
	}
	return true
}

// normHost lower-cases and strips a port (IPv6 brackets handled) and the
// trailing dot of a fully qualified name, so "API.example.com.:443" and
// "api.example.com" select the same route.
func normHost(h string) string {
	h = strings.ToLower(h)
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i > 0 {
			return h[1:i]
		}
		return h
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	return trimHostDot(h)
}

// trimHostDot strips trailing dots ("example.com." is the same host as
// "example.com"), keeping a host that is nothing but dots unchanged so it
// can never become the match-anything empty host.
func trimHostDot(h string) string {
	if t := strings.TrimRight(h, "."); t != "" {
		return t
	}
	return h
}
