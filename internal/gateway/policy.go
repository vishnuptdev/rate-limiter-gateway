package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"time"

	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/ratelimit"
)

// reqInfo is the transport-independent view of a request used by auth, key
// derivation and policy evaluation (shared by proxy, check API and simulator).
type reqInfo struct {
	method, host, path string
	ip                 string
	apiKey             string   // presented key, "" if none
	keySum             [32]byte // sha256(apiKey), valid when keySumOK
	keySumOK           bool
	header             func(canonicalName string) string
	query              func(name string) string
	route              *croute
	consumer           *cconsumer
}

const maxKeyPartLen = 128 // bound engine-key growth from attacker-controlled values

// authenticate resolves a presented key. reason is "" on success; a key that
// is present but unusable always yields a non-empty reason.
func (c *compiled) authenticate(key string, now time.Time) (*cconsumer, string) {
	if key == "" {
		return nil, ""
	}
	return c.authenticateSum(sha256.Sum256([]byte(key)), now)
}

// authenticateSum is authenticate for an already computed sha256 of the key.
func (c *compiled) authenticateSum(sum [32]byte, now time.Time) (*cconsumer, string) {
	k := c.keysBin[sum]
	switch {
	case k == nil:
		return nil, "invalid API key"
	case k.k.Revoked:
		return nil, "API key revoked"
	case k.k.ExpiresAt != nil && !now.Before(*k.k.ExpiresAt):
		return nil, "API key expired"
	case k.consumer.c.Disabled:
		return nil, "consumer disabled"
	}
	return k.consumer, ""
}

// authenticate resolves ri.apiKey, hashing it once and keeping the digest
// for api_key bucket keys.
func (ri *reqInfo) authenticate(c *compiled, now time.Time) (*cconsumer, string) {
	if ri.apiKey == "" {
		return nil, ""
	}
	ri.keySum, ri.keySumOK = sha256.Sum256([]byte(ri.apiKey)), true
	return c.authenticateSum(ri.keySum, now)
}

// extractKey reads the API key from the configured header, falling back to
// "Authorization: Bearer <key>".
func (c *compiled) extractKey(get func(string) string) string {
	if v := strings.TrimSpace(get(c.keyHeader)); v != "" {
		return v
	}
	if a := get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		return strings.TrimSpace(a[7:])
	}
	return ""
}

func trunc(s string) string {
	if len(s) > maxKeyPartLen {
		return s[:maxKeyPartLen]
	}
	return s
}

// composite builds the bucket identity for a policy (parts joined with "|").
func (ri *reqInfo) composite(cp *cpolicy) string {
	if len(cp.parts) == 1 {
		return ri.part(cp.parts[0])
	}
	var b strings.Builder
	for i, kp := range cp.parts {
		if i > 0 {
			b.WriteByte('|')
		}
		b.WriteString(ri.part(kp))
	}
	return b.String()
}

func (ri *reqInfo) part(kp keyPart) string {
	switch kp.kind {
	case partConsumer:
		if ri.consumer != nil {
			return ri.consumer.c.ID
		}
		return "ip:" + ri.ip
	case partAPIKey:
		if ri.apiKey == "" {
			return "-"
		}
		if ri.keySumOK {
			return hex.EncodeToString(ri.keySum[:8]) // == hashHex(apiKey)[:16]
		}
		return hashHex(ri.apiKey)[:16]
	case partIP:
		return ri.ip
	case partHeader:
		v := ri.header(kp.name)
		if v == "" {
			return "-"
		}
		if kp.hashVal {
			return "h:" + hashHex(v)[:16]
		}
		return trunc(v)
	case partQuery:
		if v := ri.query(kp.name); v != "" {
			return trunc(v)
		}
		return "-"
	case partPath:
		return trunc(ri.path)
	case partMethod:
		return ri.method
	case partRoute:
		return ri.route.r.ID
	}
	return "global"
}

// effective resolves the numbers for a policy: consumer override > plan
// override > policy. Zero override fields keep the lower layer. from is the
// highest-precedence layer that overrides anything ("consumer",
// "plan:<id>" or "policy").
func (ri *reqInfo) effective(cp *cpolicy, costMul int) (ratelimit.Params, string) {
	p := cp.p
	prm := ratelimit.Params{Algorithm: p.Algorithm, Limit: p.Limit, Window: p.Window.D(), Burst: p.Burst, Cost: cp.cost * costMul}
	from := "policy"
	apply := func(o model.LimitOverride, src string) bool {
		if o.Limit == 0 && o.Window == 0 && o.Burst == 0 {
			return false
		}
		if o.Limit > 0 {
			prm.Limit = o.Limit
		}
		if o.Window > 0 {
			prm.Window = o.Window.D()
		}
		if o.Burst > 0 {
			prm.Burst = o.Burst
		}
		from = src
		return true
	}
	if ri.consumer != nil {
		// Apply plan first, then consumer on top, so consumer wins per-field.
		if pl := ri.consumer.plan; pl != nil {
			apply(pl.Overrides[p.ID], "plan:"+pl.ID)
		}
		apply(ri.consumer.c.Overrides[p.ID], "consumer")
	}
	return prm, from
}

// polResult is the outcome for one policy.
type polResult struct {
	cp        *cpolicy
	params    ratelimit.Params
	from      string
	composite string
	engineKey string
	dec       ratelimit.Decision
	called    bool // engine was consulted successfully
	denied    bool
	err       error
}

type heldSlot struct {
	key string
	p   ratelimit.Params
}

// outcome is the aggregate verdict for a request.
type outcome struct {
	results []polResult
	denier  *polResult // first enforce deny
	failed  *polResult // fail-closed backend error
	shadow  bool       // at least one shadow deny
	best    *polResult // source of rate-limit headers
	held    []heldSlot // concurrency slots to release after the response
	soft    []string   // fail-open errors (notes)
	inline  [2]polResult
}

type evalOpts struct {
	skipConcurrency bool
	costMul         int
	dryRun          bool // resolve only: never call the engine
}

var errNoEngine = errors.New("no rate limit engine configured")

// evaluate runs the route's policy chain. It stops at the first enforce deny
// or fail-closed error (releasing concurrency slots already taken); shadow
// denies and fail-open errors continue. In dry-run mode only the effective
// configuration is resolved.
func (g *Gateway) evaluate(ctx context.Context, ri *reqInfo, o evalOpts) *outcome {
	out := &outcome{}
	if o.costMul < 1 {
		o.costMul = 1
	}
	if len(ri.route.policies) <= len(out.inline) {
		out.results = out.inline[:0]
	} else {
		out.results = make([]polResult, 0, len(ri.route.policies))
	}
	for _, cp := range ri.route.policies {
		if o.skipConcurrency && cp.conc {
			continue
		}
		prm, from := ri.effective(cp, o.costMul)
		comp := ri.composite(cp)
		out.results = append(out.results, polResult{cp: cp, params: prm, from: from, composite: comp, engineKey: g.EngineKey(cp.p.ID, comp)})
		res := &out.results[len(out.results)-1]
		if o.dryRun {
			continue
		}
		dec, err := g.engine.Allow(ctx, res.engineKey, prm)
		if err != nil {
			res.err = err
			if cp.failMode == model.FailClosed {
				out.failed = res
				g.releaseSlots(out.held)
				out.held = nil
				return out
			}
			out.soft = append(out.soft, cp.p.ID+": "+err.Error())
			continue
		}
		res.called, res.dec = true, dec
		if !dec.Allowed {
			res.denied = true
			if cp.mode == model.ModeShadow {
				out.shadow = true
				continue
			}
			out.denier = res
			g.releaseSlots(out.held)
			out.held = nil
			out.best = res
			return out
		}
		if cp.conc {
			out.held = append(out.held, heldSlot{res.engineKey, prm})
		}
	}
	out.best = pickBest(out.results)
	return out
}

// pickBest chooses the most restrictive enforce policy (lowest remaining) for
// the headers. Concurrency policies only count if nothing else is available.
func pickBest(rs []polResult) *polResult {
	var best, bestConc *polResult
	for i := range rs {
		r := &rs[i]
		if !r.called || r.cp.mode == model.ModeShadow {
			continue
		}
		if r.cp.conc {
			if bestConc == nil || r.dec.Remaining < bestConc.dec.Remaining {
				bestConc = r
			}
			continue
		}
		if best == nil || r.dec.Remaining < best.dec.Remaining {
			best = r
		}
	}
	if best == nil {
		return bestConc
	}
	return best
}

// releaseSlots returns concurrency slots. It uses its own short context so a
// cancelled client request can never leak a slot.
func (g *Gateway) releaseSlots(held []heldSlot) {
	if len(held) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, h := range held {
		if err := g.engine.Release(ctx, h.key, h.p); err != nil {
			g.log.Warn("release concurrency slot failed", "key", h.key, "err", err)
		}
	}
}

// ---------------------------------------------------------------------
// Client IP
// ---------------------------------------------------------------------

func (c *compiled) isTrusted(a netip.Addr) bool {
	for _, p := range c.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP returns the peer address unless the peer is a trusted proxy, in
// which case X-Forwarded-For is walked right-to-left skipping trusted hops.
// An unparseable entry stops the walk (it is never trusted as an address).
func (c *compiled) clientIP(remoteAddr string, xff []string) string {
	peer := remoteAddr
	var pa netip.Addr
	parsed := false
	if ap, err := netip.ParseAddrPort(remoteAddr); err == nil {
		pa, parsed = ap.Addr().Unmap(), true
		if ap.Addr().Is4() {
			// netip only accepts canonical dotted-quad IPv4, so the host
			// part is already exactly pa.String(); reuse it.
			peer = remoteAddr[:strings.LastIndexByte(remoteAddr, ':')]
		} else {
			peer = pa.String()
		}
	} else if a, err := netip.ParseAddr(remoteAddr); err == nil {
		pa, parsed = a.Unmap(), true
		peer = pa.String()
	}
	if !parsed || len(c.trusted) == 0 || !c.isTrusted(pa) {
		return peer
	}
	var hops []string
	for _, line := range xff {
		for _, h := range strings.Split(line, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hops = append(hops, h)
			}
		}
	}
	cand := peer
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(hops[i])
		if err != nil {
			break
		}
		a = a.Unmap()
		cand = a.String()
		if !c.isTrusted(a) {
			break
		}
	}
	return cand
}

// maxShapingDelay is a defensive hard ceiling on a queue wait. store.Validate
// already bounds a leaky bucket's delay to 30s; a decision above the ceiling
// is denied (tooLong) rather than released early, which would break the
// shaping rate.
const maxShapingDelay = 30 * time.Second

// shapingDelay is how long an admitted request must wait before proceeding:
// the largest leaky-bucket queue delay among the enforcing policies (shadow
// policies never delay traffic). When a decision's delay exceeds the ceiling
// it returns tooLong with that policy's result in src.
func (o *outcome) shapingDelay() (d time.Duration, src *polResult, tooLong bool) {
	for i := range o.results {
		r := &o.results[i]
		if !r.called || r.denied || r.cp.mode == model.ModeShadow || r.dec.Delay <= 0 {
			continue
		}
		if r.dec.Delay > maxShapingDelay {
			return r.dec.Delay, r, true
		}
		if r.dec.Delay > d {
			d = r.dec.Delay
		}
	}
	return d, nil, false
}
