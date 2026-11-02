// Package telemetry keeps RateGuard's in-memory observability state: a
// bounded request-log ring buffer, live subscribers, time-series buckets,
// the dashboard overview and Prometheus metrics.
//
// Design summary (all memory is bounded):
//
//   - Log ring: LogCapacity entries (default 10000). Long string fields are
//     truncated on Record (every string field is capped, on a UTF-8 boundary).
//   - Time series: global rings of 720 x 5s buckets (1h) and 1440 x 1m
//     buckets (24h). Each bucket has counters, status classes and a 41-slot
//     log-scale latency histogram, so no samples are stored. Per-route rings
//     are kept only for the 50 busiest routes (each ~0.47MB, so ~23MB worst
//     case); other routes return all-zero series.
//   - Overview: totals/percentiles come from the 24h minute buckets; the
//     top-N lists use bounded two-generation maps (see topMap), which cover
//     12h..24h rather than exactly 24h.
//   - Prometheus: cumulative counters/histograms with label values capped
//     at 500 distinct routes and 500 distinct policies ("_other" beyond).
//
// Record takes a single mutex, does no I/O and feeds subscribers with
// non-blocking sends. Buckets are chosen from the hub clock (Options.Now) at
// Record time, not from LogEntry.Time.
package telemetry

import (
	"io"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"ratelimitergateway/internal/model"
)

const (
	defaultLogCapacity = 10000
	maxSubscribers     = 256
	maxRouteRings      = 50
	maxPathLen         = 2048
	maxUALen           = 256
	maxErrLen          = 512
	maxIDLen           = 128
	maxSubBuf          = 4096
)

// Options configures a Hub.
type Options struct {
	LogCapacity int              // ring buffer size; default 10000
	Now         func() time.Time // clock; default time.Now
}

type subscriber struct {
	ch chan model.LogEntry
}

// Hub is the telemetry aggregator. It is safe for concurrent use.
type Hub struct {
	now func() time.Time

	mu sync.Mutex

	// log ring
	logs   []model.LogEntry
	head   int // next write position
	nlogs  int
	seq    uint64
	idBase string // 12 hex digits of start time in ms

	// subscribers
	subs    map[*subscriber]struct{}
	dropped atomic.Uint64

	// time series
	global    *rings
	routeSer  map[string]*rings
	routeTraf *capMap // total requests per route (for choosing ringed routes)
	ringMin   int64   // cached lower bound of min traffic among ringed routes

	// overview top lists
	topLimited, topRoutes, topPolicies, topConsumers *topMap

	prom promState
}

// NewHub creates a Hub.
func NewHub(o Options) *Hub {
	if o.LogCapacity <= 0 {
		o.LogCapacity = defaultLogCapacity
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	now := o.Now()
	h := &Hub{
		now:          o.Now,
		logs:         make([]model.LogEntry, o.LogCapacity),
		idBase:       hex(uint64(now.UnixMilli()), 12),
		subs:         make(map[*subscriber]struct{}),
		global:       new(rings),
		routeSer:     make(map[string]*rings),
		routeTraf:    newCapMap(topMapCap),
		topLimited:   newTopMap(now),
		topRoutes:    newTopMap(now),
		topPolicies:  newTopMap(now),
		topConsumers: newTopMap(now),
	}
	h.prom = newPromState()
	return h
}

const hexdigits = "0123456789abcdef"

// hex renders v as zero-padded lowercase hex of exactly width digits.
func hex(v uint64, width int) string {
	var b [16]byte
	for i := width - 1; i >= 0; i-- {
		b[i] = hexdigits[v&0xf]
		v >>= 4
	}
	return string(b[:width])
}

func (h *Hub) newID() string {
	var b [28]byte
	copy(b[:12], h.idBase)
	v := h.seq
	for i := 27; i >= 12; i-- {
		b[i] = hexdigits[v&0xf]
		v >>= 4
	}
	return string(b[:])
}

// trunc cuts s to at most n bytes on a UTF-8 rune boundary.
func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func decisionKind(d string) int {
	switch d {
	case model.DecisionAllowed:
		return kAllowed
	case model.DecisionLimited:
		return kLimited
	case model.DecisionShadowLimited:
		return kShadow
	case model.DecisionUnauthorized, model.DecisionNoRoute, model.DecisionError:
		return kError
	}
	return kOther
}

// Record adds a request to the log, time series, overview and metrics. It
// assigns e.ID if empty (28 hex chars: start-time ms + monotonic counter, so
// IDs sort lexicographically in arrival order, including across restarts)
// and e.Time if zero. It never blocks.
func (h *Hub) Record(e model.LogEntry) {
	now := h.now()
	kind := decisionKind(e.Decision)
	cls := statusClass(e.Status)
	lat := e.LatencyMs
	if math.IsNaN(lat) || lat < 0 {
		lat = 0
	}
	hi := histIndex(lat)
	sec := now.Unix()
	e.Path = trunc(e.Path, maxPathLen)
	e.UserAgent = trunc(e.UserAgent, maxUALen)
	e.Error = trunc(e.Error, maxErrLen)
	e.Method = trunc(e.Method, 16)
	e.Host = trunc(e.Host, 255)
	e.ClientIP = trunc(e.ClientIP, 64)
	e.RateKey = trunc(e.RateKey, 256)
	e.RouteID = trunc(e.RouteID, maxIDLen)
	e.RouteName = trunc(e.RouteName, maxIDLen)
	e.ConsumerID = trunc(e.ConsumerID, maxIDLen)
	e.ConsumerName = trunc(e.ConsumerName, maxIDLen)
	e.PolicyID = trunc(e.PolicyID, maxIDLen)
	e.Source = trunc(e.Source, 32)
	e.Decision = trunc(e.Decision, 32)
	if e.Time.IsZero() {
		e.Time = now
	}

	h.mu.Lock()
	h.seq++
	if e.ID == "" {
		e.ID = h.newID()
	}
	h.logs[h.head] = e
	h.head++
	if h.head == len(h.logs) {
		h.head = 0
	}
	if h.nlogs < len(h.logs) {
		h.nlogs++
	}

	h.global.record(sec, kind, cls, hi)
	if e.RouteID != "" {
		h.recordRoute(e.RouteID, sec, kind, cls, hi)
	}

	h.topRoutes.rotate(now)
	h.topLimited.rotate(now)
	h.topPolicies.rotate(now)
	h.topConsumers.rotate(now)
	if e.RouteID != "" {
		l := e.RouteName
		h.topRoutes.add(e.RouteID, l)
	}
	if e.ConsumerID != "" {
		h.topConsumers.add(e.ConsumerID, e.ConsumerName)
	}
	if kind == kLimited {
		if e.RateKey != "" {
			h.topLimited.add(e.RateKey, e.ConsumerName)
		}
		if e.PolicyID != "" {
			h.topPolicies.add(e.PolicyID, "")
		}
	}

	h.prom.observe(&e, kind, cls, lat)

	for s := range h.subs {
		select {
		case s.ch <- e:
		default:
			h.dropped.Add(1)
		}
	}
	h.mu.Unlock()
}

// recordRoute updates the per-route ring if the route is (or becomes) one of
// the maxRouteRings busiest. Caller holds h.mu.
func (h *Hub) recordRoute(id string, sec int64, kind, cls, hi int) {
	n := h.routeTraf.add(id, "", 1)
	r := h.routeSer[id]
	if r == nil {
		switch {
		case len(h.routeSer) < maxRouteRings:
			r = new(rings)
			h.routeSer[id] = r
		case n > h.ringMin:
			// Find the least busy ringed route; replace it if we beat it.
			minID, min := "", int64(math.MaxInt64)
			for rid := range h.routeSer {
				if c := h.routeTraf.get(rid); c < min {
					minID, min = rid, c
				}
			}
			h.ringMin = min
			if n > min {
				delete(h.routeSer, minID)
				r = new(rings)
				h.routeSer[id] = r
			}
		}
	}
	if r != nil {
		r.record(sec, kind, cls, hi)
	}
}

// QueryLogs returns matching entries, newest first.
func (h *Hub) QueryLogs(q model.LogQuery) []model.LogEntry {
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	search := strings.ToLower(q.Search)
	out := make([]model.LogEntry, 0, min(limit, 64))

	h.mu.Lock()
	defer h.mu.Unlock()
	n := len(h.logs)
	for i := 0; i < h.nlogs && len(out) < limit; i++ {
		e := &h.logs[((h.head-1-i)%n+n)%n]
		if q.Before != "" && e.ID >= q.Before {
			continue
		}
		if q.Decision != "" && e.Decision != q.Decision {
			continue
		}
		if q.RouteID != "" && e.RouteID != q.RouteID {
			continue
		}
		if q.ConsumerID != "" && e.ConsumerID != q.ConsumerID {
			continue
		}
		if q.PolicyID != "" && e.PolicyID != q.PolicyID {
			continue
		}
		if q.StatusMin > 0 && e.Status < q.StatusMin {
			continue
		}
		if q.StatusMax > 0 && e.Status > q.StatusMax {
			continue
		}
		if !q.Since.IsZero() && e.Time.Before(q.Since) {
			continue
		}
		if search != "" && !(containsFold(e.Path, search) || containsFold(e.ClientIP, search) ||
			containsFold(e.RateKey, search) || containsFold(e.ConsumerName, search)) {
			continue
		}
		out = append(out, *e)
	}
	return out
}

// containsFold reports whether s contains sub (already lower-case),
// ignoring ASCII case, without allocating.
func containsFold(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		j := 0
		for ; j < len(sub); j++ {
			c := s[i+j]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != sub[j] {
				break
			}
		}
		if j == len(sub) {
			return true
		}
	}
	return false
}

// Subscribe returns a channel of future entries with buffer buf (default 64
// if buf <= 0) and a cancel func that unsubscribes and closes the channel.
// A subscriber whose buffer is full silently misses entries (counted in
// SubscriberDrops); Record never blocks. At most 256 subscribers are
// allowed; beyond that an already-closed channel is returned.
func (h *Hub) Subscribe(buf int) (<-chan model.LogEntry, func()) {
	if buf <= 0 {
		buf = 64
	}
	if buf > maxSubBuf {
		buf = maxSubBuf
	}
	s := &subscriber{ch: make(chan model.LogEntry, buf)}
	h.mu.Lock()
	if len(h.subs) >= maxSubscribers {
		h.mu.Unlock()
		close(s.ch)
		return s.ch, func() {}
	}
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	return s.ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, s)
			close(s.ch)
			h.mu.Unlock()
		})
	}
}

// SubscriberDrops returns how many deliveries were skipped because a
// subscriber's buffer was full.
func (h *Hub) SubscriberDrops() uint64 { return h.dropped.Load() }

// LogLen returns the number of entries currently buffered.
func (h *Hub) LogLen() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.nlogs
}

// WritePrometheus writes metrics in the Prometheus text exposition format.
func (h *Hub) WritePrometheus(w io.Writer) {
	h.mu.Lock()
	snap := h.prom.snapshot()
	n := h.nlogs
	h.mu.Unlock()
	snap.write(w, n)
}
