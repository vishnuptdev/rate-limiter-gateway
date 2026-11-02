package ratelimit

import (
	"context"
	"hash/fnv"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"ratelimitergateway/internal/model"
)

const (
	numShards         = 64
	defaultMaxKeys    = 1_000_000
	defaultGCInterval = 30 * time.Second
	// concurrencyIdleTTL: Window is ignored for concurrency, so idle
	// (nothing in flight) concurrency keys are collected after this long.
	concurrencyIdleTTL = time.Minute
	overflowBuckets    = 4096
	evictSample        = 8
	overflowWarnEvery  = time.Minute
)

// MemoryOptions configures a Memory engine. Zero values pick defaults.
type MemoryOptions struct {
	MaxKeys    int              // tracked-key cap; default 1,000,000
	GCInterval time.Duration    // idle-key sweep period; default 30s
	Now        func() time.Time // injectable clock; default time.Now
	Logger     *slog.Logger     // default slog.Default()
}

// Memory is an in-process Engine. State is spread over 64 mutex-protected
// shards chosen by FNV-1a of the key, so unrelated keys rarely contend.
//
// Bounded memory: at most MaxKeys keys are tracked. When full, a new key
// first evicts a fully replenished (idle) entry from its shard, sampling up
// to 8 entries, which loses no information. If none is evictable the key is
// mapped onto one of 4096 shared overflow buckets (same Params), so a key
// flood is still rate limited, only coarser; a warning is logged at most
// once a minute and OverflowActive/OverflowCount expose it. A background
// goroutine removes keys idle for more than twice their window every
// GCInterval (token buckets: max(2*window, time-to-full)). Concurrency
// slots carry a 60s lease like the Redis engine, so a missed Release heals.
//
// The exact sliding-window log keeps one record per accepted request in
// the trailing window, so its memory is O(Limit) per key by definition.
type Memory struct {
	shards  [numShards]shard
	now     func() time.Time
	maxKeys int64
	keys    atomic.Int64
	log     *slog.Logger

	overflow     [overflowBuckets]overflowSlot
	overflowN    atomic.Int64 // requests served from overflow buckets
	overflowLast atomic.Int64 // unix ns of last overflow use
	warnLast     atomic.Int64 // unix ns of last warning

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

// overflowSlot is a shared bucket (one entry per algorithm) used when the key
// cap is full and nothing can be evicted losslessly.
type overflowSlot struct {
	mu sync.Mutex
	m  map[model.Algorithm]*entry
}

type shard struct {
	mu sync.Mutex
	m  map[string]*entry
}

type logRec struct {
	ns int64
	n  int
}

// entry is the state of one (algorithm, key). Only the fields of its
// algorithm are used.
type entry struct {
	lastSeen int64 // unix ns of last touch
	idleNs   int64 // evict after being idle this long

	// token bucket
	tokens float64
	lastNs int64

	// GCRA / leaky bucket: theoretical arrival time in unix ns (0 = fresh)
	tat int64

	// sliding window log
	log []logRec

	// sliding window counter / fixed window
	winIdx int64
	curr   int
	prev   int

	// concurrency: live leases (expiry ns, units), oldest first
	leases []logRec
}

// NewMemory creates a Memory engine and starts its GC goroutine; call
// Close to stop it.
func NewMemory(opts MemoryOptions) *Memory {
	m := &Memory{
		now:     opts.Now,
		maxKeys: int64(opts.MaxKeys),
		log:     opts.Logger,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.maxKeys <= 0 {
		m.maxKeys = defaultMaxKeys
	}
	if m.log == nil {
		m.log = slog.Default()
	}
	for i := range m.shards {
		m.shards[i].m = make(map[string]*entry)
	}
	gc := opts.GCInterval
	if gc <= 0 {
		gc = defaultGCInterval
	}
	go m.gcLoop(gc)
	return m
}

func (m *Memory) Name() string { return "memory" }

// InProcess reports that the engine never blocks on I/O, so callers need
// not put a deadline on its calls (the context is not consulted).
func (m *Memory) InProcess() bool                   { return true }
func (m *Memory) Healthy(ctx context.Context) error { return nil }

// Close stops the GC goroutine. It is safe to call more than once.
func (m *Memory) Close() error {
	m.stopOnce.Do(func() { close(m.stop) })
	<-m.done
	return nil
}

func (m *Memory) gcLoop(every time.Duration) {
	defer close(m.done)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.gc()
		}
	}
}

// gc removes idle entries; exposed (unexported) for tests.
func (m *Memory) gc() int {
	now := m.now().UnixNano()
	removed := 0
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.Lock()
		for k, e := range s.m {
			if e.idle(now) {
				delete(s.m, k)
				m.keys.Add(-1)
				removed++
			}
		}
		s.mu.Unlock()
	}
	return removed
}

// evictOne removes one fully replenished entry from the shard, sampling at
// most evictSample entries (map order is random). Caller holds s.mu.
func (s *shard) evictOne(now int64) bool {
	n := 0
	for k, e := range s.m {
		if e.idle(now) {
			delete(s.m, k)
			return true
		}
		if n++; n >= evictSample {
			break
		}
	}
	return false
}

// idle reports whether the entry is indistinguishable from a fresh one
// (so dropping it loses nothing): idle past its replenish horizon and with
// no live concurrency leases.
func (e *entry) idle(now int64) bool {
	e.purgeLeases(now)
	return len(e.leases) == 0 && now-e.lastSeen > e.idleNs
}

func (e *entry) purgeLeases(now int64) {
	i := 0
	for i < len(e.leases) && e.leases[i].ns <= now {
		i++
	}
	if i > 0 {
		e.leases = append(e.leases[:0], e.leases[i:]...)
	}
}

func (m *Memory) overflowSlotFor(sk string) *overflowSlot {
	h := fnv.New32a()
	h.Write([]byte(sk))
	return &m.overflow[h.Sum32()%overflowBuckets]
}

func (m *Memory) allowOverflow(sk string, p Params, now int64) Decision {
	m.overflowN.Add(1)
	m.overflowLast.Store(now)
	if last := m.warnLast.Load(); now-last >= int64(overflowWarnEvery) && m.warnLast.CompareAndSwap(last, now) {
		m.log.Warn("ratelimit: memory engine key cap reached; new keys share overflow buckets", "max_keys", m.maxKeys, "overflow_buckets", overflowBuckets)
	}
	o := m.overflowSlotFor(sk)
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.m == nil {
		o.m = make(map[model.Algorithm]*entry, 1)
	}
	e := o.m[p.Algorithm]
	if e == nil {
		e = &entry{}
		e.init(p, now)
		o.m[p.Algorithm] = e
	}
	e.lastSeen = now
	e.idleNs = idleNs(p)
	return e.eval(p, now, true)
}

// OverflowActive reports whether, within the last minute, a request was
// served from a shared overflow bucket because the key cap was full.
func (m *Memory) OverflowActive() bool {
	last := m.overflowLast.Load()
	return last != 0 && m.now().UnixNano()-last < int64(overflowWarnEvery)
}

// OverflowCount is the total number of requests served from overflow buckets.
func (m *Memory) OverflowCount() int64 { return m.overflowN.Load() }

// KeyCount returns the number of tracked keys.
func (m *Memory) KeyCount() int { return int(m.keys.Load()) }

func (m *Memory) shardFor(k string) *shard {
	h := fnv.New32a()
	h.Write([]byte(k))
	return &m.shards[h.Sum32()%numShards]
}

func storeKey(a model.Algorithm, key string) string { return string(a) + "\x00" + key }

func (m *Memory) Allow(ctx context.Context, key string, p Params) (Decision, error) {
	p, err := normalize(p)
	if err != nil {
		return Decision{}, err
	}
	now := m.now().UnixNano()
	sk := storeKey(p.Algorithm, key)
	s := m.shardFor(sk)
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.m[sk]
	if e == nil {
		e = &entry{}
		e.init(p, now)
		if m.keys.Add(1) > m.maxKeys {
			m.keys.Add(-1)
			if !s.evictOne(now) {
				// Nothing is losslessly evictable: share one of a fixed set
				// of overflow buckets so the key is still limited.
				return m.allowOverflow(sk, p, now), nil
			}
			// Evicted one, inserting one: the count is unchanged.
		}
		s.m[sk] = e
	}
	e.lastSeen = now
	e.idleNs = idleNs(p)
	return e.eval(p, now, true), nil
}

func (m *Memory) Peek(ctx context.Context, key string, p Params) (Decision, bool, error) {
	p, err := normalize(p)
	if err != nil {
		return Decision{}, false, err
	}
	now := m.now().UnixNano()
	sk := storeKey(p.Algorithm, key)
	s := m.shardFor(sk)
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.m[sk]
	if e == nil {
		fresh := &entry{}
		fresh.init(p, now)
		return fresh.eval(p, now, false), false, nil
	}
	return e.eval(p, now, false), true, nil
}

func (m *Memory) Release(ctx context.Context, key string, p Params) error {
	if p.Algorithm != model.AlgoConcurrency {
		return nil
	}
	s := m.shardFor(storeKey(p.Algorithm, key))
	s.mu.Lock()
	defer s.mu.Unlock()
	now := m.now().UnixNano()
	n := p.Cost
	if n <= 0 {
		n = 1
	}
	e := s.m[storeKey(p.Algorithm, key)]
	if e == nil {
		if !m.OverflowActive() {
			return nil
		}
		// The key may have been mapped onto an overflow bucket.
		o := m.overflowSlotFor(storeKey(p.Algorithm, key))
		o.mu.Lock()
		defer o.mu.Unlock()
		e = o.m[p.Algorithm]
	}
	if e != nil {
		e.purgeLeases(now)
		e.dropLeases(n)
		e.lastSeen = now
	}
	return nil
}

func (m *Memory) Reset(ctx context.Context, key string, p Params) error {
	sk := storeKey(p.Algorithm, key)
	s := m.shardFor(sk)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[sk]; ok {
		delete(s.m, sk)
		m.keys.Add(-1)
	}
	return nil
}

func idleNs(p Params) int64 {
	switch p.Algorithm {
	case model.AlgoConcurrency:
		return int64(concurrencyIdleTTL)
	case model.AlgoTokenBucket:
		// A bucket is indistinguishable from a fresh one once refilled.
		w := 2 * p.Window
		full := time.Duration(float64(p.Window) * float64(p.Burst) / float64(p.Limit))
		if full > w {
			w = full
		}
		return int64(w)
	}
	return int64(2 * p.Window)
}

func (e *entry) init(p Params, now int64) {
	e.lastSeen = now
	e.idleNs = idleNs(p)
	e.lastNs = now
	e.tokens = float64(p.Burst)
	e.winIdx = -1 // no window yet
}

// eval applies the algorithm. When consume is false the entry is not
// modified (Peek), and Allowed reports whether p.Cost would be allowed.
func (e *entry) eval(p Params, now int64, consume bool) Decision {
	switch p.Algorithm {
	case model.AlgoTokenBucket:
		return e.tokenBucket(p, now, consume)
	case model.AlgoSlidingWindow:
		return e.slidingLog(p, now, consume)
	case model.AlgoSlidingWindowCounter:
		return e.slidingCounter(p, now, consume)
	case model.AlgoFixedWindow:
		return e.fixedWindow(p, now, consume)
	case model.AlgoGCRA:
		return e.gcra(p, now, consume, false)
	case model.AlgoLeakyBucket:
		return e.gcra(p, now, consume, true)
	default:
		return e.concurrency(p, now, consume)
	}
}

const eps = 1e-9

func (e *entry) tokenBucket(p Params, now int64, consume bool) Decision {
	capF := float64(p.Burst)
	win := float64(p.Window.Nanoseconds())
	rate := float64(p.Limit) / win // tokens per ns
	tokens := e.tokens
	if el := now - e.lastNs; el > 0 {
		tokens += float64(el) * rate
	}
	if tokens > capF {
		tokens = capF
	}
	cost := float64(p.Cost)
	allowed := cost <= tokens+eps
	var retry time.Duration
	if allowed {
		if consume {
			tokens -= cost
			if tokens < 0 {
				tokens = 0
			}
		}
	} else if p.Cost > p.Burst {
		retry = time.Duration((capF - tokens) / rate) // can never fit: time to full
	} else {
		retry = time.Duration((cost - tokens) / rate)
	}
	if consume {
		e.tokens, e.lastNs = tokens, now
	}
	rem := int(tokens + eps)
	return Decision{
		Allowed:    allowed,
		Limit:      p.Burst,
		Remaining:  rem,
		ResetAfter: ceilMs(time.Duration((capF - tokens) / rate)),
		RetryAfter: ceilMs(retry),
	}
}

func (e *entry) slidingLog(p Params, now int64, consume bool) Decision {
	win := int64(p.Window)
	// Drop records that left the trailing window (ns <= now-win).
	i := 0
	for i < len(e.log) && e.log[i].ns <= now-win {
		i++
	}
	if i > 0 {
		e.log = append(e.log[:0], e.log[i:]...)
	}
	count := 0
	for _, r := range e.log {
		count += r.n
	}
	allowed := p.Cost <= p.Limit && count+p.Cost <= p.Limit
	if allowed && consume {
		e.log = append(e.log, logRec{ns: now, n: p.Cost})
		count += p.Cost
	}
	d := Decision{Allowed: allowed, Limit: p.Limit, Remaining: max(0, p.Limit-count)}
	if n := len(e.log); n > 0 {
		d.ResetAfter = ceilMs(time.Duration(e.log[n-1].ns + win - now))
	}
	if !allowed {
		if p.Cost > p.Limit {
			d.RetryAfter = d.ResetAfter // can never fit: time to empty
		} else {
			// Wait until enough of the oldest units expire.
			need, acc := count+p.Cost-p.Limit, 0
			for _, r := range e.log {
				acc += r.n
				if acc >= need {
					d.RetryAfter = ceilMs(time.Duration(r.ns + win - now))
					break
				}
			}
		}
	}
	return d
}

// slidingCounter is the weighted two-window approximation:
// estimate = prev*(1-elapsed/window) + curr, where windows are aligned to
// the epoch.
func (e *entry) slidingCounter(p Params, now int64, consume bool) Decision {
	win := int64(p.Window)
	idx := now / win
	into := now - idx*win
	frac := float64(into) / float64(win)
	curr, prev := e.curr, e.prev
	switch {
	case e.winIdx == idx:
	case e.winIdx == idx-1:
		prev, curr = e.curr, 0
	default:
		prev, curr = 0, 0
	}
	weighted := float64(prev)*(1-frac) + float64(curr)
	limit, cost := float64(p.Limit), float64(p.Cost)
	allowed := p.Cost <= p.Limit && weighted+cost <= limit+eps
	if allowed && consume {
		curr += p.Cost
		weighted += cost
	}
	if consume {
		e.winIdx, e.curr, e.prev = idx, curr, prev
	}
	d := Decision{Allowed: allowed, Limit: p.Limit, Remaining: max(0, int(limit-weighted+eps))}
	rem := win - into // time to end of current window
	switch {
	case curr > 0:
		d.ResetAfter = ceilMs(time.Duration(rem + win))
	case prev > 0:
		d.ResetAfter = ceilMs(time.Duration(rem))
	}
	if !allowed {
		if p.Cost > p.Limit {
			d.RetryAfter = d.ResetAfter
		} else if prev > 0 && limit-float64(curr)-cost >= 0 {
			// Within this window the prev weight decays linearly.
			f := 1 - (limit-float64(curr)-cost)/float64(prev)
			d.RetryAfter = ceilMs(time.Duration((f - frac) * float64(win)))
			if d.RetryAfter <= 0 {
				d.RetryAfter = time.Millisecond
			}
		} else {
			// Wait for the next window, where curr becomes the decaying prev.
			f := 1 - (limit-cost)/float64(curr)
			if f < 0 {
				f = 0
			}
			d.RetryAfter = ceilMs(time.Duration(float64(rem) + f*float64(win)))
		}
	}
	return d
}

func (e *entry) fixedWindow(p Params, now int64, consume bool) Decision {
	win := int64(p.Window)
	idx := now / win
	count := e.curr
	if e.winIdx != idx {
		count = 0
	}
	allowed := p.Cost <= p.Limit && count+p.Cost <= p.Limit
	if allowed {
		count += p.Cost
		if !consume {
			count -= p.Cost
		}
	}
	if consume {
		e.winIdx, e.curr = idx, count
	}
	reset := ceilMs(time.Duration((idx+1)*win - now))
	d := Decision{Allowed: allowed, Limit: p.Limit, Remaining: max(0, p.Limit-count), ResetAfter: reset}
	if !allowed {
		d.RetryAfter = reset
	}
	return d
}

// dropLeases frees n units, oldest lease first.
func (e *entry) dropLeases(n int) {
	for n > 0 && len(e.leases) > 0 {
		if e.leases[0].n <= n {
			n -= e.leases[0].n
			e.leases = e.leases[1:]
		} else {
			e.leases[0].n -= n
			n = 0
		}
	}
}

func (e *entry) concurrency(p Params, now int64, consume bool) Decision {
	e.purgeLeases(now)
	n := 0
	for _, l := range e.leases {
		n += l.n
	}
	allowed := p.Cost <= p.Limit && n+p.Cost <= p.Limit
	if allowed && consume {
		e.leases = append(e.leases, logRec{ns: now + int64(concurrencyLeaseTTL), n: p.Cost})
		n += p.Cost
	}
	d := Decision{Allowed: allowed, Limit: p.Limit, Remaining: max(0, p.Limit-n)}
	if n > 0 {
		d.ResetAfter = concurrencyRetryHint
	}
	if !allowed {
		d.RetryAfter = concurrencyRetryHint
	}
	return d
}

// gcra implements both the Generic Cell Rate Algorithm and the leaky bucket
// shaper; they share one piece of state, the theoretical arrival time (TAT):
// the instant at which the virtual queue of admitted requests has drained.
//
//	T   = Window/Limit            emission interval (time per unit)
//	cap = Burst*T                 queue capacity expressed as drain time
//	B   = max(TAT-now, 0)         current backlog
//
// A request of Cost n is admitted iff B + n*T <= cap (for n=1 this is the
// classic "TAT-now <= tau" with tau = T*(Burst-1)); then TAT = now + B + n*T.
// A request with n > Burst can never fit. GCRA admits immediately
// (Delay 0): the backlog is only a debt that limits later arrivals.
// Leaky bucket (shape=true) instead reports Delay = B, the time the request
// waits in the queue before it may proceed; the queue holds at most Burst
// units, so Delay never exceeds (Burst-1)*T.
//
// Remaining is the number of further units that would be admitted right now
// (GCRA: burst credit; leaky bucket: free queue slots). RetryAfter, when
// denied, is the time until the request would fit (or the time to fully
// drain when n > Burst). ResetAfter is the time to fully drain.
//
// The entry is idle (losslessly evictable) exactly when TAT <= now, which
// is indistinguishable from a fresh key, so idleNs tracks the backlog.
// State is a single int64 guarded by the shard lock (not a lock-free CAS)
// to stay consistent with the other algorithms and the eviction logic.
func (e *entry) gcra(p Params, now int64, consume, shape bool) Decision {
	win := float64(p.Window.Nanoseconds())
	lim := float64(p.Limit)
	unit := max(int64(math.Round(win/lim)), 1)                      // T
	inc := max(int64(math.Round(win*float64(p.Cost)/lim)), 1)       // n*T
	capNs := max(int64(math.Round(win*float64(p.Burst)/lim)), unit) // Burst*T
	backlog := max(e.tat-now, 0)
	wait := backlog // queue wait of this request (leaky bucket)
	allowed := backlog+inc <= capNs
	var retry time.Duration
	if allowed {
		if consume {
			backlog += inc
			e.tat = now + backlog
		}
	} else if inc > capNs {
		retry = time.Duration(backlog) // can never fit: time to drain
	} else {
		retry = time.Duration(backlog + inc - capNs)
	}
	d := Decision{Allowed: allowed, Limit: p.Burst, RetryAfter: ceilMs(retry)}
	if consume {
		e.idleNs = max(e.tat-now, 0)
	}
	// After consuming, the backlog includes this request; for a peek it is
	// the current backlog (the state a following request would see).
	d.Remaining = int(max((capNs-backlog)/unit, 0))
	d.ResetAfter = ceilMs(time.Duration(backlog))
	if shape && allowed {
		d.Delay = ceilMs(time.Duration(wait))
	}
	return d
}
