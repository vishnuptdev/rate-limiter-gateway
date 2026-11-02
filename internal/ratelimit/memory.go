package ratelimit

import (
	"context"
	"hash/fnv"
	"log/slog"
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
// Bounded memory: at most MaxKeys keys are tracked. When full, a request
// for a new key is still decided (against a fresh, untracked bucket, i.e.
// it is allowed unless Cost exceeds the limit) but leaves no state, and a
// warning is logged once. A background goroutine removes keys idle for
// more than twice their window every GCInterval (token buckets: more than
// max(2*window, time-to-full)).
//
// The exact sliding-window log keeps one record per accepted request in
// the trailing window, so its memory is O(Limit) per key by definition.
type Memory struct {
	shards  [numShards]shard
	now     func() time.Time
	maxKeys int64
	keys    atomic.Int64
	full    sync.Once
	log     *slog.Logger

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
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

	// sliding window log
	log []logRec

	// sliding window counter / fixed window
	winIdx int64
	curr   int
	prev   int

	// concurrency
	inflight int
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

func (m *Memory) Name() string                      { return "memory" }
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
			if now-e.lastSeen > e.idleNs && e.inflight == 0 {
				delete(s.m, k)
				m.keys.Add(-1)
				removed++
			}
		}
		s.mu.Unlock()
	}
	return removed
}

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
			m.full.Do(func() {
				m.log.Warn("ratelimit: memory engine key cap reached; new keys are allowed but untracked", "max_keys", m.maxKeys)
			})
			// Decide against a fresh bucket, store nothing.
			return e.eval(p, now, true), nil
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
	if e := s.m[storeKey(p.Algorithm, key)]; e != nil && e.inflight > 0 {
		e.inflight--
		e.lastSeen = m.now().UnixNano()
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

func (e *entry) concurrency(p Params, now int64, consume bool) Decision {
	allowed := p.Cost <= p.Limit && e.inflight+p.Cost <= p.Limit
	n := e.inflight
	if allowed && consume {
		e.inflight += p.Cost
		n = e.inflight
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
