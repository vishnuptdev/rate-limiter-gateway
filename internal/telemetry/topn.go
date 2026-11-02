package telemetry

import (
	"sort"
	"time"

	"ratelimitergateway/internal/model"
)

const (
	topMapCap     = 10000 // max distinct keys per map generation
	topN          = 10
	topGeneration = 12 * time.Hour
)

type entry struct {
	count int64
	label string
}

// capMap is a counter map with a hard key cap. When a new key arrives at the
// cap, every key tied for the lowest count is evicted first (so at least one
// slot frees up; with the usual "many singletons" flood the whole singleton
// tail goes at once, which keeps eviction amortised O(1) per insert).
type capMap struct {
	m   map[string]*entry
	cap int
}

func newCapMap(capacity int) *capMap {
	return &capMap{m: make(map[string]*entry), cap: capacity}
}

// add increments key by d and returns the new count.
func (c *capMap) add(key, label string, d int64) int64 {
	e := c.m[key]
	if e == nil {
		if len(c.m) >= c.cap {
			c.evictLowest()
		}
		e = &entry{}
		c.m[key] = e
	}
	e.count += d
	if label != "" {
		e.label = label
	}
	return e.count
}

func (c *capMap) get(key string) int64 {
	if e := c.m[key]; e != nil {
		return e.count
	}
	return 0
}

func (c *capMap) evictLowest() {
	first := true
	var min int64
	for _, e := range c.m {
		if first || e.count < min {
			min, first = e.count, false
		}
	}
	for k, e := range c.m {
		if e.count <= min {
			delete(c.m, k)
		}
	}
}

// topMap is a two-generation top-N counter used for the 24h overview. Counts
// accumulate in cur; every 12h cur becomes prev and a fresh cur starts, and
// prev is discarded at the next rotation. Reads merge cur+prev, so the
// result covers between 12h and 24h of history (APPROXIMATION: the window
// is not exactly 24h; right after a rotation it is ~12h, just before the
// next one ~24h). After 24h without traffic everything is dropped.
type topMap struct {
	cur, prev *capMap
	genStart  time.Time
}

func newTopMap(now time.Time) *topMap {
	return &topMap{cur: newCapMap(topMapCap), prev: newCapMap(topMapCap), genStart: now}
}

func (t *topMap) rotate(now time.Time) {
	el := now.Sub(t.genStart)
	switch {
	case el < topGeneration:
		return
	case el < 2*topGeneration:
		t.prev, t.cur = t.cur, t.prev
		t.cur.m = make(map[string]*entry)
		t.genStart = t.genStart.Add(topGeneration)
	default:
		t.prev.m = make(map[string]*entry)
		t.cur.m = make(map[string]*entry)
		t.genStart = now
	}
}

func (t *topMap) add(key, label string) { t.cur.add(key, label, 1) }

// top returns the n largest entries across both generations.
func (t *topMap) top(n int) []model.Counted {
	merged := make(map[string]*entry, len(t.cur.m)+len(t.prev.m))
	for _, g := range []*capMap{t.prev, t.cur} { // cur last so its label wins
		for k, e := range g.m {
			m := merged[k]
			if m == nil {
				m = &entry{}
				merged[k] = m
			}
			m.count += e.count
			if e.label != "" {
				m.label = e.label
			}
		}
	}
	out := make([]model.Counted, 0, len(merged))
	for k, e := range merged {
		l := e.label
		if l == "" {
			l = k
		}
		out = append(out, model.Counted{ID: k, Label: l, Count: e.count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
