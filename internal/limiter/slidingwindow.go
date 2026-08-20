package limiter

import (
	"sync"
	"time"
)

// SlidingWindow is an in-process sliding-window-log limiter: it remembers
// the timestamp of every allowed request in the trailing `window` and
// permits at most `limit` requests inside that window per key.
type SlidingWindow struct {
	limit  int
	window time.Duration
	mu     sync.Mutex
	hits   map[string][]time.Time
	now    func() time.Time
}

func NewSlidingWindow(limit int, window time.Duration) *SlidingWindow {
	return &SlidingWindow{limit: limit, window: window, hits: make(map[string][]time.Time), now: time.Now}
}

func (s *SlidingWindow) Allow(key string) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	cutoff := now.Add(-s.window)
	hits := s.hits[key]

	// Prune expired entries from the front (hits is append-only-then-pruned,
	// so it stays roughly time-ordered).
	i := 0
	for i < len(hits) && hits[i].Before(cutoff) {
		i++
	}
	hits = hits[i:]

	if len(hits) >= s.limit {
		retryAfter := hits[0].Add(s.window).Sub(now)
		if retryAfter < 0 {
			retryAfter = 0
		}
		s.hits[key] = hits
		return Result{Allowed: false, Remaining: 0, RetryAfter: retryAfter}, nil
	}

	hits = append(hits, now)
	s.hits[key] = hits
	return Result{Allowed: true, Remaining: s.limit - len(hits)}, nil
}

func (s *SlidingWindow) Usage(key string) (remaining int, limit int, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hits, exists := s.hits[key]
	if !exists {
		return s.limit, s.limit, false
	}
	cutoff := s.now().Add(-s.window)
	count := 0
	for _, h := range hits {
		if !h.Before(cutoff) {
			count++
		}
	}
	rem := s.limit - count
	if rem < 0 {
		rem = 0
	}
	return rem, s.limit, true
}
