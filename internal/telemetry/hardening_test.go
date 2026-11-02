package telemetry

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
)

// SA9: a dashboard log search over a full ring must not stall Record (the
// data plane's hot path) for the duration of the scan.
func TestQueryLogsDoesNotBlockRecord(t *testing.T) {
	h := NewHub(Options{})
	long := "/" + strings.Repeat("a", 511)
	key := strings.Repeat("a", 64)
	for i := 0; i < defaultLogCapacity; i++ {
		h.Record(model.LogEntry{Path: long, RateKey: key, ClientIP: "1.2.3.4", Decision: model.DecisionAllowed, Status: 200})
	}
	// Worst case for the substring scan: almost matches everywhere, never
	// matches, so every entry is fully scanned and nothing is returned.
	q := model.LogQuery{Search: strings.Repeat("a", 8) + "b", Limit: 1000}

	// How long one full search takes on this machine.
	st := time.Now()
	if got := h.QueryLogs(q); len(got) != 0 {
		t.Fatalf("unexpected matches: %d", len(got))
	}
	scan := time.Since(st)

	var stop atomic.Bool
	var wg sync.WaitGroup
	var searches atomic.Int64
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				h.QueryLogs(q)
				searches.Add(1)
			}
		}()
	}
	time.Sleep(10 * time.Millisecond)
	const n = 200
	lat := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		s := time.Now()
		h.Record(model.LogEntry{Path: "/x", Decision: model.DecisionAllowed, Status: 200})
		lat = append(lat, time.Since(s))
		time.Sleep(200 * time.Microsecond)
	}
	stop.Store(true)
	wg.Wait()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p90 := lat[n*9/10]
	t.Logf("full search %v; %d searches ran; Record p50=%v p90=%v max=%v", scan, searches.Load(), lat[n/2], p90, lat[n-1])
	if p90 > time.Millisecond {
		t.Fatalf("Record p90 latency %v during searches (one search takes %v): the scan holds the hub lock", p90, scan)
	}
}

// The chunked scan must still return exactly the right entries, newest
// first, while Record keeps overwriting the ring underneath it.
func TestQueryLogsConsistentUnderConcurrentRecord(t *testing.T) {
	h := NewHub(Options{LogCapacity: 1000})
	for i := 0; i < 1000; i++ {
		h.Record(model.LogEntry{Path: fmt.Sprintf("/p/%d", i), Decision: model.DecisionAllowed, Status: 200})
	}
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; !stop.Load(); i++ {
			h.Record(model.LogEntry{Path: fmt.Sprintf("/w/%d", i), Decision: model.DecisionLimited, Status: 429})
		}
	}()
	for k := 0; k < 50; k++ {
		got := h.QueryLogs(model.LogQuery{Limit: 1000})
		for i := 1; i < len(got); i++ {
			if got[i-1].ID <= got[i].ID {
				t.Fatalf("not newest-first at %d: %s then %s", i, got[i-1].ID, got[i].ID)
			}
		}
		for _, e := range h.QueryLogs(model.LogQuery{Decision: model.DecisionAllowed, Limit: 1000}) {
			if !strings.HasPrefix(e.Path, "/p/") {
				t.Fatalf("filter returned %+v", e)
			}
		}
	}
	stop.Store(true)
	<-done
}
