package telemetry

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	// Aligned to a 5-minute boundary so step arithmetic in tests is exact.
	return &fakeClock{t: time.Unix(1_800_000_000, 0).UTC()}
}
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestHub(capacity int) (*Hub, *fakeClock) {
	c := newClock()
	return NewHub(Options{LogCapacity: capacity, Now: c.Now}), c
}

func ent(route, decision string, status int, latMs float64) model.LogEntry {
	return model.LogEntry{RouteID: route, RouteName: "name-" + route, Decision: decision, Status: status, LatencyMs: latMs, Method: "GET", Path: "/p", ClientIP: "1.2.3.4", Source: "proxy"}
}

func TestRingWrapAndIDs(t *testing.T) {
	h, _ := newTestHub(5)
	for i := 0; i < 12; i++ {
		e := ent("r", model.DecisionAllowed, 200, 1)
		e.Path = fmt.Sprintf("/%d", i)
		h.Record(e)
	}
	if h.LogLen() != 5 {
		t.Fatalf("len=%d", h.LogLen())
	}
	got := h.QueryLogs(model.LogQuery{})
	if len(got) != 5 {
		t.Fatalf("got %d", len(got))
	}
	for i, e := range got {
		if want := fmt.Sprintf("/%d", 11-i); e.Path != want {
			t.Errorf("pos %d: %s want %s", i, e.Path, want)
		}
		if i > 0 && !(got[i-1].ID > e.ID) {
			t.Errorf("IDs not strictly descending: %s %s", got[i-1].ID, e.ID)
		}
		if len(e.ID) != 28 {
			t.Errorf("id len %d", len(e.ID))
		}
	}
}

func TestIDKeptAndTimeFilled(t *testing.T) {
	h, c := newTestHub(10)
	e := ent("r", model.DecisionAllowed, 200, 1)
	e.ID = "custom"
	h.Record(e)
	h.Record(ent("r", model.DecisionAllowed, 200, 1))
	got := h.QueryLogs(model.LogQuery{})
	if got[1].ID != "custom" || got[0].ID == "" {
		t.Fatalf("ids: %q %q", got[0].ID, got[1].ID)
	}
	if !got[0].Time.Equal(c.Now()) {
		t.Fatalf("time not filled")
	}
}

func TestIDsSortAcrossRestart(t *testing.T) {
	c := newClock()
	h1 := NewHub(Options{Now: c.Now})
	h1.Record(ent("r", "allowed", 200, 1))
	c.Advance(time.Second)
	h2 := NewHub(Options{Now: c.Now})
	h2.Record(ent("r", "allowed", 200, 1))
	if !(h1.QueryLogs(model.LogQuery{})[0].ID < h2.QueryLogs(model.LogQuery{})[0].ID) {
		t.Fatal("restart IDs must sort after earlier ones")
	}
}

func TestQueryFiltersAndCursor(t *testing.T) {
	h, c := newTestHub(2000)
	for i := 0; i < 300; i++ {
		e := ent("r"+strconv.Itoa(i%3), model.DecisionAllowed, 200, 1)
		e.ConsumerID = "c" + strconv.Itoa(i%2)
		e.ConsumerName = "Acme" + strconv.Itoa(i%2)
		e.PolicyID = "p1"
		e.RateKey = "key-" + strconv.Itoa(i%5)
		if i%10 == 0 {
			e.Decision, e.Status = model.DecisionLimited, 429
		}
		if i == 7 {
			e.Path = "/Special/Thing"
		}
		h.Record(e)
		if i == 149 {
			c.Advance(time.Hour)
		}
	}
	cases := []struct {
		name string
		q    model.LogQuery
		want int
	}{
		{"all default limit", model.LogQuery{}, 100},
		{"limit cap", model.LogQuery{Limit: 5000}, 300},
		{"decision", model.LogQuery{Decision: model.DecisionLimited, Limit: 1000}, 30},
		{"route", model.LogQuery{RouteID: "r1", Limit: 1000}, 100},
		{"consumer", model.LogQuery{ConsumerID: "c0", Limit: 1000}, 150},
		{"policy", model.LogQuery{PolicyID: "p1", Limit: 1000}, 300},
		{"policy none", model.LogQuery{PolicyID: "zz"}, 0},
		{"status min", model.LogQuery{StatusMin: 400, Limit: 1000}, 30},
		{"status max", model.LogQuery{StatusMax: 399, Limit: 1000}, 270},
		{"status range", model.LogQuery{StatusMin: 429, StatusMax: 429, Limit: 1000}, 30},
		{"search path ci", model.LogQuery{Search: "special/THING"}, 1},
		{"search ip", model.LogQuery{Search: "1.2.3", Limit: 1000}, 300},
		{"search rate key", model.LogQuery{Search: "KEY-3", Limit: 1000}, 60},
		{"search consumer name", model.LogQuery{Search: "acme1", Limit: 1000}, 150},
		{"since", model.LogQuery{Since: c.Now().Add(-30 * time.Minute), Limit: 1000}, 150},
		{"combined", model.LogQuery{RouteID: "r0", Decision: model.DecisionLimited, Limit: 1000}, 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(h.QueryLogs(tc.q)); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}

	// Cursor pagination walks everything exactly once, newest first.
	seen := map[string]bool{}
	before := ""
	prev := ""
	for pages := 0; pages < 10; pages++ {
		page := h.QueryLogs(model.LogQuery{Before: before, Limit: 70})
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			if seen[e.ID] {
				t.Fatalf("dup %s", e.ID)
			}
			if prev != "" && e.ID >= prev {
				t.Fatalf("order broken")
			}
			seen[e.ID] = true
			prev = e.ID
		}
		before = page[len(page)-1].ID
	}
	if len(seen) != 300 {
		t.Fatalf("saw %d", len(seen))
	}
}

func TestTruncation(t *testing.T) {
	h, _ := newTestHub(3)
	e := ent("r", "allowed", 200, 1)
	e.Path = strings.Repeat("a", 5000)
	e.UserAgent = strings.Repeat("u", 5000)
	e.Error = strings.Repeat("e", 5000)
	h.Record(e)
	g := h.QueryLogs(model.LogQuery{})[0]
	if len(g.Path) != maxPathLen || len(g.UserAgent) != maxUALen || len(g.Error) != maxErrLen {
		t.Fatal("not truncated")
	}
}

func TestSubscribeDropPolicy(t *testing.T) {
	h, _ := newTestHub(100)
	ch, cancel := h.Subscribe(2)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ { // nobody reads: must not block
			e := ent("r", "allowed", 200, 1)
			e.Path = strconv.Itoa(i)
			h.Record(e)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked on slow subscriber")
	}
	if len(ch) != 2 {
		t.Fatalf("buffered %d", len(ch))
	}
	if a, b := (<-ch).Path, (<-ch).Path; a != "0" || b != "1" {
		t.Fatalf("expected oldest kept, got %s %s", a, b)
	}
	if h.SubscriberDrops() != 48 {
		t.Fatalf("drops=%d", h.SubscriberDrops())
	}
	// A fast subscriber still receives while the slow one drops.
	fast, cancelFast := h.Subscribe(10)
	h.Record(ent("r", "allowed", 200, 1))
	select {
	case <-fast:
	default:
		t.Fatal("fast subscriber got nothing")
	}
	cancelFast()
	cancel()
	cancel() // idempotent
	if _, ok := <-fast; ok {
		t.Fatal("channel should be closed")
	}
	h.Record(ent("r", "allowed", 200, 1)) // no panic after cancel
}

func TestSubscriberCap(t *testing.T) {
	h, _ := newTestHub(10)
	var cancels []func()
	for i := 0; i < maxSubscribers; i++ {
		_, c := h.Subscribe(1)
		cancels = append(cancels, c)
	}
	ch, c := h.Subscribe(1)
	if _, ok := <-ch; ok {
		t.Fatal("over-cap subscription should be closed")
	}
	c()
	for _, c := range cancels {
		c()
	}
	ch, c = h.Subscribe(1)
	defer c()
	h.Record(ent("r", "allowed", 200, 1))
	if len(ch) != 1 {
		t.Fatal("slot should be reusable")
	}
}

func TestTimeseriesStepsAndGapFill(t *testing.T) {
	h, c := newTestHub(100)
	cases := []struct {
		rng   time.Duration
		step  int
		n     int
		snapT time.Duration
	}{
		{15 * time.Minute, 5, 180, 0},
		{time.Hour, 15, 240, 0},
		{6 * time.Hour, 60, 360, 0},
		{24 * time.Hour, 300, 288, 0},
		{time.Minute, 5, 180, 0},    // snaps to 15m
		{2 * time.Hour, 15, 240, 0}, // closer to 1h than 6h
		{4 * time.Hour, 60, 360, 0}, // closer to 6h
		{100 * time.Hour, 300, 288, 0} /* snaps to 24h */}
	for _, tc := range cases {
		ts := h.Timeseries(tc.rng, "")
		if ts.StepSeconds != tc.step || len(ts.Points) != tc.n {
			t.Errorf("rng %v: step=%d n=%d", tc.rng, ts.StepSeconds, len(ts.Points))
		}
		for i := 1; i < len(ts.Points); i++ {
			if d := ts.Points[i].T.Sub(ts.Points[i-1].T); d != time.Duration(tc.step)*time.Second {
				t.Fatalf("rng %v: gap %v", tc.rng, d)
			}
		}
		last := ts.Points[len(ts.Points)-1].T
		if now := c.Now(); last.After(now) || now.Sub(last) >= time.Duration(tc.step)*time.Second {
			t.Errorf("rng %v: last point %v vs now %v", tc.rng, last, now)
		}
		for _, p := range ts.Points {
			if p.Allowed != 0 || p.P99Ms != 0 {
				t.Fatal("empty hub must be all zero")
			}
		}
	}

	// Data: 3 requests at t0, none for 20s, 2 at t0+20s. Gap filled with zeros.
	h.Record(ent("r", model.DecisionAllowed, 200, 10))
	h.Record(ent("r", model.DecisionLimited, 429, 10))
	h.Record(ent("r", model.DecisionUnauthorized, 401, 10))
	c.Advance(20 * time.Second)
	h.Record(ent("r", model.DecisionAllowed, 200, 10))
	h.Record(ent("r", model.DecisionShadowLimited, 200, 10))
	ts := h.Timeseries(15*time.Minute, "")
	n := len(ts.Points)
	p := ts.Points
	if p[n-1].Allowed != 1 || p[n-1].ShadowLimited != 1 {
		t.Errorf("last: %+v", p[n-1])
	}
	if p[n-5].Allowed != 1 || p[n-5].Limited != 1 || p[n-5].Errors != 1 {
		t.Errorf("t0: %+v", p[n-5])
	}
	for _, i := range []int{n - 2, n - 3, n - 4, n - 6} {
		if p[i].Allowed+p[i].Limited+p[i].Errors != 0 {
			t.Errorf("gap %d not zero", i)
		}
	}
	if p[n-1].P50Ms <= 0 {
		t.Error("p50 missing")
	}

	// 1h/15s aggregates three 5s buckets: t0 .. t0+20s => points [t0,t0+15) and [t0+15,t0+30)
	ts = h.Timeseries(time.Hour, "")
	var allowed, limited int64
	for _, q := range ts.Points {
		allowed += q.Allowed
		limited += q.Limited
	}
	if allowed != 2 || limited != 1 {
		t.Errorf("1h totals allowed=%d limited=%d", allowed, limited)
	}
	nz := 0
	for _, q := range ts.Points {
		if q.Allowed+q.Limited+q.Errors+q.ShadowLimited > 0 {
			nz++
		}
	}
	if nz != 2 {
		t.Errorf("nonzero points=%d", nz)
	}
	// 24h/5m aggregates five 1m buckets.
	ts = h.Timeseries(24*time.Hour, "")
	allowed = 0
	nz = 0
	for _, q := range ts.Points {
		allowed += q.Allowed
		if q.Allowed > 0 {
			nz++
		}
	}
	if allowed != 2 || nz != 1 {
		t.Errorf("24h allowed=%d nz=%d", allowed, nz)
	}

	// Expiry: after 2h the 1h view is empty, 6h and 24h still hold the data.
	c.Advance(2 * time.Hour)
	sum := func(ts model.Timeseries) (s int64) {
		for _, q := range ts.Points {
			s += q.Allowed + q.Limited + q.Errors + q.ShadowLimited
		}
		return
	}
	if sum(h.Timeseries(time.Hour, "")) != 0 {
		t.Error("1h should have expired")
	}
	if sum(h.Timeseries(6*time.Hour, "")) != 5 || sum(h.Timeseries(24*time.Hour, "")) != 5 {
		t.Error("6h/24h should retain")
	}
	c.Advance(23 * time.Hour)
	if sum(h.Timeseries(24*time.Hour, "")) != 0 {
		t.Error("24h should have expired")
	}
}

func TestTimeseriesPerRouteTop50(t *testing.T) {
	h, _ := newTestHub(100)
	for i := 0; i < 50; i++ {
		for j := 0; j < 10; j++ {
			h.Record(ent(fmt.Sprintf("hot%02d", i), model.DecisionAllowed, 200, 1))
		}
	}
	// Ring is full; a cold route does not displace anyone.
	h.Record(ent("cold", model.DecisionAllowed, 200, 1))
	total := func(route string) (s int64) {
		for _, p := range h.Timeseries(15*time.Minute, route).Points {
			s += p.Allowed
		}
		return
	}
	if total("hot07") != 10 {
		t.Errorf("hot07=%d", total("hot07"))
	}
	if total("cold") != 0 {
		t.Errorf("cold route should be zeros, got %d", total("cold"))
	}
	if total("unknown") != 0 {
		t.Error("unknown route should be zeros")
	}
	if total("") != 501 {
		t.Errorf("global=%d", total(""))
	}
	// Once cold becomes busier than the least busy ringed route, it gets a ring.
	for i := 0; i < 20; i++ {
		h.Record(ent("cold", model.DecisionAllowed, 200, 1))
	}
	if got := total("cold"); got == 0 || got > 20 {
		t.Errorf("cold after promotion=%d (history before promotion is not backfilled)", got)
	}
	if len(h.routeSer) != maxRouteRings {
		t.Errorf("rings=%d", len(h.routeSer))
	}
}

func TestPercentileAccuracy(t *testing.T) {
	if histBounds[0] < 0.099 || histBounds[0] > 0.101 || histBounds[histBuckets-1] != histMaxMs {
		t.Fatalf("bounds %v %v", histBounds[0], histBounds[histBuckets-1])
	}
	for i := 1; i < histBuckets; i++ {
		if r := histBounds[i] / histBounds[i-1]; r < 1.3 || r > 1.5 {
			t.Fatalf("ratio %d = %v", i, r)
		}
	}
	h, _ := newTestHub(10)
	// 1..1000 ms uniformly.
	for i := 1; i <= 1000; i++ {
		h.Record(ent("r", model.DecisionAllowed, 200, float64(i)))
	}
	ov := h.Overview()
	for _, tc := range []struct {
		name       string
		got, exact float64
	}{
		{"p50", ov.P50Ms, 500}, {"p95", ov.P95Ms, 950}, {"p99", ov.P99Ms, 990},
	} {
		b := histIndex(tc.exact)
		lo, hi := 0.0, histBounds[b]
		if b > 0 {
			lo = histBounds[b-1]
		}
		if tc.got < lo || tc.got > hi {
			t.Errorf("%s=%v outside the true value's bucket (%v,%v]", tc.name, tc.got, lo, hi)
		}
		if rel := math.Abs(tc.got-tc.exact) / tc.exact; rel > 0.41 {
			t.Errorf("%s=%v rel err %.2f", tc.name, tc.got, rel)
		}
	}
	// Edge values.
	if histIndex(0) != 0 || histIndex(-5) != 0 || histIndex(math.NaN()) != 0 {
		t.Error("low edge")
	}
	if histIndex(60000) != 39 || histIndex(60001) != 40 || histIndex(1e9) != 40 {
		t.Error("high edge")
	}
	var one [histSlots]uint64
	one[histIndex(7)] = 1
	if q := histQuantile(&one, 0.5); histIndex(q) != histIndex(7) {
		t.Errorf("single sample percentile %v", q)
	}
	if histQuantile(&[histSlots]uint64{}, 0.5) != 0 {
		t.Error("empty")
	}
}

func TestOverview(t *testing.T) {
	h, c := newTestHub(100)
	rec := func(route, decision string, status int, consumer, policy, key string, n int) {
		for i := 0; i < n; i++ {
			e := ent(route, decision, status, 5)
			e.ConsumerID, e.ConsumerName, e.PolicyID, e.RateKey = consumer, "Name "+consumer, policy, key
			h.Record(e)
		}
	}
	rec("r1", model.DecisionAllowed, 200, "c1", "", "", 50)
	rec("r1", model.DecisionAllowed, 302, "c1", "", "", 5)
	rec("r2", model.DecisionAllowed, 404, "c2", "", "", 10)
	rec("r2", model.DecisionLimited, 429, "c2", "pA", "k2", 20)
	rec("r3", model.DecisionLimited, 429, "c3", "pB", "k3", 5)
	rec("r3", model.DecisionShadowLimited, 200, "c3", "pB", "k3", 3)
	rec("r3", model.DecisionError, 502, "", "", "", 4)
	rec("", model.DecisionNoRoute, 404, "", "", "", 2)
	rec("", model.DecisionUnauthorized, 401, "", "", "", 1)

	ov := h.Overview()
	if ov.Requests != 100 || ov.Allowed != 65 || ov.Limited != 25 || ov.ShadowLimited != 3 || ov.Errors != 7 {
		t.Errorf("totals %+v", ov)
	}
	sb := map[string]int64{}
	for _, s := range ov.StatusBreakdown {
		sb[s.ID] = s.Count
	}
	// 2xx: 50 + 3 shadow(200) = 53 ; 3xx 5 ; 4xx excl 429: 10+2+2... see below
	if sb["2xx"] != 53 || sb["3xx"] != 5 || sb["4xx"] != 13 || sb["429"] != 25 || sb["5xx"] != 4 || len(ov.StatusBreakdown) != 5 {
		t.Errorf("status %v", sb)
	}
	if ov.StatusBreakdown[0].ID != "2xx" || ov.StatusBreakdown[3].ID != "429" {
		t.Errorf("order %v", ov.StatusBreakdown)
	}
	// top lists
	if r := ov.TopRoutes; len(r) != 3 || r[0].ID != "r1" || r[0].Count != 55 || r[0].Label != "name-r1" || r[1].ID != "r2" {
		t.Errorf("routes %+v", r)
	}
	if p := ov.TopPolicies; len(p) != 2 || p[0].ID != "pA" || p[0].Count != 20 || p[1].Count != 5 {
		t.Errorf("policies %+v", p)
	}
	if k := ov.TopLimitedKeys; len(k) != 2 || k[0].ID != "k2" || k[0].Label != "Name c2" || k[0].Count != 20 {
		t.Errorf("keys %+v", k)
	}
	if cs := ov.TopConsumers; len(cs) != 3 || cs[0].ID != "c1" || cs[0].Count != 55 {
		t.Errorf("consumers %+v", cs)
	}
	if !ov.Since.Equal(c.Now().Add(-24 * time.Hour)) {
		t.Errorf("since %v", ov.Since)
	}
	if ov.P50Ms <= 0 {
		t.Error("p50")
	}
	// RPS: 100 requests within the current second of an exactly aligned
	// clock => divisor is 55s.
	if want := 100.0 / 55.0; math.Abs(ov.RPS1m-want) > 1e-9 {
		t.Errorf("rps=%v want %v", ov.RPS1m, want)
	}
	c.Advance(30 * time.Second)
	if ov = h.Overview(); math.Abs(ov.RPS1m-100.0/85.0) > 0.5 && ov.RPS1m == 0 {
		t.Errorf("rps after 30s=%v", ov.RPS1m)
	}
	c.Advance(2 * time.Minute)
	if ov = h.Overview(); ov.RPS1m != 0 {
		t.Errorf("rps after idle=%v", ov.RPS1m)
	}
	if ov.Requests != 100 {
		t.Errorf("24h totals should persist: %d", ov.Requests)
	}
}

func TestOverviewTopListCapAndLimit(t *testing.T) {
	h, _ := newTestHub(10)
	for i := 0; i < 25; i++ {
		for j := 0; j <= i; j++ {
			h.Record(ent(fmt.Sprintf("route%02d", i), model.DecisionAllowed, 200, 1))
		}
	}
	ov := h.Overview()
	if len(ov.TopRoutes) != 10 || ov.TopRoutes[0].ID != "route24" || ov.TopRoutes[9].ID != "route15" {
		t.Errorf("%+v", ov.TopRoutes)
	}
	// empty hub returns non-nil slices (JSON [] rather than null)
	e, _ := newTestHub(10)
	if o := e.Overview(); o.TopRoutes == nil || o.TopLimitedKeys == nil || o.TopPolicies == nil || o.TopConsumers == nil {
		t.Error("nil top lists")
	}
}

func TestOverviewTopRotation(t *testing.T) {
	h, c := newTestHub(10)
	h.Record(ent("old", model.DecisionAllowed, 200, 1))
	c.Advance(13 * time.Hour)
	h.Record(ent("new", model.DecisionAllowed, 200, 1))
	ov := h.Overview()
	if len(ov.TopRoutes) != 2 {
		t.Fatalf("both generations visible: %+v", ov.TopRoutes)
	}
	c.Advance(12 * time.Hour) // old generation (written at +0h) is now dropped
	ov = h.Overview()
	if len(ov.TopRoutes) != 1 || ov.TopRoutes[0].ID != "new" {
		t.Fatalf("after second rotation: %+v", ov.TopRoutes)
	}
	c.Advance(30 * time.Hour)
	if ov = h.Overview(); len(ov.TopRoutes) != 0 || ov.Requests != 0 {
		t.Fatalf("idle 30h: %+v", ov)
	}
}

func TestCapMapEviction(t *testing.T) {
	m := newCapMap(100)
	for i := 0; i < 50; i++ {
		m.add(fmt.Sprintf("big%d", i), "", 1000)
	}
	for i := 0; i < 10000; i++ {
		m.add(fmt.Sprintf("noise%d", i), "", 1)
		if len(m.m) > 100 {
			t.Fatalf("exceeded cap: %d", len(m.m))
		}
	}
	for i := 0; i < 50; i++ {
		if m.get(fmt.Sprintf("big%d", i)) != 1000 {
			t.Fatalf("heavy key evicted")
		}
	}
}

var promLine = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[a-zA-Z_][a-zA-Z0-9_]*="([^"\\\n]|\\.)*"(,[a-zA-Z_][a-zA-Z0-9_]*="([^"\\\n]|\\.)*")*\})? (-?[0-9.e+-]+|\+Inf|NaN)$`)

// parseProm validates every line and returns samples keyed by the full
// "name{labels}" string.
func parseProm(t *testing.T, text string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	types := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		l := sc.Text()
		if l == "" {
			t.Fatal("blank line")
		}
		if strings.HasPrefix(l, "# TYPE ") {
			f := strings.Fields(l)
			types[f[2]] = f[3]
			continue
		}
		if strings.HasPrefix(l, "# HELP ") {
			continue
		}
		if !promLine.MatchString(l) {
			t.Fatalf("bad line: %q", l)
		}
		i := strings.LastIndexByte(l, ' ')
		v, err := strconv.ParseFloat(l[i+1:], 64)
		if err != nil {
			t.Fatalf("value %q: %v", l, err)
		}
		if _, dup := out[l[:i]]; dup {
			t.Fatalf("duplicate series %q", l[:i])
		}
		out[l[:i]] = v
	}
	for _, n := range []string{"rateguard_requests_total", "rateguard_rate_limited_total", "rateguard_request_duration_seconds", "rateguard_upstream_duration_seconds", "rateguard_log_buffer_entries"} {
		if types[n] == "" {
			t.Errorf("missing TYPE for %s", n)
		}
	}
	if types["rateguard_request_duration_seconds"] != "histogram" || types["rateguard_log_buffer_entries"] != "gauge" || types["rateguard_requests_total"] != "counter" {
		t.Errorf("types %v", types)
	}
	return out
}

func TestPrometheus(t *testing.T) {
	h, _ := newTestHub(10)
	for i := 0; i < 3; i++ {
		e := ent("api", model.DecisionAllowed, 200, 3) // 3ms
		e.UpstreamMs = 2
		h.Record(e)
	}
	e := ent("api", model.DecisionLimited, 429, 0.5)
	e.PolicyID = `p"1\x`
	h.Record(e)
	h.Record(ent("", model.DecisionNoRoute, 404, 20))
	h.Record(ent("api", "weird", 100, 70000))

	var buf bytes.Buffer
	h.WritePrometheus(&buf)
	m := parseProm(t, buf.String())

	want := map[string]float64{
		`rateguard_requests_total{route="api",decision="allowed",status_class="2xx"}`:    3,
		`rateguard_requests_total{route="api",decision="limited",status_class="429"}`:    1,
		`rateguard_requests_total{route="_none",decision="no_route",status_class="4xx"}`: 1,
		`rateguard_requests_total{route="api",decision="other",status_class="other"}`:    1,
		`rateguard_rate_limited_total{policy="p\"1\\x"}`:                                 1,
		`rateguard_request_duration_seconds_bucket{route="api",le="0.001"}`:              1,
		`rateguard_request_duration_seconds_bucket{route="api",le="0.005"}`:              4,
		`rateguard_request_duration_seconds_bucket{route="api",le="10"}`:                 4,
		`rateguard_request_duration_seconds_bucket{route="api",le="+Inf"}`:               5,
		`rateguard_request_duration_seconds_count{route="api"}`:                          5,
		`rateguard_upstream_duration_seconds_count{route="api"}`:                         3,
		`rateguard_upstream_duration_seconds_bucket{route="api",le="0.005"}`:             3,
		`rateguard_log_buffer_entries`:                                                   6,
	}
	for k, v := range want {
		if got, ok := m[k]; !ok || got != v {
			t.Errorf("%s = %v (present=%v), want %v", k, got, ok, v)
		}
	}
	if s := m[`rateguard_request_duration_seconds_sum{route="api"}`]; math.Abs(s-(0.009+0.0005+70)) > 1e-9 {
		t.Errorf("sum=%v", s)
	}
	// histogram buckets are cumulative/monotonic
	var les []string
	for k := range m {
		if strings.HasPrefix(k, `rateguard_request_duration_seconds_bucket{route="api"`) {
			les = append(les, k)
		}
	}
	if len(les) != 13 {
		t.Errorf("bucket lines=%d", len(les))
	}
	// deterministic output
	var buf2 bytes.Buffer
	h.WritePrometheus(&buf2)
	if buf.String() != buf2.String() {
		t.Error("output not deterministic")
	}
	// empty hub still parses
	eh, _ := newTestHub(10)
	var b3 bytes.Buffer
	eh.WritePrometheus(&b3)
	if parseProm(t, b3.String())["rateguard_log_buffer_entries"] != 0 {
		t.Error("empty gauge")
	}
}

func TestPrometheusCardinalityCap(t *testing.T) {
	h, _ := newTestHub(10)
	for i := 0; i < 700; i++ {
		e := ent(fmt.Sprintf("route-%d", i), model.DecisionLimited, 429, 1)
		e.PolicyID = fmt.Sprintf("policy-%d", i)
		h.Record(e)
	}
	var buf bytes.Buffer
	h.WritePrometheus(&buf)
	m := parseProm(t, buf.String())
	routes, pols := map[string]bool{}, map[string]bool{}
	for k := range m {
		if strings.HasPrefix(k, "rateguard_requests_total{") {
			routes[strings.Split(k, `"`)[1]] = true
		}
		if strings.HasPrefix(k, "rateguard_rate_limited_total{") {
			pols[strings.Split(k, `"`)[1]] = true
		}
	}
	if len(routes) != maxLabelValues+1 || !routes[otherLabel] {
		t.Errorf("routes=%d other=%v", len(routes), routes[otherLabel])
	}
	if len(pols) != maxLabelValues+1 || !pols[otherLabel] {
		t.Errorf("policies=%d", len(pols))
	}
	if v := m[`rateguard_requests_total{route="_other",decision="limited",status_class="429"}`]; v != 200 {
		t.Errorf("_other=%v", v)
	}
	// An already admitted label keeps reporting under its own name.
	h.Record(ent("route-3", model.DecisionLimited, 429, 1))
	buf.Reset()
	h.WritePrometheus(&buf)
	m = parseProm(t, buf.String())
	if m[`rateguard_requests_total{route="route-3",decision="limited",status_class="429"}`] != 2 {
		t.Error("admitted label lost")
	}
}

func TestConcurrency(t *testing.T) {
	h := NewHub(Options{LogCapacity: 500})
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 3000; i++ {
				e := ent(fmt.Sprintf("r%d", (g+i)%70), model.DecisionAllowed, 200, float64(i%100))
				if i%7 == 0 {
					e.Decision, e.Status, e.PolicyID, e.RateKey = model.DecisionLimited, 429, "p", "k"
				}
				h.Record(e)
			}
		}(g)
	}
	var rg sync.WaitGroup
	for g := 0; g < 4; g++ {
		rg.Add(1)
		go func(g int) {
			defer rg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				switch g {
				case 0:
					h.QueryLogs(model.LogQuery{Search: "p", Limit: 50})
				case 1:
					h.Timeseries(time.Hour, "r3")
					h.Timeseries(24*time.Hour, "")
				case 2:
					h.Overview()
					h.WritePrometheus(&bytes.Buffer{})
				case 3:
					ch, cancel := h.Subscribe(4)
					select {
					case <-ch:
					default:
					}
					cancel()
				}
			}
		}(g)
	}
	wg.Wait()
	close(stop)
	rg.Wait()
	if ov := h.Overview(); ov.Requests != 8*3000 {
		t.Fatalf("requests=%d", ov.Requests)
	}
	if h.LogLen() != 500 {
		t.Fatalf("len=%d", h.LogLen())
	}
}

func BenchmarkRecord(b *testing.B) {
	h := NewHub(Options{})
	e := model.LogEntry{Method: "GET", Host: "api.example.com", Path: "/v1/items", RouteID: "items", RouteName: "Items",
		ClientIP: "10.0.0.1", ConsumerID: "c1", ConsumerName: "Acme", RateKey: "c1", PolicyID: "p1",
		Decision: model.DecisionAllowed, Status: 200, LatencyMs: 4.2, UpstreamMs: 3.9, Source: "proxy"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Record(e)
	}
}

func BenchmarkRecordParallelWithSubscriber(b *testing.B) {
	h := NewHub(Options{})
	ch, cancel := h.Subscribe(16)
	defer cancel()
	go func() {
		for range ch {
		}
	}()
	e := model.LogEntry{RouteID: "items", Decision: model.DecisionLimited, Status: 429, LatencyMs: 1, PolicyID: "p", RateKey: "k"}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			h.Record(e)
		}
	})
}
