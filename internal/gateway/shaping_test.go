package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/ratelimit"
)

type shapeEnv struct {
	g    *Gateway
	mem  *ratelimit.Memory
	rec  *recorder
	hits *atomic.Int64
}

func newShapeEnv(t *testing.T, policies ...model.Policy) *shapeEnv {
	t.Helper()
	var hits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	t.Cleanup(up.Close)
	mem := ratelimit.NewMemory(ratelimit.MemoryOptions{})
	t.Cleanup(func() { mem.Close() })
	e := &shapeEnv{mem: mem, rec: &recorder{}, hits: &hits}
	e.g = New(Options{Engine: mem, Recorder: e.rec, Tokens: tokens{"chk": "check"}})
	s := model.NewSnapshot()
	s.Version = 1
	ids := make([]string, 0, len(policies))
	for _, p := range policies {
		ids = append(ids, p.ID)
	}
	s.Policies = policies
	s.Routes = []model.Route{route("r", up.URL, "/", ids...)}
	if err := e.g.Apply(s); err != nil {
		t.Fatal(err)
	}
	return e
}

func leaky(id string, limit int, window time.Duration, burst int) model.Policy {
	p := pol(id, model.AlgoLeakyBucket, limit, "global")
	p.Window, p.Burst = model.Duration(window), burst
	return p
}

func (e *shapeEnv) get(ctx context.Context) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/x", nil).WithContext(ctx)
	r.RemoteAddr = "192.0.2.10:5555"
	rr := httptest.NewRecorder()
	e.g.ServeHTTP(rr, r)
	return rr
}

func TestLeakyBucketGatewayDelaysThenRejects(t *testing.T) {
	e := newShapeEnv(t, leaky("lb", 10, time.Second, 3)) // 1 per 100ms, queue of 3
	start := time.Now()
	for i := 0; i < 3; i++ {
		if rr := e.get(context.Background()); rr.Code != 200 {
			t.Fatalf("request %d: %d", i, rr.Code)
		}
	}
	// Sequential requests: the 2nd waits ~100ms and the 3rd queues behind
	// it, so shaping adds at least ~200ms in total.
	if el := time.Since(start); el < 180*time.Millisecond {
		t.Fatalf("requests were not delayed: %v", el)
	}
	// Fill the queue concurrently so the next one overflows.
	for i := 0; i < 3; i++ {
		go e.get(context.Background())
	}
	time.Sleep(50 * time.Millisecond)
	rr := e.get(context.Background())
	if rr.Code != 429 {
		t.Fatalf("full queue should 429, got %d", rr.Code)
	}
}

func TestLeakyBucketClientAbortWhileQueued(t *testing.T) {
	conc := pol("conc", model.AlgoConcurrency, 5, "global")
	e := newShapeEnv(t, conc, leaky("lb", 1, 10*time.Second, 4)) // 10s per slot
	if rr := e.get(context.Background()); rr.Code != 200 {
		t.Fatalf("first: %d", rr.Code)
	}
	before := e.hits.Load()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- e.get(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return after client abort")
	}
	if e.hits.Load() != before {
		t.Fatal("aborted request must not be proxied")
	}
	le := e.rec.last(t)
	if le.Decision != model.DecisionError || le.Error != "client_closed" {
		t.Fatalf("log entry: %+v", le)
	}
	// The concurrency slot taken before the wait must have been released.
	d, _, _ := e.mem.Peek(context.Background(), e.g.EngineKey("conc", "global"), ratelimit.Params{Algorithm: model.AlgoConcurrency, Limit: 5})
	if d.Remaining != 5 {
		t.Fatalf("concurrency slot leaked: %+v", d)
	}
}

func TestShapingDelayNeverReleasesEarly(t *testing.T) {
	mk := func(delay time.Duration) *outcome {
		return &outcome{results: []polResult{{
			cp: &cpolicy{mode: model.ModeEnforce}, called: true,
			params: ratelimit.Params{Window: time.Second}, dec: ratelimit.Decision{Allowed: true, Delay: delay},
		}, {
			cp: &cpolicy{mode: model.ModeShadow}, called: true,
			params: ratelimit.Params{Window: time.Hour}, dec: ratelimit.Decision{Allowed: true, Delay: time.Hour},
		}}}
	}
	// Delay beyond the policy window is honoured (burst > limit), shadow ignored.
	if d, _, tooLong := mk(5 * time.Second).shapingDelay(); d != 5*time.Second || tooLong {
		t.Fatalf("delay %v tooLong=%v", d, tooLong)
	}
	if _, src, tooLong := mk(31 * time.Second).shapingDelay(); src == nil || !tooLong {
		t.Fatal("delay above the hard ceiling must be denied, not clamped")
	}
}

func TestShapingQueueFullAndDeniedBeyondCeiling(t *testing.T) {
	e := newShapeEnv(t, leaky("lb", 1, 10*time.Second, 4)) // 10s per slot
	e.g.maxShapeWaiters = 2
	if rr := e.get(context.Background()); rr.Code != 200 { // first: no delay
		t.Fatalf("first: %d", rr.Code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); e.get(ctx) }()
	}
	deadline := time.Now().Add(2 * time.Second)
	for e.g.shapeWaiters.Load() != 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	rr := e.get(context.Background())
	if rr.Code != 429 || rr.Header().Get("Retry-After") != "1" || rr.Header().Get("RateLimit-Limit") != "4" {
		t.Fatalf("waiter cap: %d %v", rr.Code, rr.Header())
	}
	body := jsonBody(t, rr)
	if body["policy"] != "Policy lb" || body["retry_after_s"] != float64(1) || body["remaining"] != float64(0) || body["limit"] != float64(4) {
		t.Fatalf("429 body: %v", body)
	}
	// The rejection must not have consumed: backlog is exactly the 3 admitted requests.
	d, _, _ := e.mem.Peek(context.Background(), e.g.EngineKey("lb", "global"), ratelimit.Params{Algorithm: model.AlgoLeakyBucket, Limit: 1, Window: 10 * time.Second, Burst: 4})
	if d.Delay < 29*time.Second || d.Delay > 30*time.Second {
		t.Fatalf("phantom backlog after queue-full rejection: delay %v want ~30s", d.Delay)
	}
	if le := e.rec.last(t); le.Error != "shaping_queue_full" {
		t.Fatalf("log: %+v", le)
	}
	cancel()
	wg.Wait()
	if n := e.g.shapeWaiters.Load(); n != 0 {
		t.Fatalf("waiter counter leaked: %d", n)
	}
}

func TestCheckAPIReportsDelayMs(t *testing.T) {
	e := newShapeEnv(t, leaky("lb", 10, time.Second, 3))
	var delays []float64
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("POST", "/_rlg/v1/check", strings.NewReader(`{"route_id":"r"}`))
		r.Header.Set("Authorization", "Bearer chk")
		rr := httptest.NewRecorder()
		e.g.ServeHTTP(rr, r)
		m := jsonBody(t, rr)
		if m["allowed"] != true {
			t.Fatalf("call %d: %v", i, m)
		}
		delays = append(delays, m["delay_ms"].(float64))
	}
	if delays[0] != 0 || delays[1] < 50 || delays[1] > 100 || delays[2] < 150 || delays[2] > 200 {
		t.Fatalf("delay_ms = %v", delays)
	}
	if e.hits.Load() != 0 {
		t.Fatal("check API must not proxy")
	}
}

type delayEngine struct {
	*ratelimit.Memory
	delay time.Duration
}

func (d delayEngine) Allow(ctx context.Context, key string, p ratelimit.Params) (ratelimit.Decision, error) {
	dec, err := d.Memory.Allow(ctx, key, p)
	if dec.Allowed && p.Algorithm == model.AlgoLeakyBucket {
		dec.Delay = d.delay
	}
	return dec, err
}

func TestShapingCeilingDeniesProxyAndCheck(t *testing.T) {
	e := newShapeEnv(t, leaky("lb", 10, time.Second, 3))
	e.g.engine = delayEngine{e.mem, 31 * time.Second}
	rr := e.get(context.Background())
	if rr.Code != 429 || rr.Header().Get("Retry-After") == "" || rr.Header().Get("RateLimit-Limit") != "3" {
		t.Fatalf("proxy: %d %v", rr.Code, rr.Header())
	}
	if e.hits.Load() != 0 {
		t.Fatal("must not proxy")
	}
	if le := e.rec.last(t); le.Decision != model.DecisionLimited || le.Error != "shaping_delay_too_long" {
		t.Fatalf("log: %+v", le)
	}
	if n := e.g.shapeWaiters.Load(); n != 0 {
		t.Fatalf("reservation leaked: %d", n)
	}
	r := httptest.NewRequest("POST", "/_rlg/v1/check", strings.NewReader(`{"route_id":"r"}`))
	r.Header.Set("Authorization", "Bearer chk")
	crr := httptest.NewRecorder()
	e.g.ServeHTTP(crr, r)
	m := jsonBody(t, crr)
	if m["allowed"] != false || m["decision"] != model.DecisionLimited || m["retry_after_s"].(float64) < 1 {
		t.Fatalf("check: %v", m)
	}
}
