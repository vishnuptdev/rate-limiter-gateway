package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
	e := newShapeEnv(t, conc, leaky("lb", 1, 10*time.Second, 3)) // 10s per slot
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

func TestLeakyBucketWaitCappedAtWindow(t *testing.T) {
	o := &outcome{results: []polResult{{
		cp: &cpolicy{mode: model.ModeEnforce}, called: true,
		params: ratelimit.Params{Window: time.Second}, dec: ratelimit.Decision{Allowed: true, Delay: time.Minute},
	}, {
		cp: &cpolicy{mode: model.ModeShadow}, called: true,
		params: ratelimit.Params{Window: time.Hour}, dec: ratelimit.Decision{Allowed: true, Delay: time.Hour},
	}}}
	if d := o.shapingDelay(); d != time.Second {
		t.Fatalf("delay %v want 1s (capped, shadow ignored)", d)
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
