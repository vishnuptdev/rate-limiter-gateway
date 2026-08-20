package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ratelimitergateway/internal/limiter"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestGateway_ForwardsWithinLimit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream ok"))
	}))
	defer backend.Close()

	lim := limiter.NewTokenBucket(10, 5)
	gw, err := NewGateway(backend.URL, lim, testLogger())
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "test-key")
	rec := httptest.NewRecorder()
	gw.Handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "upstream ok" {
		t.Fatalf("expected forwarded upstream body, got %q", rec.Body.String())
	}
}

func TestGateway_RejectsMissingAPIKey(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	lim := limiter.NewTokenBucket(10, 5)
	gw, _ := NewGateway(backend.URL, lim, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	gw.Handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing API key, got %d", rec.Code)
	}
}

// TestGateway_429WithRetryAfter is the core requirement: exceeding the
// limit must yield 429 with a proper Retry-After header, and the backend
// must NOT be hit once the limit is exceeded.
func TestGateway_429WithRetryAfter(t *testing.T) {
	backendHits := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits++
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	lim := limiter.NewTokenBucket(1, 2) // burst of 2, slow refill
	gw, _ := NewGateway(backend.URL, lim, testLogger())

	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", "limited-key")
		rec := httptest.NewRecorder()
		gw.Handler(rec, req)
		return rec
	}

	r1, r2 := do(), do()
	if r1.Code != http.StatusOK || r2.Code != http.StatusOK {
		t.Fatalf("expected first two requests (within burst) to succeed, got %d and %d", r1.Code, r2.Code)
	}

	r3 := do()
	if r3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on third request (burst exhausted), got %d", r3.Code)
	}
	retryAfter := r3.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("expected a Retry-After header on 429 response")
	}

	var body map[string]interface{}
	if err := json.Unmarshal(r3.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected JSON body on 429, got %q: %v", r3.Body.String(), err)
	}
	if body["error"] != "rate limit exceeded" {
		t.Fatalf("unexpected error body: %v", body)
	}

	if backendHits != 2 {
		t.Fatalf("expected backend to be hit exactly twice (denied requests must not reach it), got %d", backendHits)
	}
}

func TestGateway_MetricsUsageEndpoint(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	lim := limiter.NewTokenBucket(5, 5)
	gw, _ := NewGateway(backend.URL, lim, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "metrics-key")
	gw.Handler(httptest.NewRecorder(), req)

	mreq := httptest.NewRequest(http.MethodGet, "/metrics/usage?key=metrics-key", nil)
	mrec := httptest.NewRecorder()
	gw.MetricsHandler(mrec, mreq)

	var body map[string]interface{}
	if err := json.Unmarshal(mrec.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if body["remaining"].(float64) != 4 {
		t.Fatalf("expected remaining=4 after one request against burst=5, got %v", body["remaining"])
	}

	allReq := httptest.NewRequest(http.MethodGet, "/metrics/usage", nil)
	allRec := httptest.NewRecorder()
	gw.MetricsHandler(allRec, allReq)
	var allBody map[string]interface{}
	json.Unmarshal(allRec.Body.Bytes(), &allBody)
	keys := allBody["keys"].([]interface{})
	if len(keys) != 1 {
		t.Fatalf("expected 1 known key, got %d", len(keys))
	}
}

var _ = time.Second
