// Package proxy implements the gateway's HTTP surface: a rate-limiting
// middleware in front of a reverse proxy to an upstream backend, plus a
// usage-metrics endpoint.
package proxy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"ratelimitergateway/internal/limiter"
)

// Gateway wires a Limiter to a reverse proxy and tracks which API keys
// have been seen, so /metrics/usage can enumerate them.
type Gateway struct {
	Limiter limiter.Limiter
	proxy   *httputil.ReverseProxy
	log     *slog.Logger

	mu       sync.Mutex
	seenKeys map[string]bool
}

func NewGateway(backendURL string, lim limiter.Limiter, log *slog.Logger) (*Gateway, error) {
	target, err := url.Parse(backendURL)
	if err != nil {
		return nil, fmt.Errorf("invalid backend URL: %w", err)
	}
	return &Gateway{
		Limiter:  lim,
		proxy:    httputil.NewSingleHostReverseProxy(target),
		log:      log,
		seenKeys: make(map[string]bool),
	}, nil
}

// apiKey extracts the caller's identity for rate-limiting purposes from
// the X-API-Key header. A missing key is rejected outright -- an
// unauthenticated caller should not be able to consume an anonymous
// shared bucket that legitimate keys depend on.
func apiKey(r *http.Request) string {
	return r.Header.Get("X-API-Key")
}

// Handler is the main proxy entrypoint: check the rate limit, then either
// forward to the backend or respond 429 with a Retry-After header.
func (g *Gateway) Handler(w http.ResponseWriter, r *http.Request) {
	key := apiKey(r)
	if key == "" {
		http.Error(w, `{"error":"missing X-API-Key header"}`, http.StatusBadRequest)
		return
	}

	g.mu.Lock()
	g.seenKeys[key] = true
	g.mu.Unlock()

	res, err := g.Limiter.Allow(key)
	if err != nil {
		g.log.Error("limiter error", "error", err, "key", key)
		http.Error(w, `{"error":"rate limiter unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	if !res.Allowed {
		retrySeconds := int(math.Ceil(res.RetryAfter.Seconds()))
		if retrySeconds < 1 {
			retrySeconds = 1
		}
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retrySeconds))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":               "rate limit exceeded",
			"retry_after_seconds": retrySeconds,
		})
		g.log.Info("rate_limited", "key", key, "retry_after_s", retrySeconds)
		return
	}

	w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", res.Remaining))
	g.proxy.ServeHTTP(w, r)
}

type usageEntry struct {
	Key       string `json:"key"`
	Remaining int    `json:"remaining"`
	Limit     int    `json:"limit"`
}

// MetricsHandler handles GET /metrics/usage[?key=...]: with a key,
// returns that key's current usage; without one, lists every key seen
// since startup.
func (g *Gateway) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if key := r.URL.Query().Get("key"); key != "" {
		remaining, limit, ok := g.Limiter.Usage(key)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"key": key, "remaining": remaining, "limit": limit, "known": ok,
		})
		return
	}

	g.mu.Lock()
	keys := make([]string, 0, len(g.seenKeys))
	for k := range g.seenKeys {
		keys = append(keys, k)
	}
	g.mu.Unlock()

	entries := make([]usageEntry, 0, len(keys))
	for _, k := range keys {
		remaining, limit, _ := g.Limiter.Usage(k)
		entries = append(entries, usageEntry{Key: k, Remaining: remaining, Limit: limit})
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"keys": entries, "generated_at": time.Now().UTC()})
}
