//go:build ignore

// Package rateguardmw is a net/http middleware that asks RateGuard's check API
// for a decision before the wrapped handler runs. Standard library only.
//
// This file carries the build tag "ignore" so the RateGuard module does not
// compile it. Copy it into your own module (remove the build line) and use it:
//
//	mw := rateguardmw.New(rateguardmw.Config{
//		BaseURL: "http://rateguard:8080",
//		Token:   os.Getenv("RATEGUARD_TOKEN"), // API token with scope "check"
//	})
//	http.Handle("/api/", mw.Wrap(apiHandler))
//
// Behaviour:
//   - Allowed: decision headers (RateLimit-*) are set and the handler runs.
//   - Denied: 429 with Retry-After and the decision details.
//   - Shaping: when a leaky_bucket policy answers with delay_ms > 0, the
//     request is held that long before the handler runs.
//   - Fail-open: if RateGuard errors or does not answer within Timeout (50 ms
//     by default), the request continues and a warning is logged.
package rateguardmw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Config configures the middleware.
type Config struct {
	BaseURL      string        // RateGuard data plane, e.g. http://rateguard:8080
	Token        string        // API token with scope "check" (rgt_...)
	APIKeyHeader string        // inbound header carrying the consumer key; default X-API-Key
	Timeout      time.Duration // per-check deadline; default 50ms; fail open beyond it
	Client       *http.Client  // optional; a default client is used if nil
}

// Middleware calls RateGuard's check API for each request.
type Middleware struct {
	cfg    Config
	client *http.Client
}

// New returns a Middleware with defaults applied.
func New(cfg Config) *Middleware {
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.APIKeyHeader == "" {
		cfg.APIKeyHeader = "X-API-Key"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 50 * time.Millisecond
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{}
	}
	return &Middleware{cfg: cfg, client: client}
}

// checkRequest is the body of POST /_rlg/v1/check.
type checkRequest struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Host   string `json:"host"`
	APIKey string `json:"api_key,omitempty"`
	IP     string `json:"ip,omitempty"`
	Cost   int    `json:"cost"`
}

// checkResponse is the subset of the check API response this middleware uses.
type checkResponse struct {
	Allowed     bool              `json:"allowed"`
	Decision    string            `json:"decision"`
	PolicyID    string            `json:"policy_id"`
	Limit       int               `json:"limit"`
	Remaining   int               `json:"remaining"`
	ResetS      int               `json:"reset_s"`
	RetryAfterS int               `json:"retry_after_s"`
	DelayMs     int64             `json:"delay_ms"`
	Headers     map[string]string `json:"headers"`
}

func (m *Middleware) check(parent context.Context, r *http.Request) (*checkResponse, error) {
	ctx, cancel := context.WithTimeout(parent, m.cfg.Timeout)
	defer cancel()

	body, err := json.Marshal(checkRequest{
		Method: r.Method,
		Path:   r.URL.Path,
		Host:   hostOnly(r.Host),
		APIKey: r.Header.Get(m.cfg.APIKeyHeader),
		IP:     remoteIP(r),
		Cost:   1,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.cfg.BaseURL+"/_rlg/v1/check", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.cfg.Token)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("check API returned HTTP %d", resp.StatusCode)
	}
	var out checkResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Wrap returns a handler that enforces the RateGuard decision before next runs.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, err := m.check(r.Context(), r)
		if err != nil {
			log.Printf("rateguard: check failed, failing open: %v", err)
			next.ServeHTTP(w, r)
			return
		}

		for k, v := range d.Headers {
			w.Header().Set(k, v)
		}

		if !d.Allowed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":         "rate_limited",
				"message":       "Rate limit exceeded",
				"policy":        d.PolicyID,
				"limit":         d.Limit,
				"remaining":     d.Remaining,
				"retry_after_s": d.RetryAfterS,
				"reset_s":       d.ResetS,
			})
			return
		}

		if d.DelayMs > 0 { // leaky-bucket shaping: hold the request
			t := time.NewTimer(time.Duration(d.DelayMs) * time.Millisecond)
			select {
			case <-t.C:
			case <-r.Context().Done():
				t.Stop()
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// hostOnly strips the port from a Host header value.
func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// remoteIP returns the peer address. If the app sits behind a proxy, replace this
// with the client address from your trusted X-Forwarded-For handling.
func remoteIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
