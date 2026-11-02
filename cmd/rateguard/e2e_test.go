package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

type adminClient struct {
	t    *testing.T
	base string
	hc   *http.Client
	csrf string
}

func (c *adminClient) do(method, path string, body any, want int) map[string]any {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		c.t.Fatalf("%s %s: status %d want %d: %s", method, path, resp.StatusCode, want, raw)
	}
	out := map[string]any{}
	if len(raw) > 0 && raw[0] == '{' {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

// TestEndToEnd boots the real binary wiring (memory engine, file store),
// configures it purely through the admin API the way the dashboard does,
// and drives traffic through the data plane and the check API.
func TestEndToEnd(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Consumer", r.Header.Get("X-RateGuard-Consumer"))
		io.WriteString(w, "upstream:"+r.URL.Path)
	}))
	defer upstream.Close()

	cfg := config{
		Listen: freeAddr(t), AdminListen: freeAddr(t), DataDir: t.TempDir(),
		Engine: "memory", Store: "file", AdminPassword: "e2e-Password-123!", LogCapacity: 1000,
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), ready) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("run exited early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for listeners")
	}
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	}()

	jar, _ := cookiejar.New(nil)
	ac := &adminClient{t: t, base: "http://" + cfg.AdminListen, hc: &http.Client{Jar: jar, Timeout: 5 * time.Second}}

	// Unauthenticated admin access is rejected.
	ac.do("GET", "/api/policies", nil, http.StatusUnauthorized)

	login := ac.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": cfg.AdminPassword}, http.StatusOK)
	ac.csrf, _ = login["csrf_token"].(string)
	if ac.csrf == "" {
		t.Fatal("no csrf token from login")
	}

	ac.do("POST", "/api/policies", map[string]any{
		"id": "e2e-limit", "name": "E2E limit", "algorithm": "fixed_window", "limit": 3, "window": "1m",
		"key_by": []string{"consumer"}, "mode": "enforce", "fail_mode": "closed", "enabled": true,
	}, http.StatusCreated)
	ac.do("POST", "/api/routes", map[string]any{
		"id": "e2e-route", "name": "E2E route", "match": map[string]any{"path_prefix": "/svc"},
		"upstream": upstream.URL, "strip_prefix": true, "policy_ids": []string{"e2e-limit"},
		"require_api_key": true, "enabled": true,
	}, http.StatusCreated)
	ac.do("POST", "/api/consumers", map[string]any{"id": "cust-1", "name": "Customer One"}, http.StatusCreated)
	issued := ac.do("POST", "/api/consumers/cust-1/keys", map[string]any{"name": "e2e"}, http.StatusCreated)
	apiKey, _ := issued["key"].(string)
	if !strings.HasPrefix(apiKey, "rlg_live_") {
		t.Fatalf("unexpected issued key: %v", issued)
	}

	data := "http://" + cfg.Listen
	get := func(path, key string) *http.Response {
		req, _ := http.NewRequest("GET", data+path, nil)
		if key != "" {
			req.Header.Set("X-API-Key", key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}

	if r := get("/svc/orders", ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing key: got %d want 401", r.StatusCode)
	}
	if r := get("/svc/orders", "rlg_live_bogus"); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad key: got %d want 401", r.StatusCode)
	}
	for i := 0; i < 3; i++ {
		r := get("/svc/orders", apiKey)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("request %d: got %d want 200", i, r.StatusCode)
		}
		if got := r.Header.Get("X-Upstream-Consumer"); got != "cust-1" {
			t.Fatalf("upstream saw consumer %q", got)
		}
	}
	r := get("/svc/orders", apiKey)
	if r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") == "" || r.Header.Get("RateLimit-Limit") != "3" {
		t.Fatalf("4th request: status %d headers %v", r.StatusCode, r.Header)
	}

	// Decision API with a check-scoped token.
	tok := ac.do("POST", "/api/tokens", map[string]any{"name": "svc", "scopes": []string{"check"}}, http.StatusCreated)
	token, _ := tok["token"].(string)
	body, _ := json.Marshal(map[string]any{"route_id": "e2e-route", "method": "GET", "path": "/svc/x", "api_key": apiKey})
	req, _ := http.NewRequest("POST", data+"/_rlg/v1/check", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var chk map[string]any
	json.NewDecoder(resp.Body).Decode(&chk)
	resp.Body.Close()
	if resp.StatusCode != 200 || chk["allowed"] != false || chk["decision"] != "limited" {
		t.Fatalf("check API: %d %v", resp.StatusCode, chk)
	}
	// The same endpoint rejects an unauthenticated caller.
	req, _ = http.NewRequest("POST", data+"/_rlg/v1/check", bytes.NewReader(body))
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("check API without token: %d", resp.StatusCode)
	}

	// Limits reset via admin frees the bucket.
	ac.do("POST", "/api/limits/reset", map[string]any{"policy_id": "e2e-limit", "key": "cust-1"}, http.StatusOK)
	if r := get("/svc/orders", apiKey); r.StatusCode != http.StatusOK {
		t.Fatalf("after reset: got %d want 200", r.StatusCode)
	}

	// Request logs captured, with no plaintext key anywhere.
	logsReq, _ := http.NewRequest("GET", ac.base+"/api/logs?limit=50", nil)
	lr, err := ac.hc.Do(logsReq)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(lr.Body)
	lr.Body.Close()
	if !strings.Contains(string(raw), `"decision":"limited"`) {
		t.Fatalf("logs missing limited entry: %s", raw)
	}
	if strings.Contains(string(raw), apiKey) {
		t.Fatal("plaintext API key leaked into logs")
	}
}
