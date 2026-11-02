package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ratelimitergateway/internal/model"
)

const demoUpstreamAddr = "127.0.0.1:9090"

// demoSnapshot seeds a realistic starter configuration: tiered plans, a
// few policies covering different algorithms, and two consumers with keys.
// The plaintext demo keys are written once to <dataDir>/demo-keys.txt (0600)
// rather than logged, so they never reach log aggregation. Production keys
// are issued from the dashboard.
func demoSnapshot(log *slog.Logger, dataDir string) (*model.Snapshot, error) {
	var keyLines []string
	now := time.Now().UTC()
	s := model.NewSnapshot()
	dur := func(d time.Duration) model.Duration { return model.Duration(d) }
	pol := func(id, name, desc string, a model.Algorithm, limit int, w time.Duration, burst int, keyBy ...string) model.Policy {
		return model.Policy{ID: id, Name: name, Description: desc, Algorithm: a, Limit: limit, Window: dur(w), Burst: burst,
			KeyBy: keyBy, Mode: model.ModeEnforce, FailMode: model.FailOpen, Enabled: true, CreatedAt: now, UpdatedAt: now}
	}
	s.Policies = []model.Policy{
		pol("per-consumer", "Per-consumer rate", "Smooth per-customer rate with short bursts", model.AlgoTokenBucket, 60, time.Minute, 20, "consumer"),
		pol("per-ip-strict", "Anonymous IP limit", "Hard cap for unauthenticated traffic", model.AlgoSlidingWindowCounter, 30, time.Minute, 0, "ip"),
		pol("login-bruteforce", "Login brute-force guard", "5 attempts per minute per IP on auth endpoints", model.AlgoSlidingWindow, 5, time.Minute, 0, "ip", "path"),
		pol("global-ceiling", "Global ceiling", "Protects the upstream from total overload", model.AlgoFixedWindow, 5000, time.Second, 0, "global"),
		pol("concurrent-exports", "Concurrent exports", "At most 2 in-flight export jobs per customer", model.AlgoConcurrency, 2, 0, 0, "consumer"),
	}
	shadow := pol("new-limit-trial", "Proposed tighter limit (shadow)", "Dry-run of a stricter limit: logged, never enforced", model.AlgoTokenBucket, 20, time.Minute, 5, "consumer")
	shadow.Mode = model.ModeShadow
	s.Policies = append(s.Policies, shadow)

	up := "http://" + demoUpstreamAddr
	route := func(id, name, prefix string, prio int, auth bool, pols ...string) model.Route {
		return model.Route{ID: id, Name: name, Match: model.RouteMatch{PathPrefix: prefix}, Upstream: up,
			PolicyIDs: pols, RequireAPIKey: auth, Priority: prio, Enabled: true, CreatedAt: now, UpdatedAt: now}
	}
	s.Routes = []model.Route{
		route("auth", "Auth endpoints", "/auth", 20, false, "login-bruteforce"),
		route("exports", "Data exports", "/api/exports", 10, true, "per-consumer", "concurrent-exports"),
		route("api", "Public API", "/api", 5, true, "per-consumer", "new-limit-trial"),
		route("public", "Public pages", "/", 0, false, "per-ip-strict"),
	}
	s.Settings.GlobalPolicyIDs = []string{"global-ceiling"}
	s.Settings.ExposeDecision = true

	s.Plans = []model.Plan{
		{ID: "free", Name: "Free", Description: "Hobby tier", Overrides: map[string]model.LimitOverride{"per-consumer": {Limit: 60, Burst: 10}}, CreatedAt: now, UpdatedAt: now},
		{ID: "pro", Name: "Pro", Description: "Production tier", Overrides: map[string]model.LimitOverride{"per-consumer": {Limit: 600, Burst: 100}}, CreatedAt: now, UpdatedAt: now},
		{ID: "enterprise", Name: "Enterprise", Description: "Custom contracts", Overrides: map[string]model.LimitOverride{"per-consumer": {Limit: 6000, Burst: 1000}, "concurrent-exports": {Limit: 10}}, CreatedAt: now, UpdatedAt: now},
	}

	for _, c := range []struct{ id, name, plan string }{
		{"acme", "Acme Corp", "pro"}, {"globex", "Globex (trial)", "free"},
	} {
		key, err := demoKey()
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(key))
		s.Consumers = append(s.Consumers, model.Consumer{
			ID: c.id, Name: c.name, PlanID: c.plan, Metadata: map[string]string{"source": "demo"},
			Keys:      []model.APIKey{{ID: "key-" + c.id, Prefix: key[:12], Hash: hex.EncodeToString(sum[:]), Name: "demo", CreatedAt: now}},
			CreatedAt: now, UpdatedAt: now,
		})
		keyLines = append(keyLines, c.name+" ("+c.plan+"): "+key)
	}
	path := filepath.Join(dataDir, "demo-keys.txt")
	if err := os.WriteFile(path, []byte(strings.Join(keyLines, "\n")+"\n"), 0o600); err != nil {
		return nil, err
	}
	log.Warn("demo mode: API keys written (keep private)", "file", path)
	return s, nil
}

func demoKey() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b[i] = alphabet[n.Int64()]
	}
	return "rlg_live_" + string(b), nil
}

// startDemoUpstream runs a tiny echo backend so the demo works standalone.
func startDemoUpstream(ctx context.Context, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/exports" || len(r.URL.Path) > 12 && r.URL.Path[:12] == "/api/exports" {
			time.Sleep(300 * time.Millisecond) // simulate a slow job for the concurrency demo
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message":  "hello from the demo upstream",
			"path":     r.URL.Path,
			"consumer": r.Header.Get("X-RateGuard-Consumer"),
			"time":     time.Now().UTC(),
		})
	})
	srv := &http.Server{Addr: demoUpstreamAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	log.Info("demo upstream listening", "addr", demoUpstreamAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("demo upstream failed", "error", err)
	}
}
