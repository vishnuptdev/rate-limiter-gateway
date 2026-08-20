// Command gateway starts the rate-limited reverse-proxy gateway along with
// a dummy upstream backend (so the whole thing is runnable standalone for
// a demo -- see README.md).
package main

import (
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"ratelimitergateway/internal/config"
	"ratelimitergateway/internal/limiter"
	"ratelimitergateway/internal/proxy"
	"ratelimitergateway/internal/redisclient"
)

func startDummyBackend(addr string, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "hello from the dummy upstream backend",
			"path":    r.URL.Path,
			"time":    time.Now().UTC(),
		})
	})
	go func() {
		log.Info("dummy backend listening", "addr", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Error("dummy backend failed", "error", err)
		}
	}()
}

func buildLimiter(cfg config.Config) limiter.Limiter {
	switch cfg.LimiterBackend {
	case config.BackendRedis:
		rc := redisclient.New(cfg.RedisAddr, 16)
		if err := rc.Ping(); err != nil {
			log.Fatalf("RLG_LIMITER_BACKEND=redis but could not reach Redis at %s: %v", cfg.RedisAddr, err)
		}
		if cfg.Strategy == config.StrategySlidingWindow {
			return limiter.NewRedisSlidingWindow(rc, cfg.Limit, cfg.Window, "rlg:sw:")
		}
		return limiter.NewRedisTokenBucket(rc, cfg.Rate, cfg.Burst, "rlg:tb:")
	default:
		if cfg.Strategy == config.StrategySlidingWindow {
			return limiter.NewSlidingWindow(cfg.Limit, cfg.Window)
		}
		return limiter.NewTokenBucket(cfg.Rate, cfg.Burst)
	}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg := config.Load()

	startDummyBackend("127.0.0.1:9090", logger)

	lim := buildLimiter(cfg)
	logger.Info("rate limiter configured", "strategy", cfg.Strategy, "backend", cfg.LimiterBackend)

	gw, err := proxy.NewGateway(cfg.BackendURL, lim, logger)
	if err != nil {
		log.Fatalf("could not build gateway: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics/usage", gw.MetricsHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/", gw.Handler)

	logger.Info("gateway listening", "port", cfg.Port, "backend_url", cfg.BackendURL)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Fatalf("gateway failed: %v", err)
	}
}
