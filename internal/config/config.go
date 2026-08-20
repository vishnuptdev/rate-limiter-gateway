// Package config loads gateway configuration from environment variables,
// with sensible defaults documented in README.md.
package config

import (
	"os"
	"strconv"
	"time"
)

type Strategy string

const (
	StrategyTokenBucket   Strategy = "token_bucket"
	StrategySlidingWindow Strategy = "sliding_window"
)

type Backend string

const (
	BackendMemory Backend = "memory"
	BackendRedis  Backend = "redis"
)

type Config struct {
	Port           string
	BackendURL     string // dummy upstream the proxy forwards to
	Strategy       Strategy
	LimiterBackend Backend
	RedisAddr      string

	// Token bucket params
	Rate  float64
	Burst int

	// Sliding window params
	Limit  int
	Window time.Duration
}

func Load() Config {
	return Config{
		Port:           getenv("RLG_PORT", "8080"),
		BackendURL:     getenv("RLG_BACKEND_URL", "http://127.0.0.1:9090"),
		Strategy:       Strategy(getenv("RLG_STRATEGY", string(StrategyTokenBucket))),
		LimiterBackend: Backend(getenv("RLG_LIMITER_BACKEND", string(BackendMemory))),
		RedisAddr:      getenv("RLG_REDIS_ADDR", "127.0.0.1:6379"),
		Rate:           getenvFloat("RLG_RATE", 5),
		Burst:          getenvInt("RLG_BURST", 10),
		Limit:          getenvInt("RLG_LIMIT", 10),
		Window:         getenvDuration("RLG_WINDOW", 10*time.Second),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
