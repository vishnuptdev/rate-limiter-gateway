// Command rateguard runs the RateGuard rate-limiting gateway: the data plane
// (reverse proxy + decision API) and the admin plane (REST API + embedded
// dashboard) in a single, dependency-free binary.
//
// Configuration is via environment variables; see README.md.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ratelimitergateway/internal/admin"
	"ratelimitergateway/internal/dashboard"
	"ratelimitergateway/internal/gateway"
	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/ratelimit"
	"ratelimitergateway/internal/redisclient"
	"ratelimitergateway/internal/store"
	"ratelimitergateway/internal/telemetry"
)

// version is overridden at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

type config struct {
	Listen, AdminListen, DataDir string
	Engine, Store                string
	RedisAddr, RedisPassword     string
	RedisDB                      int
	RedisTLS                     bool
	AdminPassword                string
	CookieSecure, MetricsPublic  bool
	TLSCert, TLSKey              string
	Demo                         bool
	LogLevel                     string
	TrustProxyHeaders            bool
	LogCapacity                  int
	MaxShapingWaiters            int
}

func loadConfig() config {
	return config{
		Listen:            env("RLG_LISTEN", ":8080"),
		AdminListen:       env("RLG_ADMIN_LISTEN", ":9000"),
		DataDir:           env("RLG_DATA_DIR", "./data"),
		Engine:            env("RLG_ENGINE", "memory"),
		Store:             env("RLG_STORE", "file"),
		RedisAddr:         env("RLG_REDIS_ADDR", "127.0.0.1:6379"),
		RedisPassword:     os.Getenv("RLG_REDIS_PASSWORD"),
		RedisDB:           envInt("RLG_REDIS_DB", 0),
		RedisTLS:          envBool("RLG_REDIS_TLS"),
		AdminPassword:     os.Getenv("RLG_ADMIN_PASSWORD"),
		CookieSecure:      envBool("RLG_COOKIE_SECURE"),
		MetricsPublic:     envBool("RLG_METRICS_PUBLIC"),
		TLSCert:           os.Getenv("RLG_TLS_CERT"),
		TLSKey:            os.Getenv("RLG_TLS_KEY"),
		Demo:              envBool("RLG_DEMO"),
		LogLevel:          env("RLG_LOG_LEVEL", "info"),
		TrustProxyHeaders: envBool("RLG_ADMIN_TRUST_PROXY"),
		LogCapacity:       envInt("RLG_LOG_CAPACITY", 10000),
		MaxShapingWaiters: envInt("RLG_MAX_SHAPING_WAITERS", 10000),
	}
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println("rateguard", version)
		return
	}
	cfg := loadConfig()
	log := newLogger(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, log, nil); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

// run starts both planes and blocks until ctx is cancelled or a listener
// fails. ready, if non-nil, is closed once both listeners are bound (tests).
func run(ctx context.Context, cfg config, log *slog.Logger, ready chan<- struct{}) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	var rc *redisclient.Client
	if cfg.Engine == "redis" || cfg.Store == "redis" {
		rc = redisclient.NewClient(redisclient.Options{
			Addr: cfg.RedisAddr, Password: cfg.RedisPassword, DB: cfg.RedisDB, TLS: cfg.RedisTLS, PoolSize: 64,
		})
		defer rc.Close()
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := rc.PingContext(pctx)
		cancel()
		if err != nil {
			return fmt.Errorf("redis %s unreachable: %w", cfg.RedisAddr, err)
		}
	}

	var engine ratelimit.Engine
	switch cfg.Engine {
	case "memory":
		engine = ratelimit.NewMemory(ratelimit.MemoryOptions{Logger: log})
	case "redis":
		engine = ratelimit.NewRedis(rc, "rateguard:rl:")
	default:
		return fmt.Errorf("RLG_ENGINE must be memory or redis, got %q", cfg.Engine)
	}
	defer engine.Close()

	var cs store.ConfigStore
	switch cfg.Store {
	case "file":
		f, err := store.NewFile(cfg.DataDir)
		if err != nil {
			return err
		}
		cs = f
	case "redis":
		cs = store.NewRedis(rc)
	default:
		return fmt.Errorf("RLG_STORE must be file or redis, got %q", cfg.Store)
	}

	hub := telemetry.NewHub(telemetry.Options{LogCapacity: cfg.LogCapacity})

	snap, err := cs.Load(ctx)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if snap == nil {
		snap = model.NewSnapshot()
		if cfg.Demo {
			snap, err = demoSnapshot(log, cfg.DataDir)
			if err != nil {
				return err
			}
		}
		snap.Version = 1
		snap.UpdatedAt = time.Now().UTC()
		if err := cs.Save(ctx, snap); err != nil {
			return fmt.Errorf("save initial config: %w", err)
		}
	}

	instanceID := randomID()
	// The gateway needs the admin token verifier and the admin server needs
	// the gateway as its runtime; break the cycle with a late-bound verifier.
	tokens := &lateVerifier{}
	gw := gateway.New(gateway.Options{Engine: engine, Recorder: hub, Tokens: tokens, Logger: log, MaxShapingWaiters: cfg.MaxShapingWaiters})
	if err := gw.Apply(snap); err != nil {
		return fmt.Errorf("stored config is invalid: %w", err)
	}

	adm, err := admin.New(admin.Options{
		DataDir: cfg.DataDir, Store: cs, Runtime: gw, Telemetry: hub, Engine: engine,
		StaticFS: dashboard.FS, Logger: log, Version: version, InstanceID: instanceID,
		DataPlaneAddr: cfg.Listen, AdminAddr: cfg.AdminListen,
		CookieSecure: cfg.CookieSecure || cfg.TLSCert != "", MetricsPublic: cfg.MetricsPublic,
		BootstrapPassword: cfg.AdminPassword, Validate: store.Validate,
		TrustProxyHeaders: cfg.TrustProxyHeaders,
	})
	if err != nil {
		return fmt.Errorf("admin: %w", err)
	}
	tokens.v = adm.Tokens()
	adm.Start(ctx)

	if cfg.Demo {
		go startDemoUpstream(ctx, log)
	}

	dataSrv := &http.Server{
		Addr: cfg.Listen, Handler: gw,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second,
		WriteTimeout: 120 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 1 << 20,
	}
	adminSrv := &http.Server{
		Addr: cfg.AdminListen, Handler: adm.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		// WriteTimeout 0: the live-log SSE stream is long-lived; the admin
		// handler bounds every other response itself.
		IdleTimeout: 120 * time.Second, MaxHeaderBytes: 1 << 20,
	}

	dataLn, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("data plane listen: %w", err)
	}
	adminLn, err := net.Listen("tcp", cfg.AdminListen)
	if err != nil {
		dataLn.Close()
		return fmt.Errorf("admin listen: %w", err)
	}
	errc := make(chan error, 2)
	go func() {
		log.Info("data plane listening", "addr", dataLn.Addr().String(), "engine", engine.Name(), "store", cs.Name())
		errc <- serve(dataSrv, dataLn, "", "")
	}()
	go func() {
		log.Info("admin dashboard listening", "addr", adminLn.Addr().String(), "tls", cfg.TLSCert != "")
		errc <- serve(adminSrv, adminLn, cfg.TLSCert, cfg.TLSKey)
	}()
	if ready != nil {
		close(ready)
	}

	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil {
			return err
		}
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = dataSrv.Shutdown(sctx)
	_ = adminSrv.Shutdown(sctx)
	return nil
}

func serve(s *http.Server, ln net.Listener, cert, key string) error {
	var err error
	if cert != "" {
		err = s.ServeTLS(ln, cert, key)
	} else {
		err = s.Serve(ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type lateVerifier struct{ v admin.TokenVerifier }

func (l *lateVerifier) Verify(token, scope string) bool {
	return l.v != nil && l.v.Verify(token, scope)
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
}

func randomID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return n
	}
	return def
}

func envBool(k string) bool {
	b, _ := strconv.ParseBool(os.Getenv(k))
	return b
}
