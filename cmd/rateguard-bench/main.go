// Command rateguard-bench is a loopback load test for the RateGuard data
// plane. It starts an upstream HTTP server and a real gateway (memory or
// Redis engine, telemetry hub attached, wired like cmd/rateguard) on
// 127.0.0.1, then fires -c concurrent keep-alive clients for -d at:
//
//	direct  the upstream, bypassing RateGuard (baseline)
//	proxy   the same upstream through RateGuard (one token-bucket policy)
//	auth    the forward-auth endpoint /_rlg/v1/auth (no upstream hop)
//
// and prints RPS and latency percentiles, plus the latency RateGuard adds
// over the direct baseline. Everything (load generator, gateway, upstream)
// shares this machine's CPUs, so absolute numbers are a lower bound on what
// a dedicated gateway host achieves.
//
//	go run ./cmd/rateguard-bench -c 64 -d 10s
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"ratelimitergateway/internal/gateway"
	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/ratelimit"
	"ratelimitergateway/internal/redisclient"
	"ratelimitergateway/internal/telemetry"
)

const apiKey = "rlg_live_loadtest000000000000000000000"

func main() {
	conc := flag.Int("c", 64, "concurrent clients")
	dur := flag.Duration("d", 10*time.Second, "duration per scenario")
	warm := flag.Duration("warmup", time.Second, "warm-up per scenario (not measured)")
	engineName := flag.String("engine", "memory", "memory or redis")
	redisAddr := flag.String("redis", "127.0.0.1:6379", "redis address (engine=redis)")
	sample := flag.Float64("sample", 1, "log_sample_allowed (fraction of allowed requests logged)")
	only := flag.String("only", "", "run a single scenario: direct, proxy or auth")
	flag.Parse()

	fmt.Printf("rateguard-bench: GOMAXPROCS=%d NumCPU=%d %s/%s %s engine=%s clients=%d duration=%s sample=%g\n",
		runtime.GOMAXPROCS(0), runtime.NumCPU(), runtime.GOOS, runtime.GOARCH, runtime.Version(), *engineName, *conc, *dur, *sample)

	upURL, stopUp := startUpstream()
	defer stopUp()

	var eng ratelimit.Engine
	switch *engineName {
	case "memory":
		eng = ratelimit.NewMemory(ratelimit.MemoryOptions{})
	case "redis":
		rc := redisclient.NewClient(redisclient.Options{Addr: *redisAddr, PoolSize: 64})
		if err := rc.Ping(); err != nil {
			fmt.Fprintln(os.Stderr, "redis:", err)
			os.Exit(1)
		}
		defer rc.Close()
		eng = ratelimit.NewRedis(rc, fmt.Sprintf("rgbench:%d:", time.Now().UnixNano()))
	default:
		fmt.Fprintln(os.Stderr, "-engine must be memory or redis")
		os.Exit(2)
	}
	defer eng.Close()

	hub := telemetry.NewHub(telemetry.Options{})
	gw := gateway.New(gateway.Options{Engine: eng, Recorder: hub, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	s := model.NewSnapshot()
	s.Version = 1
	s.Settings.LogSampleAllowed = *sample
	s.Policies = []model.Policy{{
		ID: "per-consumer", Name: "Per consumer", Algorithm: model.AlgoTokenBucket, Limit: 1_000_000_000,
		Window: model.Duration(time.Second), KeyBy: []string{"consumer"}, Mode: model.ModeEnforce,
		FailMode: model.FailOpen, Enabled: true,
	}}
	s.Consumers = []model.Consumer{{ID: "load", Name: "Load test", Keys: []model.APIKey{{ID: "k1", Prefix: apiKey[:8], Hash: hashKey(apiKey)}}}}
	s.Routes = []model.Route{{ID: "api", Name: "API", Match: model.RouteMatch{PathPrefix: "/api"}, Upstream: upURL,
		PolicyIDs: []string{"per-consumer"}, RequireAPIKey: true, Enabled: true}}
	if err := gw.Apply(s); err != nil {
		fmt.Fprintln(os.Stderr, "apply:", err)
		os.Exit(1)
	}
	gwURL, stopGw := serve(gw)
	defer stopGw()

	type scenario struct {
		name, url string
		hdr       map[string]string
	}
	scenarios := []scenario{
		{"direct", upURL + "/api/items", nil},
		{"proxy", gwURL + "/api/items", map[string]string{"X-API-Key": apiKey}},
		{"auth", gwURL + "/_rlg/v1/auth", map[string]string{"X-API-Key": apiKey, "X-Forwarded-Method": "GET", "X-Forwarded-Uri": "/api/items"}},
	}
	results := map[string]result{}
	for _, sc := range scenarios {
		if *only != "" && *only != sc.name {
			continue
		}
		run(sc.url, sc.hdr, *conc, *warm) // warm-up
		res := run(sc.url, sc.hdr, *conc, *dur)
		results[sc.name] = res
		fmt.Printf("%-7s rps=%9.0f  p50=%7.1fµs  p95=%7.1fµs  p99=%7.1fµs  max=%8.1fµs  n=%d errors=%d\n",
			sc.name, res.rps, us(res.p50), us(res.p95), us(res.p99), us(res.max), res.n, res.errors)
	}
	if d, ok := results["direct"]; ok {
		if p, ok := results["proxy"]; ok {
			fmt.Printf("added by RateGuard (proxy - direct): p50=%.1fµs p95=%.1fµs p99=%.1fµs  throughput %.0f%% of direct\n",
				us(p.p50-d.p50), us(p.p95-d.p95), us(p.p99-d.p99), 100*p.rps/d.rps)
		}
	}
}

func hashKey(k string) string {
	s := sha256.Sum256([]byte(k))
	return hex.EncodeToString(s[:])
}

func us(d time.Duration) float64 { return float64(d) / float64(time.Microsecond) }

func startUpstream() (string, func()) {
	body := []byte("ok\n")
	return serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.Write(body)
	}))
}

func serve(h http.Handler) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	go srv.Serve(ln)
	return "http://" + ln.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}
}

type result struct {
	n, errors          int
	rps                float64
	p50, p95, p99, max time.Duration
}

func run(url string, hdr map[string]string, conc int, d time.Duration) result {
	tr := &http.Transport{MaxIdleConns: conc * 2, MaxIdleConnsPerHost: conc * 2, IdleConnTimeout: 90 * time.Second, DisableCompression: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	var stop atomic.Bool
	var errs atomic.Int64
	lats := make([][]time.Duration, conc)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			own := make([]time.Duration, 0, 1<<16)
			req, _ := http.NewRequest("GET", url, nil)
			for k, v := range hdr {
				req.Header.Set(k, v)
			}
			for !stop.Load() {
				t0 := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					errs.Add(1)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				el := time.Since(t0)
				if resp.StatusCode != http.StatusOK {
					errs.Add(1)
					continue
				}
				own = append(own, el)
			}
			lats[i] = own
		}(i)
	}
	time.Sleep(d)
	stop.Store(true)
	wg.Wait()
	elapsed := time.Since(start)
	var all []time.Duration
	for _, l := range lats {
		all = append(all, l...)
	}
	slices.Sort(all)
	res := result{n: len(all), errors: int(errs.Load()), rps: float64(len(all)) / elapsed.Seconds()}
	if len(all) > 0 {
		pct := func(p float64) time.Duration { return all[min(len(all)-1, int(p*float64(len(all))))] }
		res.p50, res.p95, res.p99, res.max = pct(0.50), pct(0.95), pct(0.99), all[len(all)-1]
	}
	return res
}
