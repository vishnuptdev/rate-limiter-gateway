# RateGuard performance

This document records what RateGuard costs per request, how it was measured,
what was optimised, and how to tune a deployment. Every number below was
measured on the machine described in the next section. None of them is
estimated or carried over from somewhere else. Run the commands in
[Reproducing](#reproducing) to get numbers for your own hardware.

## Test machine

| | |
|---|---|
| CPU | `Intel(R) Xeon(R) Processor @ 2.80GHz`, 4 vCPUs (`nproc` = 4) |
| Virtualisation | Firecracker microVM, shared host |
| OS | Linux 6.18 (amd64) |
| Go | go1.24.7, `GOMAXPROCS=4` |
| Redis | 7.0.15 on the same VM (loopback). `redis-benchmark -c 1 -t ping` gives p50 0.063 ms, about 14.5k req/s for one connection |

**Noise:** this is a shared VM. When the same code was benchmarked again a
few minutes later, results moved by ±10–15%. For example, the telemetry
`Record` benchmark shows about +10% between runs although that code did not
change. Treat a difference smaller than about 15% as noise. Differences in
allocation counts are exact.

## Summary

| What | Before | After |
|---|---|---|
| Gateway proxy path, in process (no network), allocations | 83 allocs, 37.8 KiB | **53 allocs, 5.1 KiB** |
| Gateway proxy path, throughput-normalised (4 goroutines) | 26.9 µs/op | **7.1 µs/op** (−74%) |
| Gateway proxy path, one core (`-cpu 1`) | 22–46 µs/op | **16–18 µs/op** |
| 429 response, in process | 6.3 µs/op, 76 allocs | **4.2 µs/op, 26 allocs** |
| Forward-auth decision, in process | 4.3 µs/op, 54 allocs | **3.3 µs/op, 22 allocs** |
| Memory engine `Allow`, allocations | 1 (2 for concurrency) | **0** (1 for concurrency when a lease slice grows) |
| Memory engine `Allow`, 1k hot keys, 4 goroutines | not measured before | **~100–125 ns/op** (token bucket, GCRA, leaky, fixed, counter) |
| Memory engine sliding-window log, serial | 1429 ns/op (O(Limit) per call) | **~220–240 ns/op** (O(1)) |
| Redis engine `Allow`, allocations | 35–58 allocs, ~1.6 KiB | **9–18 allocs, ~0.75 KiB** (round trip time unchanged: Redis dominates) |
| Forward auth over loopback, 1 client, p50 | 151 µs (direct upstream 115 µs) | **137 µs** (direct 122 µs): about **15 µs added** |
| Proxy over loopback, 8 clients | 13.3k rps, p99 3.5 ms | **18.8k rps, p99 2.0 ms** |

The targets from the brief were:

- **Gateway overhead under 50 µs at p50: met.** The full proxy path takes
  16–18 µs on one core. A forward-auth decision adds about 15 µs at p50 over
  a direct request on the wire.
- **Memory engine `Allow` under 100 ns/op in parallel: met only at the
  boundary.** With 1k hot keys the result is 100–125 ns/op. With 100k keys
  it is about 190–250 ns/op, because a request then usually misses the CPU
  cache. With one hot key shared by every goroutine it is about 300–350
  ns/op, because all goroutines wait on that key's mutex. Most of the
  remaining cost is `time.Now` (about 35 ns on this VM's clock source), the
  shard mutex and the map lookup.
- **0–2 allocations on the engine path: met.** The memory engine makes 0
  allocations, or 1 for concurrency.

## Micro-benchmarks (before → after)

The command was `go test -bench . -benchmem -count=5`. Each value is the
median of five runs. The benchstat output is summarised by hand. "Before" is
the commit `b050610`, plus the benchmark files. For `RunParallel`
benchmarks, ns/op is wall-clock time divided by the number of operations
across all 4 goroutines: it measures throughput, not the latency of one
request.

### Gateway (`internal/gateway/bench_test.go`)

The upstream is an in-process `RoundTripper` stub, so no socket is involved.
The benchmarks use the real memory engine and a no-op recorder.

| Benchmark | sec/op | B/op | allocs/op |
|---|---|---|---|
| GatewayProxyAllowed (per-IP token bucket) | 26.9 µs → 7.1 µs | 37.8 KiB → 5.1 KiB | 83 → 53 |
| GatewayProxyAllowedAPIKey (key auth + per-consumer) | 29.0 µs → 8.3 µs | 38.0 KiB → 5.2 KiB | 89 → 56 |
| GatewayLimited (429) | 6.3 µs → 4.2 µs | 4.7 KiB → 3.2 KiB | 76 → 26 |
| ForwardAuthAllowed | 4.3 µs → 3.3 µs | 2.8 KiB → 2.0 KiB | 54 → 22 |
| CheckAPI (JSON in, JSON out) | 14.7 µs → 14.1 µs (noise) | 11.3 KiB → 11.2 KiB | 87 → 77 |

### Memory engine (`internal/ratelimit/bench_test.go`)

The parameters for every run are `Limit 1000 / 1s`.

| Benchmark (4 goroutines unless noted) | token bucket | sliding log | sliding counter | fixed | concurrency* | GCRA | leaky |
|---|---|---|---|---|---|---|---|
| Serial (1 goroutine), before | 275 ns | 1429 ns | 315 ns | 290 ns | 576 ns | 289 ns | 304 ns |
| Serial (1 goroutine), after | 198 ns | 242 ns | 203 ns | 210 ns | 394 ns | 200 ns | 221 ns |
| 1k keys, after | 124 ns | 139 ns | 118 ns | 118 ns | 200 ns | 120 ns | 124 ns |
| 100k keys, before | 180 ns | 323 ns | 232 ns | 265 ns | 402 ns | 229 ns | 235 ns |
| 100k keys, after | 191 ns | 250 ns | 224 ns | 237 ns | 321 ns | 202 ns | 237 ns |
| Single hot key, before | 344 ns | 1221 ns | 380 ns | 340 ns | 725 ns | 325 ns | 367 ns |
| Single hot key, after | 345 ns | 301 ns | 379 ns | 336 ns | 569 ns | 360 ns | 335 ns |
| allocs/op, before → after | 1 → 0 | 1 → 0 | 1 → 0 | 1 → 0 | 2 → 1 | 1 → 0 | 1 → 0 |

\* The concurrency rows include one `Allow` and one `Release` per operation.
The 1k-keys benchmark was added during this work, so it has no "before"
row. In the final run the 100k-key and single-key token bucket results
landed within noise of the baseline. An earlier run of the same code gave
151 ns for 100k keys.

### Redis engine (local Redis, 4 goroutines, 1000 keys)

| | token bucket | sliding log | counter | fixed | concurrency* | GCRA | leaky |
|---|---|---|---|---|---|---|---|
| sec/op | 46 → 49 µs | 61 → 62 µs | 51 → 48 µs | 45 → 42 µs | 94 → 89 µs | 49 → 49 µs | 46 → 48 µs |
| allocs/op | 37 → 10 | 38 → 11 | 35 → 9 | 35 → 9 | 58 → 18 | 40 → 10 | 40 → 10 |

The Redis round trip and the Lua script dominate the time. The client
changes save allocations, which means less GC work under load, but they do
not save measurable latency.

### Telemetry

`Record` was not changed. It takes about 420–490 ns serially and 780–840 ns
in parallel with a subscriber, with 1 allocation (the entry ID). That cost
is under 1% of the gateway's CPU profile in the load test.

## Load test over loopback (`cmd/rateguard-bench`)

The tool starts an upstream (`200 ok\n`) and a real gateway in one process,
both on 127.0.0.1. The gateway runs with the memory engine, a telemetry hub
as recorder and `log_sample_allowed = 1`. It has one route that requires an
API key, with a per-consumer token bucket. The tool then sends requests from
N keep-alive clients for 10 s to each target:

- `direct`: the upstream itself (the baseline).
- `proxy`: the upstream through RateGuard.
- `auth`: RateGuard's forward-auth endpoint, which makes the full rate-limit
  decision with no upstream hop.

The load generator, the gateway and the upstream all share the same 4
vCPUs.

| Clients | Target | Before: rps | Before: p50 / p95 / p99 | After: rps | After: p50 / p95 / p99 |
|---|---|---|---|---|---|
| 1 | direct | 8,210 | 115 / 199 / 282 µs | 7,767 | 122 / 209 / 289 µs |
| 1 | auth | 6,251 | 151 / 254 / 338 µs | 6,724 | 137 / 242 / 343 µs |
| 1 | proxy | 2,844 | 342 / 502 / 783 µs | 2,823 | 342 / 517 / 803 µs |
| 8 | direct | 56,988 | 117 / 258 / 637 µs | 55,583 | 120 / 263 / 650 µs |
| 8 | auth | 38,272 | 168 / 406 / 1083 µs | 42,629 | 153 / 349 / 933 µs |
| 8 | proxy | 13,260 | 442 / 1721 / 3456 µs | **18,759** | **364 / 743 / 2019 µs** |
| 64 | direct | 61,611 | 0.91 / 2.21 / 3.31 ms | 61,897 | 0.91 / 2.20 / 3.28 ms |
| 64 | auth | 43,230 | 1.28 / 3.25 / 5.14 ms | 49,957 | 1.10 / 2.80 / 4.69 ms |
| 64 | proxy | 16,080 | 3.56 / 8.18 / 11.0 ms | 17,698 | 3.36 / 6.69 / 9.37 ms |

With the Redis engine (after), 8 clients reached 12,309 rps for proxy
(p50 541 µs) and 20,029 rps for auth (p50 319 µs). With 1 client, auth had
a p50 of 400 µs.

### Reading these numbers honestly

- **On this VM, the network hop dominates the cost of proxying, not
  RateGuard's own work.** A direct request over loopback already takes
  about 115 µs at p50 with one client. Through the proxy, a request makes
  two loopback round trips plus the `net/http` client and server machinery.
  That machinery includes `ReverseProxy`, `Transport` and goroutine
  handoffs, and goroutine wake-ups are slow in this microVM. RateGuard's
  own decision work (routing, key hash, engine, headers, log entry) costs
  about 15 µs on the wire, as the `auth` row shows. In a CPU profile of the
  proxy load test, gateway code outside `net/http` is under 5% of samples,
  and `telemetry.Record` is 0.6%.
- **At 1 client, latency is unchanged.** The request is bound by wake-ups
  and syscalls, not by CPU. The gains appear under load, where the removed
  32 KiB buffer and the other allocations become less GC work. At 8
  clients, proxy throughput rose by 41% and p99 fell from 3.5 ms to 2.0 ms.
- **At 64 clients the machine is saturated.** On 4 vCPUs the load
  generator, the gateway and the upstream all compete for CPU, so latency
  there is queueing. Dedicated gateway hosts and real networks will show
  different absolute numbers. Measure on your own setup.
- **The "added latency" line that `rateguard-bench` prints is only an
  approximation.** It subtracts percentiles (proxy p50 minus direct p50),
  which is not the percentile of per-request differences.

## What was optimised

The changes are listed by commit, in order:

1. **Benchmarks and the load test tool** (no behaviour change).
2. **Proxy response path.**
   - `ReverseProxy` used to allocate a fresh 32 KiB copy buffer for every
     response, which was 85% of all bytes allocated on the proxy path. It
     now takes buffers from a `sync.Pool`.
   - Rate-limit headers are written directly with their canonical names and
     one shared backing array, instead of building a map that is then
     copied with `Header.Set`.
   - The `RateLimit-Policy` value is precomputed per policy when the config
     is compiled, and recomputed only when a plan or consumer override
     changes the numbers.
   - Upstream keep-alive pools are larger: 512 per host and 2048 in total,
     with a 90 s idle timeout and HTTP/2 negotiated for TLS upstreams.
3. **Request path.**
   - The API key is hashed with sha256 once, into a `[32]byte`, and looked
     up in a map keyed by digest. There is no per-request hex encoding, and
     the digest is reused for `api_key` bucket keys.
   - In-process engines (the memory engine) no longer get a per-request
     `context.WithTimeout`, which cost a timer and a context allocation.
     Redis keeps its 5 s deadline.
   - `clientIP` reuses the host part of an IPv4 `RemoteAddr` instead of
     formatting the address again.
   - `cleanPath` no longer prepends `"/"` to an already rooted path. That
     concatenation made `path.Clean` allocate on every request.
   - The 429 body is rendered with `strconv.Append*`, using a pre-encoded
     policy name, instead of `json.Marshal(map[string]any)`. A test checks
     the output is byte-for-byte identical to the old body.
   - `isRGHeader` compares header names in place instead of calling
     `ToLower` and `ReplaceAll` on every header in both directions. A test
     checks it matches the old function.
4. **Memory engine.**
   - Keys are `(algorithm, key)` structs instead of concatenated strings, so
     `Allow` makes 0 allocations.
   - Shards are chosen with a seeded `hash/maphash` instead of `fnv` behind
     an interface.
   - The sliding-window log keeps a running count and drops expired records
     by reslicing, so each call is O(expired records) instead of O(Limit).
     Memory stays O(Limit) per key.
5. **Redis client.**
   - Commands are encoded straight into the `bufio.Writer`, without `fmt`.
   - Replies are read with `ReadSlice`, integers are parsed in place, and
     array elements are allocated in a single slice.
   - Lengths announced by the server are now bounded, and a corrupt
     negative length returns an error instead of panicking.
   - Scripts were already run with `EVALSHA`, falling back to `EVAL`.

**Security properties are unchanged.**

- Keys are still compared as sha256 digests through a map lookup, never as
  plaintext.
- Bearer and check tokens still go through the existing constant-time
  verifier.
- No key or plaintext is cached.
- Every memory bound is kept: the key cap, overflow buckets, O(Limit) log
  memory and the pool sizes.

**Semantics are unchanged.** Every existing test passes with `-race`. The new
equivalence tests pin the header writer, the 429 body, the
reserved-header check and RESP parsing to the old forms.

### Tried and not kept, or deliberately not done

- **`FlushInterval` > 0 for known-length responses.** This saves one write
  syscall per response, but throughput moved within noise (17.6k to 18.0k
  rps). It would also change how quickly a slowly trickling body is
  forwarded, so the immediate flush (`-1`) was kept.
- **A coarse clock for the memory engine.** `time.Now` costs about 35 ns
  here, but a coarse clock lowers the time resolution of every algorithm.
  It was left out to keep semantics identical.
- **A per-key cache of sha256 results.** Hashing a key of about 40 bytes is
  a small part of the cost, and a cache keyed by the plaintext key would
  keep secrets in memory.
- **Redis pipelining across a route's policies.** Policies are evaluated in
  order and stop at the first deny, which also releases any concurrency
  slots already taken. Pipelining would change that, so it was not done.
- **Telemetry `Record`.** It is under 1% of CPU, so it was not changed.

## Tuning guide

- **Engine choice.** The memory engine adds about 0.1–0.4 µs per policy and
  is the right choice for a single instance. The Redis engine is needed
  for limits shared across instances. It adds one Redis round trip per
  policy on the route: about 45–60 µs per call with 4 goroutines against a
  local Redis here, and your network RTT plus the Lua script time on a
  real network. With Redis, the round trip is the gateway's cost. Put
  Redis close to the gateways: same AZ, or same host for sidecars.
- **Policies per route.** Each policy is one engine call. Global policies
  plus route policies add up, so keep chains short on hot routes.
- **Redis connection pool.** `cmd/rateguard` uses `PoolSize: 64` idle
  connections. Concurrency above the pool size still works, but the extra
  connections are dialled and closed per call. Size the pool to at least
  the number of engine calls in flight at peak.
- **`GOMAXPROCS`.** Go uses all visible CPUs by default. In containers with
  a CPU quota, set `GOMAXPROCS` to the quota, rounded down, to avoid
  throttling stalls. Go 1.24 does not do this automatically.
- **Log sampling.** `settings.log_sample_allowed` controls how many allowed
  requests reach the telemetry hub. Limited requests and errors are always
  logged. With sampling set to 1, every request takes the hub's mutex, at
  about 0.5 µs. In the load test, sampling 0 versus 1 differed by 0–8%,
  which is within noise here. At very high request rates, use 0.01–0.1.
  Dashboards and metrics count only the requests that were recorded.
- **Trusted proxies.** `trusted_proxies` is walked per request. Each entry
  is a prefix check, so keep the list short (CIDRs, not individual
  addresses). With an empty list, the client IP is read from `RemoteAddr`
  with no `X-Forwarded-For` parsing.
- **Upstream keep-alives.** The upstream transport keeps up to 512 idle
  connections per upstream host. Make sure the upstream's own idle timeout
  is longer than the gateway's (90 s), so the gateway does not reuse
  connections the upstream has closed.
- **Forward auth versus proxying.** If an edge proxy (NGINX, Envoy,
  Traefik) already exists, `/_rlg/v1/auth` adds about 15 µs for the
  decision, plus one hop from the edge to RateGuard. Proxying through
  RateGuard adds a full extra HTTP hop.

## Reproducing

```sh
# Micro-benchmarks (Redis ones skip if 127.0.0.1:6379 is unreachable;
# set REDIS_TEST_ADDR to point elsewhere).
go test ./internal/ratelimit ./internal/gateway ./internal/telemetry \
    -run '^$' -bench . -benchmem -count=5 | tee new.txt

# Compare two runs (benchstat needs a recent Go toolchain to install).
go install golang.org/x/perf/cmd/benchstat@latest
benchstat old.txt new.txt

# Profiles of the gateway path.
go test ./internal/gateway -run '^$' -bench GatewayProxyAllowed -benchtime 2s \
    -cpuprofile cpu.out -memprofile mem.out -o gw.test
go tool pprof -top gw.test cpu.out
go tool pprof -sample_index=alloc_objects -top gw.test mem.out

# Loopback load test (prints RPS and p50/p95/p99 for direct, proxy, auth).
go run ./cmd/rateguard-bench -c 8 -d 10s
go run ./cmd/rateguard-bench -c 64 -d 10s -sample 0.1
go run ./cmd/rateguard-bench -engine redis -redis 127.0.0.1:6379 -c 8
go run ./cmd/rateguard-bench -only proxy -cpuprofile load.prof
```
