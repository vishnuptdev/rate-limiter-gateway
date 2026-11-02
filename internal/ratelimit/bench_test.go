package ratelimit

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
)

// benchParams returns the params used by the engine benchmarks. Single-key
// runs reach steady state quickly (mostly denied: the "hot key" case);
// many-key runs are mostly allowed.
func benchParams(a model.Algorithm) Params {
	return Params{Algorithm: a, Limit: 1000, Window: time.Second}
}

func benchKeys(n int) []string {
	ks := make([]string, n)
	for i := range ks {
		ks[i] = "pol:consumer-" + strconv.Itoa(i)
	}
	return ks
}

func benchEngine(b *testing.B, e Engine, nkeys int) {
	ctx := context.Background()
	keys := benchKeys(nkeys)
	for _, a := range model.Algorithms {
		p := benchParams(a)
		b.Run(string(a), func(b *testing.B) {
			b.ReportAllocs()
			var seed atomic.Uint64
			b.RunParallel(func(pb *testing.PB) {
				i := int(seed.Add(7919))
				for pb.Next() {
					k := keys[i%len(keys)]
					i++
					if _, err := e.Allow(ctx, k, p); err != nil {
						b.Error(err)
						return
					}
					if a == model.AlgoConcurrency {
						e.Release(ctx, k, p)
					}
				}
			})
		})
	}
}

// BenchmarkMemoryAllowSingleKey: every goroutine hits the same key (worst
// case contention on one shard).
func BenchmarkMemoryAllowSingleKey(b *testing.B) {
	m := NewMemory(MemoryOptions{})
	defer m.Close()
	benchEngine(b, m, 1)
}

// BenchmarkMemoryAllow1kKeys: 1024 active keys (state fits in CPU caches).
func BenchmarkMemoryAllow1kKeys(b *testing.B) {
	m := NewMemory(MemoryOptions{})
	defer m.Close()
	benchEngine(b, m, 1024)
}

// BenchmarkMemoryAllowManyKeys: 100k distinct keys spread over the shards
// (state does not fit in cache: mostly bound by memory latency).
func BenchmarkMemoryAllowManyKeys(b *testing.B) {
	m := NewMemory(MemoryOptions{})
	defer m.Close()
	benchEngine(b, m, 100_000)
}

// BenchmarkMemoryAllowSerial is the uncontended single-goroutine cost.
func BenchmarkMemoryAllowSerial(b *testing.B) {
	m := NewMemory(MemoryOptions{})
	defer m.Close()
	ctx := context.Background()
	keys := benchKeys(1024)
	for _, a := range model.Algorithms {
		p := benchParams(a)
		b.Run(string(a), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				k := keys[i&1023]
				m.Allow(ctx, k, p)
				if a == model.AlgoConcurrency {
					m.Release(ctx, k, p)
				}
			}
		})
	}
}

// BenchmarkRedisAllow measures a round trip to Redis (skipped without one).
func BenchmarkRedisAllow(b *testing.B) {
	r, _ := newTestRedis(b)
	benchEngine(b, r, 1000)
}
