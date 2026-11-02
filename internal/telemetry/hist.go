package telemetry

import (
	"math"
	"sort"
)

// Latency histogram: 40 log-scale buckets from 0.1ms to 60s plus one
// overflow bucket. Bucket i (0 <= i < 40) holds values v with
// bounds[i-1] < v <= bounds[i] (bucket 0 holds v <= 0.1ms); bucket 40 holds
// everything above 60s. Consecutive bounds differ by a constant factor of
// ~1.41, so a percentile estimate is always inside the bucket that contains
// the true sample (relative error < 41%, typically far less because we
// interpolate linearly inside the bucket).
const (
	histBuckets = 40
	histSlots   = histBuckets + 1 // + overflow
	histMinMs   = 0.1
	histMaxMs   = 60000.0
)

var histBounds [histBuckets]float64

func init() {
	r := math.Pow(histMaxMs/histMinMs, 1.0/float64(histBuckets-1))
	for i := range histBounds {
		histBounds[i] = histMinMs * math.Pow(r, float64(i))
	}
	histBounds[histBuckets-1] = histMaxMs
}

// histIndex maps a latency in milliseconds to its bucket. NaN and negative
// values land in bucket 0.
func histIndex(ms float64) int {
	if !(ms > histMinMs) {
		return 0
	}
	if ms > histMaxMs {
		return histBuckets
	}
	return sort.SearchFloat64s(histBounds[:], ms)
}

// histQuantile estimates the q-quantile (0..1) in milliseconds from bucket
// counts using linear interpolation inside the containing bucket.
func histQuantile(counts *[histSlots]uint64, q float64) float64 {
	var total uint64
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return 0
	}
	target := q * float64(total)
	if target < 1 {
		target = 1
	}
	var cum uint64
	for i, c := range counts {
		if c == 0 {
			continue
		}
		if float64(cum+c) >= target {
			if i == histBuckets {
				return histMaxMs
			}
			lo := 0.0
			if i > 0 {
				lo = histBounds[i-1]
			}
			hi := histBounds[i]
			frac := (target - float64(cum)) / float64(c)
			return lo + (hi-lo)*frac
		}
		cum += c
	}
	return histMaxMs
}
