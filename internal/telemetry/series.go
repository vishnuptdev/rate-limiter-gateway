package telemetry

import (
	"time"

	"ratelimitergateway/internal/model"
)

// agg accumulates buckets for one output point / the overview.
type agg struct {
	total   int64
	kinds   [4]int64
	status  [numClasses]int64
	latency [histSlots]uint64
}

func (a *agg) merge(b *bucket) {
	a.total += int64(b.total)
	for i, v := range b.kinds {
		a.kinds[i] += int64(v)
	}
	for i, v := range b.status {
		a.status[i] += int64(v)
	}
	for i, v := range b.latency {
		a.latency[i] += uint64(v)
	}
}

type rangeSpec struct {
	rng   time.Duration
	step  int  // seconds per output point
	n     int  // number of points
	fine  bool // source: 5s ring (else 1m ring)
	group int  // source buckets per point
}

var rangeSpecs = []rangeSpec{
	{15 * time.Minute, 5, 180, true, 1},
	{time.Hour, 15, 240, true, 3},
	{6 * time.Hour, 60, 360, false, 1},
	{24 * time.Hour, 300, 288, false, 5},
}

// snapRange picks the supported range nearest to d (ties go to the shorter).
func snapRange(d time.Duration) rangeSpec {
	best := rangeSpecs[0]
	bestDiff := abs(d - best.rng)
	for _, s := range rangeSpecs[1:] {
		if df := abs(d - s.rng); df < bestDiff {
			best, bestDiff = s, df
		}
	}
	return best
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// Timeseries returns gap-filled points, oldest first, ending with the
// current (partial) step. rng snaps to the nearest of 15m (5s step),
// 1h (15s), 6h (1m) or 24h (5m); point boundaries are aligned to multiples
// of the step since the Unix epoch. routeID "" means all traffic; for a
// route outside the 50 busiest (or unknown) the points are all zero.
func (h *Hub) Timeseries(rng time.Duration, routeID string) model.Timeseries {
	spec := snapRange(rng)
	pts := make([]model.TimeseriesPoint, spec.n)
	sec := h.now().Unix()
	cur := sec / int64(spec.step)
	start := cur - int64(spec.n) + 1

	h.mu.Lock()
	var r *rings
	if routeID == "" {
		r = h.global
	} else {
		r = h.routeSer[routeID]
	}
	for i := range pts {
		idx := start + int64(i)
		p := &pts[i]
		p.T = time.Unix(idx*int64(spec.step), 0).UTC()
		if r == nil {
			continue
		}
		var a agg
		for j := 0; j < spec.group; j++ {
			src := idx*int64(spec.group) + int64(j)
			var b *bucket
			if spec.fine {
				b = r.fineAt(src)
			} else {
				b = r.coarseAt(src)
			}
			if b != nil {
				a.merge(b)
			}
		}
		if a.total == 0 {
			continue
		}
		p.Allowed, p.Limited, p.ShadowLimited, p.Errors = a.kinds[kAllowed], a.kinds[kLimited], a.kinds[kShadow], a.kinds[kError]
		p.P50Ms = histQuantile(&a.latency, 0.50)
		p.P95Ms = histQuantile(&a.latency, 0.95)
		p.P99Ms = histQuantile(&a.latency, 0.99)
	}
	h.mu.Unlock()
	return model.Timeseries{StepSeconds: spec.step, Points: pts}
}

// Overview summarises the last 24h. Totals, status breakdown and
// percentiles come from the 1m buckets (exact to the minute); the top lists
// come from two-generation maps and therefore cover 12h..24h (see topMap).
func (h *Hub) Overview() model.Overview {
	now := h.now()
	sec := now.Unix()
	curMin := sec / coarseStepSec

	h.mu.Lock()
	var a agg
	for i := curMin - coarseSlots + 1; i <= curMin; i++ {
		if b := h.global.coarseAt(i); b != nil {
			a.merge(b)
		}
	}
	// RPS over the last minute: the 12 newest 5s buckets, with the divisor
	// being 11 full buckets plus the elapsed part of the current one.
	curFine := sec / fineStepSec
	var recent int64
	for i := curFine - 11; i <= curFine; i++ {
		if b := h.global.fineAt(i); b != nil {
			recent += int64(b.total)
		}
	}
	elapsed := float64(11*fineStepSec) + float64(sec%fineStepSec) + float64(now.Nanosecond())/1e9
	h.topRoutes.rotate(now)
	h.topLimited.rotate(now)
	h.topPolicies.rotate(now)
	h.topConsumers.rotate(now)
	ov := model.Overview{
		TopLimitedKeys: h.topLimited.top(topN),
		TopRoutes:      h.topRoutes.top(topN),
		TopPolicies:    h.topPolicies.top(topN),
		TopConsumers:   h.topConsumers.top(topN),
	}
	h.mu.Unlock()

	ov.Requests = a.total
	ov.Allowed, ov.Limited, ov.ShadowLimited, ov.Errors = a.kinds[kAllowed], a.kinds[kLimited], a.kinds[kShadow], a.kinds[kError]
	ov.RPS1m = float64(recent) / elapsed
	ov.P50Ms = histQuantile(&a.latency, 0.50)
	ov.P95Ms = histQuantile(&a.latency, 0.95)
	ov.P99Ms = histQuantile(&a.latency, 0.99)
	ov.StatusBreakdown = make([]model.Counted, numClasses)
	for i, n := range classNames {
		ov.StatusBreakdown[i] = model.Counted{ID: n, Label: n, Count: a.status[i]}
	}
	ov.Since = now.Add(-24 * time.Hour)
	return ov
}
