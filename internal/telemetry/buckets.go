package telemetry

// Time-series storage. Per-5s buckets for the last hour (720) and per-1m
// buckets for the last 24h (1440). Each slot remembers which absolute bucket
// index it holds, so stale slots are detected and lazily reset on reuse; no
// background goroutine is needed.
const (
	fineStepSec   = 5
	fineSlots     = 720 // 1h
	coarseStepSec = 60
	coarseSlots   = 1440 // 24h
)

// Decision kinds (aggregated).
const (
	kAllowed = iota
	kLimited
	kShadow
	kError // unauthorized + no_route + error
	kOther
)

// Status classes, indexes into bucket.status.
const (
	cls2xx = iota
	cls3xx
	cls4xx
	cls429
	cls5xx
	numClasses
)

var classNames = [numClasses]string{"2xx", "3xx", "4xx", "429", "5xx"}

// statusClass returns -1 for statuses outside 200..599.
func statusClass(s int) int {
	switch {
	case s == 429:
		return cls429
	case s >= 200 && s < 300:
		return cls2xx
	case s >= 300 && s < 400:
		return cls3xx
	case s >= 400 && s < 500:
		return cls4xx
	case s >= 500 && s < 600:
		return cls5xx
	}
	return -1
}

// bucket counters are uint32 to keep per-route rings small (a single bucket
// would need >4e9 requests in <=1 minute to overflow).
type bucket struct {
	idx     int64
	total   uint32
	kinds   [4]uint32 // allowed, limited, shadow, errors
	status  [numClasses]uint32
	latency [histSlots]uint32
}

func (b *bucket) add(kind, cls, hi int) {
	b.total++
	if kind < len(b.kinds) {
		b.kinds[kind]++
	}
	if cls >= 0 {
		b.status[cls]++
	}
	b.latency[hi]++
}

// rings holds the fine and coarse bucket rings for one series.
type rings struct {
	fine   [fineSlots]bucket
	coarse [coarseSlots]bucket
}

func (r *rings) record(sec int64, kind, cls, hi int) {
	fi := sec / fineStepSec
	s := &r.fine[fi%fineSlots]
	if s.idx != fi {
		*s = bucket{idx: fi}
	}
	s.add(kind, cls, hi)
	mi := sec / coarseStepSec
	c := &r.coarse[mi%coarseSlots]
	if c.idx != mi {
		*c = bucket{idx: mi}
	}
	c.add(kind, cls, hi)
}

// fineAt / coarseAt return the bucket for absolute index i, or nil if the
// slot is empty or holds a different (stale) index.
func (r *rings) fineAt(i int64) *bucket {
	s := &r.fine[((i%fineSlots)+fineSlots)%fineSlots]
	if s.idx != i || s.total == 0 {
		return nil
	}
	return s
}

func (r *rings) coarseAt(i int64) *bucket {
	s := &r.coarse[((i%coarseSlots)+coarseSlots)%coarseSlots]
	if s.idx != i || s.total == 0 {
		return nil
	}
	return s
}
