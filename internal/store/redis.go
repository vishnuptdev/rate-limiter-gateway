package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/redisclient"
)

const (
	redisConfigKey  = "rateguard:config"
	redisVersionKey = "rateguard:config:version"
)

// ErrStaleVersion is returned by Redis.Save when the stored config already
// has a version >= the one being saved (another instance won the race).
var ErrStaleVersion = errors.New("store: stale config version")

// saveScript writes config+version only if ARGV[1] is newer than the stored
// version (or nothing is stored yet). Returns 1 on write, 0 when stale.
const saveScript = `
local cur = redis.call('GET', KEYS[2])
if cur and tonumber(cur) >= tonumber(ARGV[1]) then return 0 end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('SET', KEYS[2], ARGV[1])
return 1`

// Redis shares the config between instances.
type Redis struct {
	c         *redisclient.Client
	seen      atomic.Int64 // newest version this process has loaded or saved
	pollEvery time.Duration
}

func NewRedis(c *redisclient.Client) *Redis {
	return &Redis{c: c, pollEvery: 2 * time.Second}
}

func (r *Redis) Name() string { return "redis" }

func (r *Redis) Load(context.Context) (*model.Snapshot, error) {
	rep, err := r.c.Do("GET", redisConfigKey)
	if err != nil {
		return nil, err
	}
	if rep.IsNil {
		return nil, nil
	}
	s := model.NewSnapshot()
	if err := json.Unmarshal([]byte(rep.Str), s); err != nil {
		return nil, err
	}
	r.markSeen(s.Version)
	return s, nil
}

func (r *Redis) Save(_ context.Context, s *model.Snapshot) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	rep, err := r.c.Eval(saveScript, []string{redisConfigKey, redisVersionKey},
		[]string{strconv.FormatInt(s.Version, 10), string(b)})
	if err != nil {
		return err
	}
	if rep.Int != 1 {
		return ErrStaleVersion
	}
	r.markSeen(s.Version)
	return nil
}

func (r *Redis) markSeen(v int64) {
	for {
		cur := r.seen.Load()
		if v <= cur || r.seen.CompareAndSwap(cur, v) {
			return
		}
	}
}

// Watch polls the version key every 2s and calls fn with the new snapshot
// when it is newer than anything this process has loaded or saved.
func (r *Redis) Watch(ctx context.Context, fn func(*model.Snapshot)) {
	t := time.NewTicker(r.pollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		rep, err := r.c.Do("GET", redisVersionKey)
		if err != nil || rep.IsNil {
			continue
		}
		v, err := strconv.ParseInt(rep.Str, 10, 64)
		if err != nil || v <= r.seen.Load() {
			continue
		}
		s, err := r.Load(ctx)
		if err != nil || s == nil {
			continue
		}
		fn(s)
	}
}
