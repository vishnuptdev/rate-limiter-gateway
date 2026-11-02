package store

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/redisclient"
)

func goodSnapshot() *model.Snapshot {
	s := model.NewSnapshot()
	s.Version = 1
	s.Policies = []model.Policy{
		{ID: "p1", Name: "P1", Algorithm: model.AlgoFixedWindow, Limit: 10, Window: model.Duration(time.Minute), KeyBy: []string{"ip", "header:X-Tenant", "query:k"}, Mode: model.ModeEnforce, FailMode: model.FailOpen, Enabled: true},
		{ID: "conc", Name: "C", Algorithm: model.AlgoConcurrency, Limit: 5, KeyBy: []string{"consumer"}, Mode: model.ModeShadow, FailMode: model.FailClosed, Enabled: true},
	}
	s.Plans = []model.Plan{{ID: "pro", Name: "Pro", Overrides: map[string]model.LimitOverride{"p1": {Limit: 100}}}}
	s.Routes = []model.Route{{ID: "r1", Name: "R", Match: model.RouteMatch{Host: "*.example.com", PathPrefix: "/api", Methods: []string{"GET", "POST"}},
		Upstream: "http://127.0.0.1:9", PolicyIDs: []string{"p1"}, Enabled: true}}
	s.Consumers = []model.Consumer{{ID: "c1", Name: "C1", PlanID: "pro", Keys: []model.APIKey{{ID: "k1", Hash: strings.Repeat("ab", 32)}}}}
	s.Settings.TrustedProxies = []string{"10.0.0.0/8", "::1"}
	s.Settings.GlobalPolicyIDs = []string{"p1"}
	return s
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(s *model.Snapshot)
		fields []string // expected problem fields; nil => valid
	}{
		{"valid", func(s *model.Snapshot) {}, nil},
		{"empty snapshot valid", func(s *model.Snapshot) { *s = *model.NewSnapshot() }, nil},
		{"policy empty id", func(s *model.Snapshot) { s.Policies[1].ID = "" }, []string{"policies[1].id"}},
		{"policy bad id", func(s *model.Snapshot) { s.Policies[1].ID = "Bad ID" }, []string{"policies[1].id"}},
		{"policy dup id", func(s *model.Snapshot) { s.Policies[1].ID = "p1" }, []string{"policies[1].id"}},
		{"policy empty name", func(s *model.Snapshot) { s.Policies[0].Name = " " }, []string{"policies[0].name"}},
		{"policy long name", func(s *model.Snapshot) { s.Policies[0].Name = strings.Repeat("x", 101) }, []string{"policies[0].name"}},
		{"policy bad algo", func(s *model.Snapshot) { s.Policies[0].Algorithm = "nope" }, []string{"policies[0].algorithm"}},
		{"limit zero", func(s *model.Snapshot) { s.Policies[0].Limit = 0 }, []string{"policies[0].limit"}},
		{"limit huge", func(s *model.Snapshot) { s.Policies[0].Limit = 2e9 }, []string{"policies[0].limit"}},
		{"limit 1e9 ok", func(s *model.Snapshot) { s.Policies[0].Limit = 1e9 }, nil},
		{"window too small", func(s *model.Snapshot) { s.Policies[0].Window = model.Duration(time.Microsecond) }, []string{"policies[0].window"}},
		{"window too big", func(s *model.Snapshot) { s.Policies[0].Window = model.Duration(366 * 24 * time.Hour) }, []string{"policies[0].window"}},
		{"concurrency window ignored", func(s *model.Snapshot) { s.Policies[1].Window = 0 }, nil},
		{"burst negative", func(s *model.Snapshot) { s.Policies[0].Burst = -1 }, []string{"policies[0].burst"}},
		{"cost over limit", func(s *model.Snapshot) { s.Policies[0].Cost = 11 }, []string{"policies[0].cost"}},
		{"cost negative", func(s *model.Snapshot) { s.Policies[0].Cost = -1 }, []string{"policies[0].cost"}},
		{"cost == limit ok", func(s *model.Snapshot) { s.Policies[0].Cost = 10 }, nil},
		{"bad key_by", func(s *model.Snapshot) { s.Policies[0].KeyBy = []string{"ip", "bogus"} }, []string{"policies[0].key_by[1]"}},
		{"empty header key_by", func(s *model.Snapshot) { s.Policies[0].KeyBy = []string{"header:"} }, []string{"policies[0].key_by[0]"}},
		{"empty query key_by", func(s *model.Snapshot) { s.Policies[0].KeyBy = []string{"query:"} }, []string{"policies[0].key_by[0]"}},
		{"bad mode", func(s *model.Snapshot) { s.Policies[0].Mode = "audit" }, []string{"policies[0].mode"}},
		{"bad fail mode", func(s *model.Snapshot) { s.Policies[0].FailMode = "maybe" }, []string{"policies[0].fail_mode"}},
		{"route upstream relative", func(s *model.Snapshot) { s.Routes[0].Upstream = "/foo" }, []string{"routes[0].upstream"}},
		{"route upstream ftp", func(s *model.Snapshot) { s.Routes[0].Upstream = "ftp://x" }, []string{"routes[0].upstream"}},
		{"route upstream no host", func(s *model.Snapshot) { s.Routes[0].Upstream = "http://" }, []string{"routes[0].upstream"}},
		{"route prefix no slash", func(s *model.Snapshot) { s.Routes[0].Match.PathPrefix = "api" }, []string{"routes[0].match.path_prefix"}},
		{"route empty prefix ok", func(s *model.Snapshot) { s.Routes[0].Match.PathPrefix = "" }, nil},
		{"route lowercase method", func(s *model.Snapshot) { s.Routes[0].Match.Methods = []string{"get"} }, []string{"routes[0].match.methods[0]"}},
		{"route unknown method", func(s *model.Snapshot) { s.Routes[0].Match.Methods = []string{"FETCH"} }, []string{"routes[0].match.methods[0]"}},
		{"route unknown policy", func(s *model.Snapshot) { s.Routes[0].PolicyIDs = []string{"zzz"} }, []string{"routes[0].policy_ids[0]"}},
		{"route bad host", func(s *model.Snapshot) { s.Routes[0].Match.Host = "a/b" }, []string{"routes[0].match.host"}},
		{"plan unknown override policy", func(s *model.Snapshot) { s.Plans[0].Overrides["zzz"] = model.LimitOverride{Limit: 1} }, []string{"plans[0].overrides[zzz]"}},
		{"plan negative override", func(s *model.Snapshot) { s.Plans[0].Overrides["p1"] = model.LimitOverride{Limit: -1} }, []string{"plans[0].overrides[p1].limit"}},
		{"consumer unknown plan", func(s *model.Snapshot) { s.Consumers[0].PlanID = "gold" }, []string{"consumers[0].plan_id"}},
		{"consumer bad override", func(s *model.Snapshot) {
			s.Consumers[0].Overrides = map[string]model.LimitOverride{"zzz": {}}
		}, []string{"consumers[0].overrides[zzz]"}},
		{"key hash short", func(s *model.Snapshot) { s.Consumers[0].Keys[0].Hash = "abc" }, []string{"consumers[0].keys[0].hash"}},
		{"key hash non-hex", func(s *model.Snapshot) { s.Consumers[0].Keys[0].Hash = strings.Repeat("zz", 32) }, []string{"consumers[0].keys[0].hash"}},
		{"dup key hash", func(s *model.Snapshot) {
			s.Consumers = append(s.Consumers, model.Consumer{ID: "c2", Name: "C2", Keys: []model.APIKey{{ID: "k", Hash: strings.Repeat("AB", 32)}}})
		}, []string{"consumers[1].keys[0].hash"}},
		{"bad trusted proxy", func(s *model.Snapshot) { s.Settings.TrustedProxies = []string{"10.0.0.0/8", "nope"} }, []string{"settings.trusted_proxies[1]"}},
		{"bad cidr", func(s *model.Snapshot) { s.Settings.TrustedProxies = []string{"10.0.0.0/99"} }, []string{"settings.trusted_proxies[0]"}},
		{"unknown global policy", func(s *model.Snapshot) { s.Settings.GlobalPolicyIDs = []string{"zzz"} }, []string{"settings.global_policy_ids[0]"}},
		{"sample > 1", func(s *model.Snapshot) { s.Settings.LogSampleAllowed = 1.5 }, []string{"settings.log_sample_allowed"}},
		{"sample < 0", func(s *model.Snapshot) { s.Settings.LogSampleAllowed = -0.1 }, []string{"settings.log_sample_allowed"}},
		{"bad api header", func(s *model.Snapshot) { s.Settings.APIKeyHeader = "bad header" }, []string{"settings.api_key_header"}},
		{"negative max body", func(s *model.Snapshot) { s.Settings.MaxBodyBytes = -1 }, []string{"settings.max_body_bytes"}},
		{"ipv6 prefix 0 ok", func(s *model.Snapshot) { s.Settings.IPv6PrefixLen = 0 }, nil},
		{"ipv6 prefix 32 ok", func(s *model.Snapshot) { s.Settings.IPv6PrefixLen = 32 }, nil},
		{"ipv6 prefix 128 ok", func(s *model.Snapshot) { s.Settings.IPv6PrefixLen = 128 }, nil},
		{"ipv6 prefix 31", func(s *model.Snapshot) { s.Settings.IPv6PrefixLen = 31 }, []string{"settings.ipv6_prefix_len"}},
		{"ipv6 prefix 129", func(s *model.Snapshot) { s.Settings.IPv6PrefixLen = 129 }, []string{"settings.ipv6_prefix_len"}},
		{"ipv6 prefix negative", func(s *model.Snapshot) { s.Settings.IPv6PrefixLen = -1 }, []string{"settings.ipv6_prefix_len"}},
		{"upgrade with concurrency policy", func(s *model.Snapshot) {
			s.Routes[0].AllowUpgrade = true
			s.Routes[0].PolicyIDs = []string{"p1", "conc"}
		}, []string{"routes[0].policy_ids[1]"}},
		{"concurrency without upgrade ok", func(s *model.Snapshot) { s.Routes[0].PolicyIDs = []string{"p1", "conc"} }, nil},
		{"upgrade with global concurrency policy", func(s *model.Snapshot) {
			s.Routes[0].AllowUpgrade = true
			s.Settings.GlobalPolicyIDs = []string{"p1", "conc"}
		}, []string{"routes[0].allow_upgrade"}},
		{"upgrade max 24h ok", func(s *model.Snapshot) {
			s.Routes[0].AllowUpgrade = true
			s.Routes[0].UpgradeMaxDuration = model.Duration(24 * time.Hour)
		}, nil},
		{"upgrade max over 24h", func(s *model.Snapshot) {
			s.Routes[0].AllowUpgrade = true
			s.Routes[0].UpgradeMaxDuration = model.Duration(25 * time.Hour)
		}, []string{"routes[0].upgrade_max_duration"}},
		{"upgrade max negative", func(s *model.Snapshot) { s.Routes[0].UpgradeMaxDuration = model.Duration(-time.Second) }, []string{"routes[0].upgrade_max_duration"}},
		{"multiple problems", func(s *model.Snapshot) { s.Policies[0].Limit = 0; s.Routes[0].Upstream = "x" }, []string{"policies[0].limit", "routes[0].upstream"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := goodSnapshot()
			tc.mut(s)
			err := Validate(s)
			if tc.fields == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("want *ValidationError, got %T %v", err, err)
			}
			got := map[string]bool{}
			for _, p := range ve.Problems {
				got[p.Field] = true
				if p.Message == "" {
					t.Errorf("empty message for %s", p.Field)
				}
			}
			for _, f := range tc.fields {
				if !got[f] {
					t.Errorf("missing problem for %s; got %+v", f, ve.Problems)
				}
			}
			if len(ve.Problems) != len(tc.fields) {
				t.Errorf("problem count %d want %d: %+v", len(ve.Problems), len(tc.fields), ve.Problems)
			}
			if !strings.Contains(ve.Error(), tc.fields[0]) {
				t.Errorf("Error() %q lacks field", ve.Error())
			}
		})
	}
	if err := Validate(nil); err == nil {
		t.Error("nil snapshot must fail")
	}
}

func TestValidationErrorTruncates(t *testing.T) {
	ve := &ValidationError{}
	for i := 0; i < 8; i++ {
		ve.Problems = append(ve.Problems, Problem{Field: "f", Message: "m"})
	}
	if !strings.Contains(ve.Error(), "and 3 more") {
		t.Errorf("got %q", ve.Error())
	}
}

func roundTrip(t *testing.T, st ConfigStore) {
	t.Helper()
	ctx := context.Background()
	got, err := st.Load(ctx)
	if err != nil || got != nil {
		t.Fatalf("empty Load = %v, %v; want nil,nil", got, err)
	}
	s := goodSnapshot()
	s.Version = 7
	if err := st.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	got, err = st.Load(ctx)
	if err != nil || got == nil {
		t.Fatalf("Load: %v %v", got, err)
	}
	if got.Version != 7 || len(got.Policies) != 2 || got.Policies[0].Window.D() != time.Minute || got.Consumers[0].Keys[0].Hash != s.Consumers[0].Keys[0].Hash {
		t.Errorf("round trip mismatch: %+v", got)
	}
	got.Policies[0].Name = "mutated"
	again, _ := st.Load(ctx)
	if again.Policies[0].Name == "mutated" {
		t.Error("Load must not alias stored state")
	}
}

func TestMemoryStore(t *testing.T) {
	m := NewMemory()
	roundTrip(t, m)
	if m.Name() != "memory" {
		t.Error("name")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Watch(ctx, func(*model.Snapshot) {}); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Watch did not return on cancel")
	}
}

func TestFileStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")
	f, err := NewFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, f)
	if f.Name() != "file" {
		t.Error("name")
	}
	fi, err := os.Stat(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("perm %v want 0600", fi.Mode().Perm())
	}
	// Overwrite keeps 0600 and leaves no temp files behind.
	s := goodSnapshot()
	s.Version = 8
	if err := f.Save(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("dir should contain only config.json, got %v", ents)
	}
	fi, _ = os.Stat(filepath.Join(dir, "config.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("perm after overwrite %v", fi.Mode().Perm())
	}
	if _, err := NewFile(""); err == nil {
		t.Error("empty dir must fail")
	}
}

func TestFileStoreCorrupt(t *testing.T) {
	dir := t.TempDir()
	f, _ := NewFile(dir)
	os.WriteFile(filepath.Join(dir, "config.json"), []byte("{not json"), 0o600)
	if _, err := f.Load(context.Background()); err == nil {
		t.Error("corrupt file must error")
	}
}

func TestFileStoreAtomicUnderConcurrentLoad(t *testing.T) {
	f, _ := NewFile(t.TempDir())
	ctx := context.Background()
	s := goodSnapshot()
	f.Save(ctx, s)
	var stop atomic.Bool
	errc := make(chan error, 1)
	go func() {
		for !stop.Load() {
			got, err := f.Load(ctx)
			if err != nil || got == nil {
				errc <- err
				return
			}
		}
		errc <- nil
	}()
	for i := 0; i < 200; i++ {
		s.Version = int64(i)
		if err := f.Save(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	if err := <-errc; err != nil {
		t.Fatalf("reader observed partial write: %v", err)
	}
}

func redisClient(t *testing.T) *redisclient.Client {
	t.Helper()
	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		t.Skipf("redis unreachable at %s: %v", addr, err)
	}
	conn.Close()
	c := redisclient.New(addr, 4)
	if err := c.Ping(); err != nil {
		t.Skipf("redis ping: %v", err)
	}
	c.Do("DEL", redisConfigKey, redisVersionKey)
	t.Cleanup(func() { c.Do("DEL", redisConfigKey, redisVersionKey); c.Close() })
	return c
}

func TestRedisStore(t *testing.T) {
	c := redisClient(t)
	r := NewRedis(c)
	roundTrip(t, r) // saves version 7
	if r.Name() != "redis" {
		t.Error("name")
	}
	ctx := context.Background()
	s := goodSnapshot()
	for _, v := range []int64{7, 3} { // equal and older must be rejected
		s.Version = v
		if err := r.Save(ctx, s); !errors.Is(err, ErrStaleVersion) {
			t.Errorf("version %d: err = %v, want ErrStaleVersion", v, err)
		}
	}
	got, _ := r.Load(ctx)
	if got.Version != 7 {
		t.Errorf("stale save overwrote config: version %d", got.Version)
	}
	s.Version = 8
	if err := r.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
}

func TestRedisWatch(t *testing.T) {
	c := redisClient(t)
	a, b := NewRedis(c), NewRedis(c)
	a.pollEvery, b.pollEvery = 20*time.Millisecond, 20*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := goodSnapshot()
	s.Version = 1
	if err := a.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	b.Load(ctx)
	gotA := make(chan *model.Snapshot, 4)
	gotB := make(chan *model.Snapshot, 4)
	go a.Watch(ctx, func(s *model.Snapshot) { gotA <- s })
	go b.Watch(ctx, func(s *model.Snapshot) { gotB <- s })
	s2 := goodSnapshot()
	s2.Version = 2
	if err := a.Save(ctx, s2); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-gotB:
		if got.Version != 2 {
			t.Errorf("watch version %d", got.Version)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("instance B never saw the new version")
	}
	select {
	case <-gotA:
		t.Error("saver must not be notified of its own write")
	case <-time.After(150 * time.Millisecond):
	}
}
