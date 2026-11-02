package store

import (
	"strings"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
)

func TestValidateLeakyBucketDelayAndBurst(t *testing.T) {
	lb := func(limit int, window time.Duration, burst int) *model.Snapshot {
		s := goodSnapshot()
		s.Policies = append(s.Policies, model.Policy{ID: "lb", Name: "LB", Algorithm: model.AlgoLeakyBucket,
			Limit: limit, Window: model.Duration(window), Burst: burst, Mode: model.ModeEnforce, FailMode: model.FailOpen, Enabled: true})
		return s
	}
	cases := []struct {
		name string
		s    *model.Snapshot
		want string // substring of the error; "" = valid
	}{
		{"ok default burst", lb(100, 10*time.Second, 0), ""}, // (100-1)*0.1s = 9.9s
		{"ok at limit", lb(10, 30*time.Second, 11), ""},      // 10*3s = 30s
		{"too slow", lb(10, 30*time.Second, 12), "policies[2].burst"},
		{"default burst too slow", lb(10, time.Hour, 0), "queue delay"},
		{"burst cap", lb(2_000_000, time.Second, 1_000_001), "between 0 and 1000000"},
	}
	for _, c := range cases {
		err := Validate(c.s)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}

	// Burst cap applies to every algorithm and to overrides.
	s := goodSnapshot()
	s.Policies[0].Burst = 1_000_001
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "policies[0].burst") {
		t.Errorf("fixed window burst cap: %v", err)
	}

	// Overrides are validated against the effective leaky bucket numbers.
	s = lb(100, 10*time.Second, 0)
	s.Plans[0].Overrides["lb"] = model.LimitOverride{Burst: 1000} // 999*0.1s = 99.9s
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "plans[0].overrides[lb].burst") {
		t.Errorf("plan override: %v", err)
	}
	s = lb(100, 10*time.Second, 0)
	s.Consumers = append(s.Consumers, model.Consumer{ID: "zz", Name: "ZZ", PlanID: "pro",
		Overrides: map[string]model.LimitOverride{"lb": {Window: model.Duration(time.Hour)}}})
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "consumers[") {
		t.Errorf("consumer override: %v", err)
	}
}
