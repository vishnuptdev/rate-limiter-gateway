package gateway

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/ratelimit"
)

// setRateHeaders is the allocation-light twin of rateHeaders; both must
// describe exactly the same headers.
func TestSetRateHeadersMatchesRateHeaders(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pp := &model.Policy{ID: "p", Limit: 100, Window: model.Duration(time.Minute)}
	plain := &cpolicy{p: pp, policyHdr: policyHeader(ratelimit.Params{Limit: 100, Window: time.Minute})}
	conc := &cpolicy{p: &model.Policy{ID: "c", Limit: 5}, conc: true}
	dec := ratelimit.Decision{Limit: 100, Remaining: 42, ResetAfter: 1500 * time.Millisecond, RetryAfter: 300 * time.Millisecond}
	cases := []*polResult{
		{cp: plain, params: ratelimit.Params{Limit: 100, Window: time.Minute}, dec: dec},
		{cp: plain, params: ratelimit.Params{Limit: 7, Window: time.Minute}, dec: dec},               // limit override
		{cp: plain, params: ratelimit.Params{Limit: 100, Window: 1500 * time.Millisecond}, dec: dec}, // window override
		{cp: plain, params: ratelimit.Params{Limit: 100, Window: time.Minute}, dec: ratelimit.Decision{}},
		{cp: conc, params: ratelimit.Params{Limit: 5}, dec: ratelimit.Decision{Remaining: 4, ResetAfter: time.Second}},
	}
	for i, r := range cases {
		for _, legacy := range []bool{false, true} {
			for _, limited := range []bool{false, true} {
				cfg := &compiled{legacyHeaders: legacy}
				want := http.Header{}
				for k, v := range rateHeaders(cfg, r, now, limited) {
					want.Set(k, v)
				}
				got := http.Header{"Ratelimit-Limit": {"stale"}, "Retry-After": {"9"}}
				if !limited {
					delete(got, "Retry-After")
				}
				setRateHeaders(got, cfg, r, now, limited)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("case %d legacy=%v limited=%v:\n got %v\nwant %v", i, legacy, limited, got, want)
				}
			}
		}
	}
}

// limitedBody must be byte-identical to the reflective encoding it replaced.
func TestLimitedBodyMatchesJSONMap(t *testing.T) {
	for _, name := range []string{"Policy p", `quo"te\back`, "<b>&amp;</b>", "ünï\u2028code", ""} {
		for _, dec := range []ratelimit.Decision{
			{Limit: 10, ResetAfter: 1500 * time.Millisecond, RetryAfter: 200 * time.Millisecond},
			{ResetAfter: 0, RetryAfter: 61 * time.Second},
		} {
			p := &model.Policy{ID: "p", Name: name}
			for _, cp := range []*cpolicy{compilePolicy(p, &compiled{secretHdr: map[string]bool{}}), {p: p}} {
				d := &polResult{cp: cp, params: ratelimit.Params{Limit: 99}, dec: dec}
				rr := httptest.NewRecorder()
				writeJSON(rr, 429, map[string]any{
					"error": "rate_limited", "message": "Rate limit exceeded", "policy": d.cp.p.Name,
					"limit": limitOf(d), "remaining": 0, "retry_after_s": retryAfterSeconds(d.dec), "reset_s": ceilSeconds(d.dec.ResetAfter),
				})
				if got := string(limitedBody(d)); got != rr.Body.String() {
					t.Errorf("name %q:\n got %s\nwant %s", name, got, rr.Body.String())
				}
			}
		}
	}
}

func TestIsRGHeaderMatchesReference(t *testing.T) {
	ref := func(k string) bool {
		return strings.HasPrefix(strings.ReplaceAll(strings.ToLower(k), "_", "-"), "x-rateguard-")
	}
	for _, k := range []string{"X-Rateguard-Consumer", "x-rateguard-x", "X_RATEGUARD_Y", "X-Rateguard_Z", "X-RateGuard-",
		"X-Rateguard", "X-Rate-Guard-A", "Content-Type", "", "X-Rateguardx", "x-rateguard-\u212a", "\u0130-rateguard-a"} {
		if got, want := isRGHeader(k), ref(k); got != want {
			t.Errorf("isRGHeader(%q) = %v, reference %v", k, got, want)
		}
	}
}
