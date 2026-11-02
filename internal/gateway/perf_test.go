package gateway

import (
	"net/http"
	"reflect"
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
		{cp: plain, params: ratelimit.Params{Limit: 7, Window: time.Minute}, dec: dec},              // limit override
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
