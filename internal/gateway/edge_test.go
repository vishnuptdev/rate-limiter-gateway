package gateway

import (
	"net/netip"
	"net/url"
	"testing"
)

// Pins cleanPath on the edge cases its fast path must not change.
func TestCleanPathEdgeCases(t *testing.T) {
	for _, tc := range []struct {
		path, raw string
		want      string
		ok        bool
	}{
		{"/a/b", "", "/a/b", true},
		{"", "", "/", true},
		{"/", "", "/", true},
		{"a/b", "", "/a/b", true},
		{"/a/b/", "", "/a/b/", true},
		{"/a/./b/", "", "/a/b/", true},
		{"/a/../b", "", "/b", true},
		{"/../../etc/passwd", "", "/etc/passwd", true},
		{"/a/b/..", "", "/a", true},
		{"/a/../", "", "/", true},
		{"//a//b", "", "/a/b", true},
		{"/A/B", "", "/A/B", true},
		{"/a b", "", "/a b", true},
		{"/a/b", "/a%2Fb", "", false}, // encoded slash, either case
		{"/a/b", "/a%2fb", "", false},
		{"/a\x00b", "", "", false},
		{"/a\\b", "", "", false},
		{"/a/..%2F", "", "/a/..%2F", true}, // literal '%' in the decoded path is just a character
	} {
		u := &url.URL{Path: tc.path, RawPath: tc.raw}
		got, ok := cleanPath(u)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("cleanPath(%q, raw %q) = %q, %v; want %q, %v", tc.path, tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

// Pins clientIP (including the IPv4 fast path) and the trusted XFF walk.
func TestClientIPEdgeCases(t *testing.T) {
	trusted := &compiled{trusted: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8")}}
	none := &compiled{}
	for _, tc := range []struct {
		c      *compiled
		remote string
		xff    []string
		want   string
	}{
		{none, "192.0.2.1:80", nil, "192.0.2.1"},
		{none, "192.0.2.1", nil, "192.0.2.1"},
		{none, "[2001:db8::1]:443", nil, "2001:db8::1"},
		{none, "[2001:DB8:0:0::1]:443", nil, "2001:db8::1"},
		{none, "[fe80::1%eth0]:80", nil, "fe80::1%eth0"},
		{none, "[::ffff:192.0.2.1]:80", nil, "192.0.2.1"},
		{none, "garbage", nil, "garbage"},
		{none, "192.0.2.1:80", []string{"203.0.113.9"}, "192.0.2.1"},                    // no trusted proxies: XFF ignored
		{trusted, "192.0.2.1:80", []string{"203.0.113.9"}, "192.0.2.1"},                 // untrusted peer: XFF ignored
		{trusted, "10.0.0.1:1", []string{"203.0.113.5, 10.0.0.2"}, "203.0.113.5"},       // skip trusted hops
		{trusted, "10.0.0.1:1", []string{"198.51.100.7", "10.0.0.9"}, "198.51.100.7"},   // multiple header lines
		{trusted, "10.0.0.1:1", []string{"10.0.0.3"}, "10.0.0.3"},                       // all trusted: leftmost seen
		{trusted, "10.0.0.1:1", []string{"bogus, 10.0.0.2"}, "10.0.0.2"},                // unparseable stops the walk
		{trusted, "10.0.0.1:1", []string{"1.1.1.1, bogus, 10.0.0.2"}, "10.0.0.2"},       // never trusted past garbage
		{trusted, "10.0.0.1:1", []string{" 203.0.113.5 ,, 10.0.0.2 "}, "203.0.113.5"},   // whitespace / empty entries
		{trusted, "10.0.0.1:1", nil, "10.0.0.1"},                                        // no XFF
		{trusted, "[fd00::1]:9", []string{"2001:db8::7"}, "2001:db8::7"},                // IPv6 trusted peer
		{trusted, "[::ffff:10.0.0.1]:9", []string{"::ffff:203.0.113.5"}, "203.0.113.5"}, // mapped forms unmapped
	} {
		if got := tc.c.clientIP(tc.remote, tc.xff); got != tc.want {
			t.Errorf("clientIP(%q, %q, trusted=%v) = %q, want %q", tc.remote, tc.xff, len(tc.c.trusted) > 0, got, tc.want)
		}
	}
}
