package admin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestPasswordHash(t *testing.T) {
	h, err := hashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^pbkdf2_sha256\$1000\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`).MatchString(h) {
		t.Fatalf("bad format %q", h)
	}
	h2, _ := hashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("salt not random")
	}
	cases := []struct {
		name, hash, pw string
		want           bool
	}{
		{"match", h, "correct horse battery", true},
		{"mismatch", h, "correct horse batterY", false},
		{"empty pw", h, "", false},
		{"garbage", "nope", "x", false},
		{"wrong scheme", strings.Replace(h, "pbkdf2_sha256", "md5", 1), "correct horse battery", false},
		{"absurd iterations", "pbkdf2_sha256$999999999$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "x", false},
		{"huge pw", h, strings.Repeat("a", maxPasswordLen+1), false},
	}
	for _, c := range cases {
		if got := verifyPassword(c.hash, c.pw); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	for pw, ok := range map[string]bool{"short": false, "elevenchars": false, "twelve-chars": true, "ünïcödé-12ch": true, strings.Repeat("x", 1025): false} {
		if (checkPasswordPolicy(pw) == nil) != ok {
			t.Errorf("%q: want ok=%v", pw, ok)
		}
	}
}

func TestRandomBase62(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		s := randomBase62(40)
		if len(s) != 40 || !regexp.MustCompile(`^[0-9A-Za-z]+$`).MatchString(s) || seen[s] {
			t.Fatalf("bad %q", s)
		}
		seen[s] = true
	}
}

func TestBootstrapRandomPasswordAndMustChange(t *testing.T) {
	var out bytes.Buffer
	e := newEnv(t, func(o *Options) { o.BootstrapPassword = ""; o.stderr = &out })
	m := regexp.MustCompile(`one-time password: ([0-9A-Za-z]{20})`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("password not printed: %q", out.String())
	}
	pw := m[1]

	// auth.json: 0600, contains hash but never the plaintext.
	path := filepath.Join(e.dir, "auth.json")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("auth.json perm %v", fi.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte(pw)) || !bytes.Contains(raw, []byte("pbkdf2_sha256$")) {
		t.Fatal("auth.json leaks plaintext or lacks hash")
	}

	c := e.login("admin", pw)
	me := decode[map[string]any](t, e.req("GET", "/api/auth/me", nil, c))
	if me["user"].(map[string]any)["must_change_password"] != true || me["csrf_token"] == "" {
		t.Fatalf("me: %v", me)
	}
	// Gated until the password is changed.
	for _, p := range []string{"/api/system", "/api/policies", "/api/users"} {
		if rec := e.req("GET", p, nil, c); rec.Code != 403 || errCode(t, rec) != "password_change_required" {
			t.Fatalf("%s: %d %s", p, rec.Code, rec.Body)
		}
	}
	// Weak / wrong current password rejected.
	if rec := e.req("POST", "/api/auth/password", map[string]string{"current_password": pw, "new_password": "short"}, c); rec.Code != 422 {
		t.Fatalf("weak: %d", rec.Code)
	}
	if rec := e.req("POST", "/api/auth/password", map[string]string{"current_password": "wrong-wrong-wrong", "new_password": "a-brand-new-password"}, c); rec.Code != 401 {
		t.Fatalf("wrong current: %d", rec.Code)
	}
	if rec := e.req("POST", "/api/auth/password", map[string]string{"current_password": pw, "new_password": pw}, c); rec.Code != 422 {
		t.Fatalf("same pw: %d", rec.Code)
	}
	other := e.login("admin", pw) // a second session gets revoked on change
	if rec := e.req("POST", "/api/auth/password", map[string]string{"current_password": pw, "new_password": "a-brand-new-password"}, c); rec.Code != 204 {
		t.Fatalf("change: %d %s", rec.Code, rec.Body)
	}
	if rec := e.req("GET", "/api/system", nil, c); rec.Code != 200 {
		t.Fatalf("after change: %d", rec.Code)
	}
	if rec := e.req("GET", "/api/auth/me", nil, other); rec.Code != 401 {
		t.Fatalf("other session survived password change: %d", rec.Code)
	}
	if rec := e.req("POST", "/api/auth/login", map[string]string{"username": "admin", "password": pw}, cred{}); rec.Code != 401 {
		t.Fatal("old password still works")
	}

	// Restart: users persist, no second bootstrap.
	out.Reset()
	s2, err := New(Options{DataDir: e.dir, Store: e.store, Runtime: e.rt, stderr: &out})
	if err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 || s2.auth.userCount() != 1 {
		t.Fatal("re-bootstrapped on restart")
	}
}

func TestBootstrapPasswordPolicy(t *testing.T) {
	_, err := New(Options{DataDir: t.TempDir(), Store: &fakeStore{}, Runtime: &fakeRuntime{}, BootstrapPassword: "short"})
	if err == nil {
		t.Fatal("short bootstrap password accepted")
	}
	if _, err := New(Options{Store: &fakeStore{}, Runtime: &fakeRuntime{}}); err == nil {
		t.Fatal("missing DataDir accepted")
	}
}

func TestLoginErrorsAreGeneric(t *testing.T) {
	e := newEnv(t)
	a := e.req("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "wrong-password!"}, cred{})
	b := e.req("POST", "/api/auth/login", map[string]string{"username": "ghost", "password": "wrong-password!"}, cred{})
	if a.Code != 401 || b.Code != 401 || a.Body.String() != b.Body.String() {
		t.Fatalf("known=%d %s unknown=%d %s", a.Code, a.Body, b.Code, b.Body)
	}
	if len(a.Result().Cookies()) != 0 {
		t.Fatal("cookie set on failed login")
	}
}

func TestLoginLockout(t *testing.T) {
	cases := []struct {
		name     string
		username string
		ips      func(i int) string
		victim   string // user whose correct login is then attempted
		victimIP string
		locked   bool
	}{
		{"per-username", "admin", func(i int) string { return "198.51.100." + itoa64(int64(i+1)) + ":1" }, "admin", "203.0.113.9:1", true},
		{"per-ip", "", func(int) string { return "198.51.100.7:1" }, "admin", "198.51.100.7:2", true},
		{"other ip other user unaffected", "ghost", func(int) string { return "198.51.100.7:1" }, "admin", "203.0.113.9:1", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			for i := range 5 {
				u := c.username
				if u == "" {
					u = "user" + itoa64(int64(i)) // spraying different usernames from one IP
				}
				rec := e.req("POST", "/api/auth/login", map[string]string{"username": u, "password": "bad-password-xx"}, cred{},
					func(r *http.Request) { r.RemoteAddr = c.ips(i) })
				if rec.Code != 401 {
					t.Fatalf("attempt %d: %d", i, rec.Code)
				}
			}
			rec := e.req("POST", "/api/auth/login", map[string]string{"username": c.victim, "password": adminPW}, cred{},
				func(r *http.Request) { r.RemoteAddr = c.victimIP })
			if c.locked {
				if rec.Code != 429 || errCode(t, rec) != "locked_out" || rec.Header().Get("Retry-After") != "30" {
					t.Fatalf("want lockout, got %d %s ra=%q", rec.Code, rec.Body, rec.Header().Get("Retry-After"))
				}
				e.clock.Advance(31 * time.Second)
				rec = e.req("POST", "/api/auth/login", map[string]string{"username": c.victim, "password": adminPW}, cred{},
					func(r *http.Request) { r.RemoteAddr = c.victimIP })
			}
			if rec.Code != 200 {
				t.Fatalf("want success, got %d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestLockoutBackoff(t *testing.T) {
	c := newClock()
	l := newLockout(c.Now)
	want := []time.Duration{0, 0, 0, 0, 30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute, 15 * time.Minute}
	for i, w := range want {
		l.fail("bob", "10.0.0.1")
		if got := l.lockedFor("bob", "10.0.0.9"); got != w {
			t.Fatalf("failure %d: locked %v want %v", i+1, got, w)
		}
	}
	l.success("bob")
	if l.lockedFor("bob", "10.0.0.9") != 0 {
		t.Fatal("success did not clear username lock")
	}
	if l.lockedFor("alice", "10.0.0.1") == 0 {
		t.Fatal("success must not clear the IP lock")
	}
	// Bounded memory.
	for i := range lockoutMaxKeys + 50 {
		l.fail("u"+itoa64(int64(i)), "10.1.0.1")
	}
	if len(l.users) > lockoutMaxKeys {
		t.Fatalf("lockout map unbounded: %d", len(l.users))
	}
}

func TestSessionLifecycle(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin", adminPW)
	if rec := e.req("GET", "/api/auth/me", nil, c); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	// Session IDs are stored hashed only.
	for k := range e.s.sessions.m {
		if k == c.cookie || k != sha256Hex(c.cookie) {
			t.Fatal("session stored by raw id")
		}
	}
	// Idle timeout.
	e.clock.Advance(sessionIdle - time.Minute)
	if rec := e.req("GET", "/api/auth/me", nil, c); rec.Code != 200 {
		t.Fatal("expired too early")
	}
	e.clock.Advance(sessionIdle + time.Second)
	rec := e.req("GET", "/api/auth/me", nil, c)
	if rec.Code != 401 {
		t.Fatalf("idle session alive: %d", rec.Code)
	}
	if ck := rec.Result().Cookies(); len(ck) != 1 || ck[0].MaxAge >= 0 {
		t.Fatal("expired cookie not cleared")
	}
	// Absolute timeout even when active.
	c = e.login("admin", adminPW)
	for range 16 { // 176h > 7d, never idle > 12h
		e.clock.Advance(11 * time.Hour)
		e.req("GET", "/api/auth/me", nil, c)
	}
	if rec := e.req("GET", "/api/auth/me", nil, c); rec.Code != 401 {
		t.Fatal("absolute timeout not enforced")
	}
	// Logout.
	c = e.login("admin", adminPW)
	if rec := e.req("POST", "/api/auth/logout", nil, c); rec.Code != 204 {
		t.Fatalf("logout %d", rec.Code)
	}
	if rec := e.req("GET", "/api/auth/me", nil, c); rec.Code != 401 {
		t.Fatal("session alive after logout")
	}
	// Garbage cookie.
	if rec := e.req("GET", "/api/auth/me", nil, cred{cookie: "forged"}); rec.Code != 401 {
		t.Fatal("forged cookie accepted")
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	for _, secure := range []bool{false, true} {
		e := newEnv(t, func(o *Options) { o.CookieSecure = secure })
		rec := e.req("POST", "/api/auth/login", map[string]string{"username": "admin", "password": adminPW}, cred{})
		ck := rec.Result().Cookies()[0]
		if ck.Name != "rg_session" || !ck.HttpOnly || ck.SameSite != 3 /* Strict */ || ck.Path != "/" || ck.Secure != secure {
			t.Fatalf("cookie attrs: %+v", ck)
		}
		if len(ck.Value) < 43 {
			t.Fatal("session id too short")
		}
	}
}

func TestCSRFAndOrigin(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin", adminPW)
	body := map[string]any{"name": "x", "algorithm": "fixed_window", "limit": 1, "window": "1s", "key_by": []string{"ip"}}
	cases := []struct {
		name string
		c    cred
		opts []reqOpt
		want int
	}{
		{"no token", cred{cookie: c.cookie}, nil, 403},
		{"wrong token", cred{cookie: c.cookie, csrf: c.csrf + "x"}, nil, 403},
		{"other session's token", cred{cookie: c.cookie, csrf: e.login("admin", adminPW).csrf}, nil, 403},
		{"valid token", c, nil, 201},
		{"valid token cross-site fetch", c, []reqOpt{withHeader("Sec-Fetch-Site", "cross-site")}, 403},
		{"valid token same-site sibling", c, []reqOpt{withHeader("Sec-Fetch-Site", "same-site")}, 403},
		{"valid token foreign origin", c, []reqOpt{withHeader("Origin", "https://evil.example")}, 403},
		{"valid token null origin", c, []reqOpt{withHeader("Origin", "null")}, 403},
		{"valid token same origin", c, []reqOpt{withHeader("Origin", "http://admin.local"), withHeader("Sec-Fetch-Site", "same-origin")}, 201},
	}
	for _, tc := range cases {
		rec := e.req("POST", "/api/policies", body, tc.c, tc.opts...)
		if rec.Code != tc.want {
			t.Errorf("%s: got %d %s", tc.name, rec.Code, rec.Body)
		}
	}
	// Bearer tokens need no CSRF (no ambient credentials).
	tok := e.token("ci", ScopeAdmin)
	if rec := e.req("POST", "/api/policies", body, cred{bearer: tok}, withHeader("Origin", "https://ci.example")); rec.Code != 201 {
		t.Fatalf("bearer: %d %s", rec.Code, rec.Body)
	}
	// Login CSRF: cross-site login and form-encoded login are refused.
	if rec := e.req("POST", "/api/auth/login", map[string]string{"username": "admin", "password": adminPW}, cred{}, withHeader("Sec-Fetch-Site", "cross-site")); rec.Code != 403 {
		t.Fatalf("cross-site login: %d", rec.Code)
	}
	if rec := e.req("POST", "/api/auth/login", `{"username":"admin","password":"`+adminPW+`"}`, cred{}, withHeader("Content-Type", "text/plain")); rec.Code != 415 {
		t.Fatalf("text/plain login: %d", rec.Code)
	}
	// GETs don't need CSRF.
	if rec := e.req("GET", "/api/policies", nil, cred{cookie: c.cookie}); rec.Code != 200 {
		t.Fatalf("GET: %d", rec.Code)
	}
}

func TestTokens(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin", adminPW)
	rec := e.req("POST", "/api/tokens", map[string]any{"name": "ci", "scopes": []string{"read", "check", "read"}}, c)
	if rec.Code != 201 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	out := decode[struct {
		Token string         `json:"token"`
		Info  map[string]any `json:"info"`
	}](t, rec)
	if !regexp.MustCompile(`^rgt_[0-9A-Za-z]{40}$`).MatchString(out.Token) {
		t.Fatalf("token format %q", out.Token)
	}
	if _, has := out.Info["hash"]; has {
		t.Fatal("hash exposed")
	}
	if got := out.Info["scopes"].([]any); len(got) != 2 {
		t.Fatalf("scopes not deduped: %v", got)
	}
	// Plaintext never again: not in list, not on disk, only the hash.
	list := e.req("GET", "/api/tokens", nil, c).Body.String()
	raw, _ := os.ReadFile(filepath.Join(e.dir, "auth.json"))
	sum := sha256.Sum256([]byte(out.Token))
	if strings.Contains(list, out.Token) || strings.Contains(string(raw), out.Token) || !strings.Contains(string(raw), hex.EncodeToString(sum[:])) {
		t.Fatal("token plaintext leaked or hash missing")
	}

	ver := e.s.Tokens()
	for _, tc := range []struct {
		tok, scope string
		want       bool
	}{
		{out.Token, ScopeRead, true}, {out.Token, ScopeCheck, true}, {out.Token, ScopeAdmin, false},
		{out.Token + "x", ScopeRead, false}, {"", ScopeCheck, false}, {"rgt_" + strings.Repeat("A", 40), ScopeCheck, false},
	} {
		if got := ver.Verify(tc.tok, tc.scope); got != tc.want {
			t.Errorf("Verify(%q,%s)=%v", tc.tok, tc.scope, got)
		}
	}
	adminTok := e.token("root", ScopeAdmin)
	if !ver.Verify(adminTok, ScopeCheck) || !ver.Verify(adminTok, ScopeRead) {
		t.Error("admin scope should imply others")
	}

	// read token: viewer access only.
	if rec := e.req("GET", "/api/policies", nil, cred{bearer: out.Token}); rec.Code != 200 {
		t.Fatalf("read GET %d", rec.Code)
	}
	if rec := e.req("DELETE", "/api/policies/p2", nil, cred{bearer: out.Token}); rec.Code != 403 {
		t.Fatalf("read DELETE %d", rec.Code)
	}
	// check-only token: no admin plane at all.
	chk := e.token("svc", ScopeCheck)
	if rec := e.req("GET", "/api/policies", nil, cred{bearer: chk}); rec.Code != 403 {
		t.Fatalf("check GET %d", rec.Code)
	}
	if rec := e.req("GET", "/api/auth/me", nil, cred{bearer: chk}); rec.Code != 403 {
		t.Fatalf("check me %d", rec.Code)
	}
	// Invalid bearer never falls back to the cookie.
	if rec := e.req("GET", "/api/policies", nil, cred{cookie: c.cookie, bearer: "rgt_nope"}); rec.Code != 401 {
		t.Fatalf("bad bearer + cookie: %d", rec.Code)
	}
	// Expiry.
	exp := e.clock.Now().Add(time.Hour)
	rec = e.req("POST", "/api/tokens", map[string]any{"name": "tmp", "scopes": []string{"read"}, "expires_at": exp}, c)
	tmp := decode[struct{ Token string }](t, rec).Token
	if rec := e.req("GET", "/api/policies", nil, cred{bearer: tmp}); rec.Code != 200 {
		t.Fatal("fresh token rejected")
	}
	e.clock.Advance(time.Hour)
	if rec := e.req("GET", "/api/policies", nil, cred{bearer: tmp}); rec.Code != 401 || ver.Verify(tmp, ScopeRead) {
		t.Fatal("expired token accepted")
	}
	// Validation.
	for _, bad := range []map[string]any{
		{"name": "", "scopes": []string{"read"}},
		{"name": "x", "scopes": []string{}},
		{"name": "x", "scopes": []string{"superuser"}},
		{"name": "x", "scopes": []string{"read"}, "expires_at": e.clock.Now().Add(-time.Second)},
	} {
		if rec := e.req("POST", "/api/tokens", bad, c); rec.Code != 400 {
			t.Errorf("%v: %d", bad, rec.Code)
		}
	}
	// Delete revokes immediately.
	id := out.Info["id"].(string)
	if rec := e.req("DELETE", "/api/tokens/"+id, nil, c); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	if ver.Verify(out.Token, ScopeRead) {
		t.Fatal("deleted token still valid")
	}
	if rec := e.req("DELETE", "/api/tokens/"+id, nil, c); rec.Code != 404 {
		t.Fatal("double delete")
	}
}

func TestUsersAdmin(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin", adminPW)
	rec := e.req("POST", "/api/users", map[string]any{"username": "bob", "role": "editor", "password": "bob-initial-pass"}, c)
	if rec.Code != 201 || strings.Contains(rec.Body.String(), "password") && strings.Contains(rec.Body.String(), "pbkdf2") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if u := decode[map[string]any](t, rec); u["must_change_password"] != true {
		t.Fatal("admin-created users must change password by default")
	}
	if rec := e.req("GET", "/api/users", nil, c); strings.Contains(rec.Body.String(), "pbkdf2") {
		t.Fatal("hash exposed in user list")
	}
	for _, bad := range []map[string]any{
		{"username": "Bob!", "role": "editor", "password": "bob-initial-pass"},
		{"username": "carol", "role": "root", "password": "bob-initial-pass"},
		{"username": "carol", "role": "viewer", "password": "short"},
		{"username": "bob", "role": "viewer", "password": "bob-initial-pass"},
		{"username": "dan", "role": "viewer", "password": "bob-initial-pass", "is_admin": true},
	} {
		if rec := e.req("POST", "/api/users", bad, c); rec.Code < 400 || rec.Code == 500 {
			t.Errorf("%v: %d", bad, rec.Code)
		}
	}
	bob := e.login("bob", "bob-initial-pass")
	// Last-admin and self protections.
	if rec := e.req("PUT", "/api/users/admin", map[string]any{"role": "viewer"}, c); rec.Code != 409 {
		t.Fatalf("demote last admin: %d", rec.Code)
	}
	if rec := e.req("DELETE", "/api/users/admin", nil, c); rec.Code != 409 {
		t.Fatalf("delete self: %d", rec.Code)
	}
	tok := e.token("root", ScopeAdmin)
	if rec := e.req("DELETE", "/api/users/admin", nil, cred{bearer: tok}); rec.Code != 409 {
		t.Fatalf("delete last admin via token: %d", rec.Code)
	}
	// Password reset revokes the user's sessions.
	if rec := e.req("PUT", "/api/users/bob", map[string]any{"password": "bob-reset-password"}, c); rec.Code != 200 {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	if rec := e.req("GET", "/api/auth/me", nil, bob); rec.Code != 401 {
		t.Fatal("bob's session survived reset")
	}
	// Role change takes effect on live sessions immediately.
	bob = e.login("bob", "bob-reset-password")
	e.req("POST", "/api/auth/password", map[string]string{"current_password": "bob-reset-password", "new_password": "bob-own-password"}, bob)
	if rec := e.req("DELETE", "/api/policies/p2", nil, bob); rec.Code != 204 {
		t.Fatalf("editor delete: %d %s", rec.Code, rec.Body)
	}
	e.req("PUT", "/api/users/bob", map[string]any{"role": "viewer"}, c)
	if rec := e.req("DELETE", "/api/routes/r1", nil, bob); rec.Code != 403 {
		t.Fatalf("demoted user still editor: %d", rec.Code)
	}
	// Deleting a user kills their sessions.
	if rec := e.req("DELETE", "/api/users/bob", nil, c); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	if rec := e.req("GET", "/api/auth/me", nil, bob); rec.Code != 401 {
		t.Fatal("deleted user's session alive")
	}
}
