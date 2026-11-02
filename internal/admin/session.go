package admin

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookie     = "rg_session"
	sessionIdle       = 12 * time.Hour
	sessionAbsolute   = 7 * 24 * time.Hour
	maxSessions       = 10000
	maxSessionsPerUsr = 20
)

type session struct {
	key      string // sha256 hex of the cookie value (the raw ID is never stored)
	username string
	csrf     string
	created  time.Time
	lastSeen time.Time

	pwFailures int // failed current-password checks on /api/auth/password
	pwPending  int // in-flight current-password checks
}

// maxPasswordFailures is the per-session budget of wrong current passwords
// on /api/auth/password; exhausting it destroys the session (the attacker
// must then go through the login lockout again).
const maxPasswordFailures = 5

// sessionStore is an in-memory, bounded session table keyed by the SHA-256
// of the session ID, so a memory dump or debug print never yields a usable
// cookie.
type sessionStore struct {
	mu  sync.Mutex
	m   map[string]*session
	now func() time.Time
}

func newSessionStore(now func() time.Time) *sessionStore {
	return &sessionStore{m: map[string]*session{}, now: now}
}

// create returns the raw cookie value and the new session.
func (s *sessionStore) create(username string) (string, session) {
	raw := randomToken(32)
	now := s.now()
	ss := &session{key: sha256Hex(raw), username: username, csrf: randomToken(32), created: now, lastSeen: now}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	// Per-user cap: drop that user's oldest sessions.
	var mine []*session
	for _, x := range s.m {
		if x.username == username {
			mine = append(mine, x)
		}
	}
	if len(mine) >= maxSessionsPerUsr {
		sort.Slice(mine, func(i, j int) bool { return mine[i].lastSeen.Before(mine[j].lastSeen) })
		for _, x := range mine[:len(mine)-maxSessionsPerUsr+1] {
			delete(s.m, x.key)
		}
	}
	// Global cap: drop the least recently used session.
	for len(s.m) >= maxSessions {
		var oldest *session
		for _, x := range s.m {
			if oldest == nil || x.lastSeen.Before(oldest.lastSeen) {
				oldest = x
			}
		}
		delete(s.m, oldest.key)
	}
	s.m[ss.key] = ss
	return raw, *ss
}

func (s *sessionStore) expired(x *session, now time.Time) bool {
	return now.Sub(x.lastSeen) >= sessionIdle || now.Sub(x.created) >= sessionAbsolute
}

// get validates raw and refreshes its idle timer.
func (s *sessionStore) get(raw string) (session, bool) {
	if raw == "" || len(raw) > 128 {
		return session{}, false
	}
	key := sha256Hex(raw)
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.m[key]
	if !ok {
		return session{}, false
	}
	if s.expired(x, now) {
		delete(s.m, key)
		return session{}, false
	}
	x.lastSeen = now
	return *x, true
}

// valid reports whether the session (by key) still exists, without touching it.
func (s *sessionStore) valid(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.m[key]
	return ok && !s.expired(x, s.now())
}

// beginPasswordCheck reserves one current-password verification for the
// session; false if the session is gone or its budget is used up.
func (s *sessionStore) beginPasswordCheck(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.m[key]
	if !ok || x.pwFailures+x.pwPending >= maxPasswordFailures {
		return false
	}
	x.pwPending++
	return true
}

// finishPasswordCheck settles a reservation; on the last allowed failure the
// session is destroyed.
func (s *sessionStore) finishPasswordCheck(key string, failed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.m[key]
	if !ok {
		return
	}
	x.pwPending--
	if failed {
		x.pwFailures++
		if x.pwFailures >= maxPasswordFailures {
			delete(s.m, key)
		}
	}
}

func (s *sessionStore) delete(key string) {
	s.mu.Lock()
	delete(s.m, key)
	s.mu.Unlock()
}

// deleteUser removes every session of username except exceptKey.
func (s *sessionStore) deleteUser(username, exceptKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, x := range s.m {
		if x.username == username && k != exceptKey {
			delete(s.m, k)
		}
	}
}

func (s *sessionStore) prune() {
	s.mu.Lock()
	s.pruneLocked(s.now())
	s.mu.Unlock()
}

func (s *sessionStore) pruneLocked(now time.Time) {
	for k, x := range s.m {
		if s.expired(x, now) {
			delete(s.m, k)
		}
	}
}

func (s *sessionStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// ---------------------------------------------------------------------
// Login brute-force protection
// ---------------------------------------------------------------------

const (
	lockoutThreshold = 5
	lockoutBase      = 30 * time.Second
	lockoutMax       = 15 * time.Minute
	lockoutForget    = 30 * time.Minute // failures older than this (and not locked) are forgotten
	lockoutMaxKeys   = 10000
)

type lockEntry struct {
	failures    int
	pending     int // attempts reserved but not yet finished (in-flight verifies)
	lockedUntil time.Time
	last        time.Time
}

// lockout tracks failed logins per username and per client IP (IPv6
// bucketed by /64). After 5 failures the key is locked for 30s, doubling per
// further failure up to 15m. Unknown usernames are tracked exactly like
// known ones so lockout behaviour does not reveal which accounts exist.
//
// Attempts are reserved atomically BEFORE the slow password verification
// (begin) and finalised after it (finish), so parallel requests cannot all
// pass the check while earlier failures are still being verified: at most
// threshold-failures attempts may be in flight below the threshold, and at
// most one once a lock has expired.
type lockout struct {
	mu    sync.Mutex
	users map[string]*lockEntry
	ips   map[string]*lockEntry
	now   func() time.Time
}

func newLockout(now func() time.Time) *lockout {
	return &lockout{users: map[string]*lockEntry{}, ips: map[string]*lockEntry{}, now: now}
}

func lockUserKey(u string) string {
	u = strings.ToLower(u)
	if len(u) > 128 {
		u = sha256Hex(u) // bounded key size
	}
	return u
}

// lockIPKey buckets IPv6 addresses by /64 (one subscriber allocation) so an
// attacker cannot rotate through their prefix to evade the per-IP limit.
func lockIPKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	p, err := addr.Prefix(64)
	if err != nil {
		return addr.String()
	}
	return p.String()
}

// waitLocked returns how long e blocks a new attempt (0 = may proceed).
func (l *lockout) waitLocked(e *lockEntry, now time.Time) time.Duration {
	if e == nil {
		return 0
	}
	if e.lockedUntil.After(now) {
		return e.lockedUntil.Sub(now)
	}
	if e.failures < lockoutThreshold {
		if e.failures+e.pending >= lockoutThreshold {
			return lockoutBase // budget fully reserved by in-flight attempts
		}
		return 0
	}
	if e.pending > 0 { // lock expired: one probe at a time
		return lockoutBase
	}
	return 0
}

// forgettable reports whether e carries no live state.
func forgettable(e *lockEntry, now time.Time) bool {
	return e.pending == 0 && !e.lockedUntil.After(now) && now.Sub(e.last) > lockoutForget
}

// entryLocked returns (creating if needed) the entry for key; nil means the
// table is full of live entries and the attempt must be refused.
func (l *lockout) entryLocked(m map[string]*lockEntry, key string, now time.Time) *lockEntry {
	e := m[key]
	if e != nil {
		if forgettable(e, now) {
			*e = lockEntry{}
		}
		return e
	}
	if len(m) >= lockoutMaxKeys && !l.evict(m, now) {
		return nil
	}
	e = &lockEntry{last: now}
	m[key] = e
	return e
}

// evict frees space: forgettable entries first, else the least recently
// failed entry that is neither locked nor in flight. Never evicts a locked
// entry; returns false if nothing could be evicted.
func (l *lockout) evict(m map[string]*lockEntry, now time.Time) bool {
	var oldestK string
	var oldest *lockEntry
	freed := false
	for k, e := range m {
		if forgettable(e, now) {
			delete(m, k)
			freed = true
			continue
		}
		if e.pending > 0 || e.lockedUntil.After(now) {
			continue
		}
		if oldest == nil || e.last.Before(oldest.last) {
			oldest, oldestK = e, k
		}
	}
	if freed {
		return true
	}
	if oldest != nil {
		delete(m, oldestK)
		return true
	}
	return false
}

// attempt is a reserved login attempt; exactly one of fail/succeed must be
// called (extra calls are no-ops).
type attempt struct {
	l        *lockout
	ue, ie   *lockEntry
	finished bool
}

// begin reserves an attempt for (username, ip). If blocked it returns the
// remaining wait and a nil attempt.
func (l *lockout) begin(username, ip string) (*attempt, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	uk, ik := lockUserKey(username), lockIPKey(ip)
	if d := max(l.waitLocked(l.users[uk], now), l.waitLocked(l.ips[ik], now)); d > 0 {
		return nil, d
	}
	ue := l.entryLocked(l.users, uk, now)
	ie := l.entryLocked(l.ips, ik, now)
	if ue == nil || ie == nil {
		return nil, lockoutBase // table saturated by live entries: fail closed
	}
	ue.pending++
	ie.pending++
	return &attempt{l: l, ue: ue, ie: ie}, 0
}

func (a *attempt) fail() {
	l := a.l
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.finished {
		return
	}
	a.finished = true
	for _, e := range []*lockEntry{a.ue, a.ie} {
		e.pending--
		e.failures++
		e.last = now
		if e.failures >= lockoutThreshold {
			d := lockoutMax
			if shift := e.failures - lockoutThreshold; shift < 10 {
				d = min(lockoutBase<<shift, lockoutMax)
			}
			e.lockedUntil = now.Add(d)
		}
	}
}

// succeed clears the username's failures. The IP record keeps its failures
// so a valid account cannot be used to reset an IP that is guessing others.
func (a *attempt) succeed() {
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.finished {
		return
	}
	a.finished = true
	a.ie.pending--
	a.ue.pending--
	a.ue.failures = 0
	a.ue.lockedUntil = time.Time{}
}

// abort releases the reservation without counting it (e.g. request cancelled).
func (a *attempt) abort() {
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.finished {
		return
	}
	a.finished = true
	a.ue.pending--
	a.ie.pending--
}
