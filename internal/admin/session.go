package admin

import (
	"hash/fnv"
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
	lockoutThreshold         = 5
	lockoutOverflowThreshold = 20 // shared overflow buckets tolerate more before locking
	lockoutBase              = 30 * time.Second
	lockoutMax               = 15 * time.Minute
	lockoutForget            = 30 * time.Minute // failures older than this (and not locked) are forgotten
	lockoutMaxKeys           = 10000            // per-IP table cap
	lockoutOverflowBuckets   = 1024
	lockoutEvictSample       = 64 // entries inspected per eviction (bounded work)
)

type lockEntry struct {
	failures    int
	pending     int // attempts reserved but not yet finished (in-flight verifies)
	lockedUntil time.Time
	last        time.Time
	threshold   int // failures before locking; 0 => lockoutThreshold
}

func (e *lockEntry) limit() int {
	if e.threshold > 0 {
		return e.threshold
	}
	return lockoutThreshold
}

// lockout tracks failed logins in two dimensions:
//
//   - per username, only for usernames that exist in auth.json, so the table
//     is bounded by the real user count and cannot be flooded with junk
//     names. Failures for unknown usernames count against the IP only (they
//     still take the equal-time dummy-hash path).
//   - per client IP (IPv6 bucketed by /64), capped at 10k entries. When the
//     table is full and a bounded sample finds nothing evictable, the new IP
//     is mapped (FNV) onto one of 1024 shared overflow buckets with a higher
//     threshold. A new IP is never refused outright, and a locked or
//     in-flight entry is never evicted.
//
// After the threshold the key locks for 30s, doubling per further failure up
// to 15m. Attempts are reserved atomically BEFORE the slow password
// verification (begin) and finalised after it (fail/succeed/abort), so
// parallel requests cannot slip past the check while earlier failures are
// still being verified.
type lockout struct {
	mu       sync.Mutex
	users    map[string]*lockEntry
	ips      map[string]*lockEntry
	overflow [lockoutOverflowBuckets]*lockEntry
	now      func() time.Time
}

func newLockout(now func() time.Time) *lockout {
	return &lockout{users: map[string]*lockEntry{}, ips: map[string]*lockEntry{}, now: now}
}

func lockUserKey(u string) string { return strings.ToLower(u) }

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
func waitLocked(e *lockEntry, now time.Time) time.Duration {
	if e == nil {
		return 0
	}
	if e.lockedUntil.After(now) {
		return e.lockedUntil.Sub(now)
	}
	if e.failures < e.limit() {
		if e.failures+e.pending >= e.limit() {
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

func refresh(e *lockEntry, now time.Time) {
	if forgettable(e, now) {
		*e = lockEntry{threshold: e.threshold, last: now}
	}
}

// userEntry returns the entry for a known username (created on demand).
func (l *lockout) userEntry(key string, now time.Time) *lockEntry {
	e := l.users[key]
	if e == nil {
		e = &lockEntry{last: now}
		l.users[key] = e
	}
	refresh(e, now)
	return e
}

// ipEntry returns (creating if needed) the entry that tracks key.
func (l *lockout) ipEntry(key string, now time.Time) *lockEntry {
	if e := l.ips[key]; e != nil {
		refresh(e, now)
		return e
	}
	if len(l.ips) < lockoutMaxKeys || l.evictIP(now) {
		e := &lockEntry{last: now}
		l.ips[key] = e
		return e
	}
	i := overflowIndex(key)
	if l.overflow[i] == nil {
		l.overflow[i] = &lockEntry{threshold: lockoutOverflowThreshold, last: now}
	}
	refresh(l.overflow[i], now)
	return l.overflow[i]
}

func overflowIndex(key string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() % lockoutOverflowBuckets)
}

// evictIP inspects at most lockoutEvictSample entries (Go map iteration
// order is randomised) and removes a forgettable one, else the least
// recently failed unlocked idle one. Locked or in-flight entries are never
// evicted. Returns false if the sample held nothing evictable.
func (l *lockout) evictIP(now time.Time) bool {
	var oldestK string
	var oldest *lockEntry
	n := 0
	for k, e := range l.ips {
		if n++; n > lockoutEvictSample {
			break
		}
		if forgettable(e, now) {
			delete(l.ips, k)
			return true
		}
		if e.pending > 0 || e.lockedUntil.After(now) {
			continue
		}
		if oldest == nil || e.last.Before(oldest.last) {
			oldest, oldestK = e, k
		}
	}
	if oldest != nil {
		delete(l.ips, oldestK)
		return true
	}
	return false
}

// attempt is a reserved login attempt; exactly one of fail/succeed/abort
// takes effect (extra calls are no-ops).
type attempt struct {
	l        *lockout
	ue, ie   *lockEntry // ue is nil for unknown usernames
	finished bool
}

func (a *attempt) entries() []*lockEntry {
	if a.ue == nil {
		return []*lockEntry{a.ie}
	}
	return []*lockEntry{a.ue, a.ie}
}

// begin reserves an attempt. knownUser selects whether the per-username
// dimension applies. If blocked it returns the remaining wait and nil.
func (l *lockout) begin(username string, knownUser bool, ip string) (*attempt, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	uk, ik := lockUserKey(username), lockIPKey(ip)
	if knownUser {
		if d := waitLocked(l.users[uk], now); d > 0 {
			return nil, d
		}
	}
	// Own entry, a freshly evicted slot, or a shared overflow bucket.
	a := &attempt{l: l, ie: l.ipEntry(ik, now)}
	if d := waitLocked(a.ie, now); d > 0 {
		return nil, d
	}
	if knownUser {
		a.ue = l.userEntry(uk, now)
	}
	for _, e := range a.entries() {
		e.pending++
	}
	return a, 0
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
	for _, e := range a.entries() {
		e.pending--
		e.failures++
		e.last = now
		if e.failures >= e.limit() {
			d := lockoutMax
			if shift := e.failures - e.limit(); shift < 10 {
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
	if a.ue != nil {
		a.ue.pending--
		a.ue.failures = 0
		a.ue.lockedUntil = time.Time{}
	}
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
	for _, e := range a.entries() {
		e.pending--
	}
}

// forgetUser drops a deleted user's lockout state.
func (l *lockout) forgetUser(username string) {
	l.mu.Lock()
	delete(l.users, lockUserKey(username))
	l.mu.Unlock()
}
