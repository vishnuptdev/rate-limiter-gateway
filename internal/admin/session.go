package admin

import (
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
}

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
	lockedUntil time.Time
	last        time.Time
}

// lockout tracks failed logins per username and per client IP. After 5
// failures the key is locked for 30s, doubling per further failure up to
// 15m. Unknown usernames are tracked exactly like known ones so lockout
// behaviour does not reveal which accounts exist.
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

// lockedFor returns the remaining lock time (0 if not locked).
func (l *lockout) lockedFor(username, ip string) time.Duration {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	var d time.Duration
	for _, e := range []*lockEntry{l.users[lockUserKey(username)], l.ips[ip]} {
		if e != nil && e.lockedUntil.After(now) {
			d = max(d, e.lockedUntil.Sub(now))
		}
	}
	return d
}

func (l *lockout) fail(username, ip string) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failLocked(l.users, lockUserKey(username), now)
	l.failLocked(l.ips, ip, now)
}

func (l *lockout) failLocked(m map[string]*lockEntry, key string, now time.Time) {
	e := m[key]
	if e == nil {
		if len(m) >= lockoutMaxKeys {
			l.evict(m, now)
		}
		e = &lockEntry{}
		m[key] = e
	} else if !e.lockedUntil.After(now) && now.Sub(e.last) > lockoutForget {
		*e = lockEntry{}
	}
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

// evict removes forgettable entries, or else the least recently failed one.
func (l *lockout) evict(m map[string]*lockEntry, now time.Time) {
	var oldestK string
	var oldest *lockEntry
	for k, e := range m {
		if !e.lockedUntil.After(now) && now.Sub(e.last) > lockoutForget {
			delete(m, k)
			continue
		}
		if oldest == nil || e.last.Before(oldest.last) {
			oldest, oldestK = e, k
		}
	}
	if len(m) >= lockoutMaxKeys && oldest != nil {
		delete(m, oldestK)
	}
}

// success clears the username's failure record. The IP record is kept so a
// valid account cannot be used to reset an IP that is guessing others.
func (l *lockout) success(username string) {
	l.mu.Lock()
	delete(l.users, lockUserKey(username))
	l.mu.Unlock()
}
