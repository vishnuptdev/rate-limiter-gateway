package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Roles. Rank order matters: a higher rank includes every lower one.
const (
	RoleViewer = "viewer"
	RoleEditor = "editor"
	RoleAdmin  = "admin"
)

// Token scopes.
const (
	ScopeAdmin = "admin"
	ScopeRead  = "read"
	ScopeCheck = "check"
)

const (
	rankNone   = 0
	rankViewer = 1
	rankEditor = 2
	rankAdmin  = 3
)

func roleRank(role string) int {
	switch role {
	case RoleViewer:
		return rankViewer
	case RoleEditor:
		return rankEditor
	case RoleAdmin:
		return rankAdmin
	}
	return rankNone
}

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.@-]{0,63}$`)

const (
	maxUsers  = 1000
	maxTokens = 1000
	tokenLen  = 40 // base62 chars after "rgt_"
)

// user is the persisted record. PasswordHash never leaves this package's
// persistence layer (API responses use userView).
type user struct {
	Username           string     `json:"username"`
	Role               string     `json:"role"`
	PasswordHash       string     `json:"password_hash"`
	MustChangePassword bool       `json:"must_change_password"`
	CreatedAt          time.Time  `json:"created_at"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
}

type userView struct {
	Username           string     `json:"username"`
	Role               string     `json:"role"`
	MustChangePassword bool       `json:"must_change_password"`
	CreatedAt          time.Time  `json:"created_at"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
}

func (u *user) view() userView {
	return userView{u.Username, u.Role, u.MustChangePassword, u.CreatedAt, u.LastLoginAt}
}

// apiToken is the persisted token record; only the SHA-256 of the token is
// stored.
type apiToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	Prefix     string     `json:"prefix"`
	Hash       string     `json:"hash"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// tokenView is the API representation (no hash).
type tokenView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type tokenEntry struct {
	apiToken
	lastUsed atomic.Int64 // unix nanos; 0 = never (hot path, lock-free)
}

func (t *tokenEntry) snapshot() apiToken {
	out := t.apiToken
	out.Scopes = slices.Clone(t.Scopes)
	if n := t.lastUsed.Load(); n > 0 {
		lu := time.Unix(0, n).UTC()
		out.LastUsedAt = &lu
	}
	return out
}

func (t *tokenEntry) view() tokenView {
	s := t.snapshot()
	return tokenView{s.ID, s.Name, s.Scopes, s.Prefix, s.CreatedAt, s.CreatedBy, s.ExpiresAt, s.LastUsedAt}
}

func (t *apiToken) rank() int {
	if slices.Contains(t.Scopes, ScopeAdmin) {
		return rankAdmin
	}
	if slices.Contains(t.Scopes, ScopeRead) {
		return rankViewer
	}
	return rankNone
}

// hasScope: the admin scope implies every other scope.
func (t *apiToken) hasScope(scope string) bool {
	return slices.Contains(t.Scopes, ScopeAdmin) || slices.Contains(t.Scopes, scope)
}

type authFile struct {
	Users  []user     `json:"users"`
	Tokens []apiToken `json:"tokens"`
}

// authStore holds users and API tokens, persisted to <dataDir>/auth.json
// (0600, atomic temp+fsync+rename).
type authStore struct {
	mu     sync.RWMutex
	path   string
	now    func() time.Time
	users  map[string]*user
	tokens map[string]*tokenEntry // by ID
	byHash map[string]*tokenEntry // by sha256 hex of plaintext
}

var (
	errNotFound  = errors.New("not found")
	errExists    = errors.New("already exists")
	errLastAdmin = errors.New("cannot remove the last admin")
	errLimit     = errors.New("limit reached")
)

func loadAuthStore(path string, now func() time.Time) (*authStore, error) {
	a := &authStore{path: path, now: now, users: map[string]*user{}, tokens: map[string]*tokenEntry{}, byHash: map[string]*tokenEntry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read auth file: %w", err)
	}
	var f authFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse auth file %s: %w", path, err)
	}
	if err := a.install(f); err != nil {
		return nil, fmt.Errorf("auth file %s: %w", path, err)
	}
	return a, nil
}

func (a *authStore) install(f authFile) error {
	users := map[string]*user{}
	for i := range f.Users {
		u := f.Users[i]
		if !usernameRe.MatchString(u.Username) || roleRank(u.Role) == rankNone {
			return fmt.Errorf("invalid user record %q", u.Username)
		}
		if _, _, _, err := parseHash(u.PasswordHash); err != nil {
			return fmt.Errorf("user %q: %w", u.Username, err)
		}
		if _, dup := users[u.Username]; dup {
			return fmt.Errorf("duplicate user %q", u.Username)
		}
		users[u.Username] = &u
	}
	tokens := map[string]*tokenEntry{}
	byHash := map[string]*tokenEntry{}
	for _, t := range f.Tokens {
		e := &tokenEntry{apiToken: t}
		e.LastUsedAt = nil
		if t.LastUsedAt != nil {
			e.lastUsed.Store(t.LastUsedAt.UnixNano())
		}
		if t.ID == "" || len(t.Hash) != 64 {
			return fmt.Errorf("invalid token record %q", t.ID)
		}
		tokens[t.ID] = e
		byHash[t.Hash] = e
	}
	a.users, a.tokens, a.byHash = users, tokens, byHash
	return nil
}

// export must be called with a.mu held (read or write).
func (a *authStore) export() authFile {
	f := authFile{Users: []user{}, Tokens: []apiToken{}}
	for _, u := range a.users {
		f.Users = append(f.Users, *u)
	}
	sort.Slice(f.Users, func(i, j int) bool { return f.Users[i].Username < f.Users[j].Username })
	for _, t := range a.tokens {
		f.Tokens = append(f.Tokens, t.snapshot())
	}
	sort.Slice(f.Tokens, func(i, j int) bool { return f.Tokens[i].ID < f.Tokens[j].ID })
	return f
}

// persist writes auth.json atomically. Caller holds a.mu.
func (a *authStore) persist() error {
	b, err := json.MarshalIndent(a.export(), "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(a.path, b, 0o600)
}

// mutate runs fn under the write lock and persists; if fn or persistence
// fails, the in-memory state is rolled back.
func (a *authStore) mutate(fn func() error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	backup := a.export()
	if err := fn(); err != nil {
		_ = a.install(backup)
		return err
	}
	if err := a.persist(); err != nil {
		_ = a.install(backup)
		return fmt.Errorf("persist auth file: %w", err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// ---- users ----

func (a *authStore) userCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.users)
}

func (a *authStore) getUser(username string) (user, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	u, ok := a.users[username]
	if !ok {
		return user{}, false
	}
	return *u, true
}

func (a *authStore) listUsers() []userView {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]userView, 0, len(a.users))
	for _, u := range a.users {
		out = append(out, u.view())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// adminCount must be called with a.mu held.
func (a *authStore) adminCount() int {
	n := 0
	for _, u := range a.users {
		if u.Role == RoleAdmin {
			n++
		}
	}
	return n
}

func (a *authStore) createUser(u user) error {
	return a.mutate(func() error {
		if _, ok := a.users[u.Username]; ok {
			return errExists
		}
		if len(a.users) >= maxUsers {
			return errLimit
		}
		a.users[u.Username] = &u
		return nil
	})
}

// updateUser applies fn to a copy of the user; refuses to leave zero admins.
func (a *authStore) updateUser(username string, fn func(u *user) error) (user, error) {
	var out user
	err := a.mutate(func() error {
		cur, ok := a.users[username]
		if !ok {
			return errNotFound
		}
		next := *cur
		if err := fn(&next); err != nil {
			return err
		}
		a.users[username] = &next
		if a.adminCount() == 0 {
			return errLastAdmin
		}
		out = next
		return nil
	})
	return out, err
}

func (a *authStore) deleteUser(username string) error {
	return a.mutate(func() error {
		if _, ok := a.users[username]; !ok {
			return errNotFound
		}
		delete(a.users, username)
		if a.adminCount() == 0 {
			return errLastAdmin
		}
		return nil
	})
}

// recordLogin updates last_login_at; persistence failure is non-fatal.
func (a *authStore) recordLogin(username string) error {
	_, err := a.updateUser(username, func(u *user) error {
		t := a.now().UTC()
		u.LastLoginAt = &t
		return nil
	})
	return err
}

// ---- tokens ----

// createToken returns the plaintext (shown once) and the stored view.
func (a *authStore) createToken(name string, scopes []string, expires *time.Time, createdBy string) (string, tokenView, error) {
	plain := "rgt_" + randomBase62(tokenLen)
	e := &tokenEntry{apiToken: apiToken{
		ID:        "tok_" + randomFrom(lowerAlnum, 12),
		Name:      name,
		Scopes:    scopes,
		Prefix:    plain[:12],
		Hash:      sha256Hex(plain),
		CreatedAt: a.now().UTC(),
		CreatedBy: createdBy,
		ExpiresAt: expires,
	}}
	err := a.mutate(func() error {
		if len(a.tokens) >= maxTokens {
			return errLimit
		}
		a.tokens[e.ID] = e
		a.byHash[e.Hash] = e
		return nil
	})
	if err != nil {
		return "", tokenView{}, err
	}
	return plain, e.view(), nil
}

func (a *authStore) listTokens() []tokenView {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]tokenView, 0, len(a.tokens))
	for _, t := range a.tokens {
		out = append(out, t.view())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (a *authStore) deleteToken(id string) (tokenView, error) {
	var v tokenView
	err := a.mutate(func() error {
		t, ok := a.tokens[id]
		if !ok {
			return errNotFound
		}
		v = t.view()
		delete(a.tokens, id)
		delete(a.byHash, t.Hash)
		return nil
	})
	return v, err
}

// lookupToken resolves a plaintext token to a live (unexpired) record.
// The plaintext is hashed before lookup, so map access timing reveals
// nothing useful about valid tokens.
func (a *authStore) lookupToken(plain string) (apiToken, bool) {
	if len(plain) != 4+tokenLen || plain[:4] != "rgt_" {
		return apiToken{}, false
	}
	h := sha256Hex(plain)
	a.mu.RLock()
	e, ok := a.byHash[h]
	a.mu.RUnlock()
	if !ok || !constantTimeEqual(e.Hash, h) {
		return apiToken{}, false
	}
	now := a.now()
	if e.ExpiresAt != nil && !now.Before(*e.ExpiresAt) {
		return apiToken{}, false
	}
	e.lastUsed.Store(now.UnixNano())
	return e.snapshot(), true
}

// tokenLive reports whether token id still exists and is unexpired.
func (a *authStore) tokenLive(id string) bool {
	a.mu.RLock()
	e, ok := a.tokens[id]
	a.mu.RUnlock()
	return ok && (e.ExpiresAt == nil || a.now().Before(*e.ExpiresAt))
}

// Verify implements the gateway TokenVerifier contract: a valid, unexpired
// token carrying scope (or the admin scope).
func (a *authStore) Verify(token, scope string) bool {
	t, ok := a.lookupToken(token)
	return ok && t.hasScope(scope)
}
