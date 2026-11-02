// Package admin implements the RateGuard admin plane: the REST API under
// /api, authentication (users, sessions, CSRF, API tokens, RBAC), the audit
// log, the Prometheus endpoint and serving of the embedded dashboard.
//
// Security model (see docs/ARCHITECTURE.md "Admin"):
//   - Every /api route is registered with an explicit minimum level; there is
//     no default-allow path. Unknown /api paths return 404 JSON.
//   - Browser sessions use an HttpOnly SameSite=Strict cookie plus a
//     per-session CSRF token required on every non-GET request. Additionally,
//     unsafe cookie/anonymous requests are rejected when the browser reports
//     a cross-origin or same-site (sibling subdomain) context
//     (Sec-Fetch-Site / Origin), and JSON bodies must be sent as
//     application/json (blocks simple-form CSRF, incl. login CSRF).
//   - Bearer API tokens (rgt_...) never fall back to cookies and need no CSRF.
//     Scope mapping: "admin" => admin role (implies every scope), "read" =>
//     viewer, "check" => data-plane check API only (no admin API access).
//   - Secrets (passwords, session IDs, tokens, API keys) are stored only as
//     hashes and never logged or audited.
package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/ratelimit"
	"ratelimitergateway/internal/store"
)

// Runtime is the data plane as seen by admin (implemented by *gateway.Gateway).
type Runtime interface {
	Apply(*model.Snapshot) error
	Current() *model.Snapshot
	Simulate(context.Context, model.SimRequest) model.SimResult
	EngineKey(policyID, composite string) string
}

// Telemetry is implemented by *telemetry.Hub.
type Telemetry interface {
	QueryLogs(model.LogQuery) []model.LogEntry
	Subscribe(int) (<-chan model.LogEntry, func())
	Timeseries(time.Duration, string) model.Timeseries
	Overview() model.Overview
	WritePrometheus(io.Writer)
}

// TokenVerifier is structurally identical to gateway.TokenVerifier.
type TokenVerifier interface {
	Verify(token, scope string) bool
}

// Options configures the admin server.
type Options struct {
	DataDir       string // required: holds auth.json and audit.jsonl
	Store         store.ConfigStore
	Runtime       Runtime
	Telemetry     Telemetry        // optional; telemetry endpoints return 503 when nil
	Engine        ratelimit.Engine // optional; /api/limits returns 503 when nil
	StaticFS      fs.FS            // dashboard files; nil => placeholder page
	Logger        *slog.Logger
	Version       string
	InstanceID    string
	DataPlaneAddr string
	AdminAddr     string
	CookieSecure  bool // force Secure cookies (else only when the request is TLS)
	MetricsPublic bool // serve /metrics without auth
	// BootstrapPassword is used for the initial "admin" user when auth.json
	// has no users (RLG_ADMIN_PASSWORD). It must satisfy the password policy.
	BootstrapPassword string

	// Validate, if non-nil, is run on every candidate snapshot before
	// Runtime.Apply (wire store.Validate here). When nil nothing extra runs
	// and Runtime.Apply is relied upon to validate; import dry-runs then
	// report validated=false.
	Validate func(*model.Snapshot) error
	// TrustProxyHeaders makes the admin plane honour X-Forwarded-For (right-
	// most entry, i.e. the address seen by the immediate proxy) for lockout
	// and audit IPs, X-Forwarded-Proto for HSTS/Secure cookies and
	// X-Forwarded-Host for the Origin check. Only enable behind a proxy that
	// overwrites these headers.
	TrustProxyHeaders bool

	now    func() time.Time // test hook
	stderr io.Writer        // test hook for the bootstrap password
}

// Server is the admin HTTP server.
type Server struct {
	o        Options
	log      *slog.Logger
	now      func() time.Time
	auth     *authStore
	sessions *sessionStore
	lock     *lockout
	audit    *auditLog
	mgr      *manager
	handler  http.Handler
	started  time.Time
	dummy    string        // dummy password hash for equal-time unknown-user logins
	hashSem  chan struct{} // bounds concurrent PBKDF2 work (CPU DoS guard)
	sseSem   chan struct{} // bounds concurrent SSE streams

	heartbeat time.Duration
}

const maxSSEStreams = 64

// New loads auth.json (bootstrapping an admin user if there are none) and
// the audit log, and builds the handler.
func New(o Options) (*Server, error) {
	if o.DataDir == "" {
		return nil, errors.New("admin: DataDir is required")
	}
	if o.Store == nil || o.Runtime == nil {
		return nil, errors.New("admin: Store and Runtime are required")
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.stderr == nil {
		o.stderr = os.Stderr
	}
	if err := os.MkdirAll(o.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("admin: create data dir: %w", err)
	}
	authPath := filepath.Join(o.DataDir, "auth.json")
	if fi, err := os.Stat(authPath); err == nil && fi.Mode().Perm()&0o077 != 0 {
		o.Logger.Warn("auth file is readable by group/others; tightening to 0600", "path", authPath)
		_ = os.Chmod(authPath, 0o600)
	}
	auth, err := loadAuthStore(authPath, o.now)
	if err != nil {
		return nil, fmt.Errorf("admin: %w", err)
	}
	audit, err := newAuditLog(filepath.Join(o.DataDir, "audit.jsonl"), o.now)
	if err != nil {
		return nil, fmt.Errorf("admin: %w", err)
	}
	dummy, err := hashPassword(randomBase62(24))
	if err != nil {
		return nil, err
	}
	s := &Server{
		o:         o,
		log:       o.Logger,
		now:       o.now,
		auth:      auth,
		sessions:  newSessionStore(o.now),
		lock:      newLockout(o.now),
		audit:     audit,
		started:   o.now(),
		dummy:     dummy,
		hashSem:   make(chan struct{}, max(2, runtime.NumCPU())),
		sseSem:    make(chan struct{}, maxSSEStreams),
		heartbeat: 15 * time.Second,
	}
	s.mgr = &manager{store: o.Store, rt: o.Runtime, validate: o.Validate, now: o.now, log: o.Logger}
	if err := s.bootstrap(); err != nil {
		return nil, err
	}
	s.handler = s.routes()
	return s, nil
}

func (s *Server) bootstrap() error {
	if s.auth.userCount() > 0 {
		return nil
	}
	pw, must := s.o.BootstrapPassword, false
	if pw == "" {
		pw, must = randomBase62(20), true
	} else if err := checkPasswordPolicy(pw); err != nil {
		return fmt.Errorf("admin: bootstrap password (RLG_ADMIN_PASSWORD): %w", err)
	}
	h, err := hashPassword(pw)
	if err != nil {
		return err
	}
	if err := s.auth.createUser(user{Username: "admin", Role: RoleAdmin, PasswordHash: h, MustChangePassword: must, CreatedAt: s.now().UTC()}); err != nil {
		return fmt.Errorf("admin: bootstrap user: %w", err)
	}
	if must {
		// Printed exactly once, to stderr only (never via the structured logger).
		fmt.Fprintf(s.o.stderr, "\n  RateGuard: created admin user \"admin\" with one-time password: %s\n  You will be asked to change it at first login.\n\n", pw)
	}
	_ = s.audit.add(AuditEntry{Actor: "system", ActorType: "system", Action: "user.bootstrap", TargetType: "user", TargetID: "admin", Summary: "bootstrapped initial admin user"})
	s.log.Info("bootstrapped admin user", "username", "admin", "must_change_password", must)
	return nil
}

// Handler returns the root handler (dashboard, /api, /metrics).
func (s *Server) Handler() http.Handler { return s.handler }

// Tokens returns the API-token verifier for the data-plane check API.
func (s *Server) Tokens() TokenVerifier { return s.auth }

// Start launches the store watch loop and session janitor; it returns
// immediately. Both stop when ctx is done.
func (s *Server) Start(ctx context.Context) {
	go s.o.Store.Watch(ctx, s.mgr.onWatch)
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.sessions.prune()
			}
		}
	}()
}

// ---------------------------------------------------------------------
// Request context helpers
// ---------------------------------------------------------------------

func (s *Server) clientIP(r *http.Request) string {
	if s.o.TrustProxyHeaders {
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			parts := strings.Split(xff[len(xff)-1], ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) isTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return s.o.TrustProxyHeaders && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *Server) requestHost(r *http.Request) string {
	if s.o.TrustProxyHeaders {
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			return strings.TrimSpace(strings.Split(h, ",")[0])
		}
	}
	return r.Host
}

const csp = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if s.isTLS(r) {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/metrics" {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// crossSiteRequest reports whether a browser marked the request as coming
// from another site/origin. Non-browser clients send neither header.
func (s *Server) crossSiteRequest(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "cross-site", "same-site":
		return true
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" || !strings.EqualFold(u.Host, s.requestHost(r)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------

type principal struct {
	kind       string // "user" | "token"
	name       string // username or token name
	tokenID    string
	rank       int
	mustChange bool
	viaCookie  bool
	sessionKey string
	csrf       string
}

func (p *principal) actorType() string { return p.kind }
func (p *principal) actor() string {
	if p.kind == "token" {
		return p.name + " (" + p.tokenID + ")"
	}
	return p.name
}

var errUnauthenticated = &apiError{Status: http.StatusUnauthorized, Code: "unauthorized", Message: "authentication required"}

// authenticate returns (nil, nil) for anonymous requests and an error for
// presented-but-invalid credentials.
func (s *Server) authenticate(r *http.Request) (*principal, *apiError) {
	if authz := r.Header.Get("Authorization"); authz != "" {
		scheme, tok, ok := strings.Cut(authz, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			return nil, errUnauthenticated
		}
		t, ok := s.auth.lookupToken(strings.TrimSpace(tok))
		if !ok {
			return nil, &apiError{Status: http.StatusUnauthorized, Code: "unauthorized", Message: "invalid or expired token"}
		}
		return &principal{kind: "token", name: t.Name, tokenID: t.ID, rank: t.rank()}, nil
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	sess, ok := s.sessions.get(c.Value)
	if !ok {
		return nil, &apiError{Status: http.StatusUnauthorized, Code: "unauthorized", Message: "session expired", clearCookie: true}
	}
	u, ok := s.auth.getUser(sess.username)
	if !ok { // user deleted
		s.sessions.delete(sess.key)
		return nil, &apiError{Status: http.StatusUnauthorized, Code: "unauthorized", Message: "session expired", clearCookie: true}
	}
	return &principal{kind: "user", name: u.Username, rank: roleRank(u.Role), mustChange: u.MustChangePassword,
		viaCookie: true, sessionKey: sess.key, csrf: sess.csrf}, nil
}

// still reports whether p's credentials remain valid (long-lived streams).
func (s *Server) still(p *principal) bool {
	if p.kind == "token" {
		return s.auth.tokenLive(p.tokenID)
	}
	if !s.sessions.valid(p.sessionKey) {
		return false
	}
	u, ok := s.auth.getUser(p.name)
	return ok && !u.MustChangePassword && roleRank(u.Role) >= rankViewer
}

// level is a route's minimum requirement.
type level int

const (
	levelPublic level = iota // no auth (login)
	levelSelf                // any authenticated principal; allowed while must_change_password
	levelViewer
	levelEditor
	levelAdmin
)

func (l level) rank() int {
	switch l {
	case levelViewer:
		return rankViewer
	case levelEditor:
		return rankEditor
	case levelAdmin:
		return rankAdmin
	}
	return rankNone
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, p *principal)

// guard wraps h with authentication, CSRF and authorization for lvl.
func (s *Server) guard(lvl level, h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, aerr := s.authenticate(r)
		if aerr != nil {
			if aerr.clearCookie {
				s.clearSessionCookie(w, r)
			}
			writeErr(w, aerr)
			return
		}
		// Browser-originated unsafe requests (cookie or anonymous) must be
		// same-origin. Token requests are exempt (no ambient credentials).
		if !isSafeMethod(r.Method) && (p == nil || p.viaCookie) && s.crossSiteRequest(r) {
			writeErr(w, &apiError{Status: http.StatusForbidden, Code: "forbidden", Message: "cross-origin request rejected"})
			return
		}
		if lvl == levelPublic {
			h(w, r, p)
			return
		}
		if p == nil {
			writeErr(w, errUnauthenticated)
			return
		}
		if p.viaCookie && !isSafeMethod(r.Method) {
			got := r.Header.Get("X-CSRF-Token")
			if got == "" || !constantTimeEqual(got, p.csrf) {
				writeErr(w, &apiError{Status: http.StatusForbidden, Code: "csrf_failed", Message: "missing or invalid X-CSRF-Token"})
				return
			}
		}
		if lvl > levelSelf {
			if p.mustChange {
				writeErr(w, &apiError{Status: http.StatusForbidden, Code: "password_change_required", Message: "you must change your password before continuing"})
				return
			}
			if p.rank < lvl.rank() {
				writeErr(w, &apiError{Status: http.StatusForbidden, Code: "forbidden", Message: "insufficient permissions"})
				return
			}
		} else if p.rank < rankViewer {
			// levelSelf still requires a principal with some admin-plane
			// role: check-only tokens have none.
			writeErr(w, &apiError{Status: http.StatusForbidden, Code: "forbidden", Message: "insufficient permissions"})
			return
		}
		h(w, r, p)
	})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, raw string) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: raw, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: s.o.CookieSecure || s.isTLS(r), MaxAge: int(sessionAbsolute / time.Second),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: s.o.CookieSecure || s.isTLS(r), MaxAge: -1,
	})
}

func (s *Server) record(r *http.Request, p *principal, action, targetType, targetID, summary string) {
	e := AuditEntry{IP: s.clientIP(r), Action: action, TargetType: targetType, TargetID: targetID, Summary: summary}
	if p != nil {
		e.Actor, e.ActorType = p.actor(), p.actorType()
	}
	if err := s.audit.add(e); err != nil {
		s.log.Error("audit write failed", "err", err, "action", action)
	}
}
