package admin

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	h := func(pattern string, lvl level, fn handlerFunc) { mux.Handle(pattern, s.guard(lvl, fn)) }

	// Auth
	h("POST /api/auth/login", levelPublic, s.handleLogin)
	h("POST /api/auth/logout", levelSelf, s.handleLogout)
	h("GET /api/auth/me", levelSelf, s.handleMe)
	h("POST /api/auth/password", levelSelf, s.handlePassword)

	// Read-only
	h("GET /api/system", levelViewer, s.handleSystem)
	h("GET /api/overview", levelViewer, s.handleOverview)
	h("GET /api/timeseries", levelViewer, s.handleTimeseries)
	h("GET /api/logs", levelViewer, s.handleLogs)
	h("GET /api/logs/stream", levelViewer, s.handleLogStream)

	// Config CRUD
	registerCRUD(s, mux, policyKind)
	registerCRUD(s, mux, routeKind)
	registerCRUD(s, mux, planKind)
	registerCRUD(s, mux, consumerKind)
	h("POST /api/consumers/{id}/keys", levelEditor, s.handleCreateKey)
	h("DELETE /api/consumers/{id}/keys/{keyId}", levelEditor, s.handleRevokeKey)

	h("GET /api/settings", levelViewer, s.handleGetSettings)
	h("PUT /api/settings", levelAdmin, s.handlePutSettings)

	h("POST /api/simulate", levelViewer, s.handleSimulate) // consume=true re-checked for editor
	h("GET /api/limits", levelViewer, s.handlePeekLimit)
	h("POST /api/limits/reset", levelEditor, s.handleResetLimit)

	h("GET /api/config/export", levelAdmin, s.handleExport)
	h("POST /api/config/import", levelAdmin, s.handleImport)
	h("GET /api/audit", levelAdmin, s.handleAudit)

	h("GET /api/users", levelAdmin, s.handleListUsers)
	h("POST /api/users", levelAdmin, s.handleCreateUser)
	h("PUT /api/users/{username}", levelAdmin, s.handleUpdateUser)
	h("DELETE /api/users/{username}", levelAdmin, s.handleDeleteUser)

	h("GET /api/tokens", levelAdmin, s.handleListTokens)
	h("POST /api/tokens", levelAdmin, s.handleCreateToken)
	h("DELETE /api/tokens/{id}", levelAdmin, s.handleDeleteToken)

	// Anything else under /api is a JSON 404 (never the SPA).
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, &apiError{Status: http.StatusNotFound, Code: "not_found", Message: "no such endpoint"})
	})
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, &apiError{Status: http.StatusNotFound, Code: "not_found", Message: "no such endpoint"})
	})

	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.Handle("/", s.staticHandler())
	return s.securityHeaders(mux)
}

// ---------------------------------------------------------------------
// Auth endpoints
// ---------------------------------------------------------------------

type meUser struct {
	Username           string `json:"username"`
	Role               string `json:"role"`
	MustChangePassword bool   `json:"must_change_password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, _ *principal) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if e := decodeJSON(w, r, &req, maxBody, false); e != nil {
		writeErr(w, e)
		return
	}
	ip := s.clientIP(r)
	username := strings.TrimSpace(req.Username)
	// Reserve the attempt atomically before the slow verification so
	// parallel guesses cannot all slip past the lockout check.
	u, known := s.auth.getUser(username)
	att, d := s.lock.begin(username, known, ip)
	if att == nil {
		secs := int((d + time.Second - 1) / time.Second)
		writeErr(w, &apiError{Status: http.StatusTooManyRequests, Code: "locked_out",
			Message: "too many failed login attempts; try again later", Extra: map[string]any{"retry_after_s": secs}})
		return
	}
	defer att.abort() // no-op once fail/succeed ran
	hash := s.dummy
	if known {
		hash = u.PasswordHash
	}
	// Always run exactly one PBKDF2 verification (dummy for unknown users)
	// so response time does not reveal account existence.
	ok, err := s.verifyBounded(r.Context(), hash, req.Password)
	if err != nil {
		writeErr(w, &apiError{Status: http.StatusServiceUnavailable, Code: "unavailable", Message: "request cancelled"})
		return
	}
	if !ok || !known {
		att.fail()
		// Audit both cases (same I/O on either path). The submitted name of
		// an unknown user is never recorded: it is often a mistyped password.
		if known {
			s.record(r, nil, "auth.login_failed", "user", u.Username, "failed login")
		} else {
			s.record(r, nil, "auth.login_failed", "user", "", "failed login for unknown user")
		}
		writeErr(w, &apiError{Status: http.StatusUnauthorized, Code: "invalid_credentials", Message: "invalid username or password"})
		return
	}
	att.succeed()
	if err := s.auth.recordLogin(u.Username); err != nil {
		s.log.Warn("recording last login failed", "err", err)
	}
	raw, sess := s.sessions.create(u.Username)
	s.setSessionCookie(w, r, raw)
	s.record(r, &principal{kind: "user", name: u.Username}, "auth.login", "user", u.Username, "logged in")
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       meUser{u.Username, u.Role, u.MustChangePassword},
		"csrf_token": sess.csrf,
	})
}

// verifyBounded runs verifyPassword under the hashing semaphore.
func (s *Server) verifyBounded(ctx context.Context, hash, pw string) (bool, error) {
	select {
	case s.hashSem <- struct{}{}:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	defer func() { <-s.hashSem }()
	if s.onVerify != nil {
		s.onVerify()
	}
	return verifyPassword(hash, pw), nil
}

func (s *Server) hashBounded(ctx context.Context, pw string) (string, error) {
	select {
	case s.hashSem <- struct{}{}:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() { <-s.hashSem }()
	return hashPassword(pw)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, p *principal) {
	if p.kind != "user" {
		writeErr(w, badRequest("logout applies to browser sessions only"))
		return
	}
	s.sessions.delete(p.sessionKey)
	s.clearSessionCookie(w, r)
	s.record(r, p, "auth.logout", "user", p.name, "logged out")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, p *principal) {
	if p.kind == "token" {
		role := map[int]string{rankViewer: RoleViewer, rankAdmin: RoleAdmin}[p.rank]
		writeJSON(w, http.StatusOK, map[string]any{
			"user":       meUser{Username: "token:" + p.name, Role: role},
			"csrf_token": "",
		})
		return
	}
	u, _ := s.auth.getUser(p.name)
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       meUser{u.Username, u.Role, u.MustChangePassword},
		"csrf_token": p.csrf,
	})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request, p *principal) {
	if p.kind != "user" {
		writeErr(w, badRequest("password change applies to users only"))
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if e := decodeJSON(w, r, &req, maxBody, false); e != nil {
		writeErr(w, e)
		return
	}
	u, ok := s.auth.getUser(p.name)
	if !ok {
		writeErr(w, errUnauthenticated)
		return
	}
	// Session-authenticated, so limited per session (not per username: a
	// stranger must not be able to lock a user out of changing their
	// password). The budget is reserved before the slow verify.
	if !s.sessions.beginPasswordCheck(p.sessionKey) {
		s.clearSessionCookie(w, r)
		writeErr(w, &apiError{Status: http.StatusUnauthorized, Code: "unauthorized", Message: "too many failed attempts; please sign in again"})
		return
	}
	var good bool
	var err error
	defer func() { s.sessions.finishPasswordCheck(p.sessionKey, err == nil && !good) }()
	good, err = s.verifyBounded(r.Context(), u.PasswordHash, req.CurrentPassword)
	if err != nil {
		writeErr(w, &apiError{Status: http.StatusServiceUnavailable, Code: "unavailable", Message: "request cancelled"})
		return
	}
	if !good {
		s.record(r, p, "auth.password_change_failed", "user", p.name, "wrong current password")
		writeErr(w, &apiError{Status: http.StatusUnauthorized, Code: "invalid_credentials", Message: "current password is incorrect"})
		return
	}
	if err := checkPasswordPolicy(req.NewPassword); err != nil {
		writeErr(w, &apiError{Status: http.StatusUnprocessableEntity, Code: "weak_password", Message: err.Error()})
		return
	}
	if constantTimeEqual(req.NewPassword, req.CurrentPassword) {
		writeErr(w, &apiError{Status: http.StatusUnprocessableEntity, Code: "weak_password", Message: "new password must differ from the current password"})
		return
	}
	h, err := s.hashBounded(r.Context(), req.NewPassword)
	if err != nil {
		writeErr(w, err)
		return
	}
	if _, err := s.auth.updateUser(p.name, func(u *user) error {
		u.PasswordHash = h
		u.MustChangePassword = false
		return nil
	}); err != nil {
		s.log.Error("password change failed", "err", err)
		writeErr(w, err)
		return
	}
	// Sign out every session (including this one) and issue a fresh session
	// ID and CSRF token for the caller.
	s.sessions.deleteUser(p.name, "")
	raw, sess := s.sessions.create(p.name)
	s.setSessionCookie(w, r, raw)
	s.record(r, p, "auth.password_change", "user", p.name, "changed own password")
	writeJSON(w, http.StatusOK, map[string]any{"csrf_token": sess.csrf})
}

// ---------------------------------------------------------------------
// Users (admin)
// ---------------------------------------------------------------------

func mapAuthErr(err error, what string) error {
	switch {
	case errors.Is(err, errNotFound):
		return notFound(what)
	case errors.Is(err, errExists):
		return conflict(what + " already exists")
	case errors.Is(err, errLastAdmin):
		return conflict("cannot remove or demote the last admin")
	case errors.Is(err, errLimit):
		return conflict("too many " + what + "s")
	}
	var ae *apiError
	if errors.As(err, &ae) {
		return ae
	}
	return err
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request, _ *principal) {
	writeJSON(w, http.StatusOK, s.auth.listUsers())
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request, p *principal) {
	var req struct {
		Username           string `json:"username"`
		Role               string `json:"role"`
		Password           string `json:"password"`
		MustChangePassword *bool  `json:"must_change_password"`
	}
	if e := decodeJSON(w, r, &req, maxBody, false); e != nil {
		writeErr(w, e)
		return
	}
	if !usernameRe.MatchString(req.Username) {
		writeErr(w, badRequest("username must match ^[a-z0-9][a-z0-9_.@-]{0,63}$"))
		return
	}
	if roleRank(req.Role) == rankNone {
		writeErr(w, badRequest("role must be admin, editor or viewer"))
		return
	}
	if err := checkPasswordPolicy(req.Password); err != nil {
		writeErr(w, &apiError{Status: http.StatusUnprocessableEntity, Code: "weak_password", Message: err.Error()})
		return
	}
	must := true // an admin-chosen password should be replaced by its owner
	if req.MustChangePassword != nil {
		must = *req.MustChangePassword
	}
	h, err := s.hashBounded(r.Context(), req.Password)
	if err != nil {
		writeErr(w, err)
		return
	}
	u := user{Username: req.Username, Role: req.Role, PasswordHash: h, MustChangePassword: must, CreatedAt: s.now().UTC()}
	if err := s.auth.createUser(u); err != nil {
		writeErr(w, mapAuthErr(err, "user"))
		return
	}
	s.record(r, p, "user.create", "user", u.Username, "created user with role "+u.Role)
	writeJSON(w, http.StatusCreated, u.view())
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request, p *principal) {
	name := r.PathValue("username")
	var req struct {
		Role               *string `json:"role"`
		Password           *string `json:"password"`
		MustChangePassword *bool   `json:"must_change_password"`
	}
	if e := decodeJSON(w, r, &req, maxBody, false); e != nil {
		writeErr(w, e)
		return
	}
	if req.Role != nil && roleRank(*req.Role) == rankNone {
		writeErr(w, badRequest("role must be admin, editor or viewer"))
		return
	}
	var newHash string
	if req.Password != nil {
		if err := checkPasswordPolicy(*req.Password); err != nil {
			writeErr(w, &apiError{Status: http.StatusUnprocessableEntity, Code: "weak_password", Message: err.Error()})
			return
		}
		h, err := s.hashBounded(r.Context(), *req.Password)
		if err != nil {
			writeErr(w, err)
			return
		}
		newHash = h
	}
	var changes []string
	u, err := s.auth.updateUser(name, func(u *user) error {
		if req.Role != nil && *req.Role != u.Role {
			changes = append(changes, "role "+u.Role+"→"+*req.Role)
			u.Role = *req.Role
		}
		if newHash != "" {
			u.PasswordHash = newHash
			u.MustChangePassword = true
			changes = append(changes, "password reset")
		}
		if req.MustChangePassword != nil {
			u.MustChangePassword = *req.MustChangePassword
			changes = append(changes, "must_change_password set")
		}
		return nil
	})
	if err != nil {
		writeErr(w, mapAuthErr(err, "user"))
		return
	}
	if newHash != "" {
		keep := ""
		if p.kind == "user" && p.name == name {
			keep = p.sessionKey
		}
		s.sessions.deleteUser(name, keep)
	}
	s.record(r, p, "user.update", "user", name, "updated user: "+strings.Join(changes, ", "))
	writeJSON(w, http.StatusOK, u.view())
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request, p *principal) {
	name := r.PathValue("username")
	if p.kind == "user" && p.name == name {
		writeErr(w, conflict("you cannot delete your own account"))
		return
	}
	if err := s.auth.deleteUser(name); err != nil {
		writeErr(w, mapAuthErr(err, "user"))
		return
	}
	s.sessions.deleteUser(name, "")
	s.lock.forgetUser(name)
	s.record(r, p, "user.delete", "user", name, "deleted user")
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------
// API tokens (admin)
// ---------------------------------------------------------------------

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request, _ *principal) {
	writeJSON(w, http.StatusOK, s.auth.listTokens())
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request, p *principal) {
	var req struct {
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if e := decodeJSON(w, r, &req, maxBody, false); e != nil {
		writeErr(w, e)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 {
		writeErr(w, badRequest("name is required (max 100 characters)"))
		return
	}
	var scopes []string
	for _, sc := range req.Scopes {
		if sc != ScopeAdmin && sc != ScopeRead && sc != ScopeCheck {
			writeErr(w, badRequest("scopes must be a subset of admin, read, check"))
			return
		}
		if !slices.Contains(scopes, sc) {
			scopes = append(scopes, sc)
		}
	}
	if len(scopes) == 0 {
		writeErr(w, badRequest("at least one scope is required"))
		return
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(s.now()) {
		writeErr(w, badRequest("expires_at must be in the future"))
		return
	}
	plain, info, err := s.auth.createToken(req.Name, scopes, req.ExpiresAt, p.actor())
	if err != nil {
		writeErr(w, mapAuthErr(err, "token"))
		return
	}
	s.record(r, p, "token.create", "token", info.ID, "created token "+info.Prefix+"… with scopes "+strings.Join(scopes, ","))
	writeJSON(w, http.StatusCreated, map[string]any{"token": plain, "info": info})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request, p *principal) {
	v, err := s.auth.deleteToken(r.PathValue("id"))
	if err != nil {
		writeErr(w, mapAuthErr(err, "token"))
		return
	}
	s.record(r, p, "token.delete", "token", v.ID, "deleted token "+v.Prefix+"…")
	w.WriteHeader(http.StatusNoContent)
}
