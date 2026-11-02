package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/ratelimit"
)

func TestMain(m *testing.M) {
	pbkdf2Iterations = 1000 // speed; production uses 600000
	os.Exit(m.Run())
}

// ---- fakes ----

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fakeStore struct {
	mu       sync.Mutex
	saved    *model.Snapshot
	saves    int
	failSave bool
	watch    chan *model.Snapshot
}

func (f *fakeStore) Load(context.Context) (*model.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saved == nil {
		return nil, nil
	}
	return f.saved.Clone(), nil
}
func (f *fakeStore) Save(_ context.Context, s *model.Snapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSave {
		return errors.New("disk on fire at /secret/path")
	}
	f.saved = s.Clone()
	f.saves++
	return nil
}
func (f *fakeStore) Watch(ctx context.Context, fn func(*model.Snapshot)) {
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-f.watch:
			fn(s)
		}
	}
}
func (f *fakeStore) Name() string { return "fake" }

type fakeRuntime struct {
	mu       sync.Mutex
	cur      *model.Snapshot
	applyErr func(*model.Snapshot) error
	applies  int
	sims     []model.SimRequest
}

func (f *fakeRuntime) Apply(s *model.Snapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyErr != nil {
		if err := f.applyErr(s); err != nil {
			return err
		}
	}
	f.cur = s
	f.applies++
	return nil
}
func (f *fakeRuntime) Current() *model.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cur
}
func (f *fakeRuntime) Simulate(_ context.Context, r model.SimRequest) model.SimResult {
	f.mu.Lock()
	f.sims = append(f.sims, r)
	f.mu.Unlock()
	return model.SimResult{Matched: true, RouteID: "r1", Decision: model.DecisionAllowed, Policies: []model.SimPolicyResult{}}
}
func (f *fakeRuntime) EngineKey(policyID, composite string) string { return policyID + ":" + composite }

type fakeTelemetry struct {
	mu   sync.Mutex
	subs []chan model.LogEntry
	last model.LogQuery
}

func (f *fakeTelemetry) QueryLogs(q model.LogQuery) []model.LogEntry {
	f.mu.Lock()
	f.last = q
	f.mu.Unlock()
	return []model.LogEntry{{ID: "1", Path: "/x", Decision: "allowed", Status: 200}}
}
func (f *fakeTelemetry) Subscribe(n int) (<-chan model.LogEntry, func()) {
	ch := make(chan model.LogEntry, n)
	f.mu.Lock()
	f.subs = append(f.subs, ch)
	f.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			for i, c := range f.subs {
				if c == ch {
					f.subs = append(f.subs[:i], f.subs[i+1:]...)
					break
				}
			}
		})
	}
}
func (f *fakeTelemetry) publish(e model.LogEntry) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.subs {
		select {
		case c <- e:
		default:
		}
	}
	return len(f.subs)
}
func (f *fakeTelemetry) subscribers() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subs)
}
func (f *fakeTelemetry) Timeseries(d time.Duration, route string) model.Timeseries {
	return model.Timeseries{StepSeconds: int(d / (180 * time.Second)), Points: []model.TimeseriesPoint{}}
}
func (f *fakeTelemetry) Overview() model.Overview { return model.Overview{Requests: 42} }
func (f *fakeTelemetry) WritePrometheus(w io.Writer) {
	_, _ = io.WriteString(w, "rateguard_log_buffer_entries 1\n")
}

type fakeEngine struct {
	mu     sync.Mutex
	resets []string
	peeks  []string
	params []ratelimit.Params
}

func (f *fakeEngine) Allow(context.Context, string, ratelimit.Params) (ratelimit.Decision, error) {
	return ratelimit.Decision{Allowed: true}, nil
}
func (f *fakeEngine) Peek(_ context.Context, key string, p ratelimit.Params) (ratelimit.Decision, bool, error) {
	f.mu.Lock()
	f.peeks = append(f.peeks, key)
	f.params = append(f.params, p)
	f.mu.Unlock()
	return ratelimit.Decision{Limit: p.Limit, Remaining: p.Limit - 3, ResetAfter: 1500 * time.Millisecond}, true, nil
}
func (f *fakeEngine) Release(context.Context, string, ratelimit.Params) error { return nil }
func (f *fakeEngine) Reset(_ context.Context, key string, _ ratelimit.Params) error {
	f.mu.Lock()
	f.resets = append(f.resets, key)
	f.mu.Unlock()
	return nil
}
func (f *fakeEngine) Name() string                  { return "memory" }
func (f *fakeEngine) Healthy(context.Context) error { return nil }
func (f *fakeEngine) Close() error                  { return nil }

// fakeValidationError mimics store.ValidationError plus the ProblemsJSON
// method the integration adds.
type fakeProblem struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}
type fakeValidationError struct{ Problems []fakeProblem }

func (e *fakeValidationError) Error() string     { return "invalid configuration: " + e.Problems[0].Field }
func (e *fakeValidationError) ProblemsJSON() any { return e.Problems }

// fakeValidate rejects policies with Limit <= 0.
func fakeValidate(s *model.Snapshot) error {
	var probs []fakeProblem
	for i, p := range s.Policies {
		if p.Limit <= 0 {
			probs = append(probs, fakeProblem{Field: "policies[" + itoa64(int64(i)) + "].limit", Message: "must be >= 1"})
		}
	}
	if len(probs) > 0 {
		return &fakeValidationError{Problems: probs}
	}
	return nil
}

// ---- environment ----

const adminPW = "admin-password-123"

type env struct {
	t     *testing.T
	s     *Server
	clock *fakeClock
	store *fakeStore
	rt    *fakeRuntime
	tel   *fakeTelemetry
	eng   *fakeEngine
	dir   string
	h     http.Handler
}

func seedSnapshot() *model.Snapshot {
	s := model.NewSnapshot()
	s.Version = 1
	s.Policies = []model.Policy{
		{ID: "p1", Name: "Per IP", Algorithm: model.AlgoTokenBucket, Limit: 10, Window: model.Duration(time.Minute), KeyBy: []string{"ip"}, Mode: model.ModeEnforce, FailMode: model.FailOpen, Enabled: true},
		{ID: "p2", Name: "Unused", Algorithm: model.AlgoFixedWindow, Limit: 5, Window: model.Duration(time.Second), KeyBy: []string{"global"}, Mode: model.ModeEnforce, FailMode: model.FailOpen, Enabled: true},
	}
	s.Routes = []model.Route{{ID: "r1", Name: "API", Match: model.RouteMatch{PathPrefix: "/api"}, Upstream: "http://127.0.0.1:1", PolicyIDs: []string{"p1"}, Enabled: true}}
	s.Plans = []model.Plan{
		{ID: "pl1", Name: "Pro", Overrides: map[string]model.LimitOverride{}},
		{ID: "pl2", Name: "Free", Overrides: map[string]model.LimitOverride{}},
	}
	s.Consumers = []model.Consumer{{ID: "c1", Name: "Acme", PlanID: "pl1", Keys: []model.APIKey{{ID: "k1", Prefix: "rlg_live_abc", Hash: strings.Repeat("a", 64)}}}}
	return s
}

func newEnv(t *testing.T, mod ...func(*Options)) *env {
	t.Helper()
	e := &env{t: t, clock: newClock(), store: &fakeStore{watch: make(chan *model.Snapshot)}, rt: &fakeRuntime{cur: seedSnapshot()},
		tel: &fakeTelemetry{}, eng: &fakeEngine{}, dir: t.TempDir()}
	o := Options{DataDir: e.dir, Store: e.store, Runtime: e.rt, Telemetry: e.tel, Engine: e.eng,
		BootstrapPassword: adminPW, Version: "test", now: e.clock.Now, stderr: io.Discard}
	for _, m := range mod {
		m(&o)
	}
	s, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.s, e.h = s, s.Handler()
	return e
}

func (e *env) addUser(name, role string) {
	e.t.Helper()
	h, err := hashPassword(name + "-password-123")
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.s.auth.createUser(user{Username: name, Role: role, PasswordHash: h, CreatedAt: e.clock.Now()}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) token(name string, scopes ...string) string {
	e.t.Helper()
	plain, _, err := e.s.auth.createToken(name, scopes, nil, "test")
	if err != nil {
		e.t.Fatal(err)
	}
	return plain
}

// cred is how a test request authenticates.
type cred struct {
	cookie string
	csrf   string
	bearer string
}

func (e *env) login(username, password string) cred {
	e.t.Helper()
	rec := e.req("POST", "/api/auth/login", map[string]string{"username": username, "password": password}, cred{})
	if rec.Code != 200 {
		e.t.Fatalf("login %s: %d %s", username, rec.Code, rec.Body)
	}
	var out struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return cred{cookie: c.Value, csrf: out.CSRF}
		}
	}
	e.t.Fatal("no session cookie")
	return cred{}
}

type reqOpt func(*http.Request)

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

func (e *env) req(method, path string, body any, c cred, opts ...reqOpt) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	r := httptest.NewRequest(method, "http://admin.local"+path, rd)
	r.RemoteAddr = "192.0.2.10:5555"
	if rd != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.cookie})
		if c.csrf != "" {
			r.Header.Set("X-CSRF-Token", c.csrf)
		}
	}
	if c.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	for _, o := range opts {
		o(r)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return v
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	return decode[map[string]any](t, rec)["error"].(string)
}
