// Package model is the single shared contract between every other package:
// configuration objects (policies, routes, plans, consumers, settings),
// telemetry records, and the simulator request/response. It has no
// dependencies on other internal packages.
package model

import (
	"encoding/json"
	"fmt"
	"time"
)

// Duration is a time.Duration that marshals to/from JSON as a Go duration
// string ("1m", "500ms"). Plain integers are accepted as seconds.
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = Duration(v)
		return nil
	}
	var n float64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("duration must be a string like \"1m\" or a number of seconds")
	}
	*d = Duration(time.Duration(n * float64(time.Second)))
	return nil
}

// Algorithm selects the rate-limiting strategy of a Policy.
type Algorithm string

const (
	AlgoTokenBucket          Algorithm = "token_bucket"           // smooth rate Limit/Window, bursts up to Burst
	AlgoSlidingWindow        Algorithm = "sliding_window"         // exact log: at most Limit in any trailing Window
	AlgoSlidingWindowCounter Algorithm = "sliding_window_counter" // approximate sliding window, O(1) memory (Cloudflare-style)
	AlgoFixedWindow          Algorithm = "fixed_window"           // at most Limit per aligned Window
	AlgoConcurrency          Algorithm = "concurrency"            // at most Limit in-flight requests (released on completion)
	AlgoGCRA                 Algorithm = "gcra"                   // generic cell rate algorithm: one timestamp per key, smooth rate with Burst tolerance
	AlgoLeakyBucket          Algorithm = "leaky_bucket"           // traffic shaping: requests queue (are delayed) and drain at Limit/Window
)

var Algorithms = []Algorithm{AlgoTokenBucket, AlgoSlidingWindow, AlgoSlidingWindowCounter, AlgoFixedWindow, AlgoConcurrency, AlgoGCRA, AlgoLeakyBucket}

// Mode controls what happens when a policy's limit is exceeded.
type Mode string

const (
	ModeEnforce Mode = "enforce" // reject with 429
	ModeShadow  Mode = "shadow"  // allow, but log/count as "shadow_limited" (dry-run a new limit safely)
)

// FailMode controls behaviour when the limiter backend (e.g. Redis) errors.
type FailMode string

const (
	FailOpen   FailMode = "open"   // allow the request
	FailClosed FailMode = "closed" // reject with 503
)

// KeyBy entries define how a policy derives the bucket identity. Multiple
// entries are joined into a composite key. Valid values:
//
//	"consumer"        authenticated consumer ID (falls back to client IP when anonymous)
//	"api_key"         raw API key header value (hashed before use)
//	"ip"              client IP (honouring Settings.TrustedProxies)
//	"header:<Name>"   value of request header <Name> (missing => "-")
//	"query:<name>"    value of query parameter <name>
//	"path"            request path
//	"method"          request method
//	"route"           matched route ID
//	"global"          single shared bucket
type KeyBy = string

// Policy is a named, reusable rate limit.
type Policy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Algorithm   Algorithm `json:"algorithm"`
	Limit       int       `json:"limit"`           // requests per Window (concurrency: max in-flight)
	Window      Duration  `json:"window"`          // ignored for concurrency
	Burst       int       `json:"burst,omitempty"` // token bucket capacity; 0 => Limit
	Cost        int       `json:"cost,omitempty"`  // units consumed per request; 0 => 1
	KeyBy       []KeyBy   `json:"key_by"`
	Mode        Mode      `json:"mode"`
	FailMode    FailMode  `json:"fail_mode"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RouteMatch selects requests. All non-empty fields must match.
type RouteMatch struct {
	Host       string   `json:"host,omitempty"`        // exact host (port stripped) or "*.example.com"
	PathPrefix string   `json:"path_prefix,omitempty"` // e.g. "/api/v1"; "" or "/" matches everything
	Methods    []string `json:"methods,omitempty"`     // empty => any
}

// Route maps matching requests to an upstream and the policies applied.
type Route struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Match         RouteMatch `json:"match"`
	Upstream      string     `json:"upstream"` // absolute http(s) URL
	StripPrefix   bool       `json:"strip_prefix,omitempty"`
	PolicyIDs     []string   `json:"policy_ids"` // evaluated in order; all must allow
	RequireAPIKey bool       `json:"require_api_key"`
	Timeout       Duration   `json:"timeout,omitempty"` // upstream timeout; 0 => 30s
	Priority      int        `json:"priority"`          // higher wins; ties broken by longer PathPrefix
	Enabled       bool       `json:"enabled"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	// AllowUpgrade lets HTTP/1.1 Upgrade requests (WebSocket) through this
	// route. Off by default: an upgraded connection is a raw tunnel that is
	// rate limited only once, as the single upgrade request. h2c is always
	// rejected. Concurrency policies cannot be combined with it (their 60s
	// leases cannot represent long tunnels).
	AllowUpgrade bool `json:"allow_upgrade,omitempty"`
	// UpgradeMaxDuration is the lifetime cap of an upgraded (WebSocket)
	// tunnel; the tunnel is closed when it is reached. 0 => 1h, at most 24h.
	// Only meaningful with AllowUpgrade: Timeout then bounds the upgrade
	// handshake only.
	UpgradeMaxDuration Duration `json:"upgrade_max_duration,omitempty"`
}

// LimitOverride replaces a policy's numbers for a plan or consumer.
// Zero fields keep the policy's value.
type LimitOverride struct {
	Limit  int      `json:"limit,omitempty"`
	Window Duration `json:"window,omitempty"`
	Burst  int      `json:"burst,omitempty"`
}

// Plan is a pricing tier (e.g. Free / Pro / Enterprise) that overrides
// policy limits for every consumer on it.
type Plan struct {
	ID          string                   `json:"id"`
	Name        string                   `json:"name"`
	Description string                   `json:"description,omitempty"`
	Overrides   map[string]LimitOverride `json:"overrides"` // policy ID -> override
	CreatedAt   time.Time                `json:"created_at"`
	UpdatedAt   time.Time                `json:"updated_at"`
}

// APIKey is a credential belonging to a consumer. Only the SHA-256 hash of
// the key is stored; the plaintext is shown exactly once at creation.
type APIKey struct {
	ID        string     `json:"id"`
	Prefix    string     `json:"prefix"` // first 12 chars of the key, for display ("rlg_live_ab1")
	Hash      string     `json:"hash"`   // hex sha256 of the full key
	Name      string     `json:"name,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Revoked   bool       `json:"revoked"`
}

// Consumer is an API client (a customer, an app, a tenant).
type Consumer struct {
	ID        string                   `json:"id"`
	Name      string                   `json:"name"`
	PlanID    string                   `json:"plan_id,omitempty"`
	Overrides map[string]LimitOverride `json:"overrides,omitempty"` // beats plan overrides
	Metadata  map[string]string        `json:"metadata,omitempty"`
	Keys      []APIKey                 `json:"keys"`
	Disabled  bool                     `json:"disabled"`
	CreatedAt time.Time                `json:"created_at"`
	UpdatedAt time.Time                `json:"updated_at"`
}

// Settings are gateway-wide knobs.
type Settings struct {
	APIKeyHeader     string   `json:"api_key_header"`     // default "X-API-Key"; "Authorization: Bearer" also accepted
	TrustedProxies   []string `json:"trusted_proxies"`    // CIDRs whose X-Forwarded-For is trusted
	GlobalPolicyIDs  []string `json:"global_policy_ids"`  // applied to every route, before route policies
	LegacyHeaders    bool     `json:"legacy_headers"`     // also emit X-RateLimit-* headers
	ExposeDecision   bool     `json:"expose_decision"`    // emit X-RateGuard-Policy / X-RateGuard-Route headers
	MaxBodyBytes     int64    `json:"max_body_bytes"`     // 0 => unlimited
	LogSampleAllowed float64  `json:"log_sample_allowed"` // 0..1 fraction of allowed requests logged (limited/errors always logged)
	CheckAPIEnabled  bool     `json:"check_api_enabled"`  // enable POST /_rlg/v1/check on the data plane
	// ForwardAuthDisabled turns /_rlg/v1/auth off (zero value = enabled, so a
	// client unaware of the field cannot disable it by accident). The endpoint
	// serves NGINX auth_request, Traefik ForwardAuth, Caddy forward_auth, etc.
	ForwardAuthDisabled bool `json:"forward_auth_disabled"`
	// ForwardAuthRequireToken makes the endpoint demand
	// X-RateGuard-Auth-Token with a "check"-scoped token.
	ForwardAuthRequireToken bool     `json:"forward_auth_require_token"`
	CORSAllowOrigins        []string `json:"cors_allow_origins,omitempty"` // reserved, not yet implemented (ignored)
	// IPv6PrefixLen is how many leading bits of an IPv6 client address the
	// "ip" key part uses (32..128; 0 => 64), so a client cannot rotate
	// through its /64 to get a fresh bucket per address. IPv4 (and
	// IPv4-mapped) addresses are always used in full.
	IPv6PrefixLen int `json:"ipv6_prefix_len"`
}

func DefaultSettings() Settings {
	return Settings{
		APIKeyHeader:     "X-API-Key",
		TrustedProxies:   []string{},
		GlobalPolicyIDs:  []string{},
		LegacyHeaders:    true,
		ExposeDecision:   false,
		LogSampleAllowed: 1,
		CheckAPIEnabled:  true,
		IPv6PrefixLen:    64,
	}
}

// Snapshot is the entire gateway configuration. It is immutable once
// handed to the runtime: mutate a Clone().
type Snapshot struct {
	Version   int64      `json:"version"` // incremented on every save
	UpdatedAt time.Time  `json:"updated_at"`
	Policies  []Policy   `json:"policies"`
	Routes    []Route    `json:"routes"`
	Plans     []Plan     `json:"plans"`
	Consumers []Consumer `json:"consumers"`
	Settings  Settings   `json:"settings"`
}

func NewSnapshot() *Snapshot {
	return &Snapshot{Policies: []Policy{}, Routes: []Route{}, Plans: []Plan{}, Consumers: []Consumer{}, Settings: DefaultSettings()}
}

// Clone returns a deep copy (via JSON round-trip; snapshots are small and
// cloned only on admin writes).
func (s *Snapshot) Clone() *Snapshot {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	out := NewSnapshot()
	if err := json.Unmarshal(b, out); err != nil {
		panic(err)
	}
	return out
}

// ---------------------------------------------------------------------
// Telemetry contract
// ---------------------------------------------------------------------

// Decision outcome strings used in LogEntry.Decision and metrics labels.
const (
	DecisionAllowed       = "allowed"
	DecisionLimited       = "limited"
	DecisionShadowLimited = "shadow_limited"
	DecisionUnauthorized  = "unauthorized" // missing/invalid API key on a route that requires one
	DecisionNoRoute       = "no_route"
	DecisionError         = "error" // limiter backend error (fail closed) or upstream error
)

// LogEntry is one request as seen by the data plane.
type LogEntry struct {
	ID           string    `json:"id"`
	Time         time.Time `json:"time"`
	Method       string    `json:"method"`
	Host         string    `json:"host"`
	Path         string    `json:"path"`
	RouteID      string    `json:"route_id,omitempty"`
	RouteName    string    `json:"route_name,omitempty"`
	ClientIP     string    `json:"client_ip"`
	ConsumerID   string    `json:"consumer_id,omitempty"`
	ConsumerName string    `json:"consumer_name,omitempty"`
	RateKey      string    `json:"rate_key,omitempty"` // the composite bucket key of the deciding policy (API keys never appear raw)
	PolicyID     string    `json:"policy_id,omitempty"`
	Decision     string    `json:"decision"`
	Status       int       `json:"status"`
	Limit        int       `json:"limit,omitempty"`
	Remaining    int       `json:"remaining"`
	LatencyMs    float64   `json:"latency_ms"`  // total time in gateway
	UpstreamMs   float64   `json:"upstream_ms"` // time waiting on upstream (0 if not proxied)
	BytesOut     int64     `json:"bytes_out"`
	UserAgent    string    `json:"user_agent,omitempty"`
	Error        string    `json:"error,omitempty"`
	Source       string    `json:"source"` // "proxy" | "check_api"
}

// LogQuery filters the in-memory log buffer. Zero values mean "any".
type LogQuery struct {
	Decision   string    `json:"decision,omitempty"`
	RouteID    string    `json:"route_id,omitempty"`
	ConsumerID string    `json:"consumer_id,omitempty"`
	PolicyID   string    `json:"policy_id,omitempty"`
	StatusMin  int       `json:"status_min,omitempty"`
	StatusMax  int       `json:"status_max,omitempty"`
	Search     string    `json:"q,omitempty"` // substring match on path, client IP, rate key, consumer name
	Since      time.Time `json:"since,omitempty"`
	Before     string    `json:"before,omitempty"` // entry ID cursor: return entries older than this
	Limit      int       `json:"limit,omitempty"`  // default 100, max 1000
}

// TimeseriesPoint is one bucket of aggregated traffic.
type TimeseriesPoint struct {
	T             time.Time `json:"t"` // bucket start
	Allowed       int64     `json:"allowed"`
	Limited       int64     `json:"limited"`
	ShadowLimited int64     `json:"shadow_limited"`
	Errors        int64     `json:"errors"` // unauthorized + no_route + error
	P50Ms         float64   `json:"p50_ms"`
	P95Ms         float64   `json:"p95_ms"`
	P99Ms         float64   `json:"p99_ms"`
}

type Timeseries struct {
	StepSeconds int               `json:"step_s"`
	Points      []TimeseriesPoint `json:"points"` // oldest first, gap-filled with zeros
}

type Counted struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// Overview is the dashboard home-page summary (last 24h unless noted).
type Overview struct {
	Requests        int64     `json:"requests"`
	Allowed         int64     `json:"allowed"`
	Limited         int64     `json:"limited"`
	ShadowLimited   int64     `json:"shadow_limited"`
	Errors          int64     `json:"errors"`
	RPS1m           float64   `json:"rps_1m"` // avg requests/sec over the last minute
	P50Ms           float64   `json:"p50_ms"`
	P95Ms           float64   `json:"p95_ms"`
	P99Ms           float64   `json:"p99_ms"`
	TopLimitedKeys  []Counted `json:"top_limited_keys"` // by RateKey (Label = consumer name if known)
	TopRoutes       []Counted `json:"top_routes"`       // by request count
	TopPolicies     []Counted `json:"top_policies"`     // by limited count
	TopConsumers    []Counted `json:"top_consumers"`    // by request count
	StatusBreakdown []Counted `json:"status_breakdown"` // ID = "2xx","3xx","4xx","429","5xx"
	Since           time.Time `json:"since"`
}

// ---------------------------------------------------------------------
// Simulator ("what would happen to this request?") contract
// ---------------------------------------------------------------------

type SimRequest struct {
	Method  string            `json:"method"`
	Host    string            `json:"host"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Query   map[string]string `json:"query"`
	IP      string            `json:"ip"`
	// Consume, when true, actually consumes from the buckets (a real
	// check). When false, only the effective configuration is resolved.
	Consume bool `json:"consume"`
}

type SimPolicyResult struct {
	PolicyID   string    `json:"policy_id"`
	PolicyName string    `json:"policy_name"`
	Algorithm  Algorithm `json:"algorithm"`
	Mode       Mode      `json:"mode"`
	Limit      int       `json:"limit"`
	Window     Duration  `json:"window"`
	Burst      int       `json:"burst,omitempty"`
	LimitFrom  string    `json:"limit_from"` // "policy" | "plan:<id>" | "consumer"
	RateKey    string    `json:"rate_key"`
	// Populated only when SimRequest.Consume is true:
	Allowed      *bool `json:"allowed,omitempty"`
	Remaining    int   `json:"remaining,omitempty"`
	RetryAfterMs int64 `json:"retry_after_ms,omitempty"`
}

type SimResult struct {
	Matched      bool              `json:"matched"`
	RouteID      string            `json:"route_id,omitempty"`
	RouteName    string            `json:"route_name,omitempty"`
	Upstream     string            `json:"upstream,omitempty"`
	ConsumerID   string            `json:"consumer_id,omitempty"`
	ConsumerName string            `json:"consumer_name,omitempty"`
	AuthError    string            `json:"auth_error,omitempty"`
	Policies     []SimPolicyResult `json:"policies"`
	Decision     string            `json:"decision"` // what the gateway would do (a Decision* constant)
	Notes        []string          `json:"notes,omitempty"`
}
