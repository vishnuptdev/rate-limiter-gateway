package admin

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/store"
)

// problemLister is implemented by validation errors that can expose their
// structured problem list. Integration note: store.ValidationError gains
//
//	func (e *ValidationError) ProblemsJSON() any { return e.Problems }
//
// so admin can return `problems` without importing a concrete type (the
// error may be wrapped by Runtime.Apply; errors.As unwraps it).
type problemLister interface{ ProblemsJSON() any }

// manager serialises every configuration write through
// clone → mutate → version++ → validate → runtime.Apply → store.Save.
type manager struct {
	mu       sync.Mutex
	store    store.ConfigStore
	rt       Runtime
	validate func(*model.Snapshot) error
	now      func() time.Time
	log      *slog.Logger
}

func (m *manager) current() *model.Snapshot {
	if s := m.rt.Current(); s != nil {
		return s
	}
	return model.NewSnapshot()
}

func validationErr(err error) *apiError {
	e := &apiError{Status: http.StatusUnprocessableEntity, Code: "validation_failed", Message: err.Error()}
	var pl problemLister
	if errors.As(err, &pl) {
		e.Problems = pl.ProblemsJSON()
	}
	return e
}

// check runs the configured validator (nil => none; Runtime.Apply validates).
func (m *manager) check(s *model.Snapshot) error {
	if m.validate == nil {
		return nil
	}
	if err := m.validate(s); err != nil {
		return validationErr(err)
	}
	return nil
}

// mutate applies fn to a clone of the current snapshot and commits it.
// fn may return an *apiError (e.g. not found / conflict) to abort.
func (m *manager) mutate(ctx context.Context, fn func(next *model.Snapshot, now time.Time) error) (*model.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.current()
	next := cur.Clone()
	now := m.now().UTC()
	if err := fn(next, now); err != nil {
		return nil, err
	}
	return m.commitLocked(ctx, cur, next, now)
}

// replace commits s wholesale (import). The version is always cur+1.
func (m *manager) replace(ctx context.Context, s *model.Snapshot) (*model.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.current()
	return m.commitLocked(ctx, cur, s.Clone(), m.now().UTC())
}

func (m *manager) commitLocked(ctx context.Context, cur, next *model.Snapshot, now time.Time) (*model.Snapshot, error) {
	normalizeSnapshot(next)
	next.Version = cur.Version + 1
	next.UpdatedAt = now
	if err := m.check(next); err != nil {
		return nil, err
	}
	if err := m.rt.Apply(next); err != nil {
		return nil, validationErr(err)
	}
	// Persist even if the client went away mid-request, but bounded.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := m.store.Save(sctx, next); err != nil {
		m.log.Error("config save failed; reverting runtime", "err", err, "version", next.Version)
		if rerr := m.rt.Apply(cur); rerr != nil {
			m.log.Error("re-applying previous config failed", "err", rerr)
		}
		return nil, &apiError{Status: http.StatusInternalServerError, Code: "store_error", Message: "failed to persist configuration; change was not applied"}
	}
	return next, nil
}

// onWatch applies a snapshot saved by another instance if it is newer.
func (m *manager) onWatch(s *model.Snapshot) {
	if s == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.current()
	if s.Version <= cur.Version {
		return
	}
	if err := m.rt.Apply(s); err != nil {
		m.log.Error("applying watched config failed", "err", err, "version", s.Version)
		return
	}
	m.log.Info("applied config from store", "version", s.Version)
}

// normalizeSnapshot replaces nil slices/maps with empty ones so JSON output
// is stable ([] not null).
func normalizeSnapshot(s *model.Snapshot) {
	if s.Policies == nil {
		s.Policies = []model.Policy{}
	}
	if s.Routes == nil {
		s.Routes = []model.Route{}
	}
	if s.Plans == nil {
		s.Plans = []model.Plan{}
	}
	if s.Consumers == nil {
		s.Consumers = []model.Consumer{}
	}
	for i := range s.Policies {
		if s.Policies[i].KeyBy == nil {
			s.Policies[i].KeyBy = []string{}
		}
	}
	for i := range s.Routes {
		if s.Routes[i].PolicyIDs == nil {
			s.Routes[i].PolicyIDs = []string{}
		}
	}
	for i := range s.Plans {
		if s.Plans[i].Overrides == nil {
			s.Plans[i].Overrides = map[string]model.LimitOverride{}
		}
	}
	for i := range s.Consumers {
		if s.Consumers[i].Keys == nil {
			s.Consumers[i].Keys = []model.APIKey{}
		}
	}
	if s.Settings.TrustedProxies == nil {
		s.Settings.TrustedProxies = []string{}
	}
	if s.Settings.GlobalPolicyIDs == nil {
		s.Settings.GlobalPolicyIDs = []string{}
	}
}

// slugID builds "<slug(name)>-<4 random>" (e.g. "free-tier-a1b2").
func slugID(name, fallback string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			dash = false
		default:
			if b.Len() > 0 && !dash {
				b.WriteByte('-')
				dash = true
			}
		}
		if b.Len() >= 50 {
			break
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = fallback
	}
	return slug + "-" + randomFrom(lowerAlnum, 4)
}
