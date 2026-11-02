package store

import (
	"context"
	"sync"

	"ratelimitergateway/internal/model"
)

// Memory is an in-process ConfigStore for tests and demo mode. It stores
// clones so callers can never alias the stored snapshot.
type Memory struct {
	mu sync.Mutex
	s  *model.Snapshot
}

func NewMemory() *Memory { return &Memory{} }

func (m *Memory) Load(context.Context) (*model.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.s == nil {
		return nil, nil
	}
	return m.s.Clone(), nil
}

func (m *Memory) Save(_ context.Context, s *model.Snapshot) error {
	c := s.Clone()
	m.mu.Lock()
	m.s = c
	m.mu.Unlock()
	return nil
}

// Watch blocks until ctx is done: nobody else can write to a Memory store.
func (m *Memory) Watch(ctx context.Context, _ func(*model.Snapshot)) { <-ctx.Done() }

func (m *Memory) Name() string { return "memory" }
