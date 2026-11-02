// Package store persists the gateway configuration Snapshot.
package store

import (
	"context"

	"ratelimitergateway/internal/model"
)

// ConfigStore loads and saves the configuration snapshot.
//
// Load on an empty store returns (nil, nil) so callers can seed defaults.
// Save must be atomic (readers never observe a partial write) and must
// persist s.Version as given (the caller increments it).
// Watch invokes fn whenever another process saved a newer Version (used for
// multi-instance config sync); it blocks until ctx is done. A store that
// cannot observe external writes (single-node file store) may simply block.
type ConfigStore interface {
	Load(ctx context.Context) (*model.Snapshot, error)
	Save(ctx context.Context, s *model.Snapshot) error
	Watch(ctx context.Context, fn func(*model.Snapshot))
	Name() string
}
