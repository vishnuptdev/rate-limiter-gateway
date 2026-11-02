package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"ratelimitergateway/internal/model"
)

// File persists the snapshot as <dir>/config.json (mode 0600), replaced
// atomically via temp file + fsync + rename.
type File struct {
	dir  string
	path string
	mu   sync.Mutex
}

// NewFile creates dir (0700) if needed.
func NewFile(dir string) (*File, error) {
	if dir == "" {
		return nil, errors.New("store: file store needs a directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create %s: %w", dir, err)
	}
	return &File{dir: dir, path: filepath.Join(dir, "config.json")}, nil
}

func (f *File) Load(context.Context) (*model.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s := model.NewSnapshot()
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("store: parse %s: %w", f.path, err)
	}
	return s, nil
}

func (f *File) Save(_ context.Context, s *model.Snapshot) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	tmp, err := os.CreateTemp(f.dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func(e error) error { tmp.Close(); os.Remove(name); return e }
	if err := tmp.Chmod(0o600); err != nil {
		return cleanup(err)
	}
	if _, err := tmp.Write(b); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, f.path); err != nil {
		os.Remove(name)
		return err
	}
	if d, err := os.Open(f.dir); err == nil { // persist the rename itself
		d.Sync()
		d.Close()
	}
	return nil
}

// Watch blocks until ctx is done: a single-node file store sees no external writers.
func (f *File) Watch(ctx context.Context, _ func(*model.Snapshot)) { <-ctx.Done() }

func (f *File) Name() string { return "file" }
