package admin

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"
)

const auditMemory = 5000

// AuditEntry is one recorded mutation or security event. Summaries never
// contain secrets (passwords, key/token plaintext).
type AuditEntry struct {
	ID         string    `json:"id"`
	Time       time.Time `json:"time"`
	Actor      string    `json:"actor"`
	ActorType  string    `json:"actor_type"` // "user" | "token" | "system"
	IP         string    `json:"ip"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	Summary    string    `json:"summary"`
}

// auditLog appends to <dataDir>/audit.jsonl (0600) and keeps the last 5000
// entries in a ring for the API.
type auditLog struct {
	mu     sync.Mutex
	path   string
	ring   []AuditEntry
	next   int // write position once full
	full   bool
	lastNs int64
	now    func() time.Time
}

func newAuditLog(path string, now func() time.Time) (*auditLog, error) {
	a := &auditLog{path: path, ring: make([]AuditEntry, 0, auditMemory), now: now}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var e AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.ID == "" {
			continue // skip corrupt lines rather than refusing to start
		}
		a.push(e)
		var ns int64
		if _, err := fmt.Sscanf(e.ID, "%x", &ns); err == nil && ns > a.lastNs {
			a.lastNs = ns
		}
	}
	return a, nil
}

func (a *auditLog) push(e AuditEntry) {
	if !a.full {
		a.ring = append(a.ring, e)
		if len(a.ring) == auditMemory {
			a.full = true
		}
		return
	}
	a.ring[a.next] = e
	a.next = (a.next + 1) % auditMemory
}

// add records e (ID and Time assigned here). Disk failures are returned for
// logging but the entry is still kept in memory.
func (a *auditLog) add(e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now().UTC()
	ns := now.UnixNano()
	if ns <= a.lastNs {
		ns = a.lastNs + 1
	}
	a.lastNs = ns
	e.ID = fmt.Sprintf("%016x", ns) // fixed width hex: lexical order == time order
	e.Time = now
	a.push(e)
	if a.path == "" {
		return nil
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(a.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(b, '\n'))
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// query returns entries newest first, older than before (ID cursor) if set.
func (a *auditLog) query(limit int, before string) []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := []AuditEntry{}
	n := len(a.ring)
	for i := 0; i < n && len(out) < limit; i++ {
		// newest is just before next (when full) or at the end.
		idx := n - 1 - i
		if a.full {
			idx = (a.next - 1 - i + 2*auditMemory) % auditMemory
		}
		e := a.ring[idx]
		if before != "" && e.ID >= before {
			continue
		}
		out = append(out, e)
	}
	return out
}
