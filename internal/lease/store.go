// Package lease models short-lived guest authorization. Lease IDs are bearer
// secrets: never put them in URLs or logs. This package does not authenticate
// network clients, modify firewall rules, or grant network access.
package lease

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	ErrInvalidDuration = errors.New("lease duration must be greater than zero and at most 15 minutes")
	ErrInvalidClient   = errors.New("client identifier must be between 1 and 128 bytes")
	ErrAlreadyActive   = errors.New("client already holds an active lease")
	ErrCapacity        = errors.New("lease store is at capacity")
)

const (
	MaxDuration    = 15 * time.Minute
	MaxClientBytes = 128
	MaxLeases      = 1024
)

type Lease struct {
	ID        string
	Client    string
	ExpiresAt time.Time
}

type Store struct {
	mu     sync.Mutex
	now    func() time.Time
	leases map[string]Lease
}

// NewStore creates a volatile store. The injected clock is called while
// holding the store mutex, so it must not call back into this Store.
// Production time.Now carries monotonic readings; wall-only fake clocks can
// move backward, and suspend/resume behavior must be addressed before any
// lease is used for packet enforcement.
func NewStore(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{now: now, leases: make(map[string]Lease)}
}

// Issue creates one in-memory decision record per currently active client.
// Client is a caller-provided label, NOT a verified network identity.
// Renewal requires an explicit policy outside this package.
func (s *Store) Issue(client string, duration time.Duration) (Lease, error) {
	if len(client) == 0 || len(client) > MaxClientBytes {
		return Lease{}, ErrInvalidClient
	}
	if duration <= 0 || duration > MaxDuration {
		return Lease{}, ErrInvalidDuration
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.pruneLocked(now)
	for _, existing := range s.leases {
		if existing.Client == client {
			return Lease{}, ErrAlreadyActive
		}
	}
	if len(s.leases) >= MaxLeases {
		return Lease{}, ErrCapacity
	}

	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return Lease{}, err
	}
	id := hex.EncodeToString(buf[:])
	if _, exists := s.leases[id]; exists {
		// Improbable random collision. Never overwrite existing authority.
		return Lease{}, errors.New("lease ID collision")
	}
	lease := Lease{ID: id, Client: client, ExpiresAt: now.Add(duration)}
	s.leases[lease.ID] = lease
	return lease, nil
}

// Lookup returns an unexpired record, including its client label and expiry.
// A caller must independently verify network identity before authorizing.
// Never treat possession of a lease ID alone as proof of client identity.
func (s *Store) Lookup(id string) (Lease, bool) {
	if id == "" {
		return Lease{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lease, ok := s.leases[id]
	if !ok {
		return Lease{}, false
	}
	if !s.now().Before(lease.ExpiresAt) {
		delete(s.leases, id)
		return Lease{}, false
	}
	return lease, true
}

// Valid only checks an unexpired bearer ID; it is NOT an authorization check.
func (s *Store) Valid(id string) bool {
	_, ok := s.Lookup(id)
	return ok
}

// Revoke deletes the record and returns true only if it removed LIVE authority.
func (s *Store) Revoke(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	lease, ok := s.leases[id]
	delete(s.leases, id)
	return ok && s.now().Before(lease.ExpiresAt)
}

func (s *Store) pruneLocked(now time.Time) int {
	removed := 0
	for id, lease := range s.leases {
		if !now.Before(lease.ExpiresAt) {
			delete(s.leases, id)
			removed++
		}
	}
	return removed
}

// Prune removes expired records. Expiration must additionally be enforced by
// the eventual kernel rules; this in-memory cleanup is not a security boundary.
func (s *Store) Prune() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneLocked(s.now())
}
