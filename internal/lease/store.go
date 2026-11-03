// Package lease models short-lived guest authorization. It does not modify
// firewall rules or grant network access by itself.
package lease

import (
 "crypto/rand"
 "encoding/hex"
 "errors"
 "sync"
 "time"
)

var ErrInvalidDuration = errors.New("lease duration must be greater than zero and at most 15 minutes")
var ErrInvalidClient = errors.New("client identifier must not be empty")

const MaxDuration = 15 * time.Minute

type Lease struct {
 ID string
 Client string
 ExpiresAt time.Time
}

type Store struct {
 mu sync.Mutex
 now func() time.Time
 leases map[string]Lease
}

func NewStore(now func() time.Time) *Store {
 if now == nil { now = time.Now }
 return &Store{now: now, leases: make(map[string]Lease)}
}

// Issue creates an in-memory decision record. A client identifier is a
// caller-provided label, NOT a verified network identity.
func (s *Store) Issue(client string, duration time.Duration) (Lease, error) {
 if client == "" { return Lease{}, ErrInvalidClient }
 if duration <= 0 || duration > MaxDuration { return Lease{}, ErrInvalidDuration }
 var buf [16]byte
 if _, err := rand.Read(buf[:]); err != nil { return Lease{}, err }
 lease := Lease{ID: hex.EncodeToString(buf[:]), Client: client, ExpiresAt: s.now().Add(duration)}
 s.mu.Lock()
 defer s.mu.Unlock()
 s.leases[lease.ID] = lease
 return lease, nil
}

func (s *Store) Valid(id string) bool {
 if id == "" { return false }
 s.mu.Lock()
 defer s.mu.Unlock()
 lease, ok := s.leases[id]
 if !ok { return false }
 if !s.now().Before(lease.ExpiresAt) {
  delete(s.leases, id)
  return false
 }
 return true
}

func (s *Store) Revoke(id string) bool {
 s.mu.Lock()
 defer s.mu.Unlock()
 _, ok := s.leases[id]
 delete(s.leases, id)
 return ok
}

// Prune removes expired records. Expiration is also checked at every Valid
// call; callers must never rely on this periodic cleanup for enforcement.
func (s *Store) Prune() int {
 s.mu.Lock()
 defer s.mu.Unlock()
 now := s.now()
 removed := 0
 for id, lease := range s.leases {
  if !now.Before(lease.ExpiresAt) { delete(s.leases, id); removed++ }
 }
 return removed
}
