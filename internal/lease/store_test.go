package lease

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestLeaseLifecycle(t *testing.T) {
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	s := NewStore(func() time.Time { return now })
	l, err := s.Issue("fixture-client", MaxDuration)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.ID) != 32 || l.Client != "fixture-client" {
		t.Fatalf("unexpected lease: %+v", l)
	}
	found, ok := s.Lookup(l.ID)
	if !ok || found != l {
		t.Fatalf("lookup mismatch: %+v, %v", found, ok)
	}
	now = now.Add(MaxDuration - time.Nanosecond)
	if !s.Valid(l.ID) || s.Prune() != 0 {
		t.Fatal("lease expired too early")
	}
	now = now.Add(time.Nanosecond)
	if s.Valid(l.ID) {
		t.Fatal("lease remained valid at expiration")
	}
	if s.Revoke(l.ID) {
		t.Fatal("expired lease should have been removed")
	}
}

func TestRevocationAndVolatileRestart(t *testing.T) {
	s := NewStore(nil)
	if s.Valid("") || s.Valid("unknown") {
		t.Fatal("unknown ID validated")
	}
	l, err := s.Issue("fixture", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Revoke(l.ID) || s.Valid(l.ID) || s.Revoke(l.ID) || s.Revoke("") {
		t.Fatal("revocation failed")
	}
	if NewStore(nil).Valid(l.ID) {
		t.Fatal("fresh volatile store unexpectedly has old lease")
	}
}

func TestRevokeExpiredNotPruned(t *testing.T) {
	now := time.Unix(0, 0)
	s := NewStore(func() time.Time { return now })
	l, err := s.Issue("fixture", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if s.Revoke(l.ID) || s.Valid(l.ID) {
		t.Fatal("expired record was treated as live")
	}
}

func TestInvalidInputAndDuplicate(t *testing.T) {
	s := NewStore(nil)
	for _, d := range []time.Duration{-time.Second, 0, MaxDuration + time.Nanosecond} {
		if _, err := s.Issue("fixture", d); !errors.Is(err, ErrInvalidDuration) {
			t.Fatalf("duration %v: %v", d, err)
		}
	}
	for _, client := range []string{"", string(make([]byte, MaxClientBytes+1))} {
		if _, err := s.Issue(client, time.Minute); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("client length %d: %v", len(client), err)
		}
	}
	if _, err := s.Issue("fixture", time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Issue("fixture", time.Minute); !errors.Is(err, ErrAlreadyActive) {
		t.Fatalf("duplicate lease: %v", err)
	}
}

func TestPrune(t *testing.T) {
	now := time.Unix(0, 0)
	s := NewStore(func() time.Time { return now })
	if _, err := s.Issue("one", time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Issue("two", MaxDuration); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute - time.Nanosecond)
	if n := s.Prune(); n != 0 {
		t.Fatalf("removed %d, want 0", n)
	}
	now = now.Add(time.Nanosecond)
	if n := s.Prune(); n != 1 {
		t.Fatalf("removed %d, want 1", n)
	}
	now = now.Add(MaxDuration)
	if n := s.Prune(); n != 1 {
		t.Fatalf("removed %d, want 1", n)
	}
	if n := s.Prune(); n != 0 {
		t.Fatalf("removed %d, want 0", n)
	}
}

func TestConcurrentOperations(t *testing.T) {
	s := NewStore(nil)
	var wg sync.WaitGroup
	const workers = 40
	ids := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l, err := s.Issue(fmt.Sprintf("client-%d", i), time.Minute)
			if err != nil {
				t.Errorf("issue: %v", err)
				return
			}
			ids <- l.ID
			if !s.Valid(l.ID) {
				t.Errorf("new lease invalid: %s", l.ID)
			}
			s.Prune()
			if !s.Revoke(l.ID) || s.Valid(l.ID) {
				t.Errorf("revoked lease validated: %s", l.ID)
			}
		}(i)
	}
	wg.Wait()
	close(ids)
	seen := make(map[string]bool)
	for id := range ids {
		if seen[id] {
			t.Fatalf("duplicate ID: %s", id)
		}
		seen[id] = true
	}
	if len(seen) != workers {
		t.Fatalf("received %d IDs, want %d", len(seen), workers)
	}
}

func TestCapacity(t *testing.T) {
	s := NewStore(nil)
	for i := 0; i < MaxLeases; i++ {
		if _, err := s.Issue(fmt.Sprintf("client-%d", i), MaxDuration); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Issue("overflow", time.Minute); !errors.Is(err, ErrCapacity) {
		t.Fatalf("expected capacity error: %v", err)
	}
}
