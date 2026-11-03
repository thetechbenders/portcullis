package lease

import (
	"errors"
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
	if !s.Valid(l.ID) {
		t.Fatal("valid lease rejected")
	}
	now = now.Add(MaxDuration - time.Nanosecond)
	if !s.Valid(l.ID) {
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

func TestRevocationAndFailClosed(t *testing.T) {
	s := NewStore(nil)
	if s.Valid("") || s.Valid("unknown") {
		t.Fatal("unknown identity authorized")
	}
	l, err := s.Issue("fixture", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Revoke(l.ID) || s.Valid(l.ID) || s.Revoke(l.ID) {
		t.Fatal("revocation failed")
	}
	if NewStore(nil).Valid(l.ID) {
		t.Fatal("restart should not restore authority")
	}
}

func TestInvalidInput(t *testing.T) {
	s := NewStore(nil)
	for _, d := range []time.Duration{-time.Second, 0, MaxDuration + time.Nanosecond} {
		if _, err := s.Issue("fixture", d); !errors.Is(err, ErrInvalidDuration) {
			t.Fatalf("duration %v: %v", d, err)
		}
	}
	if _, err := s.Issue("", time.Minute); !errors.Is(err, ErrInvalidClient) {
		t.Fatal(err)
	}
}

func TestPrune(t *testing.T) {
	now := time.Unix(0, 0)
	s := NewStore(func() time.Time { return now })
	_, _ = s.Issue("one", time.Minute)
	_, _ = s.Issue("two", MaxDuration)
	now = now.Add(time.Minute)
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
