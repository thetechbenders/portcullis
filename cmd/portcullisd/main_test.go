package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
)

type fakeStartupController struct {
	startErr   error
	holdErr    error
	startCalls int
	holdCalls  int
	holding    chan struct{}
}

func (f *fakeStartupController) Start(context.Context) error {
	f.startCalls++
	return f.startErr
}

func (f *fakeStartupController) HoldFailedStart(ctx context.Context) error {
	f.holdCalls++
	if f.holding != nil {
		close(f.holding)
		<-ctx.Done()
	}
	return f.holdErr
}

func TestStartupGatePreservesFailedStartAndHoldsUntilShutdown(t *testing.T) {
	startErr := errors.New("attestation failed")
	fake := &fakeStartupController{startErr: startErr, holding: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- startController(ctx, fake, slog.New(slog.DiscardHandler)) }()
	select {
	case <-fake.holding:
	case <-time.After(2 * time.Second):
		t.Fatal("startup gate abandoned failed-start isolation")
	}
	select {
	case err := <-done:
		t.Fatalf("failed-start gate exited before cancellation: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, startErr) {
			t.Fatalf("original startup error lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("failed-start gate did not exit after cancellation")
	}
	if fake.startCalls != 1 || fake.holdCalls != 1 {
		t.Fatalf("Start calls %d, isolation holds %d", fake.startCalls, fake.holdCalls)
	}
}

func TestStartupGateNormalStartAndUnexpectedHoldError(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	good := &fakeStartupController{}
	if err := startController(context.Background(), good, logger); err != nil {
		t.Fatalf("successful startup blocked: %v", err)
	}
	if good.startCalls != 1 || good.holdCalls != 0 {
		t.Fatalf("successful startup: %+v", good)
	}

	startErr := errors.New("start failure")
	holdErr := errors.New("safety loop error")
	bad := &fakeStartupController{startErr: startErr, holdErr: holdErr}
	if err := startController(context.Background(), bad, logger); !errors.Is(err, startErr) || !errors.Is(err, holdErr) {
		t.Fatalf("startup or hold failure lost: %v", err)
	}
	if bad.startCalls != 1 || bad.holdCalls != 1 {
		t.Fatalf("failed startup: %+v", bad)
	}
}
