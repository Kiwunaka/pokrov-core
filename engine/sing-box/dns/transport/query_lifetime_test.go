package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func awaitQueryCancellation(t *testing.T, ctx context.Context, want error) {
	t.Helper()
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), want) {
			t.Fatalf("cause = %v, want %v", context.Cause(ctx), want)
		}
	case <-time.After(time.Second):
		t.Fatal("query was not cancelled")
	}
}

func TestQueryLifetimeClose(t *testing.T) {
	l := newQueryLifetime()
	ctx, cleanup, err := l.bind(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	l.close()
	awaitQueryCancellation(t, ctx, net.ErrClosed)
	l.close()
	l.reset()
	if _, _, err := l.bind(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("bind after Close: %v", err)
	}
}

func TestQueryLifetimeReset(t *testing.T) {
	l := newQueryLifetime()
	defer l.close()
	old, releaseOld, err := l.bind(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer releaseOld()
	l.reset()
	awaitQueryCancellation(t, old, net.ErrClosed)
	fresh, releaseFresh, err := l.bind(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer releaseFresh()
	if fresh.Err() != nil {
		t.Fatal("reset cancelled the new generation")
	}
}

func TestQueryLifetimeParentAndCleanupAreScoped(t *testing.T) {
	l := newQueryLifetime()
	defer l.close()
	parent, cancel := context.WithCancel(context.Background())
	ctx, cleanup, err := l.bind(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	other, releaseOther, err := l.bind(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer releaseOther()
	cancel()
	awaitQueryCancellation(t, ctx, context.Canceled)
	cleanup()
	if other.Err() != nil {
		t.Fatal("one query cancelled another")
	}
	if _, _, err := l.bind(parent); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled parent accepted: %v", err)
	}
}

func TestQueryLifetimeConcurrentResetAndClose(t *testing.T) {
	l := newQueryLifetime()
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ctx, cleanup, err := l.bind(context.Background())
			if err == nil {
				defer cleanup()
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
					t.Error("query survived close")
				}
			}
		}()
	}
	l.reset()
	l.close()
	workers.Wait()
}
