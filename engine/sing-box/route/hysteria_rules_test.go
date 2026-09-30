package route

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

type hysteriaTestRule struct {
	adapter.Rule
	closed atomic.Int32
	err    error
}

func (r *hysteriaTestRule) Close() error { r.closed.Add(1); return r.err }

func TestHysteriaRuleSnapshotClosesAfterLastReaderAndShutdown(t *testing.T) {
	old := &hysteriaTestRule{err: errors.New("retired cleanup failed")}
	current := &hysteriaTestRule{err: errors.New("current cleanup failed")}
	router := &Router{rules: []adapter.Rule{old}, logger: log.NewNOPFactory().Logger()}
	first, last := router.acquireHysteriaRules(), router.acquireHysteriaRules()
	if err := router.ReplaceHysteriaRules([]adapter.Rule{current}); err != nil || old.closed.Load() != 0 {
		t.Fatal("swap closed rules still held by a reader", err)
	}
	router.releaseHysteriaRules(first)
	if old.closed.Load() != 0 {
		t.Fatal("first reader prematurely closed retired rules")
	}
	active := router.acquireHysteriaRules()
	closing := make(chan error, 1)
	go func() { closing <- router.Close() }()
	select {
	case <-closing:
		t.Fatal("shutdown overtook active rule readers")
	case <-time.After(10 * time.Millisecond):
	}
	router.releaseHysteriaRules(last)
	if old.closed.Load() != 1 || current.closed.Load() != 0 {
		t.Fatal("last reader did not release only its retired snapshot")
	}
	router.releaseHysteriaRules(active)
	select {
	case err := <-closing:
		if !errors.Is(err, current.err) || current.closed.Load() != 1 {
			t.Fatal("shutdown lost current cleanup error or closed rules twice", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown retained a rule reader")
	}
	if router.acquireHysteriaRules() != nil {
		t.Fatal("closed router admitted another reader")
	}
	rejected := &hysteriaTestRule{}
	if err := router.ReplaceHysteriaRules([]adapter.Rule{rejected}); !errors.Is(err, net.ErrClosed) || rejected.closed.Load() != 1 {
		t.Fatal("closed router accepted or leaked a candidate", err)
	}
}
