package transport

import (
	"context"
	"errors"
	"net"
	"testing"

	mDNS "github.com/miekg/dns"
)

func TestResetDoesNotAdmitProbeFromOldGeneration(t *testing.T) {
	m := newQueryMultiplexer(queryMultiplexerOptions{
		probeReuse: true,
		dial: func(context.Context) (net.Conn, error) {
			return nil, errors.New("synthetic dial must not be admitted")
		},
	})
	defer m.Close()
	// Pause a dispatch after binding its single-use query, then reset before
	// it can request a reuse probe. WithoutCancel must not erase this fence.
	old, release, err := m.lifetime.bind(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	m.Reset()
	message := new(mDNS.Msg)
	message.SetQuestion("example.invalid.", mDNS.TypeA)
	m.maybeStartProbe(old, message)
	m.probeAccess.Lock()
	defer m.probeAccess.Unlock()
	if !m.lastProbeTime.IsZero() || m.reuseState.Load() != reuseStateUnknown {
		t.Fatal("old generation admitted a probe after Reset")
	}
}
