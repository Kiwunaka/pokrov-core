package libbox

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	mDNS "github.com/miekg/dns"
)

type hostDNSFixture struct {
	raw      bool
	lookup   func(*ExchangeContext, string, string) error
	exchange func(*ExchangeContext, []byte) error
}

func (h *hostDNSFixture) Raw() bool { return h.raw }
func (h *hostDNSFixture) Lookup(ctx *ExchangeContext, network, domain string) error {
	return h.lookup(ctx, network, domain)
}
func (h *hostDNSFixture) Exchange(ctx *ExchangeContext, message []byte) error {
	return h.exchange(ctx, message)
}

func TestPlatformDNSAsyncKeepsHostCallbacks(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(map[bool]string{false: "lookup", true: "raw"}[raw], func(t *testing.T) {
			host := &hostDNSFixture{
				raw: raw,
				lookup: func(ctx *ExchangeContext, network, domain string) error {
					if network != "ip4" || domain != "candidate.pokrov.invalid." {
						t.Error("host received the wrong DNS question")
					}
					ctx.Success("192.0.2.10")
					return nil
				},
				exchange: func(ctx *ExchangeContext, wire []byte) error {
					var request mDNS.Msg
					if err := request.Unpack(wire); err != nil {
						return err
					}
					response := new(mDNS.Msg).SetReply(&request)
					answer, err := mDNS.NewRR("candidate.pokrov.invalid. 60 IN A 192.0.2.10")
					if err != nil {
						return err
					}
					response.Answer = []mDNS.RR{answer}
					wire, err = response.Pack()
					if err != nil {
						return err
					}
					ctx.RawSuccess(wire)
					return nil
				},
			}
			transport, err := newPlatformTransport(context.Background(), logger.NOP(), host, "platform", option.LocalDNSServerOptions{})
			if err != nil {
				t.Fatal(err)
			}
			request := new(mDNS.Msg).SetQuestion("candidate.pokrov.invalid.", mDNS.TypeA)
			done := make(chan struct{})
			transport.ExchangeAsync(context.Background(), request, func(response *mDNS.Msg, err error) {
				defer close(done)
				if err != nil {
					t.Error(err)
					return
				}
				if response.Id != request.Id || len(response.Answer) != 1 || response.Answer[0].(*mDNS.A).A.String() != "192.0.2.10" {
					t.Error("asynchronous platform DNS lost the host response")
				}
			})
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("platform DNS callback did not finish")
			}
		})
	}
}

func TestPlatformDNSAsyncCancellationReachesHost(t *testing.T) {
	started, joined := make(chan struct{}), make(chan struct{})
	host := &hostDNSFixture{lookup: func(ctx *ExchangeContext, network, domain string) error {
		close(started)
		<-ctx.context.Done()
		close(joined)
		return ctx.context.Err()
	}}
	transport, err := newPlatformTransport(context.Background(), logger.NOP(), host, "platform", option.LocalDNSServerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	transport.ExchangeAsync(ctx, new(mDNS.Msg).SetQuestion("candidate.pokrov.invalid.", mDNS.TypeA), func(response *mDNS.Msg, err error) { result <- err })
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("host DNS callback did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DNS cancellation was lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled platform DNS did not settle")
	}
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("host DNS callback retained the cancelled operation")
	}
}
