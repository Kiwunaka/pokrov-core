package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
)

func TestClosedMultiplexerDoesNotDialSingleUse(t *testing.T) {
	var dials atomic.Int32
	m := newQueryMultiplexer(queryMultiplexerOptions{
		probeReuse: true,
		dial:       func(context.Context) (net.Conn, error) { dials.Add(1); return nil, errors.New("unexpected dial") },
	})
	m.Close()
	done := make(chan error, 1)
	m.ExchangeAsync(context.Background(), new(mDNS.Msg), func(_ *mDNS.Msg, err error) { done <- err })
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed transport returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closed exchange did not finish")
	}
	if dials.Load() != 0 {
		t.Fatal("closed transport dialled")
	}
}

func TestMultiplexerCancelsUnpooledConnections(t *testing.T) {
	for _, operation := range []string{"close", "reset"} {
		for _, probe := range []bool{false, true} {
			name := operation
			if probe {
				name += "_with_probe"
			}
			t.Run(name, func(t *testing.T) {
				started := make(chan struct{}, 2)
				ended := make(chan struct{}, 2)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				m := newQueryMultiplexer(queryMultiplexerOptions{
					probeReuse: true,
					dial: func(context.Context) (net.Conn, error) {
						client, peer := net.Pipe()
						t.Cleanup(func() { client.Close(); peer.Close() })
						started <- struct{}{}
						return client, nil
					},
					write: func(net.Conn, *mDNS.Msg, uint16) error { return nil },
					readNext: func(conn net.Conn) (*mDNS.Msg, error) {
						var buffer [1]byte
						_, err := conn.Read(buffer[:])
						ended <- struct{}{}
						return nil, err
					},
				})
				defer m.Close()
				message := new(mDNS.Msg)
				count := 1
				if probe {
					message.SetQuestion("example.invalid.", mDNS.TypeA)
					count = 2
				}
				done := make(chan error, 1)
				m.ExchangeAsync(ctx, message, func(_ *mDNS.Msg, err error) { done <- err })
				for i := 0; i < count; i++ {
					select {
					case <-started:
					case <-time.After(time.Second):
						t.Fatal("dial did not start")
					}
				}
				if operation == "close" {
					m.Close()
				} else {
					m.Reset()
				}
				select {
				case err := <-done:
					if !errors.Is(err, net.ErrClosed) {
						t.Fatalf("exchange returned %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("unpooled query survived transport teardown")
				}
				for i := 0; i < count; i++ {
					select {
					case <-ended:
					case <-time.After(time.Second):
						t.Fatal("unpooled socket survived transport teardown")
					}
				}
			})
		}
	}
}

func TestMultiplexerClosesLateSingleUseDialWithoutWriting(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var writes atomic.Int32
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	m := newQueryMultiplexer(queryMultiplexerOptions{
		probeReuse: true,
		dial: func(context.Context) (net.Conn, error) {
			close(entered)
			<-release
			return client, nil // Deliberately ignores cancellation.
		},
		write:    func(net.Conn, *mDNS.Msg, uint16) error { writes.Add(1); return nil },
		readNext: func(net.Conn) (*mDNS.Msg, error) { return new(mDNS.Msg), nil },
	})
	done := make(chan error, 1)
	m.ExchangeAsync(context.Background(), new(mDNS.Msg), func(_ *mDNS.Msg, err error) { done <- err })
	<-entered
	m.Close()
	close(release)
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("late dial returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("late dial did not finish")
	}
	if writes.Load() != 0 {
		t.Fatal("late connection was used after Close")
	}
	// The callback can run before defer Close. Read must promptly see EOF.
	peer.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := peer.Read(b[:]); err == nil || !errors.Is(err, io.EOF) {
		t.Fatalf("late connection was not closed: %v", err)
	}
}
