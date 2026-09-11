package urltest

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/observable"
)

var _ adapter.URLTestHistoryStorage = (*HistoryStorage)(nil)

type ProbeStage uint32

const (
	ProbeStageConnect ProbeStage = iota
	ProbeStageTLS
	ProbeStageResponse
)

// ProbeError retains the observed stage without exposing the target or the
// underlying transport message through Error(). errors.Is/As still work.
type ProbeError struct {
	Stage ProbeStage
	Err   error
}

func (e *ProbeError) Error() string {
	switch e.Stage {
	case ProbeStageConnect:
		return "URL probe connection failed"
	case ProbeStageTLS:
		return "URL probe TLS negotiation failed"
	case ProbeStageResponse:
		return "URL probe response failed"
	default:
		return "URL probe failed"
	}
}

func (e *ProbeError) Unwrap() error { return e.Err }

// ObservedFailure returns only facts carried by typed errors and probe stages.
// An unqualified timeout contains no evidence of transport or filtering cause.
func ObservedFailure(err error) string {
	if err == nil || errors.Is(err, context.Canceled) {
		return ""
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return "dns_lookup"
	}
	var networkError net.Error
	if !errors.Is(err, context.DeadlineExceeded) &&
		!(errors.As(err, &networkError) && networkError.Timeout()) {
		return ""
	}
	var operationError *net.OpError
	if errors.As(err, &operationError) &&
		(operationError.Net == "udp" || operationError.Net == "udp4" || operationError.Net == "udp6") {
		return "udp_timeout"
	}
	var probeError *ProbeError
	if errors.As(err, &probeError) {
		switch probeError.Stage {
		case ProbeStageTLS:
			return "tls_timeout"
		case ProbeStageResponse:
			return "response_timeout"
		}
	}
	return ""
}

type HistoryStorage struct {
	access       sync.RWMutex
	delayHistory map[string]*adapter.URLTestHistory
	updateHook   *observable.Subscriber[struct{}]
}

func NewHistoryStorage() *HistoryStorage {
	return &HistoryStorage{
		delayHistory: make(map[string]*adapter.URLTestHistory),
	}
}

func (s *HistoryStorage) SetHook(hook *observable.Subscriber[struct{}]) {
	s.access.Lock()
	s.updateHook = hook
	s.access.Unlock()
}

func (s *HistoryStorage) LoadURLTestHistory(tag string) *adapter.URLTestHistory {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return s.delayHistory[tag]
}

func (s *HistoryStorage) DeleteURLTestHistory(tag string) {
	s.StoreURLTestHistory(tag, &adapter.URLTestHistory{
		Delay: 65535,
		Time:  time.Now(),
	})
	// s.access.Lock()
	// // delete(s.delayHistory, tag)
	// s.access.Unlock()
	// s.notifyUpdated()
}

func (s *HistoryStorage) StoreURLTestHistory(tag string, history *adapter.URLTestHistory) *adapter.URLTestHistory {
	s.access.Lock()
	if old, ok := s.delayHistory[tag]; ok && history != nil {
		old.Delay = history.Delay
		old.Time = history.Time
		if history.IpInfo != nil {
			old.IpInfo = history.IpInfo
		}
	} else {
		s.delayHistory[tag] = history
	}
	history = s.delayHistory[tag]
	s.access.Unlock()
	s.notifyUpdated()
	return history
}

func (s *HistoryStorage) AddOnlyIpToHistory(tag string, history *adapter.URLTestHistory) {
	s.access.Lock()
	if old, ok := s.delayHistory[tag]; ok && history != nil {
		old.IpInfo = history.IpInfo
	} else {
		s.delayHistory[tag] = history
	}
	s.access.Unlock()
	s.notifyUpdated()
}

func (s *HistoryStorage) notifyUpdated() {
	s.access.RLock()
	updateHook := s.updateHook
	s.access.RUnlock()
	if updateHook != nil {
		updateHook.Emit(struct{}{})
	}
}

func (s *HistoryStorage) Close() error {
	s.access.Lock()
	defer s.access.Unlock()
	s.updateHook = nil
	return nil
}

func URLTest(ctx context.Context, link string, detour N.Dialer) (t uint16, err error) {
	if detour == nil {
		err = fmt.Errorf("urltest dialer is nil")
		return
	}
	link = resolveURLTestLink(link)
	linkURL, err := url.Parse(link)
	if err != nil {
		return
	}
	hostname := linkURL.Hostname()
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	start := time.Now()
	var stage atomic.Uint32
	stage.Store(uint32(ProbeStageConnect))
	defer func() {
		if err != nil {
			err = &ProbeError{Stage: ProbeStage(stage.Load()), Err: err}
		}
	}()
	instance, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return
	}
	defer instance.Close()
	if N.NeedHandshakeForWrite(instance) {
		start = time.Now()
	}
	req, err := http.NewRequest(http.MethodHead, link, nil)
	if err != nil {
		return
	}
	select {
	case <-ctx.Done():
		err = context.Cause(ctx)
		return
	default:
	}
	stage.Store(uint32(ProbeStageResponse))
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() { stage.Store(uint32(ProbeStageTLS)) },
		TLSHandshakeDone: func(_ tls.ConnectionState, handshakeErr error) {
			if handshakeErr == nil {
				stage.Store(uint32(ProbeStageResponse))
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return instance, nil
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: C.TCPTimeout,
	}
	defer client.CloseIdleConnections()
	select {
	case <-ctx.Done():
		err = context.Cause(ctx)
		return
	default:
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()

	t = uint16(time.Since(start) / time.Millisecond)

	if IsUnifiedDelayFromContext(ctx) {
		select {
		case <-ctx.Done():
			err = context.Cause(ctx)
			return
		default:
		}
		second := time.Now()
		resp, err = client.Do(req)
		if err != nil {
			return
		}
		resp.Body.Close()
		t = uint16(time.Since(second) / time.Millisecond) //to avid timeout in the second call
	}
	return
}

func resolveURLTestLink(link string) string {
	if link != "" {
		return link
	}
	return "https://api.pokrov.space/api/public/authenticated-egress-probe"
}
