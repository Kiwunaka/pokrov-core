package hcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	SJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

var apiProxy struct {
	sync.Mutex
	cancel   context.CancelFunc
	instance *box.Box
	server   *http.Server
}

func StartApiLoopbackProxy(boardURL, publicKey string, platform libbox.PlatformInterface) (int32, error) {
	if platform == nil {
		return 0, errors.New("platform interface required")
	}
	apiProxy.Lock()
	defer apiProxy.Unlock()
	if apiProxy.instance != nil {
		return 0, errors.New("API proxy is already running")
	}
	ctx, cancel := context.WithCancel(libbox.BaseContext(platform))
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, libbox.WrapPlatformInterface(platform))
	raw, err := json.Marshal(map[string]any{"dns": map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "local"}}, "final": "local"}, "outbounds": []any{map[string]any{"type": "mts", "tag": "mts-api", "board_url": boardURL, "public_key": publicKey, "network": "tcp", "service": "api"}}})
	if err != nil {
		cancel()
		return 0, err
	}
	options, err := SJSON.UnmarshalExtendedContext[option.Options](ctx, raw)
	if err != nil {
		cancel()
		return 0, err
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		return 0, err
	}
	if err = instance.Start(); err != nil {
		instance.Close()
		cancel()
		return 0, err
	}
	out, ok := instance.Outbound().Outbound("mts-api")
	if !ok {
		instance.Close()
		cancel()
		return 0, errors.New("API transport unavailable")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		instance.Close()
		cancel()
		return 0, err
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || !allowedAPITarget(r.Host) {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		remote, err := out.DialContext(r.Context(), "tcp", M.Socksaddr{})
		if err != nil {
			http.Error(w, "connection unavailable", http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			remote.Close()
			http.Error(w, "connection unavailable", http.StatusInternalServerError)
			return
		}
		local, rw, err := hijacker.Hijack()
		if err != nil {
			remote.Close()
			return
		}
		if _, err = fmt.Fprint(rw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			local.Close()
			remote.Close()
			return
		}
		if err = rw.Flush(); err != nil {
			local.Close()
			remote.Close()
			return
		}
		stop := context.AfterFunc(ctx, func() { local.Close(); remote.Close() })
		defer stop()
		defer local.Close()
		defer remote.Close()
		go io.Copy(remote, rw)
		io.Copy(local, remote)
	})}
	apiProxy.cancel = cancel
	apiProxy.instance = instance
	apiProxy.server = server
	go server.Serve(listener)
	return int32(listener.Addr().(*net.TCPAddr).Port), nil
}
func StopApiLoopbackProxy() {
	apiProxy.Lock()
	defer apiProxy.Unlock()
	if apiProxy.cancel != nil {
		apiProxy.cancel()
		apiProxy.server.Close()
		apiProxy.instance.Close()
		apiProxy.cancel = nil
		apiProxy.server = nil
		apiProxy.instance = nil
	}
}

func allowedAPITarget(target string) bool {
	host, port, err := net.SplitHostPort(target)
	if err != nil || port != "443" {
		return false
	}
	switch strings.ToLower(host) {
	case "app.pokrov.space", "api.pokrov.space":
		return true
	}
	return false
}
