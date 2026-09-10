//go:build with_clash_api && (linux || windows)

package hcore

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/experimental/libbox"
	"golang.org/x/net/proxy"
)

func TestStartStopReleasesServiceObservers(t *testing.T) {
	// Keep Go's process-wide thread pool from growing during the ownership
	// assertion. Default-scheduler artifact resource samples are a separate gate.
	previousProcs := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previousProcs)
	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = Stop()
		_ = os.Chdir(previousDir)
	})
	if err := Setup(&SetupRequest{BasePath: root, WorkingDir: root, TempDir: root, Mode: SetupMode_OLD}, nil); err != nil {
		t.Fatal(err)
	}
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	go func() {
		for {
			conn, err := origin.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	portReservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portReservation.Addr().(*net.TCPAddr).Port
	_ = portReservation.Close()
	request := &StartRequest{
		ConfigContent:      fmt.Sprintf(`{"log":{"disabled":true},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`, port),
		EnableRawConfig:    true,
		DisableMemoryLimit: true,
	}
	connect := func() net.Conn {
		t.Helper()
		dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, &net.Dialer{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		conn, err := dialer.Dial("tcp", origin.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write([]byte("R12")); err != nil {
			t.Fatal(err)
		}
		var reply [3]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "R12" {
			t.Fatalf("loopback session did not echo the marker: %v", err)
		}
		return conn
	}
	assertCancelled := func(conn net.Conn) {
		t.Helper()
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		var data [1]byte
		_, err := conn.Read(data[:])
		if err == nil {
			t.Fatal("stopped session remained readable")
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("stopped session remained open until the read deadline")
		}
	}
	cycle := func() {
		t.Helper()
		started, err := Start(libbox.BaseContext(nil), request)
		if err != nil || started.CoreState != CoreStates_STARTED {
			t.Fatalf("start failed: %v; synthetic cause: %v", err, errors.Unwrap(err))
		}
		oldSession := connect()
		restarted, err := Restart(libbox.BaseContext(nil), request)
		if err != nil || restarted.CoreState != CoreStates_STARTED {
			_ = oldSession.Close()
			t.Fatalf("restart failed: %v", err)
		}
		assertCancelled(oldSession)
		newSession := connect()
		stopped, err := Stop()
		if err != nil || stopped.CoreState != CoreStates_STOPPED {
			t.Fatalf("stop failed: %v", err)
		}
		assertCancelled(newSession)
	}
	for range 3 {
		cycle() // Exclude process-wide initialization from the retained-resource check.
	}
	time.Sleep(100 * time.Millisecond)
	baseline := runtime.NumGoroutine()
	resourcesBefore := countLifecycleResources(t)
	for cycleIndex := range 12 {
		cycle()
		t.Logf("cycle=%d goroutines=%d OS resources=%d", cycleIndex+1, runtime.NumGoroutine(), countLifecycleResources(t))
	}
	deadline := time.Now().Add(2 * time.Second)
	for (runtime.NumGoroutine() > baseline+2 || countLifecycleResources(t) > resourcesBefore+2) && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}
	final := runtime.NumGoroutine()
	resourcesAfter := countLifecycleResources(t)
	t.Logf("goroutines before=%d after=%d; OS resources before=%d after=%d; measured cycles=12 each start/restart/stop; old and new sessions cancelled", baseline, final, resourcesBefore, resourcesAfter)
	if final > baseline+2 {
		t.Fatalf("stopped services retain goroutines: before=%d after=%d", baseline, final)
	}
	if resourcesAfter > resourcesBefore+2 {
		t.Fatalf("stopped services retain OS resources: before=%d after=%d", resourcesBefore, resourcesAfter)
	}
}
