package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestStartedServiceCloseEndsObserversAndRejectsReuse(t *testing.T) {
	s := NewStartedService(ServiceOptions{Context: context.Background(), LogMaxLines: 4})
	_, statusDone, _ := s.serviceStatusObserver.Subscribe()
	_, logDone, _ := s.logObserver.Subscribe()
	_, urlDone, _ := s.urlTestObserver.Subscribe()
	_, clashDone, _ := s.clashModeObserver.Subscribe()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, done := range []<-chan struct{}{statusDone, logDone, urlDone, clashDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("terminal close left an observer subscription alive")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("repeated terminal close failed: %v", err)
	}
	if err := s.StartOrReloadServiceOptions(option.Options{}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed service accepted reuse: %v", err)
	}
}

func TestManagedLoggerDoesNotRetainPlantedMaterialInAnyLogSink(t *testing.T) {
	for _, debug := range []bool{false, true} {
		t.Run(map[bool]string{false: "release", true: "debug"}[debug], func(t *testing.T) {
			handler := &recordingPlatformHandler{}
			service := NewStartedService(ServiceOptions{
				Context: context.Background(), Handler: handler, Debug: debug, LogMaxLines: 8,
			})
			var output bytes.Buffer
			factory := log.NewDefaultFactory(context.Background(), log.Formatter{
				DisableColors: true, DisableTimestamp: true,
			}, &output, "", service, true)
			defer factory.Close()
			if err := factory.Start(); err != nil {
				t.Fatal(err)
			}
			factoryEntries, _, err := factory.Subscribe()
			if err != nil {
				t.Fatal(err)
			}
			defer factory.UnSubscribe(factoryEntries)
			serviceEntries, _, err := service.logObserver.Subscribe()
			if err != nil {
				t.Fatal(err)
			}
			defer service.logObserver.UnSubscribe(serviceEntries)
			const planted = "PLANTED-PRIVATE-MATERIAL"
			logger := factory.NewLogger(planted)
			messages := []string{
				"outbound failed: Authorization: Bearer " + planted,
				planted + " awg_safe_diag code=handshake_retry occurrence=1",
				"awg_safe_diag code=handshake_retry occurrence=1 token=" + planted,
				"selected endpoint URL test failed category=tls_certificate",
				"selected endpoint URL test failed category=tls_certificate token=" + planted,
			}
			for _, message := range messages {
				logger.Warn(message)
				select {
				case entry := <-factoryEntries:
					if strings.Contains(entry.Message, planted) {
						t.Fatal("factory subscription retained planted material")
					}
				case <-time.After(time.Second):
					t.Fatal("factory log subscription did not settle")
				}
				select {
				case entry := <-serviceEntries:
					if strings.Contains(entry.Message, planted) {
						t.Fatal("native service subscription retained planted material")
					}
				case <-time.After(time.Second):
					t.Fatal("native service log subscription did not settle")
				}
			}
			if strings.Contains(output.String(), planted) || strings.Contains(strings.Join(handler.debugMessages, "\n"), planted) {
				t.Fatal("writer or host callback retained planted material")
			}
			service.WriteMessage(log.LevelError, planted)
			for entry := service.logLines.Front(); entry != nil; entry = entry.Next() {
				if strings.Contains(entry.Value.Message, planted) {
					t.Fatal("native replay buffer retained planted material")
				}
			}
		})
	}
}

type recordingPlatformHandler struct {
	debugMessages []string
}

func (h *recordingPlatformHandler) ServiceStop() error { return nil }

func (h *recordingPlatformHandler) ServiceReload() error { return nil }

func (h *recordingPlatformHandler) SystemProxyStatus() (*SystemProxyStatus, error) {
	return &SystemProxyStatus{}, nil
}

func (h *recordingPlatformHandler) SetSystemProxyEnabled(bool) error { return nil }

func (h *recordingPlatformHandler) WriteDebugMessage(message string) {
	h.debugMessages = append(h.debugMessages, message)
}
