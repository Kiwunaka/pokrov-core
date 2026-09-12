package hcore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kiwunaka/POKROV-core/internal/observability"
	"github.com/sagernet/sing-box/log"
)

func TestSetupDoesNotLogCallerPathsOrListenAddress(t *testing.T) {
	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "V01_CANARY_PATH")
	if err := os.MkdirAll(filepath.Join(root, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{}, &output, "", nil, false)
	previousLogger := log.StdLogger()
	log.SetStdLogger(factory.Logger())
	observer := static.logObserver.Subscribe(16)
	t.Cleanup(func() {
		_, _ = Stop()
		static.logObserver.Unsubscribe(observer)
		log.SetStdLogger(previousLogger)
		factory.Close()
		_ = os.Chdir(previousDir)
	})
	if err := Setup(&SetupRequest{
		BasePath: root, WorkingDir: root, TempDir: root,
		Mode: SetupMode_OLD, Listen: "V01_CANARY_LISTEN", Debug: false,
	}, nil); err != nil {
		t.Fatal(err)
	}
	if output.Len() == 0 || strings.Contains(output.String(), "V01_CANARY") {
		t.Fatal("setup stderr is absent or contains caller paths/listen address")
	}
	if len(observer) == 0 {
		t.Fatal("setup did not publish legacy diagnostics")
	}
	for {
		select {
		case event := <-observer:
			if strings.Contains(event.Message, "V01_CANARY") {
				t.Fatal("setup observer contains caller paths/listen address")
			}
		default:
			return
		}
	}
}

func TestRuntimeFailureRedactsEveryDiagnosticOutput(t *testing.T) {
	const planted = "V01_CANARY https://v01.invalid/private 203.0.113.71 v01@example.invalid"
	original := errors.New("invalid config: " + planted)
	var output bytes.Buffer
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{}, &output, "", nil, false)
	previousLogger := log.StdLogger()
	previousState := static.CoreState
	log.SetStdLogger(factory.Logger())
	t.Cleanup(func() {
		log.SetStdLogger(previousLogger)
		static.CoreState = previousState
		factory.Close()
	})

	info, err := errorWrapper(MessageType_ERROR_BUILDING_CONFIG, original)
	if err.Error() != "CORE-005" || info.Message != "CORE-005" {
		t.Fatal("runtime error or status exposed raw failure material")
	}
	if !errors.Is(err, original) {
		t.Fatal("runtime error lost its original typed cause")
	}
	if observability.ClassifyStartError(err) != "CORE-005" {
		t.Fatal("structured event lost the classified failure")
	}
	if output.Len() == 0 || strings.Contains(output.String(), "V01_CANARY") {
		t.Fatal("runtime stderr log is absent or contains planted material")
	}
}
