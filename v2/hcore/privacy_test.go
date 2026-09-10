package hcore

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Kiwunaka/POKROV-core/internal/observability"
	"github.com/sagernet/sing-box/log"
)

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
