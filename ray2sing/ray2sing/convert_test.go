package ray2sing

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
)

func TestConversionFailureDoesNotPrintProxyInput(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	original := os.Stderr
	os.Stderr = write
	t.Cleanup(func() { os.Stderr = original; _ = write.Close() })
	_, err = Ray2SingboxOptions(context.Background(), "vmess://private-profile-marker", false)
	_ = write.Close()
	os.Stderr = original
	output, readErr := io.ReadAll(read)
	if err == nil || readErr != nil || strings.Contains(string(output), "private-profile-marker") {
		t.Fatal("URI conversion failure leaked input")
	}
}
