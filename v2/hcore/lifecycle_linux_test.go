//go:build with_clash_api

package hcore

import (
	"os"
	"testing"
)

func countLifecycleResources(t *testing.T) int {
	t.Helper()
	files, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(files)
}
