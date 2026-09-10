//go:build with_clash_api

package hcore

import (
	"syscall"
	"testing"
	"unsafe"
)

var lifecycleHandleCount = syscall.NewLazyDLL("kernel32.dll").NewProc("GetProcessHandleCount")

func countLifecycleResources(t *testing.T) int {
	t.Helper()
	var count uint32
	result, _, err := lifecycleHandleCount.Call(^uintptr(0), uintptr(unsafe.Pointer(&count)))
	if result == 0 {
		t.Fatal(err)
	}
	return int(count)
}
