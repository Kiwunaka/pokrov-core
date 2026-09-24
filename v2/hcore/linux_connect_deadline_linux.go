package hcore

import (
	"context"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

var linuxBootRefPattern = regexp.MustCompile(`^linux:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type linuxConnectDeadline struct {
	BootRef string `json:"boot_ref"`
	StartedElapsedMS int64 `json:"started_elapsed_ms"`
	DeadlineElapsedMS int64 `json:"deadline_elapsed_ms"`
}

func (deadline *linuxConnectDeadline) valid() bool {
	return deadline != nil && linuxBootRefPattern.MatchString(deadline.BootRef) &&
		deadline.StartedElapsedMS >= 0 && deadline.DeadlineElapsedMS <= 9007199254740991 &&
		deadline.DeadlineElapsedMS > deadline.StartedElapsedMS &&
		deadline.DeadlineElapsedMS-deadline.StartedElapsedMS <= 86400000
}

func (deadline *linuxConnectDeadline) current() bool {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || "linux:"+strings.TrimSpace(string(data)) != deadline.BootRef { return false }
	var elapsed unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &elapsed) != nil { return false }
	seconds, nanos := int64(elapsed.Sec), int64(elapsed.Nsec)
	if seconds < 0 || seconds > 9007199254740 || nanos < 0 || nanos >= 1000000000 { return false }
	ms := seconds*1000 + nanos/1000000
	return ms >= deadline.StartedElapsedMS && ms < deadline.DeadlineElapsedMS
}

// Successful start does not promote an attempt into a healthy leased flow.
// This guard owns the same Core context until its original deadline or stop.
func (deadline *linuxConnectDeadline) watch(ctx context.Context, cancel context.CancelFunc,
	promotedUntil *atomic.Int64, promotionMu *sync.Mutex) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		promotionMu.Lock()
		limit := promotedUntil.Load()
		if limit == 0 {
			if !deadline.current() { cancel(); promotionMu.Unlock(); return }
		} else {
			var elapsed unix.Timespec
			if unix.ClockGettime(unix.CLOCK_BOOTTIME, &elapsed) != nil ||
				int64(elapsed.Sec)*1000+int64(elapsed.Nsec)/1000000 >= limit {
				cancel(); promotionMu.Unlock(); return
			}
		}
		promotionMu.Unlock()
		select {
		case <-ctx.Done(): return
		case <-ticker.C:
		}
	}
}
