package hcore

import (
	"encoding/json"
	"regexp"
	"time"

	"golang.org/x/sys/unix"
)

var linuxATSLeasePattern = regexp.MustCompile(`^lease_[a-f0-9]{32}$`)
const linuxATSTimeLayout = "2006-01-02T15:04:05Z"

func linuxATSTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(linuxATSTimeLayout, value)
	return parsed, err == nil && parsed.Format(linuxATSTimeLayout) == value
}

// The promotion matches the actual parsed Core config, not a client claim about
// which lease it staged. The outbound gate independently owns per-flow limits.
func linuxATSLeaseDeadline(config []byte, command linuxCommand) (int64, bool) {
	if !linuxATSLeasePattern.MatchString(command.LeaseID) { return 0, false }
	issued, ok := linuxATSTime(command.IssuedAt)
	if !ok { return 0, false }
	newUntil, ok := linuxATSTime(command.NewFlowsUntil)
	if !ok { return 0, false }
	activeUntil, ok := linuxATSTime(command.ActiveFlowsUntil)
	if !ok { return 0, false }
	now := time.Now()
	if now.Before(issued) || !now.Before(newUntil) || !newUntil.After(issued) ||
		activeUntil.Before(newUntil) || newUntil.Sub(issued) > 10*time.Minute ||
		activeUntil.Sub(issued) > time.Hour { return 0, false }
	var profile struct {
		Outbounds []map[string]json.RawMessage `json:"outbounds"`
	}
	if json.Unmarshal(config, &profile) != nil { return 0, false }
	read := func(row map[string]json.RawMessage, field string) string {
		var value string
		if json.Unmarshal(row[field], &value) != nil { return "" }
		return value
	}
	var gate, upstream int
	for _, row := range profile.Outbounds {
		switch read(row, "tag") {
		case "pokrov-ats":
			if read(row, "type") != "pokrov-ats-lease" ||
				read(row, "upstream_tag") != "pokrov-ats-upstream" ||
				read(row, "lease_id") != command.LeaseID ||
				read(row, "issued_at") != command.IssuedAt ||
				read(row, "new_flows_until") != command.NewFlowsUntil ||
				read(row, "active_flows_until") != command.ActiveFlowsUntil { return 0, false }
			gate++
		case "pokrov-ats-upstream":
			if read(row, "type") != "vless" { return 0, false }
			upstream++
		}
	}
	if gate != 1 || upstream != 1 { return 0, false }
	var elapsed unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &elapsed) != nil { return 0, false }
	remaining := time.Until(activeUntil).Milliseconds()
	if remaining <= 0 || remaining > 3_600_000 { return 0, false }
	return int64(elapsed.Sec)*1000 + int64(elapsed.Nsec)/1000000 + remaining, true
}
