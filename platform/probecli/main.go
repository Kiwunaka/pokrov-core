// probecli runs the client's isolated candidate probe from a private,
// materialized technical profile. It does not start a tunnel.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Kiwunaka/POKROV-core/v2/hcore"
	"github.com/Kiwunaka/POKROV-core/v2/linuxruntime"
)

const probeTimeout = 12 * time.Second

type probeResult struct {
	hcore.CandidateProbeResult
	Stage string `json:"stage,omitempty"`
}

func (r probeResult) JSON() string {
	value, _ := json.Marshal(r)
	return string(value)
}

func main() {
	result := run(os.Args[1:])
	fmt.Println(result.JSON())
	if !result.Success {
		os.Exit(1)
	}
}

func run(args []string) probeResult {
	if len(args) != 2 || args[0] == "" || args[1] == "" {
		return probeResult{CandidateProbeResult: hcore.CandidateProbeResult{FailureKind: "invalid_request"}}
	}
	file, err := os.Open(args[0])
	if err != nil {
		return probeResult{CandidateProbeResult: hcore.CandidateProbeResult{FailureKind: "invalid_profile"}, Stage: "profile_file"}
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return probeResult{CandidateProbeResult: hcore.CandidateProbeResult{FailureKind: "invalid_profile"}, Stage: "profile_file"}
	}
	profile, err := io.ReadAll(io.LimitReader(file, linuxruntime.MaximumConfigBytes+1))
	if err != nil || len(profile) == 0 || len(profile) > linuxruntime.MaximumConfigBytes {
		return probeResult{CandidateProbeResult: hcore.CandidateProbeResult{FailureKind: "invalid_profile"}, Stage: "profile_file"}
	}
	stage := ""
	result := hcore.ProbeCandidate(string(profile), "fixed-probe", probeTimeout, args[1], nil, nil,
		func(name string) { stage = name })
	if result.Success {
		stage = ""
	}
	return probeResult{CandidateProbeResult: result, Stage: stage}
}
