// probecli runs the client's isolated candidate probe from a private,
// materialized technical profile. It does not start a tunnel.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/Kiwunaka/POKROV-core/v2/hcore"
	"github.com/Kiwunaka/POKROV-core/v2/linuxruntime"
)

const probeTimeout = 12 * time.Second
const fixedBootstrapTag = "pokrov-fixed-bootstrap"

var errFixedBootstrap = errors.New("fixed probe bootstrap unavailable")

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
	profile, err = materializeFixedBootstrap(profile)
	if err != nil {
		return probeResult{CandidateProbeResult: hcore.CandidateProbeResult{FailureKind: "invalid_profile"}, Stage: "bootstrap_dns"}
	}
	stage := ""
	result := hcore.ProbeCandidate(string(profile), "fixed-probe", probeTimeout, args[1], nil, nil,
		func(name string) { stage = name })
	if result.Success {
		stage = ""
	}
	return probeResult{CandidateProbeResult: result, Stage: stage}
}

// Give hostname-based VLESS its own direct DNS lane, as the Linux client does.
// The content DNS final and all outbound connection material remain unchanged.
func materializeFixedBootstrap(profile []byte) ([]byte, error) {
	var config map[string]any
	if json.Unmarshal(profile, &config) != nil || config == nil {
		return nil, errFixedBootstrap
	}
	outbounds, ok := config["outbounds"].([]any)
	if !ok {
		return nil, errFixedBootstrap
	}
	var directTag string
	var hostnameServer bool
	for _, raw := range outbounds {
		outbound, ok := raw.(map[string]any)
		if !ok {
			return nil, errFixedBootstrap
		}
		if outbound["type"] == "direct" {
			tag, ok := outbound["tag"].(string)
			if !ok || tag == "" || directTag != "" {
				return nil, errFixedBootstrap
			}
			directTag = tag
		}
		if outbound["type"] == "vless" {
			server, _ := outbound["server"].(string)
			if server != "" {
				_, err := netip.ParseAddr(server)
				hostnameServer = hostnameServer || err != nil
			}
		}
	}
	if !hostnameServer {
		return profile, nil
	}
	if directTag == "" {
		return nil, errFixedBootstrap
	}
	dns, dnsOK := config["dns"].(map[string]any)
	route, routeOK := config["route"].(map[string]any)
	if !dnsOK || !routeOK {
		return nil, errFixedBootstrap
	}
	servers, ok := dns["servers"].([]any)
	if !ok {
		return nil, errFixedBootstrap
	}
	final, ok := dns["final"].(string)
	if !ok || final == "" {
		return nil, errFixedBootstrap
	}
	var address string
	for _, raw := range servers {
		server, ok := raw.(map[string]any)
		if !ok || server["tag"] == fixedBootstrapTag {
			return nil, errFixedBootstrap
		}
		if server["tag"] == final {
			address, _ = server["address"].(string)
		}
	}
	resolved, err := netip.ParseAddr(address)
	if err != nil || !resolved.Is4() {
		return nil, errFixedBootstrap
	}
	dns["servers"] = append(servers, map[string]any{
		"tag": fixedBootstrapTag, "address": address, "detour": directTag,
	})
	route["default_domain_resolver"] = map[string]any{
		"server": fixedBootstrapTag, "strategy": "ipv4_only",
	}
	return json.Marshal(config)
}
