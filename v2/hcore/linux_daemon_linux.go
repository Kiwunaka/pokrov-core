package hcore

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/Kiwunaka/POKROV-core/v2/hutils"
	"github.com/Kiwunaka/POKROV-core/v2/linuxruntime"
	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/protocol/tun"
	"golang.org/x/sys/unix"
)

var errLinuxDaemon = errors.New("linux core runtime failed")

type linuxCommand struct {
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
	ExpectedCoreModuleSHA256 string `json:"expected_core_module_sha256,omitempty"`
	ExpectedProfileSHA256 string `json:"expected_profile_sha256,omitempty"`
	Deadline *linuxConnectDeadline `json:"deadline,omitempty"`
	LeaseID string `json:"endpoint_lease_ref,omitempty"`
	IssuedAt string `json:"issued_at,omitempty"`
	NewFlowsUntil string `json:"new_flows_until,omitempty"`
	ActiveFlowsUntil string `json:"active_flows_until,omitempty"`
	TerminateActive *bool `json:"terminate_active,omitempty"`
}

type linuxReply struct {
	Protocol string             `json:"protocol"`
	Phase    string             `json:"phase"`
	Plan     *linuxruntime.Plan `json:"plan,omitempty"`
	Health   *linuxHealth       `json:"health,omitempty"`
	TransportCapabilities string `json:"transport_capabilities_json,omitempty"`
	CoreModuleSHA256 string `json:"core_module_sha256,omitempty"`
	ProfileSHA256 string `json:"profile_sha256,omitempty"`
	IdentitySchema int `json:"identity_schema,omitempty"`
	DeadlineSchema int `json:"deadline_schema,omitempty"`
	ConnectDeadline *linuxConnectDeadline `json:"connect_deadline,omitempty"`
	LeaseID string `json:"endpoint_lease_ref,omitempty"`
	ActiveFlowsUntil string `json:"active_flows_until,omitempty"`
	LeaseRevoked *bool `json:"lease_revoked,omitempty"`
}

// ServeLinuxDaemon uses the same lifecycle as desktop/mobile with no gRPC or
// legacy command server. Only its bounded control replies reach linuxd.
func ServeLinuxDaemon(ctx context.Context, profile []byte, root string, commands io.Reader, replies io.Writer) (result error) {
	ctx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	config, plan, err := linuxruntime.Prepare(profile)
	if err != nil {
		return errLinuxDaemon
	}
	base, cancelBase := context.WithCancel(tun.WithExternalConfiguration(libbox.BaseContext(nil), func() error {
		link, err := netlink.LinkByName(plan.TunnelInterface)
		if err != nil {
			return err
		}
		for _, dns := range plan.DNSServers {
			prefix := "172.19.0.1/28"
			if dns == "fdfe:dcba:9876::2" {
				prefix = "fdfe:dcba:9876::1/126"
			}
			address, _ := netlink.ParseAddr(prefix)
			address.Flags = unix.IFA_F_NOPREFIXROUTE | unix.IFA_F_NODAD
			if err := netlink.AddrAdd(link, address); err != nil {
				return err
			}
		}
		return nil
	}))
	defer cancelBase()
	stopCancellation := context.AfterFunc(ctx, cancelBase)
	defer stopCancellation()
	request := &StartRequest{ConfigContent: string(config), EnableRawConfig: true, DisableMemoryLimit: true}
	// Parse the complete engine schema before linuxd touches the network.
	if _, err := BuildConfig(base, request); err != nil {
		return errLinuxDaemon
	}
	if err := Setup(&SetupRequest{BasePath: root, WorkingDir: root, TempDir: root, Mode: SetupMode_OLD}, nil); err != nil {
		return errLinuxDaemon
	}
	// Setup's legacy private stderr file is not used for privileged profiles.
	if err := hutils.RedirectStderr("/dev/null"); err != nil {
		return errLinuxDaemon
	}
	encoder := json.NewEncoder(replies)
	defer func() {
		stopped, err := Stop()
		if err != nil || stopped.CoreState != CoreStates_STOPPED ||
			encoder.Encode(linuxReply{Protocol: linuxruntime.Protocol, Phase: "stopped"}) != nil {
			result = errLinuxDaemon
		}
	}()
	// Hash the exact untransformed bytes read from the staged file. Prepare
	// parsed them into a separate runtime configuration retained by request.
	profileSum := sha256.Sum256(profile)
	profileSHA256 := hex.EncodeToString(profileSum[:])
	moduleSHA256 := LinuxModuleSHA256(ctx)
	if encoder.Encode(linuxReply{Protocol: linuxruntime.Protocol, Phase: "prepared", Plan: &plan,
		TransportCapabilities: libbox.TransportCapabilities(), CoreModuleSHA256: moduleSHA256,
		ProfileSHA256: profileSHA256, IdentitySchema: 1, DeadlineSchema: 1}) != nil {
		return errLinuxDaemon
	}
	actions := make(chan linuxCommand)
	go readLinuxCommands(ctx, commands, actions)
	boundStart := false
	var deadline *linuxConnectDeadline
	var promotedUntil atomic.Int64
	var promotionMu sync.Mutex
	select {
	case <-ctx.Done():
		return nil
	case command := <-actions:
		boundStart = command.Action == "start_with_identity"
		if command.Action != "start" && !boundStart {
			return errLinuxDaemon
		}
		if boundStart && (command.ExpectedCoreModuleSHA256 != moduleSHA256 ||
			command.ExpectedProfileSHA256 != profileSHA256 ||
			LinuxModuleSHA256(ctx) != moduleSHA256) {
			return errLinuxDaemon
		}
		if boundStart {
			deadline = command.Deadline
			if !deadline.current() { return errLinuxDaemon }
			go deadline.watch(ctx, cancelRun, &promotedUntil, &promotionMu)
		}
	}
	if ctx.Err() != nil { return errLinuxDaemon }
	started, err := Start(base, request)
	if err != nil || started.CoreState != CoreStates_STARTED {
		return errLinuxDaemon
	}
	if _, err := net.InterfaceByName(plan.TunnelInterface); err != nil {
		return errLinuxDaemon
	}
	startedReply := linuxReply{Protocol: linuxruntime.Protocol, Phase: "started"}
	if boundStart {
		if !deadline.current() { return errLinuxDaemon }
		startedReply.IdentitySchema = 1
		startedReply.DeadlineSchema = 1
		startedReply.ConnectDeadline = deadline
		startedReply.CoreModuleSHA256 = moduleSHA256
		startedReply.ProfileSHA256 = profileSHA256
	}
	if encoder.Encode(startedReply) != nil {
		return errLinuxDaemon
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case command := <-actions:
			switch command.Action {
			case "stop":
				return nil
			case "health":
				health := probeLinuxHealth(ctx)
				if encoder.Encode(linuxReply{Protocol: linuxruntime.Protocol, Phase: "health", Health: &health}) != nil {
					return errLinuxDaemon
				}
			case "promote_ats_lease":
				if !boundStart || promotedUntil.Load() != 0 || !deadline.current() ||
					command.ExpectedProfileSHA256 != profileSHA256 || ctx.Err() != nil {
					return errLinuxDaemon
				}
				leaseDeadline, valid := linuxATSLeaseDeadline(config, command)
				if !valid || ctx.Err() != nil { return errLinuxDaemon }
				confirmed, confirmErr := ConfirmATSLease(command.LeaseID, command.IssuedAt,
					command.NewFlowsUntil, command.ActiveFlowsUntil)
				if confirmErr != nil || !confirmed || ctx.Err() != nil { return errLinuxDaemon }
				promotionMu.Lock()
				if !deadline.current() || ctx.Err() != nil {
					promotionMu.Unlock()
					return errLinuxDaemon
				}
				promotedUntil.Store(leaseDeadline)
				promotionMu.Unlock()
				if encoder.Encode(linuxReply{Protocol: linuxruntime.Protocol, Phase: "promoted",
					ProfileSHA256: profileSHA256, LeaseID: command.LeaseID,
					ActiveFlowsUntil: command.ActiveFlowsUntil}) != nil { return errLinuxDaemon }
			case "revoke_ats_lease":
				if !boundStart || promotedUntil.Load() == 0 ||
					command.ExpectedProfileSHA256 != profileSHA256 || ctx.Err() != nil {
					return errLinuxDaemon
				}
				revoked, revokeErr := RevokeATSLease(command.LeaseID, *command.TerminateActive)
				if revokeErr != nil || !revoked { return errLinuxDaemon }
				if encoder.Encode(linuxReply{Protocol: linuxruntime.Protocol, Phase: "lease_revoked",
					ProfileSHA256: profileSHA256, LeaseID: command.LeaseID,
					LeaseRevoked: &revoked}) != nil { return errLinuxDaemon }
			default:
				return errLinuxDaemon
			}
		}
	}
}

func readLinuxCommands(ctx context.Context, input io.Reader, actions chan<- linuxCommand) {
	defer close(actions)
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 512), 1024)
	for scanner.Scan() {
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		var command linuxCommand
		if decoder.Decode(&command) != nil || command.Protocol != linuxruntime.Protocol {
			return
		}
		switch command.Action {
		case "start_with_identity":
			if !linuxIdentitySHA256(command.ExpectedCoreModuleSHA256) || !linuxIdentitySHA256(command.ExpectedProfileSHA256) ||
				!command.Deadline.valid() || command.LeaseID != "" || command.IssuedAt != "" ||
				command.NewFlowsUntil != "" || command.ActiveFlowsUntil != "" || command.TerminateActive != nil { return }
		case "start", "stop", "health":
			if command.ExpectedCoreModuleSHA256 != "" || command.ExpectedProfileSHA256 != "" || command.Deadline != nil ||
				command.LeaseID != "" || command.IssuedAt != "" || command.NewFlowsUntil != "" || command.ActiveFlowsUntil != "" || command.TerminateActive != nil { return }
		case "promote_ats_lease":
			if command.ExpectedCoreModuleSHA256 != "" || command.Deadline != nil ||
				!linuxIdentitySHA256(command.ExpectedProfileSHA256) ||
				!linuxATSLeasePattern.MatchString(command.LeaseID) ||
				command.IssuedAt == "" || command.NewFlowsUntil == "" || command.ActiveFlowsUntil == "" || command.TerminateActive != nil { return }
		case "revoke_ats_lease":
			if command.ExpectedCoreModuleSHA256 != "" || command.Deadline != nil ||
				!linuxIdentitySHA256(command.ExpectedProfileSHA256) ||
				!linuxATSLeasePattern.MatchString(command.LeaseID) || command.TerminateActive == nil ||
				command.IssuedAt != "" || command.NewFlowsUntil != "" || command.ActiveFlowsUntil != "" { return }
		default:
			return
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return
		}
		select {
		case actions <- command:
		case <-ctx.Done():
			return
		}
	}
}

func linuxIdentitySHA256(value string) bool {
	if len(value) != 64 { return false }
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') { return false }
	}
	return true
}
