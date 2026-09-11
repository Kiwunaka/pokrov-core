package hcore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"

	"github.com/Kiwunaka/POKROV-core/v2/hutils"
	"github.com/Kiwunaka/POKROV-core/v2/linuxruntime"
	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/experimental/libbox"
)

var errLinuxDaemon = errors.New("linux core runtime failed")

type linuxCommand struct {
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
}

type linuxReply struct {
	Protocol string             `json:"protocol"`
	Phase    string             `json:"phase"`
	Plan     *linuxruntime.Plan `json:"plan,omitempty"`
}

// ServeLinuxDaemon uses the same lifecycle as desktop/mobile with no gRPC or
// legacy command server. Only its bounded control replies reach linuxd.
func ServeLinuxDaemon(ctx context.Context, profile []byte, root string, commands io.Reader, replies io.Writer) (result error) {
	config, plan, err := linuxruntime.Prepare(profile)
	if err != nil {
		return errLinuxDaemon
	}
	// sing-tun removes rules in [priority, priority+10] during cleanup.
	// Refuse any existing owner in that range or the fixed route table.
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
		&netlink.Route{Table: linuxruntime.RouteTable}, netlink.RT_FILTER_TABLE)
	if err != nil || len(routes) != 0 {
		return errLinuxDaemon
	}
	rules, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return errLinuxDaemon
	}
	for _, rule := range rules {
		if rule.Table == linuxruntime.RouteTable ||
			(rule.Priority >= linuxruntime.RulePriority && rule.Priority <= linuxruntime.RulePriority+10) {
			return errLinuxDaemon
		}
	}
	base, cancelBase := context.WithCancel(libbox.BaseContext(nil))
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
	if encoder.Encode(linuxReply{Protocol: linuxruntime.Protocol, Phase: "prepared", Plan: &plan}) != nil {
		return errLinuxDaemon
	}
	actions := make(chan string)
	go readLinuxCommands(ctx, commands, actions)
	select {
	case <-ctx.Done():
		return nil
	case action := <-actions:
		if action != "start" {
			return errLinuxDaemon
		}
	}
	started, err := Start(base, request)
	if err != nil || started.CoreState != CoreStates_STARTED {
		return errLinuxDaemon
	}
	if _, err := net.InterfaceByName(plan.TunnelInterface); err != nil {
		return errLinuxDaemon
	}
	if encoder.Encode(linuxReply{Protocol: linuxruntime.Protocol, Phase: "started"}) != nil {
		return errLinuxDaemon
	}
	select {
	case <-ctx.Done():
	case action := <-actions:
		if action != "stop" {
			return errLinuxDaemon
		}
	}
	return nil
}

func readLinuxCommands(ctx context.Context, input io.Reader, actions chan<- string) {
	defer close(actions)
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 256), 256)
	for scanner.Scan() {
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		var command linuxCommand
		if decoder.Decode(&command) != nil || command.Protocol != linuxruntime.Protocol || (command.Action != "start" && command.Action != "stop") {
			return
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return
		}
		select {
		case actions <- command.Action:
		case <-ctx.Done():
			return
		}
	}
}
