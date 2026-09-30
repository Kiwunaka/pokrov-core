package box

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"slices"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing/common"
)

func validateHysteriaReloadOptions(options option.Options) error {
	if options.Experimental == nil || !options.Experimental.HysteriaReload || len(options.Inbounds) != 1 || options.Inbounds[0].Type != C.TypeHysteria2 || options.Route == nil {
		return errors.New("hysteria_reload_scope_invalid")
	}
	users := options.Inbounds[0].Options.(*option.Hysteria2InboundOptions).Users
	names, passwords := map[string]bool{}, map[string]bool{}
	for _, user := range users {
		if user.Name == "" || user.Password == "" || names[user.Name] || passwords[user.Password] {
			return errors.New("hysteria_reload_user_invalid")
		}
		names[user.Name], passwords[user.Password] = true, true
	}
	tags := map[string]bool{}
	for _, outbound := range options.Outbounds {
		if outbound.Type != C.TypeDirect || outbound.Tag == "" || tags[outbound.Tag] {
			return errors.New("hysteria_reload_outbound_invalid")
		}
		tags[outbound.Tag] = true
	}
	for _, rule := range options.Route.Rules {
		if rule.Type != C.RuleTypeDefault {
			return errors.New("hysteria_reload_rule_invalid")
		}
		switch rule.DefaultOptions.Action {
		case C.RuleActionTypeRoute:
			if !tags[rule.DefaultOptions.RouteOptions.Outbound] {
				return errors.New("hysteria_reload_route_invalid")
			}
		case C.RuleActionTypeReject, C.RuleActionTypeResolve, C.RuleActionTypeSniff:
		default:
			return errors.New("hysteria_reload_rule_invalid")
		}
	}
	return nil
}

// The dedicated server opts in to auth/account policy reloads. Listener, TLS,
// DNS, rule sets and every other runtime option remain immutable in this path.
func (s *Box) ReloadHysteria(next option.Options) error {
	if s.hysteriaOptions == nil {
		return errors.New("hysteria_reload_disabled")
	}
	if err := validateHysteriaReloadOptions(next); err != nil {
		return err
	}
	previous := *s.hysteriaOptions
	if !reflect.DeepEqual(hysteriaImmutableOptions(previous), hysteriaImmutableOptions(next)) {
		return errors.New("hysteria_reload_immutable_change")
	}
	rules, err := s.router.PrepareHysteriaRules(next.Route.Rules)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			for _, rule := range rules {
				_ = rule.Close()
			}
		}
	}()
	for _, outbound := range next.Outbounds {
		candidate, err := direct.NewOutbound(s.ctx, s.router, s.logger, outbound.Tag, *outbound.Options.(*option.DirectOutboundOptions))
		if err != nil {
			return err
		}
		if err := common.Close(candidate); err != nil {
			return err
		}
	}
	inbound, loaded := s.inbound.Get(previous.Inbounds[0].Tag)
	if !loaded {
		return errors.New("hysteria_reload_inbound_missing")
	}
	updater, supported := inbound.(interface{ UpdateUsers([]option.Hysteria2User) })
	if !supported {
		return errors.New("hysteria_reload_inbound_unsupported")
	}
	oldUsers := previous.Inbounds[0].Options.(*option.Hysteria2InboundOptions).Users
	nextUsers := next.Inbounds[0].Options.(*option.Hysteria2InboundOptions).Users
	var kept []option.Hysteria2User
	for _, user := range oldUsers {
		if slices.Contains(nextUsers, user) && reflect.DeepEqual(hysteriaUserPolicy(previous, user.Name), hysteriaUserPolicy(next, user.Name)) {
			kept = append(kept, user)
		}
	}
	// Removed credentials and changed account permissions are fenced/closed
	// before any new routing permission or authentication becomes reachable.
	updater.UpdateUsers(kept)
	for _, outbound := range next.Outbounds {
		unchanged := slices.ContainsFunc(previous.Outbounds, func(old option.Outbound) bool { return reflect.DeepEqual(old, outbound) })
		if !unchanged {
			if err := s.outbound.Create(s.ctx, s.router, s.logger, outbound.Tag, C.TypeDirect, outbound.Options); err != nil {
				return err
			}
			actual, exists := s.outbound.Outbound(outbound.Tag)
			if !exists || actual.Type() != C.TypeDirect {
				return errors.New("hysteria_reload_outbound_unverified")
			}
		}
	}
	if err := s.router.ReplaceHysteriaRules(rules); err != nil {
		committed = true
		return err
	}
	committed = true
	for _, outbound := range previous.Outbounds {
		if !slices.ContainsFunc(next.Outbounds, func(candidate option.Outbound) bool { return candidate.Tag == outbound.Tag }) {
			if err := s.outbound.Remove(outbound.Tag); err != nil {
				return err
			}
		}
	}
	updater.UpdateUsers(nextUsers)
	s.hysteriaOptions = &next
	return nil
}

func (s *Box) HysteriaRuntimeDigest() string {
	if s.hysteriaOptions == nil {
		return ""
	}
	digest := sha256.Sum256(s.hysteriaOptions.RawMessage)
	return hex.EncodeToString(digest[:])
}

func hysteriaImmutableOptions(options option.Options) option.Options {
	options.RawMessage, options.CommentsSet = nil, nil
	options.Outbounds = nil
	options.Inbounds = append([]option.Inbound(nil), options.Inbounds...)
	inbound := *options.Inbounds[0].Options.(*option.Hysteria2InboundOptions)
	inbound.Users = nil
	options.Inbounds[0].Options = &inbound
	route := *options.Route
	route.Rules = nil
	options.Route = &route
	return options
}

type hysteriaAccountPolicy struct {
	Rules     []option.Rule
	Outbounds []option.Outbound
}

func hysteriaUserPolicy(options option.Options, user string) hysteriaAccountPolicy {
	var policy hysteriaAccountPolicy
	tags := map[string]bool{}
	for _, rule := range options.Route.Rules {
		if len(rule.DefaultOptions.AuthUser) != 0 && !slices.Contains(rule.DefaultOptions.AuthUser, user) {
			continue
		}
		rule.DefaultOptions.AuthUser = nil
		policy.Rules = append(policy.Rules, rule)
		if rule.DefaultOptions.Action == C.RuleActionTypeRoute {
			tags[rule.DefaultOptions.RouteOptions.Outbound] = true
		}
	}
	for _, outbound := range options.Outbounds {
		if tags[outbound.Tag] {
			policy.Outbounds = append(policy.Outbounds, outbound)
		}
	}
	return policy
}
