package route

import (
	"errors"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
)

type hysteriaRuleSnapshot struct {
	rules      []adapter.Rule
	references int
	retired    bool
}

func (r *Router) acquireHysteriaRules() *hysteriaRuleSnapshot {
	r.rulesAccess.Lock()
	defer r.rulesAccess.Unlock()
	if r.rulesClosed {
		return nil
	}
	if r.hysteriaRules == nil {
		r.hysteriaRules = &hysteriaRuleSnapshot{rules: r.rules}
	}
	r.hysteriaRules.references++
	r.rulesReaders.Add(1)
	return r.hysteriaRules
}

func (r *Router) releaseHysteriaRules(snapshot *hysteriaRuleSnapshot) {
	defer r.rulesReaders.Done()
	r.rulesAccess.Lock()
	snapshot.references--
	closeRules := snapshot.retired && snapshot.references == 0
	r.rulesAccess.Unlock()
	if closeRules {
		if err := closeHysteriaRules(snapshot.rules); err != nil {
			r.logger.Error("close retired HY2 rules: ", err)
		}
	}
}

func (r *Router) stopHysteriaMatching() []adapter.Rule {
	r.rulesAccess.Lock()
	r.rulesClosed = true
	r.rulesAccess.Unlock()
	// The command cancels the service context before Close. Retired snapshots
	// release their rules before Done, so rule-set shutdown cannot overtake them.
	r.rulesReaders.Wait()
	return r.Rules()
}

// Only the opt-in dedicated HY2 process calls this path. Rule sets, DNS and
// network services remain those started with the immutable listener config.
func (r *Router) PrepareHysteriaRules(options []option.Rule) ([]adapter.Rule, error) {
	var rules []adapter.Rule
	for _, opts := range options {
		if err := R.ValidateNoNestedRuleActions(opts); err != nil {
			closeHysteriaRules(rules)
			return nil, err
		}
		rule, err := R.NewRule(r.ctx, r.logger, opts, false)
		if err != nil {
			closeHysteriaRules(rules)
			return nil, err
		}
		rules = append(rules, rule)
		if err := rule.Start(); err != nil {
			closeHysteriaRules(rules)
			return nil, err
		}
	}
	return rules, nil
}

func (r *Router) ReplaceHysteriaRules(rules []adapter.Rule) error {
	r.rulesAccess.Lock()
	if r.rulesClosed {
		r.rulesAccess.Unlock()
		_ = closeHysteriaRules(rules)
		return net.ErrClosed
	}
	previous := r.hysteriaRules
	if previous == nil {
		previous = &hysteriaRuleSnapshot{rules: r.rules}
	}
	previous.retired = true
	r.rules = rules
	r.hysteriaRules = &hysteriaRuleSnapshot{rules: rules}
	closeRules := previous.references == 0
	r.rulesAccess.Unlock()
	if closeRules {
		return closeHysteriaRules(previous.rules)
	}
	return nil
}

func closeHysteriaRules(rules []adapter.Rule) error {
	var err error
	for _, rule := range rules {
		err = errors.Join(err, rule.Close())
	}
	return err
}
