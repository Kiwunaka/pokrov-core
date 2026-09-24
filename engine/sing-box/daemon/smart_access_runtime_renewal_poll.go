package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sagernet/sing-box/protocol/pokrov/smartaccess"
)

// Snapshot mutable enrollment state under serviceAccess before network I/O.
// The pointer is only compared again under that lock, never read by HTTP code.
type smartAccessRuntimeRenewalAttempt struct {
	enrollment *smartAccessRuntimeRenewal
	previous smartAccessRuntimeLeaseIdentity
	capability string
	expires time.Time
	deadline time.Time
	control smartAccessRuntimeDecision
}

type smartAccessRuntimeRenewalDecision struct {
	lease smartAccessRuntimeLeaseIdentity
	restriction string // Empty for a positive lease, otherwise drain/terminate.
	issued time.Time
	newUntil time.Time
	activeUntil time.Time
	deadline time.Time
}

func (s *StartedService) nextSmartAccessRuntimeRenewal(worker *smartAccessRuntimeControlWorker,
	control smartAccessRuntimeDecision) (smartAccessRuntimeRenewalAttempt, bool) {
	s.serviceAccess.Lock()
	defer s.serviceAccess.Unlock()
	var rejected smartAccessRuntimeRenewalAttempt
	now := time.Now()
	if worker.ctx.Err() != nil || s.closed || s.serviceStatus.Status != ServiceStatus_STARTED ||
		s.instance != worker.instance || s.instance.smartAccessControl != worker || control.reason != "current" ||
		!now.Before(control.expires) || !now.Before(control.deadline) || !now.Before(worker.expires) || !now.Before(worker.deadline) {
		return rejected, false
	}
	var chosen *smartAccessRuntimeRenewal
	chosenScope := ""
	for scope, renewal := range worker.renewals {
		if now.Before(renewal.issued) || !now.Before(renewal.expires) || !now.Before(renewal.deadline) { continue }
		issued, _ := smartAccessControlTime(renewal.current.IssuedAt)
		newUntil, _ := smartAccessControlTime(renewal.current.NewFlowsUntil)
		// Use the accepted grant's midpoint, not an invented lease lifetime.
		if now.Before(issued) || now.Before(issued.Add(newUntil.Sub(issued) / 2)) || !newUntil.Before(renewal.expires) { continue }
		found := false
		for _, outbound := range worker.instance.instance.Outbound().Outbounds() {
			if lease, ok := outbound.(*smartaccess.Outbound); ok && lease.CanRenewLease(renewal.current.LeaseID) { found = true; break }
		}
		if !found { continue }
		// Least-recently attempted due scope prevents a failing service from
		// monopolizing the bounded cadence. Ties are deterministic.
		if chosen == nil || renewal.lastAttempt.Before(chosen.lastAttempt) ||
			(renewal.lastAttempt.Equal(chosen.lastAttempt) && scope < chosenScope) { chosen, chosenScope = renewal, scope }
	}
	if chosen == nil { return rejected, false }
	chosen.lastAttempt = now
	return smartAccessRuntimeRenewalAttempt{enrollment: chosen, previous: chosen.current, capability: chosen.config.Capability,
		expires: chosen.expires, deadline: chosen.deadline, control: control}, true
}

func (worker *smartAccessRuntimeControlWorker) pollRenewal(attempt smartAccessRuntimeRenewalAttempt) (smartAccessRuntimeRenewalDecision, bool) {
	var rejected smartAccessRuntimeRenewalDecision
	deadline := attempt.deadline
	if attempt.control.deadline.Before(deadline) { deadline = attempt.control.deadline }
	ctx, cancel := context.WithDeadline(worker.ctx, deadline)
	defer cancel()
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil { return rejected, false }
	nonce := hex.EncodeToString(nonceBytes)
	body, _ := json.Marshal(map[string]string{"schema_version": "pokrov-smart-access-runtime-renewal-request-v1",
		"request_nonce": nonce, "profile_digest": worker.config.ProfileDigest, "platform": worker.config.Platform,
		"expected_lease_id": attempt.previous.LeaseID})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(worker.config.APIBaseURL, "/") + "/api/client/smart-access/runtime-renewal", bytes.NewReader(body))
	if err != nil { return rejected, false }
	request.Header.Set("Authorization", "Bearer " + attempt.capability)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	started := time.Now()
	response, err := worker.client.Do(request)
	if err != nil { return rejected, false }
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK { return rejected, false }
	data, err := io.ReadAll(io.LimitReader(response.Body, smartAccessRuntimeControlLimit + 1))
	if err != nil || len(data) > smartAccessRuntimeControlLimit || ctx.Err() != nil { return rejected, false }
	return worker.verifyRenewal(data, nonce, attempt, started, time.Now())
}

func (worker *smartAccessRuntimeControlWorker) verifyRenewal(raw []byte, nonce string,
	attempt smartAccessRuntimeRenewalAttempt, started, now time.Time) (smartAccessRuntimeRenewalDecision, bool) {
	var rejected smartAccessRuntimeRenewalDecision
	outer, ok := smartAccessControlObject(raw, "schema", "envelope")
	if !ok { return rejected, false }
	var schema string
	if json.Unmarshal(outer["schema"], &schema) != nil || schema != "smart-access-runtime-renewal-response-v1" { return rejected, false }
	envelope, ok := smartAccessControlObject(outer["envelope"], "algorithm", "key_id", "payload_sha256", "payload", "signature_b64")
	if !ok { return rejected, false }
	var algorithm, keyID, digest, signatureText string
	if json.Unmarshal(envelope["algorithm"], &algorithm) != nil || algorithm != "Ed25519" ||
		json.Unmarshal(envelope["key_id"], &keyID) != nil || json.Unmarshal(envelope["payload_sha256"], &digest) != nil ||
		json.Unmarshal(envelope["signature_b64"], &signatureText) != nil { return rejected, false }
	key, found := worker.keys[keyID]
	if !found || !smartAccessRuntimeDigest.MatchString(digest) || len(signatureText) != 86 { return rejected, false }
	values, ok := smartAccessControlObject(envelope["payload"], "schema_version", "request_nonce", "capability_binding",
		"profile_digest", "platform", "audience", "expected_lease_id", "lease")
	if !ok { return worker.verifyRenewalRestriction(envelope["payload"], nonce, attempt, started, now, key, digest, signatureText) }
	payload := make(map[string]any, len(values))
	for field, raw := range values {
		if field == "lease" { continue }
		var value string
		if json.Unmarshal(raw, &value) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) { return rejected, false }
		payload[field] = value
	}
	binding := sha256.Sum256([]byte("pokrov-smart-access-runtime-renewal-binding-v1\x00" + nonce + "\x00" + attempt.capability))
	if payload["schema_version"] != "pokrov-smart-access-runtime-renewal-v1" || payload["request_nonce"] != nonce ||
		payload["profile_digest"] != worker.config.ProfileDigest || payload["platform"] != worker.config.Platform ||
		payload["audience"] != worker.config.Audience || payload["expected_lease_id"] != attempt.previous.LeaseID ||
		payload["capability_binding"] != hex.EncodeToString(binding[:]) { return rejected, false }
	lease, valid := parseSmartAccessRuntimeLeaseIdentity(values["lease"])
	if !valid || lease.LeaseID == attempt.previous.LeaseID || !lease.follows(attempt.previous) { return rejected, false }
	issued, _ := smartAccessControlTime(lease.IssuedAt)
	newUntil, _ := smartAccessControlTime(lease.NewFlowsUntil)
	activeUntil, _ := smartAccessControlTime(lease.ActiveFlowsUntil)
	previousIssued, _ := smartAccessControlTime(attempt.previous.IssuedAt)
	previousUntil, _ := smartAccessControlTime(attempt.previous.NewFlowsUntil)
	if issued.Before(started.UTC().Truncate(time.Second)) || issued.Before(previousIssued) || now.Before(issued) ||
		!now.Before(newUntil) || !newUntil.After(previousUntil) || activeUntil.After(attempt.expires) ||
		!now.Before(attempt.expires) || !now.Before(attempt.deadline) || !now.Before(attempt.control.expires) ||
		!now.Before(attempt.control.deadline) || !now.Before(worker.expires) || !now.Before(worker.deadline) { return rejected, false }
	payload["lease"] = lease.canonicalObject()
	canonical, err := json.Marshal(payload)
	if err != nil { return rejected, false }
	hash := sha256.Sum256(canonical)
	if digest != hex.EncodeToString(hash[:]) { return rejected, false }
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signatureText)
	if err != nil || !ed25519.Verify(key, append([]byte("pokrov-smart-access-runtime-renewal-v1\n"), canonical...), signature) { return rejected, false }
	return smartAccessRuntimeRenewalDecision{lease: lease, issued: issued, newUntil: newUntil,
		activeUntil: activeUntil, deadline: now.Add(newUntil.Sub(now))}, true
}

func (worker *smartAccessRuntimeControlWorker) verifyRenewalRestriction(raw []byte, nonce string,
	attempt smartAccessRuntimeRenewalAttempt, started, now time.Time, key ed25519.PublicKey,
	digest, signatureText string) (smartAccessRuntimeRenewalDecision, bool) {
	var rejected smartAccessRuntimeRenewalDecision
	fields, ok := smartAccessControlObject(raw, "schema_version", "request_nonce", "capability_binding", "profile_digest",
		"platform", "audience", "expected_lease_id", "runtime_scope_sha256", "action", "reason", "issued_at", "expires_at",
		"provider_policy_revision", "provider_security_revision", "catalog_revision", "catalog_security_revision")
	if !ok { return rejected, false }
	floors := map[string]int64{"provider_policy_revision": attempt.previous.ProviderPolicyRevision,
		"provider_security_revision": attempt.previous.ProviderSecurityRevision, "catalog_revision": attempt.previous.CatalogRevision,
		"catalog_security_revision": attempt.previous.CatalogSecurityRevision}
	payload := make(map[string]any, len(fields))
	for field, raw := range fields {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) { return rejected, false }
		if _, revision := floors[field]; revision {
			var value int64
			if json.Unmarshal(raw, &value) != nil || value < 0 || value > 9007199254740991 { return rejected, false }
			payload[field] = value
		} else {
			var value string
			if json.Unmarshal(raw, &value) != nil { return rejected, false }
			payload[field] = value
		}
	}
	binding := sha256.Sum256([]byte("pokrov-smart-access-runtime-renewal-binding-v1\x00" + nonce + "\x00" + attempt.capability))
	if payload["schema_version"] != "pokrov-smart-access-runtime-renewal-restriction-v1" || payload["request_nonce"] != nonce ||
		payload["capability_binding"] != hex.EncodeToString(binding[:]) || payload["profile_digest"] != worker.config.ProfileDigest ||
		payload["platform"] != worker.config.Platform || payload["audience"] != worker.config.Audience ||
		payload["expected_lease_id"] != attempt.previous.LeaseID || payload["runtime_scope_sha256"] != attempt.previous.RuntimeScopeSHA256 { return rejected, false }
	reason := payload["reason"].(string)
	actions := map[string]string{"access_denied": "terminate", "catalog_disabled": "terminate", "provider_policy_disabled": "terminate",
		"issuance_disabled": "drain", "provider_scope_withdrawn": "terminate", "catalog_scope_withdrawn": "terminate",
		"scope_changed": "drain", "capability_unavailable": "drain"}
	action, known := actions[reason]
	if !known || payload["action"] != action { return rejected, false }
	global := reason == "access_denied" || reason == "catalog_disabled" || reason == "provider_policy_disabled" || reason == "issuance_disabled"
	for field, floor := range floors {
		value := payload[field].(int64)
		if (global && value != 0) || (!global && value < floor) { return rejected, false }
	}
	issued, issuedOK := smartAccessControlTime(payload["issued_at"].(string))
	expires, expiresOK := smartAccessControlTime(payload["expires_at"].(string))
	if !issuedOK || !expiresOK || !issued.Before(expires) || expires.Sub(issued) > time.Minute ||
		issued.Before(started.UTC().Truncate(time.Second)) || now.Before(issued) || !now.Before(expires) ||
		expires.After(attempt.expires) || !now.Before(attempt.deadline) || !now.Before(worker.expires) || !now.Before(worker.deadline) ||
		!now.Before(attempt.control.expires) || !now.Before(attempt.control.deadline) { return rejected, false }
	canonical, err := json.Marshal(payload)
	if err != nil { return rejected, false }
	hash := sha256.Sum256(canonical)
	if digest != hex.EncodeToString(hash[:]) { return rejected, false }
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signatureText)
	if err != nil || !ed25519.Verify(key, append([]byte("pokrov-smart-access-runtime-renewal-v1\n"), canonical...), signature) { return rejected, false }
	return smartAccessRuntimeRenewalDecision{restriction: action, issued: issued, newUntil: expires,
		deadline: now.Add(expires.Sub(now))}, true
}

func (s *StartedService) applySmartAccessRuntimeRenewal(worker *smartAccessRuntimeControlWorker,
	attempt smartAccessRuntimeRenewalAttempt, decision smartAccessRuntimeRenewalDecision) {
	s.serviceAccess.Lock()
	defer s.serviceAccess.Unlock()
	if s.closed || s.serviceStatus.Status != ServiceStatus_STARTED || s.instance != worker.instance ||
		s.instance.smartAccessControl != worker || worker.renewals[attempt.previous.RuntimeScopeSHA256] != attempt.enrollment ||
		attempt.enrollment.current != attempt.previous { return }
	fresh := func() bool {
		now := time.Now()
		return worker.ctx.Err() == nil && !now.Before(decision.issued) && now.Before(decision.newUntil) && now.Before(decision.deadline) &&
			now.Before(worker.expires) && now.Before(worker.deadline) && now.Before(attempt.expires) && now.Before(attempt.deadline) &&
			now.Before(attempt.control.expires) && now.Before(attempt.control.deadline)
	}
	if !fresh() { return }
	currentIDs := make(map[string]bool)
	var target *smartaccess.Outbound
	for _, outbound := range worker.instance.instance.Outbound().Outbounds() {
		if lease, ok := outbound.(*smartaccess.Outbound); ok {
			id := lease.LeaseID()
			if currentIDs[id] || len(currentIDs) >= 256 { return }
			currentIDs[id] = true
			if id == attempt.previous.LeaseID { target = lease }
		}
	}
	if target == nil { return }
	if decision.restriction != "" {
		// Tighten the exact outbound, including its older active generations,
		// before journal I/O. The precommitted pending marker covers write failure.
		target.Revoke(decision.restriction == "terminate")
		worker.journal.restrictScope(worker.config.ProfileDigest, worker.journalGeneration,
			attempt.previous.RuntimeScopeSHA256, decision.restriction)
		return
	}
	lease := decision.lease
	renewed, err := target.RenewLease(attempt.previous.LeaseID, lease.LeaseID, lease.IssuedAt, lease.NewFlowsUntil, lease.ActiveFlowsUntil,
		func(time.Time) error {
			if !fresh() { return errors.New("smart_access_runtime_renewal_expired") }
			if err := worker.journal.retainRenewal(worker.config.ProfileDigest, worker.journalGeneration,
				attempt.previous, lease, currentIDs); err != nil { return err }
			if !fresh() { return errors.New("smart_access_runtime_renewal_expired") }
			return nil
		})
	if err != nil || !renewed { return }
	attempt.enrollment.current = lease
	if decision.activeUntil.After(worker.instance.smartAccessRestrictionExpires) {
		worker.instance.smartAccessRestrictionExpires = decision.activeUntil
	}
}
