package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/pokrov/smartaccess"
	M "github.com/sagernet/sing/common/metadata"
)

const smartAccessRuntimeControlLimit = 16 * 1024
const smartAccessRuntimeControlInterval = 30 * time.Second

var smartAccessRuntimeDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var smartAccessRuntimeCapability = regexp.MustCompile(`^pkr_src1\.[A-Za-z0-9_-]+\.[a-f0-9]{64}$`)

// This command is supplied by the authenticated native host, never from a
// profile or downloaded policy. The host fences the exact running profile and
// durably invalidates cached reuse BEFORE calling it. Credentials live in memory.
type smartAccessRuntimeControlConfig struct {
	SchemaVersion string `json:"schema_version"`
	ProfileDigest string `json:"profile_digest"`
	CatalogSHA256 string `json:"catalog_sha256"`
	Platform string `json:"platform"`
	Audience string `json:"audience"`
	APIBaseURL string `json:"api_base_url"`
	DNSResolver string `json:"dns_resolver"`
	Capability string `json:"capability"`
	IssuedAt string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
	LeaseKeysByID map[string]string `json:"lease_keys_by_id"`
}

type smartAccessRuntimeControlWorker struct {
	config smartAccessRuntimeControlConfig
	keys map[string]ed25519.PublicKey
	issued time.Time
	expires time.Time
	deadline time.Time
	instance *Instance
	ctx context.Context
	cancel context.CancelFunc
	client *http.Client
	transport *http.Transport
	journal *smartAccessRestrictionJournal
	journalGeneration string
	renewals map[string]*smartAccessRuntimeRenewal // Protected by serviceAccess.
}

type smartAccessRuntimeDecision struct {
	reason string
	expires time.Time
	deadline time.Time
}

// Decode exact object shapes, including duplicate/unknown field rejection.
// Do not return decoder errors: they can contain a supplied credential or body.
func smartAccessControlObject(raw []byte, fields ...string) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') { return nil, false }
	object := make(map[string]json.RawMessage, len(fields))
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok { return nil, false }
		if _, duplicate := object[key]; duplicate { return nil, false }
		var value json.RawMessage
		if decoder.Decode(&value) != nil { return nil, false }
		object[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') { return nil, false }
	if _, err = decoder.Token(); err != io.EOF { return nil, false }
	if len(object) != len(fields) { return nil, false }
	for _, key := range fields { if _, found := object[key]; !found { return nil, false } }
	return object, true
}

func smartAccessControlTime(value string) (time.Time, bool) {
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	return parsed, err == nil && parsed.Format("2006-01-02T15:04:05Z") == value
}

func parseSmartAccessRuntimeControl(raw string, now time.Time) (*smartAccessRuntimeControlWorker, error) {
	invalid := errors.New("smart_access_runtime_control_invalid")
	if len(raw) > smartAccessRuntimeControlLimit { return nil, invalid }
	if _, ok := smartAccessControlObject([]byte(raw), "schema_version", "profile_digest", "catalog_sha256", "platform", "audience",
		"api_base_url", "dns_resolver", "capability", "issued_at", "expires_at", "lease_keys_by_id"); !ok { return nil, invalid }
	var config smartAccessRuntimeControlConfig
	if json.Unmarshal([]byte(raw), &config) != nil || config.SchemaVersion != "pokrov-smart-access-runtime-worker-v1" ||
		!smartAccessRuntimeDigest.MatchString(config.ProfileDigest) ||
		(config.CatalogSHA256 != "" && !smartAccessRuntimeDigest.MatchString(config.CatalogSHA256)) ||
		(config.Platform != "android" && config.Platform != "windows") ||
		(config.Audience != "lab" && config.Audience != "production") ||
		!routingCatalogServiceID.MatchString(config.DNSResolver) ||
		len(config.Capability) > 4096 || !smartAccessRuntimeCapability.MatchString(config.Capability) { return nil, invalid }
	base, err := url.Parse(config.APIBaseURL)
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil ||
		base.RawQuery != "" || base.ForceQuery || base.Fragment != "" || base.RawFragment != "" ||
		(base.Path != "" && base.Path != "/") || base.RawPath != "" ||
		(base.Port() != "" && base.Port() != "443") { return nil, invalid }
	issued, validIssued := smartAccessControlTime(config.IssuedAt)
	expires, validExpires := smartAccessControlTime(config.ExpiresAt)
	if !validIssued || !validExpires || now.Before(issued) || !now.Before(expires) || !issued.Before(expires) { return nil, invalid }
	keys := make(map[string]ed25519.PublicKey, len(config.LeaseKeysByID))
	for id, encoded := range config.LeaseKeysByID {
		key, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if !routingCatalogServiceID.MatchString(id) || err != nil || len(key) != ed25519.PublicKeySize { return nil, invalid }
		keys[id] = ed25519.PublicKey(key)
	}
	if len(keys) == 0 { return nil, invalid }
	return &smartAccessRuntimeControlWorker{config: config, keys: keys, issued: issued,
		expires: expires, deadline: now.Add(expires.Sub(now))}, nil
}

// A replacement can rotate the short-lived restriction credential but cannot
// clear any outbound/rule latch. No grant issuance or lease renewal runs here.
func (s *StartedService) ConfigureSmartAccessRuntimeControl(profileDigest, raw, storageDirectory string) (bool, error) {
	worker, err := parseSmartAccessRuntimeControl(raw, time.Now())
	if err != nil { return false, err }
	if worker.config.ProfileDigest != profileDigest {
		return false, errors.New("smart_access_runtime_control_conflict")
	}
	s.serviceAccess.Lock()
	defer s.serviceAccess.Unlock()
	if s.closed || s.serviceStatus.Status != ServiceStatus_STARTED || s.instance == nil {
		return false, errors.New("smart_access_runtime_unavailable")
	}
	now := time.Now()
	if now.Before(worker.issued) || !now.Before(worker.expires) || !now.Before(worker.deadline) {
		return false, errors.New("smart_access_runtime_control_expired")
	}
	instance := s.instance
	// Ordinary profiles have no catalog/lease authority to recover or restrict.
	// Do not create an unbounded pending marker for such a profile.
	if instance.smartAccessRestrictionExpires.IsZero() || !now.Before(instance.smartAccessRestrictionExpires) { return false, nil }
	previous := instance.smartAccessControl
	if previous != nil {
		if previous.config.ProfileDigest != worker.config.ProfileDigest || previous.config.Platform != worker.config.Platform ||
			previous.config.Audience != worker.config.Audience || worker.issued.Before(previous.issued) {
			return false, errors.New("smart_access_runtime_control_conflict")
		}
		if previous.config.Capability == worker.config.Capability {
			oldConfig, _ := json.Marshal(previous.config)
			newConfig, _ := json.Marshal(worker.config)
			if !bytes.Equal(oldConfig, newConfig) || previous.ctx.Err() != nil ||
				!time.Now().Before(previous.deadline) || !time.Now().Before(previous.expires) {
				return false, errors.New("smart_access_runtime_control_conflict")
			}
			return true, nil
		}
	}
	protected, err := dialer.NewWithOptions(dialer.Options{Context: instance.ctx,
		Options: option.DialerOptions{DomainResolver: &option.DomainResolveOptions{Server: worker.config.DNSResolver}},
		RemoteIsDomain: true, NewDialer: true, ProtectPlatformSocket: true})
	if err != nil { return false, errors.New("smart_access_runtime_control_transport_unavailable") }
	worker.transport = &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		MaxResponseHeaderBytes: smartAccessRuntimeControlLimit,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: adapter.RootPoolFromContext(instance.ctx)},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return protected.DialContext(ctx, network, M.ParseSocksaddr(address))
		},
	}
	worker.client = &http.Client{Transport: worker.transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	journal, err := smartAccessRestrictionStore(storageDirectory)
	if err != nil { return false, err }
	journalGeneration, err := journal.begin(worker.config.ProfileDigest, worker.config.CatalogSHA256, instance.smartAccessRestrictionExpires)
	if err != nil { return false, err }
	worker.journal, worker.journalGeneration = journal, journalGeneration
	ctx, cancel := context.WithDeadline(instance.ctx, worker.deadline)
	worker.ctx, worker.cancel, worker.instance = ctx, cancel, instance
	if previous != nil && previous.ctx.Err() == nil && now.Before(previous.expires) && now.Before(previous.deadline) {
		worker.renewals = make(map[string]*smartAccessRuntimeRenewal)
		for scope, renewal := range previous.renewals {
			if now.Before(renewal.expires) && now.Before(renewal.deadline) && !renewal.expires.After(worker.expires) {
				worker.renewals[scope] = renewal
			}
		}
	}
	if previous != nil { previous.cancel() }
	instance.smartAccessControl = worker
	go s.runSmartAccessRuntimeControl(ctx, worker)
	return true, nil
}

func (s *StartedService) runSmartAccessRuntimeControl(ctx context.Context, worker *smartAccessRuntimeControlWorker) {
	defer worker.journal.finish(worker.config.ProfileDigest, worker.journalGeneration)
	defer worker.cancel()
	defer worker.transport.CloseIdleConnections()
	for ctx.Err() == nil && time.Now().Before(worker.expires) && time.Now().Before(worker.deadline) {
		if decision, ok := worker.poll(ctx); ok {
			s.applySmartAccessRuntimeControl(ctx, worker, decision)
			if attempt, eligible := s.nextSmartAccessRuntimeRenewal(worker, decision); eligible {
				if renewal, verified := worker.pollRenewal(attempt); verified {
					s.applySmartAccessRuntimeRenewal(worker, attempt, renewal)
				}
			}
		}
		// One restriction request and at most one due renewal per cadence;
		// failures still wait, with no burst or catch-up loop.
		timer := time.NewTimer(smartAccessRuntimeControlInterval)
		select {
		case <-ctx.Done(): timer.Stop(); return
		case <-timer.C:
		}
	}
}

func (worker *smartAccessRuntimeControlWorker) poll(ctx context.Context) (smartAccessRuntimeDecision, bool) {
	var rejected smartAccessRuntimeDecision
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil { return rejected, false }
	nonce := hex.EncodeToString(nonceBytes)
	body, _ := json.Marshal(map[string]string{"schema_version": "pokrov-smart-access-runtime-control-request-v1",
		"request_nonce": nonce, "profile_digest": worker.config.ProfileDigest, "platform": worker.config.Platform})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(worker.config.APIBaseURL, "/") + "/api/client/smart-access/runtime-control", bytes.NewReader(body))
	if err != nil { return rejected, false }
	request.Header.Set("Authorization", "Bearer " + worker.config.Capability)
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
	now := time.Now()
	reason, expires, valid := worker.verify(data, nonce, started, now)
	return smartAccessRuntimeDecision{reason: reason, expires: expires, deadline: now.Add(expires.Sub(now))}, valid
}

func (worker *smartAccessRuntimeControlWorker) verify(raw []byte, nonce string, started, now time.Time) (string, time.Time, bool) {
	outer, ok := smartAccessControlObject(raw, "schema", "envelope")
	if !ok { return "", time.Time{}, false }
	var schema string
	if json.Unmarshal(outer["schema"], &schema) != nil || schema != "smart-access-runtime-control-response-v1" { return "", time.Time{}, false }
	envelope, ok := smartAccessControlObject(outer["envelope"], "algorithm", "key_id", "payload_sha256", "payload", "signature_b64")
	if !ok { return "", time.Time{}, false }
	var algorithm, keyID, digest, signatureText string
	if json.Unmarshal(envelope["algorithm"], &algorithm) != nil || algorithm != "Ed25519" ||
		json.Unmarshal(envelope["key_id"], &keyID) != nil || json.Unmarshal(envelope["payload_sha256"], &digest) != nil ||
		json.Unmarshal(envelope["signature_b64"], &signatureText) != nil { return "", time.Time{}, false }
	key, found := worker.keys[keyID]
	if !found || !smartAccessRuntimeDigest.MatchString(digest) || len(signatureText) != 86 { return "", time.Time{}, false }
	values, ok := smartAccessControlObject(envelope["payload"], "schema_version", "request_nonce", "device_binding",
		"profile_digest", "platform", "audience", "action", "reason", "issued_at", "expires_at")
	if !ok { return "", time.Time{}, false }
	payload := make(map[string]string, len(values))
	for field, raw := range values {
		var value string
		if json.Unmarshal(raw, &value) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) { return "", time.Time{}, false }
		payload[field] = value
	}
	binding := sha256.Sum256([]byte("pokrov-smart-access-runtime-binding-v1\x00" + nonce + "\x00" + worker.config.Capability))
	if payload["schema_version"] != "pokrov-smart-access-runtime-control-v1" || payload["request_nonce"] != nonce ||
		payload["profile_digest"] != worker.config.ProfileDigest || payload["platform"] != worker.config.Platform ||
		payload["audience"] != worker.config.Audience || payload["device_binding"] != hex.EncodeToString(binding[:]) { return "", time.Time{}, false }
	reason := payload["reason"]
	expected := map[string]string{"current": "none", "issuance_disabled": "drain", "access_denied": "terminate",
		"provider_policy_disabled": "terminate", "catalog_disabled": "terminate"}
	action, known := expected[reason]
	if !known || payload["action"] != action { return "", time.Time{}, false }
	issued, validIssued := smartAccessControlTime(payload["issued_at"])
	expires, validExpires := smartAccessControlTime(payload["expires_at"])
	if !validIssued || !validExpires || !issued.Before(expires) || expires.Sub(issued) > time.Minute ||
		issued.Before(started.UTC().Truncate(time.Second)) || now.Before(issued) || !now.Before(expires) ||
		expires.After(worker.expires) || !now.Before(worker.expires) || !now.Before(worker.deadline) { return "", time.Time{}, false }
	// Every accepted value above is bounded ASCII, so sorted Go string-map JSON
	// equals the backend's sort_keys/ensure_ascii/separators canonical payload.
	canonical, err := json.Marshal(payload)
	if err != nil { return "", time.Time{}, false }
	hash := sha256.Sum256(canonical)
	if digest != hex.EncodeToString(hash[:]) { return "", time.Time{}, false }
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signatureText)
	if err != nil || !ed25519.Verify(key, append([]byte("pokrov-smart-access-runtime-control-v1\n"), canonical...), signature) { return "", time.Time{}, false }
	return reason, expires, true
}

func (s *StartedService) applySmartAccessRuntimeControl(ctx context.Context, worker *smartAccessRuntimeControlWorker, decision smartAccessRuntimeDecision) {
	s.serviceAccess.RLock()
	defer s.serviceAccess.RUnlock()
	if ctx.Err() != nil || s.closed || s.serviceStatus.Status != ServiceStatus_STARTED ||
		s.instance != worker.instance || s.instance.smartAccessControl != worker ||
		!time.Now().Before(worker.deadline) || !time.Now().Before(worker.expires) ||
		!time.Now().Before(decision.expires) || !time.Now().Before(decision.deadline) { return }
	reason := decision.reason
	if reason == "current" { return }
	box := worker.instance.instance
	if reason == "catalog_disabled" || reason == "access_denied" { box.RevokeRoutingCatalog() }
	for _, outbound := range box.Outbound().Outbounds() {
		if lease, ok := outbound.(*smartaccess.Outbound); ok { lease.Revoke(reason != "issuance_disabled") }
	}
	worker.journal.restrict(worker.config.ProfileDigest, worker.journalGeneration, reason)
}
