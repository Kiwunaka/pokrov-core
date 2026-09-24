package daemon

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const smartAccessRestrictionSnapshotLimit = 1024 * 1024
const smartAccessRestrictionDocumentLimit = smartAccessRestrictionSnapshotLimit - 1024

// This journal contains restriction metadata only. Its directory comes from the
// native owner's existing private working path, never from worker JSON/profile.
// A pending record is committed before the worker starts, so a crash after a
// failed restriction write cannot be mistaken for a clean, unrestricted stop.
type smartAccessRestrictionRecord struct {
	ProfileDigest string `json:"profile_digest"`
	CatalogSHA256 string `json:"catalog_sha256"`
	Generation string `json:"generation"`
	Pending bool `json:"pending"`
	PolicyAction string `json:"policy_action"`
	CatalogWithdrawn bool `json:"catalog_withdrawn"`
	ExpiresAt string `json:"expires_at"`
	Leases []smartAccessRuntimeLeaseIdentity `json:"leases"`
	ScopeActions map[string]string `json:"scope_actions"`
}

type smartAccessRestrictionDocument struct {
	Version int `json:"version"`
	Records []smartAccessRestrictionRecord `json:"records"`
}

type smartAccessRestrictionJournal struct {
	access sync.Mutex
	path string
	loaded bool
	document smartAccessRestrictionDocument
	live map[string]string // profile digest -> worker generation, process-local
	unsettled map[string]bool // Capacity failure must leave pending after worker finish.
}

var smartAccessRestrictionJournals = struct {
	sync.Mutex
	byPath map[string]*smartAccessRestrictionJournal
}{byPath: make(map[string]*smartAccessRestrictionJournal)}

func smartAccessRestrictionStore(directory string) (*smartAccessRestrictionJournal, error) {
	if directory == "" { return nil, errors.New("smart_access_restriction_storage_unavailable") }
	root, err := filepath.Abs(directory)
	if err != nil { return nil, errors.New("smart_access_restriction_storage_unavailable") }
	path := filepath.Join(root, "smart-access-restrictions.v1.json")
	smartAccessRestrictionJournals.Lock()
	defer smartAccessRestrictionJournals.Unlock()
	journal := smartAccessRestrictionJournals.byPath[path]
	if journal == nil {
		journal = &smartAccessRestrictionJournal{path: path, live: make(map[string]string), unsettled: make(map[string]bool)}
		smartAccessRestrictionJournals.byPath[path] = journal
	}
	return journal, nil
}

func (journal *smartAccessRestrictionJournal) loadLocked() error {
	if journal.loaded { return nil }
	invalid := errors.New("smart_access_restriction_storage_invalid")
	file, err := os.Open(journal.path)
	if errors.Is(err, os.ErrNotExist) {
		journal.document = smartAccessRestrictionDocument{Version: 1, Records: []smartAccessRestrictionRecord{}}
		journal.loaded = true
		return nil
	}
	if err != nil { return invalid }
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, smartAccessRestrictionDocumentLimit + 1))
	if err != nil || len(data) > smartAccessRestrictionDocumentLimit { return invalid }
	object, ok := smartAccessControlObject(data, "version", "records")
	if !ok { return invalid }
	var version int
	var records []json.RawMessage
	if json.Unmarshal(object["version"], &version) != nil || version != 1 ||
		json.Unmarshal(object["records"], &records) != nil || records == nil || len(records) > 3 { return invalid }
	document := smartAccessRestrictionDocument{Version: 1, Records: []smartAccessRestrictionRecord{}}
	seen := make(map[string]bool)
	for _, raw := range records {
		fields, ok := smartAccessControlObject(raw, "profile_digest", "catalog_sha256", "generation", "pending", "policy_action", "catalog_withdrawn", "expires_at", "leases", "scope_actions")
		if !ok { return invalid }
		for _, value := range fields { if bytes.Equal(bytes.TrimSpace(value), []byte("null")) { return invalid } }
		var record smartAccessRestrictionRecord
		if json.Unmarshal(raw, &record) != nil || !smartAccessRuntimeDigest.MatchString(record.ProfileDigest) ||
			(record.CatalogSHA256 != "" && !smartAccessRuntimeDigest.MatchString(record.CatalogSHA256)) ||
			!smartAccessLeaseID.MatchString(record.Generation) || seen[record.ProfileDigest] ||
			(record.PolicyAction != "none" && record.PolicyAction != "drain" && record.PolicyAction != "terminate") ||
			(record.CatalogWithdrawn && record.PolicyAction != "terminate") { return invalid }
		if record.ExpiresAt != "" {
			if _, ok := smartAccessControlTime(record.ExpiresAt); !ok { return invalid }
		}
		var leases []json.RawMessage
		if json.Unmarshal(fields["leases"], &leases) != nil || leases == nil || len(leases) > 256 { return invalid }
		leaseIDs := make(map[string]bool)
		for _, rawLease := range leases {
			lease, valid := parseSmartAccessRuntimeLeaseIdentity(rawLease)
			if !valid || leaseIDs[lease.LeaseID] { return invalid }
			activeUntil, _ := smartAccessControlTime(lease.ActiveFlowsUntil)
			expires, validExpiry := smartAccessControlTime(record.ExpiresAt)
			if !validExpiry || activeUntil.After(expires) { return invalid }
			leaseIDs[lease.LeaseID] = true
		}
		if record.ScopeActions == nil || len(record.ScopeActions) > 256 { return invalid }
		scopeKeys := make([]string, 0, len(record.ScopeActions))
		for scope, action := range record.ScopeActions {
			if !smartAccessRuntimeDigest.MatchString(scope) || (action != "drain" && action != "terminate") { return invalid }
			scopeKeys = append(scopeKeys, scope)
		}
		if _, ok := smartAccessControlObject(fields["scope_actions"], scopeKeys...); !ok { return invalid }
		seen[record.ProfileDigest] = true
		document.Records = append(document.Records, record)
	}
	journal.document, journal.loaded = document, true
	return nil
}

func (journal *smartAccessRestrictionJournal) writeLocked() error {
	failed := errors.New("smart_access_restriction_storage_unavailable")
	data, err := json.Marshal(journal.document)
	if err != nil || len(data) > smartAccessRestrictionDocumentLimit { return failed }
	file, err := os.CreateTemp(filepath.Dir(journal.path), ".smart-access-restrictions-*")
	if err != nil { return failed }
	name := file.Name()
	defer os.Remove(name) // only this operation's temporary file; retained journal is never removed
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || os.Rename(name, journal.path) != nil { return failed }
	return nil
}

func (journal *smartAccessRestrictionJournal) begin(profileDigest, catalogSHA256 string, expires time.Time) (string, error) {
	journal.access.Lock()
	defer journal.access.Unlock()
	if err := journal.loadLocked(); err != nil { return "", err }
	if journal.unsettled[profileDigest] { return "", errors.New("smart_access_restriction_recovery_required") }
	index := -1
	for i, record := range journal.document.Records {
		if record.ProfileDigest == profileDigest { index = i; break }
	}
	if index < 0 && len(journal.document.Records) >= 3 { return "", errors.New("smart_access_restriction_recovery_required") }
	if index >= 0 {
		record := journal.document.Records[index]
		// Uncertain previous-process state must be handed back before enrollment.
		if record.Pending && journal.live[profileDigest] == "" { return "", errors.New("smart_access_restriction_recovery_required") }
		if (record.PolicyAction != "none" || record.CatalogWithdrawn || len(record.ScopeActions) != 0) && journal.live[profileDigest] == "" {
			return "", errors.New("smart_access_restriction_recovery_required")
		}
		if record.CatalogSHA256 != "" && record.CatalogSHA256 != catalogSHA256 { return "", errors.New("smart_access_restriction_binding_invalid") }
	}
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil { return "", errors.New("smart_access_restriction_storage_unavailable") }
	generation := hex.EncodeToString(bytes)
	previous := append([]smartAccessRestrictionRecord{}, journal.document.Records...)
	if index < 0 {
		journal.document.Records = append(journal.document.Records,
			smartAccessRestrictionRecord{ProfileDigest: profileDigest, CatalogSHA256: catalogSHA256, PolicyAction: "none",
				Leases: []smartAccessRuntimeLeaseIdentity{}, ScopeActions: make(map[string]string)})
		index = len(journal.document.Records) - 1
	}
	record := &journal.document.Records[index]
	record.Generation, record.Pending = generation, true
	if record.CatalogSHA256 == "" { record.CatalogSHA256 = catalogSHA256 }
	previousExpiry, _ := smartAccessControlTime(record.ExpiresAt)
	if !expires.IsZero() && expires.After(previousExpiry) { record.ExpiresAt = expires.UTC().Format("2006-01-02T15:04:05Z") }
	if err := journal.writeLocked(); err != nil {
		journal.document.Records = previous
		return "", err
	}
	journal.live[profileDigest] = generation
	return generation, nil
}

// The caller has validated the renewal and holds the service/outbound locks.
// Persist before replacing lease authority; failure leaves the old lease active.
func (journal *smartAccessRestrictionJournal) extendExpiry(profileDigest, generation string, expires time.Time) error {
	journal.access.Lock()
	defer journal.access.Unlock()
	// A settled worker cannot receive another restriction. Its record can have
	// been handed back already; future enrollment captures the instance's bound.
	if journal.live[profileDigest] != generation { return nil }
	for i := range journal.document.Records {
		record := &journal.document.Records[i]
		if record.ProfileDigest != profileDigest || record.Generation != generation { continue }
		previous, _ := smartAccessControlTime(record.ExpiresAt)
		if !expires.After(previous) { return nil }
		old := record.ExpiresAt
		record.ExpiresAt = expires.UTC().Format("2006-01-02T15:04:05Z")
		if err := journal.writeLocked(); err != nil { record.ExpiresAt = old; return err }
		return nil
	}
	return errors.New("smart_access_restriction_recovery_required")
}

// Called from the renewal's pre-adoption callback after signed response/scope
// validation, while the service and target outbound locks remain held. Retain
// both generations atomically; a late candidate remains metadata, not authority.
func (journal *smartAccessRestrictionJournal) retainRenewal(profileDigest, generation string,
	previous, next smartAccessRuntimeLeaseIdentity, currentIDs map[string]bool) error {
	journal.access.Lock()
	defer journal.access.Unlock()
	failed := errors.New("smart_access_renewal_recovery_required")
	if journal.live[profileDigest] != generation || previous.LeaseID == next.LeaseID || !next.follows(previous) { return failed }
	for i := range journal.document.Records {
		record := &journal.document.Records[i]
		if record.ProfileDigest != profileDigest || record.Generation != generation { continue }
		if !record.Pending || record.PolicyAction != "none" || record.CatalogWithdrawn ||
			record.ScopeActions[next.RuntimeScopeSHA256] != "" { return failed }
		now := time.Now()
		leases := make(map[string]smartAccessRuntimeLeaseIdentity)
		for _, lease := range record.Leases {
			activeUntil, _ := smartAccessControlTime(lease.ActiveFlowsUntil)
			if now.Before(activeUntil) || currentIDs[lease.LeaseID] || lease.LeaseID == previous.LeaseID || lease.LeaseID == next.LeaseID {
				leases[lease.LeaseID] = lease
			}
		}
		for _, lease := range []smartAccessRuntimeLeaseIdentity{previous, next} {
			if retained, exists := leases[lease.LeaseID]; exists && retained != lease { return failed }
			leases[lease.LeaseID] = lease
		}
		if len(leases) > 256 { return failed }
		before := *record
		record.Leases = make([]smartAccessRuntimeLeaseIdentity, 0, len(leases))
		expires, _ := smartAccessControlTime(record.ExpiresAt)
		for _, lease := range leases {
			record.Leases = append(record.Leases, lease)
			activeUntil, _ := smartAccessControlTime(lease.ActiveFlowsUntil)
			if activeUntil.After(expires) { expires = activeUntil }
		}
		sort.Slice(record.Leases, func(i, j int) bool { return record.Leases[i].LeaseID < record.Leases[j].LeaseID })
		record.ExpiresAt = expires.UTC().Format("2006-01-02T15:04:05Z")
		if err := journal.writeLocked(); err != nil { *record = before; return err }
		return nil
	}
	return failed
}

// Failure keeps the stricter in-memory record; the already committed pending
// marker covers crash recovery. It must not delay restriction of the live graph.
func (journal *smartAccessRestrictionJournal) restrict(profileDigest, generation, reason string) {
	journal.access.Lock()
	defer journal.access.Unlock()
	for i := range journal.document.Records {
		record := &journal.document.Records[i]
		if record.ProfileDigest != profileDigest || record.Generation != generation { continue }
		if reason == "catalog_disabled" { record.CatalogWithdrawn = true }
		if reason != "issuance_disabled" { record.PolicyAction = "terminate" } else if record.PolicyAction == "none" { record.PolicyAction = "drain" }
		_ = journal.writeLocked()
		return
	}
}

func (journal *smartAccessRestrictionJournal) restrictScope(profileDigest, generation, scope, action string) {
	journal.access.Lock()
	defer journal.access.Unlock()
	for i := range journal.document.Records {
		record := &journal.document.Records[i]
		if record.ProfileDigest != profileDigest || record.Generation != generation { continue }
		if record.ScopeActions[scope] == "" && len(record.ScopeActions) >= 256 {
			// Do not widen a scoped kill or manufacture an oversized document.
			// Pending survives clean finish, so recovery cannot mistake it for none.
			journal.unsettled[profileDigest] = true
			return
		}
		if record.ScopeActions[scope] != "terminate" { record.ScopeActions[scope] = action }
		_ = journal.writeLocked()
		return
	}
}

func (journal *smartAccessRestrictionJournal) finish(profileDigest, generation string) {
	journal.access.Lock()
	defer journal.access.Unlock()
	if journal.live[profileDigest] != generation { return }
	delete(journal.live, profileDigest)
	for i := range journal.document.Records {
		if journal.document.Records[i].ProfileDigest == profileDigest {
			journal.document.Records[i].Pending = journal.unsettled[profileDigest]
			_ = journal.writeLocked()
			return
		}
	}
}

// A snapshot hash covers the exported records and liveness. Acknowledging it
// cannot erase a concurrent restriction or any record with a live worker.
func (journal *smartAccessRestrictionJournal) snapshotLocked() (string, string, error) {
	if err := journal.loadLocked(); err != nil { return "", "", err }
	// Retry an earlier failed write before claiming durable readback.
	if err := journal.writeLocked(); err != nil { return "", "", err }
	records := append([]smartAccessRestrictionRecord{}, journal.document.Records...)
	sort.Slice(records, func(i, j int) bool { return records[i].ProfileDigest < records[j].ProfileDigest })
	entries := make([]map[string]any, 0, len(records))
	for _, record := range records {
		// Maps canonicalize nested identity keys too; struct declaration order
		// must not affect the snapshot hash consumed by the client.
		leases := make([]map[string]json.RawMessage, 0, len(record.Leases))
		for _, lease := range record.Leases {
			leases = append(leases, lease.canonicalObject())
		}
		entries = append(entries, map[string]any{"profile_digest": record.ProfileDigest, "catalog_sha256": record.CatalogSHA256,
			"generation": record.Generation, "pending": record.Pending, "policy_action": record.PolicyAction,
			"catalog_withdrawn": record.CatalogWithdrawn, "expires_at": record.ExpiresAt, "leases": leases, "scope_actions": record.ScopeActions,
			"live": journal.live[record.ProfileDigest] == record.Generation})
	}
	canonical, _ := json.Marshal(entries)
	hash := sha256.Sum256(canonical)
	digest := hex.EncodeToString(hash[:])
	encoded, err := json.Marshal(map[string]any{"schema": 1, "snapshot_sha256": digest, "entries": entries})
	if err != nil || len(encoded) > smartAccessRestrictionSnapshotLimit { return "", "", errors.New("smart_access_restriction_storage_invalid") }
	return string(encoded), digest, nil
}

func ReadSmartAccessRestrictions(directory string) (string, error) {
	journal, err := smartAccessRestrictionStore(directory)
	if err != nil { return "", err }
	journal.access.Lock()
	defer journal.access.Unlock()
	encoded, _, err := journal.snapshotLocked()
	return encoded, err
}

// Only call after the client has durably retained every restriction/uncertain
// recovery marker in the snapshot. A successful call never clears live latches.
func AcknowledgeSmartAccessRestrictions(directory, snapshotSHA256 string) (bool, error) {
	if !smartAccessRuntimeDigest.MatchString(snapshotSHA256) { return false, errors.New("smart_access_restriction_ack_invalid") }
	journal, err := smartAccessRestrictionStore(directory)
	if err != nil { return false, err }
	journal.access.Lock()
	defer journal.access.Unlock()
	_, current, err := journal.snapshotLocked()
	if err != nil { return false, err }
	if current != snapshotSHA256 { return false, nil }
	previous := journal.document.Records
	retained := make([]smartAccessRestrictionRecord, 0, len(previous))
	for _, record := range previous {
		if journal.live[record.ProfileDigest] == record.Generation { retained = append(retained, record) }
	}
	journal.document.Records = retained
	if err := journal.writeLocked(); err != nil { journal.document.Records = previous; return false, err }
	for _, record := range previous { if journal.live[record.ProfileDigest] != record.Generation { delete(journal.unsettled, record.ProfileDigest) } }
	return true, nil
}
