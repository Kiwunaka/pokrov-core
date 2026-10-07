# Architecture

POKROV Core is one client runtime with three layers:

1. `platform/` exposes the small Android and desktop interfaces consumed by the app.
2. `v2/` owns setup, configuration, lifecycle, WARP, DNS, and safe shutdown behavior.
3. `engine/sing-box/` owns transports, routing, TLS, TUN, and protocol implementations.

Managed Country Auto can explicitly list `preferred_outbounds` in its existing
URLTest group. A healthy member of that tier takes precedence over other members;
latency and hysteresis still select within the tier. When its probes fail, the
remaining live members become eligible; recovery restores the preferred tier.
Groups without this field use ordinary latency selection. Failed probe history
is excluded from live selection, and tolerance arithmetic cannot wrap into a
smaller delay. The managed issuer gates this input to Core 1.2.4 or later.
Published Core 1.2.3 and
subscription exports for external clients omit this option.

An owned Windows A/B comparison kept public client 1.4.1, identical profile
bytes, the effective digest and all four SRS files. Stock Core 1.2.2 reached the
native TLS deadline after 19.542 seconds; exact Core 1.2.2 with only the URLTest
selection fix retained native DNS and egress health beyond 200 seconds and
passed strict HTTPS 204 and 64 KiB checks. This supports the isolated selection
fix; the selected member/history was not exposed. Live acceptance of the
complete Core 1.2.5 SDK remains pending.

Android callers that start Libbox CommandServer directly use the mobile SDK's
`NormalizeRuntimeConfig` on a runtime copy after validating the saved profile's
signature and digest. It reuses the existing legacy DNS normalizer before the
strict engine parser; saved profile bytes stay unchanged and normalization errors
stop startup.

The embedded engine also contains the dedicated Linux HY2 server's opt-in `experimental.hysteria_reload` path. Its local pinned `replace/sing-quic` patch closes removed/rotated users' actual QUIC sessions and cancels only their routing contexts. Private SIGUSR2 changes only that inbound's auth and direct account routes; listener, TLS, DNS and other options stay immutable. The same process may include one fixed private IPv4 TCP/UDP port 53 `pokrov-awg-dns` direct inbound with its exact first scoped DNS hijack rule; reload preserves that listener, rule, DNS policy and rule sets. Adding the listener requires a cold restart; later auth reloads retain the running process. Rule snapshots let unchanged users finish pending DNS/sniff matching while account routes swap. The existing command writes a private loaded-config/PID/systemd-InvocationID proof only after the new state is applied. This path is off for client runtimes and has no public control port.

The opt-in `pokrov-telegram-ws` outbound accepts an explicit Telegram DC address
table and an existing encrypted `vpn_outbound`. Only native obfuscated TCP:443
flows in that table can use TLS-verified `kwsN.web.telegram.org/apiws` with the
binary WebSocket protocol and the existing protected platform dialer. The
original initialization and ciphertext stay unchanged. Unsupported formats,
other destinations, UDP, and failed WSS setup retain the VPN path; a WSS failure
after transmission closes that stream and sends subsequent DC flows through
VPN until the runtime restarts, without replaying ciphertext. Host policy must
keep explicit VPN application choices ahead of this service rule. The source
inventory reports `pokrov_telegram_ws_v1` as implementation support only.
Native TG admission version 1 verifies the original pinned signed catalog,
selected service/access/platform, exact public DC literals and the current
recursive encrypted VPN fallback. Its private one-use preparation retains
original `_meta` for TG-first/DPI-second composition before final stripping and
one CoreStart. CheckConfig does not consume permission; actual Start creates a
fresh unavailable holder. The native owner captures its ID and current physical
network/profile before admission. Native owner cancellation, UTC plus monotonic
expiry, interface updates and targeted catalog revocation terminally deny WSS before closing only owned
setup/WSS streams. Untimed exact TCP443 routes keep VPN fallback after denial;
parent-live setup can preserve bytes through VPN, while committed WSS payload
is never replayed. Host original-request and final-profile digests are distinct.
The signed producer and matching Windows consumer are source-only; App emits no
TG metadata, and activation stays OFF until matching artifacts and device gates.
Android's first asynchronous interface publication can withdraw the fresh holder
before admission; this remains fail closed and does not establish device readiness.

The dormant `pokrov-local-dpi` outbound starts unavailable and creates a fresh
admission ID for each runtime. A trusted native owner must capture it with
`ReadLocalDpiAdmissionID`, bind a fresh signed exact-domain HEAD proof to the
current profile/session/network, then call `AdmitLocalDpiAdmission`; there is no
production caller yet. `LocalDpiAdmissionVersion` and the additive desktop ABI 2
descriptor/symbols report API support version 1, not proof or device readiness.
It connects only to a literal loopback SOCKS5 endpoint
whose owner controls client access and protects remote egress. A failed CONNECT
before application bytes permits one encrypted VPN dial; subsequent transport
failure withdraws only this admission and never replays the stream. The exact-ID
`WithdrawLocalDpiAdmission` leaves catalog windows and VPN outbounds intact;
withdrawal is terminal for this runtime. Remote bytes are not TLS/HTTP success.
Withdrawal denies cached payload writes and closes only owned local setup and
offloaded sockets before the native owner stops winws/WinDivert or its SOCKS
child; established ordinary VPN flows keep running.
Libbox `VerifyLocalDpiCatalog` uses Core's Ed25519 implementation and native
compiled key pins to verify the original canonical payload bytes, current signed
lifetime and exact Android Selective VPN intent with a nonshared exact control
host. It does not admit a holder or perform the TLS proof. Signed Selective
authority and native proof integration remain separate, with the feature
disabled; existing Full and expiry behavior is unchanged.

Windows source has a separate `WindowsLocalDpiAdmissionVersion` and desktop
`windows_local_dpi_admission_version:1` descriptor. Native
`PrepareWindowsLocalDpiProfile` verifies Windows authority with the host's
compiled pins and prepares only matching nonshared Selective domain rules,
including the exact control host, with a physically bound TCP:443 local path
and the original encrypted VPN fallback. It does not start winws, perform proof
or admit a holder. Android retains its loopback SOCKS path. Setup failure uses
one VPN dial; transmitted streams are never replayed. Windows service executor,
assets, current profile/network proof and captured-holder lifetime ownership
remain required, so this source capability does not enable the feature or
change retained releases.

The device-local WARP path registers on the device and caches its material by
`install_unique_id`; a caller must use its own authenticated installation ID
and cannot reuse another installation's material. First TCP and UDP operations
wait for initialization through their context, while Close wakes pending
operations and closes an endpoint that arrives later. Cloudflare `client_id`
supplies the three reserved bytes, IPv6 peer addresses are preserved, and
malformed addresses return an error. Existing packet masking remains in place;
network updates reach the internal WireGuard bind.

The pinned `replace/sing-tun` module closes the Windows adapter immediately if
session creation fails. Its finalizer passes the actual adapter handle to
`WintunCloseAdapter`. The [patch record](../engine/sing-box/replace/sing-tun/POKROV-PATCHES.md)
identifies the upstream base and Windows callback tests; those tests do not
load a driver or alter networking.

`common/urltest/DiagnosticByteBudget` now provides a shared operation-level
reservation ledger (source, NOT_VERIFIED). Its caller supplies an explicit
0..67,108,864-byte allowance matching the signed budget schema ceiling; there
is no default probe allocation. Positive reservations are checked atomically
before work, never refunded or reset by retry, and over-limit requests cancel
the derived context for all children without admitting the extra reservation.
Parent cancellation and Close also cancel that context. Snapshot reports
reserved allowances and closure/exhaustion, not measured traffic or stopped
children. The remaining allowance is not reconstructed from success/failure.

This ledger is not connected to diagnostic IO yet. The owner chose all network
bytes of each diagnostic probe for `max_diagnostic_bytes`, including DNS,
transport handshakes, packet headers and retransmissions across retries.
Existing Android system DNS/TCP preflight and selected-outbound/endpoint Core
probes remain separate uncovered producers; Core application-byte counters do
not prove this wire-traffic bound. A host must fail ATS proof closed until
native wire accounting and enforcement cover every producer. No counter/test/
native/hash/build code was executed during this source addition.

URL probes retain a typed connect/TLS/response stage. Cancellation after dial
returns an error, and the optional second request retains the original context.
The default owned HTTPS probe accepts only status 204 with the exact
`X-Pokrov-Egress-Probe: pokrov-authenticated-egress-v1` header, including the
optional second request. Other configured URL-test targets keep their existing
latency behavior. This marker is ordinary reachability evidence, not an ATS
session-bound receipt or proof of `max_diagnostic_bytes`.
The URL probe itself owns the bounded wait and samples its observed stage when
the context expires. Selected-endpoint and background outbound checks consume
that result directly, so an outer timer cannot erase a TLS or response timeout.
The safe error wrapper exposes no target or raw cause through its message while
preserving `errors.Is`/`errors.As`. Typed DNS errors take precedence over generic
timeouts; typed UDP timeouts and observed TLS/response timeouts map to separate
canonical operational codes. An unqualified deadline cannot establish UDP
blocking, DPI, MTU or other filtering causes. Android and desktop event consumers
must accept the matching additive error-code contract before new artifacts ship.

Lifecycle failures from start/restart/stop also expose only a classified catalog
code through the platform error, legacy status observer and stderr log. Their
internal typed cause remains available through `errors.Is`/`errors.As`; the
structured event keeps the same code instead of reclassifying the safe message.
Raw parser/configuration errors are not diagnostic text.

`ray2sing/` converts supported access links into sing-box options. `third_party/warp-plus/` supplies the pinned WARP registration and helper behavior.

The application supplies a materialized sing-box JSON profile for normal operation. Legacy builder APIs remain internal and are not the public POKROV app contract.

The source-only `pokrov-ats-lease` outbound wraps one VLESS upstream. It rejects
new TCP/UDP flows after the host-supplied 10-minute window, and closes admitted
connections at the original active window of at most one hour. Wall-clock and
captured monotonic deadlines both bound admission and IO; moving the wall clock
back cannot extend an admitted flow. The wrapper keeps a revoked route target
rejecting new flows and can drain or terminate current ones. It verifies its
window shape, not the account/provider authority that supplied it. The typed
gate rejects a TCP or UDP dial that returns a socket after its original dial
context was cancelled, closing that socket before it becomes an active flow.
Terminal revoke latches the active-flow read/write gate before closing sockets;
drain leaves admitted flows on their original deadline.
The inventory advertises `pokrov_ats_lease_v1` for matching Core artifacts. The
client and host source now bind exact profile/request ownership at handoff:
Android and Windows call the loaded gate's confirmation, while Linux confirms
the same gate through its private Core child command before replacing the
startup deadline. Confirmation is a read-only identity check: the leased Core
route remains usable during the pending native proof, whose payload stage must
traverse that same Core owner. It does not attest proof or delay ordinary flows;
the client must keep protection unverified until all proof stages and handoff
finish. An exact Core revocation method now denies new flows and can
terminate active flows; Android, Windows and Linux host source paths call it for
the bound lease. Signed client policy delivery and native proof production are
separate requirements; these handoffs do not create proof themselves.
This source is NOT_VERIFIED; no Core build or runtime check has run.

## Catalog rule lifetime (local implementation, NOT_VERIFIED)

The embedded rule options accept `pokrov_catalog_window` on top-level default
route and DNS rules containing an exact-domain or domain-suffix match. The
window has `issued_at` and `expires_at` in exact UTC seconds
(`YYYY-MM-DDTHH:MM:SSZ`), with expiry later than issue. Future-issued windows,
inverted rules, missing domain matches and timed children of logical rules are
rejected. Supported timed actions are route and reject. The application owns
signature verification, revision/security floors, entitlement, service selection,
precedence and the immediately following untimed fallback rule; Core does not
infer any of those from a window.

Admission checks the window before normal matching/inversion. An expired window
stops matching, and a monotonic deadline plus a latched expiry prevents wall-clock
rollback from extending a window already admitted in this process. Reloading a
profile remains subject to the application's retained catalog clock/revision
checks. Expiry changes new rule decisions and does not drain existing connections.
Timed DNS route actions force cache off and TTL zero so Core cannot retain their
answers past the rule lifetime. This does not clear an application's independent
DNS cache or add visibility into encrypted DNS/ECH.

`libbox.RoutingCatalogWindowVersion()` and the desktop ABI 2 capability descriptor
advertise version 1 in source. Clients must negotiate the loaded artifact before
staging these rules; older artifacts have no support. No replacement AAR/DLL,
focused tests, formatting gate or runtime acceptance has been produced for this
source change. Existing artifact identities and release claims remain separate.

## Smart Access lease runtime (local implementation, NOT_VERIFIED)

The `pokrov-smart-access` outbound consumes a host-verified grant projection:
lease ID, issue/new-flow/active-flow deadlines, up to eight literal relay addresses,
exact/suffix domain scope, admission/concurrency limits and optional explicit
`relay_connect_policy`. Core does
not verify the platform signature or choose a provider. The host must bind this
projection to the current account/device/profile and approved policies.

Only visible-SNI TLS over TCP/443 is admitted. Before dialing a permitted relay,
the outbound reads at most 65535 bytes of ClientHello records, rejects ECH
(including GREASE), absent/malformed SNI and names outside the lease. It replays
the same bytes through the existing connection manager, without TLS termination
or certificate changes. Raw dialer and UDP calls are rejected. Relay addresses
exclude private, mapped, translated, reserved and documentation ranges; IPv6
uses the current 2000::/3 public-unicast scope with special ranges excluded.
POKROV control domains cannot enter the leased domain scope. Android relay
sockets use the existing platform protection hook. Admission counts pending
and active flows and rate-limits new admissions per rolling minute; lower-level
interface connection behavior still belongs to the existing system dialer.

New admission is capped at 600 seconds from issue; active lifetime at 3600,
using the shorter host-projected entitlement/permission limits. Captured
monotonic deadlines prevent extending those windows by moving the wall clock
back. Admission expiry is latched per lease generation. Each flow captures its
generation and has a timer closing it at that original active deadline; both
copy directions also fence clock/closed and terminal-revoke state. A scoped
lease revoke and whole-profile terminate latch that gate before socket close;
issuance-only drain still permits admitted flows to finish. Catalog refresh
does not replace a relay on an already admitted connection.

An explicit signed relay-connect budget enables a per-outbound TCP breaker and
bounded same-provider address failover. Its six required integers are
`failure_threshold` (1..10000), `failure_window_ms`, `cooldown_ms`,
`connect_timeout_ms`, `total_timeout_ms` (each 1..600000), and `max_attempts`
(1..8); connect timeout cannot exceed total timeout. These are resource ceilings,
not measured defaults. Null policy keeps one dial to the first projected address.
Operating values remain an operator/provider decision after measurements.

Closed endpoints accumulate failed TCP connects within the window; success clears
the sequence. At threshold they open until monotonic cooldown. One real flow may
reserve half-open; concurrent callers skip it. Success closes, failure reopens.
Epochs reject late results from an older state; caller/lease cancellation does not
count as provider failure. New flows prefer the last successful approved address.
Renewal preserves breaker state; active flows keep their relay and deadlines.
Each flow visits an address at most once, within explicit attempts, per-connect,
total ClientHello-plus-connect and lease deadlines. Additional dials consume the
same minute quota. Switching occurs before forwarding ClientHello; data is never
replayed after handoff. TCP success proves neither TLS nor service health. There
are no synthetic probes. No external calls, tests, measurements or builds were run.

A dial returning a socket after its per-connect or total context deadline is
closed without admitting the flow. A per-connect timeout counts as a failed TCP
attempt for that address; cancellation of the parent flow does not.

Timed gateway route/DNS windows can carry `lease_group`: 1..16 unique original
lease IDs including that window's lease. Every member must resolve to a real
Smart Access outbound with identical domain/matcher scope. The first outbound
anchors one `ServiceLeaseGroup` for the exact service and ordered member pointers;
inconsistent membership is rejected at startup. This executes the client
coordinator's verified order without another ranking or remote provider selector.
Route and DNS rules share its current choice. Local admission expiry/revocation,
quota/concurrency exhaustion or lack of an available TCP breaker member causes
the next rule evaluation to choose the first available candidate. Healthy affinity
is retained after earlier candidates recover. If all candidates are unavailable,
the host's existing scoped VPN/block rules follow. Group reads reserve no probes;
the actual connection rechecks lease, half-open and quota limits.

Selected-outbound/runtime probes of a Smart Access anchor check only that
service group's current IPv4 lease: an uncached A answer from its bound HTTPS
resolver must contain only owned relay addresses, followed by a visible-SNI TLS
handshake through `NewConnection` with normal CA/hostname verification. Both
compiled DNS and TCP rule windows, member/lease identity and instance cancellation
must remain current. Direct/block/DNS leaves remain ineligible. This explicit
resolver check does not prove the ordinary DNS rule walk, HTTP feature access or
other service groups; production admission still requires its capability proofs.
Desktop ABI 2 exposes the same checks through `pokrovCoreProbeSelectedOutbound`
and `pokrovCoreProbeRuntimeEgressV1`; `smart_access_probe_version=1` identifies
support. Startup retains its existing selected-probe budget; the periodic call
accepts at most 3000 ms and joins its cancellation observer before return.
Only an empty caller-owned string means healthy; fixed errors disclose no
transport details. The caller releases every string with `freeString` and owns
the profile/generation fence. Missing older-library support fails closed for
Smart Access without changing ordinary VPN verification.

Desktop probe results retain the typed DNS/connect/TLS stage when an inner
transport deadline completes while the outer probe remains current. This lets
the client recognize the completed Smart Access failure and apply its existing
scoped VPN recovery, matching Android. Caller cancellation, an outer probe
deadline and late results retain their existing lifecycle outcomes.

A provider DoH transport error retires that selected member for the remaining
profile lifetime, then reevaluates the domain from the first rule. Subsequent DNS
and TCP choose the same available standby or the scoped VPN/block fallback.
Caller cancellation and valid negative DNS answers do not retire a member. In-flight
queries and already established connections keep their original owner.

Selection affects subsequent DNS/connection evaluation, never moves/replays an
already admitted or failed connection, and does not cancel old DNS cache entries
or in-flight queries. Each outbound remains separately addressable for renewal,
revocation and journal handback; renewing its identity preserves the group pointer
and affinity. Service withdrawal visits all linked windows/outbounds, while an
individual lease withdrawal permits another approved member. Native selection
is process-local and not inferred from client inventory. UI selection readback is
described below; TLS/service-level health and end-to-end failover evidence remain open.

`StartedService.RenewSmartAccessLease` installs fresh
identity/dates for new admissions only. It requires the expected current lease,
a previously unused identity and a strictly later admission deadline. Exact
retries acknowledge the installed generation without resetting its monotonic
deadlines. Rate and concurrency limits remain shared across generations. The
relay, domain scope and resolver configuration are unchanged. Old generations
remain individually revocable until their original active deadline; expiry of
an old flow closes only that flow. At most 256 generation identities are retained,
with expired history pruned on renewal. Global or current-generation revocation
prevents renewal and cannot be cleared by a new identity.
Runtime grant identities accept `selective` (including selected-service DNS-only
routing) and `smart_safe`; renewal preserves the original routing mode.

Control version 4 exposes this through `CommandServer.RenewSmartAccessLease`
and desktop `pokrovCoreRenewSmartAccessLease`, with five strings: expected/next
lease IDs and exact UTC issue/new-flow/active-flow dates. Return 1 means installed
or exact retry, 0 means expected ID absent, -1 means rejected or unavailable.
Core does not authenticate a grant. Client source verifies unchanged scope,
retains both restriction identities before dispatch, and hosts fence the running
profile and invalidate reuse of its old staged bytes. New version-4 client
profiles retain the original outer catalog lifetime in leased route/DNS windows;
each admission additionally consults the outbound's current lease. Neither
renewal nor retries reset the outer window or any existing flow deadline.
Foreground renewal is connected in source; background delivery, replacement
artifacts and runtime verification remain unfinished.

A structurally valid cached lease whose new-flow deadline has already passed
loads with admission latched off. Its outbound stays registered so the declared
route/DNS VPN or block fallback can start; it never regains relay admission.
Future-issued and structurally invalid leases still reject configuration. This
does not authorize host reuse of a profile invalidated by a received revocation.

`StartedService.RevokeSmartAccessLease` and the matching gomobile
`CommandServer` method target the exact lease ID. `terminateActive=false`
immediately blocks admission and cancels pending flows, allowing admitted flows
to finish within their original limit; `true` also closes admitted flows.
The authenticated host safety decision owns this choice. The outbound stays
registered and rejecting after revocation, so removing a target cannot change
the default route. The bounded restriction worker below can deliver signed
profile-wide decisions independently of Flutter.

Smart Access route/DNS windows additionally carry `lease_id`. At rule startup
Core resolves `pokrov-smart-access-<lease_id>` to the exact Smart Access outbound
and rejects a missing/wrong target. Each rule admission consults that outbound's
locked admission latch as well as its own wall/monotonic window. Received revoke
therefore stops subsequent provider DNS selection too; the client's following
VPN/block rule owns fallback. Ordinary catalog rules omit the lease ID. Already
admitted DNS exchanges and application DNS caches are outside this rule gate;
it does not claim to cancel them or migrate an active relay connection.

Whole-catalog withdrawal has a separate source API,
`StartedService.RevokeRoutingCatalog`, exposed through `CommandServer` and the
additive desktop `pokrovCoreRevokeRoutingCatalog` export. It latches every timed
catalog route/DNS window closed while retaining the following fallback and all
untimed manual/safety rules. It also terminates all Smart Access relay flows in
that runtime. Already routed non-lease connections and admitted DNS exchanges
are not cancelled. Return 1 means catalog windows or leases were found (including
an idempotent repeat), 0 means absent, and -1 means unavailable on desktop.
`libbox.RoutingCatalogControlVersion()` describes this separate API; lifetime
support alone does not imply withdrawal support. The desktop descriptor now
declares `routing_catalog_control_version: 4`; hosts require the matching exports
or gomobile method. Android/Windows source fences the exact running profile,
invalidates its native reuse after a positive result, and exposes the command
to the client's signed-control delivery and restriction inventory. These changes
remain unbuilt and unverified; retained binaries do not acquire the capability.

Control version 2 additionally exposes `StartedService.RevokeSmartAccessPolicy`,
the matching gomobile method and desktop `pokrovCoreRevokeSmartAccessPolicy(int)`.
The authenticated host binds this call to the exact running profile. Core visits
only actual Smart Access outbounds: false drains pending/new flows, true also
terminates admitted flows, within the existing original lifetime limits. Ordinary
catalog/manual/safety rules are unchanged. Result 1 means leases were found and
restricted, 0 means absent, -1 means invalid input or unavailable runtime. This
supports signed provider-wide disable or issuance-only drain when client lease
metadata is unreadable; Core receives no account credentials or remote authority.

Control version 3 adds `RevokeRoutingCatalogService(serviceID)` to the service,
gomobile and desktop adapters (`pokrovCoreRevokeRoutingCatalogService`). New client
profiles label every timed catalog window with its public `service_id`. The command
latches only matching windows closed and terminates their linked Smart Access
leases; untimed fallback/manual/safety rules and other services stay in place.
Already routed non-lease connections and admitted DNS exchanges are unchanged.
The authenticated host fences the running profile and invalidates matching reuse
after a positive result. Older profiles without service labels cannot acknowledge
this scoped operation. It grants no rule insertion, route mutation or lease renewal.

Desktop ABI 2 adds `pokrovCoreRevokeSmartAccessLease`: 1 means a matching lease
was revoked, 0 means absent with no mutation, -1 means invalid input or unavailable
runtime. No allocated return value is involved. The exact export/signature owner
is `config/abi-contract.json`. `smart_access_lease_version: 1` and
`libbox.SmartAccessLeaseVersion()` advertise this source contract, not provider
health. Client source materialization now covers the bounded web/current-origin
subset and foreground signed-provider replacement delivery. Durable/background
revocation delivery and failover remain integration work.
No formatter, test, build or replacement artifact was
produced in this implementation-first phase.

### Native restriction worker (source only, NOT_VERIFIED)

`SmartAccessRuntimeControlVersion() == 1` and desktop descriptor field
`smart_access_runtime_control_version: 1` negotiate a separate command:
`ConfigureSmartAccessRuntimeControl(profileDigest, configJSON)` / desktop
`pokrovCoreConfigureSmartAccessRuntimeControl`. The two-string API is owned by
`config/abi-contract.json`. The authenticated host fences the exact running
profile and invalidates reusable saved/staged bytes before enabling the worker.
Core compares the command identity with its JSON binding. Configuration is not
part of a profile and is never persisted or logged.

The exact eleven-field JSON object uses schema
`pokrov-smart-access-runtime-worker-v1`, `profile_digest`, `catalog_sha256`, `platform`, `audience`,
`api_base_url`, `dns_resolver`, `capability`, `issued_at`, `expires_at` and
`lease_keys_by_id`. The host forwards its local public lease pins and a backend
restriction-only delegation; it supplies no account access/refresh token.
Config/response bodies are bounded to 16 KiB, capabilities to 4096 bytes. The
worker makes one POST to `/api/client/smart-access/runtime-control`, optionally
performs one due renewal after a fresh signed `current` decision, then waits
30 seconds before the next cycle, including after failures. Each request has
a ten-second deadline and uses the existing protected socket dialer, explicit
profile resolver, normal certificate trust and HTTPS/443. No system proxy,
redirect, implicit resolver, transport downgrade or provider probe is used.

Responses require exact object shapes (including duplicate-field rejection),
canonical payload SHA-256, pinned Ed25519 signature under
`pokrov-smart-access-runtime-control-v1\n`, fresh random request nonce,
capability/nonce binding, matching profile/platform/audience, and the backend's
reason/action mapping. Freshness is at most 60 seconds and cannot exceed the
capability expiry. Wall-clock and captured monotonic deadlines fence receipt
and delivery. HTTP/auth/parse/signature failures do not manufacture a kill.

Each worker captures the live `Instance`; stop/reload cancels its context.
Replacement cancels the old worker, and delivery checks both instance and worker
identity under the service lock. Signed catalog disable and access denial close
catalog windows and terminate leases; provider denial terminates leases;
issuance disable drains them. A later `none` never removes a latch. Capability
rotation cannot extend a lease or clear an earlier restriction. The worker ends
at the parent-session-bound expiry and cannot refresh its own authorization.

Before starting a worker, Core commits a pending record to
`smart-access-restrictions.v1.json` in the native owner's existing private
working directory. The directory is passed by the native adapter, never by
worker JSON. The bounded journal has at most three profile records, 256 recovery
lease identities per profile and a document ceiling of 1 MiB minus 1024 bytes
reserved for readback wrapping. Records contain only profile/catalog digest,
random worker generation, pending state, strongest policy action, catalog
withdrawal, `expires_at` and `leases`. Unknown catalog
digest is the empty string; it is not reconstructed from a native profile hash.
No capability, token, trust key, raw grant or provider data is written.

Core derives the restriction expiry from the accepted profile's catalog route/DNS
windows and lease active-flow bounds, retaining their maximum on the instance.
This original bound is committed with pending before worker startup and exported
in every snapshot entry (UTC seconds, empty only for unknown stored state).
It is independent of credential expiry and requires no Flutter metadata or new
worker-config field. An ordinary profile with no remaining timed authority does
not enroll a worker. Renewal validates its candidate, then persists any larger
bound for a live worker before adopting the new lease. A failed write rejects
renewal; a successful but late write cannot admit an expired candidate. The
instance also retains renewal bounds before a later worker is provisioned.

Live restrictions apply before attempting journal I/O. A write failure retains
stricter process-local metadata; the previously committed pending record covers
an intervening crash. Clean worker completion clears pending after retrying the
full record write. Replacement generations cannot settle the previous worker's
record. Corrupt/unreadable journals and three unconsumed slots reject enrollment
without overwriting retained state. Atomic writes sync a newly created private
temporary file and rename it over the journal; no power-loss durability claim
is made before platform verification.

The additive `ReadSmartAccessRestrictions` / `AcknowledgeSmartAccessRestrictions`
APIs work after Core setup even without a live profile. Read retries retained
dirty writes and returns schema 1, `snapshot_sha256` and entries with process-local
`live` flags. Pending plus non-live means uncertain crash recovery, not a signed
kill. Acknowledgement must follow durable client retention of every restriction
and uncertainty marker. It requires the exact current snapshot hash and removes
only non-live entries; concurrent changes require rereading. Errors acknowledge
nothing. Android/Windows source and the Dart runtime interface expose these
operations. The client-store consumer persists restrictions before ACK and gates
stage/renewal using the retained ledger. Native expiry lets it bound crash markers
even when its separate lease inventory is unavailable. A later clean snapshot
may supply a missing original expiry but cannot clear a still-valid restriction.
Core worker support still requires the loaded methods/exports. This unreleased
source schema has nine stored and ten exported entry fields; `scope_actions`
maps at most 256 scope digests to drain/terminate. No older built artifact is claimed
compatible and no crash/device/power-loss proof has been run.

Android and Windows source now provision the worker from a foreground normal
session refresh. Native reuse invalidation protects tile/service restart from
the old saved bytes. Client handback and foreground recovery are connected in
source, including automatic enrollment of a current verified lease after fresh
foreground authority and successful worker setup. This section claims no AAR/DLL build,
runtime acceptance, measured polling behavior or production activation.

`ReadSmartAccessLeases` returns a schema-1 object with sorted `lease_ids` (at most
256 actual current outbound IDs) and sorted `selections` (at most 256 service
rows), bounded to 65536 bytes under the service read lock. Historical generations and raw
scope are excluded. Android invokes the CommandServer method with its existing
session/profile fences. Desktop exports `pokrovCoreReadSmartAccessLeases` as a
caller-owned string released by `freeString`; Windows command 18 requires the
exact running profile through the authenticated serial service. Runtime control
version 1 now requires this additional method/export in the unreleased source.
The client uses these IDs to match saved scope fingerprints with a fresh signed
grant after UI restart. A later renewal still compares the exact old/current ID
under Core's lock, so the snapshot cannot authorize a stale or changed instance.

Each selection row has `service_id`, `lease_id`, `selection_index`, `state`
(`pending`, `gateway`, `unavailable`) and `available`. Pending means no matching
service rule has selected a gateway; gateway reports the last selected member and
whether local admission/quota/breaker permits it at read time. Unavailable means
the last selection found none (empty lease ID, index -1, available=false), not
proof that VPN fallback or a service request succeeded. Group selection occurs
after domain/port/family matching, so unrelated traffic cannot create an observation.
Readback peeks without choosing another provider or probing. IDs include standbys.
This unreleased object replaces the earlier source-only array; no built artifact
compatibility is claimed. Android/Windows/Dart use the same 64 KiB response bound.

`ConfigureSmartAccessRenewal(profileDigest, configJSON)` is a separate two-string
enrollment command on StartedService, CommandServer, hcore and desktop
`pokrovCoreConfigureSmartAccessRenewal`. Runtime control version 1 in this
unreleased source requires this method/export too. The authenticated native host
invalidates matching saved reuse before dispatch and keeps the command out of
profiles, persistence and events. The JSON bound is 16 KiB; its exact six fields
are schema `pokrov-smart-access-runtime-renewal-worker-v1`, profile digest,
`pkr_srn1.` capability, issued/expiry dates and a strict 23-field lease identity.
The identity contains scope digest and revision floors, never relay/domain data.

Enrollment requires a live matching restriction worker, its platform/audience,
and the exact current lease ID and three authority dates under Core's locks.
Revoked, expired or historical generations cannot enroll. Delegation expiry fits
the worker lifetime and is captured against wall and monotonic clocks. Per-scope
replacement cannot regress revision floors; an exact retry keeps its deadline.
Expired entries are removed, with at most 256 scopes / 1 MiB of commands retained.
A live worker replacement copies still-valid enrollments without resetting their
deadlines; instance stop drops them. The command performs no HTTP request, journal
grant write or lease extension. Once enrolled, the existing worker can perform
the signed renewal path below. Foreground source enrolls at most one scope per
refresh and keeps only successful scope/lease/expiry receipts in UI memory.
Signed scope-specific negative delivery uses the same worker. These are NOT_VERIFIED source
changes; no artifact, formatter, test or runtime check was produced.

The native journal now provides `retainRenewal` for the signed-renewal
pre-adoption callback. It atomically writes old/new 23-field identities plus any
larger recovery expiry before authority changes. It requires the live worker
generation, no profile kill, consistent immutable scope and nondecreasing floors;
ID collision, full inventory or write failure rejects retention. Expired history
is pruned while current native IDs and both transition identities remain. A
persisted candidate is still only metadata if later adoption fails.

Readback includes these identities and recursively canonicalizes their keys for
the snapshot hash, with a total 1 MiB response limit. The client matches its
original saved catalog/scope, durably merges identities into its existing secure
inventory and updates active restriction metadata before ACK. All received kills
remain latched; missing/corrupt binding, capacity or persistence failure leaves
the native snapshot unacknowledged. No new grant is reconstructed. Verified native
renewal now calls this producer before adoption; this source path has not run
and makes no crash or durability proof claim.

The worker chooses at most one enrolled due scope after each fresh signed
profile-control `current`. Due time is the midpoint of that scope's accepted
admission lifetime. Least-recently attempted due scopes go first, with a stable
scope-digest tie break; failures cannot monopolize another service's turn. This
is a bounded four-request-per-minute maximum for one worker (control plus
renewal), not a promise to renew all 256 inventory slots before expiry. Capacity
and upstream failure leave original bounds/fallback in force. There is no burst
retry, catch-up loop or provider probe.

Renewal snapshots the credential, current 23-field identity and deadlines under
the service lock, then POSTs nonce/profile/platform/expected ID to the separate
renewal endpoint through the existing protected HTTPS client. Its request is
bounded by the worker, delegation, fresh control decision and ten-second HTTP
deadline. An exact response requires strict envelope/payload/identity shapes,
canonical nested SHA-256, a local pinned Ed25519 key under the renewal signing
context, nonce/capability binding and exact expected current ID. Scope fields
must match and all six revision floors must be nondecreasing. The new identity
must be distinct, newly issued since this request and advance admission; its
10-minute/1-hour bounds also fit the delegation/original catalog expiry.

Application rechecks live instance/worker/enrollment/current identity under the
service lock, finds the exact current outbound, and calls the existing renewal
primitive. Its pre-adoption callback checks wall/monotonic freshness before and
after `retainRenewal`. Write failure, cancellation, expiry or a foreground winner
prevents adoption; an already persisted unused candidate remains harmless
metadata. Successful adoption advances the enrollment's current identity and
instance recovery bound. Old flows retain their own generation, deadlines and
egress; received revocation is never cleared. A fresh signed grant may reopen an
expired admission window, but cannot reopen a revoked lease. HTTP and invalid
responses do not imply a signed scope kill.

A renewal restriction is a separate strict 16-field payload with schema
`pokrov-smart-access-runtime-renewal-restriction-v1` under the same renewal
envelope/signing context. It binds nonce, capability hash, profile/platform/
audience, expected current lease and scope digest, plus action/reason, issuance/
expiry and four catalog/provider global revision fields. Its lifetime is at most
60 seconds and fits the delegation; request-time, wall/monotonic and live-owner
fences still apply. Global access/catalog/provider disable reasons terminate;
issuance disable drains, with all four revision fields zero. Scoped provider or
catalog withdrawal terminates; scope change or capability unavailability drains.
Scoped revisions must meet the current accepted identity's four global floors.

After verification and exact-current-ID checks, a restriction revokes the target
outbound, including its older active generations, before journal I/O. It never
extends authority. The strongest scope action is retained for client handback;
other outbounds are unaffected by this scope-bound response. Whole-profile
restrictions still use the existing control channel. Write failure keeps the
stricter in-memory record and the precommitted pending marker covers a crash.
If the 256-scope map is full, live revocation still applies and the generation
remains pending after finish; it cannot silently restart as clean. Strict journal
loading rejects duplicate scope keys. Positive renewal retention rejects a scope
already present in `scope_actions`. Client secure retention precedes exact-hash ACK.

Android endpoint verification uses the additive `CommandServer.ProbeEndpoint`
gomobile method. Its bounded result belongs to the captured runtime instance and
endpoint of that call; a terminal diagnostic event cannot complete another probe.
The host retains its generation/session fence before applying the result. Older
AARs without this method provide no endpoint verification through this path.
Selector and URL-test groups use `CommandServer.ProbeSelectedOutbound`. Core
captures their selected proxy leaf, runs a bounded per-call URL test, and rejects
the result if the selected leaf or runtime instance changed. Direct, block, DNS,
unsupported groups and cyclic selection cannot supply protected egress proof.
The shared URL-test cache remains diagnostic data and is not a response channel
for this verifier. Timeout and late results cannot settle a different call.
A successful URL test whose selected leaf changed returns the existing closed
`selected route probe unavailable` error, so the host's bounded group retry can
verify the current leaf. It supplies no replacement proof and does not reclassify
real transport errors or expired/cancelled contexts as a selection change.
Periodic Android checks use `CommandServer.ProbeRuntimeEgress(tag, timeoutMs,
cancellation)` with a maximum 3000 ms budget for the selected group or endpoint,
without the startup endpoint initialization wait. Cancellation reaches the probe
context, and its native callback watcher is joined before return. The captured
runtime and exact selected leaf must still be current. The existing transport
worker may settle later; its result cannot complete another check. Startup probe
methods keep their existing budgets.
The shared event ABI and desktop ABI are unchanged. Source-level checks do not
prove that a retained AAR contains the method; replacement artifact binding and
device evidence remain required before promoting this behavior.

The AWG2 and AWG 3.1 experiments remain inside the same embedded sing-box
graph. Their machine owners are `config/awg2-capability.json` and
`config/awg31-capability.json`, with distinct `pokrov.awg2.endpoint.v1` and
`pokrov.awg31.endpoint.v1` contract IDs. The separate default-off Hysteria2
lab is pinned by `config/hy2-capability.json` as
`pokrov.hy2.outbound.v1`; raw `hysteria2://` and `hy2://` conversion remains
disabled so only a provenance-bound managed profile can reach the embedded
official sing-box outbound. The engine uses the official pinned
`amneziawg-go/v3` module for both modes; POKROV adds only typed configuration,
validation and host integration, not custom cryptography. AWG 3.1 requires an
explicit contract ID and remains wire-incompatible with AWG2.

Android and Windows release builds include the `with_awg` tag. The retained
release ABI descriptor does not advertise either AWG lab. The new optional
transport inventory below reports the compiled AWG 3.1 subset only; this does
not grant lab access or prove a rebuilt artifact. A host may accept an `awg` endpoint only
from the digest-bound managed owner-lab path and only with
`useIntegratedTun=false`; Android `VpnService` or the Windows privileged
service remains the single system TUN and route owner. The endpoint validator
runs before device creation and rejects unsupported MTU, keys, peers,
header/junk fields, instruction chains, timing/padding bounds and integrated
TUN ownership. AWG2 rejects every AWG 3.1-only field instead of silently
upgrading a profile. On Android, the AWG endpoint requests platform protection
only for its outer socket, so `VpnService.protect(fd)` can bypass recapture
without enabling global interface auto-detection for ordinary transports. For
an inner FQDN, an explicit endpoint `domain_resolver` selects that resolver and
its strategy, allowing managed AWG to use the profile's protected DNS transport.
Without that field, the endpoint retains the profile's
`route.default_domain_resolver` and its strategy, including the existing
bootstrap behavior for DNS graphs with FakeIP. AWG peers remain IP literals;
their outer socket and bootstrap handling are unchanged, as are TLS verification
and the authenticated egress hostname.

Cross-field validation also requires disjoint H1-H4 ranges. S1/S2/S3 plus
their pinned handshake/cookie sizes, S4 plus MTU and the 32-byte transport
overhead, and junk packet size must fit 2016 bytes: the smallest message buffer
of the supported Android/Windows engines (pinned Windows `2048-32`). A smaller
upstream buffer on another build target further limits that target. Scalar
schema bounds remain necessary but do not by themselves authorize an oversized
combination. Content padding is capped to the inner MTU by the pinned engine;
these memory/wire bounds do not promise a particular network path MTU.
For AWG3.1, the latest possible send rekey precedes the earliest key rejection;
the upstream receive-refresh calculation must also remain positive using the
configured minimum keepalive/retry values. Omitted timing fields use the pinned
upstream defaults. Rejections occur before device creation with fixed messages.

The embedded AWG device logger never formats upstream arguments because they
can contain endpoint or peer material. It emits only fixed
`awg_safe_diag` classifier codes for bounded handshake send/accept/reject,
retry and transport-error categories, with at most four occurrences per code
and device lifetime. Unclassified verbose lines are dropped and unknown errors
collapse to `upstream_error`; these diagnostics locate an interoperability
failure without becoming traffic or identity evidence. When release debug
forwarding is disabled, the daemon recognizes only that closed code set and
occurrence `1..4`, reconstructs the canonical payload and drops every other
line before the Android callback.

`ray2sing` is not an AWG authority. Raw `awg://` and WireGuard-style
`[Interface]` AWG inputs fail closed instead of being rewritten as ordinary
WireGuard. Synthetic documentation-address fixtures may test the typed
endpoints; real endpoint, key and provider material must not enter source,
logs, fixtures or retained public evidence.

### Compiled transport inventory (source only)

`include.TransportCapabilities()` is the shared producer behind
`libbox.TransportCapabilities()` and optional desktop
`pokrovCoreTransportCapabilities`. It returns compact ASCII JSON at most 4096
bytes: `schema: 1`, then `features` in unique lexical order. Desktop strings are
caller-owned and released with `freeString`. The existing exact capability
descriptor and desktop ABI 2 remain unchanged; absent export means unavailable.
The API performs no setup, profile parsing, connection, probe or TUN operation.

The inventory lists compiled ingredients for the current ATS transports:
TLS, VLESS, native gRPC (full or lite) and native XHTTP are unconditional; uTLS/Reality require `with_utls`,
Hysteria2 requires `with_quic`, and the `pokrov.awg31.endpoint.v1` subset requires
`with_awg`. The complete feature IDs and meanings belong to
`config/abi-contract.json.transport_capabilities`. Disabled protocol error stubs
are not capabilities. In particular native V2Ray XHTTP is independent of the
unimplemented `xray` outbound and does not advertise xray-json ingestion.

Native XHTTP bounds connection establishment by the caller's dial context, then
keeps an established stream alive until its connection or owning client closes.
Closing the client cancels pending HTTP work and closes its TCP/UDP sockets,
including pooled connections. The transport remains reusable after this reset,
as required by VLESS interface changes. REALITY-XHTTP profiles use an explicit
`stream-one` mode, HTTP/2 ALPN and an empty VLESS flow.

With `with_utls`, the REALITY client advertises version 26.3.27 and retains
both the `X25519MLKEM768` and X25519 key shares supplied by the fingerprint.
When `tls.record_fragment` is omitted, REALITY splits the ClientHello into TLS
records to retain the hybrid Chrome workaround verified on the owned DE path.
An explicit `false` keeps one record for SNI frontends such as the RU bridge
HAProxy, whose raw ClientHello parser does not reassemble TLS records; an explicit
`true` enables splitting. Server verification remains mandatory. Other TLS
outbounds keep their configured fragmentation behavior and default to disabled.

This bounded ingredient inventory does not establish that an arbitrary profile
or combination is supported. Profile option/contract checks still apply. It is
not an artifact digest, opaque signed capability ref/revision, endpoint/access
lease, IP-family reachability, readiness or proof. The client must bind those
facts independently before selector admission. Android, desktop FFI and Windows
service consumers are implemented in source. Linux adds a root-only fixed
metadata mode plus inventory in the actual child's prepared reply. iOS reads
the loaded gomobile export in Runner for preflight and requests it from the
running packet-tunnel extension over its existing message channel. Linux also
reports `core_module_sha256` from its own `/proc/self/exe`, distinct from a
package/container checksum; the daemon preserves the preflight/child boundary.
An empty digest is unavailable and cannot admit ATS. The Windows client service
computes its loaded DLL's identity outside Core and owns the file lifetime. No host
preflight inventory substitutes for the running process's answer. Artifact
generation, Apple export retention/ownership, export/build-tag parity and device
checks remain open. NOT_VERIFIED;
no build or execution was performed during the implementation-first stage.

The desktop ABI version is `2`. `config/abi-contract.json` is the
machine-readable owner for its exported symbols and additive capability/event
descriptor. `pokrovCoreCapabilities` returns that descriptor as UTF-8 JSON.
C strings returned by the library, including the descriptor, are caller-owned
and must be released through `freeString`.

Released ABI 2 binaries that predate `pokrovCoreCapabilities` remain compatible
with the ABI 2 client binding. A present descriptor is mandatory to parse and
must match the supported descriptor and event ABI. Unknown schema/event
versions and unknown lifecycle event identifiers fail closed. ABI 3 is not
declared by this contract and cannot be enabled by an additive descriptor.

`config/observability-contracts.json` is a compatibility snapshot of the
platform-owned operational event schema and error catalog. It records only the
canonical versions and exact SHA-256 values; it is not an independent catalog.
`scripts/verify-observability-contracts.ps1` validates the local snapshot and,
when given a platform checkout, fails on cross-repository drift.

`config/core-event-abi.json` owns the additive structured Core event ABI. Its
event ABI version is `1`; it does not change desktop ABI `2`. Before a runtime
start, the host registers `pokrovCoreSetEventCallback` and supplies the current
`run_id`, `attempt_id`, and generation through `pokrovCoreSetEventContext`.
Core then emits only the closed lifecycle and egress event definitions and
error codes declared by that contract. Delivery is bounded, asynchronous, and
non-blocking. The callback arguments contain primitive safe fields only; raw
Core log lines, configuration, destinations, URLs, credentials, and upstream
error text are not part of the ABI.

The Android gomobile surface exposes the same event ABI through
`OperationalEventHandler`, `SetOperationalEventHandler`, and
`SetOperationalEventContext`. Windows uses the two C callback exports. Hosts
must reject unknown schema/event versions, names, outcomes and error codes, as
well as stale run, attempt, generation, or sequence values. Arbitrary upstream
debug lines are not release evidence and must not be promoted into the
operational event stream.

The managed `StartedService` also filters native logging before every factory
writer/observable sink and before its own replay buffer and subscribers. The
same closed policy applies in release and debug mode: bounded AWG diagnostics
and fixed selected-probe outcomes survive; arbitrary messages become
`runtime_log_redacted`, and upstream logger tags are omitted. Severity and
fatal/panic control flow remain unchanged. Other users of the embedded logger
without this platform filter retain their existing behavior. This source
boundary does not prove that a retained AAR/DLL contains the change.

The legacy logger follows the same boundary: release setup records only whether
stored settings were available and never formats the settings value or its
database table. Setup messages omit caller-provided filesystem paths and the
listen address from both stderr and the legacy observer, including with debug
disabled. The desktop FFI returns a local caller-owned error string for
ABI compatibility, but it does not mirror that raw error into the process log;
the release host maps it to a fixed public failure category.

On Windows, the current source materializes the auto-route TUN inbound with the
exact interface name `POKROV`. The privileged client service uses that stable
ownership identifier to snapshot and restore only Core-owned addresses,
routes, DNS and interface settings after stop or crash. Android and other
platforms keep their platform-owned naming behavior. Source target `1.1.0` is
`PRE_CANDIDATE_LOCAL`; published `1.0.3` artifact hashes predate this source
change and do not prove it until a new exact DLL and Android AAR are built and
retained. The retained `1.0.3`
artifacts also predate the structured event surfaces; clients may recognize
that exact legacy identity for compatibility, but release `1.2.0` requires
replacement artifacts with the structured event capability.

`StartedService.CloseService` stops the current engine instance while keeping
the command server's observers available for another start or reload.
`StartedService.Close` is terminal: it closes the instance, five background
observers and URL-test history, and rejects reuse. Desktop stop, discarded
independent/tunnel instances, failed service construction and command-server
shutdown use this terminal operation. Monitoring shutdown cancels its context
before stopping the ticker; ticker ownership is synchronized with activity
notifications so a stopped monitor cannot restart its scheduler.
URL-test history uses its existing mutex when installing, reading and clearing
the update hook, so a probe finishing during shutdown cannot race with hook
detachment. Notification happens after releasing the history lock.

The tagged lifecycle regression exercises loopback sessions through repeated
start/restart/stop, requires old sessions to close, and measures retained Go
goroutines and Linux descriptors or Windows handles. It fixes the test's Go
scheduler at two processors to exclude process-wide thread-pool growth from
the service ownership assertion. Exact artifact measurements and device VPN
checks remain separate from this source-level test.

### Apple static inventory binding (source, NOT_VERIFIED)

The pinned gomobile `bind` implementation used by `scripts/build-apple.sh`
builds c-archive libraries inside `PokrovCore.xcframework`. iOS Runner and
PacketTunnelExtension link separate copies of that code into their executable
images. The client calls the generated `LibboxTransportCapabilities` declaration
directly, retaining the getter without a dlsym visibility or manual NSString
ownership assumption. Matching headers/archive with the new getter are required
to build those host sources. The static framework must not be embedded as a
runtime dylib, and a path to it cannot identify the executing Core.

Runner's host executable path is now locator metadata only. The running tunnel
continues to supply its own inventory over the provider message. Apple image
digest production, signed/encrypted image treatment and binding preflight to
the separate extension image remain open; no Core artifact or Apple application
was built, hashed or executed for this correction.

### Android loaded-module identity (source, NOT_VERIFIED)

The Android-only mobile adapter exposes `CoreModuleSHA256()` through gomobile.
The adapter delegates to `v2/hcore/module_identity_android.go`; it accepts no
caller path, package checksum or expected digest. A C anchor in this same linked
module obtains its loader path, address and base through `dladdr`. The backing
descriptor must match the executable address's `/proc/self/maps` device/inode.
The ELF executable PT_LOAD segment must also match the mapping's file offset.
This supports extracted libraries and directly mapped uncompressed APK entries;
the latter hashes the exact ELF entry bytes, not the APK container. Duplicate
entries, unsupported packaging, missing proc/loader data and inconsistent
identity leave the result empty.

The module is bounded to 1 GiB and its backing file to 2 GiB. Maps parsing reads
at most 16 MiB with a 16 KiB line bound; hashing streams through 128 KiB. The
descriptor's size/mtime/ctime and address mapping are checked again afterward.
The result is retained once per process, matching gomobile's no-unload lifetime.
This observes the OS-owned installed image; it is not protection against a
compromised host/Core or remote attestation. No paths, addresses, file contents
or underlying error messages are returned or logged. No runtime/profile/TUN
action is performed by the getter.

The client accepts only a lowercase 64-hex result and forwards it as optional
`coreModuleSha256`. Older AARs lack the getter and remain unavailable for ATS
selection without changing ordinary Core health. Source is NOT_VERIFIED: no
hash, native invocation, generated binding, AAR build or device operation was
performed. All target ABIs, direct/split APK and extracted packaging, generated
Java method retention, linker/proc access, digest parity and replacement behavior
remain checks for the later verification stage. Executor revalidation before
profile start remains a separate unfinished integration.

### Linux expected identity at start (source, NOT_VERIFIED)

The private Linux handshake now advertises `identity_schema: 1` with the
`deadline_schema: 1`, the actual child's `core_module_sha256` and SHA-256 of the exact untransformed
staged-profile bytes. `linuxruntime.Prepare` creates a separate runtime config;
the digest identifies its input rather than that transformed JSON or a path.
linuxd compares both fields before executing its network transaction. Missing
schema, missing digest or a different pair stops the prepared child without
arming that transaction.

The dedicated `start_with_identity` command carries both expected digests and
a required deadline object (original Linux boot ref, elapsed start/end in ms).
Core compares them with the prepared pair and rereads its self-executable hash
before `hcore.Start`. It validates CLOCK_BOOTTIME before/after Start and retains
a 100 ms watcher on that runtime context after responding. Expiry, clock loss
or boot mismatch cancels the attempt; startup does not renew or promote a lease.
The 24-hour ceiling is a schema bound, not a default. It echoes the pair, both
schemas and original deadline in `started`; linuxd requires
that confirmation, otherwise its normal transaction rollback retains ownership
until restoration. Commands are bounded to 512 bytes and unknown actions or
nonempty expectations on ordinary start/stop/health are rejected. Existing
ordinary start remains available to ordinary connect; bound requests never
fall back to it. New Core and linuxd sources must be packaged together.

This binds local execution bytes and the attempt interval. Remote profile
authorization, lease/proof handoff and Dart selector executor integration remain
open. No hash, Core process, test, formatter, build or network operation was
executed for this change; existing Linux evidence does not cover these sources.

### Desktop cancellation during startup (source, NOT_VERIFIED)

`pokrovCoreStartInterruptibleV1` is an additive desktop ABI 2 export. It accepts
the ordinary profile arguments plus a C callback and opaque invocation owner.
The thin adapter delegates to `hcore.StartInterruptible`: a 25 ms observer
cancels the existing startup context when the callback returns nonzero. It
never invokes Stop concurrently with Start and joins before the ABI returns.
The callback must be nonblocking, thread-safe and cannot reenter Core. Its
owner and function pointer are not retained after return. Null callbacks cancel;
the host treats a null result as failure and frees all returned strings.

Startup observes cancellation before configuration/instance admission, during
the optional delay, between engine lifecycle stages and around TUN creation/
activation. Context-aware IO sees the same cancellation. A cancellation racing
the final successful stage leaves the instance available for serialized Stop.
Windows requires this symbol for its bound operation before network recovery
is armed; old ordinary start remains unchanged. The service retains the original
boot deadline and postresponse cleanup owner. Returning successfully does not
cancel a healthy context or promote the attempt into a lease.

This is cooperative cancellation, not forced thread termination: a synchronous
OS/driver call must return before its owner can finish restoration. No hard
real-time settlement is claimed. No tests, formatter, ABI generation, build,
native call or runtime proof was performed. Retained binaries are unchanged.

Server inbounds, panel state, provisioning, and traffic accounting remain outside POKROV Core.

Ordinary candidate selection uses an isolated raw-profile Core instance with no
inbounds, host routes, command server or persistent cache. The selected protected
outbound requires an owned HTTPS 204 with the egress marker, then reads a full
64 KiB response through the same outbound. If the API target fails, it tries the
static `pokrov.space` target within the remaining deadline. A body that stalls
after TLS returns `data_stalled`; an invalid status, marker or body length does
not prove a network failure. Node-local targets require the later 443 front.
Android supplies a captured-network socket and DNS adapter; Windows supplies
the physical interface. DNS servers and upstream
resolvers are retained; client DNS rules referencing stripped route rule sets
are omitted. Each probe has its own deadline and interruption callback.
When a selected-app profile routes ordinary traffic directly, the probe uses
the protected outbound of its process rule, or its first selector if that rule
is absent. The app's direct final route is not used as proof of the VPN path.
Cancellation closes the instance and waits
for the request and observer to return before releasing the caller-owned callback.
The existing active runtime and its TUN remain untouched by probes. The optional
desktop ABI 2 exports return a fixed failure kind and duration, with strings
released by `freeString`; profiles and transport errors never enter the result.
The candidate result retains its last fixed stage and the monotonic
`stage_started_ms` offset from probe entry. TLS stages distinguish blocking reads
and writes from processing and completion of the default CA/hostname check;
the result also measures profile parsing, Box creation and the certificate-store
part of that creation independently for each call, including constructor errors.
Zero setup milliseconds mean sub-millisecond work or a phase not entered, as
identified by the last stage. The diagnostics preserve execution, trust, curves
and probe deadlines. Cleanup preserves the last
observed stage, while `duration_ms` continues to include cleanup.
