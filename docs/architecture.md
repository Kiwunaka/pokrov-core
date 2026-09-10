# Architecture

POKROV Core is one client runtime with three layers:

1. `platform/` exposes the small Android and desktop interfaces consumed by the app.
2. `v2/` owns setup, configuration, lifecycle, WARP, DNS, and safe shutdown behavior.
3. `engine/sing-box/` owns transports, routing, TLS, TUN, and protocol implementations.

URL probes retain a typed connect/TLS/response stage. Cancellation after dial
returns an error, and the optional second request retains the original context.
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

Android and Windows release builds include the `with_awg` tag, but the public
ABI does not advertise either AWG lab. A host may accept an `awg` endpoint only
from the digest-bound managed owner-lab path and only with
`useIntegratedTun=false`; Android `VpnService` or the Windows privileged
service remains the single system TUN and route owner. The endpoint validator
runs before device creation and rejects unsupported MTU, keys, peers,
header/junk fields, instruction chains, timing/padding bounds and integrated
TUN ownership. AWG2 rejects every AWG 3.1-only field instead of silently
upgrading a profile. On Android, the AWG endpoint requests platform protection
only for its outer socket, so `VpnService.protect(fd)` can bypass recapture
without enabling global interface auto-detection for ordinary transports. For
an inner FQDN, the endpoint also honors the profile's
`route.default_domain_resolver` and its strategy instead of silently falling
back to the DNS graph's final transport. This keeps Android endpoint probes and
ordinary dialers on the same explicit bootstrap-resolution contract without
changing TLS verification or replacing the authenticated egress hostname with
a pinned provider address.

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
database table. The desktop FFI returns a local caller-owned error string for
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

The tagged lifecycle regression exercises loopback sessions through repeated
start/restart/stop, requires old sessions to close, and measures retained Go
goroutines and Linux descriptors or Windows handles. It fixes the test's Go
scheduler at two processors to exclude process-wide thread-pool growth from
the service ownership assertion. Exact artifact measurements and device VPN
checks remain separate from this source-level test.

Server inbounds, panel state, provisioning, and traffic accounting remain outside POKROV Core.
