# Architecture

POKROV Core is one client runtime with three layers:

1. `platform/` exposes the small Android and desktop interfaces consumed by the app.
2. `v2/` owns setup, configuration, lifecycle, WARP, DNS, and safe shutdown behavior.
3. `engine/sing-box/` owns transports, routing, TLS, TUN, and protocol implementations.

`ray2sing/` converts supported access links into sing-box options. `third_party/warp-plus/` supplies the pinned WARP registration and helper behavior.

The application supplies a materialized sing-box JSON profile for normal operation. Legacy builder APIs remain internal and are not the public POKROV app contract.

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

Server inbounds, panel state, provisioning, and traffic accounting remain outside POKROV Core.
