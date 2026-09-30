# Changelog

## 1.2.1 — 2026-09-30 (prerelease)

- Add a dormant localDPI outbound with fresh runtime admission IDs and scoped
  publication/withdrawal; never replay a stream after application bytes.
- Verify signed Android Selective catalog scope with native pinned keys and
  Core Ed25519; ordinary VPN intents grant no localDPI authority.
- Expose admission API version 1 to Android and desktop hosts. Native proof,
  device acceptance and app adoption remain separate; the feature stays off.

## 1.2.0 — 2026-09-30 (prerelease)

- Move the embedded runtime to sing-box `1.14.2` and keep POKROV transports,
  DNS fallback, TLS fragmentation and platform callbacks.
- Exclude Psiphon, Tor, Mieru, DNSTT, SSH and remote server inbounds from client
  builds; require credentials for local SOCKS, HTTP and mixed proxies.
- Expose selector switching and network reset without replacing the runtime;
  close retired XHTTP clients and keep xmux connection limits stable.
- Preserve issued managed profiles through strict legacy DNS migration, retain
  full-config options, and omit profiles from URI conversion errors.
- Keep the app `1.4.0` on Core `1.1.2`; app adoption belongs to `1.5`.

## 1.1.2 — 2026-09-29

- Candidate verification now requires a marked HTTPS 204 and a full 64 KiB
  transfer through the selected outbound, with a static reserve target within
  the existing probe deadline.
- Reports a response body that stalls after TLS as `data_stalled`; malformed or
  short responses do not count as network failures.

## 1.1.1 — 2026-09-29

- Matched Windows process names without case sensitivity and made selected-app
  candidate probes verify the protected route.
- Built Android Core with compiler optimizations enabled.
- Disabled outbound monitoring by default; explicit monitoring probes only the
  selected path and no longer queries third-party IP information services.
- Exposed the loaded Core version through Android and desktop host bindings.

## 1.1.0 — unreleased (`PRE_CANDIDATE_LOCAL`)

- Added the backward-compatible structured operational-event ABI to desktop
  and Android hosts, with typed lifecycle events and fail-closed negotiation.
- Added the stable Windows `POKROV` TUN ownership name required by service
  crash/reboot recovery.
- Raised the pinned Go/dependency floor after reachable-vulnerability review.
- Added the pinned `pokrov.awg2.endpoint.v1` capability contract, schema,
  synthetic fixture, dependency/license gate and focused typed-endpoint tests.
- Added a separate disabled `pokrov.awg31.endpoint.v1` lab contract backed by
  official `amneziawg-go/v3 v3.1.20260814`, including header protection,
  content padding, bounded timing ranges, random trailers and bounded I1-I5
  signature packets without custom POKROV cryptography.
- Added a separate disabled `pokrov.hy2.outbound.v1` managed Hysteria2 lab
  contract and blocked raw Hysteria2 URI conversion.
- Made the AWG endpoint fail closed before device creation and fixed bind
  context plus partial-start cleanup while keeping the host as the sole TUN
  owner. Endpoint readiness now follows successful native Device startup, and
  contract-owned junk/padding maxima are enforced before `IpcSet`.
- Disabled raw AWG legacy conversion so AWG material cannot silently become
  vanilla WireGuard.
- Kept AWG2 non-advertised and disabled by default pending exact Android,
  Windows, physical-device and RU-origin evidence.
- Expanded release CI to full-module tests, focused vet/race/vulnerability and
  bounded Staticcheck gates, parser fuzzing and deterministic CycloneDX source
  SBOM generation.
- Added clean-source two-build comparison and bounded provenance for Android,
  Windows and Apple outputs, including Android ABI checks, Windows export
  validation and the active client's 100-cycle proxy backtest.
- Kept Linux explicitly outside the POKROV 1.2.0 shipped artifact matrix and
  kept CI evidence separate from signing, candidate creation and publication.
- This section names source intent only. No `1.1.0` artifact, tag or candidate
  exists until the exact release gates complete.

## 1.0.3 — 2026-08-13

- Fixed WARP endpoint initialization so registration failures are reported,
  startup is bounded, and concurrent readiness checks cannot deadlock startup.
- Added the Cloudflare client headers required by the current registration API
  and validated malformed registration responses.
- Made selected endpoint and selected outbound latency probes bounded and
  observable without blocking the client command channel.
- Routed Android socket-protection and probe diagnostics back to the client.

## 1.0.2 — 2026-08-04

- Replaced the inherited public URL-test default with the owned authenticated
  POKROV egress marker.
- Preserved explicit caller-provided URL-test targets and desktop ABI 2.
- Added focused regression coverage for both default and explicit targets.

## 1.0.1 — 2026-07-25

- Rebuilt the Android AAR and Windows DLL as clean patch-release artifacts.
- Disabled incidental Go VCS stamping so release builds remain reproducible
  before and after recording their hashes.
- Retained desktop ABI 2, Android package identity, embedded engine versions,
  and the pinned `libcronet.dll` dependency.

## 1.0.0 — 2026-07-23

- Established the independent POKROV Core release line.
- Added the POKROV desktop ABI and Android package.
- Included the cached-connection allocator race fix.
- Included safe WARP/WireGuard shutdown ordering.
- Enabled native TLS record fragmentation for standard TLS, uTLS, and Reality.
- Preserved encrypted Android DNS bootstrap behavior.
- Backtested Windows through 100 runtime start/stop cycles.
