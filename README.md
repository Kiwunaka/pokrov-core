# POKROV Core

POKROV Core is the network runtime used by POKROV clients. `1.1.0` is the
unreleased local target for POKROV product `1.2.0`; no candidate has been
created. The current retained public Core release remains `1.0.3` with its
original reproducible artifact hashes.

The repository contains:

- the POKROV lifecycle and configuration layer;
- an embedded sing-box engine with POKROV fixes;
- Android and desktop bindings;
- WARP/WireGuard support;
- disabled-by-default, typed AWG2 and AWG 3.1 owner-lab endpoints behind
  separate digest-bound contracts;
- reproducible build and verification scripts.

The server remains a separate Xray-based system. This repository builds client outbounds only.

## Supported release targets

| Target | Artifact | State |
| --- | --- | --- |
| Android | `pokrov-core.aar` | active |
| Windows x64 | `pokrov-core.dll` + `libcronet.dll` | active |
| iOS/macOS | `PokrovCore.xcframework` | source-build CI; hosted result and device proof required |
| Linux | none | not shipped in POKROV 1.2.0 |

## Requirements

- Go `1.25.13`
- Git
- Android SDK and `gomobile v0.1.11` for Android
- MinGW-w64 for the Windows DLL
- Xcode and gomobile for Apple frameworks

## Build

Windows:

```powershell
.\scripts\build-windows.ps1 `
  -GoExecutable C:\path\to\go.exe `
  -CCompiler C:\path\to\x86_64-w64-mingw32-gcc.exe `
  -CronetLibrary C:\path\to\verified\libcronet.dll
```

Android:

```powershell
.\scripts\build-android.ps1 `
  -GoExecutable C:\path\to\go.exe `
  -AndroidSdk C:\path\to\Android\Sdk
```

Tests:

```powershell
.\scripts\test.ps1 -GoExecutable C:\path\to\go.exe
```

Artifacts are written under `dist/` and are not committed.

## Release CI and evidence ceiling

The release workflow runs the complete Go module tests plus focused vet, race,
reachable-vulnerability, bounded Staticcheck and parser-fuzz gates on Linux. It
also generates deterministic CycloneDX source SBOMs, then builds Android,
Windows and Apple outputs twice in separate jobs. Android verifies all four
required ABIs; Windows verifies the desktop export contract and runs the active
client's 100-cycle proxy backtest.

`scripts/new-release-artifact-evidence.ps1` rejects dirty source and differing
build trees and records source, contract, SBOM and artifact hashes. CI retains
only bounded `PRE_CANDIDATE_LOCAL` evidence JSON and source SBOMs; it does not
upload release binaries, sign, attest, tag, publish or promote them. A passing
workflow is source/build proof for that revision, not physical-device, signed
candidate, public-release or RU-origin proof. CycloneDX license detection is
advisory: unresolved license warnings must remain visible and require separate
license/notice review before release approval.

## Layout

- `platform/` — public Android and desktop adapters.
- `v2/` — POKROV configuration, lifecycle, resolver, WARP, and service code.
- `engine/sing-box/` — embedded transport engine.
- `ray2sing/` — profile-to-sing-box conversion.
- `config/awg2-capability.json`, `config/awg31-capability.json`, and
  `config/hy2-capability.json` — pinned AWG/Hysteria2 lab schemas, official
  dependencies, build tags and evidence ceilings.
- `third_party/warp-plus/` — pinned WARP helper.
- `scripts/` — deterministic builds and focused checks.
- `docs/` — architecture and release policy.

## Versioning

POKROV Core follows semantic versioning. Public ABI breaks require a major
release. Additive runtime capabilities produce a minor release; targeted fixes
produce a patch release after the Android and Windows backtests pass. Core
`1.1.0` is a separate component version from product `1.2.0`.

## License

POKROV Core is distributed under GPL-3.0-or-later. Embedded components retain their own copyright and license notices; see `THIRD_PARTY_NOTICES.md`.
