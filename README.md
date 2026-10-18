# POKROV Core

POKROV Core is the network runtime used by POKROV clients. Source/build version
is defined by [VERSION](VERSION) and [config/release.json](config/release.json);
the client selects binaries through its [default runtime manifest](../POKROV-app/config/runtime-artifacts.seed.json)
or an explicit build override. A source fix does not
update those binaries or publish a release. Current app readiness and accepted
runtime versions are maintained in POKROV-app's [cutover readiness](../POKROV-app/docs/operations/cutover-readiness.md).
Start with the [layout](#layout), [architecture](docs/architecture.md), and
[release/build contract](docs/release.md). The owner's [current queue](C:/Users/kiwun/Downloads/POKROV_KNOWN_PROBLEMS_2026-10-13.md)
and [execution plan, section 0](C:/Users/kiwun/Downloads/POKROV_EXECUTION_PLAN_2026-09-24.md)
set the active work; dated receipts below are history.

The repository contains:

- the POKROV lifecycle and configuration layer;
- an embedded sing-box engine with POKROV fixes;
- Android and desktop bindings;
- WARP/WireGuard support;
- disabled-by-default, typed AWG2 and AWG 3.1 owner-lab endpoints behind
  separate digest-bound contracts;
- build and test scripts.

POKROV-node owns server provisioning and operation. Its opt-in use of the
embedded engine's server features is separate from the client release builds.

`SelectOutbound` selects a candidate already present in the running selector;
`ResetNetwork` resets network sessions and DNS while preserving the runtime and
selected candidate. Set `interrupt_exist_connections=true` to close old TCP/UDP
sessions when switching. Android exposes both calls through `mobile`; desktop
ABI 2 adds optional `pokrovCoreSelectOutboundV1` and `pokrovCoreResetNetworkV1`
exports whose returned strings must be released with `freeString`.

Client profiles no longer create a mixed proxy by default. SOCKS, HTTP and
mixed inbounds require nonempty usernames and passwords on every interface,
including loopback. Empty XHTTP xmux uses the Xray 26.7.28 client defaults with
three pooled clients and finite reuse; retired clients preserve active streams
and close after their last user. This does not change the bridge Xray pin.

## Supported release targets

| Target | Artifact | State |
| --- | --- | --- |
| Android | `pokrov-core.aar` | active |
| Windows x64 | `pokrov-core.dll` + `libcronet.dll` | active |
| iOS/macOS | `PokrovCore.xcframework` | local macOS build script; artifact and device acceptance remain separate |
| Linux | none | private daemon/probe adapters; no public release artifact |

The [private Linux daemon adapter](platform/linux/README.md) now provides the
conditional beta's internal Core lifecycle. Its isolated-VM evidence does not
change the public release targets above.

## Requirements

- Go `1.26.8`
- Git
- Android SDK, NDK `29.0.14206865`, JDK, and pinned `gomobile v0.1.12` for Android
- MinGW-w64 for the Windows DLL
- Xcode, Python 3, and pinned gomobile for Apple frameworks

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

The script verifies cached gomobile and gobind module/toolchain identities with
`go version -m` and installs the pinned versions when they differ. Default output
contains all four Android ABIs; `-Arm64Only` is for explicit private candidates.
Use `-OutputDirectory` to keep a private AAR outside the checkout. On macOS,
`bash scripts/build-apple.sh` builds the XCFramework with the pinned tools;
this command is not exercised by Linux CI.

Tests:

```powershell
.\scripts\test.ps1 -GoExecutable C:\path\to\go.exe
```

Artifacts are written under `dist/` and are not committed.

## CI

CI runs `scripts/test.ps1` on Linux. It does not build, sign or publish
libraries; release builds are made locally with the scripts above.

## Layout

| Area | Owning code |
| --- | --- |
| Android bindings and runtime normalization | `platform/mobile/` |
| Desktop C ABI and caller-owned strings | `platform/desktop/`; `config/abi-contract.json` |
| Private Linux daemon and fixed probe | `platform/linux/`, `platform/probecli/`; [Linux contract](platform/linux/README.md) |
| Profile parsing, DNS, inbound validation and WARP configuration | `v2/config/` |
| Lifecycle, selection, network reset and candidate probes | `v2/hcore/` |
| Embedded routing, DNS, transports and CommandServer | `engine/sing-box/`; its `go.mod` is a separate module |
| Local transport dependency patches | `engine/sing-box/replace/`; replacements must agree in both module graphs |
| Closed runtime event fields | `internal/observability/`; `config/core-event-abi.json` |

- `ray2sing/` — profile-to-sing-box conversion.
- `config/awg2-capability.json`, `config/awg31-capability.json`, and
  `config/hy2-capability.json` — AWG/Hysteria2 capability schemas read by the
  portal.
- `third_party/warp-plus/` — pinned WARP helper.
- `scripts/` — builds and tests.
- `docs/architecture.md` — source contracts and focused subsystem references.
- `docs/release.md` — build pins, artifact acceptance and historical receipts.
- `docs/reference-review.md` — importing a focused upstream fix.

## Versioning

POKROV Core follows semantic versioning. Public ABI breaks require a major
release. Additive runtime capabilities produce a minor release; targeted fixes
produce a patch release after the affected platform backtests pass. Core and
POKROV app versions are separate. A private build may retain the current Core
version while its caller-supplied manifest records the exact source revision.

## License

POKROV Core is distributed under GPL-3.0-or-later. Embedded components retain their own copyright and license notices; see `THIRD_PARTY_NOTICES.md`.
