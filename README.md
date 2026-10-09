# POKROV Core

POKROV Core is the network runtime used by POKROV clients. The current Core
prerelease is `1.2.2`; latest stable remains `1.1.2`. The app `1.4.0` keeps
Core `1.1.2` until app `1.5`.
`config/release.json` retains the original `1.0.3` build
evidence separately.

The repository contains:

- the POKROV lifecycle and configuration layer;
- an embedded sing-box engine with POKROV fixes;
- Android and desktop bindings;
- WARP/WireGuard support;
- disabled-by-default, typed AWG2 and AWG 3.1 owner-lab endpoints behind
  separate digest-bound contracts;
- build and test scripts.

The server remains a separate Xray-based system. This repository builds client outbounds only.

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
| iOS/macOS | `PokrovCore.xcframework` | source-build CI; hosted result and device proof required |
| Linux | none | not shipped in POKROV 1.2.0 |

The [private Linux daemon adapter](platform/linux/README.md) now provides the
conditional beta's internal Core lifecycle. Its isolated-VM evidence does not
change the public release targets above.

## Requirements

- Go `1.26.8`
- Git
- Android SDK and `gomobile v0.1.12` for Android
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

## CI

CI runs `scripts/test.ps1` on Linux. It does not build, sign or publish
libraries; release builds are made locally with the scripts above.

## Layout

- `platform/` — public Android and desktop adapters.
- `v2/` — POKROV configuration, lifecycle, resolver, WARP, and service code.
- `engine/sing-box/` — embedded transport engine.
- `ray2sing/` — profile-to-sing-box conversion.
- `config/awg2-capability.json`, `config/awg31-capability.json`, and
  `config/hy2-capability.json` — AWG/Hysteria2 capability schemas read by the
  portal.
- `third_party/warp-plus/` — pinned WARP helper.
- `scripts/` — builds and tests.
- `docs/` — architecture and release policy.

## Versioning

POKROV Core follows semantic versioning. Public ABI breaks require a major
release. Additive runtime capabilities produce a minor release; targeted fixes
produce a patch release after the Android and Windows backtests pass. Core
`1.2.2` is a separate component version from the POKROV app release.

## License

POKROV Core is distributed under GPL-3.0-or-later. Embedded components retain their own copyright and license notices; see `THIRD_PARTY_NOTICES.md`.
