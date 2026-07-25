# POKROV Core

POKROV Core is the network runtime used by POKROV clients. Version `1.0.1` is
the current patch release and replaces the provenance-exception build of
`1.0.0`.

The repository contains:

- the POKROV lifecycle and configuration layer;
- an embedded sing-box engine with POKROV fixes;
- Android and desktop bindings;
- WARP/WireGuard support;
- reproducible build and verification scripts.

The server remains a separate Xray-based system. This repository builds client outbounds only.

## Supported release targets

| Target | Artifact | State |
| --- | --- | --- |
| Android | `pokrov-core.aar` | active |
| Windows x64 | `pokrov-core.dll` + `libcronet.dll` | active |
| iOS/macOS | `PokrovCore.xcframework` | source ready; macOS build and device proof required |

## Requirements

- Go `1.25.12`
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

## Layout

- `platform/` — public Android and desktop adapters.
- `v2/` — POKROV configuration, lifecycle, resolver, WARP, and service code.
- `engine/sing-box/` — embedded transport engine.
- `ray2sing/` — profile-to-sing-box conversion.
- `third_party/warp-plus/` — pinned WARP helper.
- `scripts/` — deterministic builds and focused checks.
- `docs/` — architecture and release policy.

## Versioning

POKROV Core follows semantic versioning. Public ABI breaks require a major release. Engine updates and targeted fixes normally produce minor or patch releases after the Android and Windows backtests pass.

## License

POKROV Core is distributed under GPL-3.0-or-later. Embedded components retain their own copyright and license notices; see `THIRD_PARTY_NOTICES.md`.
