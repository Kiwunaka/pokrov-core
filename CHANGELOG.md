# Changelog

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
