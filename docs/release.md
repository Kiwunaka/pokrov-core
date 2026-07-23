# Release process

1. Update `VERSION`, `config/release.json`, and `CHANGELOG.md`.
2. Run `scripts/test.ps1`.
3. Build Android and Windows twice and compare SHA-256 hashes.
4. Verify Android contains `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`.
5. Verify the Windows exports and run the 100-cycle app backtest.
6. Record remaining physical-device and Apple checks without converting them into passes.
7. Commit the exact source, create an annotated `vX.Y.Z` tag, then publish artifacts from that commit.

Release `1.0.0` has reproducible local Android and Windows builds. Their exact sizes and SHA-256 values are retained in `config/release.json`. Host integration and the Windows 100-cycle test must use those exact artifacts; Apple remains `MANUAL_OWNER_TEST`.

The Windows build accepts `libcronet.dll` only when its size and SHA-256 match
`config/release.json`. Pass it through `-CronetLibrary` on a clean checkout.
The build does not fetch a mutable or unavailable revision implicitly.
