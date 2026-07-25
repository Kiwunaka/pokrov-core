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

Release `1.0.1` disables incidental Go VCS stamping in Android and Windows
artifacts. Source identity is the annotated release tag and its GitHub release
commit. This lets the final evidence-only commit retain exact artifact hashes
without changing those artifacts on the required second build.

The two pre-tag `1.0.1` builds matched byte-for-byte:

- Android AAR: `106831626` bytes,
  SHA-256 `25b96622f9ef6e648e1167847ef4205c63bad88c7c897e862bf36249830114e3`;
- Windows DLL: `55117824` bytes,
  SHA-256 `8f4aa233054b78ac2e6dbcef7634b6f4829a9f27f4cd65674de80f6f3b299f9e`;
- Windows `libcronet.dll`: `8596992` bytes,
  SHA-256 `8ef1f8bbde77f954af1ae47bee1819ac8dc2354bb0e1d4baba3dad9e58d7a6f7`.
