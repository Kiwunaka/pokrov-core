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

Release `1.0.2` keeps the same toolchain, embedded engine, Android package,
desktop ABI, and pinned Cronet dependency while changing only the default
URL-test target. Explicit caller targets remain unchanged.

The two pre-tag `1.0.2` builds matched byte-for-byte:

- Android AAR: `106832036` bytes,
  SHA-256 `e98861ec0b658304515c04af6ab98a60f3664f8b5eb7660b57e6f0baa0df385f`;
- Windows DLL: `55122944` bytes,
  SHA-256 `b6d4e28b5fb9d475acc623fed84d2009137a55972a841216a81ae6ac45f98305`;
- Windows `libcronet.dll`: `8596992` bytes,
  SHA-256 `8ef1f8bbde77f954af1ae47bee1819ac8dc2354bb0e1d4baba3dad9e58d7a6f7`.

Release `1.0.3` keeps the public ABI and embedded engine versions while fixing
WARP initialization, Cloudflare registration compatibility, and bounded
selected-endpoint diagnostics.

The two pre-tag `1.0.3` builds matched byte-for-byte:

- Android AAR: `106861671` bytes,
  SHA-256 `6e6f3b688fe415c9392e19aa4f8660885316897cfc369cf8c3ff3d01100ee14f`;
- Windows DLL: `55134208` bytes,
  SHA-256 `7cc83854fc4022b759e9de3d0942b90a24c859cfd51e3231d04e7c7a6b7d5054`;
- Windows `libcronet.dll`: `8596992` bytes,
  SHA-256 `8ef1f8bbde77f954af1ae47bee1819ac8dc2354bb0e1d4baba3dad9e58d7a6f7`.
