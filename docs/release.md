# Release process

1. Update `VERSION`, `config/release.json`, and `CHANGELOG.md`.
2. Run `scripts/test.ps1`.
3. Build Android and Windows twice and compare SHA-256 hashes.
4. Verify Android contains `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`.
5. Verify the Windows exports and run the 100-cycle app backtest.
6. Record remaining physical-device and Apple checks without converting them into passes.
7. Commit the exact source, create an annotated `vX.Y.Z` tag, then publish artifacts from that commit.

The current source target is Core `1.1.0` in `PRE_CANDIDATE_LOCAL` state for
POKROV product `1.2.0`. This component-version decision does not create a tag,
artifact or candidate. `config/release.json` retains the immutable public
`1.0.3` evidence in a separate `retained_public_release` block until exact
`1.1.0` artifacts are built twice and accepted by the client manifest.

`scripts/test.ps1` also checks `config/abi-contract.json` against
`config/release.json`, every desktop `//export` declaration and the exact
capability descriptor embedded in the library. Adding, removing or renaming an
export or event identifier requires an explicit compatibility decision; it
cannot be hidden in an artifact rebuild.

The same gate verifies `config/awg2-capability.json`, its schema, the exact
`amneziawg-go v0.2.16` module sum and MIT notice, both release build tags, the
typed endpoint tests and the fail-closed legacy-converter tests. Passing these
checks proves source and build-command consistency only. AWG2 remains
`prototype_disabled_by_default`; exact AAR/DLL network interop, physical-device
behavior, battery/thermal measurements and RU-origin results require retained
evidence for the exact candidate and cannot be inferred from this gate.

Core CI runs the complete root-module test graph, focused `go vet`, race and
pinned `govulncheck v1.7.0` reachable-code scans for supported runtime packages
and the Android event bridge. Pinned Staticcheck `v0.7.0` runs the `SA2*`,
`SA5*` and `SA6*` correctness/security families over the release-owned package
surface. This bounded set is deliberate: wider inherited style, deprecation and
dead-code cleanup is not a 1.2.0 release gate. The config/profile parser also
runs a 30-second no-panic fuzz target.

The same workflow generates deterministic CycloneDX `v1.10.0` source SBOMs for
the root and embedded sing-box modules. Automatic license detection may emit
warnings for local forks, the Go standard library or dependencies whose module
metadata does not expose a license. A successful SBOM command proves inventory
generation, not complete legal clearance; warnings and the maintained notices
remain inputs to the separate release license review.

Three platform jobs build from a clean revision twice and require byte-identical
file trees before writing bounded provenance:

- Ubuntu builds the Android AAR and verifies `armeabi-v7a`, `arm64-v8a`, `x86`
  and `x86_64`;
- Windows uses pinned MinGW-w64, verifies every desktop export and runs the
  active client's current-source 100-cycle proxy backtest;
- macOS builds and compares the Apple XCFramework as source-build evidence.

`scripts/new-release-artifact-evidence.ps1` records source, release-contract,
SBOM and artifact hashes and rejects dirty source or mismatched build trees.
The jobs upload only SBOM/evidence JSON with `PRE_CANDIDATE_LOCAL` and
`candidate_proven=false`; they do not publish binaries, sign, attest, tag or
promote a release. Hosted workflow results, exact-candidate reproduction,
physical-device proof and public/RU-origin evidence remain separate gates.

`scripts/build-windows.ps1` inspects the completed DLL with the MinGW toolchain
and fails when any contract export is absent. These gates do not claim signing
or candidate evidence until the exact candidate artifact is actually executed
and retained.

Post-`1.0.3` working source requires Go `1.25.13` and the remediated dependency
floor recorded in both Go modules: gRPC `1.82.1`, CIRCL `1.6.3`,
`golang.org/x/crypto` `0.53.0`, `x/net` `0.56.0`, and `x/text` `0.39.0`.
The floor was selected from reachable `govulncheck` findings; lowering any of
these versions requires a new vulnerability review. It changes source/build
inputs only and does not relabel the retained `1.0.3` artifacts.

The source contract declares desktop ABI `2` and Core event ABI `1` through
`config/abi-contract.json` and `config/core-event-abi.json`. A release `1.2.0`
candidate must include both callback exports in the Windows DLL and the
corresponding gomobile handler/context methods in the Android AAR. A successful
source test or development AAR build does not replace exact candidate hashes,
reproducibility, signing, client manifest synchronization, or retained build
evidence.

Every Core pull request and push to `main` also runs the cross-repository
release contract against the active client `main` and platform `master`. That
job must fail when client/Core identity or the strict release-handoff v2
contract diverges. It creates no candidate artifact and does not replace the
reproducible-build, signing, device, tag, or publish steps above.

Release `1.0.0` has reproducible local Android and Windows builds. Their exact sizes and SHA-256 values are retained in `config/release.json`. Host integration and the Windows 100-cycle test must use those exact artifacts; Apple remains `MANUAL_OWNER_TEST`.

The Windows build accepts `libcronet.dll` only when its size and SHA-256 match
the retained public release dependency in `config/release.json`. Pass it
through `-CronetLibrary` on a clean checkout.
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

Post-`1.0.3` working source assigns the Windows TUN interface the stable name
`POKROV` for the client service recovery contract. This is not part of the
retained `1.0.3` DLL above. It requires a new reproducible build, ABI contract
verification, exact hashes and client sync before it can become release truth.
