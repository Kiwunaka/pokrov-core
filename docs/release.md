# Release process

The embedded fork targets stable sing-box `1.14.2` while retaining POKROV
XHTTP, Smart Access, WARP, AWG and opt-in Telegram WSS transports. Runtime client
builds use `pokrov_client`: Psiphon, Tor, Mieru, DNSTT, SSH and remote server
inbounds are omitted; TUN and authenticated local SOCKS/HTTP/mixed remain.
Android host certificate roots and the public host callbacks remain supported.
POKROV catalog DNS and `bypass_if_failed` retain their failure/reselection path;
combining that path with the new DNS response/evaluate/race actions is rejected.
The WireGuard fork preserves Noise payloads and send errors; fake Noise packets
keep their full header and bypass reserved-byte rewriting. Size and idle library
RSS comparisons do not measure traffic memory or physical-device behavior.

Imported managed sing-box profiles are normalized in memory before strict
1.14 decoding. Legacy DNS servers retain resolver settings; plain direct
references use the native typed DNS direct dialer and preserve route interface
binding. Selectors and configured direct outbounds retain their detours.
Legacy DNS route targets become `hijack-dns`, and top-level Portal `_meta` is
excluded. Unsupported legacy references and per-server query overrides fail
closed. Native Xray JSON is explicitly unsupported; URI conversion errors do
not print the imported profile.

Outbound monitoring is disabled unless the sing-box profile sets
`experimental.monitoring` or a legacy Core profile explicitly sets
`enable-outbound-monitoring`. When enabled, its periodic and requested probes
use the currently selected outbound path and do not query third-party IP
information services.

Android `mobile.CoreVersion()` and desktop `pokrovCoreVersion()` return the
version compiled into the loaded library. The desktop string is released with
`freeString`; the host can show this value in diagnostics without guessing from
the client seed.

1. Update `VERSION`, `config/release.json`, and `CHANGELOG.md`.
2. Run `scripts/test.ps1`.
3. Build the changed Android and Windows libraries with the release scripts.
   Do not rebuild unchanged source solely to refresh hashes or evidence.
4. Verify Android contains `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`.
5. Verify the Windows exports and run the 100-cycle app backtest.
6. Record remaining physical-device and Apple checks without converting them into passes.
7. Commit the exact source, create an annotated `vX.Y.Z` tag, then publish artifacts from that commit.

Core `1.2.2` is a prerelease for the Android and Windows libraries; `1.1.2`
remains latest stable. Prior prerelease assets are retained.
`config/release.json` retains the immutable prior `1.0.3` evidence in a
separate `retained_public_release` block.

Compared with published `1.1.2`, the `1.2.0` Windows DLL is 46,348,800 bytes
(16.16% smaller) and the Android AAR is 91,397,063 bytes (11.42% smaller), with
all four Android ABIs and 34 required desktop exports present. The new DLL
passed 100 proxy-only start/stop cycles in the Windows VM, leaving no test
processes or listening ports. An original fixed PL profile passed HTTPS 204
and the full 64 KiB payload from RU. A REALITY bridge profile starts but still
fails during connection; bridge acceptance remains open.
One isolated Windows library-load sample measured idle process RSS of
37,339,136 bytes for `1.1.2` and 30,912,512 bytes for `1.2.0`; the incremental
RSS after loading was 20,566,016 and 14,393,344 bytes respectively. This sample opened no VPN or
network connection and does not measure traffic memory. Each final artifact
was built once; byte-for-byte reproduction was not rechecked for this release.

Core `1.2.0` is published independently of the app: the released POKROV app
`1.4.0` keeps its Core `1.1.2` pin until the app `1.5` integration. Local SDK
checks and builds cover the new source; phone, VM app integration and Apple
acceptance are separate checks and are not implied by a Core release.

Core `1.2.1` adds dormant localDPI with fresh runtime admission IDs, scoped
withdrawal and a stateless signed Android Selective catalog verifier. Native
hosts supply compiled key pins, retain the original signed bytes and perform
the fenced TLS proof before admission. Five Android methods and four additive
desktop symbols expose this API; desktop ABI 2 now has 38 required exports.
The feature stays off, app `1.4.0` retains Core `1.1.2`, and published `1.2.0`
assets are retained. App adoption and physical-device acceptance remain separate.
The final `1.2.1` libraries passed the full Core test script, focused race
checks, four-ABI/Java binding inspection and 38 desktop export checks. The
Windows VM SDK passed 100 proxy-only start/stop cycles and actual version,
nil/stopped admission controls and cleanup checks. The Portal Unicode fixture
passed the stateless verifier, and Android consumer compilation passed against
the final AAR. Foreign-UID, TLS-proof and cancellation checks on the phone
remain queued; these results do not assert localDPI device readiness.

Core `1.2.2` honors an explicit REALITY `record_fragment: false` and exposes
Android `mobile.NormalizeRuntimeConfig` for the command-server caller. The host
verifies saved signed bytes first, then normalizes only the runtime copy; an
error stops startup. The final AAR passed all four Android ABI checks, the new
Java binding check and caller compilation; the DLL passed 38 desktop export
checks. The Windows VM loaded Core `1.2.2` with ABI 2, completed 100 proxy-only
start/stop cycles with no remaining test host or listener, and confirmed an
ordinary CH candidate in 833 ms while preserving the saved profile bytes. The
phone loaded Core `1.2.2`, confirmed CH VPN egress, and passed the QS staged-byte
integrity check without Flutter. This prerelease does not
change app `1.4.0`'s Core `1.1.2` pin or latest stable; these checks do not assert
localDPI, Windows TUN or Apple acceptance.

`scripts/test.ps1` checks the desktop `//export` declarations, ABI version and
capability descriptor against `config/abi-contract.json`, runs gofmt, the root
module tests and focused engine tests (AWG, REALITY/uTLS, XHTTP, Hysteria2
reload, DNS, selector groups, daemon and libbox). It takes about 30 seconds with
a warm build cache. CI runs the same script on Linux and builds no artifacts.

Both module graphs pin Psiphon uTLS to
`v1.1.1-0.20260729134728-7a1fc711853d`, the upstream
[`release-branch.go1.26` commit](https://github.com/Psiphon-Labs/utls/commit/7a1fc711853d6dd31c10eca10bbd53bf3b082aac).
That exact module contains its own
[BSD license](https://github.com/Psiphon-Labs/utls/blob/7a1fc711853d6dd31c10eca10bbd53bf3b082aac/LICENSE).
This replaces the older fork revision that lacked a root license; it does not
apply the new branch's license retroactively to retained old artifacts.
The Psiphon adapter compiles without API changes, and the upstream certificate,
TLS profile compatibility, fragmentation-without-SNI and obfuscated-session-ticket
tests pass against local Linux fixtures. The upstream test package imports a
Unix-only IPC dependency and does not compile on Windows, although the product
adapter does. Full Core validation and newly bound product binaries/notices are
still required before release; older binaries continue to retain their original
dependency and licensing evidence.

`scripts/build-windows.ps1` inspects the completed DLL with the MinGW toolchain
and fails when any contract export is absent; `scripts/build-android.ps1` fails
when an Android ABI is missing.

Post-`1.0.3` working source requires Go `1.26.8` and the remediated dependency
floor recorded in both Go modules: gRPC `1.83.2`, CIRCL `1.6.3`,
`golang.org/x/crypto` `0.56.0`, `x/net` `0.58.0`, and `x/text` `0.41.0`.
Android source builds also pin NDK `29.0.14206865` in `config/release.json`.
The build validates that exact `source.properties` revision and selects it
through `ANDROID_NDK_HOME` before `gomobile` links the pinned Cronet archive.
The floor was selected from reachable `govulncheck` findings; lowering any of
these versions requires a new vulnerability review. It changes source/build
inputs only and does not relabel the retained `1.0.3` artifacts.

gRPC `1.83.2` closes the reachable findings
[GO-2026-6443](https://pkg.go.dev/vuln/GO-2026-6443) and
[GO-2026-6348](https://pkg.go.dev/vuln/GO-2026-6348) reported by the source CI
scan. Both module graphs use that version and its required `x/net`/RPC schema
dependencies. Existing binaries retain their original dependency identities.

The Apple build reads the required Go version from `config/release.json`, as
the Android and Windows builders do. This keeps its preflight on the same
toolchain as CI; a preflight pass alone does not prove an Apple artifact build.

The 2026-09-06 C05 review found source call paths from the runtime packages to
`golang.org/x/crypto/ssh` affected by `GO-2026-6354` and `GO-2026-6355`.
The fixed `x/crypto 0.56.0` requires Go 1.26; the working toolchain is therefore
pinned to `go1.26.8`. Windows also pins `tfo-go/v2 2.3.3`: the previous 2.3.1
failed to link against Go 1.26's `internal/poll` implementation. A separate
trial build reproduced that failure and then built successfully with 2.3.3.
The local Psiphon TLS ConnectionState mirror also follows Go 1.26's public
HelloRetryRequest field position; the structural guard stays enabled and a live
TLS 1.3 direct/HRR handshake tests both unsafe conversion and exporter closure.
Both root and embedded engine modules use this dependency floor. This source
change requires fresh platform artifact hashes, ABI/lifecycle checks and
consumer binding; earlier D05 binaries and their evidence retain their original
Go 1.25.13 identity until that work is completed. For the stripped C05 DLL/SO,
govulncheck extract returns no symbols, so binary findings use module-level
precision. A bounded source scan without call paths is not a full reachability
proof for other advisories.

The source contract declares desktop ABI `2` and Core event ABI `1` through
`config/abi-contract.json` and `config/core-event-abi.json`. A release `1.2.0`
candidate must include both callback exports in the Windows DLL and the
corresponding gomobile handler/context methods in the Android AAR. A successful
source test or development AAR build does not replace exact candidate hashes,
reproducibility, signing, client manifest synchronization, or retained build
evidence.

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
