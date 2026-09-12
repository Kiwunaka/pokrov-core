# POKROV Windows adapter cleanup

Base: `github.com/sagernet/sing-tun v0.8.0-beta.17`, upstream commit
`635920688d0a7aa2171afa56be2a0760a69fecb9`. The module contents and license
notices are retained. Only two upstream source files change:

- `internal/wintun/wintun_windows.go`: pass the adapter handle directly to
  `SyscallN`; the old argument count was being passed as the handle. The same
  correction appears in upstream commit
  `46aa536b378d6ce2d64f1d2ab6e0a1b25ebd2300`. Its unrelated changes are omitted.
- `tun_windows.go`: close the newly created adapter immediately when
  `StartSession` fails, matching the existing configuration-failure cleanup.

The four supplied `internal/wintun/*/wintun.dll` files remain byte-identical
to the official Wintun 0.14.1 archive (SHA-256
`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`).
These prebuilt files have separate [binary terms](LICENSE-WINTUN-BINARIES.txt),
retained verbatim from `wintun/LICENSE.txt` in that archive. The Core and module
source licenses do not replace those terms. This record establishes provenance,
not a complete license-compatibility assessment.

The three `pokrov_*` fixture files require `pokrov_wintun_test` and Windows.
They replace Wintun calls with synthetic callbacks, never load the DLL or
change networking, and prove the original failures and corrected ownership.
From the Core root on Windows:

```powershell
go test -count=1 -tags pokrov_wintun_test -run '^TestPokrov(FinalizerPassesAdapterHandle|FailedSessionClosesAdapterImmediately)$' github.com/sagernet/sing-tun/internal/wintun github.com/sagernet/sing-tun
```

This is a POKROV-local patch; no upstream contribution has been submitted.
