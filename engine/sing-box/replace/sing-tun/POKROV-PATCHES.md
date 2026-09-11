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

The three `pokrov_*` fixture files require `pokrov_wintun_test` and Windows.
They replace Wintun calls with synthetic callbacks, never load the DLL or
change networking, and prove the original failures and corrected ownership.
From the Core root on Windows:

```powershell
go test -count=1 -tags pokrov_wintun_test -run '^TestPokrov(FinalizerPassesAdapterHandle|FailedSessionClosesAdapterImmediately)$' github.com/sagernet/sing-tun/internal/wintun github.com/sagernet/sing-tun
```

This is a POKROV-local patch; no upstream contribution has been submitted.
