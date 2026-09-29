# POKROV Windows adapter cleanup

Base: `github.com/sagernet/sing-tun v0.9.6-0.20260924001923-ddaa4ca25e3b`,
the dependency required by sing-box 1.14.2. The source API and module dependencies
are updated; existing license notices and bundled Wintun binaries are retained.
The local changes preserve Windows adapter ownership and correct a DNS error:

- `internal/wintun/wintun_windows.go`: upstream now passes the owned adapter
  handle directly to `SyscallN`; the POKROV finalizer regression test is retained.
- `tun_windows.go`: retain create-only ownership and close the newly created
  adapter immediately when `StartSession` fails. An adapter with the same name
  is never reopened after creation fails. Strict-route WFP filters are retained;
  DNS blocking follows the upstream `DNSMode` contract.
- `tun.go`: IPv4 `/32` without a DNS server returns a configuration error instead
  of indexing a missing IPv6 prefix when formatting that error.

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
