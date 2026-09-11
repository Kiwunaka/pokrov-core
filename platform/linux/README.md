# Private Linux daemon adapter

This executable is an internal child of POKROV-app's `pokrov-linuxd` service.
It is not a public Linux release artifact or a replacement for the desktop ABI.
The supported development host is Ubuntu 24.04 amd64 with systemd,
NetworkManager, systemd-resolved and nftables.

The adapter accepts no arguments. It runs as root, reads only the root-owned
mode-0600 `/var/lib/pokrov/profiles/active-profile.json`, and uses
`/var/lib/pokrov/core` for private runtime state. The parent supplies stdin
commands and a separate inherited FD 3 pipe for bounded replies; raw Core
stdout/stderr and configuration never enter that protocol.

`pokrov-linux-core-v1` has the following lifecycle:

1. Validate and normalize the materialized profile, reject occupied route table
   20555 or rule priorities 20555–20565, and parse the engine schema. Reply
   `prepared` with only `tunnel_interface`, `routing_mark` and `dns_servers`.
2. After the parent installs its traffic filter, accept `start`, invoke the
   existing hcore lifecycle, verify `pokrov0` exists, then reply `started`.
3. On `stop`, SIGTERM or parent cancellation, invoke hcore.Stop and acknowledge
   `stopped`. A process exit without this acknowledgement is not cleanup proof.

The child exclusively chooses TUN `pokrov0`, mark `0x504b`, table/rule index
20555, system stack and strict automatic routes. sing-tun's priority-range
cleanup makes conflict rejection necessary before startup. linuxd owns nftables
and the per-link resolved/NM transaction; Core does not install an auto-redirect
firewall. Port 53 is hijacked into the profile's DNS policy before other rules.
There is no plaintext DNS fallback added by this adapter.

The profile boundary accepts one fixed-address TUN and optional loopback mixed
inbounds. It rejects paths, namespaces, interface/mark overrides and auxiliary
services, while retaining supported proxy and DNS transport options. AWG
endpoint configuration is outside this Linux boundary. The profile compiler
does not turn the adapter into an arbitrary root command or file API.

For a development build, use the root module's Go toolchain and existing tags:

```sh
CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -tags with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_grpc,with_awg,tfogo_checklinkname0 \
  -ldflags '-w -s -checklinkname=0' -o pokrov-core ./platform/linux
go test ./v2/linuxruntime
```

This source has bounded isolated-VM lifecycle evidence in the client repository,
`docs/operations/evidence/2026-09-11-r12-l02-linux-runtime/`. It does not provide
durable crash/suspend recovery, signed packaging or desktop-session acceptance;
those remain client L03/L04 requirements. Android/Windows artifact bindings and
public release scope are unchanged by this private adapter.
