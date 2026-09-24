# Private Linux daemon adapter

This executable is an internal child of POKROV-app's `pokrov-linuxd` service.
It is not a public Linux release artifact or a replacement for the desktop ABI.
The supported development host is Ubuntu 24.04 amd64 with systemd,
NetworkManager, systemd-resolved and nftables.

The normal runtime mode accepts no arguments. It runs as root, reads only the root-owned
mode-0600 `/var/lib/pokrov/profiles/active-profile.json`, and uses
`/var/lib/pokrov/core` for private runtime state. The parent supplies stdin
commands and a separate inherited FD 3 pipe for bounded replies; raw Core
stdout/stderr and configuration never enter that protocol.

`pokrov-linux-core-v1` has the following lifecycle:

1. Validate and normalize the materialized profile and parse the engine schema. Reply
   `prepared` with the plan (`tunnel_interface`, `routing_mark`, `dns_servers`)
   and optional `transport_capabilities_json` from that exact Core process.
2. After the parent installs its traffic filter, accept `start`, invoke the
   existing hcore lifecycle, verify `pokrov0` exists, then reply `started`.
3. After the parent finishes the network transaction, accept `health`. Resolve
   `api.pokrov.space` through the system resolver (five-second bound), then
   validate HTTPS through the captured default proxy leaf (ten-second bound).
   Require the owned endpoint's 204 response and
   `X-Pokrov-Egress-Probe: pokrov-authenticated-egress-v1`, normal certificate
   verification, no redirects and an unchanged selected leaf. Direct, block and
   DNS outbounds cannot supply VPN proof. Reply with only `dns_ready` and
   `core_egress_validated` booleans; do not export destinations or raw errors.
4. On `stop`, SIGTERM or parent cancellation, invoke hcore.Stop and acknowledge
   `stopped`. A process exit without this acknowledgement is not cleanup proof.

The child exclusively chooses TUN `pokrov0`, mark `0x504b` and the system stack.
Its private Linux context enables sing-tun external configuration: a bounded
callback assigns only the fixed IPv4/IPv6 addresses before the stack binds its
listeners. Those addresses disappear with the nonpersistent TUN. Core installs
and removes no policy rules or routes, including the IPv6 rule that sing-tun
otherwise installs even with `auto_route=false`. The context switch is not a
profile JSON option and is not enabled by Android/Windows entrypoints.

linuxd owns route table/priority 20555, route protocol 243, metric 42700,
nftables and the per-link resolved/NM transaction. It rejects occupied route
ownership before starting Core and journals exact cleanup objects; no
priority-range deletion is used. Core does not install an auto-redirect
firewall. Port 53 is hijacked into the profile's DNS policy before other rules.
There is no plaintext DNS fallback added by this adapter.

The profile boundary accepts one fixed-address TUN and optional loopback mixed
inbounds. It rejects paths, namespaces, interface/mark overrides and auxiliary
services, while retaining supported proxy and DNS transport options. AWG
endpoint configuration is outside this Linux boundary. The profile compiler
does not turn the adapter into an arbitrary root command or file API.

Source now also accepts the single fixed `--transport-capabilities` argument.
This root-only mode emits a compact object with `schema: 1`,
`transport_capabilities_json` (the libbox inventory string), and
`core_module_sha256`, in that order and followed by one newline on stdout. It
exits before profile/state/control-pipe handling. The digest is SHA-256 of the
kernel's `/proc/self/exe` file, streamed in 128 KiB chunks with a 1 GiB file bound,
size/mtime consistency and cancellation checks; unavailable identity is empty.
The actual tunnel child's `prepared` reply also carries its own executable
digest. Renaming/replacing the installation pathname does not make a running
child report the replacement's hash. No package/archive hash is substituted.
It does not prepare/start a tunnel or probe a destination. linuxd invokes it
only for preflight metadata under a three-second deadline and bounded output;
the running child supplies its own inventory in the `prepared` reply instead.
The inventory describes engine ingredients, not this adapter's profile allowlist:
for example a compiled AWG ingredient does not remove the endpoint prohibition
above. New Core and linuxd must ship together because retained daemon readers
reject unknown child reply fields. No artifact/build/runtime evidence is added;
metadata/child wire and timeout checks remain NOT_VERIFIED.

The private handshake also supports identity-bound start. `prepared` includes
`identity_schema: 1`, `deadline_schema: 1` and `profile_sha256` over the untransformed bytes read from
the fixed staged file. linuxd checks the candidate's module/profile pair before
its network transaction. `start_with_identity` carries both expectations; Core
compares them and rereads its own module hash before starting. The `started`
reply confirms the same schema/pair. Missing/mismatched confirmation takes the
existing daemon rollback path. Ordinary start never absorbs a bound request.
The command also requires the original boot/start/end deadline. Core validates
CLOCK_BOOTTIME before/after start, confirms the tuple and keeps a 100 ms clock
watcher after responding. Expiry/clock loss closes the attempt; startup does not
promote a lease. No wakeup or hard real-time shutdown is claimed. The command
line limit is 512 bytes. Policy/lease/proof and selector executor integration
remain open; this source has no new runtime evidence.

For a development build, use the root module's Go toolchain and existing tags:

```sh
CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -tags with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_grpc,with_awg,tfogo_checklinkname0 \
  -ldflags '-w -s -checklinkname=0' -o pokrov-core ./platform/linux
go test ./v2/linuxruntime
```

This source has bounded isolated-VM lifecycle evidence in the client repository,
`docs/operations/evidence/2026-09-11-r12-l02-linux-runtime/`. It does not provide
signed packaging or desktop-session acceptance. The daemon's durable recovery
is a client L03 responsibility; exact host evidence remains separate from this
adapter's build. Android/Windows artifact bindings and
public release scope are unchanged by this private adapter.
