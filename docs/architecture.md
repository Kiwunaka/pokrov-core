# Architecture

POKROV Core is one client runtime with three layers:

1. `platform/` exposes the small Android and desktop interfaces consumed by the app.
2. `v2/` owns setup, configuration, lifecycle, WARP, DNS, and safe shutdown behavior.
3. `engine/sing-box/` owns transports, routing, TLS, TUN, and protocol implementations.

`ray2sing/` converts supported access links into sing-box options. `third_party/warp-plus/` supplies the pinned WARP registration and helper behavior.

The application supplies a materialized sing-box JSON profile for normal operation. Legacy builder APIs remain internal and are not the public POKROV app contract.

The desktop ABI version is `2`. C strings returned by the library are caller-owned and must be released through `freeString`.

Server inbounds, panel state, provisioning, and traffic accounting remain outside POKROV Core.
