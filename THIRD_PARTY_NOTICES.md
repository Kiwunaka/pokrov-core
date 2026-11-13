# Third-party notices

POKROV Core includes and links third-party software.

- sing-box and related SagerNet modules: GPL-3.0-or-later. The embedded engine license is retained at `engine/sing-box/LICENSE`.
  The default-off managed Hysteria2 lab uses this existing embedded engine and
  adds no second implementation or dependency.
- ray2sing converter: CC0-1.0. Its license is retained at `ray2sing/LICENSE`.
- warp-plus helper: MIT. Its license is retained at `third_party/warp-plus/LICENSE`.
- AmneziaWG Go `v0.2.16`: MIT. Its exact module sum and bounded AWG2 usage are
  recorded in `config/awg2-capability.json`; the license is retained at
  `third_party/licenses/amneziawg-go-MIT.txt`.
- OpenFlux MTS board carrier: GPL-3.0; its license is retained at `engine/sing-box/protocol/pokrov/mtscarrier/LICENSE`.
- VK TURN TCP carrier and authentication protocol: adapted from [vk-turn-proxy v1.8.3](https://github.com/cacggghp/vk-turn-proxy/tree/v1.8.3), GPL-3.0; its license is retained at `engine/sing-box/protocol/pokrov/vk/LICENSE`. The outer carrier requires inner VLESS REALITY or TLS authentication. Android runs VK's own verification page and returns its one-shot result in memory.
- Embedded WireGuard, Tailscale, Psiphon, and protocol modules retain their license files in their source directories.
- Cronet is Chromium's network stack. Chromium uses a BSD-style license and
  bundled components retain their respective licenses; see [Chromium LICENSE](https://github.com/chromium/chromium/blob/main/LICENSE).
  The Go wrapper is [cronet-go, GPL-3.0-or-later](https://github.com/SagerNet/cronet-go/blob/c10c03c318db6d47bec8705c8290bad34bc32b64/LICENSE).
- The optional [Slipstream Rust client](https://github.com/Mygod/slipstream-rust/tree/c7b265c11dd13d6dfd601bc81d54d61ee9bdde23)
  is Apache-2.0; its license is retained at `third_party/slipstream/LICENSE` and
  distributed with the native client. Its native TLS/QUIC components include
  [OpenSSL, Apache-2.0](https://www.openssl.org/source/license.html),
  [picoquic, MIT](https://github.com/Mygod/slipstream-picoquic/blob/d4a865c54929cfeb2a61902a0340b8758ad5492e/LICENSE),
  and [picotls, MIT](https://github.com/h2o/picotls).

POKROV-specific changes do not replace third-party copyright or license notices.
