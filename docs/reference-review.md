# Reference review

External core and transport projects are advisory inputs, not automatic dependencies.

For each candidate update:

1. Identify the exact issue and fixing commit.
2. Reproduce the failure against the current POKROV release when possible.
3. Import the smallest relevant change.
4. Run the affected package tests and platform backtest.
5. Record whether the change is POKROV-only or suitable for an upstream contribution.

Do not merge a reference branch wholesale into `main`. Release ownership and versioning remain under POKROV.

`config/release.json` pins the sing-box upstream tag and commit. To enumerate the
fork's changed files, check out that commit in a separate temporary upstream
checkout and run `git diff --no-index --name-status <upstream-checkout>
engine/sing-box`; use `--ignore-cr-at-eol` when reviewing the patch on Windows.
Git owns the file list and history. The main local changes are the adapters and
Box lifecycle, `common/{tls,urltest,certificate,dialer}`, `daemon`, `dns`,
`experimental/{libbox,cachefile,v2rayapi}`, client `include` registries, `option`,
`protocol/{pokrov,awg,group,naive,tun,wireguard,hysteria2}`, `route`, and the
embedded replacements. A matching version string alone does not establish
equivalence with upstream.

REALITY follows the [Xray v26.6.27 client wire layout](https://github.com/XTLS/Xray-core/blob/v26.6.27/transport/internet/reality/reality.go)
and announces `26.6.27`. The Core requires an X25519MLKEM768 share before optional
X25519, matching [REALITY 83f621788ca8](https://github.com/XTLS/REALITY/blob/83f621788ca8/tls.go),
the dependency pinned by Xray v26.10.21. Offline tests decrypt the session ID and
check the version, reserved byte, AEAD and hybrid share. The optional local
Xray test checks 26.6.27, 26.7.28 and 26.9.9 against a loopback TLS decoy. A future
server minimum or protocol change still requires review and local compatibility
testing before changing the node pin.
