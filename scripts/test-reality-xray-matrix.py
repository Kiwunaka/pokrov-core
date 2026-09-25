"""Check the current sing-box REALITY client against local Xray binaries.

Each Xray runs on loopback with disposable credentials. The HTTPS request is
sent through the client's local HTTP proxy; no production node is modified.
"""

import argparse
import ipaddress
import json
import re
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def start(binary, config):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.Popen(
        [str(binary), "run", "-c", str(config)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
    )


def stop(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True, type=Path)
    parser.add_argument("--xray", required=True, action="append", type=Path)
    parser.add_argument("--url", default="https://www.gstatic.com/generate_204")
    parser.add_argument("--check-pokrov-marker", action="store_true")
    parser.add_argument("--egress-ip", type=ipaddress.IPv4Address)
    args = parser.parse_args()

    key_output = subprocess.check_output(
        [str(args.xray[0]), "x25519"], stderr=subprocess.DEVNULL, text=True
    )
    private = re.search(r"^PrivateKey:\s*(\S+)", key_output, re.MULTILINE)
    public = re.search(r"^Password \(PublicKey\):\s*(\S+)", key_output, re.MULTILINE)
    if not private or not public:
        raise SystemExit("Could not parse Xray's disposable key pair")

    identity = str(uuid.uuid4())
    server_port, proxy_port = free_port(), free_port()
    freedom = {"protocol": "freedom"}
    if args.egress_ip is not None:
        freedom["settings"] = {"redirect": f"{args.egress_ip}:443"}
    server = {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": server_port, "protocol": "vless",
            "settings": {"clients": [{"id": identity, "flow": "xtls-rprx-vision"}],
                         "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality",
                               "realitySettings": {
                                   "dest": "www.cloudflare.com:443",
                                   "serverNames": ["www.cloudflare.com"],
                                   "privateKey": private.group(1), "shortIds": [""]}},
        }],
        "outbounds": [freedom],
    }
    client = {
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1",
                      "listen_port": proxy_port}],
        "outbounds": [{
            "type": "vless", "tag": "out", "server": "127.0.0.1",
            "server_port": server_port, "uuid": identity,
            "flow": "xtls-rprx-vision",
            "tls": {"enabled": True, "server_name": "www.cloudflare.com",
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {"enabled": True, "public_key": public.group(1),
                                "short_id": ""}},
        }],
        "route": {"final": "out"},
    }

    failed = False
    with tempfile.TemporaryDirectory(prefix="pokrov-reality-") as directory:
        server_config = Path(directory) / "server.json"
        client_config = Path(directory) / "client.json"
        server_config.write_text(json.dumps(server), encoding="utf-8")
        client_config.write_text(json.dumps(client), encoding="utf-8")
        proxy = urllib.request.ProxyHandler({"https": f"http://127.0.0.1:{proxy_port}"})
        opener = urllib.request.build_opener(proxy)
        for binary in args.xray:
            xray_process = client_process = None
            try:
                xray_process = start(binary, server_config)
                time.sleep(0.7)
                if xray_process.poll() is not None:
                    raise RuntimeError("Xray startup")
                client_process = start(args.client, client_config)
                time.sleep(0.7)
                if client_process.poll() is not None:
                    raise RuntimeError("client startup")
                request = urllib.request.Request(args.url, method="HEAD")
                with opener.open(request, timeout=20) as response:
                    status = response.status
                    marker_ok = (
                        response.headers.get("X-Pokrov-Egress-Probe")
                        == "pokrov-authenticated-egress-v1"
                        if args.check_pokrov_marker else None
                    )
                marker = marker_ok if marker_ok is not None else "not_checked"
                print(f"{binary.parent.name}: HTTP {status}, marker={marker}")
                failed |= status != 204 or marker_ok is False
            except Exception as error:
                reason = getattr(error, "reason", error)
                print(f"{binary.parent.name}: FAIL ({type(reason).__name__})")
                failed = True
            finally:
                stop(client_process)
                stop(xray_process)
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
