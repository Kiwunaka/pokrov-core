#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(tr -d '\r\n' < "$ROOT/VERSION")"
OUTPUT_DIRECTORY="${1:-$ROOT/dist/apple}"

if [[ "$(go env GOVERSION)" != "go1.25.13" ]]; then
  echo "Go 1.25.13 is required." >&2
  exit 1
fi

go install github.com/sagernet/gomobile/cmd/gomobile@v0.1.11
go install github.com/sagernet/gomobile/cmd/gobind@v0.1.11

mkdir -p "$OUTPUT_DIRECTORY"
cd "$ROOT"

TAGS="with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_grpc,with_awg,tfogo_checklinkname0,with_naive_outbound,with_conntrack,with_dhcp,with_low_memory,with_purego"

gomobile bind \
  -target ios,iossimulator,macos \
  -libname PokrovCore \
  -tags "$TAGS" \
  -trimpath \
  -ldflags "-w -s -checklinkname=0 -buildid= -X github.com/Kiwunaka/POKROV-core/v2/hcommon/constants.Version=$VERSION" \
  -o "$OUTPUT_DIRECTORY/PokrovCore.xcframework" \
  github.com/sagernet/sing-box/experimental/libbox \
  ./platform/mobile
