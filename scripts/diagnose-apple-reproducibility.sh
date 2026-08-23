#!/usr/bin/env bash
set -euo pipefail

FIRST_ROOT="${1:?first Apple build root is required}/PokrovCore.xcframework"
SECOND_ROOT="${2:?second Apple build root is required}/PokrovCore.xcframework"

echo "Apple XCFramework root Info.plist diff:"
if diff -u "$FIRST_ROOT/Info.plist" "$SECOND_ROOT/Info.plist"; then
  echo "Root Info.plist files are byte-identical."
fi

for root in "$FIRST_ROOT" "$SECOND_ROOT"; do
  echo "Apple binary diagnostics for $root"
  find "$root" -type f -path '*/PokrovCore.framework/Versions/A/PokrovCore' -print |
    LC_ALL=C sort |
    while IFS= read -r binary; do
      shasum -a 256 "$binary"
      file "$binary"
      xcrun dwarfdump --uuid "$binary" || true
      xcrun otool -l "$binary" | awk '
        /cmd LC_UUID/ { print; remaining = 3; next }
        remaining > 0 { print; remaining-- }
      ' || true
    done
done
