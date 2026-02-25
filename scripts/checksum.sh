#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <version>" >&2
  exit 1
fi

VERSION="$1"
DIST_DIR="dist"
ARM_ARCHIVE="$DIST_DIR/velar-darwin-arm64-${VERSION}.tar.gz"
INTEL_ARCHIVE="$DIST_DIR/velar-darwin-x86_64-${VERSION}.tar.gz"

for f in "$ARM_ARCHIVE" "$INTEL_ARCHIVE"; do
  if [[ ! -f "$f" ]]; then
    echo "Missing archive: $f" >&2
    exit 1
  fi
done

SHA256_ARM64=$(sha256sum "$ARM_ARCHIVE" | awk '{print $1}')
SHA256_X86_64=$(sha256sum "$INTEL_ARCHIVE" | awk '{print $1}')

cat <<EOF
VERSION=${VERSION}
SHA256_ARM64=${SHA256_ARM64}
SHA256_X86_64=${SHA256_X86_64}
EOF
