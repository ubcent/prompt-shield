#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <arm64|x86_64> <version>" >&2
  exit 1
fi

ARCH="$1"
VERSION="$2"

case "$ARCH" in
  arm64)
    GOARCH="arm64"
    OUT_ARCH="arm64"
    ;;
  x86_64)
    GOARCH="amd64"
    OUT_ARCH="x86_64"
    ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

DIST_DIR="dist"
PKG_DIR="$DIST_DIR/velar-darwin-${OUT_ARCH}-${VERSION}"
ARCHIVE="$DIST_DIR/velar-darwin-${OUT_ARCH}-${VERSION}.tar.gz"

rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"

CGO_ENABLED=0 GOOS=darwin GOARCH="$GOARCH" go build \
  -ldflags="-X main.Version=${VERSION}" \
  -o "$PKG_DIR/velar" \
  ./cmd/velar

CGO_ENABLED=0 GOOS=darwin GOARCH="$GOARCH" go build \
  -ldflags="-X main.Version=${VERSION}" \
  -o "$PKG_DIR/velard" \
  ./cmd/velard

tar -C "$PKG_DIR" -czf "$ARCHIVE" velar velard

echo "$ARCHIVE"
