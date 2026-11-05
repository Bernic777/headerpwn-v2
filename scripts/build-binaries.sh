#!/usr/bin/env bash
# Cross-compile headerpwn for every release target.
# Usage: ./scripts/build-binaries.sh [version] [output-dir]
set -euo pipefail

VERSION="${1:-${VERSION:-dev}}"
OUT_DIR="${2:-dist}"

targets=(
	"linux/amd64/"
	"linux/arm64/"
	"linux/arm/7"
	"linux/386/"
	"windows/amd64/"
	"windows/arm64/"
	"windows/386/"
	"darwin/amd64/"
	"darwin/arm64/"
	"freebsd/amd64/"
)

mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/headerpwn-"$VERSION"-* "$OUT_DIR"/sha256sums.txt

for target in "${targets[@]}"; do
	IFS=/ read -r goos goarch goarm <<<"$target"
	arch="$goarch"
	if [ "$goarch" = "arm" ]; then
		arch="armv${goarm:-7}"
	fi
	name="headerpwn-${VERSION}-${goos}-${arch}"
	ext=""
	if [ "$goos" = "windows" ]; then
		ext=".exe"
	fi

	echo "building ${name}${ext}"
	if [ -n "$goarm" ]; then
		CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" \
			go build -trimpath -ldflags="-s -w" -o "$OUT_DIR/$name$ext" .
	else
		CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
			go build -trimpath -ldflags="-s -w" -o "$OUT_DIR/$name$ext" .
	fi
done

(
	cd "$OUT_DIR"
	sha256sum headerpwn-* >sha256sums.txt
)

echo
echo "artifacts in $OUT_DIR:"
ls -lh "$OUT_DIR"
