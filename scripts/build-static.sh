#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
VERSION="${VERSION:-$(cat VERSION 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo local)}"
if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
  BUILD_DATE="${BUILD_DATE:-$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || python3 - <<'PY'
import datetime,os
print(datetime.datetime.fromtimestamp(int(os.environ['SOURCE_DATE_EPOCH']),datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
PY
)}"
else
  BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
fi
mkdir -p dist
LDFLAGS="-s -w -buildid= -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}"
for arch in amd64 arm64; do
  echo "==> linux/${arch}"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -buildvcs=false -trimpath -tags 'netgo osusergo' -ldflags "$LDFLAGS" -o "dist/netprobe-linux-${arch}" ./cmd/netprobe
done
sha256sum dist/netprobe-linux-amd64 dist/netprobe-linux-arm64 > dist/SHA256SUMS
echo "Static builds created under dist/"
