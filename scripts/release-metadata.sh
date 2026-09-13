#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
VERSION="${VERSION:-$(cat VERSION)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo local)}"
BUILD_DATE="${BUILD_DATE:-$(./dist/netprobe-linux-amd64 --version 2>/dev/null | sed -n 's/.* built=\([^ ]*\).*/\1/p')}"
[[ -n "$BUILD_DATE" ]] || BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
[[ -x dist/netprobe-linux-amd64 && -x dist/netprobe-linux-arm64 ]] || { echo 'build binaries first' >&2; exit 1; }
AMD_SHA="$(sha256sum dist/netprobe-linux-amd64 | awk '{print $1}')"
ARM_SHA="$(sha256sum dist/netprobe-linux-arm64 | awk '{print $1}')"
cat > dist/SBOM.cdx.json <<JSON
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "${BUILD_DATE}",
    "component": {
      "type": "application",
      "name": "netprobe-ir",
      "version": "${VERSION}",
      "licenses": [{"license":{"id":"GPL-3.0-only"}}],
      "externalReferences": [{"type":"vcs","url":"https://github.com/cumakurt/netprobe-ir"}]
    }
  },
  "components": [
    {"type":"file","name":"netprobe-linux-amd64","version":"${VERSION}","hashes":[{"alg":"SHA-256","content":"${AMD_SHA}"}]},
    {"type":"file","name":"netprobe-linux-arm64","version":"${VERSION}","hashes":[{"alg":"SHA-256","content":"${ARM_SHA}"}]}
  ]
}
JSON
cat > dist/SBOM.spdx.json <<JSON
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "NetProbe IR ${VERSION} release",
  "documentNamespace": "https://github.com/cumakurt/netprobe-ir/releases/${VERSION}/spdx",
  "creationInfo": {"created":"${BUILD_DATE}","creators":["Organization: NetProbe IR","Person: Cuma KURT"]},
  "packages": [{"name":"netprobe-ir","SPDXID":"SPDXRef-Package-NetProbeIR","versionInfo":"${VERSION}","downloadLocation":"NOASSERTION","licenseConcluded":"GPL-3.0-only","licenseDeclared":"GPL-3.0-only","filesAnalyzed":false}],
  "files": [
    {"fileName":"dist/netprobe-linux-amd64","SPDXID":"SPDXRef-File-amd64","checksums":[{"algorithm":"SHA256","checksumValue":"${AMD_SHA}"}]},
    {"fileName":"dist/netprobe-linux-arm64","SPDXID":"SPDXRef-File-arm64","checksums":[{"algorithm":"SHA256","checksumValue":"${ARM_SHA}"}]}
  ]
}
JSON
cat > dist/provenance.json <<JSON
{
  "project": "NetProbe IR",
  "version": "${VERSION}",
  "commit": "${COMMIT}",
  "build_date": "${BUILD_DATE}",
  "go_version": "$(go version | awk '{print $3}')",
  "reproducible_controls": ["CGO_ENABLED=0", "-trimpath", "-buildvcs=false", "-buildid=", "SOURCE_DATE_EPOCH supported"],
  "artifacts": {
    "linux_amd64": {"path":"dist/netprobe-linux-amd64","sha256":"${AMD_SHA}"},
    "linux_arm64": {"path":"dist/netprobe-linux-arm64","sha256":"${ARM_SHA}"}
  },
  "source_repository": "https://github.com/cumakurt/netprobe-ir",
  "license": "GPL-3.0-only"
}
JSON
python3 -m json.tool dist/SBOM.cdx.json >/dev/null
python3 -m json.tool dist/SBOM.spdx.json >/dev/null
python3 -m json.tool dist/provenance.json >/dev/null
sha256sum dist/netprobe-linux-amd64 dist/netprobe-linux-arm64 dist/SBOM.cdx.json dist/SBOM.spdx.json dist/provenance.json > dist/SHA256SUMS
if [[ -n "${SIGNING_DATA_DIR:-}" ]]; then
  ./dist/netprobe-linux-amd64 config sign --data-dir "$SIGNING_DATA_DIR" --signature dist/SHA256SUMS.sig.json dist/SHA256SUMS
  echo "Signed release checksum manifest with local Ed25519 evidence key."
else
  echo "SIGNING_DATA_DIR not set; generated checksums/SBOM/provenance without a release signature."
fi
