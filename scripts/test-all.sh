#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo '==> gofmt check'
unformatted="$(gofmt -l cmd internal)"
if [[ -n "$unformatted" ]]; then echo "$unformatted"; exit 1; fi

echo '==> shell syntax'
sh -n install.sh uninstall.sh scripts/install.sh scripts/uninstall.sh \
  packaging/openrc/netprobe-ir packaging/runit/run packaging/sysv/netprobe-ir
bash -n scripts/build-static.sh scripts/release-metadata.sh scripts/build-ebpf-core.sh scripts/test-all.sh scripts/integration-live-linux.sh scripts/integration-live-tls-linux.sh scripts/integration-ui-browser.sh scripts/capture-readme-screenshots.sh

if command -v python3 >/dev/null 2>&1; then
  echo '==> JSON configuration syntax'
  python3 -m json.tool configs/netprobe.example.json >/dev/null
  python3 -m json.tool configs/iocs.example.json >/dev/null
  python3 -m json.tool configs/ids-rules.example.json >/dev/null
  python3 -m json.tool configs/stix-bundle.example.json >/dev/null
  python3 -m json.tool configs/syslog-destinations.example.json >/dev/null
  python3 -m json.tool configs/flow-collectors.example.json >/dev/null
  python3 -m json.tool configs/kev-catalog.example.json >/dev/null
  python3 -m json.tool configs/enrichment.example.json >/dev/null
  python3 -m json.tool configs/playbooks.example.json >/dev/null
else
  echo '==> JSON configuration syntax: SKIP (python3 not installed; not a runtime dependency)'
fi

echo '==> source/embedded web assets are synchronized'
cmp -s web/static/index.html internal/server/static/index.html
cmp -s web/static/app.css internal/server/static/app.css
cmp -s web/static/app.js internal/server/static/app.js
cmp -s web/static/analytics.js internal/server/static/analytics.js
cmp -s web/static/analytics.css internal/server/static/analytics.css

if command -v node >/dev/null 2>&1; then
  echo '==> embedded web JavaScript syntax'
  node --check internal/server/static/app.js
  node --check internal/server/static/analytics.js
  node --check scripts/ui-e2e.js
  node --check scripts/capture-readme-screenshots.js
else
  echo '==> embedded web JavaScript syntax: SKIP (node not installed; not a runtime dependency)'
fi

echo '==> go vet'
go vet ./...

echo '==> unit/integration tests'
go test ./...

echo '==> race detector (package groups)'
mapfile -t RACE_PKGS < <(go list ./...)
RACE_GROUPS=4
RACE_TOTAL=${#RACE_PKGS[@]}
RACE_CHUNK=$(( (RACE_TOTAL + RACE_GROUPS - 1) / RACE_GROUPS ))
for ((i=0; i<RACE_TOTAL; i+=RACE_CHUNK)); do
  group=("${RACE_PKGS[@]:i:RACE_CHUNK}")
  echo "    race group $((i/RACE_CHUNK+1)): ${#group[@]} packages"
  go test -race "${group[@]}"
done

echo '==> static build + embedded self-test'
./scripts/build-static.sh
./dist/netprobe-linux-amd64 --self-test


echo '==> Sigma v2 translation CLI'
./dist/netprobe-linux-amd64 sigma --in configs/sigma-rule.example.yml --format query | grep -F 'process:python3' >/dev/null
./dist/netprobe-linux-amd64 sigma --in configs/sigma-rule.example.yml --format npdl | grep -F 'rule NP-SIGMA-1001' >/dev/null

echo '==> v0.9 interoperability / analytics CLI'
./dist/netprobe-linux-amd64 sigma --correlation --in configs/sigma-correlation.example.yml | grep -F 'temporal_ordered' >/dev/null
./dist/netprobe-linux-amd64 import-rule --file configs/suricata-rules.example.rules | grep -F '9000001' >/dev/null
./dist/netprobe-linux-amd64 benchmark --iterations 1000 | grep -F 'synthetic-security-hotpath' >/dev/null
TMP_SBOM="$(mktemp -d)"
./dist/netprobe-linux-amd64 sbom --format cyclonedx --dpkg-status /definitely/missing --out "$TMP_SBOM/host.cdx.json"
./dist/netprobe-linux-amd64 sbom --format spdx --dpkg-status /definitely/missing --out "$TMP_SBOM/host.spdx.json"
python3 -m json.tool "$TMP_SBOM/host.cdx.json" >/dev/null
python3 -m json.tool "$TMP_SBOM/host.spdx.json" >/dev/null
rm -rf "$TMP_SBOM"

echo '==> release SBOM / provenance metadata'
./scripts/release-metadata.sh
python3 -m json.tool dist/SBOM.cdx.json >/dev/null
python3 -m json.tool dist/SBOM.spdx.json >/dev/null
python3 -m json.tool dist/provenance.json >/dev/null

echo '==> release checksums'
sha256sum -c dist/SHA256SUMS

echo '==> target architecture artifacts'
file ./dist/netprobe-linux-amd64 | grep -Eq 'x86-64|x86_64'
file ./dist/netprobe-linux-arm64 | grep -Eq 'ARM aarch64|aarch64'

echo '==> project metadata'
./dist/netprobe-linux-amd64 --about | grep -F 'Cuma KURT' >/dev/null
./dist/netprobe-linux-amd64 --about | grep -F 'https://github.com/cumakurt/netprobe-ir' >/dev/null
./dist/netprobe-linux-amd64 --about | grep -F 'GNU GPLv3' >/dev/null
./dist/netprobe-linux-amd64 --version | grep -F '1.0.0' >/dev/null

echo '==> static linkage'
file ./dist/netprobe-linux-amd64
if ldd ./dist/netprobe-linux-amd64 2>&1 | grep -q 'not a dynamic executable'; then :; else
  if readelf -d ./dist/netprobe-linux-amd64 2>/dev/null | grep -q NEEDED; then echo 'binary has dynamic dependencies'; exit 1; fi
fi

echo '==> installer/uninstaller staged-root regression'
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
./install.sh --root "$STAGE" --bundled-only >/tmp/netprobe-install-stage.log
[[ -x "$STAGE/usr/local/sbin/netprobe-ir" ]]
[[ -L "$STAGE/usr/local/sbin/netprobe" ]]
[[ -f "$STAGE/etc/netprobe-ir/config.json" ]]
grep -F 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET AF_NETLINK' "$STAGE/etc/systemd/system/netprobe-ir.service" >/dev/null
grep -F '[9/9] Running post-install verification' /tmp/netprobe-install-stage.log >/dev/null
[[ -f "$STAGE/var/lib/netprobe-ir/auth/users.json" ]]
[[ "$(stat -c '%a' "$STAGE/var/lib/netprobe-ir/auth/users.json")" == "600" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/LICENSE" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/docs/IDS_SECURITY.md" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/docs/HUNT_QUERY.md" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/examples/iocs.example.json" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/examples/ids-rules.example.json" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/examples/syslog-destinations.example.json" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/examples/flow-collectors.example.json" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/docs/EXPORT_SYSLOG_FLOW.md" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/docs/ADVANCED_V07.md" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/examples/detections.example.npdl" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/examples/yara-rules.example.yar" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/examples/kev-catalog.example.json" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/examples/sigma-rule.example.yml" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/examples/sigma-correlation.example.yml" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/examples/suricata-rules.example.rules" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/examples/enrichment.example.json" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/examples/playbooks.example.json" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/docs/ADVANCED_V09.md" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/docs/ADVANCED_V09_TR.md" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/docs/ADVANCED_V10.md" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/docs/ADVANCED_V10_TR.md" ]]
[[ -f "$STAGE/usr/local/share/doc/netprobe-ir/docs/SUPPLY_CHAIN.md" ]]
"$STAGE/usr/local/sbin/netprobe-ir" auth reset --data-dir "$STAGE/var/lib/netprobe-ir" --username admin | grep -F 'Temporary password:' >/dev/null
./uninstall.sh --root "$STAGE" --purge --yes >/tmp/netprobe-uninstall-stage.log
[[ ! -e "$STAGE/usr/local/sbin/netprobe-ir" ]]
[[ ! -e "$STAGE/etc/netprobe-ir" ]]
[[ ! -e "$STAGE/var/lib/netprobe-ir" ]]
rm -rf "$STAGE"
trap - EXIT

echo 'All non-privileged and staged-install tests passed.'
