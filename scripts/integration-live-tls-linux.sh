#!/usr/bin/env bash
# Real passive capture + TLS ClientHello/SNI/ALPN/JA3/JA4/NPSH integration test.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/dist/netprobe-linux-amd64}"
[[ -x "$BIN" ]] || { echo "Missing $BIN; run scripts/build-static.sh first"; exit 1; }
for c in unshare ip curl openssl python3; do command -v "$c" >/dev/null || { echo "SKIP: missing $c"; exit 77; }; done
if ! unshare -Urn true 2>/dev/null; then echo 'SKIP: unprivileged user/network namespaces unavailable'; exit 77; fi
unshare -Urn env NETPROBE_BIN="$BIN" bash <<'NETPROBE_NS'
set -euo pipefail
ip link set lo up
TMP=$(mktemp -d)
cat >"$TMP/config.json" <<'JSON'
{"auth":{"enabled":false},"security":{"console_allowed_cidrs":["127.0.0.0/8","::1/128"]}}
JSON
SPID=''; NPID=''
cleanup(){ if [[ -n "$NPID" ]];then kill "$NPID" 2>/dev/null||true;wait "$NPID" 2>/dev/null||true;fi;if [[ -n "$SPID" ]];then kill "$SPID" 2>/dev/null||true;wait "$SPID" 2>/dev/null||true;fi;rm -rf "$TMP"; }
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -days 1 -subj '/CN=localhost' >/dev/null 2>&1
openssl s_server -quiet -www -accept 18443 -cert "$TMP/cert.pem" -key "$TMP/key.pem" >"$TMP/sserver.log" 2>&1 & SPID=$!
"$NETPROBE_BIN" --config "$TMP/config.json" --interface lo --listen 127.0.0.1:19002 --data-dir "$TMP/data" --no-recorder >"$TMP/netprobe.log" 2>&1 & NPID=$!
sleep 2
curl -kfsS https://localhost:18443/ >/dev/null
sleep 1
curl -fsS 'http://127.0.0.1:19002/api/v1/flows?limit=500' > "$TMP/flows.json"
python3 - "$TMP/flows.json" <<'PY'
import json,sys
flows=json.load(open(sys.argv[1]))
target=[f for f in flows if f['local']['port']==18443 or f['remote']['port']==18443]
assert target, 'no TLS target flow'
parsed=[f for f in target if (f.get('dpi') or {}).get('tls')]
assert parsed, 'TLS ClientHello not parsed'
assert any((f['dpi']['tls'].get('sni') or '')=='localhost' for f in parsed), 'SNI missing'
assert any(f['dpi']['tls'].get('ja3') for f in parsed), 'JA3 missing'
assert any(f['dpi']['tls'].get('ja4') for f in parsed), 'JA4 missing'
assert any(f['dpi']['tls'].get('server_fingerprint') for f in parsed), 'NPSH server fingerprint missing'
assert any('http/1.1' in (f['dpi']['tls'].get('alpn') or []) for f in parsed), 'ALPN missing'
print('PASS: real TLS ClientHello, SNI, ALPN, JA3, JA4, NPSH')
PY
kill -TERM "$NPID"; wait "$NPID"; NPID=''
NETPROBE_NS
