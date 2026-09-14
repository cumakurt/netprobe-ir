#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/dist/netprobe-linux-amd64}"
CHROME="${CHROME:-$(command -v chromium || command -v chromium-browser || command -v google-chrome || true)}"
[[ -x "$BIN" ]] || { echo "Missing $BIN; run scripts/build-static.sh first"; exit 1; }
[[ -n "$CHROME" ]] || { echo "SKIP: Chromium/Chrome unavailable"; exit 77; }
command -v node >/dev/null || { echo "SKIP: node unavailable"; exit 77; }
command -v curl >/dev/null || { echo "SKIP: curl unavailable"; exit 77; }
command -v python3 >/dev/null || { echo "SKIP: python3 unavailable"; exit 77; }
# Real browser E2E needs real loopback packet capture so the graph and traffic
# chart are populated from production data paths. Re-exec inside an unprivileged
# user/network namespace when available, matching the live capture regression.
if [[ "${NETPROBE_UI_NS:-}" != "1" ]]; then
  command -v unshare >/dev/null || { echo "SKIP: unshare unavailable"; exit 77; }
  command -v ip >/dev/null || { echo "SKIP: ip unavailable"; exit 77; }
  if ! unshare -Urn true 2>/dev/null; then echo 'SKIP: unprivileged user/network namespaces unavailable'; exit 77; fi
  exec unshare -Urn env NETPROBE_UI_NS=1 BIN="$BIN" CHROME="$CHROME" bash "$0"
fi
ip link set lo up
TMP="$(mktemp -d)"; NPID=''; CPID=''; TPID=''
cleanup(){ if [[ -n "$CPID" ]]; then kill "$CPID" 2>/dev/null || true; wait "$CPID" 2>/dev/null || true; fi; if [[ -n "$TPID" ]]; then kill "$TPID" 2>/dev/null || true; wait "$TPID" 2>/dev/null || true; fi; if [[ -n "$NPID" ]]; then kill "$NPID" 2>/dev/null || true; wait "$NPID" 2>/dev/null || true; fi; rm -rf "$TMP" 2>/dev/null || true; }
trap cleanup EXIT
pick_port(){ python3 - <<'PY'
import socket
s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()
PY
}
PORT="$(pick_port)"; DPORT="$(pick_port)"
cat >"$TMP/config.json" <<JSON
{"auth":{"enabled":false},"recorder":{"enabled":false},"security":{"console_allowed_cidrs":["127.0.0.0/8","::1/128"]}}
JSON
"$BIN" --config "$TMP/config.json" --interface lo --listen "127.0.0.1:$PORT" --data-dir "$TMP/data" >"$TMP/netprobe.log" 2>&1 & NPID=$!
for _ in $(seq 1 80); do curl -fsS "http://127.0.0.1:$PORT/api/v1/status" >/dev/null 2>&1 && break; sleep .1; done
curl -fsS "http://127.0.0.1:$PORT/" >/dev/null
for _ in $(seq 1 16); do curl -fsS "http://127.0.0.1:$PORT/api/v1/health" >/dev/null; done
# Exercise the visible analytics path with traffic from an unrelated process.
python3 - <<'PY' &
import socket,time
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for _ in range(240):
    sock.sendto(b'ui-regression-traffic',('127.0.0.1',19001))
    time.sleep(.25)
sock.close()
PY
TPID=$!
sleep 1
mkdir -p "$TMP/chrome"
"$CHROME" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage --remote-debugging-port="$DPORT" --user-data-dir="$TMP/chrome" "http://127.0.0.1:$PORT/#/overview" >"$TMP/chrome.log" 2>&1 & CPID=$!
for _ in $(seq 1 100); do curl -fsS "http://127.0.0.1:$DPORT/json/list" >/dev/null 2>&1 && break; sleep .1; done
NETPROBE_URL="http://127.0.0.1:$PORT" NETPROBE_SENSOR_PORT="$PORT" CHROME_PORT="$DPORT" node "$ROOT/scripts/ui-e2e.js"
echo 'PASS: real Chromium end-to-end console interactions'
