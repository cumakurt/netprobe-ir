#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${NETPROBE_README_NS:-}" != "1" ]]; then
  for command_name in go node chromium unshare ip curl magick identify python3; do
    command -v "$command_name" >/dev/null || { echo "Missing required command: $command_name" >&2; exit 1; }
  done
  unshare -Urn true 2>/dev/null || { echo 'Unprivileged network namespaces are required for synthetic screenshots' >&2; exit 1; }
  work_dir="$(mktemp -d)"
  trap 'rm -rf "$work_dir"' EXIT
  cd "$ROOT"
  go build -o "$work_dir/netprobe-readme-demo" ./scripts/readme-demo
  unshare -Urn env NETPROBE_README_NS=1 NETPROBE_README_WORK="$work_dir" NETPROBE_README_BIN="$work_dir/netprobe-readme-demo" bash "$0"

  mapfile -t images < <(find "$work_dir/new-img" -maxdepth 1 -type f -name '*.png' | sort)
  [[ "${#images[@]}" -eq 10 ]] || { echo "Expected 10 screenshots, found ${#images[@]}" >&2; exit 1; }
  for image_path in "${images[@]}"; do
    dimensions="$(identify -format '%w %h' "$image_path")"
    [[ "$dimensions" == "1520 1060" ]] || { echo "Unexpected screenshot dimensions: $image_path ($dimensions)" >&2; exit 1; }
  done
  mkdir -p "$work_dir/optimized-img"
  for image_path in "${images[@]}"; do
    magick "$image_path" -strip -define png:compression-level=9 "$work_dir/optimized-img/$(basename "$image_path")"
  done
  mkdir -p "$ROOT/img"
  find "$ROOT/img" -maxdepth 1 -type f -delete
  cp "$work_dir"/optimized-img/*.png "$ROOT/img/"
  echo "Updated ${#images[@]} synthetic console screenshots under img/"
  exit
fi

ip link set lo up
ip link add demo0 type veth peer name demo1
ip link set dev demo0 addrgenmode none
ip link set dev demo1 addrgenmode none
ip link set demo0 up
ip link set demo1 up
work_dir="$NETPROBE_README_WORK"
demo_pid=''
chrome_pid=''
traffic_pid=''
cleanup() {
  if [[ -n "$chrome_pid" ]]; then kill "$chrome_pid" 2>/dev/null || true; wait "$chrome_pid" 2>/dev/null || true; fi
  if [[ -n "$traffic_pid" ]]; then kill "$traffic_pid" 2>/dev/null || true; wait "$traffic_pid" 2>/dev/null || true; fi
  if [[ -n "$demo_pid" ]]; then kill "$demo_pid" 2>/dev/null || true; wait "$demo_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT

"$NETPROBE_README_BIN" --listen 127.0.0.1:19003 --data-dir "$work_dir/data" >"$work_dir/demo.log" 2>&1 & demo_pid=$!
for _ in $(seq 1 100); do
  if curl -fsS http://127.0.0.1:19003/api/v1/status >/dev/null 2>&1; then break; fi
  sleep .1
done
curl -fsS http://127.0.0.1:19003/api/v1/findings | python3 -c 'import json,sys; assert len(json.load(sys.stdin)) >= 5'
curl -fsS http://127.0.0.1:19003/api/v1/flows | python3 -c 'import json,sys; assert len(json.load(sys.stdin)) >= 6'

# Raw frames on the demo veth create real capture counters without exposing the
# browser's DevTools and console traffic to the screenshot telemetry.
python3 - <<'PY' & traffic_pid=$!
import socket,struct,time
def frame(source,destination,source_port,destination_port,payload,source_mac,destination_mac):
    tcp=struct.pack('!HHIIHHHH',source_port,destination_port,100,0,(5<<12)|0x18,4096,0,0)
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp)+len(payload),0,0,64,6,0,socket.inet_aton(source),socket.inet_aton(destination))
    return destination_mac+source_mac+struct.pack('!H',0x0800)+ip+tcp+payload
first=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
second=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
first.bind(('demo0',0))
second.bind(('demo1',0))
mac0,mac1=b'\x02\xaa\xbb\xcc\xdd\x01',b'\x02\xaa\xbb\xcc\xdd\x02'
broadcast=b'\xff'*6
request=frame('10.42.0.17','203.0.113.77',51123,80,b'GET /update/check HTTP/1.1\r\nHost: updates.example.test\r\n\r\n'+b'X'*256,mac0,broadcast)
response=frame('203.0.113.77','10.42.0.17',80,51123,b'HTTP/1.1 200 OK\r\nContent-Length: 256\r\n\r\n'+b'Y'*256,mac1,broadcast)
while True:
    first.send(request)
    second.send(response)
    time.sleep(.35)
PY
sleep 1
kill -0 "$traffic_pid"
curl -fsS http://127.0.0.1:19003/api/v1/status | python3 -c 'import json,sys; assert json.load(sys.stdin)["status"]["packets"] > 0'

mkdir -p "$work_dir/chrome" "$work_dir/new-img"
chromium --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
  --remote-debugging-port=9333 --user-data-dir="$work_dir/chrome" \
  --window-size=1520,1060 --force-device-scale-factor=1 \
  http://127.0.0.1:19003/#/overview >"$work_dir/chrome.log" 2>&1 & chrome_pid=$!
for _ in $(seq 1 100); do
  if curl -fsS http://127.0.0.1:9333/json/list >/dev/null 2>&1; then break; fi
  sleep .1
done
NETPROBE_DEMO_URL=http://127.0.0.1:19003 CHROME_PORT=9333 \
  NETPROBE_SCREENSHOT_OUTPUT="$work_dir/new-img" node "$ROOT/scripts/capture-readme-screenshots.js"
curl -fsS http://127.0.0.1:19003/api/v1/flows | python3 -c 'import json,sys; flows=json.load(sys.stdin); assert len(flows)==6 and all(f["local"]["port"] != 9333 and f["remote"]["port"] != 9333 for f in flows)'
