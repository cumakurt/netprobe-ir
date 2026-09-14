# Live traffic analytics

Open **Top Analytics** in the primary menu for global packet telemetry. Open an
interface under **Interfaces** for its live device RX/TX chart and captured traffic
breakdown. Both views use one Server-Sent Events stream, updated once per second.
No page reload or external chart/font/icon service is required.

## Reading the measurements

- Captured bytes are the lengths of successfully decoded, live captured frames.
  Capture filters, snap length, decoding failures and capture drops affect coverage.
  Replay frames are excluded. These are observations, not estimates of unsampled
  traffic, payload goodput, or deduplicated packets on the entire network.
- Inbound/outbound/forwarded/unknown are mutually exclusive host-relative
  directions. Forwarded observations count once. A wire packet captured on two
  interfaces contributes two observations to global counters. Loopback can also
  expose multiple observations. Unknown direction is retained explicitly.
- Interface chart RX/TX and device packet/error/drop totals come from
  `/proc/net/dev`. They include traffic outside capture filters and continue while
  capture is stopped. Their totals are since device counter initialization/reset.
  The first device sample, a reset, missing device, or unavailable OS source has
  no rate (`null`, displayed as **Not available**). Rate denominators use measured
  elapsed seconds. Coarse kernel rates average only valid kernel sample intervals.
- Active flows are observed bidirectional conversations within
  `capture.flow_idle_seconds` (120 seconds when unspecified/nonpositive), excluding
  TCP conversations after FIN/RST. They are not an OS established socket count.
  New connections count first observed TCP SYNs without ACK; retransmitted SYNs
  within a retained conversation do not increase this metric. UDP flow counts do
  not imply a connection handshake. Captures beginning mid-connection cannot
  recover an unobserved start. A first-seen flow source may be the responder.
- Flow duration is first-to-last observed packet time. Flow rankings cover the
  currently retained idle-timeout window. They are not a historical database of
  every closed connection. The longest-open ranking excludes FIN/RST flows.
- Traffic rankings and protocol/application distributions are cumulative since
  telemetry startup. **Chart range** controls the time-series window only.
  **Filter Top rows** searches the server's returned Top results, not all flows or
  counters. The existing Focus/Hunt tools remain available for forensic filtering.
- Port rankings count both source and destination port incidences (identical
  ports once per packet). They include ephemeral client ports. Endpoint volume
  combines sent and received bytes (identical endpoints once). Packet-size
  distribution is ranked by packet count and uses captured frame size.

## Retention and resource bounds

The central `internal/telemetry` store receives live metadata directly from the
packet pipeline, without a lossy event-bus subscription. Packet updates do not
scan retained forensic flow snapshots. One context-bound sampling worker records
one-second intervals and reads all Linux device counters once per second.

Each scope keeps 900 second samples and 1,440 minute samples. Thus **Live**, 1m,
5m, 15m, 1h, 6h and 24h charts become available as actual samples accumulate.
History is in memory and resets on restart; no samples are invented before startup.
History responses are downsampled to at most 360 points using sums and measured
sample durations. A browser retains at most 900 samples and updates an existing
canvas. Longer ranges refresh coarse history every 30 seconds while counters stay
live. Chart peaks are peaks of the displayed interval averages, not subsecond peaks.

Limits are 64 scopes including global, 4,096 labels per aggregation group,
100,000 retained labels across groups/scopes (plus bounded overflow labels),
50,000 conversations per scope and 100,000 across scopes. Once label capacity is
reached, unseen labels accumulate under `Other (cardinality limit)`. Packet/byte
counters continue to count observations. Rankings become partial and the response
sets `limited`; the UI flags this. Exhausting conversation capacity also sets
`flow_limited`, hiding potentially incomplete flow counters. Label overflow alone
does not hide accurate flow counters.
The server returns at most 20 rows per ranking; the UI pages five rows at a time.
Snapshots are cached per scope for one second. Top-flow selection retains only
20 candidates per metric, avoiding full-flow sorting/copies on every client update.

The UI preserves inputs and DOM nodes between updates, stops streams while hidden,
closes them on navigation/logout/pause, and reconnects after disconnection. Motion
stops when telemetry is stale or paused and honors `prefers-reduced-motion`. Arrow
width and speed increase monotonically with observed bitrate and packet rate;
exact measurements remain visible beside them.

## API

Both additive routes use existing console ACL/authentication and `read:telemetry`:

- `GET /api/v1/telemetry?interface=eth0&range=5m` returns `snapshot` and `history`.
- `GET /api/v1/telemetry/stream?interface=eth0&range=5m` streams named `telemetry`
  SSE events. Omit `interface` for global observations. Omit `range` for Live.

A stream event contains a `snapshot` and, initially/every 30 seconds, `history`.
`snapshot.current` contains complete measured-interval counts and `seconds`;
convert bytes to bit/s as `bytes * 8 / seconds`. Direction arrays are ordered
inbound, outbound, forwarded, unknown. Device `rx`/`tx` are nullable interval
counts; use `kernel_seconds` for device rates. `snapshot.kernel` contains nullable
absolute device counters. `snapshot.time` is the latest sampler time, enabling
staleness detection. `groups` contains ranked `{key, bytes, packets, flows}` rows.
Unsupported ranges return 400; missing scopes 404; absent telemetry 503; non-GET
requests 405. Sessions/tokens are revalidated during streaming. A five-second
write deadline bounds slow consumers; request cancellation releases the ticker.
Existing `/ws`, `/api/v1/traffic/*`, flow and packet API contracts remain available.
The legacy traffic chart preserves its previous forwarded accounting semantics;
use Top Analytics for separately counted directions.

## Application identification

The built-in DPI engine retains stream reassembly and existing protocol packs.
Port-only application hints have been removed. Arbitrary traffic on ports 22, 53,
80, 443, 3389 or 51820 is not sufficient evidence of an application. UDP/443 is
no longer automatically QUIC. The HTTP/2 recognizer requires its connection
preface; Redis recognition no longer mistakes arbitrary HTTP GET text for Redis.

Application labels use parsed protocol messages or exact DNS-boundary matching
of observed HTTP Host/TLS SNI. Additive fields `dpi.evidence` and
`dpi.matched_host` expose the basis. DNS questions alone never label a connection
as YouTube or another named service. SNI/Host identifies an advertised service
hostname, not authenticated ownership, decrypted content or an installed client;
these metadata can be spoofed. Shared cloud/CDN names identify that infrastructure
only. No IP geolocation, generic CDN address or port inference is used.

The hostname catalog covers YouTube, Netflix, Spotify, WhatsApp, Telegram,
Discord, Zoom, Microsoft Teams, Slack, GitHub, GitLab, Dropbox, Google Drive,
OneDrive, AWS, Azure and Cloudflare where an explicit matching hostname is visible.
The catalog lives in `internal/dpi/applications.go`; keep additions narrow and
include positive and deceptive-suffix tests. Self-hosted deployments/custom domains,
ECH, proprietary encrypted traffic and unsupported signatures remain generic
protocol classifications or **Unknown / Unclassified**. Protocol recognition
includes existing HTTP, HTTP/2, TLS, DNS, SSH and protocol packs, plus SIP, SMTP,
FTP/IMAP/POP3 greetings, BitTorrent handshake and WireGuard handshake shapes.
OpenVPN and RTP are not guessed. QUIC support validates supported v1 long-header
metadata; it does not decrypt QUIC to infer HTTP/3 or an application hostname.

Signature references:

- [BitTorrent BEP 3 handshake](https://www.bittorrent.org/beps/bep_0003.html)
- [WireGuard protocol](https://www.wireguard.com/protocol/)
- [QUIC RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)

## Validation

Run `make test` for formatting, JS syntax, embedded-asset parity, `go vet`, all
Go tests, race detection, both static Linux architectures and staged installation.
Run `scripts/integration-ui-browser.sh` for real Chromium/loopback traffic checks.
It requires Chromium, Node, curl, Python, iproute2 and unprivileged network/user
namespaces. It tests live analytics, stable input/DOM identity, pause/resume, range
switching, interface navigation and RX/TX, hover, legend visibility, three viewport
sizes and short-run heap behavior. Set `NETPROBE_UI_SCREENSHOTS` to a directory to
save responsive screenshots. This short-run check is not a long-duration soak test.

Run `go test ./internal/telemetry -run '^$' -bench . -benchmem` to measure packet
aggregation and snapshot cost with 10,000 conversations. Fixtures are confined to
tests; no fixture data is served in the application.
