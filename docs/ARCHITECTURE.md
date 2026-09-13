# Architecture

[Türkçe](ARCHITECTURE_TR.md) · **English** · [Documentation index](README.md)

## Data path

```text
Linux interface(s)
      │
      ▼
AF_PACKET / SOCK_RAW
      │
      ▼
Ethernet/VLAN/IP/TCP/UDP decoder
      │
      ├──────────────► PCAPNG flight recorder
      │
      ▼
Endpoint/direction classifier
      │
      ├──────────────► /proc socket inode -> PID mapper
      │
      ▼
Flow key / state
      │
      ▼
Stateful DPI
      │
      ▼
Flow store ──────────────► bounded recent packet metadata ring
      │
      ├──────────────► Native IDS / IOC / stateful security findings
      │                    │
      │                    └────► incident PCAP preservation
      │
      ├──────────────► Anomaly engine
      │                    │
      │                    └────► incident PCAP preservation
      ▼
REST / WebSocket / metrics / reports
      │
      ▼
Embedded web UI
```

## Capture

The current passive backend uses `TPACKET_V3/PACKET_MMAP` per selected interface when the host supports it, with automatic `AF_PACKET/SOCK_RAW` fallback. The receive buffer is configurable. The binary requires `CAP_NET_RAW` or root privileges.

A bounded frame channel provides explicit backpressure. If the consumer cannot keep up, drop counters increase and the UI reports degraded capture health. The software does not silently hide packet loss.

## Decoder

The decoder accepts Ethernet frames and supports:

- 802.1Q and 802.1ad VLAN stacking
- IPv4
- IPv6
- common IPv6 extension headers
- first IPv6 fragment transport decoding
- TCP
- UDP
- ICMP
- ICMPv6

Malformed or truncated packets are rejected without panicking.

## Process attribution

The process mapper builds two synchronized snapshots:

1. `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`
2. `/proc/<pid>/fd/* -> socket:[inode]`

It joins those datasets on socket inode and enriches matches with:

- PID / PPID
- UID / username
- comm
- executable path
- command line
- cgroup
- best-effort container metadata

Exact 5-tuple matches are preferred. Connected or wildcard listeners can fall back to a local socket mapping. Short-lived connections get a throttled immediate refresh after a miss.

Forwarded traffic with neither endpoint owned by the local host is explicitly marked `forwarded` rather than assigned a fabricated process.

## Flow identity

A local/remote flow identifier is derived from:

```text
L4 protocol | local IP:port | remote IP:port
```

and hashed to a compact stable ID for the in-memory lifetime of the flow.

The flow tracks:

- first/last seen
- observed interfaces
- TX/RX packets and bytes
- TCP flags
- process attribution
- DPI metadata
- risk score/reasons

Idle flows are garbage collected after the configured timeout.

## Stateful DPI

TCP payloads are buffered per direction up to a configurable maximum. A bounded pending-segment map handles common out-of-order startup cases. DPI parsers consume reconstructed startup bytes rather than assuming a full application message fits inside one packet.

Current native parsers:

- HTTP/1.x
- DNS UDP/TCP
- TLS ClientHello
- SSH banners
- service/port hints

TLS ClientHello extraction includes SNI, ALPN, supported version, cipher/extension counts, standards-compatible JA3 and a short NetProbe fingerprint.

Payload is never falsely presented as decrypted TLS content.

## Anomaly engine

The anomaly engine is intentionally explainable. It currently scores:

- high outbound byte volume
- destination fan-out
- remote endpoint/port scan behavior
- short-window connection bursts
- periodic beaconing using inter-arrival coefficient of variation
- high-entropy DNS names

Alerts have rule IDs, severity, score and evidence. Flow risk stores human-readable reasons.

## Native IDS and security findings

The native IDS receives each decoded packet plus its correlated flow, DPI result, direction and packet-history ID. Deterministic signatures, exact operator-supplied IOCs, boundary policy checks and bounded stateful correlation create `SecurityFinding` records. Severity is intentionally independent of verdict/confidence. High/critical findings invoke the recorder evidence-protection hook. Custom JSON rules are loaded once at startup and use Go RE2 for regex matches.

The anomaly engine remains separate because heuristic baseline behavior should not be visually or semantically conflated with deterministic signature/IOC evidence.

## Server-side Focus/Hunt

`Engine.Hunt` parses the same `field:value` language exposed by the UI and searches retained flows, packet metadata, process summaries, behavioral alerts and security findings. The browser still performs local filtering for instant interaction, but the Hunt workspace refreshes from `/api/v1/hunt` so it is not limited to the current WebSocket slice.

## Per-interface lifecycle

Capture lifecycle is tracked per interface. Each capture session has its own context, AF_PACKET socket, generation, running/stopping state and timestamps. Global pause/resume operates on every session; interface control endpoints act on one session while keeping other sessions active.

## Flight recorder

PCAPNG is written in size-bounded rotating segments. The recorder uses a bounded queue and exposes recorder drops.

On a high-severity alert the current segment is closed first, then recent closed segments are copied to the incident directory. Closing before copying ensures block-complete forensic files.

## Web/control plane

The HTTP server is part of the same static binary. HTML/CSS/JavaScript assets are embedded at build time and require no external frontend runtime.

The console is a white SOC/NOC-style single-page interface with executive Overview, Security Findings, Live Traffic, Applications, Assets, Investigation Graph, Attack Stories, Detection Quality, Response Playbooks, SOC Performance, Hunt/Search, Behavioral Alerts and administration routes. Hash routing preserves browser Back/Forward behavior and breadcrumbs. The live IN/OUT chart uses bounded server-side packet-metadata buckets plus incremental WebSocket points; retained flow volume drives protocol distribution.

The control plane exposes status, flows, recent packet metadata, process summaries/details, behavioral alerts, native security findings, server-side Hunt, per-interface capture control, reports, metrics and WebSocket telemetry. The recent packet history is intentionally bounded to 1000 metadata records; raw packet evidence belongs in the PCAPNG flight recorder.

Capture lifecycle is split from daemon lifecycle. `POST /api/v1/control/stop` cancels AF_PACKET acquisition and waits for capture goroutines to close while the HTTP server and retained forensic context remain available. `POST /api/v1/control/start` creates a new capture session inside the same daemon. This is what makes Start/Stop from the web UI technically possible.

Control actions require POST, pass through the normal API authentication wrapper, and browser requests with an Origin header are restricted to the same origin to reduce loopback-console CSRF risk. Remote listening is refused without authentication unless the operator explicitly overrides the safety check.

## High-performance target backend

For sustained multi-gigabit capture the recommended future data plane is:

```text
XDP -> AF_XDP UMEM/rings -> zero-copy decoder/DPI
             +
eBPF connect/accept/send/recv events -> socket cookie -> PID/cgroup
```

That backend should preserve the same flow/DPI/anomaly/web interfaces so the rest of the application remains unchanged.
