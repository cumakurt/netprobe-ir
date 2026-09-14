# NetProbe IR — Linux Network Forensics & Runtime Network Observability

[Türkçe](README_TR.md) · **English** · [Documentation](docs/README.md)

NetProbe IR is a Linux **host network forensics, live traffic visibility, and process-to-network correlation** sensor. Its purpose is not merely to list addresses and ports. Whenever Linux exposes enough evidence, NetProbe IR builds this chain:

```text
packet → flow → socket → PID → executable → user/cgroup/container
      → application protocol → behavior/anomaly → PCAP evidence → report
```

The release package contains **fully static Linux binaries** with no mandatory shared-library runtime dependency. Packet capture, `/proc` process attribution, focused native DPI, an embedded web UI, WebSocket telemetry, explainable anomaly rules, a rotating PCAPNG flight recorder, and HTML/JSON reporting are provided in one application.

> **Authorization:** use NetProbe IR only on systems and networks you own or are explicitly authorized to monitor. PCAP evidence may contain credentials, session data, personal information, or proprietary content.

---

## Project information

| Field | Value |
|---|---|
| Project | NetProbe IR |
| Version | 1.0.0 |
| Developer | **Cuma KURT** |
| Email | **cumakurt@gmail.com** |
| LinkedIn | https://www.linkedin.com/in/cuma-kurt-34414917/ |
| Repository | https://github.com/cumakurt/netprobe-ir |
| License | **GNU General Public License v3 — GPL-3.0-only** |

The installed binary exposes the same metadata:

```bash
netprobe-ir --about
```

The complete license text is in `LICENSE`; `AUTHORS` and `COPYRIGHT` contain developer and copyright metadata.

## Product tour

The screenshots below are captured from the v1.0.0 web console and show real product views rather than illustrative mockups.

### Executive overview

<p align="center">
  <img src="img/Screenshot%202026-09-13%20at%2010-35-35%20NetProbe%20IR%20%E2%80%94%20Security%20%26%20Network%20Forensics%20Console.png" alt="NetProbe IR executive overview" width="900">
</p>

### Investigation graph

<p align="center">
  <img src="img/Screenshot%202026-09-13%20at%2010-37-31%20NetProbe%20IR%20%E2%80%94%20Security%20%26%20Network%20Forensics%20Console.png" alt="Interactive NetProbe IR investigation graph" width="900">
</p>

### Attack stories and detection quality

<p align="center">
  <img src="img/Screenshot%202026-09-13%20at%2010-37-59%20NetProbe%20IR%20%E2%80%94%20Security%20%26%20Network%20Forensics%20Console.png" alt="NetProbe IR attack stories" width="900">
</p>

<p align="center">
  <img src="img/Screenshot%202026-09-13%20at%2010-38-08%20NetProbe%20IR%20%E2%80%94%20Security%20%26%20Network%20Forensics%20Console.png" alt="NetProbe IR detection quality center" width="900">
</p>

### SOC performance and telemetry health

<p align="center">
  <img src="img/Screenshot%202026-09-13%20at%2010-38-25%20NetProbe%20IR%20%E2%80%94%20Security%20%26%20Network%20Forensics%20Console.png" alt="NetProbe IR SOC performance and telemetry health" width="900">
</p>

Additional views are available in the [`img/`](img/) directory.





## v1.0.0 Production Investigation, Notifications & Live Traffic

v1.0.0 is the first production-readiness milestone focused on high-density investigation usability, context-aware asset pivots, secure notification management and real telemetry-driven IN/OUT traffic visibility. It reuses the existing capture/event/RBAC/audit architecture rather than adding parallel pipelines.

### Interactive Investigation Graph

- Canvas rendering instead of one DOM element per node;
- wheel/trackpad zoom, pan, Fit to Screen, Reset View and Center Graph;
- single select, Ctrl/Command/Shift multi-select and rectangle selection;
- multi-node drag with session-scoped position persistence;
- node/edge hover and detail panel;
- source/destination IP, asset, protocol, port, application, severity and time-range filters;
- server-side filtering, neighborhood focus, clustering, edge aggregation and bounded node/edge output;
- context actions into Traffic, Flows, Security Findings and Assets.

### Dynamic Assets

Assets are clickable observed entities. Detail views expose only evidence actually present in retained telemetry: IP/name, process/user/container/pod/interface identity, first/last seen, IN/OUT/total traffic, flow count, protocols, ports, related findings and related assets. MAC/hostname fields are never fabricated when unavailable. Asset actions pivot directly into Traffic, Flows, Security Findings or the Investigation Graph with context preserved.

### Notification Management

System Settings now manages Email/SMTP and Telegram notifications with independent severity routing. SMTP supports clear text, STARTTLS and implicit TLS/SSL, sender/recipient lists, timeout and test delivery. Telegram supports bot token, chat ID, timeout and test delivery. Notification delivery is asynchronous through a bounded queue with finite retries, bounded exponential backoff, deduplication/cooldown and delivery/drop statistics. SMTP passwords and Telegram bot tokens are encrypted at rest, masked in normal API/UI responses and never intentionally logged.

### Real Live IN / OUT Traffic

Overview contains a telemetry-driven IN/OUT chart backed by the existing packet-metadata event bus. The server maintains bounded one-second buckets and downsampled history for 1m, 5m, 15m, 1h and 24h windows. The UI supports bits/sec, bytes/sec, packets/sec and flows/sec, current/peak values, hover details and Pause/Resume of UI updates without stopping backend capture.

### Release qualification

v1.0.0 includes Go unit/integration tests, full repository race-detector coverage, local/mock SMTP and Telegram tests, 5,000-flow graph bounding tests, live-traffic history/downsampling tests, real Chromium console E2E, real Linux capture/IDS/Hunt regression and real TLS SNI/ALPN/JA3/JA4/NPSH regression. See `docs/ADVANCED_V10.md` and `TEST-RESULTS.md`.

## v0.9.0 interoperability, executive security and response automation

v0.9.0 keeps the complete v0.8.1 detection-quality/root-cause stack and adds an interoperability and executive-operations layer. The design objective is to turn large volumes of packet, runtime and detection telemetry into a smaller set of decision-ready incidents while making those events easier to export, correlate and automate.

### CISO-oriented Overview and unified investigation

- **Interface Acquisition was removed from Overview**. Interface-level acquisition health remains available under Interfaces and the new **SOC Performance** workspace.
- Every top KPI card is now a drill-down link. **Active Flows** opens Live Traffic, findings open Security Findings, process/application KPIs open Applications, and captured-data KPIs open traffic evidence.
- Executive panels add posture score, 24-hour risk trend, evidence-confidence distribution, Attack Story/exploit/root-cause coverage, Detection Quality and Fleet resilience.
- Attack Stories can open a **Unified Investigation Workspace** combining graph, risk timeline, probable root cause, files, runtime events, exploit correlation, TLS infrastructure and DNS graph context.

### Canonical events and detection interoperability

- **OCSF-compatible canonical event envelopes** for findings, flows and runtime events through `/api/v1/ocsf`; this is deliberately described as OCSF-compatible rather than exhaustive OCSF coverage.
- **Sigma correlation planning** for event/value counts, temporal and ordered-temporal correlations, group-by, timespan and thresholds.
- **Suricata/Snort rule import analyzer** with explicit supported/unsupported option reporting and coverage scoring; unsupported syntax is never silently discarded.
- Rule translation remains non-executing: imported text is parsed/analyzed and converted to deterministic NetProbe query/rule structures.

### Response playbooks

- Persistent playbooks with `dry_run`, `approval_required` and explicit `automatic` modes.
- Conditions can require severity, confidence, verdict, category, tags, YARA or KEV evidence.
- Actions reuse the existing Case, PCAP-protection and Active Response primitives. Automatic mode cannot bypass the global response enable/dry-run flags, action allowlist, target allowlist or response safety checks.

### Historical analytics, infrastructure intelligence and assets

- Bounded historical analytics for flow/finding/runtime summaries with time/type/severity/process/destination queries.
- Host/package **Asset Intelligence** and CycloneDX/SPDX inventory export.
- Optional local CIDR enrichment with ASN, organization and country metadata.
- TLS certificate/SPKI clustering with SAN/self-signed/expiry context and IP/SNI/JA4 reuse.
- DNS domain→IP infrastructure graph with diversity/churn and fast-flux-like context.
- Runtime anomaly detections for high-signal Linux behavior such as `memfd_create`, `ptrace`, deleted/temp-directory execution and sensitive namespace/mount/capability activity when observed.

### eBPF, performance, profiles and supply chain

- Auditable **CO-RE eBPF source/build/readiness path** plus the existing adaptive bpftrace and `/proc` fallbacks. The release host did not provide a BTF/libbpf/bpftool environment, so this package does not claim a live native CO-RE pass on the release host.
- **SOC Performance** page for acquisition errors/drops, recorder/export pressure, interface health, runtime-sensor readiness and a bounded synthetic regression benchmark.
- Experimental OpenTelemetry Profiles HTTP adapter kept outside detection/response decisions.
- Release tooling emits **CycloneDX SBOM, SPDX SBOM, provenance and SHA-256 manifests**, supports `SOURCE_DATE_EPOCH`, and can optionally sign the release checksum manifest with the existing Ed25519 evidence key.

Multi-tenant isolation remains intentionally out of scope. Detailed semantics, APIs, security boundaries and non-claims are in `docs/ADVANCED_V09.md`.

## v0.8.1 Detection Quality & Root-Cause Release

v0.8.1 keeps the v0.8 full-width responsive console and adds a focused investigation-quality layer. The core goal is **fewer ambiguous alerts and more evidence-backed incidents**.

Major additions:

- persistent **Detection Quality Center** fed by labeled Detection Lab runs; per-rule TP/FP/FN, precision, recall and quality score;
- **Attack Story v2** with file/runtime/network stages, risk timeline and explicit probable-root-cause inference;
- adaptive **eBPF/bpftrace runtime event discovery** that uses syscall tracepoints actually available on the host and falls back to `/proc`;
- **Sigma Engine v2** with named selections, common boolean conditions and common modifiers plus coverage/warning reporting;
- **CVE/KEV runtime exploit correlation** that preserves the boundary between exposure context and version proof;
- **C2 Analytics v2** using jitter, size similarity, periodicity, TX/RX, destination rotation and JA4 reuse;
- **Fleet Health v2** with online/stale/offline state and version/config/rules drift;
- new SOC UI surfaces for detection quality, root cause, risk timeline, runtime evidence and fleet health;
- new Prometheus/health metrics for the v0.8.1 analytics.

Multi-tenant isolation remains intentionally out of scope. See `docs/ADVANCED_V081.md` for the full data model, APIs, security boundaries and non-claims.

## v0.8.0 correlation, sigma and console design refresh

v0.8.0 builds on the complete v0.7 runtime-security stack and focuses on three goals: **stronger operator workflow**, **better rule portability**, and a **visibly clearer console** that fills the page gracefully from narrow laptops to large SOC displays.

### Security and analytics additions

- strengthened **eBPF/runtime attribution readiness** surfaces through the existing runtime-attribution layer and explicit capability reporting in health/status paths;
- **Sigma subset import/translation** via `netprobe sigma --in rule.yml --format query|npdl`, allowing a pragmatic subset of Sigma rules to be converted into NetProbe hunt queries or starter NPDL content;
- continued **CVE/KEV exposure correlation**, Detection Lab, Attack Stories and Fleet workflows from v0.7 as the primary v0.8 investigation spine;
- the single-node product deliberately still excludes **multi-tenant isolation** in this release, as requested.

### Web console and UX refresh

- same light theme, but improved **color contrast**, iconography, emoji-assisted navigation and card hierarchy;
- wider full-page layout with improved use of horizontal space on large screens;
- more adaptive `auto-fit` grids so cards, KPIs and operational panels resize more naturally;
- better mobile and narrow-window handling with an overlay sidebar, close button, sticky focus bar and denser top bar wrapping;
- UI refinements for Fleet, Stories, Lab, Operations and streaming/export views without changing the underlying APIs.

## v0.7.0 advanced analytics, malware evidence and extensibility

v0.7.0 preserves the complete v0.6 Syslog/Flow export plane and the earlier capture/DPI/IDS/Hunt/SOC stack, then adds a new **runtime-security and investigation layer**. The goal is to answer not only “what traffic occurred?” but also “what process/file/identity produced it, what security context surrounds it, and what evidence should an analyst retain?”

### Network files and malware evidence

- bounded reconstruction of supported HTTP/1 downloads, SMTP/MIME attachments, FTP data transfers and SMB2 write-oriented objects;
- SHA-256, SHA-1, MD5, MIME type, size and Shannon entropy for each artifact;
- optional asynchronous **YARA-X** scanning through the external `yr` runtime;
- YARA-X matches become high-confidence/critical security findings and are linked into flows, processes, Attack Stories and Investigation Graph evidence;
- **Files & Malware** web workspace with drill-down to flow/process/hash/YARA context;
- Smart-PCAP privacy policy also gates file reconstruction, so `headers`, `metadata` and `drop` retention modes cannot silently preserve application payload through the file subsystem.

### Semantic detection and protocol coverage

- **NPDL — NetProbe Detection Language**, a non-Turing-complete detection scripting language for process, flow, packet, TLS, HTTP and file fields;
- cleartext HTTP/2 (`h2c`) preface and SETTINGS metadata;
- deeper QUIC long-header/version/DCID/SCID/Retry/version-negotiation metadata and HTTP/3 transport classification without pretending encrypted QPACK headers are visible;
- selectable protocol packs: `core`, `enterprise`, `database`, `devops`, `ics`;
- enterprise/database/OT signatures and port-aware hints for Kerberos, LDAP, SMB, RDP, Redis, PostgreSQL, MySQL, Modbus/TCP, DNP3, Siemens S7/ISO-on-TCP and BACnet/IP;
- lateral-movement and NTLM authentication fan-out correlation;
- encrypted-DNS intelligence for DoT/DoQ/DoH/DoH-like behavior with process allowlists;
- process/user/container/pod/service identity baselines for new-destination, new-application and unusual-hour deviations;
- jitter-aware C2 beacon analytics using median interval, relative MAD, transfer-size similarity and periodicity.

### Vulnerability, streaming, fleet and plugin capabilities

- dpkg/rpm/apk package inventory plus CISA-KEV-compatible catalog ingestion; name overlaps are explicitly labeled **exposure context**, not proof that the installed version is vulnerable;
- event streaming adapters for OTLP/HTTP Logs, NATS Core, Kafka through `kcat`, and ClickHouse JSONEachRow;
- external `wasmtime` WASI plugin runner with per-invocation timeout and output limits; NetProbe grants no filesystem/network preopens to plugins;
- fleet command queue/poll/ack workflows on top of the existing bounded sensor federation model;
- sensor self-protection for watched-file hash changes, watched-file disappearance, low disk space and backward clock movement;
- evidence-based Analyst with deterministic local mode and optional remote OpenAI-compatible `/chat/completions` mode using a bounded retained-evidence pack. The Analyst is never part of IDS or response decision logic.

### Important optional dependencies

The NetProbe binary itself remains static. Advanced integrations are capability-driven:

| Feature | Optional external runtime |
|---|---|
| YARA-X scanning | `yr` |
| WASM plugins | `wasmtime` |
| Kafka streaming | `kcat` |
| eBPF attribution | `bpftrace` plus compatible kernel/permissions |
| Active response | platform tools such as `nft` plus appropriate privilege |

If an optional executable is missing, only that capability becomes unavailable/degraded; capture, DPI, IDS and the web console continue operating.

For the full v0.7 security model, field semantics, configuration examples and explicit non-claims, read `docs/ADVANCED_V07.md`.

## v0.6.0 standards-based export plane

v0.6.0 keeps the full v0.5 authentication/SOC and v0.4 sensor/forensics stack and adds real-time, non-blocking export to external SIEM and flow collectors:

- multiple Remote Syslog destinations from **System Settings**, independently enabled/disabled and health-monitored;
- UDP, TCP and TLS Syslog, RFC 3164, RFC 5424, RFC 5425 secure mode and RFC 6587 octet-counting/non-transparent framing;
- TLS CA validation, custom CA files and optional client-certificate/mTLS; private-key paths are redacted from normal API responses;
- structured live `security`, `network`, `flow`, `dpi`, `dns`, `http`, `tls`, `anomaly` and `system` event categories without uncontrolled raw-payload export;
- multiple simultaneous NetFlow v5, NetFlow v9, IPFIX/v10 and sFlow v5 collectors;
- IPv4/IPv6 v9/IPFIX/sFlow, v9/IPFIX template refresh, Observation Domain IDs, source-interface filtering, sampling and active/inactive flow timeouts;
- unidirectional NetFlow/IPFIX records and delta counters across active-timeout exports to prevent collector double-counting;
- sFlow packet sampling directly from live packet-metadata events using sampled IPv4/IPv6 records;
- bounded per-destination queues, non-blocking event-bus publication, drop counters and reconnect/backoff;
- authenticated/RBAC-protected CRUD/test APIs, audit logging, persistence, web health cards and Prometheus metrics.

The complete protocol, security, API, persistence and test model is documented in `docs/EXPORT_SYSLOG_FLOW.md`.

## v0.5.0 security and SOC operations layer

v0.5.0 keeps the v0.4 sensor/forensics foundation and adds a secure multi-user management plane:

- default `admin` username with a random installer-generated one-time bootstrap password and mandatory first-login password change,
- PBKDF2-HMAC-SHA256 password storage, brute-force lockout, idle/absolute session limits and session revocation,
- `HttpOnly` + `SameSite=Strict` session cookies and same-origin protection for mutating browser-session requests,
- continuous authorization revalidation for long-lived WebSocket telemetry,
- `admin / responder / analyst / viewer` RBAC with last-enabled-admin protection,
- TOTP MFA and single-use recovery codes,
- scoped/expiring API tokens and revocation,
- OIDC Authorization Code + PKCE with RS256/JWKS verification,
- HMAC-SHA256 chained tamper-evident Audit Trail,
- two-person Active Response approval,
- Attack Stories, MITRE ATT&CK aggregation, Asset Identity, Time Machine and baseline diff,
- Detection Tuning with expiring suppressions,
- webhook and CEF/LEEF syslog integration,
- authenticated encrypted backup/restore using AES-256-CTR + HMAC-SHA256 Encrypt-then-MAC,
- management CIDR lockdown, signed-configuration controls and forensic-immutable case protection.

See `docs/AUTH_SECURITY.md` for the complete identity/security model.

### v0.4.0 sensor/forensics foundation


In addition to the v0.3 IDS/Hunt console, v0.4.0 adds:

- passive high-throughput `TPACKET_V3/PACKET_MMAP` capture with automatic AF_PACKET fallback; AF_XDP capability is reported but passive redirect is intentionally not enabled because it can consume host traffic without an inline forwarding design,
- optional `bpftrace`-driven eBPF attribution events with automatic `/proc` fallback when eBPF tooling/capability is unavailable,
- offline PCAP/PCAPNG replay through the same decode/DPI/IDS/Hunt pipeline,
- JA4 client fingerprinting, NetProbe TLS Server Fingerprint (NPSH), QUIC long-header metadata/fingerprint and observable TLS certificate metadata,
- STIX 2.1 file import and TAXII 2.1 threat-intelligence collection,
- process-aware behavioral baselining,
- incident cases, analyst notes, evidence collection and signed evidence ZIP export,
- investigation graph views linking processes, flows, IPs, domains, TLS metadata, interfaces and findings,
- Detection Lab with rule lifecycle (`draft`, `test`, `enabled`, `deprecated`) and Ed25519 rule-pack signatures,
- guarded active-response actions with dry-run default, allowlists, TTL rollback and explicit `APPLY` confirmation,
- distributed sensor metadata/finding/flow federation while leaving PCAP evidence on the sensor by default.

Run `netprobe-ir replay <capture.pcapng>` for offline analysis and `netprobe-ir rules sign|verify` for rule-pack integrity operations. See `docs/IMPLEMENTATION_STATUS.md` for verified limitations.

---

# 1. Quick start

After extracting the release:

```bash
chmod +x install.sh uninstall.sh
sudo ./install.sh
```

Default UI:

```text
http://127.0.0.1:8443
```

On systemd hosts:

```bash
systemctl status netprobe-ir
journalctl -u netprobe-ir -f
```

Direct execution without installation:

```bash
sudo ./dist/netprobe-linux-amd64
```

ARM64:

```bash
sudo ./dist/netprobe-linux-arm64
```

---

# 2. Universal installer

`install.sh` is designed to keep distribution-specific assumptions to a minimum. Because NetProbe IR is shipped as a static binary, a normal installation does **not** require libpcap, OpenSSL, nDPI, Node.js, npm, Python, Go, or another language runtime.

The installer:

1. verifies Linux,
2. detects `amd64/x86_64` or `arm64/aarch64`,
3. reads `/etc/os-release`,
4. validates base POSIX installation utilities,
5. selects the matching bundled static binary,
6. verifies it against `dist/SHA256SUMS` when SHA-256 tooling is available,
7. can fall back to a GitHub release when the bundled binary is absent,
8. detects a package manager and installs only a minimal HTTPS downloader when the fallback actually needs one,
9. installs the executable, configuration, persistent data directories, documentation and license,
10. detects the init system,
11. installs/enables/starts service integration,
12. runs the installed binary's `--self-test`.

The normal console output intentionally stays concise: stage progress, useful facts, warnings and actionable failures are printed; package-manager noise is captured instead of flooding the terminal.

## Installer options

```text
--yes, -y          unattended/package-manager operations
--no-start         install without starting the service
--no-enable        do not enable the service at boot
--force-config     back up and replace an existing config.json
--bundled-only     never download a missing binary
--download-only    skip the bundled binary and fetch the configured release
--root <path>      stage below an alternate root; service start is skipped
-h, --help         help
```

Examples:

```bash
sudo ./install.sh
sudo ./install.sh --no-start
sudo ./install.sh --bundled-only
sudo ./install.sh --force-config
```

`--force-config` creates a timestamped backup before replacement.

## Init systems

Automatic integration is included for:

| Init | Installed integration |
|---|---|
| systemd | `/etc/systemd/system/netprobe-ir.service` |
| OpenRC | `/etc/init.d/netprobe-ir` and `/etc/conf.d/netprobe-ir` |
| runit | `/etc/sv/netprobe-ir/run` |
| SysV init | `/etc/init.d/netprobe-ir` |
| custom/unknown | binary/config are installed and manual startup is reported |

## Package managers used only for download fallback

If a release must be downloaded and neither `curl` nor `wget` exists, the installer recognizes common managers including:

```text
apt-get, dnf, yum, zypper, pacman, apk,
xbps-install, emerge, eopkg
```

A bundled installation normally invokes none of them.

---

# 3. Uninstall

Safe default removal:

```bash
sudo ./uninstall.sh
```

This stops/disables the service and removes executable/service/documentation files while preserving:

```text
/etc/netprobe-ir/
/var/lib/netprobe-ir/
```

The preserved paths may contain configuration, PCAP evidence, incident artifacts, and reports.

Permanent removal requires explicit purge:

```bash
sudo ./uninstall.sh --purge
```

For non-interactive purge:

```bash
sudo ./uninstall.sh --purge --yes
```

---

# 4. Installed layout

```text
/usr/local/sbin/netprobe-ir             canonical executable
/usr/local/sbin/netprobe                compatibility symlink
/etc/netprobe-ir/config.json            configuration
/var/lib/netprobe-ir/                   persistent capture/report data
/usr/local/share/doc/netprobe-ir/       documentation and license
```

Runtime data usually includes:

```text
/var/lib/netprobe-ir/
├── pcap/
├── incidents/
└── reports/
```

---

# 5. Core capabilities

- Ethernet and stacked VLAN parsing
- IPv4 and IPv6
- TCP, UDP, ICMP and ICMPv6
- per-interface packet/byte/drop/error accounting
- local/remote flow normalization
- TX/RX packet and byte counters
- `/proc/net/*` + `/proc/<pid>/fd` socket inode correlation
- PID, PPID, UID, username, executable, command line and cgroup enrichment
- best-effort container/cgroup metadata
- HTTP/1.x metadata DPI
- DNS over UDP/TCP parsing with A/AAAA answers
- TLS ClientHello SNI, ALPN, supported version, JA3 and NetProbe TLS fingerprint
- SSH banner detection
- selected service/port hints
- bounded TCP startup reassembly
- explainable exfiltration, fan-out, scan, burst, beacon and DNS-entropy rules
- rotating PCAPNG flight recording
- high-severity incident PCAP preservation
- embedded web UI
- REST API
- WebSocket live updates
- Prometheus-style metrics
- JSON/HTML reports
- remote-bind authentication guard
- optional TLS for the web server
- graceful-shutdown reports

---

# 6. Capture

The current v1.0.0 passive backend uses Linux `TPACKET_V3/PACKET_MMAP` per selected interface when available, with automatic `AF_PACKET/SOCK_RAW` fallback.

Supported parsing includes:

- Ethernet II
- 802.1Q / 802.1ad VLAN stacking
- IPv4
- IPv6 and common extension headers
- TCP
- UDP
- ICMP / ICMPv6

The pipeline is bounded. When processing cannot keep pace, NetProbe IR exposes capture/recorder drops instead of presenting a false “complete capture” state.

Selected interfaces:

```bash
sudo netprobe-ir --interface eth0
sudo netprobe-ir --interface eth0,wg0,docker0
```

When no interface is explicitly configured, eligible UP interfaces are discovered automatically.

---

# 7. Process attribution

The process mapper joins:

```text
/proc/net/tcp*
/proc/net/udp*
/proc/<pid>/fd/* → socket:[inode]
```

and enriches the selected PID using Linux procfs metadata.

Attribution labels include:

| Label | Meaning |
|---|---|
| `exact-socket` | strongest tuple/socket match |
| `local-socket` | local endpoint match |
| `wildcard-listener` | wildcard listener match |
| `forwarded` | routed/bridged traffic without a local owning process |
| `socket-not-mapped` | no reliable process match |

A throttled immediate refresh reduces the chance of missing short-lived sockets between periodic snapshots.

Attribution may still be constrained by `hidepid`, Yama/ptrace policy, PID namespaces, very short process lifetime, or traffic that is only forwarded through the host. NetProbe IR never fabricates a PID when the evidence is absent.

---

# 8. Native DPI

## HTTP/1.x

Request/response start line, method/path, Host, User-Agent and Content-Type metadata.

## DNS

UDP/TCP DNS query parsing and basic A/AAAA response metadata.

## TLS ClientHello

- SNI
- ALPN
- supported TLS version
- cipher/extension metadata
- standards-compatible JA3
- NetProbe TLS fingerprint

## SSH

SSH banner detection.

## Encrypted traffic limitation

NetProbe IR does not claim to decrypt TLS application payload without session keys. It exposes visible metadata and traffic behavior; encrypted content remains encrypted.

---

# 9. TCP startup reconstruction

DPI does not assume an application header arrives in one packet. Startup payload is buffered per direction with:

- in-order reconstruction,
- bounded handling of common out-of-order startup segments,
- `dpi.max_stream_bytes` memory protection.

---

# 10. Explainable anomaly engine

Current rules detect/score:

- high outbound volume / possible exfiltration,
- destination fan-out,
- remote port/endpoint scan behavior,
- connection bursts,
- periodic beaconing,
- high-entropy DNS names.

A flow keeps human-readable evidence in addition to a numeric risk score.

---

# 10A. Native IDS and Security Findings

NetProbe IR v0.4.0 adds a second security engine that is deliberately separate from the anomaly scorer. The **native IDS** evaluates packet flags, bounded payload/application signatures, stateful connection/DNS behavior, network-boundary policy and operator-supplied threat intelligence. Findings are visible immediately in the dedicated **Security Findings** workspace and are linked to packet, flow, interface and local-process evidence whenever attribution exists.

The central certainty model is:

```text
severity   = how urgent/impactful the observation may be
verdict    = what kind of evidence produced the observation
confidence = confidence in that observed pattern (0..100)
```

Verdicts are not interchangeable:

| Verdict | Interpretation |
|---|---|
| `confirmed_ioc` | exact match against an IOC supplied by the operator; it confirms the match, not the reputation source itself |
| `signature_match` | deterministic packet/application pattern matched; strong evidence of the pattern, not proof that exploitation succeeded |
| `confirmed_exposure` | directly observed insecure condition such as cleartext authentication |
| `policy_exposure` | high-risk boundary/policy condition requiring local validation |
| `behavioral` | stateful heuristic/correlation threshold; analyst validation required |

Built-in coverage includes TCP NULL/XMAS/SYN+FIN/SYN+RST scan patterns, multi-port scan/host sweep, Log4Shell-style JNDI, Shellshock, traversal, SQLi, command-injection and reverse-shell/EncodedCommand patterns, scanner User-Agents, cleartext HTTP Basic/FTP/Telnet/mail authentication, Internet-bound SMB, external inbound RDP, DNS tunneling/NXDOMAIN behavior, executable/script delivery over cleartext HTTP, oversized ICMP/tunneling behavior, and exact IP/domain/SNI/JA3 IOC matching.

The full rule catalog, exact verdict semantics, IOC schema, custom JSON rule format and limitations are documented in **`docs/IDS_SECURITY.md`**. Example files are provided as `configs/iocs.example.json` and `configs/ids-rules.example.json`.

Important: a behavioral or signature finding must not be read as automatic proof of compromise. A `signature_match` confirms that the specified pattern was observed. A `confirmed_ioc` confirms an exact match to the operator-provided IOC set, not that the IOC feed is independently correct.

---

# 11. PCAPNG flight recorder

When enabled, packets are written below:

```text
<data_dir>/pcap/
```

Default policy:

```text
64 MiB segments
1024 MiB rotating recorder disk budget
```

On a high/critical alert, the active segment is closed first and recent evidence is copied below:

```text
<data_dir>/incidents/
```

Disable packet recording when it is not required:

```bash
sudo netprobe-ir --no-recorder
```

Treat PCAP evidence as sensitive data.

---

# 12. Embedded SOC/NOC-style web console

The web console is embedded in the static executable and requires no Node.js, npm, nginx, Apache, or frontend runtime. The current UI uses a **white, high-contrast SOC/NOC layout** designed so the capture state, traffic pressure, process activity and anomalies are immediately understandable.

Default URL:

```text
http://127.0.0.1:8443
```

The persistent navigation contains Overview, **Security Findings**, Live Traffic, Applications, Interfaces, **Hunt / Search**, Behavioral Alerts and System views. Overview combines capture health, current throughput, packet rate, active flows, process/alert counters, a live TX/RX history chart, DPI protocol-distribution donut, top applications, recent alerts and recent flows.

## 12.1 Live visual telemetry

The throughput chart is calculated from consecutive WebSocket telemetry samples rather than fixed demo values. It shows TX and RX rates over the recent history window. The protocol chart groups retained flow volume by DPI protocol. Capture loss/error state is surfaced rather than hidden.

## 12.2 Clickable drill-down

The console uses hash-based routes so browser Back/Forward navigation, breadcrumbs and explicit Back controls remain usable. Clickable entities include:

```text
Flow        -> endpoints, L4/IP, interfaces, traffic, flags, attribution, DPI, process and risk reasons
Packet      -> timestamp, interface, direction, endpoints, length, flags, flow, process and DPI metadata
Application -> PID/PPID, user/UID, executable, command line, cgroup/container, flows, destinations and alerts
Security    -> severity, verdict, confidence, rule/category/MITRE, evidence, packet, flow, process and interface
Alert       -> rule, severity, score, description, evidence, PID, remote endpoint and related flow
Interface   -> packet/byte/drop/error counters plus flows and recent packets observed on that interface
```

Remote endpoints in the flow view can be clicked to return to Live Traffic with that address applied as the search filter.

## 12.3 Bounded packet metadata history

The UI does not retain unlimited raw packet payloads in memory. A bounded **1000-entry recent packet metadata ring** supports packet-level drill-down. Full raw evidence remains the responsibility of the rotating PCAPNG flight recorder when enabled.

```text
recent packet metadata -> interactive UI investigation
PCAPNG flight recorder -> raw forensic packet evidence
```

## 12.4 Start/Stop from the UI

The top bar and System view can pause or resume packet acquisition. **Stop capture does not terminate the daemon or web server**: it pauses AF_PACKET acquisition while preserving the console, retained evidence and reporting endpoints. Start capture resumes acquisition inside the same process.

This distinction is intentional; stopping the entire daemon would also remove the web endpoint needed to issue a subsequent Start command. Control routes are authenticated like the other API endpoints, accept POST only, and reject cross-origin browser control requests.

## 12.5 Per-interface capture control

Each Linux interface has its own acquisition session. The Interfaces workspace exposes **Start interface / Stop interface** controls that close or recreate only that interface's AF_PACKET socket. Other running interfaces continue to capture. Global Start/Stop still controls all sessions. Interface state, start/stop timestamps, packets, bytes, errors and drops remain visible independently.

## 12.6 Focus filters and server-side Hunt/Search

The global focus bar understands fielded queries such as:

```text
src:10.0.0.8 dst:1.1.1.1 proto:tcp app:tls process:curl
iface:eth0 dir:outbound severity:critical verdict:signature_match
rule:NP-IDS-1201 mitre:T1190
```

Supported fields include `src`, `dst`, `ip`, `sport`, `dport`, `port`, `proto`, `app`, `process`, `pid`, `iface`, `dir`, `severity`, `verdict`, `rule`, `mitre` and `category`. The advanced filter drawer provides common source/destination/protocol/application/process/interface/direction/severity fields without requiring query-language knowledge.

Focus narrows the investigation view; it does **not** change capture or delete surrounding PCAP evidence. The Hunt workspace calls `/api/v1/hunt`, so the search runs against retained daemon evidence instead of being limited to the browser's latest WebSocket slice. See `docs/HUNT_QUERY.md`.

The layout is responsive: desktop keeps the persistent SOC sidebar, while narrower displays use a collapsible menu and horizontally scrollable forensic tables without silently dropping columns.

The footer includes developer, email, repository, LinkedIn and GPLv3 information.

---

# 13. API, metrics and WebSocket

```text
GET /api/v1/status
GET /api/v1/flows?limit=500
GET /api/v1/flows/<id>
GET /api/v1/packets?limit=300
GET /api/v1/packets/<id>
GET /api/v1/processes
GET /api/v1/processes/<pid>
GET /api/v1/alerts?limit=500
GET /api/v1/findings?limit=1000
GET /api/v1/findings/<id>
GET /api/v1/hunt?q=<query>&limit=500
GET /api/v1/graph
GET /api/v1/assets
GET /api/v1/assets/<url-escaped-id>
GET /api/v1/traffic/live
GET /api/v1/traffic/history?range=1m|5m|15m|1h|24h
GET /api/v1/notifications
PUT /api/v1/notifications
POST /api/v1/notifications/test/email
POST /api/v1/notifications/test/telegram
POST /api/v1/control/start
POST /api/v1/control/stop
POST /api/v1/control/interface/<url-escaped-name>/start
POST /api/v1/control/interface/<url-escaped-name>/stop
GET /api/v1/report.json
GET /api/v1/report.html
GET /metrics
GET /ws
```

Examples:

```bash
curl http://127.0.0.1:8443/api/v1/status
curl 'http://127.0.0.1:8443/api/v1/flows?limit=100'
curl http://127.0.0.1:8443/metrics
curl -G http://127.0.0.1:8443/api/v1/hunt --data-urlencode 'q=severity:critical process:curl'
```

Authenticated request:

```bash
curl -H 'Authorization: Bearer LONG_RANDOM_TOKEN' \
  http://10.0.0.5:8443/api/v1/status
```

---

# 14. Remote web security

The default listener is loopback-only:

```text
127.0.0.1:8443
```

A remote bind should use authentication:

```bash
sudo netprobe-ir \
  --listen 0.0.0.0:8443 \
  --auth-token 'LONG_RANDOM_TOKEN'
```

TLS certificate/key:

```bash
sudo netprobe-ir \
  --listen 0.0.0.0:8443 \
  --auth-token 'LONG_RANDOM_TOKEN' \
  --tls-cert /etc/netprobe-ir/server.crt \
  --tls-key /etc/netprobe-ir/server.key
```

Prefer storing tokens in a root-readable config instead of the command line so they are less likely to leak through shell history or process listings.

---

# 15. CLI

```text
-config <file>          JSON configuration file
-listen <host:port>     web listener override
-interface <name>       capture interface; repeat or comma-separate
-data-dir <path>        data-directory override
-auth-token <token>     API/UI token override
-tls-cert <path>        TLS certificate
-tls-key <path>         TLS private key
-no-recorder            disable PCAPNG recorder
-self-test              run functional self-test and exit
-version                build/version information
-about                  project/developer/license information
```

---

# 16. Configuration

Installed configuration:

```text
/etc/netprobe-ir/config.json
```

Example:

```json
{
  "listen": "127.0.0.1:8443",
  "interfaces": [],
  "data_dir": "/var/lib/netprobe-ir",
  "auth_token": "",
  "allow_unauthenticated_remote": false,
  "capture": {
    "snap_len": 65535,
    "read_buffer": 4194304,
    "flow_idle_seconds": 120
  },
  "recorder": {
    "enabled": true,
    "segment_mb": 64,
    "max_disk_mb": 1024,
    "incident_copies": true
  },
  "dpi": {
    "max_stream_bytes": 131072
  },
  "anomaly": {
    "enabled": true,
    "exfiltration_mb": 100,
    "fanout_destinations": 50,
    "port_scan_ports": 30,
    "burst_connections": 80,
    "beacon_min_samples": 4,
    "beacon_max_jitter": 0.15,
    "dns_entropy_threshold": 4.2
  },
  "ids": {
    "enabled": true,
    "home_nets": [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    ],
    "port_scan_ports": 20,
    "host_sweep_hosts": 20,
    "window_seconds": 30,
    "dns_high_entropy_queries": 12,
    "nxdomain_threshold": 20,
    "ioc_file": "",
    "rules_file": "",
    "max_findings": 5000
  }
}
```

IDS-specific configuration:

- `ids.home_nets` defines organizational networks for external-boundary policy rules.
- `ids.ioc_file` points to an exact IOC JSON file; empty disables external IOC loading.
- `ids.rules_file` points to an optional custom JSON rule pack; empty means built-ins only.
- `ids.port_scan_ports`, `ids.host_sweep_hosts`, `ids.window_seconds`, `ids.dns_high_entropy_queries` and `ids.nxdomain_threshold` tune stateful rules.
- `ids.max_findings` bounds retained native IDS findings.
- rule/IOC parse errors are exposed by `/api/v1/status` and the System UI.

Core field reference:

| Field | Meaning |
|---|---|
| `listen` | Web/API bind address |
| `interfaces` | Automatic discovery when empty; otherwise the listed interfaces |
| `data_dir` | Root directory for PCAP, incidents, reports and persisted state |
| `auth_token` | Web/API bearer token |
| `allow_unauthenticated_remote` | Explicit remote-bind safety override; not recommended for production |
| `capture.snap_len` | Maximum retained bytes per frame |
| `capture.read_buffer` | Requested kernel socket receive buffer |
| `capture.flow_idle_seconds` | Idle-flow lifetime |
| `recorder.segment_mb` | Rotating PCAPNG segment size |
| `recorder.max_disk_mb` | Recorder disk budget |
| `recorder.incident_copies` | Preserve recent PCAP after important alerts |
| `dpi.max_stream_bytes` | Per-flow/direction reassembly memory limit |
| `anomaly.*` | Explainable behavior-detection thresholds |
| `ids.*` | Native IDS enablement, home networks, limits and external rule/IOC paths |

See `docs/IDS_SECURITY.md` before changing thresholds or assigning custom verdicts.

Restart after a service configuration change:

```bash
sudo systemctl restart netprobe-ir
```

---

# 17. Privileges and systemd hardening

Raw `AF_PACKET` capture requires `CAP_NET_RAW`; complete cross-user attribution also depends on procfs/security policy.

The packaged systemd unit runs as root but applies a constrained service sandbox including `NoNewPrivileges`, protected system/home/kernel settings, restricted address families and a capability bounding set.

See `docs/SECURITY.md` for the privilege and sensitive-data model.

---

# 18. Reports

A graceful `SIGINT`/`SIGTERM` shutdown writes:

```text
<data_dir>/reports/report-YYYYMMDD-HHMMSS.json
<data_dir>/reports/report-YYYYMMDD-HHMMSS.html
```

Current reports are also available through the API.

---

# 19. Static binary verification

From the project root:

```bash
sha256sum -c dist/SHA256SUMS
file dist/netprobe-linux-amd64
ldd dist/netprobe-linux-amd64
```

The binary is built with:

```text
CGO_ENABLED=0
```

and should not require mandatory application shared libraries.

---

# 20. Build and tests

Build static binaries:

```bash
./scripts/build-static.sh
```

Standard suite:

```bash
./scripts/test-all.sh
```

Real Linux HTTP/capture/process-attribution integration:

```bash
./scripts/integration-live-linux.sh
```

Real TLS ClientHello/SNI/ALPN/JA3 integration:

```bash
./scripts/integration-live-tls-linux.sh
```

Embedded binary self-test:

```bash
./dist/netprobe-linux-amd64 --self-test
```

Installer/uninstaller staging validation:

```bash
TMPROOT=$(mktemp -d)
sudo ./install.sh --root "$TMPROOT" --bundled-only
sudo ./uninstall.sh --root "$TMPROOT" --purge --yes
rm -rf "$TMPROOT"
```

See `TEST-RESULTS.md` and `docs/TESTING.md`.

---

# 21. Troubleshooting

### Raw socket permission error

Check service and privilege context:

```bash
systemctl status netprobe-ir
journalctl -u netprobe-ir -n 100 --no-pager
```

Containers may require explicit `CAP_NET_RAW` and access to the intended network namespace/interfaces.

### UI unavailable

```bash
ss -lntp | grep 8443
curl -v http://127.0.0.1:8443/api/v1/status
```

### Low process-attribution rate

Inspect procfs/Yama/PID namespace restrictions. `hidepid` and hardened procfs policies can legitimately prevent correlation.

### Recorder disk pressure

Reduce `recorder.max_disk_mb`, disable the recorder, and separately review retained incident evidence.

### Remote bind rejected

Configure a long auth token or intentionally change the remote-auth safety override only on an isolated management network.

---

# 22. Performance and implementation status

The v0.4.0 passive capture path uses `TPACKET_V3/PACKET_MMAP` when the host supports it and falls back automatically to AF_PACKET. The active backend is visible in interface status. Capacity still depends on PPS, packet size, CPU, NIC, flow cardinality, DPI/IDS load, interface count and recorder I/O; always watch drop/error counters under production load.

AF_XDP socket-family capability is probed, but NetProbe deliberately does **not** attach a passive XDP redirect dataplane: `XDP_REDIRECT` can consume packets from the normal host network path unless userspace implements an inline forwarding design. This release therefore prioritizes passive safety over claiming zero-copy capture.

Process attribution uses `/proc` by default and can consume compatible `bpftrace`/eBPF events when configured and available. If live eBPF tooling or permissions are missing, attribution falls back to `/proc` and the status API reports the effective backend.

The current v1.0 stack includes the v0.4 replay/evidence/threat-intelligence foundation, v0.5 authentication/SOC operations, v0.6 standards-based Syslog/Flow export, v0.7 runtime-security/extensibility, v0.8.1 detection-quality/root-cause, v0.9 interoperability/executive operations, and v1.0 interactive investigation, notifications and live traffic. Environment-conditional and deliberately unclaimed capabilities are documented in `docs/IMPLEMENTATION_STATUS.md`.

Still not claimed as complete enterprise functionality:

- passive AF_XDP zero-copy dataplane,
- TLS payload decryption/session-key import,
- nDPI or full Suricata/Snort community signature catalogs,
- encrypted HTTP/2/HTTP/3 header/payload decryption without session keys; v0.7 does parse cleartext h2c metadata and observable QUIC transport metadata,
- Kubernetes API enrichment,
- active-active controller consensus/distributed SQL; ClickHouse event streaming is available as an external analytics path.

See `docs/IMPLEMENTATION_STATUS.md` and `TEST-RESULTS.md` for the exact verified status.

---

# 23. Repository structure

```text
cmd/netprobe/                 CLI / daemon
internal/capture/             TPACKET_V3/AF_PACKET capture selection
internal/decode/              Ethernet/VLAN/IP/TCP/UDP/ICMP parser
internal/procmap/             socket inode → PID/process mapper
internal/dpi/                 TCP startup reconstruction + DPI
internal/flow/                flow store
internal/fileextract/         bounded network file reconstruction + YARA-X adapter
internal/scripting/           NPDL semantic detection engine
internal/beacon/              advanced periodic C2 analytics
internal/dnsintel/            encrypted-DNS behavior intelligence
internal/identitybaseline/    process/user/container/pod/service profiles
internal/lateral/             lateral-movement / NTLM fan-out correlation
internal/vulnintel/           package inventory + KEV exposure context
internal/smartpcap/           privacy-aware evidence retention policy
internal/streaming/           OTLP/NATS/Kafka/ClickHouse adapters
internal/wasmplugin/          optional wasmtime/WASI plugin runner
internal/selfprotect/         sensor integrity/disk/clock monitoring
internal/analyst/             evidence-constrained investigation assistant
internal/anomaly/             explainable rules
internal/baseline/            process-aware behavior baseline
internal/cases/               incident case store/export
internal/detectionlab/        replay-backed rule laboratory
internal/ebpfattr/            optional bpftrace/eBPF attribution provider
internal/evidence/            Ed25519 evidence/rule signing
internal/federation/          multi-sensor metadata federation
internal/investigation/       graph construction
internal/notifications/       bounded Email/Telegram delivery
internal/trafficseries/       live IN/OUT history and downsampling
internal/response/            guarded active response
internal/threatintel/         STIX/TAXII intelligence hub
internal/replay/              PCAP/PCAPNG offline replay
internal/pcapng/              rotating flight recorder
internal/pipeline/            data pipeline
internal/server/              REST/WebSocket + embedded UI
internal/report/              HTML/JSON reports
internal/selftest/            embedded tests
configs/                      example config
packaging/systemd/            systemd unit
packaging/openrc/             OpenRC integration
packaging/runit/              runit integration
packaging/sysv/               SysV integration
scripts/                      build/test/compatibility wrappers
docs/                         paired English/Turkish technical documentation
dist/                         static binaries and checksums
install.sh                    universal installer
uninstall.sh                  safe uninstaller
LICENSE                       complete GNU GPLv3 text
AUTHORS                       developer metadata
COPYRIGHT                     copyright/SPDX summary
```

---

# 24. License and developer

NetProbe IR is released under **GNU General Public License version 3 only (GPL-3.0-only)**.

```text
Copyright (C) 2026 Cuma KURT <cumakurt@gmail.com>
```

- Developer: **Cuma KURT**
- Email: **cumakurt@gmail.com**
- LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
- Repository: https://github.com/cumakurt/netprobe-ir

Read `LICENSE` before redistribution or creation of derivative works, and see `docs/SECURITY.md` for security reporting guidance.

### DNS and web access analysis

Dedicated **DNS Queries** and **Web Access** menus refresh captured observations every second, with search, pause/resume and cursor pagination. See [capture coverage, retention limits and API](docs/DNS_WEB_ANALYSIS.md).

### Live Traffic Analytics

The **Top Analytics** menu and **Interfaces → interface name** provide live
SSE telemetry, observed Top rankings, application visibility and real Linux
RX/TX charts. See [measurement semantics, API and validation](docs/TRAFFIC_ANALYTICS.md)
for capture coverage, retention, Unknown classifications and resource bounds.
