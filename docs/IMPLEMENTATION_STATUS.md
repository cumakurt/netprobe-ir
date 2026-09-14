# Implementation Status — NetProbe IR v1.0.0

[Türkçe](IMPLEMENTATION_STATUS_TR.md) · **English** · [Documentation index](README.md)

This file distinguishes **implemented and release-tested behavior** from environment-conditional capabilities and deliberate non-claims. It is intended to prevent feature names in the UI from being mistaken for guarantees the sensor cannot technically make.

## Unreleased development: on-demand host triage

An unlocked incident case with an attributed local process can now capture a read-only Linux snapshot through **Capture host triage** or `POST /api/v1/cases/{id}/triage`. The snapshot records the collecting user and time, hostname, process PID/name/UID/login UID/audit session ID/executable/cgroup/start ticks, a SHA-256 digest of the target executable when it is readable and at most 64 MiB, up to eight ancestors, up to 128 socket connections linked through that process's file descriptors, and metadata for up to 128 regular open files. It also inventories the matching systemd service unit and drop-ins, plus bounded host cron file metadata. Regular persistence files up to 1 MiB receive SHA-256 hashes; symlinks are recorded without following them. If `/usr/bin/journalctl` is available, up to 100 PID-scoped journal entries from a bounded one-hour window contribute timestamps, boot/unit/priority identifiers, message lengths and SHA-256 digests. Raw journal messages, open file contents and persistence file contents are not retained. A case stores at most eight snapshots. Signed case exports include each snapshot as `triage-NNN.json` and cover it with the existing evidence manifest.

Collection requires `case:write`, uses the existing origin and audit controls, and rejects locked cases. The process name, executable and start ticks recorded with new process telemetry are compared with the live PID; a second start-time read also detects replacement during collection. Legacy cases without recorded start ticks display a PID-reuse warning. Missing permissions, unavailable journald and truncated scans appear as snapshot warnings. Host cron files and PID-scoped journal entries are investigation hints, not proof that they belong to the recorded process. Command lines, environment variables, memory, file contents and raw log messages remain outside this collection scope.

## Implemented v1.0 investigation / notification / live-traffic path

- Canvas Investigation Graph with interactive zoom/pan/select/drag/rectangle-selection and session node positions;
- server-side graph filtering, time-windowing, neighborhood queries, clustering, edge aggregation and hard result limits;
- interactive Asset detail and context-aware pivots;
- encrypted Email/Telegram notification configuration with backend severity enforcement;
- bounded asynchronous notification queue, bounded exponential retry, cooldown/dedup and sanitized delivery errors;
- real SMTP clear/STARTTLS/implicit-TLS test/delivery and Telegram Bot API test/delivery;
- packet-metadata-driven IN/OUT traffic series, bounded retention, history downsampling and incremental WebSocket live points;
- 1m / 5m / 15m / 1h / 24h dashboard ranges and UI-only pause/resume;
- real Chromium end-to-end interaction suite in addition to Go/server/live-kernel regression.

No notification secret is intentionally returned in plaintext by the settings API. Asset fields absent from observed data (for example MAC/hostname when unavailable) are left absent/empty rather than fabricated.

## Implemented core sensor path

- passive Linux capture using TPACKET_V3/PACKET_MMAP with AF_PACKET fallback;
- Ethernet/VLAN, IPv4/IPv6, TCP/UDP/ICMP decoding;
- process/socket attribution using `/proc`, with optional bpftrace/eBPF event provider and automatic fallback;
- flow tracking, TCP startup reconstruction and native protocol metadata extraction;
- DNS, HTTP/1, TLS ClientHello/ServerHello, JA3, JA4, NPSH, QUIC long-header metadata and observable certificate metadata;
- HTTP/2 cleartext preface/SETTINGS parsing and HTTP/3/QUIC transport classification;
- protocol packs for core, enterprise, database, DevOps and ICS/OT signatures/hints;
- native IDS, exact IOC matching, custom JSON rules, anomaly correlation, Hunt/Focus and behavior baselines;
- rotating PCAPNG Flight Recorder and Smart-PCAP evidence-retention policy;
- PCAP/PCAPNG replay through the normal decode/DPI/IDS pipeline;
- incident cases, signed evidence bundles, Attack Stories and Investigation Graph;
- secure web authentication/RBAC/MFA/API tokens/OIDC/audit/backup/response approvals;
- standards-based Remote Syslog and NetFlow v5/v9, IPFIX and sFlow export;
- STIX/TAXII threat intelligence;
- sensor federation/fleet metadata and command queue/poll/ack workflows.

## Implemented v0.7 advanced path

### Files and malware evidence

- bounded HTTP/1, SMTP/MIME, FTP and supported SMB2 file/object reconstruction;
- SHA-256/SHA-1/MD5, MIME, size and entropy;
- optional asynchronous YARA-X adapter via external `yr`;
- YARA matches become security findings;
- file artifacts are graph entities linked to flows/processes;
- Smart-PCAP `headers`, `metadata` and `drop` modes block file-payload retention.

### Detection and behavior

- NPDL non-Turing-complete semantic detection rules;
- advanced jitter-aware C2 beacon analytics;
- encrypted DNS behavior intelligence;
- identity profiles for process/user/container/pod/service contexts;
- lateral movement and NTLM fan-out behavior correlation;
- installed-package inventory and CISA-KEV-compatible exposure context.

### Extensibility and data plane

- OTLP/HTTP Logs event export;
- NATS Core event publish;
- Kafka producer adapter through external `kcat`;
- ClickHouse JSONEachRow event export;
- external `wasmtime` WASI plugin runner with timeout/output limits and no NetProbe-granted filesystem/network preopens;
- evidence-based local analyst plus optional bounded remote OpenAI-compatible chat-completions mode;
- self-protection checks for watched-file integrity, disk pressure and clock rollback.


## Implemented v0.8.1 quality/root-cause path

- persistent Detection Quality Center fed by labeled Detection Lab runs;
- Attack Story v2 with runtime/file/network stages, risk timeline and probable-root-cause inference;
- bounded runtime-event history and event-bus publication;
- adaptive bpftrace syscall tracepoint discovery;
- Sigma v2 deterministic subset evaluator and translation coverage/warnings;
- KEV + finding + runtime exploit correlation;
- C2 v2 scoring with timing, size, TX/RX, destination rotation and JA4 reuse;
- Fleet Health v2 freshness/health/drift scoring.

## Implemented v0.9.0 interoperability / executive path

- CISO-oriented Executive Overview with clickable KPI drill-down and no Interface Acquisition panel;
- OCSF-compatible canonical event envelopes;
- Sigma correlation-plan parser/compiler;
- Suricata/Snort subset import analyzer with coverage/review reporting;
- response playbooks with dry-run, approval-required and explicit automatic modes;
- approval-required active-response actions bridged into the existing approval store;
- bounded local historical analytics;
- Asset Intelligence plus CycloneDX/SPDX host inventory;
- local CIDR/ASN/organization/country enrichment;
- TLS certificate/SPKI reuse intelligence and DNS infrastructure graph;
- runtime anomaly detections for selected high-signal Linux behaviors;
- auditable CO-RE BPF source/build/readiness path;
- Unified Investigation Workspace and SOC Performance UI;
- experimental OpenTelemetry Profiles HTTP adapter;
- release CycloneDX/SPDX SBOM, provenance, reproducibility controls and optional Ed25519 checksum-manifest signing.

## Environment-conditional capabilities

### Live eBPF / CO-RE runtime telemetry

The live adaptive provider requires a compatible Linux kernel, privilege and `bpftrace`; when unavailable, `/proc` attribution remains active. v0.9 also ships CO-RE C source, a build helper and readiness probe. The release host had no kernel BTF, `bpftool`, `bpftrace` or generated `vmlinux.h`, so the CO-RE object could not be built or live-qualified there. The UI therefore reports the path as fallback rather than active.

### YARA-X

Requires a configured rule file and a usable `yr` executable. The NetProbe binary itself does not embed the YARA-X engine. Missing `yr` degrades only malware scanning; file hashing/metadata can still work.

### WASM plugins

Requires `wasmtime` when plugins are enabled. NetProbe executes the external runtime with bounded input/output/time and does not grant explicit preopened host directories or sockets. Operators must still treat third-party modules as untrusted software and review them.

### Kafka

The Kafka target is a real producer adapter implemented through `kcat`; `kcat` must be installed. NetProbe does not claim an embedded Kafka protocol stack.

### Active response

Requires appropriate OS tools and privilege. Automated tests validate guardrails/command construction; release testing does not intentionally kill arbitrary host processes or modify production firewall/interface state.

### Vulnerability context

The KEV catalog gives known-exploited vulnerability context but does not provide Linux distribution package-manager affected-version ranges. NetProbe therefore sets `proven_vulnerable=false` for package-name/product overlaps. This is prioritization context, not a vulnerability scanner proof.

### Remote analyst

Remote mode requires an explicitly configured endpoint and an API key environment variable. It sends bounded retained evidence outside the sensor; it is disabled by default and must be enabled only when organizational data-handling policy permits it.

## Deliberate non-claims

NetProbe IR v1.0.0 does **not** claim:

- passive AF_XDP zero-copy redirect as a safe host-sniffing dataplane;
- transparent TLS/HTTP3 payload decryption without session keys;
- encrypted HPACK/QPACK application-header visibility without keys;
- nDPI or complete Suricata/Snort rule-language/community-corpus compatibility;
- proof that an installed package version is vulnerable solely because a KEV product name overlaps;
- full Kubernetes API inventory/enrichment when only local cgroup/process attribution is available;
- native in-process Kafka or NATS JetStream durable-stream semantics;
- active-active controller consensus or a distributed SQL control-plane database;
- guaranteed malware detection when YARA-X/rules are unavailable;
- a remote LLM as a security decision authority;
- multi-tenant isolation;
- a release-host-qualified active CO-RE userspace loader; v0.9 ships the auditable BPF source/build/readiness path while live runtime events still use adaptive bpftrace when available;
- complete Sigma specification compatibility; unsupported/complex semantics are reported for review;
- probable root-cause inference as certainty.

## Release verification

The exact commands, live-kernel tests, optional-capability skips and ZIP re-verification results are recorded in `TEST-RESULTS.md`.
