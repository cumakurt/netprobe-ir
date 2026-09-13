# Testing — NetProbe IR v1.0.0

[Türkçe](TESTING_TR.md) · **English** · [Documentation index](README.md)

NetProbe IR separates ordinary non-privileged regression tests from Linux capability-dependent live capture tests. A build is not described as live-capture verified unless the privileged namespace integration actually runs and passes.

## v1.0.0 interactive investigation test coverage

The v1.0 release additionally verifies:

- Canvas Investigation Graph server-side filtering, clustering, node/edge limits and neighborhood queries;
- real Chromium zoom, pan, single/multi-select, drag, rectangle selection and context navigation;
- observed-only Asset detail and Asset → Traffic / Graph pivots;
- encrypted notification persistence, masking, SMTP/Telegram severity routing, timeout/auth/TLS/recipient/rate-limit error handling, deduplication and bounded queue behavior;
- real IN/OUT traffic-series ingestion from `packet_metadata`, bounded history, 24-hour downsampling and WebSocket incremental updates;
- Overview KPI drill-down and removal of Interface Acquisition from the executive Overview;
- short-run browser heap sanity with bounded client-side traffic history.

The Chromium test runs against a real NetProbe daemon in an isolated Linux user/network namespace when the environment supports it. The test does not substitute synthetic browser-only telemetry for the backend.


## Standard suite

```bash
./scripts/test-all.sh
```

The standard suite validates:

1. `gofmt` cleanliness
2. POSIX installer/uninstaller/init-script syntax
3. Bash build/live-test script syntax
4. JSON syntax for main config, IOC example, IDS custom-rule example and STIX example
5. source/embedded web asset synchronization
6. JavaScript syntax with Node.js when Node is available in the development environment
7. `go vet ./...`
8. `go test ./...`
9. `go test -race ./...`
10. static Linux x86_64 + ARM64 builds
11. x86_64 embedded `--self-test`
12. version/developer/repository/GPL metadata
13. static-link verification
14. staged-root installer/uninstaller regression
15. installation of IDS/Hunt documentation and non-active IOC/rule examples

## Native IDS tests

Unit/integration coverage includes deterministic and stateful behavior such as:

- JNDI/Log4Shell signature generation
- TCP NULL scan signature
- reverse-shell / PowerShell EncodedCommand plaintext signature
- same-target multi-port scan correlation
- same-service host-sweep correlation
- false-positive guard: different-host + different-port normal fan-out must not become a host-sweep finding
- exact IP/SNI/JA3 IOC matching
- custom RE2 rule matching
- Security Findings list/detail REST API
- server-side Hunt query returning the retained finding

The tests distinguish `signature_match`, `confirmed_ioc`, policy/exposure and behavioral findings rather than asserting that every high-severity event is proof of compromise.


## v0.4/v0.5 feature-package tests

The standard Go suite additionally verifies:

- bpftrace/eBPF attribution event parsing and provider lifecycle/fallback behavior,
- STIX 2.1 import and TAXII 2.1 object/pagination handling against local HTTP fixtures,
- process-aware baseline deviation detection,
- Incident Case lifecycle and export,
- Ed25519 signed manifests, detached rule signatures and evidence tamper detection,
- Investigation Graph construction,
- Detection Lab PCAP replay,
- Active Response dry-run/confirmation guardrails,
- federation hub/client authentication and bounded snapshots,
- PCAPNG replay, JA4 official-example regression, QUIC metadata, NPSH and TLS 1.2 certificate metadata,
- explicit rejection of passive AF_XDP selection.

The release qualification also exercises the static binary CLI rule-pack `sign → verify` path and a real generated PCAPNG through `netprobe-ir replay`, with final JSON/HTML report generation.

## v0.6.0 Remote Syslog / Flow Export tests

The standard suite additionally verifies real local/mock collector behavior for:

- UDP, TCP, TLS and mutual-TLS Syslog delivery;
- RFC3164/RFC5424 formatting and RFC6587 octet-counting/non-transparent framing;
- TLS certificate validation failures;
- IPv4 and IPv6 Syslog transport when IPv6 loopback is available;
- independent multiple destinations, unreachable-collector reconnect/backoff and bounded queue overflow;
- NetFlow v5, NetFlow v9, IPFIX v10 and sFlow v5 binary wire fields;
- v9/IPFIX IPv4/IPv6 template IDs and periodic template refresh;
- RFC7011 IPFIX sequence semantics;
- sFlow packet-metadata sampling rather than aggregate-flow synthesis;
- unidirectional flow splitting and active-timeout counter deltas;
- multiple simultaneous flow collectors, flow timeout and persistence;
- invalid host/port/protocol rejection;
- exporter CRUD/test persistence through authenticated APIs and `read:integrations` versus `admin:settings` authorization;
- non-blocking Event Bus load behavior, bounded queues and drop accounting.

`docs/EXPORT_SYSLOG_FLOW.md` and `docs/EXPORT_SYSLOG_FLOW_TR.md` describe protocol semantics and operational limitations in detail.

## Embedded binary self-test

```bash
./dist/netprobe-linux-amd64 --self-test
```

It checks synthetic decoding/DPI/flow behavior, anomaly/report rendering and PCAPNG generation/validation. A failed subtest exits non-zero.

## Real Linux capture + per-interface + IDS integration

```bash
./scripts/integration-live-linux.sh
```

When unprivileged user/network namespaces are permitted, the script creates an isolated Linux network namespace, enables loopback and creates an additional veth pair. It starts the static NetProbe binary with at least `lo` and `veth0`, then validates real behavior:

- TPACKET_V3/PACKET_MMAP captures real HTTP traffic (with AF_PACKET fallback available)
- HTTP DPI produces the expected flow
- the HTTP flow is attributed to the actual local Python server PID
- recent packet metadata is populated and linked to a flow
- stopping `veth0` changes only `veth0` to stopped while `lo` remains running
- traffic generated on loopback still increases counters while `veth0` is stopped
- restarting `veth0` restores independent acquisition
- a real plaintext JNDI test request produces `NP-IDS-1201` with `signature_match`
- server-side Hunt for `rule:NP-IDS-1201 severity:critical` returns that retained finding
- global capture Stop freezes counters while web/API stay reachable
- global Start resumes acquisition and counters increase again
- graceful shutdown emits non-empty PCAPNG plus final JSON/HTML reports
- final JSON contains `security_findings`

If user/network namespaces or required raw-packet capabilities are unavailable, the script exits `77` to report a **skip**, not a pass.

## Real TLS integration

```bash
./scripts/integration-live-tls-linux.sh
```

The TLS test starts a local TLS endpoint inside a Linux namespace and makes a real TLS connection. It verifies that capture/DPI extracts ClientHello metadata such as SNI (`localhost`), ALPN when offered, JA3, JA4 and NPSH ServerHello fingerprint data without claiming payload decryption.

## Static builds

```bash
./scripts/build-static.sh
file dist/netprobe-linux-amd64 dist/netprobe-linux-arm64
sha256sum -c dist/SHA256SUMS
```

`netprobe-linux-amd64` is executed in the x86_64 release environment. ARM64 is cross-compiled, inspected as an ARM64 ELF and checksum-verified. It is not described as runtime-tested unless an ARM64 host/emulator was actually available.

## Installer regression

A safe test uses a staged root:

```bash
ROOT="$(mktemp -d)"
./install.sh --root "$ROOT" --bundled-only
"$ROOT/usr/local/sbin/netprobe-ir" --about
./uninstall.sh --root "$ROOT" --purge --yes
rm -rf "$ROOT"
```

The test must not activate services in the real host. It verifies binary/config/docs/license placement, IDS example placement and complete purge of the staged NetProbe paths.

## Web/UI checks

Automated coverage verifies:

- JavaScript parses successfully when Node is available
- embedded assets match source assets
- Security Findings and Hunt routes/assets exist
- per-interface control function is embedded
- REST endpoints for findings/Hunt/control respond as expected
- browser-origin protections remain enforced for state-changing controls
- drill-down API objects used by the UI are available

A source/DOM-level review is not described as a screenshot/pixel regression test. Browser-rendered visual regression is claimed only if `TEST-RESULTS.md` explicitly records one.

## Security test safety

Synthetic/live IDS tests use local namespaces, loopback/veth and documentation-reserved/example values. They are intended to verify a defensive detector against traffic generated inside the isolated test environment, not to scan or attack external systems.

## v0.7.0 advanced analytics tests

The v0.7 release suite additionally covers:

- HTTP/SMTP file reconstruction, hashes, MIME/entropy and asynchronous scanner update behavior;
- YARA-X CLI NDJSON adapter parsing with a local fake `yr` executable;
- Smart-PCAP payload-retention privacy gating;
- NPDL parse/evaluate behavior and pipeline wiring;
- h2c SETTINGS, protocol-pack signatures and QUIC metadata;
- jitter-aware beacon scoring, encrypted DNS, identity baseline and lateral/NTLM correlation;
- KEV catalog ingestion, package inventory parsing and non-proof exposure semantics;
- OTLP, local NATS, fake-kcat Kafka adapter and ClickHouse JSONEachRow delivery;
- WASM runner status/error behavior with controlled fake runtimes;
- self-protection hash/disk/clock checks;
- evidence-based local/remote analyst fixtures;
- fleet command queue/poll/ack API;
- existing v0.6 Syslog/Flow export and all earlier capture/IDS/Hunt/auth/replay/case tests.

## v0.8.1 quality/root-cause tests

The v0.8.1 suite additionally covers:

- Detection Quality persistence and TP/FP/FN/precision/recall calculation;
- Attack Story v2 runtime/file evidence, risk timeline and inferred root cause;
- adaptive eBPF/bpftrace tracepoint-program construction and runtime-line parsing;
- Sigma v2 named selections, boolean conditions, CIDR/regex/common modifiers and safe NPDL starter behavior;
- KEV runtime exploit correlation while preserving `version_proven=false` for name-only overlap;
- C2 v2 scoring fields and explainable reasons;
- Fleet Health freshness/drift scoring;
- authenticated API surfaces for quality/runtime/exploit/fleet/Sigma.

## v0.9.0 interoperability and executive tests

The v0.9.0 suite additionally covers OCSF mapping, Sigma correlation plans, Suricata/Snort coverage analysis, response-playbook guardrails, historical analytics, asset/TLS/DNS intelligence, runtime anomalies, SOC Performance, the Profiles adapter, release metadata and responsive web-asset synchronization.
