# NetProbe IR v0.9.0 — Interoperability, Investigation and Executive Security

[Türkçe](ADVANCED_V09_TR.md) · **English** · [Documentation index](README.md)

NetProbe IR v0.9.0 extends the existing packet → flow → process → file → finding → story → case pipeline. It does not introduce a second capture engine or a second authentication plane. New v0.9 services consume the same bounded telemetry and remain behind the existing RBAC, audit and same-origin controls.

## 1. Executive Overview

The Overview page is intentionally no longer an interface-acquisition dashboard. Interface-level acquisition details belong to **Interfaces** and **SOC Performance**. The Overview is aimed at CISO/SOC leadership and answers four questions:

1. What is the current security posture?
2. Which risks have the highest evidence confidence?
3. Is risk increasing over the last day?
4. Are detection, fleet and evidence pipelines healthy enough to trust the picture?

All primary KPI cards are drill-down links. Active Flows opens Live Traffic; findings open Security Findings; process/application KPIs open Applications; captured-data KPIs open the underlying traffic surface. Additional panels show posture score, Attack Stories, exploit chains, Detection Quality, Fleet resilience, root-cause coverage, advanced C2 findings, TLS infrastructure reuse and DNS infrastructure churn.

## 2. OCSF-compatible canonical event envelope

`internal/ocsf` maps NetProbe findings, flows and runtime events into a stable canonical envelope inspired by OCSF terminology. The goal is to reduce exporter-specific field drift and give integrations a common source representation.

Endpoint:

```text
GET /api/v1/ocsf?kind=findings|flows|runtime&limit=200
```

The response deliberately describes itself as `ocsf-compatible-canonical-envelope`; v0.9.0 does **not** claim exhaustive coverage of every OCSF class or profile. Original fields that cannot be normalized without losing meaning can remain in `unmapped`.

## 3. Sigma correlation

The Sigma translator from v0.8.1 remains available for detection rules. v0.9 adds correlation-plan parsing for:

- `event_count`
- `value_count`
- `temporal`
- `temporal_ordered`
- `group-by`
- `timespan`
- threshold fields such as `gte` / `lte`

CLI:

```bash
netprobe sigma --correlation --in configs/sigma-correlation.example.yml
```

Web/API:

```text
POST /api/v1/sigma/correlation
```

Correlation conversion returns a plan for NetProbe's deterministic correlation layer. Unsupported semantics must be surfaced rather than silently discarded.

## 4. Suricata / Snort import analyzer

The importer is deliberately a compatibility layer, not a claim that NetProbe is Suricata or Snort. It currently understands a useful subset of rule headers and options including:

- actions such as `alert`, `drop`, `reject`, `pass`;
- `tcp`, `udp`, `icmp`, `ip` headers;
- `msg`, `sid`, `rev`, `classtype`, `flow`;
- `content`, `nocase`, `offset`, `depth`, `distance`, `within`;
- `pcre`, `threshold`, `detection_filter`, `reference`.

Every import reports coverage and `requires_review`. Unsupported options are listed. They are never silently treated as supported.

```bash
netprobe import-rule --file configs/suricata-rules.example.rules
```

The Detection Quality page also exposes an interactive analyzer.

## 5. Response Playbooks

Playbooks map findings to deterministic actions with three explicit modes:

- `dry_run` — evaluate and report only;
- `approval_required` — produce a response decision that must pass the human approval workflow;
- `automatic` — execute only when the playbook is explicitly marked automatic **and** the existing Active Response manager allows the requested action.

Conditions can constrain minimum severity/confidence, verdict, category, tags and evidence requirements such as YARA or KEV. Actions use the existing response/case/evidence primitives; there is no bypass around response allowlists or the global Active Response enable/dry-run setting.

The web console exposes playbook CRUD under **Response Playbooks**. Changes are protected by administrative permissions and audit logging.

## 6. Historical analytics store

The v0.9 historical store is a bounded JSONL event store intended for local sensor history and fast investigation without introducing an external database requirement. It receives flow creation, finding and runtime-event summaries.

Query dimensions include:

- time range;
- event type;
- severity;
- process;
- destination;
- result limit.

Endpoint:

```text
GET /api/v1/analytics?from=...&to=...&type=finding,runtime&severity=critical,high&process=python&dst=203.0.113.5
```

For very large deployments, ClickHouse streaming remains the scale-out path; v0.9 does not pretend the bounded local JSONL store is a distributed warehouse.

## 7. Asset Intelligence and SBOM

Asset Intelligence exposes host/kernel/architecture and installed-package context. On Debian-family systems it parses `/var/lib/dpkg/status` when available. The in-memory model also has container/pod/image/digest/service-account/node fields so richer runtime collectors can populate them without changing the API schema.

Endpoints:

```text
GET /api/v1/asset-intelligence
GET /api/v1/asset-intelligence?format=cyclonedx
GET /api/v1/asset-intelligence?format=spdx
```

CLI:

```bash
netprobe sbom --format cyclonedx --out host.cdx.json
netprobe sbom --format spdx --out host.spdx.json
```

Package presence is context, not proof of exploitability. CVE/KEV findings still preserve that distinction.

## 8. Threat-intelligence enrichment

An optional local CIDR enrichment dataset can add ASN, organization, country and source metadata without sending observed IP addresses to an external service.

Configuration:

```json
"threat_intel": {
  "enrichment_file": "/etc/netprobe-ir/enrichment.json"
}
```

Lookup:

```text
GET /api/v1/enrichment?ip=203.0.113.20
```

Most-specific-prefix matching is used. The sample dataset uses documentation prefixes only.

## 9. TLS certificate intelligence

NetProbe records visible X.509 context where the monitored protocol makes it available, including:

- certificate and SPKI SHA-256;
- subject / issuer / serial;
- SANs;
- self-signed state;
- expiry context;
- remote IP / SNI / JA4 association.

The intelligence store clusters reuse by SPKI/certificate identity and marks unusually broad IP/SNI reuse as suspicious context. It does not claim maliciousness from certificate reuse alone.

```text
GET /api/v1/tls-intelligence
```

## 10. DNS infrastructure graph

The DNS graph persists observed domain → answer-IP edges with first-seen, last-seen and count. Domain summaries include answer diversity and churn. High address diversity and churn can be surfaced as fast-flux-like context, not as standalone proof of malware.

```text
GET /api/v1/dns-graph
```

The Threat Intelligence workspace combines this with TLS infrastructure context.

## 11. Runtime anomaly detections

Runtime event telemetry feeds deterministic behavior rules for high-signal Linux activity such as:

- `memfd_create`;
- `ptrace`;
- execution from `/tmp` or `/dev/shm`;
- deleted executable paths;
- namespace / mount / capability-sensitive activity when observed.

These findings enter the same IDS/finding/Attack Story pipeline as network detections. Attribution confidence and event source remain visible.

## 12. CO-RE eBPF path and fallback

v0.9 ships an auditable CO-RE BPF source under `bpf/netprobe_runtime.bpf.c`, a build helper (`scripts/build-ebpf-core.sh`) and a readiness probe. The source uses BTF/CO-RE conventions and a bounded ring-buffer event map.

```bash
netprobe ebpf-core --build
GET /api/v1/core-ebpf
```

The release host used for v0.9 qualification did not provide kernel BTF, `bpftool`, libbpf headers or a validated BPF build/runtime environment. Therefore this release **does not claim that the CO-RE path passed a live kernel test on the release host**. Existing adaptive runtime attribution remains available through bpftrace when installed and `/proc` otherwise. The web console reports readiness/fallback instead of pretending native eBPF is active.

## 13. Unified Investigation Workspace

Attack Stories now link into a unified investigation workspace combining:

- story / risk timeline;
- probable root cause and inference reasons;
- graph context;
- file evidence;
- runtime events;
- CVE/KEV exploit correlations;
- TLS infrastructure clusters;
- DNS infrastructure context.

The workspace separates **severity** from **confidence**. Root cause remains an inference and is labelled as such.

## 14. SOC Performance

Acquisition detail moved out of Overview into **SOC Performance**. This page includes:

- packet counts;
- capture errors;
- recorder drops;
- Syslog/Flow exporter drops;
- per-interface acquisition health;
- CO-RE readiness/fallback;
- a dependency-free synthetic hot-path benchmark.

CLI:

```bash
netprobe benchmark --iterations 100000
```

The synthetic benchmark is useful for release-to-release regression on the same hardware. It is **not** a substitute for a real 1/10/25-Gbit traffic generator benchmark.

## 15. Experimental OpenTelemetry Profiles adapter

`profiles.enabled` exposes an experimental HTTP exporter for a bounded profile envelope. It is deliberately outside detection and response decision paths.

```text
GET  /api/v1/profiles
POST /api/v1/profiles
```

The API key/token is read from the configured environment-variable name and is not returned by the normal status API.

## 16. Release supply-chain metadata

`scripts/release-metadata.sh` creates:

- `dist/SBOM.cdx.json`;
- `dist/SBOM.spdx.json`;
- `dist/provenance.json`;
- `dist/SHA256SUMS`.

`SOURCE_DATE_EPOCH` is honored by the static build helper for reproducible timestamp control. Builds use `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false` and an empty Go build ID. If `SIGNING_DATA_DIR` is provided, the release checksum manifest is signed with NetProbe's existing Ed25519 evidence signer. Unsigned builds are explicitly reported as unsigned.

## 17. Security boundaries

- All new web APIs are protected by existing RBAC.
- Playbook changes require administrative settings permission.
- Import/translation endpoints do not execute imported rule text.
- Benchmark endpoints have bounded iteration counts and request timeouts.
- Enrichment is local/offline unless the operator separately configures other integrations.
- Profile tokens are retrieved from environment variables.
- Automatic response still cannot bypass the Active Response manager's global enable flag, allowlist, action allowlist or confirmation semantics.
- Multi-tenant isolation is intentionally **not implemented** in v0.9.0.

## 18. Non-claims

NetProbe IR v0.9.0 does not claim:

- complete OCSF schema coverage;
- complete Suricata/Snort rule-language compatibility;
- complete Sigma backend equivalence for every modifier/correlation construct;
- proof that a package-name/KEV overlap means the installed version is exploitable;
- native CO-RE live qualification on a host without BTF/libbpf tooling;
- encrypted TLS/HTTP2/HTTP3 payload visibility without decryption keys;
- that synthetic microbenchmarks equal line-rate packet-generator testing;
- multi-tenant isolation.
