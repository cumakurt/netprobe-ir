# Changelog

[Türkçe](CHANGELOG_TR.md) · **English** · [Documentation index](docs/README.md)

## 1.0.0 — 2026-09-13

### Added
- High-density Canvas Investigation Graph with zoom/pan/multi-select/rectangle selection/drag/session positioning, filtering, clustering, edge aggregation and context pivots.
- Dynamic interactive Assets with traffic/flow/alert/graph navigation.
- Encrypted Email/SMTP and Telegram Notification Management with independent severity routing, test actions, bounded async delivery, retry/backoff, cooldown/dedup and delivery metrics.
- Real telemetry-backed IN/OUT live traffic history with 1m/5m/15m/1h/24h server-side downsampling and WebSocket incremental updates.
- Real Chromium E2E console qualification.

### Security / Performance
- Notification secrets are masked in API/UI and encrypted at rest.
- New mutating settings APIs reuse existing RBAC/audit/same-origin protections.
- Large graph output is bounded and clustered server-side before Canvas rendering.


## 0.9.0 — 2026-09-13

### Added
- CISO-oriented Executive Overview with posture, risk trend, confidence, Detection Quality, exploit/root-cause and Fleet resilience analytics.
- Clickable top KPI cards with direct drill-down into Live Traffic, Security Findings and Applications.
- OCSF-compatible canonical event envelopes for findings, flows and runtime events.
- Sigma correlation-plan parsing for event/value count and temporal/ordered-temporal correlation.
- Suricata/Snort rule import analyzer with coverage, unsupported-option reporting and review requirements.
- Persistent response playbooks with dry-run, approval-required and explicit automatic modes.
- Bounded historical analytics store and query API.
- Asset Intelligence plus host CycloneDX/SPDX inventory export.
- Local CIDR ASN/organization/country enrichment.
- TLS certificate/SPKI reuse intelligence and DNS infrastructure graph analytics.
- Runtime anomaly detections for memfd/ptrace/temp/deleted execution and sensitive runtime activity.
- CO-RE eBPF source/build/readiness path plus explicit fallback reporting.
- Unified Investigation Workspace.
- SOC Performance workspace and bounded synthetic regression benchmark.
- Experimental OpenTelemetry Profiles HTTP adapter.
- Release CycloneDX/SPDX SBOM, provenance and reproducibility controls.

### UI
- Removed Interface Acquisition from Overview; acquisition detail now lives under Interfaces/SOC Performance.
- Added executive risk posture, 24h risk trend, evidence confidence, operational resilience and infrastructure-intelligence visuals.
- Added Response Playbooks and SOC Performance navigation/workspaces.
- Preserved the responsive white-theme design and full-width layout.

### Security / Compatibility
- New APIs remain behind existing RBAC/audit/same-origin controls.
- Imported rules are parsed/analyzed; they are not executed as code.
- Automatic response cannot bypass existing response enable/dry-run/action/target allowlist controls.
- Multi-tenant isolation remains intentionally excluded.
- The release host does not provide a qualified BTF/libbpf/bpftool environment, so native CO-RE live qualification is not claimed.

## 0.8.1 — 2026-09-13

### Added
- Detection Quality Center with persistent labeled Detection Lab runs, TP/FP/FN, precision, recall and weighted quality score.
- Attack Story v2 risk timeline and explicit probable-root-cause inference.
- Bounded runtime-event evidence history and API surface.
- Adaptive bpftrace syscall tracepoint discovery for runtime event coverage.
- Sigma Engine v2 named selections, boolean conditions, common modifiers, deterministic evaluator and translation coverage/warnings.
- CVE/KEV runtime exploit-correlation view with explicit version-proof boundary.
- C2 Analytics v2 TX/RX ratio, destination rotation, JA4 reuse and explainable reasons.
- Fleet Health v2 health score, freshness and desired/current version/config/rule drift.

## 0.8.0 — 2026-09-13

### Added
- Added a pragmatic Sigma-subset translator (`netprobe sigma`) that converts Sigma-style rules into NetProbe hunt queries or starter NPDL snippets.
- Added a sample Sigma rule under `configs/sigma-rule.example.yml`.
- Added responsive navigation controls for mobile/narrow screens, including sidebar overlay, dismiss actions and improved viewport fitting.

### Improved
- Refreshed the white-theme web console with clearer colors, richer iconography/emoji navigation and fluid full-width layout behavior.
- Improved page, KPI and panel responsiveness so the UI scales more cleanly across small and large displays.
- Updated release documentation to describe the v0.8 UX refresh and Sigma workflow.

### Compatibility
- Multi-tenant support remains intentionally out of scope for v0.8.0.
- Existing capture, DPI, IDS, Hunt, export, response, runtime-security and fleet workflows remain backwards compatible with v0.7 data/state.

## 0.7.0 — 2026-09-13

- Previous v0.7 runtime-security, malware-evidence and extensibility release.
