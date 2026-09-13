# Web Console Design Review — v1.0.0

[Türkçe](UI_DESIGN_TR.md) · **English** · [Documentation index](README.md)

## v1.0 investigation interaction model

The v1.0 console keeps the responsive white SOC/CISO theme and turns Investigation Graph into a high-density Canvas workspace. Canvas rendering avoids one-DOM-element-per-node scaling. Wheel/trackpad zoom, pan, fit/reset/center, hover hit-testing, rectangle selection, multi-select and drag all operate without rebuilding the entire application page. The graph requests filtered/time-bounded datasets from the server and applies clustering/edge aggregation and explicit visible-node/edge ceilings.

Asset rows are interactive pivots rather than static inventory text. When a user pivots from an IP or asset to Traffic, Flows, Alerts or Investigation Graph, the console carries the relevant IP/focus/time context into the destination route.

Overview live traffic uses real backend packet metadata. The browser receives only the current incremental point over the existing WebSocket and requests bounded/downsampled history when the operator changes the time range. Pause Live stops browser updates only; packet acquisition continues unchanged.

Settings → Notifications exposes Email and Telegram channels to administrators. Stored secrets are represented only as `*_set` state in API/UI responses; changing unrelated fields does not require redisplaying the secret.

NetProbe IR v1.0.0 treats the browser as a host-aware SOC/incident-response console rather than a decorative dashboard. The UI is deliberately light/white, information-dense without being noisy, and optimized for the question a SOC analyst or CISO asks first: **“Is something risky happening now, where, and what evidence supports it?”**

## One-glance design goals

Without opening a detail pane, Overview must answer:

- Is capture globally active, paused, or degraded?
- Which interfaces are actively collecting and which are individually stopped?
- Are there critical or high-confidence security findings?
- How many findings are exact IOC/signature/exposure versus behavioral hypotheses?
- What is the current TX/RX and packet pressure?
- Which processes/applications are producing the highest traffic or risk?
- Which protocols dominate retained traffic?
- Can the operator immediately pivot into the evidence that caused a finding?

White surfaces, restrained borders, generous spacing and semantic red/amber/green accents keep operational meaning visible without turning the dashboard into a wall of color.

## Navigation model

The persistent menu is intentionally task-oriented:

1. **Overview** — posture, acquisition health, live rates, top protocols/processes and priority findings.
2. **Security Findings** — native IDS/IOC/signature/policy/behavioral evidence with confidence/verdict.
3. **Live Traffic** — searchable flows and recent packet metadata.
4. **Applications** — process-centric traffic/risk view.
5. **Interfaces** — per-interface acquisition state and independent Start/Stop controls.
6. **Hunt / Search** — server-side investigation across retained findings, flows, packets, processes and alerts.
7. **Behavioral Alerts** — anomaly engine output kept distinct from deterministic security findings.
8. **System** — global capture controls, health, reports and diagnostics.

## Security certainty is visible, not hidden

Severity and certainty are separate visual concepts. A red `critical` label means impact/priority, while the verdict explains what the evidence actually proves:

- `confirmed_ioc` — exact match to operator-supplied IOC data.
- `signature_match` — deterministic pattern observed in visible traffic.
- `confirmed_exposure` — directly observed insecure transport/credential exposure.
- `policy_exposure` — network-boundary condition that violates a high-risk policy assumption.
- `behavioral` — threshold/correlation hypothesis requiring analyst validation.

The console must never present a behavioral threshold as if compromise were proven.

## Focus and Hunt interaction

The global Focus bar accepts compact field queries and remains available while moving between Security Findings and Live Traffic. Supported fields include:

`src:`, `dst:`, `ip:`, `sport:`, `dport:`, `port:`, `proto:`, `app:`, `process:`, `pid:`, `iface:`, `dir:`, `severity:`, `verdict:`, `rule:`, `mitre:`.

Examples:

```text
src:10.10.10.15 dst:1.1.1.1 proto:udp
app:dns process:python severity:high
verdict:confirmed_ioc iface:eth0
rule:NP-IDS-1201 severity:critical
mitre:T1046 proto:tcp
```

The filter drawer gives non-query-language users the same core controls through explicit source/destination/protocol/application/process/interface/direction/severity fields. Hunt performs the query server-side against daemon-retained evidence rather than only what happens to be present in the browser's most recent WebSocket frame.

## Drill-down and pivot model

Every forensic object that looks interactive is actually interactive. Rows/cards expose keyboard and pointer activation, visible focus rings and real detail routes.

```text
Security Finding
  -> linked Packet
  -> linked Flow
  -> linked Process
  -> one-click Focus on src/dst/process/protocol/interface/rule/MITRE

Live Traffic
  -> Flow detail
      -> Process detail
      -> related findings/alerts
  -> Packet detail
      -> Flow detail
      -> Process detail

Applications
  -> Process detail
      -> retained flows
      -> linked security findings
      -> behavioral alerts

Interfaces
  -> Interface detail
      -> interface flows / packets
      -> independent Start/Stop acquisition

Hunt
  -> mixed retained evidence
      -> object detail
      -> refine/pivot query
```

Hash-based routes preserve browser Back/Forward behavior. Breadcrumbs and explicit Back controls prevent operators from losing investigation context.

## Per-interface acquisition controls

Global capture state and interface state are intentionally independent.

- **Stop interface** closes only that interface's AF_PACKET capture session.
- Other running interfaces continue to collect.
- The web/API control plane remains online.
- **Start interface** creates a fresh capture session for that interface.
- Global Stop pauses all sessions while retaining the console and evidence.
- Global Start resumes acquisition using configured interfaces.

Each interface card shows `running`, `stopping` or `stopped` plus packet/byte/error/drop evidence. This avoids the dangerous ambiguity of a UI that appears healthy while one sensor path is silently inactive.

## Charts and visual hierarchy

Charts are evidence-backed rather than decorative:

- TX/RX rate graph is calculated from consecutive WebSocket counter samples.
- Protocol distribution is derived from retained flow byte volume.
- Top process/application cards are derived from actual retained flow/process summaries.
- Security posture counts use retained native IDS findings and verdict classes.

No demo/random values are injected into production charts.

## Accessibility and operational usability

- Keyboard navigation and Enter/Space activation are supported on drill-down rows/cards.
- Focus rings are visible.
- State is conveyed by labels/icons as well as color.
- Evidence tables scroll horizontally on narrow displays instead of hiding columns.
- Mobile layouts collapse the navigation while preserving capture/security status.
- Destructive/pause controls are visually separated from investigation actions.
- Capture errors and drops remain first-class health signals.

## Visual-review criticism applied to v0.3

The design was reviewed from a separate visual/operations perspective with the following criticisms applied:

1. **Too many alerts can destroy hierarchy.** Resolution: priority findings, certainty/verdict and behavioral alerts are separated; Overview only surfaces the highest-value items.
2. **A search box without retention semantics can mislead.** Resolution: Hunt is explicitly server-side and reports result counts by evidence type; live filtering remains distinct.
3. **Per-interface controls can be confused with daemon controls.** Resolution: interface buttons live on interface cards/detail pages while global acquisition controls remain in the header/System area.
4. **Clickable-looking text that is not actionable causes analyst friction.** Resolution: flow, packet, process, finding, alert and interface objects resolve to detail routes.
5. **Dense visualizations can obscure forensic evidence.** Resolution: graphs summarize; tables/details preserve exact endpoints, PID, rule, MITRE, timestamps and evidence.
6. **Red everywhere destroys red's meaning.** Resolution: color is semantic and sparse; normal telemetry stays neutral/blue.
7. **A stopped sensor can look like zero traffic.** Resolution: explicit stopped/running/degraded badges accompany zero-rate charts/counters.

## Deliberate non-goals

The embedded console is not a full PCAP hex editor, SIEM data lake or replacement for mature broad-signature NIDS ecosystems. Raw bytes remain in PCAPNG. Long-duration enterprise retention belongs in an external backend. Missing process attribution is shown honestly rather than invented for forwarded traffic.

## Visual verification note

Source-level UI asset tests, JavaScript syntax validation, REST/control tests, security-finding/Hunt tests and live capture integration are part of release verification. No automated screenshot-based visual-regression claim is made unless the release test report explicitly records a browser-rendering test; source review is not represented as pixel-level browser validation.

## v0.9.0 SOC investigation surfaces

The v0.9.0 console retains the white theme and fluid full-page layout introduced in v0.8 and adds:

- Detection Quality Center with low-quality rules shown first;
- Sigma translation/coverage panel;
- probable-root-cause callouts explicitly marked as inference;
- compact per-story risk timeline bars;
- runtime-event and exploit-correlation tables;
- richer C2 beacon columns;
- Fleet Health meters, freshness state and drift badges.

The console must remain usable at narrow widths: navigation moves to an overlay sidebar, major card grids collapse through `auto-fit`, tables remain horizontally scrollable, and page content uses the full available viewport instead of a fixed desktop canvas.
