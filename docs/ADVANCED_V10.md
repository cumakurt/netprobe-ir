# NetProbe IR v1.0.0 — Interactive Investigation, Notifications and Live Traffic

[Türkçe](ADVANCED_V10_TR.md) · **English** · [Documentation index](README.md)

NetProbe IR v1.0.0 extends the existing capture → flow → process → finding → story → case architecture. It does **not** add a second packet-processing path, a second authentication system, or a frontend-only mock layer. The new investigation, asset, notification and live-traffic features reuse the existing event bus, telemetry stores, RBAC, audit and web security boundaries.

## 1. Investigation Graph architecture

The v1.0 Investigation Graph is rendered in an HTML Canvas. Nodes are not represented by thousands of independent DOM elements. The browser maintains only view state (transform, selected nodes, hidden/collapsed state and session-scoped positions); graph evidence itself comes from the server API.

### Interaction model

The graph supports:

- wheel/trackpad zoom centered on the pointer;
- pointer pan;
- Fit to Screen, Reset View and Center Graph;
- single node selection;
- Ctrl/Command/Shift multi-select;
- rectangle/area selection;
- dragging one or several selected nodes;
- session-scoped node-position persistence using `sessionStorage`;
- node/edge hit testing and hover details;
- node and relationship detail panel;
- search and filters;
- neighborhood focus/isolation;
- hide-unrelated and show-all;
- relation collapse;
- cluster expand/collapse;
- context-aware navigation into Traffic, Flows, Security Findings and Assets.

### Server-side filtering and scaling

`GET /api/v1/graph` accepts the supported graph filters and returns bounded graph metadata. Filtering can constrain source/destination IP, asset/process text, protocol, port, application, severity and time range. Focus/neighborhood requests reduce the returned topology around the selected node.

The server applies safeguards before data reaches the browser:

- maximum visible node count;
- maximum visible edge count;
- cluster substitution for dense graphs;
- edge aggregation;
- time-window filtering;
- neighborhood filtering;
- result metadata that reports total/visible/truncated/clustered state.

The automated large-graph regression generates 5,000 flows and verifies bounded output and practical build time. The goal is to prevent UI lock-up and excessive transfer; it is not a claim that every possible topology or millions of edges can be rendered unbounded in one browser view.

## 2. Graph context navigation

Graph context pivots reuse the console's global focus query rather than inventing a parallel filtering mechanism. An IP node can pivot to Traffic/Flows/Security Findings with an IP focus; an asset pivot opens the dynamic asset view; neighborhood actions request a focused server-side graph.

The browser keeps graph filters and selected/position state within the current session where practical.

## 3. Dynamic Assets

`GET /api/v1/assets` returns observed assets aggregated from retained flows/findings. `GET /api/v1/assets/{id}` returns a single observed asset.

The model can expose, when evidence exists:

- IP / display name;
- process, user, container, Kubernetes pod or interface identity;
- first seen / last seen;
- total bytes;
- IN bytes / OUT bytes;
- flow count;
- observed protocols/applications;
- observed ports;
- related findings;
- related assets;
- risk derived from retained flow/finding context.

Fields not supported by source telemetry are left empty. NetProbe does not fabricate MAC addresses, hostnames or identity data.

Asset actions support Traffic, Flows, Security Findings and Investigation Graph pivots.

## 4. Notification Management

The notification manager persists settings below the NetProbe data directory and owns one bounded asynchronous queue. It is connected to the security-finding pipeline; capture/DPI/detection does not wait for SMTP or Telegram delivery.

### Email

Configuration supports:

- enable/disable;
- SMTP hostname/IP and port;
- username/password;
- sender;
- recipient list;
- clear text;
- STARTTLS;
- implicit TLS/SSL;
- connection timeout;
- independent severity set.

### Telegram

Configuration supports:

- enable/disable;
- bot token;
- chat ID;
- timeout;
- independent severity set.

### Secret storage

SMTP password and Telegram token are sensitive fields.

- They are never returned as plaintext by the normal settings API.
- The API returns only `password_set` / `bot_token_set` flags.
- Persisted settings are protected with AES-GCM authenticated encryption.
- The local 256-bit settings key is stored with mode `0600` under the data directory.
- Encrypted settings are written with mode `0600`.
- Leaving a secret input blank during update preserves the existing secret.
- Notification audit events record the operation, not plaintext credentials.

This protects secrets at rest against accidental disclosure and casual file inspection. It does not claim protection against a privileged attacker who can read both the encrypted file and its local key.

### Severity routing and reliability

Severity selection is enforced in the backend, not only the UI. The manager normalizes `informational` to `info` and supports info/low/medium/high/critical.

Delivery uses:

- bounded queue;
- finite retry count;
- bounded exponential backoff;
- cooldown/deduplication;
- bounded deduplication state;
- sent/failed/dropped/deduplicated statistics;
- last-success/last-error state.

When the queue is full, export notification jobs are dropped and counted rather than blocking the detection pipeline or allowing unbounded RAM growth.

### Test actions and sanitized errors

Administrators can call the Email or Telegram test actions from System Settings. Error handling classifies useful operational failures such as connection timeout, authentication failure, DNS/network failure, TLS handshake failure, SMTP recipient rejection, Telegram authorization failure and Telegram rate limiting. Secret values are not appended to errors.

The release tests use local/mock SMTP and Telegram endpoints; they do not claim delivery through a specific external mail provider or the public Telegram service from the build host.

## 5. Live IN / OUT Traffic

The live Overview chart uses `internal/trafficseries.Store`, which subscribes to the existing packet-metadata event bus. It does not open another capture socket or independently parse traffic.

One-second buckets record:

- IN bytes;
- OUT bytes;
- IN packets;
- OUT packets;
- unique observed flows;
- IN/OUT flow counters.

The API exposes:

- `GET /api/v1/traffic/live`
- `GET /api/v1/traffic/history?range=1m|5m|15m|1h|24h`

Supported UI metrics are bits/sec, bytes/sec, packets/sec and flows/sec.

### Downsampling

The history service changes bucket size by requested time range. Short windows retain high resolution, while long windows such as 24h aggregate into larger buckets. This prevents the browser from downloading an entire day of per-second data on every range change.

### Live update and memory bounds

The existing WebSocket telemetry frame includes the current traffic point. The browser appends incremental points only when Live mode is active. Browser history is bounded; Pause Live stops UI updates only and never stops backend capture.

The chart exposes hover details, current IN/OUT rate, peak IN/OUT, time labels and unit-aware formatting.

## 6. RBAC and browser security

- `/api/v1/notifications*` requires `admin:settings`.
- `/api/v1/graph` uses the existing graph read permission.
- live traffic endpoints use existing read/status permissions.
- asset detail uses the asset read permission.
- browser-session state-changing requests remain covered by the existing same-origin mutation check.
- notification changes are written to the audit trail.

## 7. Test coverage

The v1.0 suite includes:

- graph query/filter/neighborhood/clustering tests;
- a 5,000-flow large-graph bounded-output regression;
- asset aggregation/detail API tests;
- live traffic event-bus and history/downsampling tests;
- notification encrypted-persistence and API secret-masking tests;
- SMTP local delivery test;
- SMTP authentication failure, timeout, TLS failure and recipient rejection tests;
- Telegram mock success, timeout, rate-limit and token-redaction tests;
- backend severity routing and deduplication tests;
- RBAC and cross-origin mutation tests;
- real Chromium end-to-end tests for KPI drill-down, graph interactions, asset navigation, notification UI masking and live traffic UI controls;
- real Linux packet capture/IDS/Hunt regression;
- real TLS SNI/ALPN/JA3/JA4/NPSH regression;
- full Go race detector in package groups.

The release environment ships Chromium with an enterprise `URLBlocklist: ["*"]` policy. For the release-only browser qualification, that global policy was temporarily removed for the test process and restored immediately after the run. No policy modification is part of the product or release ZIP.

## 8. Non-claims / boundaries

v1.0.0 does not claim:

- unlimited browser rendering of arbitrary graph size;
- external public SMTP/Telegram provider qualification for every vendor;
- discovery of MAC/hostname fields that the underlying telemetry never observed;
- multi-tenant isolation;
- lossless telemetry when bounded queues are exhausted — drops are intentionally counted and exposed;
- live native CO-RE success on hosts where the required BTF/toolchain/runtime prerequisites are unavailable.
