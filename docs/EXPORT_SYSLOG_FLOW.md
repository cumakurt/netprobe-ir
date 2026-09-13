# Remote Syslog and Flow Export — NetProbe IR v0.6.0

[Türkçe](EXPORT_SYSLOG_FLOW_TR.md) · **English** · [Documentation index](README.md)

NetProbe IR v0.6.0 adds a non-blocking export plane for sending structured live network/security telemetry to external SIEM/log systems and standards-based flow collectors. Export is deliberately separated from capture/DPI: a slow or unreachable destination cannot block packet capture, DPI, IDS, Hunt, recording, or the web console.

## Architecture

```text
Capture / Replay
      |
Decode -> Flow -> DPI -> IDS / anomaly
      |             |
      +---- structured Event Bus ----------------+
             |                                    |
       Syslog dispatcher                    Flow dispatcher
             |                                    |
       per-target bounded queue             per-target bounded queue
             |                                    |
 UDP / TCP / TLS workers             v5 / v9 / IPFIX / sFlow workers
             |                                    |
       SIEM / log collector                  Flow collector
```

`internal/eventbus` uses bounded subscriber channels and non-blocking publication. Each destination/collector has a second bounded queue. Queue pressure is reported as drops rather than allowing unbounded RAM growth.

## Remote Syslog

Configure destinations from **System Settings -> Remote Syslog**. Multiple enabled targets run independently.

System Settings does not redraw on live telemetry updates, so exporter forms retain input and focus while you edit. Use **Refresh exporters** to reload exporter settings and delivery statistics, or the console refresh button to update capture health.

### Transports and formats

- UDP Syslog.
- TCP Syslog.
- TCP + TLS, TLS 1.2 minimum.
- RFC 3164 BSD-style message formatting.
- RFC 5424 message formatting and NetProbe structured data.
- RFC 6587 TCP framing:
  - octet counting: `<length> <message>`;
  - non-transparent framing: LF-terminated messages.
- RFC 5425 behavior is provided by **TLS + RFC 5424 + octet-counting**, which is the secure recommended combination. TLS with non-transparent framing remains available only as collector compatibility mode and should not be described as strict RFC 5425 framing.

Standards references:
- RFC 3164: https://www.rfc-editor.org/rfc/rfc3164
- RFC 5424: https://www.rfc-editor.org/rfc/rfc5424
- RFC 5425: https://www.rfc-editor.org/rfc/rfc5425
- RFC 6587: https://www.rfc-editor.org/rfc/rfc6587

### TLS / mTLS

TLS defaults to certificate verification and a minimum TLS version of 1.2. A destination can specify:

- system trust store;
- an additional PEM CA file;
- an explicit TLS server name;
- a client certificate and matching private-key file for mTLS;
- `insecure_skip_verify` only when the operator explicitly disables verification.

The private-key file path is retained in the protected exporter configuration but is redacted from normal API responses (`client_key_file` is empty and `has_client_key=true`). Private-key content is never returned or logged. Exporter configuration files are written with mode `0600`.

### Event categories

The pipeline publishes structured event categories rather than raw packet payloads:

| Category | Examples |
|---|---|
| `security` | native IDS findings, exact IOC matches, policy exposures |
| `network` | packet metadata: endpoints, ports, protocol, flags, interface, timestamp, length, ToS/DSCP, VLAN/ICMP metadata |
| `flow` | flow endpoints, counters, times, process attribution, DPI and risk fields |
| `dpi` | protocol/application classification |
| `dns` | query/type/rcode/answers that the DPI engine can observe |
| `http` | method/path/host/status/user-agent/content-type metadata |
| `tls` | TLS version, SNI, ALPN, JA3/JA4/NPSH and observable certificate metadata |
| `anomaly` | behavioral/anomaly alerts and risk evidence |
| `system` | operator capture-control and application system events |

A target may subscribe to any combination or `all`. NetProbe does **not** put arbitrary packet payload bytes into Syslog.

### Syslog health and failure behavior

Each destination reports:

- state (`disabled`, `starting`, `connected`, `backoff`, `error`, `stopped`);
- sent messages;
- failed messages;
- dropped messages;
- queue depth;
- event-bus drops;
- reconnect count;
- last successful send;
- last error.

TCP/TLS workers maintain long-lived connections. Dial failures use bounded exponential backoff up to 30 seconds. The capture/DPI publisher never waits for a remote collector. When queues fill, new exporter events are dropped and counted.

## Flow Export

Configure collectors from **System Settings -> Flow Export / Remote Flow Collector**. Multiple collector protocols can run simultaneously.

### Protocols

#### NetFlow v5

- standard version-5 24-byte header and 48-byte flow record;
- IPv4 only, as required by the v5 wire format;
- unidirectional source/destination records;
- packets, octets, ports, TCP flags, L4 protocol, ToS and interface index;
- deterministic sampling interval when configured.

IPv6 flows are intentionally not disguised as v5. Use NetFlow v9, IPFIX, or sFlow for IPv6.

#### NetFlow v9

- version-9 export header;
- Template FlowSet ID 0;
- separate IPv4/IPv6 template IDs;
- Data FlowSets referencing the advertised templates;
- 4-byte FlowSet alignment/padding;
- Observation Domain/Source ID;
- configurable template refresh interval;
- packet/octet counters, protocol, ToS, flags, ports, addresses, interfaces, switched times, ICMP type/code, VLAN, direction and sampling interval.

Reference: https://www.rfc-editor.org/rfc/rfc3954

#### IPFIX / NetFlow v10

- IPFIX version 10;
- Template Set ID 2;
- separate IPv4/IPv6 templates;
- Observation Domain ID;
- RFC 7011 sequence semantics: Template Records do **not** increment the Data Record sequence number;
- variable-length `applicationName` when DPI application/protocol classification is known;
- flow start/end milliseconds, counters, addresses, ports, interfaces, protocol, ToS, TCP flags, ICMP, VLAN, direction and sampling information.

Reference: https://www.rfc-editor.org/rfc/rfc7011

#### sFlow v5

sFlow is generated from live `packet_metadata` events rather than from an expired aggregate Flow. The exporter performs deterministic sampling and emits sFlow v5 flow samples using the standardized `sampled_ipv4` (format 3) and `sampled_ipv6` (format 4) records. This preserves packet-sampling semantics while still keeping raw packet payload out of the exporter event bus.

References:
- https://sflow.org/developers/structures.php
- https://sflow.org/sflow_version_5.txt

### Directional counters and active timeout correctness

NetProbe's internal host flow is bidirectional (`PacketsTX/RX`, `BytesTX/RX`). NetFlow/IPFIX records are exported as separate unidirectional records. Long-lived flows are periodically exported using **counter deltas** since the previous active-timeout export, so collector totals do not double-count cumulative host-flow counters. Inactive timeout exports only the remaining delta and retires the exporter state.

### Flow collector settings

- enable/disable;
- collector host/IP and UDP port;
- protocol: `netflow5`, `netflow9`, `ipfix`, `sflow`;
- source-interface filter;
- Observation Domain / exporter ID;
- active timeout;
- inactive timeout;
- template refresh interval;
- deterministic sampling rate;
- sFlow agent address;
- bounded queue size.

### Flow health

Each collector reports:

- active flow states;
- exported unidirectional records/samples;
- exported datagrams;
- failed exports;
- dropped exports;
- queue depth;
- template sends;
- reconnect count;
- collector state;
- last successful export and last error.

Flow collectors use UDP, as expected for the implemented NetFlow v5/v9, IPFIX and sFlow exporter paths. A successful UDP `Test` means the datagram was produced and handed to the local network stack; UDP has no protocol-level acknowledgement proving the remote application consumed it.

## Persistence and upgrades

The feature is additive and does not replace the existing v0.5 integration store.

```text
DATA_DIR/exporters/syslog.json
DATA_DIR/exporters/flow.json
```

The directory is created during normal configuration preparation. Missing files are treated as an empty configuration, so upgrading an older installation requires no destructive migration. Files are atomic-replaced and use restrictive permissions. Existing packet capture, authentication, IDS rules, cases, audit history, user database and legacy integration configuration are unchanged.

## REST API

All endpoints use the existing authentication, RBAC, scoped-token and same-origin browser protections.

Read access requires `read:integrations`. Mutations require `admin:settings` and are written to the existing audit chain.

```text
GET    /api/v1/export/syslog
POST   /api/v1/export/syslog
GET    /api/v1/export/syslog/{id}
PUT    /api/v1/export/syslog/{id}
DELETE /api/v1/export/syslog/{id}
POST   /api/v1/export/syslog/{id}/enable
POST   /api/v1/export/syslog/{id}/disable
POST   /api/v1/export/syslog/{id}/test

GET    /api/v1/export/flow
POST   /api/v1/export/flow
GET    /api/v1/export/flow/{id}
PUT    /api/v1/export/flow/{id}
DELETE /api/v1/export/flow/{id}
POST   /api/v1/export/flow/{id}/enable
POST   /api/v1/export/flow/{id}/disable
POST   /api/v1/export/flow/{id}/test
```

## Prometheus metrics

`/metrics` includes per-destination labels and counters such as:

```text
netprobe_syslog_sent_total
netprobe_syslog_failed_total
netprobe_syslog_dropped_total
netprobe_syslog_queue_depth
netprobe_syslog_reconnect_total
netprobe_syslog_last_success_timestamp_seconds
netprobe_syslog_state

netprobe_flow_exported_total
netprobe_flow_export_datagrams_total
netprobe_flow_failed_total
netprobe_flow_dropped_total
netprobe_flow_queue_depth
netprobe_flow_active
netprobe_flow_template_sends_total
netprobe_flow_reconnect_total
netprobe_flow_last_success_timestamp_seconds
netprobe_flow_state
```

The main Health/Self-Diagnostics endpoint also exposes both exporter status sets.

## Security notes

- Do not disable TLS certificate verification except in a controlled diagnostic environment.
- Clear-text UDP/TCP Syslog exposes exported metadata to network observers; the UI displays a warning.
- NetProbe validates hosts, ports, protocol names, queue bounds, timeouts, event categories and TLS client-certificate pairs on the backend. The UI performs equivalent early validation for operator feedback.
- Host/port/config values are never passed to a shell command.
- Exporter mutations use backend RBAC even if UI controls are hidden for lower-privilege roles.
- Every create/update/delete/enable/disable/test operation is audit logged.

## Test coverage

The automated suite contains real local/mock collectors and validates:

- RFC 3164 and RFC 5424 formatting;
- RFC 6587 octet-counting and non-transparent framing;
- UDP, TCP, TLS and mTLS Syslog delivery;
- TLS certificate validation failure;
- IPv4 and IPv6 Syslog transport where IPv6 loopback is available;
- reconnect/backoff and bounded-queue overflow;
- multiple concurrent Syslog targets;
- NetFlow v5 wire fields;
- NetFlow v9 IPv4/IPv6 templates and data sets;
- IPFIX IPv4/IPv6 templates, RFC 7011 sequence semantics, application metadata and template refresh;
- sFlow v5 packet-event sampling and sampled IPv4/IPv6 structures;
- unidirectional record splitting and active-timeout counter deltas;
- multiple simultaneous flow collectors;
- flow timeout and persistence;
- invalid host/port/protocol validation;
- authenticated API CRUD/test/persistence and read-vs-admin authorization;
- non-blocking event-bus load/drop behavior;
- full NetProbe regression and race detector.

See `TEST-RESULTS.md` for the release qualification actually executed on the packaged source and binaries.
