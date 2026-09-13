# NetProbe IR v0.7 Advanced Analytics, Runtime Security and Extensibility

[Türkçe](ADVANCED_V07_TR.md) · **English** · [Documentation index](README.md)

This document describes the advanced v0.7 capabilities that sit above the existing capture, process-attribution, DPI, IDS, Hunt, evidence, export and SOC-management layers.

## 1. Design principles

v0.7 follows six rules:

1. **Evidence first.** A detection must point back to retained flow, packet, process, file or case evidence whenever possible.
2. **No silent decryption claims.** Encrypted HTTP/3/TLS application headers or payloads are not reported unless actually observable.
3. **Non-blocking capture.** Malware scanning, event streaming, plugins and remote analysis are outside the hot packet path.
4. **Bounded state.** File history, queues, plugin output and analytics windows have explicit limits.
5. **Capability reporting.** Optional binaries such as `yr`, `wasmtime` and `kcat` are not treated as mandatory runtime dependencies. Their absence degrades only the associated feature.
6. **Privacy-aware retention.** Smart-PCAP policy controls both packet evidence and network-file reconstruction so metadata-only policies cannot accidentally retain payload through another subsystem.

## 2. File extraction and malware evidence

The `internal/fileextract` engine reconstructs bounded application objects from supported cleartext application traffic. It currently recognizes:

- HTTP/1 responses and multipart/form-data objects where enough in-order payload is available,
- SMTP/MIME attachments,
- FTP control/data relationships for supported passive/active transfer metadata,
- SMB2 write-oriented reconstruction for supported message sequences.

Every artifact records, when available:

- artifact ID and timestamp,
- source flow ID,
- protocol and direction,
- source/destination endpoints,
- associated process attribution,
- safe filename,
- detected MIME type,
- byte size,
- SHA-256, SHA-1 and MD5,
- Shannon entropy,
- protocol-specific metadata,
- YARA-X matches.

Reconstruction is intentionally bounded by `file_extraction.max_file_mb` and `file_extraction.max_artifacts`.

### YARA-X

If `file_extraction.yara_rules` is configured and the `yr` executable is available, stored artifacts are scanned asynchronously. The packet-processing goroutine does not wait for the scanner. A YARA-X match becomes a `signature_match` security finding with the file hash and rule identity preserved as evidence.

Example:

```json
"file_extraction": {
  "enabled": true,
  "store_payload": true,
  "max_file_mb": 32,
  "max_artifacts": 2000,
  "yara_x_binary": "yr",
  "yara_rules": "/etc/netprobe-ir/yara-rules.yar"
}
```

`configs/yara-rules.example.yar` is a demonstration file, not a production malware corpus.

## 3. Smart PCAP retention

Smart-PCAP separates observation from evidence retention. Rules are evaluated against process, application, interface, IP/CIDR and direction.

Actions:

- `full`: store the full frame and permit file reconstruction;
- `headers`: store only link/network/transport headers and do not reconstruct files;
- `metadata`: retain structured telemetry only and do not reconstruct files;
- `drop`: do not write PCAP evidence and do not reconstruct files; normal transient DPI/IDS processing still occurs.

Example:

```json
"smart_pcap": {
  "mode": "smart",
  "default_action": "headers",
  "rules": [
    {"name":"retain-curl","action":"full","process":"curl"},
    {"name":"private-subnet-metadata","action":"metadata","cidr":"10.55.0.0/16"}
  ]
}
```

This is a retention policy, not a packet firewall.

## 4. NPDL semantic scripting

NetProbe Detection Language is intentionally non-Turing-complete. It supports no shell execution, imports, filesystem access, loops or network calls.

Grammar example:

```text
rule suspicious_python_tls
 title Suspicious Python outbound TLS
 severity high
 confidence 85
 mitre T1071.001,T1059.006
 when process ~ python AND application ~ TLS AND direction = outbound
end
```

Operators:

- `=` and `!=` for case-insensitive equality,
- `~` for case-insensitive substring,
- `>`, `>=`, `<`, `<=` for numeric fields.

Common fields include `process`, `exe`, `application`, `protocol`, `direction`, `src_ip`, `dst_ip`, `remote_ip`, `port`, `sni`, `ja4`, `http_host`, `risk`, `file_sha256`, `file_name`, `yara` and `finding_rule`.

NPDL findings are labeled `script_match` and remain separate from exact IOC and built-in signature verdicts.

## 5. HTTP/2, HTTP/3 and QUIC visibility

v0.7 recognizes cleartext HTTP/2 (`h2c`) connection prefaces and SETTINGS frames and records visible settings metadata. It does not claim to decode encrypted HTTP/2 headers inside TLS without keys.

For QUIC/HTTP/3, NetProbe records observable transport metadata such as long-header packet type, version, source/destination connection IDs, Retry/version-negotiation state and the NetProbe QUIC fingerprint. HTTP/3 application headers remain encrypted in normal traffic and are therefore not invented by the sensor.

## 6. Protocol packs

Protocol analyzers are grouped into selectable packs:

- `core`: DNS, HTTP, TLS, SSH and common transport/application metadata;
- `enterprise`: SMB, RDP, Kerberos, LDAP and related administration/authentication hints;
- `database`: PostgreSQL, MySQL and Redis/RESP;
- `devops`: common infrastructure service signatures including etcd-style HTTP/2 traffic;
- `ics`: Modbus/TCP, DNP3, Siemens S7/ISO-on-TCP and BACnet/IP.

Detection uses protocol signatures when possible and well-known ports as lower-confidence hints. A port number alone is not represented as certainty.

## 7. Lateral movement and credential behavior

The lateral engine correlates outbound remote-administration/authentication traffic by process/user identity over a bounded window. It can emit behavioral findings for:

- one identity reaching many hosts using SMB/RDP/SSH/WinRM/Kerberos/LDAP,
- NTLM material observed across multiple remote hosts.

These are behavioral correlations, not proof of credential theft.

## 8. Encrypted DNS intelligence

The encrypted-DNS engine identifies observable DoT/DoQ characteristics and DoH/DoH-like usage from port, HTTP metadata and known-resolver SNI. A process allowlist can suppress expected browser/resolver activity. Unexpected encrypted DNS usage becomes a behavioral finding with process, PID, SNI and remote endpoint context.

## 9. Advanced C2 beacon analysis

Flows are grouped by PID, destination IP, destination port and application. The engine calculates:

- median connection interval,
- relative median absolute deviation (jitter),
- transfer-size similarity,
- periodicity ratio,
- an explainable 0–100 score.

Only groups meeting sample and score thresholds become findings. The UI exposes the contributing metrics instead of a black-box probability.

## 10. Identity-specific behavioral profiles

Separate profiles are learned for available identities:

- process executable/command,
- user/UID,
- container ID,
- Kubernetes namespace/pod when attribution exposes them,
- cgroup/service identity.

After a minimum observation count, NetProbe can flag a previously unseen destination, application or network-activity hour for that identity. Profiles are persisted under the data directory.

## 11. Vulnerability and KEV context

NetProbe can inventory packages from `dpkg-query`, RPM or APK and ingest a CISA-KEV-compatible JSON catalog from a local file or configured URL.

Important limitation: the KEV catalog does not supply package-manager-specific affected-version ranges. v0.7 therefore reports package/product name overlap as **exposure context**, with `proven_vulnerable=false`. It does not claim that a matching installed version is vulnerable without version-range evidence.

## 12. OTLP, NATS, Kafka and ClickHouse streaming

The internal event bus can fan out events through bounded workers:

- OTLP/HTTP Logs JSON to `/v1/logs`,
- NATS Core `PUB`, optionally over TLS,
- Kafka via the external `kcat` producer adapter,
- ClickHouse HTTP `JSONEachRow` inserts.

Capture never waits for a downstream stream target. Queue overflow increments drop counters.

Kafka support is intentionally an adapter around `kcat`; the core binary remains dependency-free. If `kcat` is absent, only that target becomes degraded.

## 13. WASM/WASI plugin runner

Optional plugins are executed with an external `wasmtime` runtime. NetProbe passes one structured event as JSON on stdin and expects JSON findings/enrichment on stdout.

Controls include:

- explicit plugin enablement,
- timeout per invocation,
- maximum accepted output size,
- no filesystem/network preopens granted by NetProbe,
- per-plugin run/failure/drop health counters.

The external runtime is optional and its absence is visible in health/status rather than crashing capture.

## 14. Fleet management

The federation layer stores bounded sensor state and supports controller-side command queues with sensor poll/ack endpoints. Commands have TTL/state/result tracking. The design keeps PCAP local by default and is intended for controlled metadata/configuration operations rather than arbitrary remote shell execution.

## 15. Evidence-based Analyst

The local analyst is deterministic and answers from bounded retained evidence: flows, findings, files and packet metadata. It returns evidence IDs with the answer.

Optional remote mode sends the bounded evidence pack to a configured OpenAI-compatible `/chat/completions` endpoint using an API key read from an environment variable. Remote mode is disabled by default and is not used by IDS, scoring or response decisions.

Organizations with confidentiality requirements should leave remote mode disabled unless their data-handling policy explicitly permits sending evidence to that endpoint.

## 16. Sensor self-protection

The self-protection monitor can baseline selected files and then detect:

- file content changes,
- watched-file disappearance,
- low free space under the data directory,
- significant backward wall-clock movement.

The web UI exposes current integrity state and an administrator-only rebaseline operation. Rebaseline is audited.

## 17. Operational dependencies

The NetProbe binary itself remains static. Optional advanced integrations can require external tools:

| Feature | Optional dependency |
|---|---|
| YARA-X scanning | `yr` |
| WASM plugins | `wasmtime` |
| Kafka producer | `kcat` |
| eBPF attribution | `bpftrace` and compatible kernel/permissions |
| Active response | platform tools such as `nft` and appropriate privilege |

Missing optional tools must not stop normal packet capture/DPI/IDS operation.

## 18. What v0.7 does not claim

- transparent decryption of TLS/HTTP/3 payloads without keys;
- full HPACK/QPACK header decoding for encrypted sessions;
- a complete Suricata/Snort community rules corpus;
- a native in-process Kafka client or JetStream durable consumer;
- proof of vulnerability solely from KEV/package-name overlap;
- safe arbitrary third-party WASM code beyond the external WASI runtime/limits described above;
- live eBPF attribution on hosts without the required kernel capability/tooling;
- active-active controller consensus or distributed SQL semantics.

See `TEST-RESULTS.md` for exactly what was executed in the release environment.
