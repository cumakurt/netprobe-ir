# Native IDS, Security Findings and Threat-Hunting Model

[Türkçe](IDS_SECURITY_TR.md) · **English** · [Documentation index](README.md)

NetProbe IR v0.4.0 adds a native, host-aware IDS layer on top of packet decoding, flow state, DPI and process attribution. It is designed for incident response: every detection is linked back to retained packet metadata, flow context, interface and local process information whenever Linux can provide it.

## Detection certainty model

Severity and certainty are different concepts. The console therefore exposes both `severity` and `verdict`, plus a numeric `confidence`.

| Verdict | Meaning |
|---|---|
| `confirmed_ioc` | Exact match against an IOC explicitly supplied by the operator. It confirms the match, not the correctness/reputation of the external IOC source. |
| `signature_match` | Packet/application content matched a strong deterministic signature. It is strong evidence of the observed pattern, but a match alone does not prove exploitation succeeded. |
| `confirmed_exposure` | A directly observable insecure condition, for example cleartext credentials/protocol use. |
| `policy_exposure` | Traffic violates a high-risk boundary/policy assumption, such as Internet-bound SMB. Validate against local architecture. |
| `behavioral` | Stateful correlation crossed a heuristic threshold. Useful for hunting; it must not be treated as proof of compromise. |

This model intentionally prevents a high-entropy DNS heuristic from being displayed with the same certainty as an exact operator-supplied IOC.

## Built-in rule catalog

| Rule | Default severity | Verdict | What it detects | MITRE mapping |
|---|---|---|---|---|
| `NP-IDS-1001` | high | signature_match | TCP SYN+FIN malformed/scan pattern | T1046 |
| `NP-IDS-1002` | high | signature_match | TCP SYN+RST malformed combination | — |
| `NP-IDS-1003` | high | signature_match | classic TCP NULL scan pattern | T1046 |
| `NP-IDS-1004` | high | signature_match | classic TCP XMAS (FIN+PSH+URG) pattern | T1046 |
| `NP-IDS-1101` | high | behavioral | one actor reaches many unique destination ports inside the state window | T1046 |
| `NP-IDS-1102` | high | behavioral | one actor reaches many unique destination hosts inside the state window | T1046 |
| `NP-IDS-1201` | critical | signature_match | `${jndi:...}` Log4Shell-style JNDI injection token | T1190 |
| `NP-IDS-1202` | critical | signature_match | Shellshock-style function syntax in HTTP-like headers | T1190 |
| `NP-IDS-1203` | high | signature_match | common vulnerability-scanner/recon User-Agent strings | T1046 |
| `NP-IDS-1204` | high | signature_match | HTTP path traversal encodings | T1190 |
| `NP-IDS-1205` | high | signature_match | common SQL injection tokens in the HTTP path | T1190 |
| `NP-IDS-1206` | critical | signature_match | command-injection/download-shell tokens in HTTP path | T1059, T1190 |
| `NP-IDS-1207` | critical | signature_match | plaintext reverse-shell / encoded PowerShell command tokens | T1059 |
| `NP-IDS-1301` | high | confirmed_exposure | HTTP Basic Authorization observed without TLS | T1557 |
| `NP-IDS-1302` | high | confirmed_exposure | FTP USER/PASS commands on cleartext control channel | — |
| `NP-IDS-1303` | high | confirmed_exposure | Telnet cleartext remote terminal traffic | — |
| `NP-IDS-1304` | high | confirmed_exposure | POP3/IMAP credential-like authentication without TLS evidence | — |
| `NP-IDS-1401` | critical | policy_exposure | outbound SMB/445 to an external network | T1021.002 |
| `NP-IDS-1402` | high | policy_exposure | inbound external RDP/3389 to the monitored host | T1021.001 |
| `NP-IDS-1501` | high | behavioral | repeated long, high-entropy DNS labels consistent with tunneling | T1048.003 |
| `NP-IDS-1502` | medium | behavioral | excessive NXDOMAIN responses consistent with DGA/faulty generation | T1071.004 |
| `NP-IDS-1701` | medium | policy_exposure | executable/script-like object received over cleartext HTTP | T1105 |
| `NP-IDS-1901` | medium | behavioral | unusually large ICMP payload consistent with tunnel/covert transfer | T1095 |
| `NP-IOC-IP` | critical | confirmed_ioc | exact source/destination IP IOC match | T1071 |
| `NP-IOC-DOMAIN` | critical | confirmed_ioc | configured domain IOC match in DNS | T1071.004 |
| `NP-IOC-SNI` | critical | confirmed_ioc | configured domain/SNI IOC match in TLS ClientHello | T1071.001 |
| `NP-IOC-JA3` | critical | confirmed_ioc | exact configured JA3 fingerprint match | T1071.001 |

Rules are intentionally bounded and explainable. They do not claim to replace a full Suricata/Snort signature ecosystem. NetProbe IR's differentiator is that a finding can also carry PID/executable/cgroup/container attribution and direct links to packet/flow evidence.

## Stateful correlation

The IDS keeps short bounded windows for connection and DNS events. For local outbound traffic, a process identity is preferred as the actor when process attribution is available. For inbound/forwarded traffic, the remote/source IP is used. This makes a local process touching 25 ports materially different from unrelated traffic from 25 sources.

Configurable thresholds:

```json
"ids": {
  "enabled": true,
  "home_nets": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "port_scan_ports": 20,
  "host_sweep_hosts": 20,
  "window_seconds": 30,
  "dns_high_entropy_queries": 12,
  "nxdomain_threshold": 20,
  "ioc_file": "/etc/netprobe-ir/iocs.json",
  "rules_file": "/etc/netprobe-ir/ids-rules.json",
  "max_findings": 5000
}
```

`home_nets` is used to interpret boundary/external-network policy rules. RFC1918, loopback, link-local and multicast addresses are treated as non-external even when `home_nets` is empty.

## Exact IOC file

Use `configs/iocs.example.json` as a template:

```json
{
  "ips": ["203.0.113.66"],
  "domains": ["malware.example"],
  "sni": ["c2.example"],
  "ja3": ["0123456789abcdef0123456789abcdef"]
}
```

Domain matching is case-insensitive and matches the exact name plus its subdomains. The example addresses/domains are documentation-only values. NetProbe IR intentionally does not ship a stale hard-coded reputation feed.

A `confirmed_ioc` verdict means “the observed field exactly matched the configured IOC data.” It does **not** independently establish that the IOC feed itself is correct, current or malicious.

## Custom JSON rule packs

`configs/ids-rules.example.json` demonstrates the rule format. Up to 500 custom rules are loaded at startup. Invalid files/rules are reported through `/api/v1/status` and the System console.

Supported matching fields:

- `payload` — first 16 KiB of the decoded packet payload
- `http.path`
- `http.host`
- `http.user_agent`
- `dns.query`
- `tls.sni`
- `tls.ja3`
- `process` — executable + comm
- `src.ip`
- `dst.ip`
- `application`

Supported operators:

- `contains` (also the default for an unknown/empty operator)
- `equals`
- `prefix`
- `suffix`
- `regex` — Go RE2 syntax; no catastrophic backtracking engine is used

Optional `protocol` can constrain a rule to the L4 or detected DPI protocol. Optional `direction` can constrain it to `inbound`, `outbound` or `forwarded`.

Example:

```json
{
  "id": "LOCAL-HTTP-ADMIN-001",
  "enabled": true,
  "title": "Sensitive admin path reached",
  "description": "Example local policy rule.",
  "severity": "high",
  "confidence": 90,
  "verdict": "policy_exposure",
  "category": "local-policy",
  "tactic": "Initial Access",
  "mitre": ["T1190"],
  "tags": ["http", "admin"],
  "protocol": "HTTP",
  "field": "http.path",
  "operator": "regex",
  "value": "(?i)^/(admin|management)(/|\\?|$)"
}
```

Custom rules should encode local policy and known-good threat intelligence, not simply maximize alert volume.

## Security Findings console

The dedicated Security Findings route shows:

- severity
- verdict and confidence
- rule ID/title/category
- timestamp
- source and destination endpoint
- direction/interface
- process/PID when attributable
- application/protocol
- MITRE technique IDs
- evidence map
- linked packet ID and flow ID

Every retained finding is clickable. The detail screen links to the associated flow/packet/process and exposes one-click Focus buttons that create a Hunt filter around the relevant source, destination, protocol, process or interface.

## Evidence protection

High/critical native IDS findings call the flight recorder protection hook. When recorder incident copies are enabled, recent completed PCAPNG segments are preserved under the incident directory using the rule ID as incident context.

## Important limitations

- TLS application payload is not decrypted. TLS-based findings are limited to visible metadata such as SNI/JA3 unless traffic itself is cleartext.
- Packet signatures inspect a bounded payload region and can miss patterns split in ways not reconstructed by the relevant parser.
- Process attribution is local-host evidence; forwarded traffic intentionally has no invented PID.
- NAT, VPN, bridge and container topology can expose one logical conversation on multiple interfaces.
- A signature match proves the pattern was observed, not that exploitation succeeded.
- Behavioral detections are hypotheses requiring analyst validation.
- The built-in engine is intentionally much smaller than mature community IDS rule ecosystems.

For environments that need broad commodity signature coverage, use NetProbe IR alongside Suricata and correlate alerts operationally; do not disable a mature network IDS merely because NetProbe IR provides host-aware findings.
