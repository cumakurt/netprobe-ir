# Focus / Hunt Query Language

[Türkçe](HUNT_QUERY_TR.md) · **English** · [Documentation index](README.md)

NetProbe IR v0.4.0 has one query model shared by the focus bar, Security Findings, Live Traffic and the Hunt/Search workspace. The dedicated `/api/v1/hunt` endpoint executes the query against evidence still retained by the daemon; it is not limited to the browser's current WebSocket snapshot.

## Syntax

Terms are ANDed:

```text
src:10.10.5.20 dst:1.1.1.1 proto:tcp app:tls process:curl severity:critical
```

Quoted values preserve spaces:

```text
process:"python worker" rule:LOCAL-HTTP-ADMIN-001
```

Free text searches the serialized evidence object:

```text
management.example
```

## Fields

| Field | Meaning |
|---|---|
| `src` | source IP |
| `dst` | destination IP |
| `ip` | either endpoint |
| `sport` | source port |
| `dport` | destination port |
| `port` | either port |
| `proto` / `protocol` | L4 and/or detected protocol context |
| `app` / `application` | detected application |
| `process` | comm/executable/process label |
| `pid` | local PID when attributed |
| `iface` / `interface` | capture interface |
| `dir` / `direction` | inbound/outbound/forwarded |
| `severity` | critical/high/medium/low/info |
| `verdict` | confirmed_ioc/signature_match/confirmed_exposure/policy_exposure/behavioral |
| `rule` | IDS or anomaly rule identifier |
| `mitre` | MITRE ATT&CK technique identifier |
| `category` | security finding category |

Matching is case-insensitive substring matching. Multiple terms are ANDed; there is no OR/NOT grammar in v0.4.0.

## Examples

```text
src:10.0.0.8 app:dns
process:curl dst:1.1.1.1
severity:critical verdict:signature_match
rule:NP-IDS-1201
mitre:T1046
iface:eth0 dir:outbound process:python
port:445
app:tls dst:203.0.113
```

## UI focus versus capture filtering

Focus/Hunt filters **display/search results**. They do not modify the AF_PACKET capture socket and do not discard evidence from the flight recorder. This is deliberate: an analyst can focus on one IP without losing surrounding evidence needed to reconstruct the incident.

## Retention semantics

- Flows are available while retained by the flow store and its idle-GC policy.
- Security Findings are bounded by `ids.max_findings`.
- Recent packet metadata is bounded to 1000 records.
- Raw historical packet evidence belongs in PCAPNG, not in the in-memory Hunt API.
- Behavioral alerts use the anomaly engine's retained alert history.

The Hunt response reports total matches per evidence type and returns up to the requested per-type `limit` (maximum 5000).

## REST example

```bash
curl -G http://127.0.0.1:8443/api/v1/hunt \
  --data-urlencode 'q=src:10.0.0.8 severity:critical' \
  --data-urlencode 'limit=500'
```

Authenticated remote binding:

```bash
curl -H 'Authorization: Bearer <token>' -G https://sensor.example/api/v1/hunt \
  --data-urlencode 'q=process:curl dst:1.1.1.1'
```
