# Security Notes

[Türkçe](SECURITY_TR.md) · **English** · [Documentation index](README.md)

## Privilege model

Network capture requires `CAP_NET_RAW`. Full cross-user process attribution can additionally depend on `/proc` permissions, `hidepid`, Yama/ptrace policy and PID namespaces.

The simplest operational model is a root-owned system service with strong systemd sandboxing. A sample unit is provided under `packaging/systemd/`.

Do not expose the web UI to an untrusted network without authentication and TLS.

## Web binding safety

Default:

```text
127.0.0.1:8443
```

If the configured listener is not loopback, startup fails unless either:

- `auth_token` is set, or
- `allow_unauthenticated_remote` is explicitly enabled.

The second option should only be used in an already isolated management network.

## Sensitive data

PCAPNG may contain credentials, cookies, unencrypted application data, personal data and proprietary content. Treat `<data_dir>/pcap` and `<data_dir>/incidents` as sensitive forensic evidence.

Recommended controls:

- root-only directory ownership
- disk encryption
- retention limits
- disable the recorder when unnecessary
- avoid shipping PCAPs to third parties without authorization

HTTP metadata may include paths, hosts and user-agent strings. DNS queries and TLS SNI can also contain sensitive organizational information.

## TLS limitations

NetProbe IR does not decrypt TLS payloads. SNI/ALPN/JA3 are derived from visible ClientHello metadata where available. Encrypted application data remains encrypted.

## Parser hardening

Parsers use explicit length checks before reading fields. Per-flow TCP reassembly is capped by `dpi.max_stream_bytes`, and pending out-of-order segments are bounded.

## Denial-of-service considerations

An attacker who can generate large numbers of unique flows can increase memory pressure. Operators should combine interface scoping, host firewalling and suitable idle timeouts. Future releases should add a configurable hard flow-table cap and admission policy.

## Authentication token handling

Prefer storing the token in a root-readable configuration file instead of passing it on the command line, because CLI arguments may be visible in process listings.

## Reporting security issues

Security reports can be sent to the project maintainer:

- Cuma KURT
- Email: `cumakurt@gmail.com`
- Repository: `https://github.com/cumakurt/netprobe-ir`

For a suspected vulnerability, prefer a private report before public disclosure. Include the affected version, reproduction conditions, impact, and any relevant logs or PCAP excerpts after removing unrelated sensitive data.


## IDS verdict safety

NetProbe IR deliberately does not label every anomaly as a confirmed attack. `confirmed_ioc` means an exact match against operator-supplied IOC material, `signature_match` means the specified deterministic pattern was observed, and `behavioral` means a bounded correlation threshold was crossed. None of these automatically proves successful exploitation or host compromise.

Custom rule files and IOC feeds are security-sensitive configuration. Protect them with root-only write permissions, review provenance and freshness, and restart the service after updates because v0.4.0 loads them at startup. A compromised rule file can create misleading findings.

## Interface control

Web Start/Stop actions alter packet acquisition and therefore require the same API authentication as other protected endpoints. Browser control requests with an `Origin` header must be same-origin. Remote management should use TLS and an authentication token. Stopping an interface deliberately does not delete retained evidence.
