# Yerleşik IDS, Security Findings ve Threat-Hunting Modeli

**Türkçe** · [English](IDS_SECURITY.md) · [Dokümantasyon dizini](README_TR.md)

NetProbe IR v0.4.0; paket çözümleme, flow state, DPI ve proses korelasyonunun üzerine host-aware bir IDS katmanı ekler. Amaç yalnızca alarm üretmek değil, mümkün olduğunda alarmı **paket → flow → interface → PID/executable → DPI kanıtı** zincirine bağlamaktır.

## Kesinlik modeli: severity ile verdict aynı şey değildir

Her bulgu `severity`, `verdict` ve `confidence` alanlarını ayrı taşır.

| Verdict | Anlamı |
|---|---|
| `confirmed_ioc` | Operatörün verdiği IOC ile birebir eşleşme. Eşleşmeyi doğrular; IOC kaynağının doğruluğunu/malicious olduğunu bağımsız olarak doğrulamaz. |
| `signature_match` | Paket/uygulama içeriği deterministik güçlü bir imzayla eşleşti. Desenin görüldüğüne güçlü kanıttır; exploit'in başarılı olduğunu tek başına ispatlamaz. |
| `confirmed_exposure` | Cleartext credential/protokol gibi doğrudan gözlenebilir güvensiz durum. |
| `policy_exposure` | Internet'e SMB gibi yüksek riskli sınır/politika ihlali. Yerel mimariyle doğrulanmalıdır. |
| `behavioral` | Stateful korelasyon/heuristic eşiği aşıldı. Hunting için değerlidir fakat compromise kanıtı değildir. |

Bu ayrım sayesinde “yüksek entropili DNS olabilir” ile operatörün verdiği exact IOC eşleşmesi aynı kesinlikte gösterilmez.

## Yerleşik kural kataloğu

| Kural | Severity | Verdict | Tespit | MITRE |
|---|---|---|---|---|
| `NP-IDS-1001` | high | signature_match | TCP SYN+FIN anormal/scan paterni | T1046 |
| `NP-IDS-1002` | high | signature_match | TCP SYN+RST anormal kombinasyonu | — |
| `NP-IDS-1003` | high | signature_match | TCP NULL scan | T1046 |
| `NP-IDS-1004` | high | signature_match | TCP XMAS scan | T1046 |
| `NP-IDS-1101` | high | behavioral | kısa pencerede çok sayıda farklı hedef porta erişim | T1046 |
| `NP-IDS-1102` | high | behavioral | kısa pencerede çok sayıda farklı host'a erişim | T1046 |
| `NP-IDS-1201` | critical | signature_match | `${jndi:...}` Log4Shell/JNDI injection paterni | T1190 |
| `NP-IDS-1202` | critical | signature_match | HTTP benzeri header içinde Shellshock fonksiyon paterni | T1190 |
| `NP-IDS-1203` | high | signature_match | yaygın vulnerability scanner/recon User-Agent | T1046 |
| `NP-IDS-1204` | high | signature_match | HTTP path traversal encodingleri | T1190 |
| `NP-IDS-1205` | high | signature_match | HTTP path içinde yaygın SQLi tokenları | T1190 |
| `NP-IDS-1206` | critical | signature_match | HTTP command-injection/download-shell tokenları | T1059, T1190 |
| `NP-IDS-1207` | critical | signature_match | plaintext reverse-shell / encoded PowerShell komut tokenları | T1059 |
| `NP-IDS-1301` | high | confirmed_exposure | TLS olmadan HTTP Basic Authorization | T1557 |
| `NP-IDS-1302` | high | confirmed_exposure | cleartext FTP USER/PASS | — |
| `NP-IDS-1303` | high | confirmed_exposure | cleartext Telnet | — |
| `NP-IDS-1304` | high | confirmed_exposure | TLS kanıtı olmadan POP3/IMAP credential benzeri auth | — |
| `NP-IDS-1401` | critical | policy_exposure | external ağa outbound SMB/445 | T1021.002 |
| `NP-IDS-1402` | high | policy_exposure | external kaynaktan local RDP/3389 | T1021.001 |
| `NP-IDS-1501` | high | behavioral | tekrarlayan uzun/yüksek entropili DNS label; tunneling şüphesi | T1048.003 |
| `NP-IDS-1502` | medium | behavioral | yoğun NXDOMAIN; DGA/faulty generation şüphesi | T1071.004 |
| `NP-IDS-1701` | medium | policy_exposure | cleartext HTTP üzerinden executable/script benzeri teslimat | T1105 |
| `NP-IDS-1901` | medium | behavioral | olağandışı büyük ICMP payload; tunnel/covert transfer şüphesi | T1095 |
| `NP-IOC-IP` | critical | confirmed_ioc | exact source/destination IP IOC | T1071 |
| `NP-IOC-DOMAIN` | critical | confirmed_ioc | DNS domain IOC | T1071.004 |
| `NP-IOC-SNI` | critical | confirmed_ioc | TLS SNI/domain IOC | T1071.001 |
| `NP-IOC-JA3` | critical | confirmed_ioc | exact JA3 IOC | T1071.001 |

Bu motor Suricata/Snort'un binlerce community signature'ını kopyalamaya çalışmaz. NetProbe IR'ın farkı, bulguyu yerel PID/executable/cgroup/container ve forensic evidence ile bağlamaktır.

## Stateful korelasyon

Connection ve DNS olayları bounded zaman penceresinde tutulur. Local outbound trafik attribution içeriyorsa actor olarak proses tercih edilir; inbound/forwarded trafikte remote/source IP kullanılır. Böylece tek prosesin 25 porta erişimiyle 25 bağımsız kaynağın birer bağlantısı aynı olay gibi yorumlanmaz.

False-positive kontrolü için multi-port scan kuralı **aynı hedef host** üzerindeki farklı destination portları; host-sweep ise **aynı destination servis portu** üzerindeki farklı hedef hostları sayar. Böylece normal browser/CDN trafiğinin ilgisiz host+port fan-out davranışı bu kuralla host sweep sayılmaz. IDS connection/DNS state tabloları en yeni 50.000 olayla hard-cap edilir; finding dedup tablosu da bounded/expiry mekanizmasıyla sınırlanır. Böylece yüksek-cardinality saldırgan trafiği detector belleğini sınırsız büyütemez.

Örnek IDS config:

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

`home_nets`, external boundary/policy kurallarını yorumlamak için kullanılır. RFC1918, loopback, link-local ve multicast adresler ayrıca non-external kabul edilir.

## Exact IOC dosyası

`configs/iocs.example.json` örneği:

```json
{
  "ips": ["203.0.113.66"],
  "domains": ["malware.example"],
  "sni": ["c2.example"],
  "ja3": ["0123456789abcdef0123456789abcdef"]
}
```

Domain karşılaştırması case-insensitive'dir ve alt domainleri de kapsar. Örnek değerler dokümantasyon içindir. Binary içine hızla eskiyecek sabit bir threat feed gömülmez.

`confirmed_ioc`, “gözlenen alan konfigüre edilen IOC ile birebir eşleşti” anlamına gelir; IOC kaynağının güncel/güvenilir/malicious olduğunu ayrıca ispatlamaz.

## Custom JSON IDS rule pack

`configs/ids-rules.example.json` örnek rule pack'tir. Startup sırasında en fazla 500 custom rule yüklenir. Parse/regex hataları `/api/v1/status` ve System ekranında görünür.

Desteklenen `field` değerleri:

- `payload` — decode edilmiş paketin ilk 16 KiB payload'ı
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

Operatörler:

- `contains` / varsayılan
- `equals`
- `prefix`
- `suffix`
- `regex` — Go RE2; catastrophic-backtracking yapan regex motoru kullanılmaz

Opsiyonel `protocol`, rule'u L4 veya DPI protokolüne; `direction` ise `inbound`, `outbound`, `forwarded` yönüne sınırlar.

Örnek:

```json
{
  "id": "LOCAL-HTTP-ADMIN-001",
  "enabled": true,
  "title": "Sensitive admin path reached",
  "description": "Yerel politika örneği.",
  "severity": "high",
  "confidence": 90,
  "verdict": "policy_exposure",
  "category": "local-policy",
  "tactic": "Initial Access",
  "mitre": ["T1190"],
  "protocol": "HTTP",
  "field": "http.path",
  "operator": "regex",
  "value": "(?i)^/(admin|management)(/|\\?|$)"
}
```

## Security Findings ekranı

Her bulgu tıklanabilir ve şunları gösterir:

- severity
- verdict
- confidence
- rule ID/title/category
- source/destination
- interface/direction
- PID/process
- protocol/application
- MITRE teknikleri
- evidence alanı
- ilişkili packet ID / flow ID

Detay ekranından kaynak/hedef IP, protocol, interface ve process tek tıkla Focus/Hunt filtresine aktarılabilir.

## Incident PCAP koruma

High/critical bulgular Flight Recorder'ın protect mekanizmasını tetikler. `incident_copies` açıksa tamamlanmış yakın PCAPNG segmentleri rule ID bağlamıyla `incidents/` altında korunur.

## Kritik sınırlar

- TLS payload decrypt edilmez; TLS tarafında SNI/JA3 gibi görünür metadata kullanılır.
- Signature match, exploit'in başarıyla çalıştığını tek başına ispatlamaz.
- Behavioral bulgu analist doğrulaması gerektiren hipotezdir.
- Process attribution yalnızca local-host kanıtıdır; forwarded trafik için hayali PID üretilmez.
- Bridge/VPN/NAT/container topolojisi aynı mantıksal trafiği birden fazla interface'te gösterebilir.
- Built-in rule set, olgun community IDS ekosistemlerinden bilinçli olarak daha küçüktür.

Geniş commodity signature coverage gereken ortamlarda NetProbe IR'ı Suricata gibi olgun bir NIDS ile birlikte kullanmak en doğru yaklaşımdır.
