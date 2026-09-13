# Focus / Hunt Sorgu Dili

**Türkçe** · [English](HUNT_QUERY.md) · [Dokümantasyon dizini](README_TR.md)

NetProbe IR v0.4.0, üstteki Focus barı, Security Findings, Live Traffic ve Hunt/Search alanında ortak bir sorgu dili kullanır. `/api/v1/hunt` sorguyu daemon'ın hâlâ tuttuğu evidence üzerinde sunucu tarafında çalıştırır; yalnızca tarayıcının son WebSocket snapshot'ı ile sınırlı değildir.

## Sözdizimi

Terimler AND ile birlikte değerlendirilir:

```text
src:10.10.5.20 dst:1.1.1.1 proto:tcp app:tls process:curl severity:critical
```

Boşluk içeren değerler quote edilebilir:

```text
process:"python worker" rule:LOCAL-HTTP-ADMIN-001
```

Alan adı verilmemiş serbest metin serialized evidence içinde aranır:

```text
management.example
```

## Alanlar

| Alan | Anlam |
|---|---|
| `src` | kaynak IP |
| `dst` | hedef IP |
| `ip` | iki endpoint'ten herhangi biri |
| `sport` | kaynak port |
| `dport` | hedef port |
| `port` | iki porttan herhangi biri |
| `proto` / `protocol` | L4 / tespit edilen protokol bağlamı |
| `app` / `application` | tespit edilen uygulama |
| `process` | process adı/executable |
| `pid` | attribution varsa local PID |
| `iface` / `interface` | capture interface |
| `dir` / `direction` | inbound/outbound/forwarded |
| `severity` | critical/high/medium/low/info |
| `verdict` | confirmed_ioc/signature_match/confirmed_exposure/policy_exposure/behavioral |
| `rule` | IDS/anomaly rule ID |
| `mitre` | MITRE ATT&CK technique ID |
| `category` | Security Finding kategorisi |

Karşılaştırma case-insensitive substring mantığındadır. Birden fazla terim AND'dir; v0.4.0'da OR/NOT grammar yoktur.

## Örnekler

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

## Focus, capture filtresi değildir

Focus/Hunt yalnızca gösterilen/aranan evidence'ı daraltır. AF_PACKET socket filtresini değiştirmez ve Flight Recorder'dan veriyi atmaz. Böylece analist tek IP'ye odaklanırken incident bağlamındaki diğer paketleri kaybetmez.

## Retention

- Flow'lar flow-store idle GC politikası boyunca.
- Security Finding sayısı `ids.max_findings` ile bounded.
- Packet metadata son 1000 kayıtla bounded.
- Ham tarihsel paketler için esas kaynak PCAPNG'dir.
- Behavioral alert'ler anomaly engine retention'ına bağlıdır.

Hunt response her evidence türü için toplam eşleşme sayısını verir ve istenen `limit` kadar (en fazla 5000) kayıt döndürür.

## REST örneği

```bash
curl -G http://127.0.0.1:8443/api/v1/hunt \
  --data-urlencode 'q=src:10.0.0.8 severity:critical' \
  --data-urlencode 'limit=500'
```
