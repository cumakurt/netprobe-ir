# Remote Syslog ve Flow Export — NetProbe IR v0.6.0

**Türkçe** · [English](EXPORT_SYSLOG_FLOW.md) · [Dokümantasyon dizini](README_TR.md)

NetProbe IR v0.6.0, canlı DPI/ağ/güvenlik telemetrisini SIEM/log sistemlerine ve standart flow collector'lara aktaran ayrı bir **non-blocking export plane** ekler. Uzak hedefin yavaşlaması veya erişilemez olması packet capture, DPI, IDS, Hunt, PCAP kaydı ya da web panelini bloklamaz.

## Mimari

```text
Capture / Replay
      |
Decode -> Flow -> DPI -> IDS / Anomaly
      |             |
      +---- Structured Event Bus ----------------+
             |                                    |
       Syslog Dispatcher                    Flow Dispatcher
             |                                    |
       hedef başına bounded queue            hedef başına bounded queue
             |                                    |
 UDP / TCP / TLS Worker              v5 / v9 / IPFIX / sFlow Worker
             |                                    |
       SIEM / Log Collector                  Flow Collector
```

`internal/eventbus` bounded channel kullanır ve publish işlemi beklemeden döner. Her hedefin ayrıca kendi sınırlı kuyruğu vardır. Collector baskısı sınırsız RAM büyümesine değil ölçülebilir `dropped` sayacına dönüşür.

## Remote Syslog

Yapılandırma **System Settings / Sistem Ayarları -> Remote Syslog** bölümündedir. Birden fazla hedef bağımsız ve eşzamanlı çalışabilir.

### Transport ve formatlar

- UDP Syslog
- TCP Syslog
- TCP + TLS (minimum TLS 1.2)
- RFC 3164 BSD Syslog formatı
- RFC 5424 modern Syslog formatı ve NetProbe structured-data alanı
- RFC 6587 TCP framing:
  - Octet Counting: `<uzunluk> <mesaj>`
  - Non-Transparent: LF ile sonlandırma
- **TLS + RFC5424 + Octet Counting**, RFC5425 uyumlu güvenli varsayılan yoldur. TLS + non-transparent yalnız collector uyumluluğu için sunulur ve strict RFC5425 framing olarak değerlendirilmez.

Standartlar:
- https://www.rfc-editor.org/rfc/rfc3164
- https://www.rfc-editor.org/rfc/rfc5424
- https://www.rfc-editor.org/rfc/rfc5425
- https://www.rfc-editor.org/rfc/rfc6587

### TLS / mTLS

TLS sunucu sertifikası varsayılan olarak doğrulanır. Hedef başına şunlar seçilebilir:

- sistem CA deposu;
- ek PEM CA dosyası;
- TLS server-name;
- mTLS client certificate + private key dosyası;
- yalnız bilinçli troubleshooting için certificate verification kapatma.

Private-key içeriği hiçbir zaman API veya log'a verilmez. Private-key dosya yolu da standart API cevabında redakte edilir; yalnız `has_client_key=true` bilgisi gösterilir. Exporter config dosyaları `0600` izinleriyle saklanır.

### Gönderilebilen event kategorileri

| Kategori | İçerik |
|---|---|
| `security` | IDS findings, exact IOC, policy/security tespitleri |
| `network` | IP/port/protokol/flag/interface/timestamp/length/ToS/VLAN/ICMP packet metadata |
| `flow` | endpoint, sayaç, süre, process attribution, DPI ve risk alanları |
| `dpi` | uygulama/protokol classification |
| `dns` | DNS query/type/rcode/answer metadata |
| `http` | method/path/host/status/user-agent/content-type metadata |
| `tls` | TLS version/SNI/ALPN/JA3/JA4/NPSH ve görülebilir certificate metadata |
| `anomaly` | anomaly/behavioral alert ve risk kanıtı |
| `system` | capture-control ve uygulama sistem olayları |

Hedef `all` veya kategori kombinasyonu seçebilir. **Ham packet payload Syslog'a otomatik gönderilmez.** Event bus yalnız yapılandırılmış analiz nesnelerini taşır.

### Syslog health ve hata davranışı

Her hedef için web/API/metrics katmanında:

- state;
- sent;
- failed;
- dropped;
- queue depth;
- event-bus drops;
- reconnect count;
- last successful send;
- last error

izlenir. TCP/TLS bağlantıları kalıcı tutulur. Bağlantı hatalarında maksimum 30 saniyeye kadar bounded exponential backoff uygulanır. Capture/DPI publisher uzak sunucuyu hiçbir zaman beklemez.

## Flow Export

**System Settings -> Flow Export / Remote Flow Collector** bölümünde birden çok collector tanımlanabilir.

### NetFlow v5

- gerçek v5 header + 48-byte record;
- format gereği yalnız IPv4;
- unidirectional source/destination record;
- packet/octet, port, TCP flags, protocol, ToS ve interface index;
- yapılandırılmışsa deterministic sampling interval.

IPv6 verisi v5 formatına zorla sokulmaz; IPv6 için v9/IPFIX/sFlow seçilmelidir.

### NetFlow v9

- version 9 header;
- Template FlowSet ID 0;
- IPv4 ve IPv6 için ayrı template;
- Template ID'ye bağlı Data FlowSet;
- 4-byte alignment/padding;
- Source/Observation Domain ID;
- periyodik template refresh;
- counter, protocol, ToS, TCP flags, port, IP, interface, switched-time, ICMP, VLAN, direction ve sampling alanları.

Referans: https://www.rfc-editor.org/rfc/rfc3954

### IPFIX / NetFlow v10

- IPFIX v10 header;
- Template Set ID 2;
- IPv4/IPv6 template;
- Observation Domain ID;
- RFC7011 sequence semantiği: Template record'ları sequence artırmaz, yalnız Data Record sayısı artırır;
- DPI varsa variable-length `applicationName`;
- start/end milliseconds, counter, IP, port, interface, protocol, ToS, TCP flags, ICMP, VLAN, direction ve sampling.

Referans: https://www.rfc-editor.org/rfc/rfc7011

### sFlow v5

sFlow, inactive olmuş aggregate flow'dan sahte sample üretmek yerine canlı `packet_metadata` event'lerinden deterministic sampling yapar. Wire formatında standard `sampled_ipv4` format 3 ve `sampled_ipv6` format 4 record'ları kullanılır. Böylece raw payload event bus'a taşınmadan gerçek packet-sampling semantiği korunur.

Referanslar:
- https://sflow.org/developers/structures.php
- https://sflow.org/sflow_version_5.txt

### Directional record ve timeout doğruluğu

NetProbe'un iç flow modeli TX/RX sayaçlarını aynı host flow üzerinde tutar. NetFlow/IPFIX ise collector'a **ayrı unidirectional record'lar** gönderir. Uzun yaşayan flow active-timeout ile tekrar export edildiğinde kümülatif sayaçların tamamı tekrar gönderilmez; yalnız son export'tan sonraki **delta** gönderilir. Inactive timeout kalan deltayı yollar ve exporter state'i temizler. Böylece collector'da double-count oluşmaz.

### Collector ayarları

- Enable/Disable
- Host/IP ve UDP port
- `netflow5`, `netflow9`, `ipfix`, `sflow`
- source-interface filtresi
- Observation Domain / exporter ID
- active timeout
- inactive timeout
- template refresh interval
- deterministic sampling rate
- sFlow agent IP
- bounded queue size

### Flow monitoring

- active flows
- exported unidirectional records/samples
- exported datagrams
- failed exports
- dropped exports
- queue depth
- template sends
- reconnect count
- state
- last success / last error

UDP protokollerinde `Test`, geçerli datagramın oluşturulup işletim sistemi network stack'ine teslim edildiğini gösterir; UDP'de uzak uygulamanın datagramı işlediğini kanıtlayan protokol-level ACK yoktur.

## Persistence ve upgrade

Yeni yapı mevcut v0.5 configuration/integration verisini değiştirmez:

```text
DATA_DIR/exporters/syslog.json
DATA_DIR/exporters/flow.json
```

Eski kurulumda bu dosyaların bulunmaması boş export config olarak değerlendirilir. Bu nedenle destructive migration gerekmez. Yeni dosyalar atomic replace ile ve kısıtlı izinlerle yazılır. Mevcut user/auth, IDS, case, audit, packet capture ve legacy integration ayarları korunur.

## API ve yetkilendirme

Okuma için `read:integrations`, değiştirme için `admin:settings` gerekir. Browser session mutasyonlarında mevcut same-origin/CSRF kontrolü uygulanır; scoped API token otomasyonları backend scope kontrolüne tabidir. Her create/update/delete/enable/disable/test işlemi mevcut tamper-evident audit chain'e yazılır.

```text
GET/POST               /api/v1/export/syslog
GET/PUT/DELETE          /api/v1/export/syslog/{id}
POST                    /api/v1/export/syslog/{id}/enable|disable|test

GET/POST               /api/v1/export/flow
GET/PUT/DELETE          /api/v1/export/flow/{id}
POST                    /api/v1/export/flow/{id}/enable|disable|test
```

## Prometheus / Health

`/metrics` üzerinden Syslog sent/failed/dropped/queue/reconnect/last-success/state ve Flow exported/datagrams/failed/dropped/queue/active/template/reconnect/last-success/state metrikleri verilir. Aynı durumlar Health/Self-Diagnostics API'sinde de görünür.

## Güvenlik

- TLS verification varsayılan açık.
- Clear-text Syslog seçilirse UI açık uyarı verir.
- Host/IP/port/protocol/timeout/queue/category/mTLS çiftleri backend'de doğrulanır.
- Config değerleri shell komutuna taşınmaz.
- Private key içeriği log/API'ye konmaz.
- UI'da buton gizlemek yetki mekanizması değildir; gerçek RBAC backend'dedir.
- Config değişiklikleri audit edilir.

## Test kapsamı

Release testleri local/mock collector'larla gerçek socket üzerinden aşağıdakileri doğrular:

- UDP/TCP/TLS/mTLS Syslog;
- RFC3164/RFC5424;
- RFC6587 iki framing modu;
- TLS certificate validation başarısızlığı;
- IPv4 ve ortam destekliyorsa IPv6;
- reconnect/backoff ve bounded queue overflow;
- eşzamanlı çoklu Syslog hedefleri;
- NetFlow v5 wire field decode;
- NetFlow v9 IPv4/IPv6 template/data;
- IPFIX IPv4/IPv6, template refresh ve RFC7011 sequence;
- sFlow v5 sampled IPv4/IPv6;
- active-timeout counter delta;
- eşzamanlı çoklu collector;
- persistence ve flow timeout;
- hatalı host/port/protocol;
- API auth/RBAC/audit/persistence;
- event bus non-blocking yük davranışı;
- tam eski NetProbe regression ve race detector.

Final koşulan sonuçlar [`TEST-RESULTS_TR.md`](../TEST-RESULTS_TR.md) dosyasındadır.
