# Test — NetProbe IR v1.0.0

**Türkçe** · [English](TESTING.md) · [Dokümantasyon dizini](README_TR.md)

NetProbe IR, normal yetkisiz regression testlerini Linux capability gerektiren canlı capture testlerinden ayırır. Privileged namespace entegrasyonu gerçekten çalışıp geçmedikçe build “live-capture verified” olarak tanımlanmaz.

## v1.0.0 interaktif inceleme kapsamı

- Investigation Graph filtreleme, clustering, node/edge limitleri ve neighborhood sorguları;
- gerçek Chromium üzerinde zoom, pan, tekli/çoklu seçim, drag, rectangle selection ve context navigation;
- yalnız gözlenen verileri gösteren Asset detail ve Asset → Traffic/Graph pivotları;
- notification secret şifreleme/masking, SMTP/Telegram severity routing, hata sınıfları, dedup ve bounded queue;
- `packet_metadata` üzerinden gerçek IN/OUT trafik serisi, bounded history, 24 saat downsampling ve incremental WebSocket update;
- Overview KPI drill-down ve Executive Overview'dan Interface Acquisition'ın kaldırılması;
- bounded client history ile kısa süreli browser heap sanity.

Desteklenen ortamlarda Chromium testi, izole Linux user/network namespace içinde gerçek NetProbe daemon'a karşı çalışır; backend yerine sentetik browser telemetrisi kullanmaz.

## Standart paket

```bash
./scripts/test-all.sh
```

Paket `gofmt`, shell/JSON/JavaScript syntax, kaynak–gömülü web asset eşitliği, `go vet`, bütün Go testleri ve race detector; AMD64/ARM64 statik build, embedded self-test, metadata/link kontrolü, statik link doğrulama ve staged installer/uninstaller regression adımlarını yürütür.

## Yerleşik IDS testleri

Kapsam JNDI/Log4Shell, TCP NULL, reverse-shell/PowerShell EncodedCommand imzalarını; multi-port scan ve host sweep korelasyonunu; normal fan-out false-positive guard'ını; IP/SNI/JA3 IOC ve custom RE2 eşleşmelerini; Findings list/detail API'sini ve sunucu taraflı Hunt sonuçlarını içerir. Testler `signature_match`, `confirmed_ioc`, exposure/policy ve `behavioral` verdict'lerini birbirinden ayırır.

## v0.4–v0.6 regression kapsamı

- bpftrace/eBPF event parse, provider yaşam döngüsü ve fallback;
- STIX/TAXII, process-aware baseline, incident case/export ve Ed25519 tamper kontrolleri;
- graph, Detection Lab replay, Active Response guardrail ve federation;
- PCAPNG replay, JA4, QUIC, NPSH ve TLS certificate metadata;
- pasif AF_XDP seçiminin açıkça reddi;
- UDP/TCP/TLS/mTLS Syslog, RFC3164/5424/6587 ve sertifika hata yolları;
- NetFlow v5/v9, IPFIX v10 ve sFlow v5 wire format, template, sequence, sampling ve timeout davranışı;
- authenticated exporter CRUD/test API'leri, bounded queue ve drop accounting.

Export ayrıntıları için [İngilizce](EXPORT_SYSLOG_FLOW.md) veya [Türkçe](EXPORT_SYSLOG_FLOW_TR.md) belgeye bakın.

## Embedded self-test

```bash
./dist/netprobe-linux-amd64 --self-test
```

Sentetik decode/DPI/flow, anomali/rapor render ve PCAPNG üretim/doğrulamasını kontrol eder. Başarısız alt test non-zero çıkar.

## Gerçek Linux capture, interface ve IDS entegrasyonu

```bash
./scripts/integration-live-linux.sh
```

Uygun user/network namespace ortamında script loopback ve veth çifti oluşturup gerçek TPACKET_V3/AF_PACKET capture, HTTP DPI, gerçek Python PID attribution, paket geçmişi, bağımsız interface Stop/Start, `NP-IDS-1201` üretimi, sunucu taraflı Hunt, global Stop/Start, PCAPNG ve JSON/HTML raporlarını doğrular. Gerekli namespace/capability yoksa pass yerine **skip** göstermek için `77` ile çıkar.

## Gerçek TLS entegrasyonu

```bash
./scripts/integration-live-tls-linux.sh
```

İzole namespace içinde yerel TLS bağlantısı kurar; SNI (`localhost`), ALPN, JA3, JA4 ve NPSH metadata'sını payload decryption iddiası olmadan doğrular.

## Statik build'ler

```bash
./scripts/build-static.sh
file dist/netprobe-linux-amd64 dist/netprobe-linux-arm64
sha256sum -c dist/SHA256SUMS
```

AMD64 release ortamında çalıştırılır. ARM64 cross-compile edilir, ELF mimarisi ve checksum'u kontrol edilir; ARM64 host/emulator yoksa runtime-tested olarak tanımlanmaz.

## Installer regression

```bash
TEST_ROOT="$(mktemp -d)"
./install.sh --root "$TEST_ROOT" --bundled-only
"$TEST_ROOT/usr/local/sbin/netprobe-ir" --about
./uninstall.sh --root "$TEST_ROOT" --purge --yes
rm -rf "$TEST_ROOT"
```

Bu test gerçek host servislerini etkinleştirmez; binary/config/docs/license yerleşimini ve yalnız staged NetProbe yollarının purge edilmesini doğrular.

## Web/UI kontrolleri

JavaScript syntax, embedded asset eşitliği, route/control fonksiyonları, REST endpoint'leri, browser same-origin koruması ve UI'nin kullandığı drill-down nesneleri otomatik test edilir. Kaynak/DOM incelemesi pixel regression sayılmaz; browser render doğrulaması yalnız test raporunda açıkça kaydedildiğinde iddia edilir.

## Güvenli test sınırı

Sentetik/canlı IDS testleri local namespace, loopback/veth ve dokümantasyon için ayrılmış örnek değerleri kullanır. Amaç dış sistemleri taramak değil, izole ortamda üretilen trafiğe karşı savunma dedektörünü doğrulamaktır.

## v0.7 gelişmiş analiz testleri

File reconstruction ve hash/MIME/entropy; fake `yr` ile YARA-X adapter; Smart-PCAP privacy gate; NPDL; h2c/protocol pack/QUIC; beacon/encrypted DNS/identity/lateral analiz; KEV context; OTLP/NATS/fake-kcat/ClickHouse; WASM; self-protection; Analyst fixture'ları ve fleet command API kapsanır.

## v0.8.1 kalite ve kök neden testleri

Detection Quality hesapları, Attack Story v2, adaptive bpftrace, Sigma v2, KEV runtime korelasyonu, C2 v2, Fleet Health v2 ve bunların authenticated API yüzeyleri test edilir.

## v0.9 birlikte çalışabilirlik testleri

OCSF envelope mapping, Sigma correlation planı, Suricata/Snort coverage analizi, response playbook guardrail'leri, historical analytics, asset/TLS/DNS intelligence, runtime anomaly, SOC Performance, Profiles adapter ve release metadata yolları standart Go/regression paketi içinde doğrulanır.

Nihai çalıştırma sonuçları [`TEST-RESULTS_TR.md`](../TEST-RESULTS_TR.md) dosyasındadır.
