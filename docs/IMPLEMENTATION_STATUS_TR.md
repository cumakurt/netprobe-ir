# Uygulama Durumu — NetProbe IR v1.0.0

**Türkçe** · [English](IMPLEMENTATION_STATUS.md) · [Dokümantasyon dizini](README_TR.md)

Bu belge, **uygulanmış ve sürüm testlerinden geçmiş davranışları** ortam koşullarına bağlı yeteneklerden ve bilinçli kapsam dışı iddialardan ayırır. Arayüzde görülen bir özellik adının, sensörün teknik olarak veremeyeceği bir garanti gibi yorumlanmasını önler.

## Uygulanmış v1.0 inceleme, bildirim ve canlı trafik yolu

- zoom/pan/select/drag/rectangle selection, çoklu seçim ve session node konumları sunan Canvas Investigation Graph;
- sunucu taraflı graph filtreleme, zaman aralığı, neighborhood sorgusu, clustering, edge aggregation ve sert sonuç limitleri;
- interaktif Asset ayrıntıları ve context-aware pivotlar;
- backend severity enforcement kullanan şifreli Email/Telegram notification config'i;
- sınırlı asynchronous queue, exponential retry, cooldown/dedup ve temizlenmiş delivery hataları;
- gerçek SMTP clear/STARTTLS/implicit TLS ile Telegram Bot API test/gönderim yolları;
- packet metadata tabanlı IN/OUT trafik serisi, sınırlı saklama, history downsampling ve incremental WebSocket noktaları;
- 1m/5m/15m/1h/24h dashboard aralıkları ve yalnız arayüzü durduran Pause/Resume;
- Go/server/live-kernel testlerine ek gerçek Chromium uçtan uca etkileşim paketi.

Notification secret'ları settings API tarafından düz metin döndürülmez. MAC/hostname gibi gözlenmeyen Asset alanları uydurulmaz; boş bırakılır.

## Uygulanmış temel sensör yolu

- TPACKET_V3/PACKET_MMAP ve AF_PACKET fallback ile pasif Linux capture;
- Ethernet/VLAN, IPv4/IPv6, TCP/UDP/ICMP decode;
- `/proc` tabanlı socket/proses attribution, opsiyonel bpftrace/eBPF provider ve otomatik fallback;
- flow tracking, TCP başlangıç reassembly ve yerleşik protokol metadata çıkarımı;
- DNS, HTTP/1, TLS ClientHello/ServerHello, JA3, JA4, NPSH, QUIC long-header ve gözlenebilir certificate metadata'sı;
- cleartext HTTP/2 preface/SETTINGS ve HTTP/3/QUIC transport sınıflandırması;
- core, enterprise, database, DevOps ve ICS/OT protokol paketleri;
- yerleşik IDS, tam IOC eşleşmesi, özel JSON kuralları, anomali korelasyonu, Hunt/Focus ve davranış baseline'ları;
- dönen PCAPNG Flight Recorder ve Smart-PCAP saklama politikası;
- normal decode/DPI/IDS hattı üzerinden PCAP/PCAPNG replay;
- incident case, imzalı evidence bundle, Attack Story ve Investigation Graph;
- güvenli web authentication/RBAC/MFA/API token/OIDC/audit/backup/response approval;
- standart Remote Syslog, NetFlow v5/v9, IPFIX ve sFlow export;
- STIX/TAXII threat intelligence;
- sensor federation/fleet metadata ve command queue/poll/ack.

## Uygulanmış v0.7 gelişmiş yol

### Dosya ve malware kanıtı

- sınırlı HTTP/1, SMTP/MIME, FTP ve desteklenen SMB2 file/object reconstruction;
- SHA-256/SHA-1/MD5, MIME, boyut ve entropi;
- dış `yr` üzerinden opsiyonel asynchronous YARA-X adapter;
- YARA eşleşmelerinden güvenlik bulgusu ve graph üzerinde flow/proses bağlantısı;
- Smart-PCAP `headers`, `metadata` ve `drop` modlarında file payload saklamasının engellenmesi.

### Tespit ve davranış

- Turing-complete olmayan NPDL semantic rule'ları;
- jitter-aware C2 beacon analizi ve encrypted DNS davranış zekâsı;
- process/user/container/pod/service identity profilleri;
- lateral movement ve NTLM fan-out korelasyonu;
- paket envanteri ve CISA-KEV uyumlu exposure context.

### Genişletilebilirlik ve veri düzlemi

- OTLP/HTTP Logs, NATS Core, `kcat` üzerinden Kafka ve ClickHouse JSONEachRow export;
- timeout/output limitli ve NetProbe tarafından filesystem/network preopen verilmeyen dış `wasmtime` WASI runner;
- evidence-based yerel Analyst ve opsiyonel, sınırlı OpenAI-compatible remote mod;
- watched-file bütünlüğü, disk baskısı ve saat geri dönüşü self-protection kontrolleri.

## Uygulanmış v0.8.1 kalite ve kök neden yolu

- etiketlenmiş Detection Lab çalışmalarıyla beslenen kalıcı Detection Quality Center;
- runtime/file/network aşamaları, risk timeline ve probable-root-cause inference içeren Attack Story v2;
- sınırlı runtime-event geçmişi ve Event Bus yayını;
- adaptive bpftrace syscall tracepoint keşfi;
- Sigma v2 deterministic subset evaluator ile coverage/warning;
- KEV + finding + runtime exploit korelasyonu;
- zamanlama, boyut, TX/RX, destination rotation ve JA4 reuse içeren C2 v2 puanlaması;
- Fleet Health v2 freshness/health/drift puanlaması.

## Uygulanmış v0.9 birlikte çalışabilirlik ve yönetici yolu

- tıklanabilir KPI drill-down içeren ve Interface Acquisition paneli kaldırılmış CISO Overview;
- OCSF-compatible canonical event envelope'ları;
- Sigma correlation plan parser/compiler;
- coverage/review raporlu Suricata/Snort subset import analyzer;
- dry-run, approval-required ve açık automatic modlu response playbook'ları;
- mevcut approval store'a bağlı active-response işlemleri;
- sınırlı local historical analytics;
- Asset Intelligence ve CycloneDX/SPDX host inventory;
- local CIDR/ASN/organization/country enrichment;
- TLS certificate/SPKI reuse intelligence ve DNS infrastructure graph;
- seçili yüksek sinyalli Linux davranışları için runtime anomaly detection;
- denetlenebilir CO-RE BPF source/build/readiness yolu;
- Unified Investigation Workspace ve SOC Performance UI;
- deneysel OpenTelemetry Profiles HTTP adapter;
- CycloneDX/SPDX SBOM, provenance, reproducibility kontrolleri ve opsiyonel Ed25519 manifest imzası.

## Ortama bağlı yetenekler

### Canlı eBPF / CO-RE telemetrisi

Adaptive provider uyumlu Linux kernel, yetki ve `bpftrace` gerektirir; bulunmadığında `/proc` attribution devam eder. CO-RE yolu için BTF, `bpftool` ve build toolchain gerekir. Sürüm hostunda bunlar bulunmadığından native CO-RE canlı başarı iddia edilmez ve arayüz fallback durumunu gösterir.

### YARA-X, WASM ve Kafka

YARA-X için yapılandırılmış kural dosyası ve `yr`, WASM plugin'leri için `wasmtime`, Kafka adapter'ı için `kcat` gerekir. Eksik runtime yalnız ilgili capability'yi degraded/unavailable yapar; ana capture/DPI/IDS/konsol çalışmaya devam eder. Üçüncü taraf modüller güvenilmeyen yazılım kabul edilip incelenmelidir.

### Active response

Uygun işletim sistemi aracı ve yetki gerekir. Otomatik testler guardrail ve komut üretimini doğrular; sürüm testleri production firewall/interface durumunu bilinçli olarak değiştirmez veya rastgele proses sonlandırmaz.

### Vulnerability context

KEV kataloğu bilinen exploit bağlamı sağlar fakat dağıtım paketleri için etkilenen sürüm aralıklarını sağlamaz. Ürün/paket adı örtüşmelerinde `proven_vulnerable=false` kalır; bu bir önceliklendirme sinyalidir, kesin zafiyet kanıtı değildir.

### Remote Analyst

Remote mod açıkça yapılandırılan endpoint ve API key ister, sınırlı retained evidence'ı sensör dışına gönderir ve varsayılan olarak kapalıdır. Yalnız kurumun veri işleme politikası izin veriyorsa etkinleştirilmelidir.

## Bilinçli olarak iddia edilmeyenler

NetProbe IR v1.0.0 şunları eksiksiz desteklediğini iddia etmez:

- güvenli pasif host sniffing için production AF_XDP zero-copy redirect;
- session key olmadan TLS/HTTP3 payload decryption veya encrypted HPACK/QPACK görünürlüğü;
- nDPI ya da tam Suricata/Snort rule language/community corpus uyumu;
- yalnız KEV ürün adı örtüştüğü için kurulu sürümün zafiyetli olduğunun kanıtı;
- yalnız local cgroup/proses verisinden tam Kubernetes API inventory/enrichment;
- native in-process Kafka veya NATS JetStream durability;
- active-active controller consensus ya da distributed SQL control plane;
- YARA-X/rule yokken garanti malware detection;
- remote LLM'nin güvenlik kararı otoritesi olması;
- multi-tenant isolation;
- release host üzerinde doğrulanmış aktif CO-RE userspace loader;
- eksiksiz Sigma specification uyumu;
- probable root-cause inference'ın kesinlik olması.

## Sürüm doğrulaması

Çalıştırılan komutlar, live-kernel testleri, opsiyonel capability skip'leri ve paket doğrulama sonuçları [`TEST-RESULTS_TR.md`](../TEST-RESULTS_TR.md) dosyasındadır.
