# NetProbe IR v0.9.0 — Birlikte Çalışabilirlik, Investigation ve CISO Görünümü

**Türkçe** · [English](ADVANCED_V09.md) · [Dokümantasyon dizini](README_TR.md)

v0.9.0 mevcut `packet → flow → process → file → finding → story → case` zincirini büyütür; ikinci bir capture, auth veya response altyapısı kurmaz. Yeni servisler aynı bounded telemetry, RBAC, audit ve evidence katmanlarını kullanır.

## 1. CISO odaklı Overview

Overview artık **Interface Acquisition** tablosu göstermez. Interface ayrıntıları `Interfaces` ve `SOC Performance` sayfalarındadır. Overview; güvenlik duruşu, yüksek-confidence kanıt, 24 saatlik risk eğilimi, Attack Story/exploit zincirleri, Detection Quality ve Fleet resilience gibi karar verici metriklere odaklanır.

En üst KPI kartlarının tamamı tıklanabilir drill-down'dır. Örnek:

- Active Flows → Live Traffic
- Critical/Confirmed Findings → Security Findings
- Processes → Applications
- Captured Data → Live Traffic

## 2. OCSF uyumlu canonical event envelope

`internal/ocsf`, finding/flow/runtime event'lerini ortak bir canonical envelope'a dönüştürür. Amaç exporter ve SIEM entegrasyonlarında field drift'i azaltmaktır.

```text
GET /api/v1/ocsf?kind=findings|flows|runtime
```

Bu sürüm “tam OCSF implementasyonu” iddia etmez. Response bunu açıkça `ocsf-compatible-canonical-envelope` olarak tanımlar; kayıpsız normalize edilemeyen bilgiler `unmapped` alanında kalabilir.

## 3. Sigma correlation

v0.8.1 Sigma detection parser'ına ek olarak:

- event_count
- value_count
- temporal
- temporal_ordered
- group-by
- timespan
- gte/lte threshold

destekli correlation planı eklenmiştir.

```bash
netprobe sigma --correlation --in configs/sigma-correlation.example.yml
```

Unsupported semantik sessizce yok sayılmaz.

## 4. Suricata/Snort import analyzer

Importer; `alert/drop/reject/pass`, TCP/UDP/ICMP/IP header'ları ve `msg`, `sid`, `rev`, `classtype`, `flow`, `content`, `nocase`, offset/depth/distance/within, `pcre`, threshold/detection_filter/reference alt kümesini analiz eder.

Her kural için coverage ve `requires_review` döner. Desteklenmeyen option'lar açıkça listelenir.

```bash
netprobe import-rule --file configs/suricata-rules.example.rules
```

## 5. Response Playbooks

Üç açık çalışma modu vardır:

- `dry_run`
- `approval_required`
- `automatic`

Koşullar severity/confidence/verdict/category/tag/YARA/KEV evidence alanlarını kullanabilir. Action'lar mevcut Active Response/Case/PCAP koruma yollarını kullanır. Automatic mod, response engine'in global `enabled`, `dry_run`, `allowed_actions` ve allowlist güvenlik kontrollerini atlayamaz.

## 6. Historical Analytics

Bounded JSONL store flow creation, finding ve runtime event summary'lerini tutar. Time range, type, severity, process ve destination filtreleri desteklenir:

```text
GET /api/v1/analytics?from=...&to=...&type=finding,runtime&process=python
```

Bu local store dağıtık data warehouse değildir; çok büyük ortamlarda mevcut ClickHouse streaming yolu kullanılmalıdır.

## 7. Asset Intelligence ve SBOM

Host/OS/kernel/arch ve uygun sistemlerde dpkg package inventory çıkarılır. Model ayrıca container/pod/image/digest/service-account/node alanlarına hazırdır.

```text
GET /api/v1/asset-intelligence
GET /api/v1/asset-intelligence?format=cyclonedx
GET /api/v1/asset-intelligence?format=spdx
```

CLI de CycloneDX/SPDX çıktısı üretir. Package varlığı exploit kanıtı olarak değerlendirilmez.

## 8. Threat Intel Enrichment

Opsiyonel local CIDR dataset ile ASN/organization/country/source enrichment yapılabilir. Gözlenen IP'leri üçüncü tarafa göndermek zorunlu değildir.

```text
GET /api/v1/enrichment?ip=203.0.113.20
```

## 9. TLS Certificate Intelligence

Görülebilen X.509 metadata'dan cert/SPKI SHA-256, subject, issuer, serial, SAN, self-signed/expiry bilgisi ile IP/SNI/JA4 ilişkileri tutulur. SPKI/certificate reuse cluster'ları C2/infrastructure investigation için bağlam sağlar; tek başına malicious hükmü değildir.

## 10. DNS Infrastructure Graph

Domain→IP edge'leri first/last seen ve count ile tutulur. Answer diversity/churn yüksekse fast-flux-like bağlam üretilebilir; bu da tek başına kötü amaç kanıtı değildir.

## 11. Runtime anomaly

`memfd_create`, `ptrace`, `/tmp` veya `/dev/shm` üzerinden execution, deleted executable ve bazı namespace/mount/capability event'leri deterministik runtime finding'e dönüşebilir. Bunlar normal IDS/Story/Case zincirine katılır.

## 12. CO-RE eBPF yolu ve fallback

Paket içinde `bpf/netprobe_runtime.bpf.c`, `scripts/build-ebpf-core.sh` ve readiness probe vardır. Ancak v0.9 release hostunda kernel BTF, bpftool/libbpf build ortamı bulunmadığı için **native CO-RE live test geçti iddiası yoktur**. Bpftrace mevcutsa adaptive runtime provider, yoksa `/proc` fallback çalışır. UI bunu Ready/Fallback olarak dürüst biçimde gösterir.

## 13. Unified Investigation Workspace

Attack Story üzerinden tek ekranda root-cause inference, risk timeline, graph, files, runtime event'ler, exploit correlation, TLS ve DNS infrastructure bağlamı açılır. Severity ve confidence ayrı gösterilir; root-cause her zaman inference olarak işaretlenir.

## 14. SOC Performance

Interface acquisition artık Overview yerine burada görünür. Packet/capture error/recorder drop/export drop, interface health, CO-RE readiness ve synthetic benchmark bir aradadır.

```bash
netprobe benchmark --iterations 100000
```

Synthetic benchmark gerçek 1/10/25 Gbit line-rate testinin yerine geçmez.

## 15. Experimental OpenTelemetry Profiles

Opsiyonel HTTP profile adapter detection/response karar yolunun dışında tutulur. Token değeri config/API'de açık dönmek yerine environment variable üzerinden okunur.

## 16. Supply-chain çıktıları

`scripts/release-metadata.sh`:

- CycloneDX SBOM
- SPDX SBOM
- provenance JSON
- SHA256SUMS

üretir. `SOURCE_DATE_EPOCH`, `-trimpath`, `-buildvcs=false`, empty build-id ve static CGO-disabled build reproducibility'yi iyileştirir. `SIGNING_DATA_DIR` verilirse checksum manifesti Ed25519 ile imzalanabilir; verilmezse release açıkça unsigned kalır.

## 17. Güvenlik sınırları

Yeni API'ler mevcut RBAC'a bağlıdır. Rule import kod çalıştırmaz. Benchmark limitlidir. Playbook automatic modu response allowlist'ini aşamaz. Multi-tenant izolasyon bu sürümde kullanıcı isteği doğrultusunda yoktur.

## 18. Bilinçli non-claim'ler

v0.9.0 şunları iddia etmez: eksiksiz OCSF veya Suricata/Snort uyumu; her Sigma construct için birebir backend semantiği; package-name/KEV overlap'in kesin exploitability olduğu; BTF/libbpf olmayan release hostunda native CO-RE canlı testinin geçtiği; TLS key olmadan encrypted payload görünürlüğü; synthetic benchmark'ın line-rate benchmark olduğu; multi-tenant isolation.
