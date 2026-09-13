# Değişiklik Günlüğü

**Türkçe** · [English](CHANGELOG.md) · [Dokümantasyon dizini](docs/README_TR.md)

## 1.0.0 — 2026-09-13

### Eklendi

- Zoom/pan/multi-select/rectangle selection/drag/session positioning, filtreleme, clustering, edge aggregation ve context pivot içeren yüksek yoğunluklu Canvas Investigation Graph.
- Traffic/flow/alert/graph navigasyonu sağlayan dinamik interaktif Asset'ler.
- Bağımsız severity routing, test, bounded async delivery, retry/backoff, cooldown/dedup ve delivery metric içeren şifreli Email/SMTP ve Telegram Notification Management.
- 1m/5m/15m/1h/24h server-side downsampling ve incremental WebSocket update içeren gerçek telemetri tabanlı IN/OUT history.
- Gerçek Chromium E2E konsol doğrulaması.

### Güvenlik / performans

- Notification secret'ları API/UI'de maskelenir ve disk üzerinde şifrelenir.
- Yeni mutating settings API'leri mevcut RBAC/audit/same-origin korumalarını kullanır.
- Büyük graph çıktısı Canvas render öncesinde sunucu tarafında sınırlanır ve cluster edilir.

## 0.9.0 — 2026-09-13

### Eklendi

- Posture, risk trendi, confidence, Detection Quality, exploit/root-cause ve Fleet resilience içeren CISO Executive Overview.
- Live Traffic, Security Findings ve Applications'a doğrudan drill-down yapan KPI kartları.
- Finding, flow ve runtime için OCSF-compatible canonical event envelope'ları.
- Sigma count/temporal/ordered-temporal correlation planı ve Suricata/Snort coverage analyzer.
- Dry-run, approval-required ve açık automatic modlu kalıcı response playbook'ları.
- Bounded historical analytics, Asset Intelligence ve CycloneDX/SPDX host inventory.
- Local CIDR enrichment, TLS certificate/SPKI reuse ve DNS infrastructure graph.
- Seçili Linux runtime anomaly tespitleri, CO-RE source/build/readiness yolu.
- Unified Investigation Workspace, SOC Performance ve deneysel OpenTelemetry Profiles adapter.
- Release SBOM, provenance ve reproducibility kontrolleri.

### Arayüz

- Interface Acquisition, Overview'dan kaldırılıp Interfaces/SOC Performance altına taşındı.
- Executive risk posture, 24 saat trend, evidence confidence, resilience ve infrastructure intelligence görselleri eklendi.
- Response Playbooks ve SOC Performance sayfaları eklendi; responsive beyaz tema korundu.

### Güvenlik / uyumluluk

- Yeni API'ler mevcut RBAC/audit/same-origin kontrolleri arkasındadır.
- Import edilen kurallar kod olarak çalıştırılmaz; automatic response allowlist/guardrail'leri aşamaz.
- Multi-tenant isolation kapsam dışıdır; release hostunda native CO-RE live pass iddia edilmez.

## 0.8.1 — 2026-09-13

- Detection Quality Center, Attack Story v2 risk timeline ve probable root cause.
- Bounded runtime evidence ve adaptive bpftrace tracepoint keşfi.
- Sigma Engine v2, CVE/KEV runtime correlation, C2 Analytics v2 ve Fleet Health v2.

## 0.8.0 — 2026-09-13

- `netprobe sigma` ile Sigma subset çevirisi ve örnek Sigma kuralı.
- Mobile/narrow ekran navigasyonu ve daha akışkan responsive beyaz konsol.
- Multi-tenant support kapsam dışında; önceki capture/DPI/IDS/Hunt/export/response akışları geriye uyumludur.

## 0.7.0 — 2026-09-13

- Runtime security, malware evidence ve extensibility sürümü.
