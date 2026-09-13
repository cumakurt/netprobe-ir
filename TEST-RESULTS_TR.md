# NetProbe IR v1.0.0 — Nihai Sürüm Test Sonuçları

**Türkçe** · [English](TEST-RESULTS.md) · [Dokümantasyon dizini](docs/README_TR.md)

- Sürüm tarihi: 2026-09-13
- Paket: `netprobe-ir-1.0.0`
- Sürüm teması: **Production Investigation, Notification Management ve Live Traffic**

Bu rapor nihai v1.0.0 kaynak ağacı ve sürüm binary'leri üzerinde gerçekten çalıştırılan doğrulamaları kaydeder. Opsiyonel dış runtime'lar açıkça belirtilir; bulunmayan bağımlılıklar başarılı canlı doğrulama gibi gösterilmez.

## 1. Tam kaynak kalite kapısı — PASS

`./scripts/test-all.sh` üzerinden başarıyla çalıştırılanlar:

- `gofmt`, shell ve JSON syntax kontrolleri;
- kaynak/gömülü web asset eşitliği ve `node --check`;
- `go vet ./...`, `go test ./...` ve paket gruplarında repository-wide race detector;
- AMD64/ARM64 statik build ve embedded self-test;
- Sigma/interoperability/analytics CLI regression;
- SBOM/provenance üretimi ve release checksum doğrulaması;
- staged installer/auth-reset/uninstaller regression.

**Sonuç: PASS**

## 2. v1.0 backend regression — PASS

Cache kullanılmadan `go test -count=1 ./internal/notifications ./internal/trafficseries ./internal/investigation ./internal/server` çalıştırıldı. Kapsam; 5.000-flow graph safeguard, filtre/neighborhood/clustering, dynamic Asset API'leri, gerçek Event Bus trafik serisi/downsampling, Email/Telegram secret şifreleme ve masking, SMTP/Telegram hata sınıfları, severity routing, bounded async delivery, cooldown/dedup, RBAC ve same-origin korumasını içerdi.

**Sonuç: PASS**

## 3. Gerçek Chromium E2E konsol regression — PASS

Nihai binary ile `./scripts/integration-ui-browser.sh` çalıştırıldı. Overview KPI drill-down, Live Traffic range ve UI-only Pause/Resume; graph context navigation, zoom/pan, seçim/multi-select/rectangle selection, multi-node drag ve session position; Asset pivotları; Notification Settings save/load/masking; bounded browser traffic history ve kısa heap sanity doğrulandı.

Build hostundaki global Chromium `URLBlocklist: ["*"]` policy girdisi yalnız bu release E2E çalışması için geçici kaldırılıp hemen geri yüklendi. Ürün veya ZIP içinde Chromium policy değişikliği yoktur.

**Sonuç: PASS**

## 4. Gerçek Linux packet capture regression — PASS

Nihai tekrarlanabilir AMD64 binary ile gerçek AF_PACKET ve TPACKET_V3 capture, HTTP DPI, `/proc` PID attribution, bounded packet history, interface Stop/Start, yerleşik IDS, Hunt API, konsol açık kalırken global Stop/Resume, PCAPNG recorder ve graceful final report doğrulandı.

**Sonuç: PASS**

## 5. Gerçek TLS regression — PASS

Gerçek TLS ClientHello, SNI, ALPN, JA3, JA4 ve NPSH doğrulandı.

**Sonuç: PASS**

## 6. Tekrarlanabilir statik build — PASS

Kontrollü girdiler `VERSION=1.0.0`, `COMMIT=release-1.0.0`, `SOURCE_DATE_EPOCH=1789257600`, `2026-09-13T00:00:00Z` build zamanı, `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false` ve boş Go build ID değerleridir. AMD64 ve ARM64 binary'leri iki kez bağımsız oluşturulup byte-for-byte karşılaştırıldı.

Nihai SHA-256 değerleri:

- AMD64: `df1cc7c181c92818a21e211779ba40697a00b267cbf5bc05359f776ba51f5ef7`
- ARM64: `7359159e052239ace554ca185b07f4755f0f777f2a1d51eb661c94887aa1da4c`

**Sonuç: PASS**

## 7. Opsiyonel runtime sınırları

Release hostunda `bpftool`/native CO-RE BTF toolchain, `bpftrace`, YARA-X `yr`, `wasmtime` ve `kcat` kurulu değildi. Bu sürüm bu dış runtime'ların canlı başarısını iddia etmez. Adapter/parser/readiness/fallback yolları uygulanabilir yerlerde otomatik testlerle kapsanır.

## Nihai sürüm kararı

Bu sürüm için çalıştırılan zorunlu v1.0.0 kalite, backend, browser, canlı Linux ve TLS kapılarının tümü geçti.

**Sürüm kararı: ONAYLANDI**
