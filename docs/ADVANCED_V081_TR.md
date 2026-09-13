# NetProbe IR v0.8.1 — Detection Quality & Root-Cause Sürümü

**Türkçe** · [English](ADVANCED_V081.md) · [Dokümantasyon dizini](README_TR.md)

NetProbe IR v0.8.1, v0.8.0 capture/DPI/IDS/runtime-security/export/fleet mimarisinin üzerine kurulmuş bir kalite ve korelasyon sürümüdür. Amaç daha fazla alarm üretmek değil; detection kalitesini ölçmek, farklı kanıt türlerini birleştirmek, C2 skorunu açıklamak, fleet drift durumunu göstermek ve olası kök nedeni kanıt ile çıkarım arasındaki sınırı koruyarak sunmaktır.

## 1. Detection Quality Center

Kalite kayıtları kalıcı olarak şu dosyada tutulur:

```text
<data_dir>/detection-quality/runs.json
```

Detection Lab çalıştırılırken isteğe bağlı olarak:

- `label`,
- `benign`,
- `expected_rules[]`

alanları verilebilir.

Sistem her etiketli corpus çalışmasında gözlenen rule ID/count değerlerini, beklenen rule’ları, frame sayısını ve işlem süresini saklar. Ardından rule bazında:

- true positive,
- false positive,
- false negative,
- precision,
- recall,
- kalite skoru

hesaplar.

API:

```text
GET /api/v1/detection-quality
```

Bu skorlar corpus etiketlerinin doğruluğuna bağlıdır; “mutlak detection doğruluğu” olarak yorumlanmamalıdır.

## 2. Attack Story v2

Attack Story v2 aynı pipeline içinde bulunan:

- findings,
- flows,
- reconstructed files/YARA,
- runtime/eBPF event’leri,
- MITRE metadata

üzerinden tek temporal hikâye oluşturur.

Story içinde risk timeline ve olası root cause bulunur.

## 3. Root Cause Engine

Root cause sonucu her zaman:

```text
inference: true
```

olarak işaretlenir. Sistem en erken şüpheli stage’i seçer ve sonrasındaki bağımsız kanıtların sayısı/türüyle confidence değerini artırır.

Bu sonuç “saldırı kesin burada başladı” anlamına gelmez. Analistin incelemesini hızlandıran kanıta dayalı bir hipotezdir.

## 4. eBPF Runtime Events v2

NetProbe ana binary’si statik kalır. Runtime provider opsiyonel `bpftrace` ile çalışır.

v0.8.1’de NetProbe host üzerindeki mevcut syscall tracepoint’lerini keşfeder ve yalnız gerçekten desteklenen probe’lardan program oluşturur. Böylece tek bir eksik tracepoint tüm eBPF provider’ını devre dışı bırakmaz.

Host destekliyorsa aşağıdaki event aileleri kullanılabilir:

- TCP connect,
- execve,
- openat,
- unlinkat,
- renameat2,
- chmod/fchmodat,
- chown,
- memfd_create,
- ptrace,
- setuid/setgid,
- mount,
- setns,
- clone,
- bind,
- listen,
- accept4.

API:

```text
GET /api/v1/runtime-events
```

`bpftrace` yoksa `/proc` attribution fallback devam eder.

## 5. Sigma Engine v2

Desteklenen subset genişletildi:

- named selections,
- AND / OR / NOT,
- `1 of prefix*`,
- `all of prefix*`,
- contains,
- startswith,
- endswith,
- exists,
- re,
- cidr.

CLI:

```bash
netprobe-ir sigma --in configs/sigma-rule.example.yml --format query
netprobe-ir sigma --in configs/sigma-rule.example.yml --format npdl
```

Web/API:

```text
POST /api/v1/sigma/translate
```

Translator coverage yüzdesi ve warning döndürür. Desteklenmeyen semantik sessizce yok sayılmaz. Karmaşık Sigma kuralı güvenli biçimde doğrudan NPDL’e çevrilemiyorsa generated NPDL **disabled/manual-review** olarak üretilir.

## 6. CVE/KEV Runtime Exploit Correlation

Sistem KEV package/product overlap ile version-proven vulnerability kavramını ayrı tutar.

v0.8.1 korelasyonu şunları birleştirir:

- KEV exposure context,
- Security Finding,
- verdict/confidence/severity,
- process/PID,
- yakın zamandaki runtime execution event’leri.

API:

```text
GET /api/v1/exploit-correlations
```

Sonuçta `version_proven` ayrıca gösterilir. Yüksek korelasyon skoru bu alanı otomatik olarak `true` yapmaz.

## 7. C2 Analytics v2

Beacon skoru artık:

- median interval,
- jitter / relative MAD,
- packet/transfer size similarity,
- periodicity,
- TX/RX ratio,
- destination rotation,
- JA4 reuse

sinyallerini birlikte kullanır.

Her sonuç açıklama nedenlerini de içerir.

## 8. Fleet Health v2

Multi-tenant bu sürümde bilinçli olarak yoktur.

Sensor snapshot artık version/config/rules hash bilgilerini taşıyabilir. Controller:

- online/stale/offline,
- health score,
- age,
- version drift,
- config drift,
- rules drift

hesaplar.

API:

```text
GET /api/v1/fleet/health
```

## 9. Monitoring

Prometheus ve `/api/v1/health` içine:

- Detection Quality,
- runtime events,
- exploit correlations,
- fleet health

ölçümleri eklendi.

## 10. UI

Beyaz tema korunur. Yeni görsel alanlar:

- Detection Quality Center,
- Sigma translator,
- root-cause callout,
- risk timeline,
- runtime event tablosu,
- exploit-correlation tablosu,
- gelişmiş C2 kolonları,
- Fleet health meter/drift badge.

v0.8’deki responsive/tam sayfa tasarım davranışı korunur.

## 11. Açık sınırlar

v0.8.1 şu iddiaları yapmaz:

- multi-tenant izolasyon,
- bundled native libbpf/CO-RE agent,
- tüm kernel’lerde tüm tracepoint’lerin bulunduğu,
- KEV product overlap’ın vulnerable version kanıtı olduğu,
- root-cause çıkarımının kesinlik olduğu,
- Sigma standardının tamamının desteklendiği,
- C2 skorunun tek başına compromise kanıtı olduğu.
