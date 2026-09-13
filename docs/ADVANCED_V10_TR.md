# NetProbe IR v1.0.0 — Interaktif Investigation, Notifications ve Live Traffic

**Türkçe** · [English](ADVANCED_V10.md) · [Dokümantasyon dizini](README_TR.md)

NetProbe IR v1.0.0 mevcut `capture → flow → process → finding → story → case` mimarisini genişletir. İkinci bir packet-processing yolu, ikinci bir authentication sistemi veya yalnızca frontend'de görünen sahte bir katman kurmaz. Investigation, asset, notification ve live-traffic özellikleri mevcut Event Bus, telemetry store, RBAC, audit ve web güvenlik katmanlarını kullanır.

## 1. Investigation Graph mimarisi

v1.0 Investigation Graph HTML Canvas üzerinde render edilir. Binlerce node için bağımsız DOM elementi üretmez. Browser yalnız view state'i (transform, selection, hidden/collapsed state ve session node positions) tutar; graph evidence server API'den gelir.

Desteklenen etkileşimler:

- mouse wheel/trackpad zoom;
- pan;
- Fit to Screen;
- Reset View;
- Center Graph;
- tek node seçimi;
- Ctrl/Command/Shift multi-select;
- rectangle/area selection;
- seçili node'ları birlikte drag-and-drop;
- node position'larını browser session boyunca `sessionStorage` ile koruma;
- node/edge hit-test ve hover detail;
- selected node/edge detail paneli;
- search + filter;
- neighborhood isolation;
- hide unrelated / show all;
- relation collapse;
- cluster expand/collapse;
- Traffic, Flows, Security Findings ve Assets ekranlarına context navigation.

### Server-side ölçek korumaları

`GET /api/v1/graph` source/destination IP, asset, protocol, port, application, severity ve time-window filtrelerini işler. Server browser'a göndermeden önce max-node/max-edge sınırları, clustering, edge aggregation, time-window ve neighborhood azaltımı uygular.

Large-graph regression 5.000 flow üretir ve graph çıktısının bounded kaldığını doğrular. Bu test, her büyüklükte topology'nin limitsiz tek browser canvas'ında gösterileceği iddiası değildir.

## 2. Context navigation

Graph pivot'ları mevcut global Focus/Hunt query modelini yeniden kullanır. IP node'u Traffic/Flows/Security Findings ekranına geçerken IP context korunur. Asset pivot'u dynamic asset detail görünümüne gider. Neighborhood işlemi server-side focused graph ister.

## 3. Dynamic Assets

`/api/v1/assets` ve `/api/v1/assets/{id}` retained flow/finding evidence üzerinden asset üretir.

Mümkünse gösterilen alanlar:

- IP/name;
- process/user/container/pod/interface identity;
- first/last seen;
- total / IN / OUT traffic;
- flow count;
- protocols/applications;
- ports;
- related findings;
- related assets;
- retained evidence tabanlı risk.

Kaynak telemetride olmayan MAC/hostname gibi değerler fake/mock olarak üretilmez.

## 4. Notification Management

Notification manager NetProbe data directory altında encrypted settings saklar ve tek bounded async queue kullanır. Security finding pipeline SMTP/Telegram teslimini beklemez.

### Email

- Enable/Disable
- SMTP host/IP
- Port
- Username/Password
- Sender
- Recipient list
- Clear text
- STARTTLS
- implicit TLS/SSL
- Timeout
- Severity selection

### Telegram

- Enable/Disable
- Bot Token
- Chat ID
- Timeout
- Severity selection

### Secret güvenliği

SMTP password ve Telegram token normal settings API response'unda plaintext olarak dönmez. Yalnız `password_set` / `bot_token_set` flag'leri döner. Persisted settings AES-GCM authenticated encryption kullanır; local 256-bit key ve encrypted settings dosyaları `0600` modunda tutulur. Secret alanı update sırasında boş bırakılırsa eski secret korunur.

Bu model secret'ı yanlışlıkla UI/API/log üzerinden açığa çıkarmamayı ve disk üzerinde plaintext tutmamayı hedefler. Root seviyesinde hem encrypted file hem local key'i okuyabilen saldırgana karşı ayrı bir HSM/KMS güvenlik sınırı iddia etmez.

### Reliability

- backend severity enforcement;
- bounded queue;
- finite retry;
- bounded exponential backoff;
- cooldown/deduplication;
- bounded dedup state;
- sent/failed/dropped/deduplicated/queue metrics.

Queue dolarsa capture/detection bloklanmaz; notification işi drop edilir ve metric artar.

## 5. Gerçek IN / OUT Live Traffic

Overview grafiği mevcut `packet_metadata` Event Bus üzerinden `internal/trafficseries.Store` tarafından beslenir. Yeni packet capture socket'i veya duplicate parser açılmaz.

Tutulan temel sayaçlar:

- IN/OUT bytes;
- IN/OUT packets;
- unique flows;
- IN/OUT flows.

API:

- `GET /api/v1/traffic/live`
- `GET /api/v1/traffic/history?range=1m|5m|15m|1h|24h`

UI metrics:

- bits/sec
- bytes/sec
- packets/sec
- flows/sec

Uzun zaman aralıkları server-side downsample edilir. Browser history bounded tutulur. Existing WebSocket üzerinden incremental live point gelir. Pause Live yalnız UI update'ini durdurur; capture devam eder.

## 6. Security / RBAC

- Notification endpoints: `admin:settings`.
- Graph: mevcut `read:graph`.
- Traffic history/live: mevcut status/read permission.
- Asset detail: mevcut asset read permission.
- Browser mutation: same-origin/CSRF koruması.
- Notification config/test işlemleri audit edilir.

## 7. Test kapsamı

- graph filter/neighborhood/clustering;
- 5.000-flow large graph bound;
- asset aggregation/detail;
- live traffic Event Bus + history/downsampling;
- notification encrypted persistence + masking;
- local SMTP delivery;
- SMTP auth failure/timeout/TLS failure/recipient rejection;
- Telegram mock success/timeout/rate-limit/token masking;
- severity routing + deduplication;
- RBAC + cross-origin rejection;
- real Chromium E2E: KPI drill-down, graph zoom/pan/single+multi-select/drag/rectangle, graph→Traffic, Asset→Traffic/Graph, notification masking, live traffic range/Pause ve bounded browser history;
- real Linux capture/IDS/Hunt;
- real TLS SNI/ALPN/JA3/JA4/NPSH;
- Go race detector.

Release ortamındaki Chromium global `URLBlocklist: ["*"]` policy ile geldiği için release-only browser testi sırasında bu policy geçici olarak kaldırılıp test sonunda aynen geri kondu. Ürün veya ZIP bu host policy değişikliğini içermez.

## 8. Sınırlar

v1.0.0 şunları iddia etmez:

- sınırsız node/edge graph render;
- tüm public SMTP/Telegram provider'larında vendor-specific sertifikasyon;
- telemetride bulunmayan MAC/hostname keşfi;
- multi-tenant izolasyon;
- bounded queue tükendiğinde zero-loss; drop metric açıkça tutulur;
- prerequisites olmayan hostta native CO-RE live pass.
