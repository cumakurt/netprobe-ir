# Web Konsolu Tasarım İncelemesi — v1.0.0

**Türkçe** · [English](UI_DESIGN.md) · [Dokümantasyon dizini](README_TR.md)

## v1.0 inceleme etkileşim modeli

v1.0 konsolu responsive beyaz SOC/CISO temasını korur ve Investigation Graph'ı yüksek yoğunluklu bir Canvas çalışma alanına dönüştürür. Canvas, node başına DOM elementi ölçekleme sorununu önler. Wheel/trackpad zoom, pan, fit/reset/center, hover hit-testing, rectangle selection, multi-select ve drag tüm sayfayı yeniden oluşturmadan çalışır. Graph, filtrelenmiş ve zamanla sınırlandırılmış veriyi sunucudan ister; clustering, edge aggregation ve açık node/edge tavanları uygular.

Asset satırları statik envanter metni değil, etkileşimli pivotlardır. IP veya asset'ten Traffic, Flows, Alerts ya da Investigation Graph'a geçildiğinde IP/focus/time bağlamı hedef rotaya taşınır.

Overview canlı trafik grafiği gerçek backend packet metadata'sını kullanır. Tarayıcı WebSocket üzerinden yalnız güncel incremental noktayı alır; zaman aralığı değiştiğinde bounded/downsampled history ister. Pause Live yalnız tarayıcı güncellemelerini durdurur, capture devam eder.

Settings → Notifications, yöneticilere Email ve Telegram kanallarını açar. Kayıtlı secret'lar API/UI'de yalnız `*_set` durumu olarak temsil edilir; ilgisiz alanları değiştirmek için secret'ın yeniden gösterilmesi gerekmez.

## Tek bakışta tasarım hedefleri

Overview, detay paneli açmadan şunları cevaplamalıdır:

- Capture aktif, paused veya degraded mı?
- Hangi interface'ler veri topluyor ya da ayrı ayrı durdurulmuş?
- Critical/high-confidence bulgu var mı ve verdict'i ne?
- Güncel TX/RX ile paket baskısı nedir?
- En fazla trafik veya risk hangi proses/uygulamalarda?
- Hangi protokoller baskın?
- Operatör bulguyu üreten kanıta doğrudan geçebilir mi?

Beyaz yüzey, sınırlı border, yeterli boşluk ve semantic kırmızı/amber/yeşil vurgular operasyon anlamını korur; arayüzü renk duvarına çevirmez.

## Navigasyon modeli

Kalıcı menü görev odaklıdır:

1. **Overview** — posture, acquisition health, live rate, üst protokol/proses ve öncelikli bulgular.
2. **Security Findings** — confidence/verdict ile IDS/IOC/imza/politika/davranış kanıtı.
3. **Live Traffic** — aranabilir flow ve güncel paket metadata'sı.
4. **Applications** — proses merkezli trafik ve risk.
5. **Interfaces** — interface başına acquisition durumu ve Start/Stop.
6. **Hunt / Search** — tutulan bulgu, flow, paket, proses ve alarmlarda sunucu taraflı inceleme.
7. **Behavioral Alerts** — deterministic bulgulardan ayrı anomali çıktısı.
8. **System ve yönetim çalışma alanları** — global capture, sağlık, rapor, entegrasyon ve ayarlar.

## Güvenlik kesinliği görünürdür

Severity ve kesinlik ayrı kavramlardır. `critical` öncelik/etkiyi; verdict ise kanıtın neyi gösterdiğini anlatır:

- `confirmed_ioc`: operatör IOC'siyle tam eşleşme;
- `signature_match`: visible traffic'te deterministic pattern;
- `confirmed_exposure`: doğrudan gözlenen güvensiz koşul;
- `policy_exposure`: yerel doğrulama gerektiren yüksek riskli sınır/politika koşulu;
- `behavioral`: analist doğrulaması gerektiren threshold/correlation hipotezi.

Davranış eşiği hiçbir zaman compromise kanıtı gibi gösterilmez.

## Focus ve Hunt

Global Focus bar `src:`, `dst:`, `ip:`, `sport:`, `dport:`, `port:`, `proto:`, `app:`, `process:`, `pid:`, `iface:`, `dir:`, `severity:`, `verdict:`, `rule:` ve `mitre:` alanlarını kabul eder.

```text
src:10.10.10.15 dst:1.1.1.1 proto:udp
app:dns process:python severity:high
verdict:confirmed_ioc iface:eth0
```

Filter drawer aynı ana kontrolleri sorgu dili bilmeyen kullanıcıya sunar. Hunt, yalnız son WebSocket frame'inde değil daemon tarafından tutulan kanıt üzerinde çalışır.

## Drill-down ve pivot modeli

```text
Security Finding → Packet → Flow → Process → Focus pivotları
Live Traffic     → Flow/Packet detail → Process → ilgili bulgu/alarm
Applications     → Process detail → flow → bulgu → davranış alarmı
Interfaces       → Interface detail → flow/paket → bağımsız Start/Stop
Hunt             → karma kanıt → object detail → sorguyu daralt
Assets           → Traffic/Flows/Findings/Graph context pivotu
```

Tıklanabilir görünen adli nesneler pointer ve klavye ile gerçekten etkinleştirilebilir. Hash route, breadcrumb ve Back kontrolleri investigation context'ini korur.

## Interface acquisition kontrolleri

Global capture ve interface durumu bağımsızdır. Stop interface yalnız hedef AF_PACKET oturumunu kapatır; diğer interface'ler ve web/API çalışır. Start interface yeni oturum açar. Kartlar `running`, `stopping` veya `stopped` ile packet/byte/error/drop bilgisini gösterir; durmuş sensör “sıfır trafik” gibi görünmez.

## Grafikler ve görsel hiyerarşi

- TX/RX rate gerçek backend telemetry'sinden;
- protokol dağılımı retained flow byte'larından;
- üst proses/uygulamalar gerçek flow/proses özetlerinden;
- security posture sayıları retained IDS bulgularından üretilir.

Production grafiğine demo veya rastgele değer eklenmez.

## Erişilebilirlik ve operasyonel kullanım

- Drill-down satır/kartlarında klavye ve Enter/Space desteği;
- görünür focus ring;
- rengin yanında label/icon ile durum;
- dar ekranda sütun gizlemek yerine yatay kayan evidence table;
- capture/security durumunu koruyan mobile navigation;
- pause/destructive kontrolleriyle investigation işlemlerinin görsel ayrımı;
- capture error/drop değerlerinin first-class health sinyali olması.

## Uygulanan tasarım eleştirileri

Alarm yoğunluğu certainty ve priority katmanlarıyla; arama-retention belirsizliği ayrı Hunt modeliyle; interface/daemon kontrol karışıklığı farklı yüzeylerle; sahte tıklanabilirlik gerçek detail route'larıyla; aşırı yoğun grafikler exact evidence tablolarıyla; aşırı kırmızı kullanımı sparse semantic renkle; durmuş capture belirsizliği açık badge'lerle giderildi.

## Bilinçli kapsam dışı alanlar

Gömülü konsol tam PCAP hex editor, SIEM data lake veya geniş community-signature NIDS yerine geçmez. Ham byte'lar PCAPNG'de kalır; uzun süreli kurumsal saklama dış backend'e aittir. Eksik process attribution uydurulmaz.

## Görsel doğrulama

Source asset testleri, JavaScript syntax, REST/control, Findings/Hunt ve live capture entegrasyonu release verification'a dahildir. Pixel-level browser iddiası yalnız test raporunda gerçek browser testi kaydedilmişse yapılır. v1.0.0 gerçek Chromium E2E kapsamı için [`TEST-RESULTS_TR.md`](../TEST-RESULTS_TR.md) dosyasına bakın.

## v0.9 SOC inceleme yüzeyleri

Detection Quality Center, Sigma coverage, açık inference etiketi taşıyan probable root cause, story risk timeline, runtime/exploit tabloları, C2 alanları ve Fleet Health/drift görünümü beyaz responsive tasarımı genişletir. Dar ekranda navigation overlay sidebar'a dönüşür, grid'ler `auto-fit` ile küçülür ve tablolar yatay kayar.
