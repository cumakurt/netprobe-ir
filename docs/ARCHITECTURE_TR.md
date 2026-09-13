# Mimari

**Türkçe** · [English](ARCHITECTURE.md) · [Dokümantasyon dizini](README_TR.md)

## Veri yolu

```text
Linux interface'leri
      │
      ▼
TPACKET_V3 / AF_PACKET / SOCK_RAW
      │
      ▼
Ethernet/VLAN/IP/TCP/UDP decoder
      │
      ├──────────────► PCAPNG Flight Recorder
      │
      ▼
Endpoint/yön sınıflandırıcı
      │
      ├──────────────► /proc socket inode → PID eşleyici
      │
      ▼
Flow anahtarı ve durumu
      │
      ▼
Stateful DPI
      │
      ▼
Flow store ──────────────► sınırlı güncel paket metadata halkası
      │
      ├──────────────► Yerleşik IDS / IOC / stateful güvenlik bulguları
      │                    │
      │                    └────► olay PCAP koruması
      ├──────────────► Anomali motoru
      │                    │
      │                    └────► olay PCAP koruması
      ▼
REST / WebSocket / metrikler / raporlar
      │
      ▼
Gömülü web arayüzü
```

## Paket yakalama

Doğrulanmış pasif Linux veri yolu, desteklenen sistemlerde seçilen her interface için `TPACKET_V3/PACKET_MMAP` kullanır ve gerektiğinde `AF_PACKET/SOCK_RAW` yoluna otomatik döner. Receive buffer yapılandırılabilir; binary `CAP_NET_RAW` veya root yetkisi gerektirir.

Sınırlı frame kanalı açık backpressure uygular. Tüketici yetişemezse drop sayaçları artar ve arayüz capture sağlığını degraded olarak gösterir; paket kaybı gizlenmez.

## Decoder

Decoder Ethernet frame'lerini kabul eder ve şunları destekler:

- 802.1Q ve 802.1ad VLAN stacking;
- IPv4 ve IPv6;
- yaygın IPv6 extension header'ları ve ilk fragment transport decode'u;
- TCP, UDP, ICMP ve ICMPv6.

Bozuk veya kesilmiş paketler panic üretmeden reddedilir.

## Proses ilişkilendirme

Proses eşleyici iki senkron snapshot oluşturur:

1. `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`;
2. `/proc/<pid>/fd/* → socket:[inode]`.

Veriler socket inode üzerinden birleştirilir; PID/PPID, UID/kullanıcı adı, `comm`, executable yolu, komut satırı, cgroup ve best-effort container metadata'sı eklenir. Önce tam 5-tuple eşleşmesi denenir; bağlı ya da wildcard listener'larda yerel socket eşleşmesine dönülebilir. Kısa ömürlü bağlantılar için kaçırma sonrasında throttled anlık yenileme yapılır.

İki endpoint'i de yerel hosta ait olmayan yönlendirilmiş trafik, uydurma bir proses yerine açıkça `forwarded` olarak işaretlenir.

## Flow kimliği

Yerel/uzak flow kimliği aşağıdaki bileşimden üretilir ve flow'un bellek yaşamı boyunca kararlı, kısa bir kimliğe hash edilir:

```text
L4 protokolü | yerel IP:port | uzak IP:port
```

Flow; ilk/son görülme zamanı, interface'ler, TX/RX paket ve byte'ları, TCP flag'leri, proses ilişkisi, DPI metadata'sı ve risk nedenlerini tutar. Boşta kalan flow'lar yapılandırılmış timeout sonunda temizlenir.

## Stateful DPI

TCP payload her yön için yapılandırılabilir üst sınıra kadar tamponlanır. Sınırlı pending-segment haritası yaygın başlangıç sırasızlıklarını işler. Parser'lar bir uygulama mesajının tek pakete sığdığını varsaymak yerine yeniden oluşturulmuş başlangıç byte'larını tüketir.

Yerleşik parser'lar HTTP/1.x, UDP/TCP DNS, TLS ClientHello/ServerHello metadata'sı, SSH banner'ları ve servis/port ipuçlarını kapsar. Görülebildiğinde SNI, ALPN, TLS sürümü, cipher/extension sayıları, JA3, JA4 ve NetProbe TLS Server Fingerprint (NPSH) çıkarılır. TLS payload hiçbir zaman çözülmüş gibi sunulmaz.

## Tespit ve anomali katmanları

Açıklanabilir anomali motoru yüksek outbound hacim, destination fan-out, port/endpoint taraması, kısa süreli bağlantı patlaması, periyodik beacon ve yüksek entropili DNS adlarını puanlar. Alarm kayıtları rule ID, severity, skor ve kanıt taşır.

Yerleşik IDS her decode edilmiş paketi ilişkili flow, DPI sonucu, yön ve paket geçmişi kimliğiyle değerlendirir. Deterministik imzalar, operatör IOC'leri, sınır politikaları ve sınırlı stateful korelasyon `SecurityFinding` üretir. Severity, verdict ve confidence birbirinden bağımsızdır. High/critical bulgular recorder kanıt koruma hook'unu çağırır. Özel JSON kuralları başlangıçta bir kez yüklenir ve regex için Go RE2 kullanır.

Anomali motoru ayrı tutulur; heuristic davranış deterministic imza/IOC kanıtı gibi sunulmaz.

## Sunucu taraflı Focus/Hunt

`Engine.Hunt`, web arayüzündeki `field:value` dilini ayrıştırıp saklanan flow, paket metadata'sı, proses özeti, davranış alarmı ve güvenlik bulgularında arar. Tarayıcı hızlı etkileşim için yerel filtreleme yapabilir; Hunt çalışma alanı `/api/v1/hunt` üzerinden yenilendiği için son WebSocket dilimiyle sınırlı değildir.

## Interface yaşam döngüsü

Her capture oturumunun kendi context'i, AF_PACKET socket'i, generation değeri, çalışma/durma durumu ve zaman damgaları vardır. Global durdurma/başlatma bütün oturumları; interface endpoint'leri yalnız hedef oturumu etkiler.

## Flight Recorder

PCAPNG, boyutu sınırlı dönen segmentlere yazılır. Recorder sınırlı queue kullanır ve drop sayılarını dışarı açar. Yüksek önem dereceli alarmda geçerli segment önce kapatılır, sonra yakın tarihli kapalı segmentler olay dizinine kopyalanır. Bu sıra, kopyalanan dosyaların block-complete olmasını sağlar.

## Web ve kontrol düzlemi

HTTP sunucusu aynı statik binary içindedir; HTML/CSS/JavaScript build sırasında gömülür ve harici frontend runtime gerektirmez. Konsol Overview, Security Findings, Live Traffic, Applications, Interfaces, Hunt/Search, Behavioral Alerts ve System rotalarını sunar. Hash routing, tarayıcı geri/ileri davranışını ve investigation context'ini korur.

Kontrol düzlemi status, flow, paket metadata'sı, proses, alarm, güvenlik bulgusu, Hunt, interface capture kontrolü, rapor, metrik ve WebSocket telemetrisi sağlar. Güncel paket geçmişi bilinçli olarak 1000 metadata kaydıyla sınırlıdır; ham kanıt PCAPNG recorder'da tutulur.

Capture yaşam döngüsü daemon yaşam döngüsünden ayrıdır. `POST /api/v1/control/stop`, HTTP sunucusunu ve tutulan kanıtı kapatmadan paket acquisition'ını durdurur; `POST /api/v1/control/start` aynı daemon içinde yeni capture oturumu oluşturur. Kontrol işlemleri POST, kimlik doğrulama/RBAC ve same-origin denetimlerinden geçer. Kimlik doğrulama olmadan uzak dinleme, açık güvenlik override'ı yoksa reddedilir.

## Yüksek performans hedefi

Uzun süreli multi-gigabit yakalama için gelecek veri yolu hedefi şöyledir:

```text
XDP → AF_XDP UMEM/rings → zero-copy decoder/DPI
             +
eBPF connect/accept/send/recv → socket cookie → PID/cgroup
```

Bu backend, üst katmanları değiştirmemek için mevcut flow/DPI/anomali/web arayüzlerini korumalıdır. v1.0.0 pasif host trafiğini yanlışlıkla tüketme riski nedeniyle production-ready AF_XDP redirect desteği iddia etmez.
