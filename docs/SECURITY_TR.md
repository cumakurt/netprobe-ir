# Güvenlik Notları

**Türkçe** · [English](SECURITY.md) · [Dokümantasyon dizini](README_TR.md)

## Yetki modeli

Ağ yakalama `CAP_NET_RAW` gerektirir. Kullanıcılar arası eksiksiz proses ilişkilendirmesi ayrıca `/proc` izinlerine, `hidepid` seçeneğine, Yama/ptrace politikasına ve PID namespace'lerine bağlıdır.

En basit operasyon modeli, güçlü systemd sandboxing ile çalışan root-owned bir sistem servisidir. Örnek unit `packaging/systemd/` altındadır. Web arayüzünü kimlik doğrulama ve TLS olmadan güvenilmeyen bir ağa açmayın.

## Web bind güvenliği

Varsayılan listener `127.0.0.1:8443` adresidir. Loopback dışındaki bir listener için `auth_token` ayarlanmadıysa veya `allow_unauthenticated_remote` açıkça etkinleştirilmediyse uygulama başlamaz. İkinci seçenek yalnız zaten izole edilmiş bir yönetim ağında kullanılmalıdır.

## Hassas veriler

PCAPNG; kimlik bilgileri, cookie'ler, şifrelenmemiş uygulama verileri, kişisel veriler ve ticari bilgiler içerebilir. `<data_dir>/pcap` ile `<data_dir>/incidents` dizinlerini hassas adli kanıt olarak değerlendirin.

Önerilen kontroller:

- dizinleri yalnız root tarafından okunabilir/yazılabilir tutun;
- disk şifreleme ve saklama limitleri uygulayın;
- gerekli değilse recorder'ı kapatın;
- yetki olmadan PCAP dosyalarını üçüncü taraflara göndermeyin.

HTTP metadata'sı path, host ve User-Agent; DNS sorguları ile TLS SNI ise hassas kurumsal bilgi içerebilir.

## TLS sınırları

NetProbe IR TLS payload'larını çözmez. SNI, ALPN, JA3 ve ilgili fingerprint'ler yalnız görülebilen handshake metadata'sından çıkarılır. Şifreli uygulama verisi şifreli kalır.

## Parser sağlamlaştırması

Parser'lar alanları okumadan önce açık uzunluk kontrolleri yapar. Flow başına TCP reassembly `dpi.max_stream_bytes` ile, sırasız bekleyen segmentler ise sabit sınırlarla kısıtlanır.

## Servis reddi değerlendirmesi

Çok sayıda benzersiz flow üretebilen bir saldırgan bellek baskısını artırabilir. Interface kapsamı, host firewall ve uygun idle timeout birlikte kullanılmalıdır. Üretim yükünde flow/packet/recorder drop sayaçları izlenmelidir.

## Token ve secret yönetimi

Komut satırı argümanları proses listesinde görünebildiğinden token'ı root-readable config dosyasında tutun. SMTP parolaları ve Telegram bot token'ları disk üzerinde şifrelenir, normal API/UI cevaplarında maskelenir ve bilinçli olarak loglanmaz.

## IDS verdict güvenliği

NetProbe IR her anomaliyi doğrulanmış saldırı saymaz. `confirmed_ioc` operatörün sağladığı IOC ile tam eşleşmeyi, `signature_match` belirli deterministic pattern'ın gözlendiğini, `behavioral` ise sınırlı bir korelasyon eşiğinin aşıldığını belirtir. Bunların hiçbiri tek başına exploit başarısını veya host compromise durumunu kanıtlamaz.

Özel kural dosyaları ve IOC feed'leri güvenlik açısından hassastır. Root-only yazma izni kullanın; kaynak ve güncelliği inceleyin. Değişikliklerden sonra servisi yeniden başlatın; ele geçirilmiş bir kural dosyası yanıltıcı bulgular üretebilir.

## Interface kontrolü

Web Start/Stop işlemleri paket yakalamayı değiştirdiği için diğer korumalı endpoint'lerle aynı kimlik doğrulama/RBAC kurallarına tabidir. `Origin` header'ı taşıyan tarayıcı kontrol istekleri same-origin olmalıdır. Interface'i durdurmak saklanan kanıtı silmez.

## Güvenlik açığı bildirimi

Şüpheli bir güvenlik açığını herkese açık yayımdan önce özel olarak proje sorumlusuna bildirin:

- Cuma KURT
- E-posta: `cumakurt@gmail.com`
- Repository: `https://github.com/cumakurt/netprobe-ir`

Etkilenen sürümü, yeniden üretim koşullarını ve etkiyi ekleyin; log veya PCAP paylaşırken ilgisiz hassas verileri çıkarın.
