# NetProbe IR v0.7.0 — Kimlik Doğrulama, RBAC ve SOC Operasyonları

**Türkçe** · [English](AUTH_SECURITY.md) · [Dokümantasyon dizini](README_TR.md)

NetProbe IR v0.5.0 web kimlik doğrulamasını varsayılan olarak etkinleştirir. Varsayılan yönetici kullanıcı adı `admin`'dir; ancak ürün herkes tarafından bilinen sabit bir varsayılan parola **taşımaz**. `install.sh`, servis başlamadan önce `netprobe-ir auth bootstrap` çalıştırır ve kriptografik olarak rastgele üretilen ilk parolayı yalnızca kurulum sonunda gösterir. Hesap `must_change_password` olarak işaretlenir; ilk parola değiştirilmeden telemetri konsolu kullanılamaz.

## İlk kullanıcı ve parola kurtarma

Normal kurulum:

```bash
sudo ./install.sh
```

Kurulum sonunda ilk yönetici bilgileri gösterilir. Parola düz metin olarak kullanıcı deposuna yazılmaz. Parola kaybolursa sensör üzerinde yerel olarak sıfırlanabilir:

```bash
sudo netprobe-ir auth reset --data-dir /var/lib/netprobe-ir --username admin
```

Komut yeni geçici parola üretir ve sonraki girişte parola değişimini zorunlu kılar.

## Parola saklama

Parolalar kullanıcı başına benzersiz rastgele salt ile PBKDF2-HMAC-SHA256 kullanılarak türetilmiş biçimde saklanır. Varsayılan iterasyon sayısı 600.000'dir ve `auth.password_iterations` ile değiştirilebilir. NetProbe kullanıcı deposunda geri çevrilebilir düz metin parola saklamaz.

Varsayılan parola politikası:

- en az 12 karakter,
- büyük harf,
- küçük harf,
- rakam,
- özel karakter.

Parola değişikliği ilgili kullanıcının mevcut yerel oturumlarını iptal eder.

## Oturumlar

Tarayıcı girişi `HttpOnly`, `SameSite=Strict` session cookie kullanır. Session ID kriptografik olarak rastgele üretilir. Varsayılan süreler:

- idle timeout: 30 dakika,
- absolute timeout: 12 saat.

**My Account** ekranından aktif oturumlar görülebilir ve iptal edilebilir. Uzun ömürlü WebSocket telemetrisi de sürekli yeniden yetkilendirilir; session expiry, logout, parola değişikliği, kullanıcı disable veya API token revoke sonrasında eski socket telemetri almaya devam edemez.

Session-cookie ile yapılan değiştirici istekler merkezi same-origin kontrolünden geçer. Otomasyon için kullanılan scoped bearer token'lar ise açık scope yetkilendirmesi kullanır.

## Brute-force koruması

Başarısız girişler normalize kullanıcı adı + kaynak IP ikilisi üzerinden izlenir. Varsayılan politika beş başarısız denemeden sonra beş dakika kilit uygular. Parola ve MFA hataları aynı koruma yolunu kullanır.

## Roller

| Rol | Amaç |
|---|---|
| `viewer` | salt-okunur dashboard ve kanıt görünürlüğü |
| `analyst` | investigation, Hunt, case ve tuning çalışmaları |
| `responder` | analyst yetkileri + onaylı müdahale işlemleri |
| `admin` | kullanıcı, token, audit, backup, config ve tam konsol yönetimi |

Yetkilendirme backend üzerinde zorunlu olarak uygulanır. UI'da bir düğmenin gizlenmesi güvenlik sınırı değildir. Sistem son aktif administrator hesabının disable veya demote edilmesini engeller.

## API token'ları

Administrator, isteğe bağlı TTL içeren scope'lu API token oluşturabilir. Ham token yalnızca oluşturulurken döndürülür; kalıcı depoda yalnızca SHA-256 hash bulunur. Token istenildiği anda revoke edilebilir.

## TOTP MFA

Kullanıcılar **My Account** üzerinden TOTP MFA etkinleştirebilir. Enrollment Base32 secret/URI üretir ve aktivasyon öncesinde geçerli TOTP kodu ister. On adet tek kullanımlık recovery code oluşturulur; diskte yalnızca SHA-256 hash'leri tutulur ve kullanılan recovery code anında silinir.

## OIDC / SSO

İsteğe bağlı OIDC entegrasyonu Authorization Code + PKCE kullanır. İstemci issuer metadata, JWKS üzerinden RS256 imzası, state ve PKCE akışını doğrular. `config.json` içindeki `oidc` bölümü kullanılır.

## Audit Trail

Güvenlik açısından önemli işlemler HMAC-SHA256 zincirli, değiştirilmesi tespit edilebilir audit log'a yazılır. Operations ekranından zincir bütünlüğü doğrulanabilir.

## İki-person response approval

Yüksek etkili response işlemlerinde talep eden ve onaylayan kişi ayrılabilir. Kullanıcı kendi talebini onaylayamaz. Kimlik ve approval state, aksiyon çalıştırılmadan **önce** doğrulanır.

## Şifreli backup

Operations ekranı bütünlük kontrollü backup oluşturabilir. Şifreli `.npbackup` envelope, ayrı PBKDF2 türetilmiş encryption/MAC key'leri, AES-256-CTR ve HMAC-SHA256 Encrypt-then-MAC kullanır. Yanlış parola, değiştirilmiş envelope veya iç manifest hash uyuşmazlığı restore sırasında reddedilir.

## Console lockdown

`security.console_allowed_cidrs` yönetim paneline erişebilecek ağları sınırlar. Varsayılan config yalnızca loopback'e izin verir. Ayrıca NetProbe açıkça override edilmediği sürece authentication olmadan non-loopback bind edilmesini reddeder.

## v0.5.0 SOC operasyon özellikleri

Authenticated konsola eklenen alanlar:

- Attack Stories correlation,
- MITRE ATT&CK aggregation,
- Asset Identity,
- Time Machine/history snapshot,
- network-baseline diff,
- detection suppression/tuning,
- CEF/LEEF syslog ve webhook entegrasyonları,
- scoped API token,
- encrypted backup/restore,
- Health/Self-Diagnostics,
- iki-person response approval,
- yerel kullanıcı ve OIDC hesap akışları.

v0.4'teki capture, process attribution, DPI, IDS, Hunt, Replay, Incident Case, Investigation Graph, Detection Lab, Threat Intelligence, evidence signing, response guardrail ve sensor federation yetenekleri v0.5 authorization katmanının arkasında aynen çalışmaya devam eder.
