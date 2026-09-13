# NetProbe IR v0.7 Gelişmiş Analiz, Runtime Security ve Genişletilebilirlik

**Türkçe** · [English](ADVANCED_V07.md) · [Dokümantasyon dizini](README_TR.md)

Bu belge v0.7 ile eklenen ileri seviye yeteneklerin çalışma modelini, güvenlik sınırlarını ve operasyonel bağımlılıklarını açıklar. v0.7, mevcut capture → process attribution → DPI → IDS → Hunt → Case → evidence → export zincirinin üzerine kuruludur; ikinci ve kopuk bir telemetri altyapısı oluşturmaz.

## 1. Temel prensipler

1. **Kanıt önceliklidir.** Bulgular mümkün olduğunca flow, packet, process, file veya case kimliğiyle ilişkilendirilir.
2. **Şifreli veride görünmeyen içerik uydurulmaz.** TLS/HTTP/3 payload veya QPACK header anahtarsız görünmüyorsa UI bunu görünür değil olarak belirtir.
3. **Capture hot-path bloklanmaz.** YARA-X, streaming, WASM ve remote analyst işlemleri asynchronous/bounded katmanlardadır.
4. **State sınırlıdır.** Queue, artifact, plugin output ve korelasyon pencereleri bounded tutulur.
5. **Opsiyonel bağımlılıklar capability olarak raporlanır.** `yr`, `wasmtime` veya `kcat` yokluğu ana sensörü durdurmaz.
6. **Retention politikası tek noktadan uygulanır.** Smart PCAP `headers/metadata/drop` seçildiyse aynı trafik network-file reconstruction yoluyla ikinci kez payload olarak tutulmaz.

## 2. Network file extraction ve malware evidence

`internal/fileextract` motoru yeterli cleartext/in-order payload görüldüğünde sınırlı boyutta uygulama nesnesi reconstruct eder. Desteklenen başlıca yollar HTTP/1 response, SMTP/MIME attachment, desteklenen FTP control/data ilişkileri ve SMB2 write akışlarıdır.

Her artifact için mümkün olduğunda şu metadata tutulur:

- artifact ID/zaman,
- flow ID,
- protokol ve yön,
- source/destination endpoint,
- process attribution,
- güvenli filename,
- MIME,
- boyut,
- SHA-256/SHA-1/MD5,
- Shannon entropy,
- protokole özgü metadata,
- YARA-X eşleşmeleri.

`max_file_mb` ve `max_artifacts` sınırları bellek/disk büyümesini kontrol eder.

### YARA-X

`yara_rules` tanımlı ve `yr` binary mevcutsa diske alınan artifact'ler asynchronous taranır. Tarama packet-processing goroutine'ini bekletmez. Eşleşmeler `signature_match` finding üretir ve file SHA-256/rule adı evidence olarak eklenir.

Örnek:

```json
"file_extraction": {
  "enabled": true,
  "store_payload": true,
  "max_file_mb": 32,
  "max_artifacts": 2000,
  "yara_x_binary": "yr",
  "yara_rules": "/etc/netprobe-ir/yara-rules.yar"
}
```

`configs/yara-rules.example.yar` yalnız demonstrasyon içindir; production malware rule corpus değildir.

## 3. Smart PCAP

Amaç gözlem ile evidence retention'ı ayırmaktır.

- `full`: frame tam tutulur ve file reconstruction yapılabilir.
- `headers`: link/network/transport header tutulur; application payload ve file reconstruction tutulmaz.
- `metadata`: yalnız yapılandırılmış metadata tutulur.
- `drop`: PCAP/file evidence tutulmaz; transient DPI/IDS analizi devam eder.

Rule selector'ları process, application, interface, IP, CIDR ve direction olabilir.

## 4. NPDL — NetProbe Detection Language

NPDL bilinçli olarak Turing-complete değildir. Loop, import, shell, filesystem veya network erişimi içermez.

```text
rule suspicious_python_tls
 title Suspicious Python outbound TLS
 severity high
 confidence 85
 mitre T1071.001,T1059.006
 when process ~ python AND application ~ TLS AND direction = outbound
end
```

Desteklenen temel operatörler `=`, `!=`, `~`, `>`, `>=`, `<`, `<=` şeklindedir. `process`, `exe`, `application`, `protocol`, `direction`, `src_ip`, `dst_ip`, `port`, `sni`, `ja4`, `http_host`, `risk`, `file_sha256`, `file_name`, `yara`, `finding_rule` gibi alanlar kullanılabilir.

NPDL bulguları `script_match` verdict'iyle işaretlenir; exact IOC veya built-in signature ile karıştırılmaz.

## 5. HTTP/2, HTTP/3 ve QUIC

Cleartext HTTP/2 (`h2c`) preface ve SETTINGS metadata parse edilir. TLS içindeki HTTP/2 header'ları session key olmadan çözüldüğü iddia edilmez.

QUIC tarafında long-header packet type, version, DCID/SCID, Retry/version negotiation ve NetProbe QUIC fingerprint gibi gözlenebilir transport metadata çıkarılır. Normal HTTP/3 QPACK header/payload şifrelidir ve anahtarsız sensörde görünmez.

## 6. Protocol packs

- `core`: DNS/HTTP/TLS/SSH ve temel uygulama protokolleri,
- `enterprise`: SMB/RDP/Kerberos/LDAP ve yönetim/auth ipuçları,
- `database`: PostgreSQL/MySQL/Redis,
- `devops`: altyapı servis imzaları ve etcd-benzeri HTTP/2 trafik,
- `ics`: Modbus/TCP, DNP3, Siemens S7/ISO-on-TCP, BACnet/IP.

Payload signature bulunabildiğinde porttan daha güçlü confidence kullanılır. Tek başına port kesin classification gibi gösterilmez.

## 7. Lateral movement / credential davranışı

Aynı identity'nin bounded zaman penceresinde çok sayıda hosta SMB/RDP/SSH/WinRM/Kerberos/LDAP ile erişmesi veya NTLM materyalinin çoklu hostlarda görülmesi behavioral finding oluşturabilir. Bu sonuç credential theft'in kesin kanıtı değildir; investigation sinyalidir.

## 8. Encrypted DNS

DoT/DoQ port özellikleri, DoH HTTP metadata ve bilinen resolver SNI bilgisi kullanılır. Firefox/Chrome/systemd-resolved gibi beklenen process'ler allowlist edilebilir. Beklenmeyen process tarafından encrypted DNS kullanımı process/PID/SNI/remote bağlamıyla finding üretir.

## 9. Gelişmiş C2 beacon analizi

Aynı PID + remote IP + port + application akışları üzerinde median interval, relative MAD/jitter, transfer-size similarity ve periodicity ölçülür. Sonuç açıklanabilir 0–100 skorla gösterilir; kara-kutu ML kararı değildir.

## 10. Identity baseline

Process, user/UID, container, Kubernetes pod ve cgroup/service için ayrı network personality tutulabilir. Profil yeterince olgunlaştığında yeni destination, yeni application veya daha önce gözlenmeyen saat dilimi behavioral deviation üretir.

## 11. Vulnerability / KEV context

`dpkg-query`, RPM veya APK ile installed package inventory çıkarılabilir. CISA-KEV uyumlu JSON local file/URL üzerinden alınabilir. KEV'in package-manager-specific affected-version range içermemesi nedeniyle ürün adı eşleşmesi yalnız **exposure context** olarak gösterilir ve `proven_vulnerable=false` kalır. Bu, CVE'nin o sürümde kesin bulunduğu iddiası değildir.

## 12. OTLP, NATS, Kafka ve ClickHouse

Internal Event Bus bounded worker'lar üzerinden:

- OTLP/HTTP Logs,
- NATS Core PUB,
- `kcat` adapter ile Kafka producer,
- ClickHouse JSONEachRow

gönderebilir. Queue dolarsa capture beklemez; drop sayacı artar.

## 13. WASM/WASI plugin modeli

Opsiyonel plugin'ler dış `wasmtime` runtime üzerinden çalıştırılır. Event JSON stdin ile verilir, finding/enrichment JSON stdout beklenir. Timeout ve max output sınırları vardır. NetProbe plugin'e filesystem/network preopen vermez. Runtime yokluğu yalnız plugin özelliğini degraded yapar.

## 14. Fleet Management

Federation katmanı bounded sensor status/flow/finding snapshot'larını merkezi tarafta tutabilir. Controller, sensor için TTL'li command queue oluşturabilir; sensor token ile poll eder ve sonucu ack eder. Tasarım arbitrary remote shell yerine kontrollü command türlerine yöneliktir. PCAP varsayılan olarak sensörde kalır.

## 15. Evidence-based Analyst

Local analyst retained flow/finding/file/packet metadata üzerinden deterministik özet üretir ve evidence ID'leri döndürür. Opsiyonel remote mod, bounded evidence paketini OpenAI-compatible `/chat/completions` endpoint'ine gönderebilir. API anahtarı config içinde değil environment variable üzerinden okunur. Remote analyst hiçbir zaman IDS karar yolunda değildir.

Gizlilik politikası remote evidence gönderimine izin vermiyorsa `remote_enabled=false` bırakılmalıdır.

## 16. Sensor self-protection

Watch edilen binary/config/rule dosyalarının hash değişimi/kaybolması, data directory disk baskısı ve geriye doğru önemli clock hareketi izlenebilir. Rebaseline yalnız yetkili admin API üzerinden yapılır ve audit log'a yazılır.

## 17. Opsiyonel bağımlılıklar

| Özellik | Opsiyonel araç |
|---|---|
| YARA-X | `yr` |
| WASM | `wasmtime` |
| Kafka | `kcat` |
| eBPF attribution | `bpftrace` + uyumlu kernel/yetki |
| Active response | ör. `nft` + gerekli privilege |

NetProbe static binary'nin temel capture/DPI/IDS işlevleri bu araçlar olmadan da çalışır.

## 18. Bilinçli sınırlar

v0.7 aşağıdakileri iddia etmez:

- anahtarsız TLS/HTTP3 payload çözme,
- encrypted session için full HPACK/QPACK decode,
- Suricata/Snort community rules'ın eksiksiz karşılığı,
- native in-process Kafka client veya JetStream durable consumer,
- yalnız KEV/package-name eşleşmesiyle kesin vulnerability,
- required kernel/tooling olmayan hostta live eBPF,
- active-active controller consensus/distributed SQL.

Release ortamında gerçekten çalıştırılan testler için [`TEST-RESULTS_TR.md`](../TEST-RESULTS_TR.md) dosyasına bakın.
