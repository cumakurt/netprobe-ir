# Sürüm Tedarik Zinciri Kontrolleri

**Türkçe** · [English](SUPPLY_CHAIN.md) · [Dokümantasyon dizini](README_TR.md)

NetProbe IR sürüm build'leri statiktir (`CGO_ENABLED=0`) ve `-trimpath`, `-buildvcs=false` ile boş Go build ID kullanır. Tekrarlanabilir build karşılaştırmalarında gömülü zamanı sabitlemek için `SOURCE_DATE_EPOCH` ayarlayın.

```bash
SOURCE_DATE_EPOCH=1789257600 COMMIT=<kaynak-commit> ./scripts/build-static.sh
./scripts/release-metadata.sh
```

Release metadata yardımcısı CycloneDX/SPDX SBOM belgelerini, `provenance.json` dosyasını ve checksum manifestini üretir. `SIGNING_DATA_DIR` kalıcı bir imzalama dizinini gösteriyorsa mevcut Ed25519 evidence signer `dist/SHA256SUMS.sig.json` dosyasını oluşturur.

İmza, yapılandırılan private key'in kullanıldığını kanıtlar; tek başına açık PKI kimliği oluşturmaz. Güvenilen public key'i koruyun ve bağımsız bir kanal üzerinden dağıtın.

## Nihai v1.0.0 paket doğrulaması

Nihai v1.0.0 arşivi binary/release ve kaynak checksum manifestlerini birlikte taşır:

```bash
sha256sum -c dist/SHA256SUMS
sha256sum -c SOURCE-SHA256SUMS
```

Detached Ed25519 imzaları:

- `dist/SHA256SUMS.sig.json`
- `SOURCE-SHA256SUMS.sig.json`
- `dist/RELEASE-PUBLIC-KEY.txt`

Paket içindeki NetProbe binary'siyle doğrulama:

```bash
PUB=$(cat dist/RELEASE-PUBLIC-KEY.txt)
./dist/netprobe-linux-amd64 config verify --public-key "$PUB" \
  --signature dist/SHA256SUMS.sig.json dist/SHA256SUMS
./dist/netprobe-linux-amd64 config verify --public-key "$PUB" \
  --signature SOURCE-SHA256SUMS.sig.json SOURCE-SHA256SUMS
```

Private signing key sürüm arşivine bilinçli olarak dahil edilmez. Paket içindeki public key bu sürümün bütünlüğünü doğrulamayı sağlar; kurumsal trust anchoring gereken ortamlarda anahtarı bağımsız ve güvenilir bir kanal üzerinden pinleyin.
