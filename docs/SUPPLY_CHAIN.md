# Release Supply-Chain Controls

[Türkçe](SUPPLY_CHAIN_TR.md) · **English** · [Documentation index](README.md)

NetProbe IR release builds are static (`CGO_ENABLED=0`) and use `-trimpath`, `-buildvcs=false` and an empty Go build ID. Set `SOURCE_DATE_EPOCH` to pin the embedded build timestamp when comparing reproducible builds.

```bash
SOURCE_DATE_EPOCH=1789257600 COMMIT=<source-commit> ./scripts/build-static.sh
./scripts/release-metadata.sh
```

The release metadata helper emits CycloneDX/SPDX SBOM documents, `provenance.json` and a checksum manifest. If `SIGNING_DATA_DIR` points at a persistent signing directory, the existing Ed25519 evidence signer creates `dist/SHA256SUMS.sig.json`.

A signature proves possession of the configured signing key; it does not by itself establish a public PKI identity. Protect and independently distribute the trusted public key.

## Final v1.0.0 package verification

The final v1.0.0 archive carries both binary/release and source checksum manifests:

```bash
sha256sum -c dist/SHA256SUMS
sha256sum -c SOURCE-SHA256SUMS
```

Detached Ed25519 signatures are shipped as:

- `dist/SHA256SUMS.sig.json`
- `SOURCE-SHA256SUMS.sig.json`
- `dist/RELEASE-PUBLIC-KEY.txt`

Verification with the bundled NetProbe binary:

```bash
PUB=$(cat dist/RELEASE-PUBLIC-KEY.txt)
./dist/netprobe-linux-amd64 config verify --public-key "$PUB" \
  --signature dist/SHA256SUMS.sig.json dist/SHA256SUMS
./dist/netprobe-linux-amd64 config verify --public-key "$PUB" \
  --signature SOURCE-SHA256SUMS.sig.json SOURCE-SHA256SUMS
```

The private signing key is intentionally **not included** in the release archive. The packaged public key enables integrity verification of this release, but users who require organizational trust anchoring should distribute/pin the public key through an independent trusted channel.
