# NetProbe IR v1.0.0 — Final Release Test Results

[Türkçe](TEST-RESULTS_TR.md) · **English** · [Documentation index](docs/README.md)

- Release date: 2026-09-13
- Package: `netprobe-ir-1.0.0`
- Release theme: **Production Investigation, Notification Management & Live Traffic**

This report records validation actually executed for the final v1.0.0 source tree and release binaries. Optional external runtimes are called out explicitly; unavailable dependencies are not represented as successful live qualifications.

## 1. Full source quality gate — PASS

Executed successfully through `./scripts/test-all.sh`:

- `gofmt` source-format check
- shell syntax checks
- shipped JSON syntax checks
- source/embedded web-asset synchronization
- JavaScript syntax (`node --check`)
- `go vet ./...`
- `go test ./...`
- repository-wide `go test -race` in bounded package groups
- AMD64/ARM64 static build
- embedded self-test
- Sigma/interoperability/analytics CLI regression
- SBOM/provenance generation
- release checksum verification
- staged installer/auth-reset/uninstaller regression

Result: **PASS**

## 2. v1.0 focused backend regression — PASS

Re-run uncached:

```bash
go test -count=1 ./internal/notifications ./internal/trafficseries ./internal/investigation ./internal/server
```

Covered Canvas graph query/filter/neighborhood/clustering and 5,000-flow safeguards; dynamic Asset APIs; event-bus IN/OUT traffic history/downsampling; Email/Telegram encrypted persistence and masking; SMTP and Telegram delivery/error handling; severity routing, bounded asynchronous delivery, cooldown/dedup; RBAC and browser same-origin protections.

Result: **PASS**

## 3. Real Chromium E2E console regression — PASS

Executed with the final release binary through `./scripts/integration-ui-browser.sh`.

Validated Overview KPI drill-down; live-traffic time ranges and UI-only Pause/Resume; graph navigation, zoom, pan, single/multi/rectangle selection, drag and session positions; Asset pivots; Notification Settings save/load and masking; bounded browser history and short-run heap sanity.

The build host Chromium had a global `URLBlocklist: ["*"]`. The policy entry was temporarily removed only for this release E2E run and restored immediately afterward. No Chromium policy change is included in the product or archive.

Result: **PASS**

## 4. Real Linux packet-capture regression — PASS

The final reproducible AMD64 binary passed real AF_PACKET and TPACKET_V3 capture, HTTP DPI, `/proc` PID attribution, bounded packet history, per-interface Stop/Start, native IDS, server-side Hunt, global Stop/Resume with the console online, PCAPNG recording and graceful final reporting.

Result: **PASS**

## 5. Real TLS regression — PASS

The final binary passed real TLS ClientHello, SNI, ALPN, JA3, JA4 and NPSH verification.

Result: **PASS**

## 6. Reproducible static builds — PASS

Controlled inputs:

- `VERSION=1.0.0`
- `COMMIT=release-1.0.0`
- `SOURCE_DATE_EPOCH=1789257600`
- embedded build timestamp `2026-09-13T00:00:00Z`
- `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, empty Go build ID

AMD64 and ARM64 binaries were built twice independently and compared byte-for-byte.

Final SHA-256 values:

- AMD64: `df1cc7c181c92818a21e211779ba40697a00b267cbf5bc05359f776ba51f5ef7`
- ARM64: `7359159e052239ace554ca185b07f4755f0f777f2a1d51eb661c94887aa1da4c`

Result: **PASS**

## 7. Optional runtime qualification boundaries

The release host did not have `bpftool` and a qualified native CO-RE BTF toolchain, `bpftrace`, YARA-X `yr`, `wasmtime` or `kcat`. The release therefore does not claim live qualification of those external runtimes on that host. Adapter, parser, readiness and fallback paths remain covered by automated tests where applicable.

## Final release decision

All mandatory v1.0.0 quality, backend, browser, live Linux and TLS gates executed for this release passed.

**Release decision: APPROVED**
