# NetProbe IR v0.8.1 — Detection Quality & Root-Cause Release

[Türkçe](ADVANCED_V081_TR.md) · **English** · [Documentation index](README.md)

NetProbe IR v0.8.1 is a focused hardening release built on the v0.8.0 capture/DPI/IDS/runtime-security/export/fleet stack. The release goal is not to increase raw alert volume. It is to reduce analyst ambiguity by measuring detection quality, correlating multiple evidence types, explaining C2 scoring, surfacing fleet drift, and making probable root cause visible without presenting inference as proof.

## 1. Detection Quality Center

The Detection Quality Center is backed by a persistent store under:

```text
<data_dir>/detection-quality/runs.json
```

A Detection Lab run can optionally carry:

- `label`
- `benign=true|false`
- `expected_rules[]`

The isolated replay engine still produces its normal per-rule results. When a run is labeled, NetProbe records:

- observed rule IDs and counts,
- expected rule IDs,
- benign/malicious corpus intent,
- frame count,
- elapsed processing time.

The quality summary exposes per-rule:

- true positives,
- false positives,
- false negatives,
- precision,
- recall,
- quality score,
- last observed timestamp.

The overall score is deliberately simple and explainable: a weighted precision/recall score. It is not a machine-learning classifier and it is not a substitute for analyst review. A corpus is only as good as its labels.

API:

```text
GET /api/v1/detection-quality
```

Detection Lab labeling is supplied to:

```text
POST /api/v1/lab/run
```

Example body:

```json
{
  "path": "/var/lib/netprobe-ir/pcap/test.pcapng",
  "label": "known-log4shell-positive",
  "benign": false,
  "expected_rules": ["NP-IDS-1201"]
}
```

## 2. Attack Story v2

Attack Story v2 uses the same retained findings, flows, reconstructed files and runtime events already owned by the pipeline. It does not create a second telemetry database.

A story can now include:

- security findings,
- network stages,
- file/YARA stages,
- runtime/eBPF stages,
- ATT&CK technique aggregation,
- score reasons,
- a risk timeline,
- probable root-cause inference.

The risk timeline is an analyst visualization. Its score is a monotonic evidence-pressure indicator, not a probability of compromise.

## 3. Root Cause Engine

Root cause is deliberately marked as:

```text
inference: true
```

The engine selects the earliest relevant suspicious stage and adjusts confidence using supporting later evidence. Runtime evidence before network/file stages increases confidence because it improves temporal causality. The result includes:

- timestamp,
- evidence kind,
- evidence title,
- confidence,
- linked finding/flow/file identifiers when available,
- textual reasons.

NetProbe does **not** claim that the inferred stage is cryptographic proof of initial compromise. It is a ranked analyst hypothesis supported by retained evidence.

The root cause is returned as part of:

```text
GET /api/v1/stories
```

## 4. eBPF Runtime Events v2

The optional runtime provider continues to use `bpftrace` so the core NetProbe binary remains fully static and dependency-free. v0.8.1 improves this provider in two important ways:

1. NetProbe discovers syscall tracepoints available on the running host.
2. It builds a runtime probe program only from supported tracepoints instead of failing the entire provider when one syscall tracepoint is missing.

Supported event families include, when exposed by the host/kernel/bpftrace combination:

- TCP connect attribution,
- `execve`,
- `openat`,
- `unlinkat`,
- `renameat2`,
- `chmod` / `fchmodat`,
- `chown`,
- `memfd_create`,
- `ptrace`,
- `setuid` / `setgid`,
- `mount`,
- `setns`,
- `clone`,
- `bind`,
- `listen`,
- `accept4`.

Runtime events are retained in a bounded in-memory history and published to the existing event bus.

API:

```text
GET /api/v1/runtime-events
```

The endpoint reports:

- active attribution backend,
- whether the provider executable is available,
- supported NetProbe event families,
- retained runtime events.

### Fallback

If `bpftrace` is unavailable or the provider cannot start, normal `/proc` attribution remains active. NetProbe must not claim kernel-event coverage in this state.

## 5. Sigma Engine v2

v0.8.1 extends the v0.8 Sigma translator into a more structured Sigma subset parser/evaluator.

Supported concepts include:

- multiple named detection selections,
- `selection` conditions,
- simple `AND`, `OR`, and `NOT` conditions,
- `1 of prefix*`,
- `all of prefix*`,
- common field modifiers:
  - `contains`,
  - `startswith`,
  - `endswith`,
  - `exists`,
  - `re`,
  - `cidr`.

The translator returns a coverage percentage and warnings. Unsupported semantics must not be silently discarded.

CLI:

```bash
netprobe-ir sigma --in configs/sigma-rule.example.yml --format query
netprobe-ir sigma --in configs/sigma-rule.example.yml --format npdl
```

Web/API translation:

```text
POST /api/v1/sigma/translate
```

The embedded Sigma evaluator can validate the supported subset deterministically. The Hunt-query representation is an analyst-facing translation; complex boolean semantics should be reviewed before operational use.

Generated NPDL is enabled only for a safe, directly translatable subset. Complex Sigma conditions produce a disabled manual-review NPDL starter rather than a dangerously approximate enabled rule.

## 6. CVE/KEV Runtime Exploit Correlation

The existing package/KEV inventory deliberately keeps the distinction between:

```text
product-name overlap
```

and:

```text
version-proven vulnerability
```

v0.8.1 adds a runtime exploit-correlation view that joins:

- installed package/product KEV context,
- Security Findings,
- finding verdict/confidence/severity,
- PID/process context,
- nearby execution-oriented runtime events.

API:

```text
GET /api/v1/exploit-correlations
```

Each result contains:

- CVE ID,
- package/product,
- correlated finding/flow/process,
- risk score,
- runtime-correlation flag,
- explicit `version_proven` boolean,
- score reasons,
- runtime evidence.

A high score means the independent evidence is strongly correlated. It does **not** rewrite a KEV product-name overlap into proof that the installed version is vulnerable.

## 7. C2 Analytics v2

The advanced beacon engine now considers:

- median interval,
- relative MAD / jitter,
- transfer-size similarity,
- periodicity,
- TX/RX ratio,
- destination rotation for the same process/application personality,
- JA4 reuse.

Each group includes human-readable reasons such as:

- low timing jitter,
- high size similarity,
- strong periodicity,
- stable JA4 reuse,
- destination rotation,
- TX-heavy transfer ratio.

The engine remains explainable and deterministic. It does not label encrypted traffic as malicious merely because it is encrypted.

## 8. Fleet Health v2

Fleet remains single-organization in v0.8.1. Multi-tenant isolation is intentionally out of scope.

Sensor snapshots can report:

- running version,
- config SHA-256,
- rules SHA-256,
- normal sensor status.

The controller computes:

- online / stale / offline state,
- health score,
- snapshot age,
- desired-vs-current version drift,
- desired-vs-current config hash drift,
- desired-vs-current rules hash drift,
- critical finding count.

API:

```text
GET /api/v1/fleet/health
```

The existing authenticated command queue remains responsible for controller-to-sensor actions.

## 9. Monitoring

Prometheus output now includes additional metrics for:

- detection quality score,
- precision,
- recall,
- quality run count,
- retained runtime events,
- exploit correlations,
- fleet sensor count,
- online/stale/offline fleet states.

The `/api/v1/health` runtime-security section also includes quality, runtime, exploit-correlation and fleet-health summaries.

## 10. Web console

The v0.8 light theme is retained. v0.8.1 adds:

- Detection Quality navigation/workspace,
- rule-quality tables,
- Sigma translator,
- Attack Story root-cause callouts,
- per-story risk timeline bars,
- runtime-event table,
- exploit-correlation table,
- richer C2 scoring columns,
- fleet health meters and drift badges.

The full-width responsive behavior introduced in v0.8 remains intact.

## 11. Security boundaries and non-claims

v0.8.1 does not claim:

- multi-tenant data isolation,
- a bundled native libbpf/CO-RE runtime agent; runtime events are currently delivered by the optional bpftrace provider,
- that all kernel versions expose all listed syscall tracepoints,
- that KEV product overlap proves an installed version is vulnerable,
- that probable root cause is certainty,
- that Sigma compatibility is complete across the entire Sigma specification,
- that a C2 score alone proves command-and-control activity.

These boundaries are intentional. NetProbe continues to distinguish evidence, inference, exposure context and proof.
