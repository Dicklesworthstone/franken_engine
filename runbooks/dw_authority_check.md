# Runbook: Authority/Intake Analyzer (`frankenctl check` / `frankenctl onboard`)

> Operator runbook per DW.DOCS (`bd-fqlfw.12`). Capability beads: `bd-fqlfw.5`
> (epic), `bd-fqlfw.5.1` (`check`), `bd-fqlfw.5.2` (`onboard`), `bd-fqlfw.5.3`
> (`franken-lsp`), `bd-fqlfw.5.4` (wording/soundness), `bd-fqlfw.5.5` (capstone).
> Claim state: see *Claim-state note* below — the analyzer reports an **inferred
> authority footprint for supported syntax**, never a noninterference proof.

## What this does (one paragraph)

The authority/intake analyzer projects FrankenEngine's capability + information-flow
algebra onto static source, without running it. `frankenctl check <file>` reports
the **minimal capability footprint** a file's supported hostcall edges require
(`process.env` → `EnvRead`, `hostcall<"fs.read">(...)` → `fs.read`, …), plus
information-flow findings: ambient-authority rejections (`FE-CAP-0001`), denied
flows (`FE-CAP-0002`), and required-declassification obligations (`FE-CAP-0003`,
e.g. `hostcall<"declassify.audit">(...)`). `frankenctl onboard <pkg>` walks a
package's static ES-module graph and aggregates the same facts per module into a
manifest, a least-authority capability profile, a denied-ambient list, an IFC flow
inventory, and a per-compatibility-mode resolution report. Reach for `check` when
reviewing a single extension file; reach for `onboard` when intaking a whole
package before granting it any authority. Both share the runtime's lowering
pipeline, so a definite finding is one the runtime enforcer makes identically.

## Preflight

- Build: `cargo build --release -p frankenengine-engine --bin frankenctl`
  (and `--bin franken-lsp` for editor integration).
- Dependencies: **none** at analysis time (no node/bun/solver). The gate's heavy
  Cargo work routes through `rch`; if `rch` is unavailable, run the gate with
  `DW_RUN_LOCAL=1` (see *Normal use*).
- Inputs: a JS/TS source file (`check`) or a package directory / entry file
  (`onboard`). Typed-hostcall syntax (`hostcall<"cap">(...)`) is TypeScript; it is
  recognized in `.js` files too, but a file using it is treated as TS for
  normalization.

## Normal use

```bash
# Single file — machine output (agent/robot mode), optional evidence bundle:
frankenctl check ./ext.js --format json --out ./artifacts/check-bundle

# Whole package — manifest + capability profile + IFC + per-mode resolution:
frankenctl onboard ./my-extension --format json --out ./artifacts/onboard-bundle

# Full capability gate -> content-addressed bundle under artifacts/dw_authority_check/<ts>/
./scripts/run_dw_authority_check.sh ci             # routes Cargo through rch
DW_RUN_LOCAL=1 ./scripts/run_dw_authority_check.sh ci   # local fallback when rch is down

# Verify / replay an emitted bundle:
./scripts/e2e/dw_authority_check_replay.sh bundle artifacts/dw_authority_check/<ts>
```

## Reading the artifact bundle (`artifacts/dw_authority_check/<timestamp>/`)

| File | Answers |
|---|---|
| `run_manifest.json` | Did it pass? source revision, host facts, content hashes, verify command. |
| `events.jsonl` | The detailed step log: one line per test step with timing + output hash. |
| `commands.txt` | Exact commands run, in order. |
| `steps/<n>_*.log` | Full stdout+stderr of step `<n>` (one per gate test). |
| `degraded_receipt.json` | Present only if a required dependency was missing. |

A single-file `--out` bundle (`check`/`onboard`) instead contains `run_manifest.json`
(carrying `report_sha256`) and `events.jsonl` (one event per finding / per
aggregated obligation), so a report is replay-stable and content-addressed.

## Exit codes (`check` and `onboard`)

| Code | Meaning | Operator action |
|---|---|---|
| 0 | analyzed cleanly, **no** findings | none — the file/package needs no host capabilities for its supported syntax |
| 1 | analyzed, authority/IFC findings present | read `findings` / the denied-ambient + IFC inventory; grant exactly the reported capabilities, mediate declassifications with a signed receipt |
| 2 | unanalyzable (parse error / unsupported construct) — **fail-closed** | the analyzer asserts nothing; fix the construct or narrow the file (try `--goal module` for files with imports) and re-run |

Gate exit codes follow DW.STD: `0` pass, non-zero (`≠3`) fail-closed, `3` degraded
(dependency unavailable — read `degraded_receipt.json`).

## Failure triage

- **`frankenctl check` exits 2 on a file you expect to analyze** → the lowering
  pipeline does not yet support a construct in it (tracked in
  `lowering_gap_inventory.rs`). The report's `fail_closed_reason` names the cause.
  Try `--goal module` if it uses `import`/`export`.
- **`analysis_completeness: "bounded_at_first_violation"`** → lowering fail-closed
  at the **first** ambient-authority access; constructs after it were **not**
  analyzed. Resolve the reported access and re-run to surface any further footprint.
- **`onboard` reports an import under `external_dependencies` instead of analyzing
  it** → that specifier resolves outside the package (e.g. a bare `npm` import);
  it is reported, never silently followed.
- **Gate hangs / fails on `rch exec`** → the rch workers are unavailable (e.g. a
  sibling-crate drift). Re-run with `DW_RUN_LOCAL=1` to build locally; the 4 gate
  tests are identical either way.

## Claim-state note

The runtime-side **compile-time ambient-authority rejection** (`FE-CLAIM-006`) is
**OBSERVED** (16-scenario red-team corpus + RGC gate). The static analyzer here
reports an **inferred authority footprint for the *supported* syntax** of a file
or package — it shares the runtime's lowering, so each emitted finding carries
`confidence = "definite"`, and anything it cannot lower is surfaced fail-closed
(`unanalyzable` / `bounded_at_first_violation`), never silently passed. It is
**not** a noninterference proof for arbitrary JS/TS, and the report's frozen
`disclaimer` says so. The end-to-end capability-typed TS-to-IR *contract* claim
remains bounded; see `docs/AUTHORITY_FOOTPRINT_ANALYZED_SUBSET_V1.md` for the
exact analyzed-subset boundary.
