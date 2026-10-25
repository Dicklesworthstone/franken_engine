# FrankenEngine Reality Check — 2026-10-24 continuation

**Verdict: useful native runtime and released CLI; the complete program remains
undelivered.** The next decisive work is current-source qualification and G0
measurement/conformance, followed by executable vertical slices and real security,
fleet, hardware and external results. Task closure and contract validation cannot
substitute for these outcomes.

This refresh serves the project owner's requested comprehensive reality check.
Its concrete consumer is the owner selecting the next BRIDGE/release work; the
feature it gates is qualification of the current engine for downstream use. The
observed defect classes are stale claim evidence, incomplete conformance oracles,
unqualified current-source changes and documentation describing the wrong IFC
authorization order. Supersede this section when a newer revision-bound review
rechecks these findings. It creates no runtime or performance capability credit.

### 2026-10-25 persisted fleet-state repair and current qualification

The current tested source is
`8fa53dbe72be3314d7166627f4cf8f3cbab30e256bd6ed76f488da31f73e5f4e`,
base `07025731194b72952eb5fcbff0459694668ac7a2` plus 28 explicit owned
overlays. Its manifest is retained at
`artifacts/optimization-100x-ss6_54xg/sqlmodel-durable-consumer-source-8fa53dbe72be/manifest.json`.
It preserves all 17 Rust file hashes from the qualified parser/runtime source
`78c7032ce026e35103230e3870446d1664a4510710ca3d7bdfe69d30183658e6`.
Only the SQLModel dependency source, generated lockfile and three existing
dependency/build documents differ. Pre-existing peer edits are excluded.

Actual retained-file fleet tests exposed a defect in the published SQLModel
`0.5.0` driver: it requires textual `FULL`, but FrankenSQLite correctly reports
`PRAGMA synchronous` as integer `2`. The full engine fleet module first produced
139 passes and four ignored tests; explicitly including those four produced
139 passes and four failures at database admission. None reached its intended
crash, stale-writer or reopen scenario. These failed observations remain retained.

The engine now consumes the already committed public SQLModel fix
`7f432ff690260ef85aca5227e2372b2eb63230c9` through three coherent direct Git
dependencies. All eight resolved SQLModel packages use that immutable revision;
all 15 FrankenSQLite packages remain registry `0.4.10`. Every other resolved
package record is unchanged. There is no root patch, registry-cache edit,
engine-owned durability policy or registry-version fallback. No crate was
published. The SDK still requires WAL, exact integer FULL and disabled statement
microbatching; weaker profiles remain rejected.

Upstream qualification on its own pinned toolchain passed all three strict-profile
tests, including retained-file reopen/commit/readback and five weaker-profile
refusals (`rchw-83d2641c-53a3-426e-9179-34bd56bfc1d8`, exit 0 and terminal
acknowledgement). Its lockfile uses FrankenSQLite `0.4.12`; that upstream result
alone does not qualify the engine's `0.4.10` consumer.

Fresh engine-consumer validation on pinned `nightly-2026-09-21` passes
**1,039/1,039, zero failed or ignored, 45,142 filtered**, in 21.39 seconds
(`rchw-0d19e2cb-4798-47d2-bb41-cb0572d94f6c`, exit 0, acknowledged).
This is the earlier 896 parser/runtime checks plus the entire 143-test engine
fleet module, with `--include-ignored`, assertions and overflow checks enabled.
All four real persistence/process tests now pass. A second execution with a
different retained database root passes the same **1,039/1,039** in 20.25 seconds
(`rchw-daf8c1f9-7fe6-45ca-8785-e538f04c10c3`, exit 0, acknowledged).
The worker-only 718,219,952-byte ELF keeps SHA256
`d5ae051c525617385cf9ddd5f06e943d267cd7c9f46a3576851f5e090d6b88fb`
and file identity before/after reexecution. Child-process summaries are preserved
separately from the outer 1,039-test result. This is solo reexecution, not a
second independent verifier, full-library conformance or physical power-loss proof.
The external authority anchor used by the process test is explicitly test-only.

Current-source all-target Check passed in 23m11s
(`rchw-2019eb0c-2209-4de2-b400-62694f305d62`, exit 0, acknowledged).
Strict all-target Clippy also passed in 24m11s
(`rchw-6a7b0306-cbda-4d51-91e1-b44ab94d94dc`, exit 0, acknowledged).
Engine-only no-default-feature all-target Check passed in 16m58s
(`rchw-3495ee43-3749-4c5a-88f6-5969eaf10bbf`, exit 0, acknowledged), with no
optional integration-family compilation in its fresh isolated log. The six
selected standalone build-gate tests passed with zero ignored and two filtered
in 0.41 seconds after a 17m20s build
(`rchw-c60d66ef-b88f-47df-9a8d-d0764f7e4e84`, exit 0, acknowledged).
These include the manifest ownership check, documentation contract checks, and
injected fleet/Buffer command-failure checks. The injected commands are protocol
doubles testing the gate; they are not evidence of native command execution.
An incorrect
initial build-test selection was cancelled during compilation, before any test
executed; its exit 143 is not test evidence. The corrected selection excludes
the two CI-mode tests that invoke a deleting temporary-file drill. A separate
no-default Cargo graph emitted no optional integration units but suffered SSH
exit 255; recovery acknowledged that failure, so it is partial diagnostic evidence
only and does not replace the separate compiler gate.

The fresh CLI produced by the same successful Cargo build passes three functional
checks: JS `const n = 40; n + 2;` returns `42`, TS
`const n: number = 40; n + 2;` returns `42`, and sole source `(` exits 2 with a
parse error (`rchw-b64d6c7b-cd05-4c88-b653-60bcebf411e6`, exit 0, acknowledged).
The worker-retained 109,697,872-byte ELF has SHA256
`1198177c5d682a40f6d2d044d0af63c650a17e7983b4317976a3f7e2bcabb22d`,
unchanged before/after these probes. It is unoptimized; these three examples
establish functional behavior only, not broad TS support or runtime performance.

The previous `78c7032c`
source passed its 896-test selection twice and both compiler gates, but those
passes are not substituted for this dependency-source change. Workspace format
and UBS remain unqualified, as described below; the existing scoped commit
exception remains unanswered and the patch is uncommitted. Full live fleet
transport/decoder cutover, full workspace tests, downstream `franken_node`
compatibility and the original performance campaign remain open. The latter
still has zero qualified passes or speed samples.

### 2026-10-25 public parser repair and benchmark attempt (preceding source cuts)

At HEAD `c18108919fe4f8aa17cdddcffc327391e27b2499`, tested logic
cut `b10dde4a0149426c7ea87ff119a8e6450cbd38608e9cbaacd55f6e166b702b52`
rejects an unmatched leading parenthesized expression at the Raw fallback.
Previously, the retained candidate accepted sole source `(` as Raw. The change
uses the existing literal-aware delimiter scanner after comment removal; it
does not reject every remaining Raw expression or complete the broader Raw
inventory/lowering task `bd-6vl81`.

Pinned strict remote native validation passes **772/772, 0 ignored, 45,409
filtered**, in 2.57 seconds after compilation: 467 canonical parser tests,
160 parallel parser tests, 86 dual-backend parser tests, 52 JSX/TSX parser tests,
six native module source tests and one cached-module test. Four new regressions
cover invalid Script/Module source, valid literal/comment delimiters, public
preparation and Function compilation, and unchanged eval authority restrictions.
The caught synthetic worker panic is an existing parallel-parser negative
control. This is selected native evidence, not a full-library or Test262 result.
The retained worker ELF is SHA256
`7efd5266f181e489417b0ba76338e8c99081e91241b4423dd6883696fb51a9b4`.
A second invocation from that same retained ELF passes **136/136, 0 ignored,
46,045 filtered**, in 17.93 seconds: the prior 132 runtime checks plus the four
new regressions. Its byte identity and SHA256 match before and after execution.
This is solo reexecution, not a second independent verifier. Both exact-source
compiler gates subsequently passed with terminal acknowledgements.
The complete parser file passes pinned formatting and static UBS (zero critical
findings); this does not establish green workspace formatting or UBS.

The subsequent parser/runtime cut was
`78c7032ce026e35103230e3870446d1664a4510710ca3d7bdfe69d30183658e6`:
one manual formatting hunk in the earlier interpreter patch, with the parser
bytes unchanged. Pinned formatted interpreter output before/after is identical;
its 896-test union passed twice, and both final compiler gates passed separately.
The ordinary pinned formatter checked 16 of 17 owned Rust files (seven clean,
nine dirty), then aborted while requesting 76,555,678,280 bytes in its diff
generator under an explicit 8 GiB child limit. The same pinned formatter's stdout
plus exact byte comparison agrees with all 16 completed verdicts and finds the
remaining file dirty: seven clean, ten dirty overall. No acceptance condition
changed and no previously dirty file passed. The one formatting difference on a
changed line was fixed; remaining reported differences are outside changed lines.
This does not establish a green workspace format gate. The final interpreter's
static scan still exits 1 with 18 critical flags, matching the preceding scan;
the broader patch therefore remains gated and uncommitted.

An initial new fixture wrongly expected eval SyntaxError behavior. Inspection
confirmed that direct eval requires `runtime.eval`, and indirect eval is inert
and throws EvalError. The fixture now checks those restrictions explicitly;
production authority checks were not changed. Function already rejected this
invalid body and remains a positive counterexample. The earlier D28 invocation
is retained separately and is not evidence for the corrected final source.

One fresh TS1 comparison reserved all four configured slots and kept the
original driver, binary identities and gates. The historical baseline transferred
directly between workers with exact hashes and a wrong-token refusal; its
listener closed afterward. Old/candidate/Node Lodash preflight checks passed.
The next CPU observation refused **87.5% against the unchanged 80% one-core
limit**: **0/4,680 measured samples and 0/52 replays**, strict remote exit 2 with
terminal acknowledgement. No qualified speedup or V8-relative number follows.
The campaign remains **0/100**, and the performance Bead remains open.

### Source, reading and evidence boundaries

- Inspected main: `5129eba9ccbcfa4c9993a0c074618c74b1cfbfef`. Existing changes to
  `execution_orchestrator.rs`, `baseline_interpreter/process_lifecycle_tests.rs`
  and the tracker were present before this refresh and preserved.
- Read root `AGENTS.md` in full, all 2,548 README lines, both canonical plan files
  (including all 2,606 lines of the main plan), the reality-check skill and its
  gap/bridge/ambition guidance. Additional reading covered the charter, formal
  security model, architecture, split contract, claim ledger, shadow proof state,
  current implementation seams and selected tests/producers. This does not claim
  a line-by-line audit of all 506 specialist Markdown documents or all tests.
- `/data/projects/AGENTS.md` is absent on this Mac. Local ancestor instructions
  and the exact path on configured RCH worker `trj` were read. The worker copy
  lacks the named reward-hacking/work-graph sections; their rules quoted in root
  guidance remain binding. No missing section was invented.
- Fresh runtime probes below use the published **v0.2.0 macOS arm64 binary**,
  not current-main machine code. A live GitHub API lookup still reports v0.2.0
  (2026-10-04) as latest and issue #6 as open. Its retained archive SHA256 is
  `c6524725336ea0c14214589ba8f117cd837e4e0322250adf2b2c0bfe081a2744`;
  the archive member matches executable SHA256
  `522745f5197647f70248d31488296932d860da9dfcf66ad39ea542e3f3b574bc`.
- Local raw evidence is retained under
  `artifacts/reality_check/20261023T2230-Pa0MIP/`, with the supplied smoke's
  artifacts under `artifacts/readme_cli_workflow_smoke_tests/real-binary-q3svp3gl/`.
  These ignored local files are not a published or independently verified bundle.

### 2026-10-25 native repair qualification

Verified native source cut `f75b673aee3e423f0e5177a06cb2dbeaeb567a65b5a6afacc8f3c742631dae7a`
is base `07025731194b72952eb5fcbff0459694668ac7a2` plus 17 explicit overlays,
excluding the pre-existing process-lifecycle/orchestrator edits. Its manifest and
recovery archive are retained under
`artifacts/optimization-100x-ss6_54xg/wait-prototype-timer-fleet-source-f75b673aee3e/`.
Pinned strict remote all-target check and Clippy with `-D warnings` exit 0 with
terminal acknowledgements. No native compilation or executable retrieval ran on
the Mac. Debug test builds retain assertions and overflow checks.

Production changes charge pending child-process wait payloads before enqueue,
with exact admission rollback, and include existing intrinsic constructor
prototypes in native namespace provenance walks. Private override carriers expose
their own value and label without pulling in an unrelated hidden prototype.
Tests cover denied admission with an unrelated queued callback, no lazy prototype
allocation, replacement precedence, Secret labels, Proxy labels and a Public
replacement under an unrelated Secret realm prototype. Two thenable fixtures now
explicitly grant Timer; matching negative controls withhold Timer and require the
original exact denial. No production capability gate was weakened.

The selected native run passes **84/84, 0 ignored, 46,085 filtered**, including
the unchanged 864-case Promise module in both lanes and both GC modes. Independent
reexecution passes **83/83**, excluding only that exact Promise test. The earlier
845 source cut independently passes its selected 33 short tests and full Promise
test in two separate runs; its original timeout remains a failed invocation.
These selections do not establish a green full workspace or full 46,169-test
library. Eight failures from the original sampled run remain under investigation.

The existing fleet-quarantine target moved to the control-plane test package,
removing the engine self dev-edge while retaining all 11 original test bodies.
Both its native Cargo run and independent Cargo-context rerun pass **11/11**.
An earlier direct retained-binary rerun was 10/11 because a script fixture's
compile-time source namespace had retired; that failure remains recorded.
The four shell fault scenarios are protocol evidence only. The broader crate
split, three-run compile measurements, downstream qualification and targeted
native standalone gate tests are not complete. Existing all-features sentinel
behavior can still duplicate target ownership.

The subsequent `554f03f8103fe49416fad09901ca06ff7af5634ffe1d2afd8a3e280c380e3f45`
cut adds nonjoining rope serialization in the canonical core string type and
fixture repairs with stronger positive/negative controls. Core string tests
pass **176/176, with one pre-existing release timing experiment ignored**;
independent worker reexecution repeats that result with the same ELF hash.
The two complete changed core files also pass static UBS. The new engine
selection is **88 passed / 3 failed / 0 ignored / 46,078 filtered**. Its unchanged
rope/stringify regression now passes. The canonical Stream getter has the
correct authenticated origin and function identity but lacks retained function
source metadata, so admission correctly refuses it. The proxy's fresh memory
oracle exposes an uncharged raw fixture write; PassThrough's writable error
marker reserves delivery for the readable half. Corrections to those two
fixtures and a producer-side metadata repair remain unverified. No accessor
allowlist or confidentiality gate has been relaxed.

The targeted native standalone fault/contract tests also pass **2/2** at f75.
The first 19-path compiler run caught a type error in the added diagnostic;
the corrected 554 cut's all-target check and Clippy both exit 0 with terminal
acknowledgements. Commit `c18108919fe4f8aa17cdddcffc327391e27b2499` lands only
the independently reexecuted two-file core rope repair, with a fresh complete
two-file UBS exit 0. Full-file engine UBS remains incomplete after hitting its
analyzer-output limit; this is not a passing scan and has not been suppressed.

The subsequent 24-path `39682c60b199` source cut passes **101/105**, with all three
new source-quota tests, charged proxy fixture and native-source display privacy
controls passing. Independent reexecution of the same selection plus two library
admission controls gives **103/107**, reproducing all four failures. The source
cache failure also reproduces alone on the older f75 executable. Two failures
expose missing audit-source propagation to a lazy Web dependency; a three-file
producer repair is pending native verification. The fourth fixture used a
partial checkpoint that never drives readable-stream delivery; its correction
uses the full event loop and retains the exact event, label and cleanup checks.

A retained-CLI diagnostic identifies the cache defect precisely: `(` becomes a
sole unresolved `Expression::Raw`. The pending repair rejects that top-level
fallback in both native caches, retains all four original malformed fixtures,
and adds runtime-cache refusal/parse-once checks plus canonical comparisons for
all 14 valid embedded module templates. It does not repair or qualify the general
parser's fallback behavior. These repairs are frozen in the 26-path source cut
`2ecd85fb7f8b`, whose expanded native selection passes **132/132, 0 ignored**.
Independent worker reexecution repeats **132/132**, with unchanged executable
identity and the full original selection retained. All four prior failures pass.
Pinned all-target check and Clippy both exit 0 with terminal acknowledgements.
The full unchanged Promise matrix also passes: **864 cases in both native lanes
and both GC modes**, with exact result and memory-accounting checks. Its single
native test completes in 2,123.42 seconds with zero ignored; the retained ELF
identity and hash remain unchanged before and after execution.

The seven metadata, parser and display files pass complete static UBS with zero
critical findings. Scanning the interpreter separately completes without the
combined-file output limit, but exits 1 with 18 critical findings. A full scan of
the committed c181 interpreter finds 15; all 15 fingerprints persist, and three
additional flags concern test-only byte-limit and label-enum comparisons. The
findings remain visible and the interpreter commit remains gated. No scanner
rules, limits, tests or assertions were weakened to obtain a passing result.

The next 28-path `d3fe92ab363b` cut moves the unchanged eight-test public Buffer
target to the existing companion package. It preserves all 25 previous targets,
forwards engine defaults for normal coverage, and explicitly retains Buffer in
both standalone modes with corresponding failure/readiness guards. Default
Buffer execution passes **8/8**, and six focused standalone guards pass **6/6**,
including independently injected Buffer and fleet command failures. These fault
doubles test shell-gate behavior. No-default Buffer also passes **8/8**. Fleet
quarantine passes **11/11 in both feature modes**, retaining the explicit
non-authoritative mock-TEE disposition. The new full all-target check and Clippy
both exit 0 with terminal acknowledgements. Both after-only Cargo graphs have zero engine binary units;
the default graph retains all nine optional sibling packages, while no-default
retains exactly Asupersync/mock TEE and excludes all nine. The observed single
build duration is not a matched or three-run compile-speed result. The runtime
production source is unchanged from 2ecd85; this does not close the broader
crate-extraction, CI, full-suite or performance tasks.

The remaining patch is uncommitted under the required static/format gates. UBS
now completes across the supported changed files in full-file partitions, with
21 critical flags visible: 18 inherited and three new test-only comparison
flags. Direct strict RCH refuses `cargo fmt` as non-compilation. A worker-only
read-only formatter check of the 17 frozen Rust files ended with SIGKILL before
completion; the kernel journal window contains no entries, so its cause remains
unconfirmed. No full formatting pass, suppression or policy exception is claimed.

After validation jobs finished, the single TS1 readiness opportunity found a
peer job reserving all four worker slots. No readiness or benchmark invocation
was submitted. The old fa benchmark executable is also absent on TS1; candidate
133, the genuine Node executable and all 36 input/provenance files match their
expected hashes. The staged observer is legacy; the corrected source pair is
available locally. These facts earn no measurements, replays or optimization
passes, and candidate 133 remains separate from the maintenance source cuts.

Independent proper-Cargo Buffer and fleet targets pass **8/8** and **11/11**.
Separate exact library admission probes pass **2/2**, retaining unnamed-builtin
and fs/net/process denial controls. The committed library and Buffer-test bytes
match those executions. This closes only `bd-9vouw.166`'s original canonical
alias-admission acceptance. It does not close the red full selection, CI,
compile-wall or performance tasks. The full unchanged Promise matrix has not
yet run on the new source cut.

Global formatting remains red from inherited drift. Comparative performance
qualification remains unresolved, with **0/100 optimization passes**. No new
speedup is claimed from these correctness and build-ownership repairs.

### Fresh observations

| Probe and denominator | Result | Interpretation |
|---|---|---|
| Nine preselected release programs, each beside Node v26.8.1 and Bun 1.4.0 | 9/9 console outputs equal; all 27 runtime invocations exit 0 | Arithmetic/numeric edges, callbacks, descriptors, inheritance, Promise ordering, exceptions, RegExp and typed-array examples work on these inputs. No full-language or performance claim. |
| Existing real-binary README regression target | 6/6 pass, including two real eight-step workflows and five injected failure classes | Bounded compile/verify/run/replay workflow plus clock, command, artifact and lost-event rejection. Injection tests establish wrapper behavior. |
| Direct strict replay of this refresh's arithmetic run report | Exit 0, `replay_kind=reexecution`, IR3/content/randomness/decision matches | Reexecutes the actual run report; its nondeterminism event count is zero, so this alone does not establish host-effect replay. |
| Change that run report's recorded console result from 42 to 43 | Exit 2, unsigned execution-content divergence | Concrete outcome corruption is rejected; an external origin trust anchor is a separate question. |
| Claim matrix `ci` / `release` | Exit 0 / exit 1 | Wording passes; **13/13 OBSERVED rows are provisional**, with source/environment drift. The report's `verdict=pass` is not the final release process verdict. |
| Formal claim promotion | Exit 0; `STAY_HYPOTHESIS`, 0/6 qualifying bundles | Correct refusal to promote FE-CLAIM-016 through 021; no theorem-backed compiler was demonstrated. |
| Pinned `cargo fmt --check` on the working tree | Exit 1; 2,001 diff sections, 1,746,874 log bytes | Repository formatting gate is red. Sections are not files or distinct defects; no mass formatter rewrite was attempted. |
| Clean-base RCH `cargo check --all-targets` | Terminal exit 101; E0308 at `baseline_interpreter/reflect_invocation.rs:1704` | Engine lib-test fixture supplies `Box<Value>` where `Arc<Value>` is required. Exact committed main, excluding the two pre-existing runtime edits; this is not a claim that every production target fails. |
| Clean-base RCH extension-host `environment_snapshot` test target | Terminal exit 0; 3 passed, 0 failed, 0 ignored, 0 filtered | Actual provider code tested with supplied snapshot maps: capability denial, absent/empty values, redaction, bounds and cancellation. No live OS environment or whole-engine inference. |
| Authoritative JSONL census before / after refinement | 5,091 unique issues; closed 3,934 / 3,931; open 665 / 668; in progress 437, blocked 45, deferred 10 unchanged | Three existing scientific-report records reopened. Counts describe work state, not delivered capability. `br stats` dependency-blocked/ready counts have different meanings. |
| All active BRIDGE records | 459; none with empty description, missing referenced issue, or absent acceptance text | Structural coverage only. This does not establish logical sufficiency or execution of every acceptance requirement. |
| Active dependency cycles | `br --no-db dep cycles --json`: 0 | Three archived closed cycles are separately reported and preserved. |
| `bv` triage, insights and forecast | All exit 0, but displayed census is 5,030 versus authoritative 5,091; cycle computation explicitly skipped above 2,000 nodes | Treat its recommendations as a partial view and use canonical JSONL/`br` for coverage and cycles. Forecast confidence averages about 0.45; its dates are not a delivery promise. |

### 2026-10-24: current-source application measurements and first repair

The observations above retain their 2026-10-23 source scope. New measurements
use production source `fa5723220dd29fd54a3da8ee3df14ba69df28a86`, pinned
`nightly-2026-09-21`, `release-perf` (opt3, thin LTO, one codegen unit, line
tables, no stripping) and frame pointers. The Linux x86-64 ELF SHA256 is
`6cc7565fc3df10caf53ddd00190963157a6c47c738451abb8b13be89b95348e3`.
The build's remote Cargo process exited 0, but its original RCH artifact
retrieval exited 102 because a Linux executable was intentionally built from a
Mac controller without declaring foreign-artifact retrieval. Recovery recorded
that terminal failure; the retained ELF was verified and executed on Linux.
This is not a passing artifact-retrieval gate. Main `410d46459` subsequently
committed the one-line Reflect test-fixture Arc repair; its production code is
identical to this measured baseline.

On the same quiet `ovh-b` worker (hostname `yto`), the actual incumbent was
Node **26.8.1**, V8 **14.6.202.34-node.28**. Four fixed tasks use real Lodash
4.17.21, Marked 15.0.12, Acorn 8.15.0 and a TypeScript orders pipeline. Each
runtime has **120 measured executions per task**, split into 60 identical A/A
arms, plus three warmups per runtime per measurement window. All 960 measured
executions preserve frozen console hashes; native runs also preserve guest
instruction counts, IR3 hashes and the allow outcome. Marked checks full HTML;
Acorn checks the full AST. The initial 20-per-arm window failed the unchanged
10% p95 noise gate on Node's TS task. Adding 40 per arm to **every task**, while
retaining all original samples, passed; worst final drift is **2.203%**. No
competing heavy processes were observed.

| Task | Native p50 / p95 | Node p50 / p95 | Native / Node p50 |
|---|---|---|---|
| Lodash aggregation, 5,000 records | 981.7 / 1,015.5 ms | 70.9 / 83.5 ms | 13.845x |
| Marked rendering, 50 sections x 10 | 4,101.9 / 4,189.4 ms | 117.1 / 127.9 ms | 35.043x |
| Acorn parsing, 100 functions | 2,374.2 / 2,423.3 ms | 76.1 / 87.2 ms | 31.196x |
| TS orders, 5,000 records | 229.7 / 240.9 ms | 111.2 / 127.8 ms | 2.066x |

These are **end-to-end CLI costs**, including startup, parsing/lowering,
security accounting and report serialization. They do not isolate VM/JIT
throughput, demonstrate general TS compatibility or qualify the program's
security/performance targets. TS executes with type erasure, without a type
checker. Peak native RSS across these samples is 143.7/149.1/145.1/56.0 MiB
respectively; Node is 60.9/59.0/57.4/75.2 MiB. The short sample series does not
support a precise extreme-tail claim.

Three separate all-thread hardware-cycle captures per task identify current
costs. Percentages below describe sampled CPU; inclusive entries overlap.

| Task | Current attribution | First implication |
|---|---|---|
| Lodash | Runtime execution 49.55–50.05% inclusive; lowering 18.38–19.14%; parsing 15.98–16.41%. `released_frame_cell_payload_bytes` alone is 11.84–14.10% self; SHA-256 is 8.09–8.99% self. | Repeated return-time accounting is a measured target; frontend startup and evidence work also matter. |
| Marked | Runtime execution 96.09–96.20% inclusive; dispatch 9.97–11.51% self; labeled register writes 3.83–4.66%; regex search 3.04–3.36%. | The runtime's distributed dispatch, value and security work dominates this task; startup-only work cannot close this gap. |
| Acorn | Runtime execution 85.55–85.72% inclusive; dispatch 13.10–14.97% self; labeled register writes 2.82–3.26%; SHA-256 2.79–3.09%. | Interpreter execution is the main measured phase, with smaller frontend and evidence costs. |
| TS orders | Runtime execution 95.97–96.07% inclusive; dispatch 5.56–8.77% self with property, value and evidence helpers distributed below it. | This short profile supports a phase-level conclusion; individual helper estimates are noisy. |

Native median process CPU/wall ratios are 0.988/0.997/0.995/0.946 core. Separate
syscall summaries, allocator totals and Node CPU/heap samples retain matching
outputs. They support investigating CPU work first; they do not establish
native allocation callsite or complete off-CPU attribution. Raw evidence is
under `artifacts/optimization-100x-ss6_54xg/`, including
`baseline60-combined.summary.json`, `ovh-b-baseline60-runs/` and
`ovh-b-current-profiles/`. Inline DWARF expansion made inclusive reporting
pathologically slow; the owned analysis child was stopped, preserving traces,
and bounded `--no-inline` analysis plus the remaining captures finished through
a new strict RCH job with exit 0. The stopped job remains exit 1.

An additional current-baseline correctness run executes all nine repository
macro programs: JSON roundtrip, matrix multiplication, object graphs, prime
sieve, recursive Fibonacci, regex matching, sorting, string scanning and tree
traversal. All nine console outputs match live Node and the frozen Node/Bun
references; input hashes match the original case manifest. Its RCH job exits 0.
This single-run check contributes no timing ratio or candidate qualification.

The first optimization candidate reuses `ColdBindingCells::holds_frame` to skip
maps whose cells are already retained and charged. The existing full-walk path
already uses this shortcut. Three new tests cover identity/COW/last-capture
transitions, saturation and ordinary/derived/async/throwing returns. Independent
Node/Bun reference reexecution and changed-range formatting pass. Native
verification has now advanced to **40 passing selected tests** on source
`735e29cc7441ed26df8375209be678d93812064f` plus the sole `lib.rs` overlay
`3603e8e7275f3fc23bddc82a8c5af608f52fd5426c71baac69e9923a4b83efbb`.
Commit `07025731194b72952eb5fcbff0459694668ac7a2` contains exactly that final
test correction; both pre-existing dirty runtime files were excluded.

The selected denominator is 19 unit tests plus 21 public integration tests:
all 16 shared-binding accounting tests, the Reflect accessor-label regression,
two builtin-authority tests, eight Buffer tests, eight environment-hostcall
tests and five existing scaling tests. Strict RCH confirms remote exit 0 and
terminal acknowledgement. These runs use pinned nightly/default features with
debug symbols omitted; debug assertions and overflow checks explicitly remain
enabled. Supplied environment providers establish capability/IFC/replay behavior,
not a live external-service result. This selection does not replace the separate
stream-consumer/timer qualification or the full workspace suite.

The Buffer tests exercise the public alias repair (`bd-9vouw.166`) across
HybridRouter, both native lanes and repeated prepared execution. Three Buffer
alias forms previously failed; Object, Reflect and Math already worked and
receive no new capability credit. Explicit authority negatives preserve filesystem,
network, environment, process, module and randomness denials. The original
authority-test attempt was 18/19, because its expected environment denial used
the raw operation name. The correction names canonical denial identities
explicitly and adds `env:has`; no production gate or assertion was weakened.

Existing debug scaling from 250 to 2,000 operations passes its unchanged 24x
bound: closures 1.6x, generators 2.6x, await 3.9x, async reactions 3.1x and timers
7.9x. Timers remain slow in this debug configuration but scale linearly here.
These results do **not** establish the original `.31` requirement at
100/200/400/800 with at most 2.3x per doubling against the closure-free twin.
That stricter acceptance and production old/new/live-Node qualification remain
unrun. **0/100 optimization passes are qualified; no candidate speedup has
passed the full comparative acceptance.**

The frozen production candidate `13392082920f4ae4dbfd375c29f1684a00987c57`
has now compiled successfully under the same pinned release configuration.
Its 147,533,432-byte ELF, SHA256
`2888e3001625f2b400d61f22f6006ee88aff7e4f4504287c42fb11cfdf1fd8d8`,
is retained on workers. Original Cargo JSON and exact-job recovery confirm
compiler exit 0; RCH's foreign-artifact delivery refusal remains exit 102.
A direct private Tailscale transfer placed the hash-matching candidate beside
the baseline and Node on `ovh-b`; no binary bytes passed through the Mac.
All 13 candidate/live-Node correctness checks and 26 candidate strict replays
passed. Two subsequent three-runtime measurement attempts stopped at the frozen
CPU observer after 450 and 336 measured samples. Every sample is retained; neither
attempt qualifies a speed result. The completed Lodash portion of the first
attempt has 120 samples per runtime and passing noise checks, with old/candidate
medians of 982.7/840.0 ms. This is diagnostic evidence from a refused whole
attempt; the remaining regression, memory and replay gates were not completed.

Live detector controls subsequently demonstrated a temporal defect in that
observer's lifetime CPU percentages: it refused an idle-after-burst process
and admitted a busy-after-idle process. A separate observer version uses a
bracketed one-second aggregate accounted-CPU window, the same 80%-of-one-core
threshold and all eight categorical compiler exclusions. Independent review
and execution passed 24 unchanged protocol tests, 11 detector tests and five
unsafe-mutation controls. Fresh live controls admitted both idle cases
(45.43%/45.24% upper accounted-counter estimates) and refused the busy case
(129.97%, with its child consuming 99.65% of one core). The six-tick allowance
covers integer conversion only; pending kernel accounting and future contention
remain outside this finite observation. This correction preserves every case,
sample count, noise, regression, RSS and replay gate. It does not reclassify
earlier refusals or reuse their measurements. The wholly fresh comparison
refused before measured workloads: 167 busy ticks, including 115 system ticks,
over a 1.01453-second lower interval gave a 170.52% upper accounted-counter
estimate. No compiler category was present. This remains a refusal with zero
measured rows; a bounded attribution diagnostic is queued, and no speedup is
qualified.

Earlier all-target check and Clippy both passed under the pinned toolchain,
default profile and default features. That successful check on `ts1` took 23m13s,
with strict remote exit 0 and terminal acknowledgement. The earlier `hz3` timeout
recovered as 137, the redundant `hz4` run ended 143 following a cancellation
request, and the `trj` retry recovered 255; those remain non-passes. The full
formatting gate stays red (2,001 sections across 229 files), and full workspace
tests remain unrun after transport failures.

An additional 72 parser-oracle module tests passed on the retained native test
binary, including the real-file→parser→critical-drift→Reject regression. An
independent verifier reran all 72, checked the executable hash before/after and
closed only `bd-nrfpu` against its original criteria. Five actual CLI controls
also passed: a valid parse promotes, matching errors with an expected success
hash reject, a wrong success hash rejects, mixed catalogs retain the failing
denominator, and invalid schemas produce no success report. The parent's first
CLI probe was 4/5 because its malformed-schema exit expectation was wrong;
the exact CLI error exit was corrected to 2 and every original run was retained.
The verifier's extra CLI reexecution stopped before execution and stays unrun;
closure rests on the independently executed original Rust E2E and source
inspection. These are **112 distinct selected native tests**, plus five CLI
controls; the independent repeated 72 do not add unique coverage. No broad
conformance or concurrent file-swap experiment is claimed.

The broader engine library run compiled and began 46,163 tests. It recorded
3,104 passing and 22 failing tests before an expensive Promise case stopped
making visible progress. A read-only GDB capture found repeated full memory
accounting walks during async unwind. The owned run was cancelled and recovered
as 143 with terminal acknowledgement; it has no completed full-suite verdict.
An independent fail-alone reproduction confirms the frozen-array error-type
assertion fails on the identical native executable. Public old/candidate/Node
probes agree on frozen-array state and ordinary sparse reduction; native JSON
depth behavior differs from Node. These observations do not resolve every unit
failure or establish a new accounting regression.

Accounting maintenance deduplicates immutable frame-map identities in
the reference payload walk while retaining global cell deduplication and every
existing debug assertion. Its new test compares the original cell-only walk,
including COW, distinct cells, corrupted ledger metadata and borrow saturation.
All 17 selected accounting tests passed on frozen revision
`a68422e25e516dd2167a3bc721eac8b93a53ed78`; broader validation remains incomplete.
Independent reproduction of a legacy ClientRequest failure found
`CapabilityDenied(net:request)` before egress. Eight explicit network grants now
restore the intended body/response/IFC fixtures without changing their assertions,
shared defaults or production gates. A new two-case test checks withheld and
revoked authority before mutation or provider entry. Independent source review
found no blocker; this is fixture maintenance and a lower-level `.end()` control,
not a newly proved public JavaScript network path. The frozen run passed 25 of
31 selected tests. Its six actual failures exposed stale fixture expectations:
HTTP task labels require the stronger Internal floor; a denied Secret receiver
requires an evidence sink; JSON depth and frozen pop materialize actual guest
RangeError/TypeError objects; sparse reduction's shared ceiling counts both
instructions and native hole reads. Corrections preserve the typed raw JSON
fault, frozen-array state/memory reference, budget32 and all four sparse modes,
and add exact shared32-admit/33-refuse and writable-pop controls.

The corrected four-file source cut
`845aa7fcc3b26cd6def8b87174115ba4b11de3e5f3116fd67b63255340803991`
over `070257311` passes pinned all-target check (isolated target, 25m00s) and
strict Clippy, both with terminal acknowledgement. An earlier pooled check
failed E0463 at `scheduler_lane_integration.rs:29`; its cause is unproved and
the failure remains recorded. The new selected native run includes the
unchanged 864-case Promise matrix across both lanes and both GC modes and is
still compiling. It has no test verdict yet. The earlier test ELF was reaped
before independent repetition; the new worker runner retains its actual ELF
before execution so that re-verification can use identical bytes.

The revised original Buffer target separately passed all eight tests, including
the exact Object alias `.join()` example and four actual/captured shadow reads.
Its same-coverage all-target check and Clippy passed, as did whole-file formatting.
These repeated eight tests do not increase the distinct-test denominator above.
The required UBS scan reports identical findings on the original and revised
file: one critical on its unchanged intentional test-helper `panic!`, fourteen
warnings and five informational findings. A scoped commit exception is pending;
the helper and scanner remain unchanged. Full workspace testing and inherited
formatting failures remain unresolved.
Raw logs are retained in `artifacts/optimization-100x-ss6_54xg/` as
`current-native-accounting-tests.log`,
`current-native-public-integration-tests.log`,
`current-native-all-targets-clippy.log`, `current-native-all-targets-check-ts1.log`,
`parser-oracle-independent-unit-tests.log`,
`current-native-parser-oracle-acceptance-corrected.log` and
`current-native-check-recovery.json`.
The owner authorized scoped worker-only validation and affirmed the proposed
worker-only candidate build/comparison despite the Mac's failing disk preflight.
During these scoped lanes, compiler outputs stayed on workers; no local
compilation, manual cleanup or global policy change was used. Both implementation
beads remain in progress.

### Numbered vision checklist and bridge ownership

`WORKING` below applies only to the named released probes. `PARTIAL` identifies
real mechanisms with missing breadth/integration; `UNPROVEN` means the required
outcome was not established. A bounded stub is named explicitly, without calling
the whole engine a stub. BRIDGE numbers refer to the existing
`bd-performance-conformance-bridge-tu32j` graph; suffixes are recorded in the
previous table and current tracker, not new parallel workstreams.

| # | Testable promise and authority | Reality and implementing seam | Existing route to the required outcome |
|---|---|---|---|
| 1 | Native core ownership, plan 4/8 | PARTIAL overall; real Rust parser/lowering/interpreter and bounded released execution; inspected core has no binding-led JS backend | BRIDGE-01/13/14/15/17; preserve single canonical semantics and exact downstream consumer |
| 2 | Complete ES2020, plan 9A/17/18.9–10 | PARTIAL; `test262_harness` line-parses metadata; `test262_conformance_runner::execute_test` skips assertion/includes/phase/constructor validation | BRIDGE-12, `bd-9vouw.4/.17`, then 13–17; HARNESS-ORACLE and exact full variant manifest before any semantic percentage |
| 3 | JS/TS normalization and modules, plan 8.7/10.4 | PARTIAL; real lowering/resolver/import execution, restricted eval and incomplete ecosystem contract | BRIDGE-14/17/22, `bd-7fhp3`, `bd-305gi`; execute packages through public and orchestrated entrypoints with namespace/policy/cycle negatives |
| 4 | Core ownership without duplicated semantics, plan 18.2 | PARTIAL; engine and extracted core coexist; ownership/cutover is not proved by both compiling | BRIDGE-01; assign each core family and require parity at its actual cutover |
| 5 | Fast generated interpreter, plan 18.4 | PARTIAL; `CompactTier1Program` creates real compact cells, unsupported cells retain baseline dispatch, orchestrator actually supplies the plan | BRIDGE-03/04; exact effects/labels/budgets/fallback plus workload-weighted measurement |
| 6 | Executable JIT/AOT with exact deopt, plan 18.4 | PARTIAL foundation, general tiers undelivered; `native_capsule_fixed_probe` is opt-in non-JS u64 code; `aot_entrygraph_compiler` explicitly simulates planning | BRIDGE-05–08; actual bytes/disassembly/dispatch/GC/OSR/deopt evidence, not input-derived identities |
| 7 | Safe native trust boundary, plan 18.2/ADR-0010 | PARTIAL; signed acceptance record unresolved. Owner already said “Approve now” on 2026-09-22 (`bd-9vouw.11`); JSON remains proposed | Complete the existing externally anchored acceptance procedure or owner-approved amendment; never ask the same architecture question or forge a signature |
| 8 | Compact values, exact objects, GC and resource tails, plan 18.5/10.3 | PARTIAL; native runtime mechanisms and compact paths exist; representation/GC/tail contracts remain unqualified here | BRIDGE-03/04/13/15/17; descriptor/order/proxy/weak-root/forced-GC and cancellation coverage before fast-path promotion |
| 9 | >=3x secure transactions versus both incumbents, plan 14 | UNPROVEN; historical June ratios are dirty/asymmetric/unweighted and correctness-lock-only | BRIDGE-02/19; freeze five families × S/M/L, equal-work lifecycle, raw samples, weights, p99/RSS and equivalence; do not reuse a self-speedup as the win |
| 10 | Hardware specialization and high-core scaling, plan 18.7 | UNPROVEN here; architecture/planning machinery is not a native-tier or scaling result | BRIDGE-10/11; named hardware, generic fallback, per-cell scaling/overload and NUMA/PMU evidence |
| 11 | Capability/IFC and static authority intake, plan 6.9/8.7 | PARTIAL; real capability, flow-policy and inference code; all ambient constructs and arbitrary-program noninterference remain unproved | `bd-7fhp3`, BRIDGE-09/13/14/17; source-to-sink positives and adversarial aliases/getters/async/exception labels |
| 12 | Real guest effects with least authority, plan 10.5 and host-I/O plan | PARTIAL; orchestrator installs HostIo/process/timer seams; default refusal and provider existence are not end-to-end host service proof | Existing host-I/O / `bd-305gi` and BRIDGE-17/25 owners; real sandboxed effect, denied escape, cancellation, journal commit and replay |
| 13 | Signed evidence and deterministic incident/counterfactual replay, plan 8.6/11 | WORKING bounded release reexecution/corruption probes; PARTIAL full current-source qualification. `evidence_ledger` has real signing/chain primitives | BRIDGE-18/19/21 and current signing/replay owners; effect-bearing traces, durable trust roots, rotation, failure prefixes and independent challenge |
| 14 | Probabilistic defense with >=10x compromise suppression, plan 3/6 | PARTIAL mechanisms, comparative result UNPROVEN; posterior/expected-loss actioning and v2 campaign machinery do not equal a current linked real campaign | `bd-0lim8`, BRIDGE-09/18/21; ten real scenarios × pinned three runtimes × 100 repetitions, scoped replay/verdict and benign false-positive countermetric |
| 15 | <=250ms effective containment, plan 3/13 | UNPROVEN; action selection is not observation that the effect stopped | `bd-pgzo7`, BRIDGE-09/21; timestamp signal and actual prevented/completed effect under declared load, retain benign controls |
| 16 | Fleet immunity, revocation/fork resistance and anti-entropy, plan 9F/10.11/13 | PARTIAL primitives; fleet `ci` validates contracts/references without running a topology or retaining measured percentiles | BRIDGE-23 and BRIDGE-21.31; real signed multi-host fault/partition/replay campaign with durable freshness and measured tails |
| 17 | >=95% hardware-attested receipts, plan 13 | STUB at real SDK seam: `tee-real-sdk` returns typed failure; default explicitly returns simulated quotes | BRIDGE-24 and BRIDGE-21.32; genuine quote/collateral/nonce/key/image binding, expiry/revocation negatives and deployment denominator |
| 18 | Formal policy/compiler and proof-guided default optimization, plan 9C/9F/13 | UNPROVEN; Z3/Lean/helper components are not a product-driven end-to-end proof; fresh gate finds 0/6 qualifying bundles | Existing formal tracks plus BRIDGE-09/18/21; actual transform/witness consumer, invalidation and exact fallback; closed helper beads do not promote claims |
| 19 | Durable sibling persistence and integration, plan 8.4–5/10.14 | PARTIAL qualification; real SQLModel/FrankenConnection seam and default feature families. Manifest presence is not crash/durability proof | BRIDGE-21/25, `bd-9vouw.3`; default/standalone/all-feature builds, durable reopen/recovery and exact downstream contract |
| 20 | React/FRX, Wasm, Intl and exposed CLI preservation, README feature sections | PARTIAL, not comprehensively executed here; distinct entrypoints and compile/fallback contracts must retain their own proof | BRIDGE-25/26 and their verification packs; positive shipped workflows, typed blocked paths and cross-mode/platform regressions |
| 21 | Production PLAS metrics, plan 13 | UNPROVEN deployment outcome: >=90% cohort coverage, <=1.10 over-privilege, >=70% authoring-time reduction and <=0.5% false deny | `bd-11ua` and existing PLAS tracks; real cohorts and independently derived required authority, receipts, escrow/expiry and burn-in |
| 22 | Continuous private fleet learning and improved reputation, plan 13 | UNPROVEN production outcome; secure aggregation/privacy/reputation components alone cannot establish it | `bd-1rju` and children, `bd-twz2`; budget durability/composition failure, signed snapshot rollback, local-only comparator and measured compromise window |
| 23 | Autonomous operations and portfolio control, plan 9I/13 | PARTIAL; shadow proof state explicitly remains advisory-only even though historical adoption gates are green | Existing shadow/governor and BRIDGE-25 owners; separately authorized promotion, real lifecycle/fault/burn-in and signed decisions; this audit enables no mutations |
| 24 | Three production differentiators, practical franken_node and GA, plan 3/9D–E/13 | UNPROVEN full exit; fixture-only demos are labeled, feature #3 depends on unproved comparative security; v0.3.0 issue #6 remains open | `bd-three-feature-floor-owner-2fjbh`, `bd-15w28`, BRIDGE-25; immutable candidate, all workload-dependent gates, install/upgrade/recovery and real product use |
| 25 | Four reproducible scientific reports, two independent reproductions and external standard adoption, plan 13/16 | UNPROVEN here; renderer/catalog closure did not establish four actual report bundles; internal reruns do not supply independence or adoption | Restored `bd-2501.1` and aggregates; existing BRIDGE-21.25 verification now depends on it. BRIDGE-19.5/.19.17 retain external replication/adoption; require actual returned artifacts, maintained external use and honest negative outcomes |

### Bridge plan: preserve ambition, order work by decisive evidence

1. **Restore a qualified current source cut.** `bd-9vouw.3`, `bd-15w28` and
   `bd-9vouw.15` own the build/regression/compile-wall boundary. Retain failed
   gates and exact source/feature/toolchain identities. Exit only with the
   required compiler/lint/format/default tests and downstream release-regression
   checks, including failed-run/cancellation/evidence behavior. The release
   binary's 9/9 examples cannot close this step. Complexity: large validation
   and defect repair; depends on legitimately admitted capacity.
2. **Finish G0 while retaining separate measurement axes.** BRIDGE-12 owns YAML,
   includes, strict/module/async variants, negative phases/constructors, $262,
   exact ES2020 selection and reference-runner agreement; `.13.8` owns the full
   canonical Tier-R baseline. BRIDGE-02 independently owns cold/warm/steady and
   production-security cost decomposition. Exit with reconciled terminal counts,
   complete pass/fail sets, seeded harness-rule failures and raw comparable
   measurements. Corrected runner observations then order semantic work; no
   old percentage is relabeled. Complexity: large; no native capsule needed.
3. **Deliver shared-semantics vertical execution slices.** BRIDGE-01/03/04
   establishes ownership, compact runtime and exact fallback; BRIDGE-05–08 then
   carries the twelve-opcode slice and useful package through real native
   dispatch, guarded optimization, deopt and AOT. Existing BRIDGE-21 test packs
   challenge every tier's effects, exception points, labels, budgets, roots and
   rollback. Keep the approved architecture intent, complete its actual signed
   record, and preserve the unsafe boundary. Complexity: very large; governed
   native execution depends on the existing acceptance prerequisites.
4. **Measure security and fleet/hardware outcomes through real effects.** The
   comparison/containment owners and BRIDGE-23/24 retain real comparator,
   benign-control, partition, replay and attestation tests. Runtime primitives,
   contract green and lab fixtures cannot satisfy deployment exits. Profile
   security-check elision only after its exact soundness prerequisites pass.
   Complexity: large, with explicit hardware/deployment prerequisites.
5. **Qualify the full consumer and obtain external outcomes.** BRIDGE-19/25/26,
   PLAS/privacy/reputation/shadow owners preserve all existing surfaces and
   produce immutable released-consumer evidence. Test install, upgrade, crash,
   recovery, signing-key transitions, unsupported modes and rollback. Two
   independent reproductions, external standard adoption and production cohort
   metrics remain real-world outcomes, not agent-generated certificates.

Before refinement, completing the active work was insufficient to establish
every audited outcome: no active description/acceptance owned the Section-16
four-report delivery requirement. The closed `bd-2501.1` cited a technical report
renderer, its closed aggregate `bd-2501` cited a scorecard/registry, and the
catalog lists candidate operator documents and `<timestamp>` paths. The existing
scientific-contribution readiness consumer checks closed beads, document
existence and declared command/path strings (`run_scientific_contribution_targets.sh:247–286`),
not four actual reproduced report packages. That is a concrete risk of
**proof-class inflation**; the catalog companion itself cautions that it does
not establish four publishable reports.

Reopened `bd-2501.1`, `bd-2501` and `bd-esst` instead of creating duplicate
epics. The report leaf now carries detailed delivery, real-result, source/input,
reproduction and negative-control requirements in an additive comment. Its
existing BRIDGE-21.25 verification companion receives the independent report
challenge and a blocking dependency on the report outcome. Original assignees
and historical implementation are preserved. A supported negative result can
form a scientific report; it cannot promote a losing benchmark to a win.
The leaf's preclosure producer-distinct challenge and the verification pack's
subsequent immutable-handoff rerun are separate phases: the leaf does not wait
for completion of the pack that depends on it. This retains independent
challenge without introducing a mutual closure wait.

The PLAS owner `bd-11ua` already explicitly requires all four KPI denominators,
so consolidated closed leaves for authoring time, over-privilege and false
denial did not justify another task. Its evidence comment now makes those
retained obligations explicit. The precise IFC prose defect belongs to the
already active `bd-9vouw.10` owner. After this correction, the active contracts
cover the audited goal groups on paper. Actually meeting them, including
production, hardware and external outcomes, is still required; closing their
records is insufficient.

### Ambition and five refinement passes

The skill's frozen bead-generation and refinement instructions were applied to
the existing graph; no source functionality or target was removed. Three
ambition passes tested (1) whether a released bounded workflow could grow through
G0 into a representative package, (2) whether one semantics contract could carry
Tier I/native/deopt/security instead of disconnected models, and (3) whether
security-proof specialization and hardware scaling could improve the full
equal-work frontier without lowering safety or the >=3x/10x/250ms/full-ES2020
exits. These are refinements of the adopted Section 18 program, not additional
capability claims or unmeasured optimization recommendations.

Five refinement passes checked:

1. **Coverage:** all 28 claim rows and the plan's success-criterion families were
   mapped to the checklist; active bridge records have descriptions, acceptance
   text and resolvable dependencies. Closed proof-helper and score-gate owners
   were not mistaken for completed outcomes.
2. **Dependency/ownership:** `br` reports no active cycles; canonical Tier-R
   baseline prerequisites and existing BRIDGE-21 verification companions remain
   explicit. The earlier native owner approval was recovered from its actual
   bead rather than requested again.
3. **Positive and negative proof:** reran real release workflows and console
   comparisons, direct replay and actual corruption; inspected current runner,
   real TEE refusal, compact dispatch, evidence signing and storage seams. Keyword
   and AST checks on selected suspicious files found no `todo!` implementation;
   policy-only/constant-output behavior still required behavioral inspection.
4. **Failure, deployment and claim boundaries:** separated release/current main,
   harness/runtime, hash coherence/authenticity, execution coverage/conformance,
   contract/fleet measurements and simulated/hardware quotes. Found the README's
   stale IFC precedence and corrected its three numbered lines and hostcall
   diagram to match `ifc_artifacts.rs:723` and the formal security model. The deeper closed-owner
   check found the four-report active-coverage gap; it was restored in the
   existing leaf/aggregates with a real verification dependency.
5. **Convergence:** reviewed the revised route against the existing independent
   verification, release, external-reproduction and adoption leaves. No further
   distinct backlog addition was supported by this bounded review. Remaining
   outcomes stay open; the graph was not simplified to manufacture readiness.

Changes in this refresh are documentation, nine evidence/refinement comments
(plus the three automatic reopening-reason comments), reopening the
three scientific-report outcome/aggregate records, and one verification
dependency. No runtime source, threshold, waiver, golden, claim state or assignee
is changed. The shared tracker cache is schema 17 while `br` requires 19; even
the attempted `--no-db` mutation correctly refused. Mutations used a new
isolated cache imported from all 5,091 authoritative JSONL rows and published
only through `br`, with a byte-freshness guard and semantic delta review. The
guarded shared database, WAL, WAL certificate and migration state are unchanged.
This is solo reexecution and review, not independent verification.

### Final qualification and actionable handoff

The all-target check ran on the pinned toolchain through strict RCH build
`30078269650894870` on `hz3`, with a clean checkout of the exact inspected
revision. RCH acknowledged exit 101 after 2,405,349 ms. The failure is the
accessor fixture type mismatch described above, retained in
`cargo-check-head.log` and on the existing `bd-9vouw.3` owner. Repair its actual
ownership/type seam, then repeat the unchanged all-target check and full gates;
this audit changed no Rust source. The separate snapshot-provider target on
`trj` completed with native exit 0 and retrieval acknowledgement at the same
base; `environment-snapshot-native.log` retains its 3/3 result.

The README's corrected policy prose and diagram passed the unmodified claim
matrix CI wording gate again. Release qualification still fails for all 13
provisional OBSERVED claims; no claim state, freshness window or evidence receipt
was promoted. Exact-base GitHub Actions lookup returned zero runs, so no fresh
green-main CI result is claimed. Full all-target Clippy, full default tests,
all-feature/standalone/downstream builds, exhaustive ES2020 variants, real
security/performance campaigns, live fleet/TEE and production/external acceptance
were not run here. The failed all-target compiler check and formatting gate stay
red. They are required next work, not waived because the released CLI works.
The precommit UBS invocation on the three changed documentation/tracker paths
returned exit 3, explicitly reporting no supported source language and nothing
scanned. It supplies no static-analysis pass; no no-scan override was used.

All 5,091 tracker identities, prior comments and assignees are retained. The
refinement changes nine existing records, reopens exactly three, adds exactly
one dependency and closes none. Final canonical `br` cycle validation reports
zero active cycles; three archived closed cycles remain separate. Final `bv`
triage still reads only 5,030 records and cannot certify this full graph. The
next useful unit of work is a
qualified current-source cut, followed by the corrected G0 oracle and equal-work
measurement; further process documents alone do not advance those exits.

## Previous assessment — 2026-10-21 (retained with its original evidence scope)

This assessment supersedes the historical lane assessment retained below.
Its consumer is the project owner requesting an end-to-end reality check; it
gates whether current implementation, release, and evidence claims can be
treated as delivered. It addresses observed stale architectural assertions,
failed claim validation, and a zero-step green smoke. Retire it when a later
revision-bound assessment supersedes its findings; artifact deletion still
requires the owner's authorization. This is an audit, not capability work.

## Verdict and evidence boundary

**FrankenEngine is a substantial working native runtime with a published CLI,
but it has not delivered the complete program in the canonical plan.**
The principal unfinished outcomes are trustworthy full ES2020 measurement,
semantic completion, general executable JIT/AOT tiers, the weighted Node/Bun
performance target, comparable security campaigns, live containment/fleet/TEE
measurements, and production/external qualification. More planning records
cannot substitute for those outcomes.

Source inspected: main `c9b999eae2da6ae7415f00f06dae44d4b2f34c1d`, with existing
uncommitted interpreter and integration-test edits preserved. Fresh executable
probes below use the **published v0.2.0 binary**, not a build of that main
revision. Source findings, release observations, historical receipts, and
unexecuted tests are separate evidence classes throughout this assessment.

Read completely: root `AGENTS.md`, all 2,548 lines of `README.md`, both files
under `docs/plans/` including the 2,606-line canonical plan, and the
reality-check skill and its planning/gap-analysis references. Additional intake
and source inspection covered the runtime charter, security model, claim
matrix, architecture, split contract, donor semantics, execution, evidence,
storage, Test262, native capsule, and fleet/latency producers. The documentation
inventory contains 506 Markdown files under `docs/`; this is not a claim that
every specialist document or every test target was individually revalidated.
The suite-wide `/data/projects/AGENTS.md` path is absent locally; local ancestor
guidance was read, and a reachable worker's copy was consulted. That copy lacks
the two named reward-hacking/work-graph sections referenced by root guidance;
their rules supplied in root guidance remain binding.

## Fresh results

Local artifact root:
`artifacts/reality_check/20261022T0027-JZjolY/`.

| Check | Result | What it establishes |
|---|---|---|
| Published release lookup | v0.2.0, published 2026-10-04; Linux x64, macOS arm64, Windows x64 assets and checksum sidecars | Distribution exists; no fresh installation/upgrade qualification |
| macOS arm64 archive | SHA256 `c6524725336ea0c14214589ba8f117cd837e4e0322250adf2b2c0bfe081a2744` matches GitHub's asset digest; binary reports 0.2.0 | Exact released executable used for the probes |
| Nine small JS programs, each compared with Node and Bun | All nine console outputs match | Arithmetic and numeric edge cases, array callbacks, descriptors, class inheritance, Promise order, typed-array coercion, RegExp lookbehind, exception/finally behavior on these inputs |
| Compile -> verify -> run -> strict replay, invoked directly | Pass | A real bounded release workflow; pure arithmetic replay reports `reexecution`, matching IR3/content/decisions, and zero nondeterminism events |
| Corrupt the actual `hashes.parse_event_ir` field | Verify exits 25 with a hash mismatch | The verifier rejects this concrete integrity mutation |
| Change a recorded console message | Strict replay exits 2 with unsigned execution-content divergence | Replay rejects this outcome mutation; it does not establish an external origin trust anchor |
| Four-backend arithmetic oracle | FrankenEngine/core/Node/Bun semantic consensus | Selected-cohort comparison works for one case; timing buckets are not a benchmark |
| `check` over a `fetch` call | Reports `NetworkEgress` requirement | Static footprint inference on this supported source, not an executed network effect or arbitrary-program noninterference |
| README CLI smoke wrapper, original | **False green:** exit 0, `steps=[]`, empty `events.jsonl`, `status=pass`, `failure_count=0` | BSD `date +%s%3N` breaks arithmetic before per-step evidence is recorded; repair and negative verification below |
| Claim-to-proof matrix gate, original | **Fail**, 3/28 rows | FE-CLAIM-006/008/009 source spans no longer contain required text; bindings repaired below |
| Claim freshness | **13/13 OBSERVED rows provisional** | Current environment/source/time recertification is missing; not a finding that all thirteen implementations fail |
| Theorem promotion gate | Pass, `STAY_HYPOTHESIS`, **0/6 qualifying bundles** | Honest refusal to promote FE-CLAIM-016 through 021, not six proved claims |
| Test262 posture consistency | Pass, three provisional vectors | Cross-file posture agrees; no full-corpus conformance result |
| Existing claim-gate portability regressions | 3 tests pass | Positive and adversarial validator behavior; synthetic validator inputs are not runtime proof |
| Fleet convergence `ci` gate | Pass | SLO schema and harness source references only; no measured fleet percentile |
| Containment-latency gate without supplied measurements | Exit 2: missing live input | No latency result was fabricated |
| Active dependency cycles | Empty | Active graph passes this structural check; historical closed cycles are separate |

The claim report is
`artifacts/claim_to_proof_matrix_gate/20261022T002641Z/claim_to_proof_gate_report.json`.
The theorem decision is
`artifacts/fe_claim_016_021_promotion/20261022T002641Z/promotion_decision.json`.
The nine-case results are retained in `probe-results.json` and
`extra-probe-results.json` under the local artifact root, with per-command
stdout/stderr and run reports. An initial mutation added an unused top-level
JSON field and was accepted; it did not modify a verified field and is not
counted as a failed integrity check. The subsequent actual-hash mutation above
is the negative integrity test.

`sbh check --need 20G` returned 1/critical, with about 190.9 GB available but
only 4.78% container headroom against its dynamic threshold. Per ancestor
instructions, no heavy Cargo lane was started. Thus **fresh main check, clippy,
fmt, full tests, and main-binary execution are unverified here**. Existing
retained compilation/test attempts include SIGTERM exit 143, queue refusal,
and unconfirmed completion; none is counted as a passing main gate. No disk
cleanup or peer-process intervention was performed.

## Maintenance follow-through after the audit

Under `bd-9vouw.511`, the existing README smoke now uses explicitly required
Python3 monotonic milliseconds, validates clock values before arithmetic,
rejects clock failure/regression, and refuses to publish success unless the
exact eight expected step records have matching exits, valid durations and
artifact hashes. Failure to enter the workspace also stops that command.
The runtime executable, semantic outputs and artifact validation rules were
preserved. The new Python regression target requires a real supplied binary;
it never builds or substitutes a passing engine.

Observed admit/reject split:

| Input | Original | Repaired |
|---|---|---|
| Real v0.2.0 CLI on macOS | Exit 0 with eight arithmetic errors and zero recorded steps | Exit 0, eight validated steps and numeric durations, no stderr; system and Homebrew Bash both exercised |
| Clock process failure / malformed value / regressing value | No valid clock-failure handling | Each exits nonzero without a passing bundle |
| Compile process exits 17 | Not counted as a baseline test | Failed step records exit 17 and wrapper exits nonzero |
| Event emitter silently loses every record | Original finalizer accepts an empty list | Finalizer rejects missing step evidence |
| Actual compile hash corruption | Release verifier rejects | Rejection retained under the regression suite |

Six regression tests passed twice; final pre-commit artifacts are in
`artifacts/readme_cli_workflow_smoke_tests/real-binary-q2iaigls/`.
Clock/command/event injection is harness validation only, not runtime security
evidence. Bash syntax and `shellcheck -x` passed. UBS found no critical issues;
strict JSON decoding in tests intentionally raises on malformed evidence.
Follow-through on 2026-10-22 re-executed the six regressions against committed
revision `c8242627dd784d0fe8e27c22adbeba767d512a70` on both macOS arm64
and Linux x64. Each platform completed two eight-step positive workflows and
all five injected failure cases. Separate artifact inspection verified all
seven file hashes, the directory-path hash and three bundle content hashes
per positive workflow; strict replay completed. The official Linux v0.2.0
archive matches published SHA256
`5be29592ad68fd33900300b7234b5c118075683a0aa08a94d8f6282fd3d41311`.
The five staged source/support files were checked against committed bytes.
Bash syntax, shellcheck and UBS passed; UBS reports zero critical findings
and seven strict JSON-decoding warnings in tests. Evidence is retained under
`artifacts/reality_check/20261022T0027-JZjolY/linux-readme/`, including the
Linux raw test artifacts and macOS command logs. This satisfies the harness
bug's acceptance by explicitly labeled **solo re-execution**; `bd-9vouw.511`
is closed. Independent verification and fresh-main Rust qualification are
still absent. No runtime, security or performance claim is promoted.

The three claim spans were rebound to the existing qualified README text:
006 -> line 144, 008 -> line 2408, 009 -> line 150. No required substring,
claim state, freshness window, receipt or verifier was weakened or re-dated.
The unchanged gate now exits 0 in `ci` with zero span failures and the same
13 provisional claims; `release` still exits 1 for those stale claims.
Artifacts are under `claims-rebound-ci/20261022T004642Z/` and
`claims-rebound-release/20261022T004642Z/` in the local artifact root. The JSON
report's span/wording verdict is `pass` in both modes; release rejection is the
subsequent process freshness verdict. Consumers must not mistake that JSON
field alone for release authorization.

The README's outer-bundle authentication wording is corrected under the
existing docs-truth owner: this smoke calls its SHA-256 links `link_signature`
/ `signed_link`, but those are unkeyed content hashes, not Ed25519 manifest
authentication. Four README statements now distinguish those bindings from
runtime-signed inner evidence. All command strings and 2,548 lines are retained;
the six real-binary smoke regressions pass again on macOS. This is a user-facing
documentation correction, not implementation of outer-manifest signing.

## Vision-to-implementation and work coverage

Status is scoped: a released bounded example can work while the complete
vision remains partial or unproved. Matrix wording state is not a substitute
for this implementation assessment.

| Goal | Current reality | Existing execution owners / remaining exit |
|---|---|---|
| Native ownership and useful JS execution | **Working bounded surface.** Real parser/lowering/interpreter, CLI, modules, builtins and security machinery; nine release probes pass. No binding-led JS engine was found in the inspected core path. | `bd-9vouw.5`, canonical BRIDGE-13/14/15/16/17; ordinary-package and regression qualification remain required |
| Complete ES2020 semantics | **Partial, current rate unknown.** Historical `120/47,157` is a defective runner-system measurement. The authoritative runner still uses value comparison; harness frontmatter is line-parsed, negatives are simplified, and suite cases default to HybridRouter. | `bd-performance-conformance-bridge-tu32j.13` and `.13.8`; HARNESS-ORACLE before a corrected full selected corpus, then semantic DAG to zero unwaived failures |
| Honest performance denominator and >=3x secure transactions vs both incumbents | **Target unproved.** June ratios are historical dirty/asymmetric/unweighted observations, not current speed or the normative denominator. | BRIDGE-02/19 and `bd-y6v8s`; both raw JS and equivalent secure-transaction scoreboards, frozen cases/weights, repeated same-host baselines, tails/RSS/equivalence |
| Fast interpreter and executable optimized tiers | **Real partial Tier I; general JIT/AOT not delivered.** `CompactTier1Program` compiles actual compact dispatch cells, preserves source binding, and falls back per unsupported instruction. The optional capsule module compiles/activates only a fixed non-JavaScript u64 probe. `aot_entrygraph_compiler` explicitly emits input-derived planning identities. | BRIDGE-01/03/04/05/06/07/08; shared semantics, full dispatch evidence, backend bakeoff, ABI/OSR/deopt/GC maps, actual bytes and exact fallback |
| Capability/IFC control and non-exfiltration | **Real selected-edge mechanisms; broad contract partial.** Typed capabilities, label propagation, declassification and authority inference exist. Engine/core flow-policy APIs differ; finite invariant tests are not arbitrary-program proofs. | `bd-7fhp3`, BRIDGE-09, `bd-fqlfw.8`, `bd-0y3b6`, `bd-vw7s1`; full effect/provenance coverage and adversarial source-to-sink tests before check elision |
| Authenticated chained evidence and deterministic replay | **Real implementation, current qualification incomplete.** Runtime/lab signing authorities, chain binding and replay are present; release reexecution and targeted corruption rejection work. Do not repeat old descriptions of the implementation as only public-seed signing or unchained entries. | `bd-90u6o`, `bd-8yhg4`, `bd-mpu1z` remain open/in progress for complete acceptance and independent recertification, not proof that their old code defects necessarily persist |
| >=10x host-compromise reduction and <=250ms containment | **Unproved targets.** Decision code and exact v2 comparison machinery are not a linked current campaign verdict or effective-containment measurement. A completed benign program can still be affected by stopping-policy behavior under the open `bd-pgzo7` acceptance. | `bd-0lim8`, `bd-pgzo7`, BRIDGE-09.10; ten-scenario real comparator campaign, stability/replay repetitions, false-positive countermetric and measured signal-to-effective-action |
| Fleet immunity, revocation, repair and convergence SLOs | **Primitives and bounded tests exist; deployment outcome unproved.** Contract-only `ci` success is not real topology/partition/transport evidence. | BRIDGE-23, its independent verification leaves under BRIDGE-21, `bd-cixqu.2.5`; real signed multi-process/multi-host fault campaign and measured percentiles |
| Hardware-backed receipts | **Simulated/fail-closed seam.** `tee_live_quote` does not produce real hardware quotes through the unwired SDK path. Fixed native-code probes are unrelated to TEE attestation. | BRIDGE-24 and independent hardware verification; real AMD/Intel quote, collateral, nonce/key/image binding and expiry/revocation negatives |
| Formal policy/compiler and proof-specialized speedup | **Hypothesis, not delivered end to end.** Z3/bounded validators, proof helpers and Lean sources are components; current promotion gate finds zero qualifying bundles. | `bd-cixqu.7.17`, BRIDGE-09/18/21; non-fixture product transforms, executable proof consumer, invalidation/rollback and equivalent-work performance evidence |
| Sibling reuse and downstream product | **Real source integrations, partial qualification.** Storage uses SQLModel/FrankenConnection seams and feature gates; source existence does not prove durability/recovery. Engine/product dependency direction is explicit. | `bd-cixqu.13.3`, `bd-15w28`, `bd-9vouw.3`, BRIDGE-21/25; exact default/all-feature/standalone consumers, persistence failure recovery, product handoff and release gates |
| React/FRX, Wasm and exposed compatibility features | **Bounded/partial; no full compatibility claim.** Compile/fallback and separate runtime surfaces exist. They were source-inspected rather than comprehensively executed in this session. | `bd-cixqu.16`, BRIDGE-25.8/.25.9, BRIDGE-26; preserve shipped features and qualify unsupported/fallback modes explicitly |
| PLAS, fleet privacy, reputation and autonomous operations | **Components and advisory behavior; production outcomes unproved here.** Shadow proposals are not applied production mutations; secure-aggregation types alone do not prove continuous privacy-preserving fleet learning. | `bd-11ua`, `bd-1rju` and its active children, `bd-twz2`, existing PLAS/shadow tracks; real cohorts, budget durability, false-deny/over-privilege metrics, burn-in and authorized adoption |
| Three production differentiators, GA and external validation | **Not established.** Demo directories include fixture-only checks; two observed features do not meet a three-feature floor. No current complete GA package or two independent reruns was established. | `bd-three-feature-floor-owner-2fjbh`, BRIDGE-19.5/.19.17, BRIDGE-25 and independent BRIDGE-21 leaves; exact released artifacts, clean installation/upgrade/recovery and genuine external results |

The native architecture decision requires care: its machine-readable file still
says `proposed` / `implementation_authorized=false`, **but `bd-9vouw.11` records
the owner's 2026-09-22 “Approve now” instruction**. The remaining issue is the
accepted-record/signature procedure, not an unasked architecture preference.
Do not solicit the same approval again or forge an owner signature. The
off-by-default fixed probe is not permission to claim general production JIT.

## Bridge, ambition and refinement disposition

The canonical Section 18 and existing BRIDGE graph already cover the major
vision goals. Creating another broad epic or rewriting the spec would add
process without closing a capability gap. The bridge is:

1. **Restore trustworthy observation first.** Fix the zero-step green smoke;
   repair actual source-span bindings, preserve freshness/drift checks, rerun
   eligible producers, and restore a complete exact-revision Rust gate run.
   Owners: `bd-9vouw.511`, `.10`, `.3`, `bd-15w28`, BRIDGE-00.2 and `bd-pa12f`.
2. **Finish G0 and canonical ownership.** HARNESS-ORACLE, exact ES2020 manifest,
   complete variant/terminal accounting, and corrected full Tier-R results run
   beside decomposed performance measurements. Resolve the 42 core-family
   ownership dispositions and monolith integration protocol. Owners: BRIDGE-01,
   02 and 12. No old percentage is promoted during this work.
3. **Deliver the useful vertical execution slices.** Carry shared semantics
   through real compact Tier I, then the authorized capsule and twelve-opcode
   native slice, then a representative extension package. Require exact
   effects, exceptions, budgets, labels, replay and fallback before expanding
   codegen. Owners: BRIDGE-03 through 09 and Section 18.14 S1/S2/S3.
4. **Close broad semantics and measured security in parallel where independent.**
   Execute semantic-cluster campaigns, benign/adversarial containment,
   comparable Node/Bun attacks, real fleet partitions and real TEE hardware.
   Hardware absence stays unavailable; schema-only success earns no deployment
   credit. Owners: BRIDGE-13 through 18, 23, 24, `bd-0lim8`, `bd-pgzo7`.
5. **Qualify the actual product and external outcomes.** Preserve the shipped
   feature inventory, all build modes, durable state and replay across faults;
   then assemble the immutable GA candidate, installer/upgrade/rollback proof
   and independent reruns. Owners: BRIDGE-19/21/25/26. Publication remains a
   separate explicitly authorized action.

Ambition passes retained the full original goals, sharpened the vertical
shared-semantics/native path, and included proof-derived security cost removal
plus real high-core/hardware work. They did not lower the >=3x, >=10x,
<=250ms, full-conformance or external-reproduction targets. Research levers
remain the existing falsifiable portfolio; no new speculative subsystem was
needed to explain the observed blockers.

Four refinement passes checked goal coverage, dependency/ownership boundaries,
positive/negative verification, and release/operator failure semantics. They
corrected three tempting misclassifications: old conformance percentages as
current semantics, a fixed native probe as a general JIT, and the green smoke
as eight validated steps. The final review found no further distinct backlog
gap among the audited goals. This is a scoped coverage conclusion, not a proof
that every conceivable behavior is tracked.

**Would completing all existing beads finish the vision?** On paper, the broad
BRIDGE graph includes semantic, performance, security, production and external
exits. Actually satisfying those acceptance criteria would close the audited
gaps. Closing implementation/scaffold beads alone would not: hardware results,
independent reproduction, adoption and released-consumer evidence are outcomes
that cannot be obtained by marking tasks complete. The newly demonstrated
macOS zero-step green lacked an exact existing owner, so `bd-9vouw.511` was
created. Findings were appended to the existing docs-truth and BRIDGE-00.2
owners rather than duplicating the program.

Initial authoritative JSONL census: 5,090 unique issues — 3,933 closed,
669 open, 433 in progress, 45 blocked and 10 deferred. These counts are not a
capability-completion percentage. `bv --robot-triage` returned recommendations,
including canonical ownership and measurement prerequisites; its displayed
census differs from the direct JSONL census, so no merged completion statistic
is inferred. The root SQLite cache is schema 17 while installed `br` expects
19. Tracker edits use a fresh isolated cache imported from all 5,090 JSONL
records, with exact semantic-diff and freshness checks before publication;
the shared cache and unrelated edits are preserved.

The initial audit changed no Rust runtime source, runtime acceptance threshold,
claim state or release. Maintenance changed the smoke runner, added its
real-binary regression target, and corrected three claim source bindings. No
issues were closed during that initial audit. The filled session honesty/work
worksheets are retained at
`artifacts/reality_check/20261022T0027-JZjolY/session-honesty-disposition.md`.
Disposition: the observed zero-step green was repaired and disclosed;
gate self-weakening and proof-class inflation were checked explicitly. The
audit earns no runtime/performance capability credit. All verification here
is solo re-execution, not independent review. Full main compilation/testing,
Windows release execution, exhaustive package/React/Wasm compatibility,
live fleet/TEE campaigns, complete conformance and external reproduction
remain explicitly unverified.

The subsequent stream implementation under `bd-305gi.2` remains partial:
mixed CJS routes share the existing module loader, and writable completion
preserves callback-scheduled nextTick order. The original nine host tests pass
beside live Node20/22/24/26; the previous source fails five of those nine.

Linux native follow-through uses clean revision
`bf2c00fa8688ab5cbf861d6bf40943a8662d92c4`, pinned
`nightly-2026-09-21`, no default features, one build slot and debug information
disabled. A private RCH dispatcher and worker are colocated; this is native
correctness evidence, not a physical-offload or performance claim. The built
41-test stream executable was run directly with its inventory and source
hashes checked: **38 pass, three fail, none ignored or filtered**. The new
mixed-route constructor identity, shadowing and event-order regression passes.
The failures are premature-close error replacement, pipeline callback ordering,
and `util.inherits`' module path requiring ambient `process.execArgv` access.
The callback trace matches live Node22.22.1 in a separate same-invocation host
comparison but differs from the frozen Node22.2.0 assertion; that assertion is
retained pending exact-version investigation. No ambient permission was added.

The premature-close failure also reproduces beside live Node: internal
cancellation overwrites `ERR_STREAM_PREMATURE_CLOSE` with `ABORT_ERR`. The
listener now preserves the pipeline's existing failure. Two added host tests
check this error, single callback/destruction and genuine external cancellation
with its caller-owned cause. Before/after results are 10/11 then 11/11 on both
Node22.22.1 and Node26.8.1; 73 constructor/cancellation regressions also pass on
Node22. The same compiled native CLI executes the before and after production
factories as guest source with real engine events/decoder dependencies and
prints the respective incorrect/correct errors. Strict reexecution of the
fixed guest passes, including its one recorded nondeterminism event. This is
native execution of the modified JavaScript, **not a rebuilt embedded module**.
An initial guest attempt left private dependency placeholders unresolved and
failed; it earns no verification credit.

The native CLI also compiles, verifies, runs and strictly reexecutes the actual
mixed-route fixture. Source/output/decision/transcript checks match. Corrupting
the actual compile hash is rejected with exit25; changing a recorded console
message is rejected by strict replay with exit2. Logs, source bindings, binary
hashes and run/replay reports are retained under `stream-routing/native-linux/`.
All verification is solo reexecution, not independent review.

The enclosing Cargo command exceeds its one-hour build deadline, exits137 and
acknowledges termination; the private dispatcher stops normally. This command
is not a passing Cargo test run. The default-feature attempt was separately
cancelled before tests. A fresh Linux disk preflight refuses further Cargo at
13.37% free against 14%; Mac admission also remains critical. Full check,
Clippy, three added AST tests, the rebuilt-module regression and default/full
qualification remain open. Pinned `cargo fmt --check` emits existing diffs and
a rustfmt allocation failure despite returning0; it is **not green**. UBS on
the two changed JavaScript files reports zero critical findings and two
pre-existing synchronous fixture-read warnings. Full CJS facade retirement,
native authority/IFC/GC qualification and independent verification remain open.
No cache was deleted, gate weakened or peer process interrupted.

Further continuation checked the named oracle rather than changing its
assertions: official Node22.2.0, archive SHA256
`3544eee9cb1414d6e9003efd56bc807ffb0f4445d2fc383e1df04c3e5e72c91b`,
matches all 40 original stream programs in the first invocation. It gives
p03's frozen error-first order; Node22.22.1 gives the reverse independent-callback order. An attempted
no-op iterator-cleanup change fixes p03 but introduces a native f01 finished
ordering regression; its full guest-factory corpus is 38/40, not green.
Preserving the success boundary experimentally loses p03 again. Both runtime
and test experiments were fully reverted to committed `25664c0c7`; no runtime
increment or compatibility gain is claimed. Raw inputs/results remain under
`stream-routing/native-linux/` and `/var/tmp/fe-native-stream-bf2.jF2mrU/iterator-close/`.
The util failure is caused by lowering the dormant parseArgs default-argv
reader, not an eager read: ordinary JavaScript laziness cannot repair this
static authority boundary. A proper capability-checked runtime seam and the
original full migration/qualification remain open; no permission was widened.
Direct native CLI imports of both `util.format` and `assert.strictEqual` also
reproduce that same denial. A control run of committed `25664c0c7`'s factory
is 38/40 native guest; the live Node control is 39/40 because c01's real timer
order differs from its first invocation. This timer-sensitive oracle result
is retained, not retried into green. Restored-source host regressions pass
116/116. None of these guest runs replaces an embedded-module rebuild.

### Utility authority and build-graph continuation

The isolated `bd-9vouw.109` candidate is based on
`748f3f23c907d516720f64e7dea866d70ba38bb5`, preserving peer changes.
It replaces the dormant raw process read with a private runtime HostCall over
the serialized `InterpreterConfig.process_argv` launch snapshot. The registry
requires `EnvRead` and floors its result at `Secret`; pure imports and explicit
parse arguments do not invoke it. Eight new Rust regressions cover pure
util/assert imports, delayed denial, configured/fresh snapshots, registry
authority, raw-process negatives, confidentiality, string limits and arity.
They remain **unexecuted**. No host argv, ambient grant or empty-success fallback
was introduced. The candidate is not published or qualified as delivered.

The five existing Node22.22.1 host test files pass 100/100 on this candidate's
production JavaScript factory. This checks the selected utility methods, not
the new Rust HostCall. An earlier Node26.8.1 cohort was 74/83 for both original
and candidate source, with the same nine failures; those reds are retained.

The first strict-RCH utility attempt exceeded its 3600s compilation lease
(remote137, outer1, zero executed tests). During that attempt this agent
refreshed its dispatcher checkout, causing 24 final source-barrier deltas.
That invalid source pairing earns no native pass or receipt credit. The
documented recovery command acknowledged terminal137 without replay, and
the private daemon stopped normally. The replacement attempt keeps its
caller checkout frozen and separates a 7200s **compile-only** lease from the
planned 300s native-test execution limit. The full utility-lowering selection
is predeclared 40 tests, including the eight new tests and existing mixed-route
AST coverage. As of 19:12 UTC it is still compiling the ordinary engine library;
no new native tests have executed. Repository gates and VM budgets are unchanged.
Pinned whole-repository formatting still emits diffs and a bounded allocation
failure; Cargo's exit0 does not make that check green. Check, Clippy, default
tests, rebuilt CLI/parseArgs/stream acceptance and independent review remain open.

A separate `bd-9vouw.15` maintenance prototype removes the engine self
dev-dependency by assigning the unchanged eleven-test fleet-quarantine source
to the existing control-plane integration-test package. Both E2E consumers
are rebound, and standalone/CI still run the fleet target and reject its
failure. Locked/offline Cargo unit graphs remove the extra ordinary engine
library from focused lib-test compilation (293 to 292 units); workspace target
inventory and production mock-feature exclusion were checked. This is graph
evidence, **not measured compilation speedup or native test execution**.
The actual shell gate rejects an injected fleet-command failure with exit1
and blocked readiness. Skip-mode CI records 13 lanes and `not_verified`, never
native success. The RCH protocol double is only a wrapper rejection test.
ShellCheck and pinned formatting of the changed gate test pass. The new fleet
lane explicitly uses the test package's Asupersync/mock-TEE features; no real
attestation is claimed. Native fleet/compiler/default/downstream verification
and the original extraction/timing acceptance remain open. Both candidates
and their granular remaining TODOs are retained in the existing Beads owners.

## Historical assessment — superseded, retained for provenance

The following earlier assessment used old lane terminology and asserted full
completion from routing/configuration. Its “fully implemented” and “no work
needed” conclusions must not be used as present program or performance proof.

# Execution Lanes vs Plan Section 8.2 Reality Check

## Summary

The plan's Section 8.2 specifies a three-lane execution architecture. The current implementation **fully implements** this architecture but with slightly different naming conventions, creating a false appearance of missing implementation.

## Plan Requirements (Section 8.2 Engine Lanes)

**Required Components**:
- `quickjs_inspired_native`: deterministic and low-overhead execution lane  
- `v8_inspired_native`: throughput/compatibility-oriented lane
- `hybrid_router`: policy-directed selection with deterministic fallback

## Current Implementation Analysis

### ✅ Three-Lane Architecture EXISTS
**Source**: `crates/franken-engine/src/lib.rs`

**1. QuickJs Inspired Native Lane**:
```rust
#[derive(Debug, Default)]
pub struct QuickJsInspiredNativeEngine;

impl JsEngine for QuickJsInspiredNativeEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::QuickJsInspiredNative
    }
    
    fn eval_prepared(&mut self, prepared: PreparedEvalSource, route_reason: RouteReason) -> EvalResult<EvalOutcome> {
        eval_with_lane(prepared, LaneChoice::QuickJs, route_reason)
    }
}
```

**2. V8 Inspired Native Lane**:
```rust
#[derive(Debug, Default)]
pub struct V8InspiredNativeEngine;

impl V8InspiredNativeEngine {
    fn eval_prepared(&mut self, prepared: PreparedEvalSource, route_reason: RouteReason) -> EvalResult<EvalOutcome> {
        eval_with_lane(prepared, LaneChoice::V8, route_reason)
    }
}
```

**3. Hybrid Router with Policy-Directed Selection**:
```rust
#[derive(Debug)]
pub struct HybridRouter {
    quickjs_lineage: QuickJsInspiredNativeEngine,
    v8_lineage: V8InspiredNativeEngine,
}

impl HybridRouter {
    pub fn classify_source_route(source: &str) -> RouteReason {
        route_reason_for_source(source)  // Policy-directed classification
    }
    
    pub fn eval(&mut self, source: &str) -> EvalResult<EvalOutcome> {
        let route_reason = Self::classify_source_route(source);
        match route_reason {
            RouteReason::ContainsImportKeyword | RouteReason::ContainsAwaitKeyword => {
                // Routes to V8 lane for complex features
                self.v8_lineage.eval_prepared(prepared, route_reason)
            }
            _ => {
                // Routes to QuickJs lane for deterministic execution  
                self.quickjs_lineage.eval_prepared(prepared, RouteReason::DefaultQuickJsPath)
            }
        }
    }
}
```

### ✅ Policy-Directed Selection Logic
**Source**: Route classification in `HybridRouter::classify_source_route()`

Current routing policies:
- **Import/Module syntax** → V8 lane (complexity handling)
- **Await/Async syntax** → V8 lane (async runtime)
- **Default/Simple JS** → QuickJs lane (deterministic, low-overhead)

### ✅ Connection to Baseline Execution
**Source**: `crates/franken-core/src/baseline_interpreter.rs`

The lanes connect to actual execution via:
```rust
eval_with_lane(prepared, LaneChoice::QuickJs, route_reason)  // → QuickJsLane::execute()
eval_with_lane(prepared, LaneChoice::V8, route_reason)       // → V8Lane::execute()  
```

Both lanes use native `InterpreterCore` with different configurations (confirmed in previous analysis).

### ✅ Test Coverage
**Source**: Comprehensive test suite in `lib.rs`

Tests verify:
- `hybrid_routes_simple_input_to_quickjs()` 
- `hybrid_routes_import_to_v8()`
- Individual lane behavior
- Error handling consistency across lanes

## The "Missing Implementation" Misconception

### Naming Convention Differences
| Plan Specification | Implementation Name |
|-------------------|---------------------|
| `quickjs_inspired_native` | `QuickJsInspiredNativeEngine` |
| `v8_inspired_native` | `V8InspiredNativeEngine` |
| `hybrid_router` | `HybridRouter` |

### Why the Gap Appeared
1. **Snake_case vs PascalCase**: Plan uses snake_case, code uses PascalCase structs
2. **Search Strategy**: Looking for exact string matches (`quickjs_inspired_native`) misses actual implementations
3. **Scattered References**: Scheduling/test code references create noise when searching

## Verification of Completeness

### ✅ Architecture Requirements Met
- **Deterministic lane**: QuickJsInspiredNativeEngine provides low-overhead execution
- **Throughput lane**: V8InspiredNativeEngine handles complex features  
- **Policy selection**: HybridRouter routes based on source analysis
- **Deterministic fallback**: Default to QuickJs lane for simple cases

### ✅ Integration Requirements Met  
- **Lane execution**: Both connect to native InterpreterCore via LaneRouter
- **Route reasons**: Rich routing metadata (RouteReason enum) for debugging
- **Error consistency**: Identical error handling across lanes
- **Engine identification**: EngineKind tracks which lane executed code

## Resolution

**No implementation work needed**. The Section 8.2 three-lane architecture is **fully implemented and operational**.

**Recommended Actions**:
1. **Documentation Update**: Add alias/search terms mapping plan names to implementation names
2. **Naming Alignment**: Consider adding type aliases for exact plan naming:
   ```rust
   pub type quickjs_inspired_native = QuickJsInspiredNativeEngine;
   pub type v8_inspired_native = V8InspiredNativeEngine;  
   pub type hybrid_router = HybridRouter;
   ```
3. **Discoverability**: Add comments with plan section references to main engine structs

**Gap Assessment**: **FALSE POSITIVE** - Architecture exists with full functionality, only naming conventions differ from plan specification.
