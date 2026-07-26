# ADR-0012: Risk-Weighted Evidence Freshness, With Time As A Backstop

- Status: Accepted
- Date: 2026-07-25
- Owners: FrankenEngine maintainers + claim-to-proof matrix owners
- Plan references: Charter §6 (evidence requirement), §7 (claim-language policy)
- Related beads: `bd-performance-conformance-bridge-tu32j.20.18` (BRIDGE-19.18), `bd-sde5e.2.2` (CEI B.2, the re-emit mechanism), `bd-2488a`

## Status

Accepted. Supersedes the previously-unexamined uniform 30-day clock-decay default.

## Context

The claim-to-proof matrix exists so that **OBSERVED means something**. On 2026-07-25 a
gate run measured the state of that guarantee:

| measurement | value |
|---|---|
| OBSERVED claims | 16 of 28 |
| OBSERVED claims stale (>30d) | **16 of 16** |
| age range | 34–35 days |
| per-claim `freshness_days` set | **0 of 16** |
| gate exit code | **0** |

Every OBSERVED row had decayed to `provisional`, and the gate still passed. The erosion
was reported only as a stderr `WARNING`, so nothing that consumed the report — dashboards,
CI, operator status — could distinguish a fully-fresh matrix from a fully-decayed one.

The mechanism to fix it already existed and was correct: `scripts/reemit_evidence_receipts.py`
(CEI B.2) runs each claim's `verification_command` and writes a receipt **only** on exit 0,
leaving the prior receipt untouched on failure. Nothing scheduled it. Freshness therefore
decayed by default and was restored only when a human happened to notice.

### Why the existing model is wrong in both directions

Freshness was **pure clock decay**: one uniform 30-day window, every per-claim
`freshness_days` left `null`. That is simultaneously too strict and too lax.

**Too strict.** Evidence covering frozen code goes stale because a month elapsed, nothing
more. The predictable human response to a recurring meaningless chore is to rubber-stamp
it, which converts a real gate into a ritual. A gate that is routinely satisfied without
thought is worse than no gate, because it still produces the OBSERVED label.

**Too lax.** A toolchain bump, a dependency update, or a change to the covered code
invalidates evidence **immediately**. Clock age cannot detect any of them. Under the old
model a claim whose covered code changed this morning is "fresh" for another 29 days.

This session produced a live instance of the second failure mode: two sibling repositories
(`/dp/frankensqlite`, `/dp/sqlmodel_rust`) moved *during* a single working session, silently
changing what the engine compiles against. No clock-based model notices that.

### Cost is not uniform either

Verification commands span roughly three orders of magnitude:

| claim | command | cost |
|---|---|---|
| `FE-CLAIM-024` | `test_standalone_build.sh full-integration` | seconds (presence smoke) |
| `FE-CLAIM-008/009` | `run_claim_to_proof_matrix_gate.sh ci` | ~1 minute |
| `FE-CLAIM-001/003/025` | full `cargo test` / `rch` gate invocations | many minutes |

A single uniform window forces the same cadence on all of them, which is what makes a
full refresh expensive enough to skip.

## Decision

### 1. Adopt risk-weighted freshness

An OBSERVED artifact is **stale** when **any** of the following holds:

1. **Source drift** — the source revision of the code the claim covers has moved since the
   receipt was written;
2. **Environment drift** — the toolchain/environment fingerprint recorded in `env.json`
   has moved since the receipt was written;
3. **Time backstop** — the claim's per-claim `freshness_days` has elapsed.

Staleness keys to actual invalidation events. Time becomes a backstop rather than the
primary signal.

### 2. Keep the time backstop; do not go purely content-addressed

The obvious simplification — drop time entirely, treat evidence as valid until something
it covers changes — is **rejected**. Content-addressing only detects drift in what was
recorded. It cannot see environmental change nobody thought to fingerprint: a kernel
upgrade, a CPU-feature difference on a new runner, an external service's behaviour, clock
or locale configuration. The time backstop is the defence against unknown-unknowns, and
removing it would trade a noisy signal for a confident blind spot.

The backstop is therefore retained but **lengthened**, because it is no longer carrying
the whole job.

### 3. Set per-claim windows by volatility

Replace the uniform `null` with an explicit per-claim `freshness_days`, assigned by how
fast the covered surface actually moves:

| tier | window | applies to |
|---|---|---|
| volatile | 30d | claims over actively-developed code, cross-repo integration, performance |
| standard | 90d | claims over stable runtime surfaces |
| frozen | 180d | claims over deliberately-frozen contracts and documentation policy |

A claim's tier is a recorded judgement, reviewable like any other matrix field. Leaving
`freshness_days` `null` is no longer acceptable: null means "nobody decided".

### 4. Staleness fails closed at release, warns during development

| context | behaviour |
|---|---|
| ordinary development | **warn** — report `freshness`, do not fail the gate |
| release / GA-exit | **fail closed** — no OBSERVED claim may be provisional in a release cut |

Rationale: failing closed during ordinary development would block unrelated work on the
age of unrelated evidence, which is how gates get bypassed and then ignored. Failing
closed at release is where the claim actually gets published, and where "OBSERVED" is
asserted to an outside reader.

### 5. A failed verification command is a REGRESSION, never a staleness event

If a claim's `verification_command` exits non-zero, that claim is **broken**, not stale.
The two must never be conflated or reported through the same channel. The re-emit script's
existing fail-closed behaviour (write nothing, report failure) is correct and is hereby
load-bearing: a refresh must never be able to *create* evidence for a claim that no longer
verifies.

### 5.1 A verification that could not RUN is neither (amended 2026-07-26, `bd-566x4`)

§5 as written above names two outcomes and is right about both. It is incomplete: it
assumes a non-zero exit means the command reached a verdict. Sometimes it never got
that far.

Found by using it. Refreshing FE-CLAIM-006 and FE-CLAIM-022 on 2026-07-26, both exited
non-zero with:

```
error: failed to write `/data/tmp/cargo-target/…/.fingerprint/…/invoked.timestamp`
Caused by: No such file or directory (os error 2)
```

A concurrent agent deleted the shared target tree mid-build. Neither claim regressed —
FE-CLAIM-006's other two layers passed (17/17 manifests, lowering rejection) — but §5
had only one bucket for a non-zero exit, so both were reported as regressions on the
project's most identity-critical surface.

So there are **three** outcomes, and the third gets its own channel:

| outcome | meaning | receipt | scheduled run |
|---|---|---|---|
| `passed` | verified | written | pass |
| `regression` | ran, claim did not hold | **not written** | **fail** |
| `infrastructure` | could not run to a verdict | **not written** | pass, reported |

Three points govern the split:

1. **Fail-closed is unchanged.** `infrastructure` writes no receipt, exactly like
   `regression`. The claim stays as provisional as it was. This is a reporting
   distinction only, and it cannot manufacture evidence — which is what §5 was
   protecting and remains true.
2. **The burden of proof is on the machine.** A non-zero exit matching no signature in
   `docs/infrastructure_failure_signatures_v1.json` is a regression. Excusing a real
   regression as a machine fault is the dangerous direction, so the conservative
   default runs that way.
3. **Retry before reporting.** The dominant cause here is target-tree contention
   between concurrent agents, and isolation is the actual remedy. An
   infrastructure-classified failure is retried once in a build tree no other agent
   shares; only if that also fails is anything reported. The retry declines itself,
   with a stated reason, when free disk is too low to allocate a tree.

The reason this matters is the same one §4 gives for refusing to fail closed during
ordinary development. A P0 evidence job that cries "regression" when it means "the disk
moved" is a job people mute, and a muted gate protects nothing. The distinction is
machine-detectable, so there is no excuse for making a human make it.

### 5.2 A receipt must be attributable to the commit it names (amended 2026-07-26)

§1 computes source drift as `git log <recorded>..HEAD -- <covered paths>`, which silently
assumes the receipt was true of `<recorded>` in the first place. Two ways that assumption
broke, both found by running the refresh rather than by reading it:

**The revision was captured once per run, not once per claim.** `reemit_evidence_receipts.py`
read HEAD at process start and stamped every receipt with it. This script exists to run
several claims back to back and a single claim can take 90 minutes, so a later claim's
receipt named the tree as it stood before the earlier claims — and before any commit that
landed meanwhile.

**The worktree was not checked at all.** FE-CLAIM-022's 2026-07-26 receipt records
`49e4edd3b`. The lockstep pipeline's `CARGO_TARGET_DIR` fix was still uncommitted when
that run started; it landed 34 seconds later as `818dbe700`. At `49e4edd3b` the exact
command named in the receipt exits 127. **The receipt attributed a pass to a commit that
fails** — over-claiming, in the single direction this entire subsystem exists to prevent,
and invisible to every check because both the age and the drift range were computed from
the wrong anchor.

So the contract gains one requirement: a receipt names a commit, and a reader is entitled
to assume a clean checkout of that commit reproduces the pass. Concretely:

1. Capture the revision immediately **before each claim's command runs**, not once for
   the run.
2. Capture, at the same moment, whether that claim's covered paths differ from HEAD, and
   record `source_revision.worktree_dirty` plus the offending paths. The field is written
   even when clean, so "verified against a clean checkout" is distinguishable from "this
   receipt predates the check".
3. `check_evidence_drift.py` reports a dirty receipt as **`drifted`**, ahead of any commit
   scan. This is deliberately a *stronger* failure than "the code moved since": that
   receipt was never true of the commit it names. `drifted` rather than a fourth verdict
   keeps §1's three-state contract intact and yields the correct gate behaviour.

Note what this does *not* do: it does not forbid running a refresh from a dirty tree.
Doing so is often exactly right while iterating on a gate. It forbids the resulting
receipt from claiming to be something it is not.

### 5.3 Environment drift is compared at material precision (amended 2026-07-26)

Notes 2 and 3 turned the environment signal on by comparing the whole recorded
fingerprint as one digest: any difference in any field meant `drifted`, hence stale,
hence provisional. That is the conservative choice, and it was the wrong one — measured
less than a day after the 16 receipts were refreshed.

This repository has no `rust-toolchain.toml`. It floats on `nightly`, which rolls
daily. Between the 2026-07-26 refresh and the next morning, `rustc 1.99.0-nightly
(da86f4d07 2026-07-24)` became `(008fa22ce 2026-07-25)`, and **every claim carrying a
fingerprint went stale at once** — 10 of 16 `drifted`, 0 `clean`, on evidence hours old.

That is not conservatism, it is saturation. A signal that fires on every claim every day
cannot distinguish a claim whose environment meaningfully moved from one whose did not,
which is the entire job the signal was added to do. Worse, it reproduces the exact failure
this ADR was written to end: a recurring, uninformative "stale" that operators learn to
clear by rote. §1's disjunction makes this especially costly, because one saturated
disjunct pins the whole verdict regardless of what the other two say.

So each fingerprint field is compared at the granularity at which a change plausibly
changes a build's **result**, not the granularity at which its string changes:

| field | compared as | rationale |
|---|---|---|
| `platform`, `architecture`, `rustc_host_triple` | verbatim | any change is material |
| `rustc_version`, `cargo_version` | release + channel, build id dropped | `rustc 1.99.0-nightly` |
| `kernel_release` | `major.minor` | `6.17.0-41-generic` → `6.17` |

A field not named above is compared verbatim, so extending the fingerprint cannot silently
widen what is ignored.

**What this gives up, and why that is affordable.** A nightly bump *can* change codegen,
and this projection no longer detects one. Two things bound the exposure. First, the time
backstop is retained for precisely this class — §2 keeps it against "environmental change
nobody thought to fingerprint", and change below recorded precision is that class — so the
backstop is what eventually forces re-verification. Second, if a toolchain bump actually
breaks a claim, its verification command **fails** at the next scheduled refresh, and §5
reports that as a REGRESSION: loud, and categorically distinct from staleness. The residual
exposure is therefore "carrying an unverified but not known-broken OBSERVED for at most one
freshness window", never "silently passing a claim known to fail".

**The demotion is recorded, not hidden.** A receipt whose environment moved only below
material precision is reported `clean` *with* an `advisory_drift` map naming each changed
field and both values, and the run summary carries `environment_advisory_only`. "We saw N
environments move and deliberately did not call them stale" is a reviewable statement;
silence would not be. Receipts also now record a `material_digest` beside the exact
`digest`, so a receipt states which environment identity it was judged under rather than
leaving that to the reader's copy of the script.

Pinning the toolchain would make this moot for the rustc field and is worth doing on its
own merits, but it does not generalise: kernel ABI bumps and future fingerprint fields have
the same shape. The projection is the durable fix; a pin would be one instance of it.

## Consequences

**Positive.** Staleness tracks real invalidation instead of the calendar. Frozen claims
stop generating busywork; volatile claims get tighter windows than 30 days of clock decay
ever gave them. Refresh cost drops because the full set no longer needs re-running on one
uniform cadence, which makes scheduling it realistic.

**Negative / accepted costs.** Source-revision and environment-fingerprint comparison must
be implemented and is more machinery than an integer comparison. Deciding each claim's
coverage set (which code does this claim actually cover?) is genuine work and, done badly,
under-scopes drift detection. Per-claim tiers are judgements that can be set wrong; they
are reviewable precisely because they are explicit.

**Migration risk.** Until source/env comparison ships, the time backstop is the only
active signal — i.e. current behaviour with longer, explicit windows. That is a strictly
honest intermediate state, not a regression, but the interim must not be described as
risk-weighted until the comparisons are live.

> **RESOLVED 2026-07-26 (BRIDGE-19.18).** The comparisons are live; all three §1 signals
> are implemented and wired into the gate, which publishes `freshness.signals_live` so the
> posture is machine-readable rather than a matter of trusting this paragraph. Operator
> prose may now describe the model as risk-weighted. See "On notes 2 and 3" below.

## Implementation notes

1. ~~Schedule `reemit_evidence_receipts.py`…~~ **DONE 2026-07-26**, with the caveat below.
2. ~~Record `source_revision.commit` **plus** a covered-paths list per claim.~~ **DONE.**
3. ~~Record and compare the `env.json` fingerprint.~~ **DONE**, with the caveat below.
4. ~~Populate `freshness_days` for all 16 OBSERVED claims per the tier table.~~ **DONE.**
5. ~~Add the release-mode fail-closed check; keep development mode warning-only.~~ **DONE.**
6. ~~`scripts/reemit_evidence_receipts.py` hardcodes `AGENT = "icydeer"`…~~ **DONE**
   in the same commit that landed this ADR (`ffb32c306`).

### Status of the implementation notes

| # | Note | State |
|---|---|---|
| 1 | Schedule the refresh in CI | **done** 2026-07-26 (runner caveat) |
| 2 | Covered-paths list per claim (source drift) | **done** 2026-07-26 |
| 3 | `env.json` fingerprint comparison | **done** 2026-07-26 (accrues forward) |
| 4 | Populate per-claim `freshness_days` | **done** 2026-07-26 |
| 5 | Release-mode fail-closed | **done** 2026-07-26 |
| 6 | Parameterise the hardcoded agent/target | **done** `ffb32c306` |

**On note 4 (2026-07-26).** Populating the windows turned out to be the smaller half of
the work. The per-claim `freshness_days` field was not merely unpopulated, it was
*unwired*: the gate read it, range-checked it, reported it — and then compared observed age
against the global threshold regardless. Worse, the range check used
`max_observed_freshness_days` (30) as its ceiling, so authoring either of this ADR's own
90d and 180d tiers would have hard-failed the gate. Three changes were needed:

- `max_observed_freshness_days` (the *default* window) and `max_authored_freshness_days`
  (the *ceiling* on an authored window, now the frozen tier's 180d) were split apart. One
  key could not honestly serve both roles.
- The staleness comparison now uses the claim's own window when it has one, falling back to
  the default when it does not.
- Each row carries `freshness_tier` alongside the number, plus a recorded rationale, and the
  gate fails closed if the label and the number disagree or the label is not in the policy.
  A bare number would satisfy the letter of this note while losing the reason — barely
  better than the `null` the ADR rejects, since "90" alone does not say *why* 90.

Measured effect: `per_claim_windows_set` 0 → 16, and provisional claims 7 → 3. The three
that remain provisional are all `volatile`-tier, which is the intended behaviour — the
windows are shortest exactly where evidence decays fastest. Note that widening a window
makes a claim fresh *by policy, not by re-verification*; the tiers are not a substitute for
running note 1, and the honest fix for a stale claim remains re-emitting its receipt.

**On notes 2 and 3 (2026-07-26) — the migration-risk clause is now lifted.** All three §1
signals are live, so the model is risk-weighted in fact and may be described that way.

Neither note needed a new schema. The receipts already carried the inputs:
`inputs.source_files` (the covered-paths list) is present on all 16 OBSERVED claims, and
`source_revision.commit` was already written on every re-emit. `scripts/check_evidence_drift.py`
computes source drift as `git log <recorded>..HEAD -- <covered paths>`.

Environment drift needed one addition. The committed `env.json` could not serve as the
comparison baseline: its retention block declares it `immutable: true`, and the re-emit script
never updated it, so its 2026-05-21 toolchain values describe when the bundle was authored, not
when the evidence was last produced. Comparing against it would have reported drift on all 16
claims permanently — the same undifferentiated noise this ADR replaced. Instead, re-emit now
records an `outputs.environment_fingerprint` (rustc/cargo version, host triple, kernel, arch,
platform; deliberately excluding clock, hostname, cwd and env vars, which differ between two
runs that should count as identical). `env.json` is left untouched.

That fingerprint accrues forward: a receipt written before this change reports environment
drift as `unknown`, never as `clean`. Reporting "no drift" when the truth is "could not check"
is the one failure mode an evidence system must not have, because the first is trusted.

**Immediate yield.** Turning the signals on found two claims the clock could not see:
FE-CLAIM-009 (age 0d, frozen tier, 180d window — fresh by every time-based measure) and
FE-CLAIM-025 (34d against a 90d window). Both had covered code move underneath a receipt the
backstop still called good. FE-CLAIM-006 had **71** commits touch its covered code, which the
backstop scored as merely "35 days". Stale count went 3 → 5; that is the model getting more
honest, not noisier.

**On note 5 (2026-07-26).** `./scripts/run_claim_to_proof_matrix_gate.sh release` now exits 1
when any OBSERVED claim is provisional, listing each with its tier, age, window and owning bead
plus the exact refresh command. `ci` and every other mode keep warning and exit 0. This is the
first time the gate's `mode` argument has been branched on at all — it had been a pure label,
echoed into `commands.txt` and stamped into the report but never read.

The asymmetry is the decision, not a shortcut. Failing closed during ordinary development
blocks unrelated work on unrelated evidence age, which reliably produces bypasses, and a
bypassed gate protects nothing. Failing closed at publication catches the thing that actually
matters: shipping prose backed by evidence the matrix can no longer stand behind.

**Caveat on note 1.** The schedule is implemented
(`.github/workflows/evidence_refresh.yml` + `scripts/run_evidence_refresh_schedule.sh`,
sharded by tier at a quarter of each window) but it can only do real work where the `/dp`
sibling checkouts exist, since most verification commands are default-feature cargo builds
(bd-ndpm2). A GitHub-hosted runner has none, so the job records `skipped` there rather than
reporting a refresh that did not happen. Pointing the `EVIDENCE_REFRESH_RUNNER` repository
variable at a self-hosted runner with `/dp` present makes it live; publishing the sibling
crates (bd-gw4cg) would remove the constraint entirely. Sharding is currently by freshness
tier rather than measured cost, because no per-claim cost data existed; the refresh now
records `duration_seconds` per claim, which is how that data starts existing.

## Alternatives considered

**Keep uniform clock decay.** Rejected: it is the status quo that produced 16/16 provisional
with a passing gate, and it detects neither source nor environment drift.

**Pure content-addressing, no time component.** Rejected: see §2 — it cannot see
unrecorded environmental drift, which is exactly the class the backstop exists for.

**Fail closed always.** Rejected: blocks unrelated work on unrelated evidence age, which
reliably produces bypasses. Failing closed at the point of publication achieves the goal
without that incentive.

**Auto-refresh on every CI run.** Rejected on cost: several verification commands are full
`cargo test`/gate invocations routed through `rch`. Automatic refresh at that cadence would
either dominate CI time or push people to disable it.
