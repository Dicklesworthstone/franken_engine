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

## Implementation notes

1. Schedule `reemit_evidence_receipts.py` (weekly CI and pre-release), publishing per-claim
   pass/fail; shard by cost tier so the expensive claims do not gate the cheap ones.
2. Record `source_revision.commit` (already written) **plus** a covered-paths list per
   claim, so source drift is computable rather than assumed.
3. Record and compare the `env.json` fingerprint per the reproducibility contract.
4. Populate `freshness_days` for all 16 OBSERVED claims per the tier table.
5. Add the release-mode fail-closed check; keep development mode warning-only.
6. `scripts/reemit_evidence_receipts.py` hardcodes `AGENT = "icydeer"` and a
   `target_icydeer` warm-target path — an artifact of the agent who wrote it. That must be
   parameterised before the script runs unattended on a schedule.

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
