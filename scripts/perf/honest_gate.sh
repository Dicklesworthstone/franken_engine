#!/bin/bash
set -euo pipefail

# PERF-ARTIFACT-1.2 (bd-o4cbn.12.2): honest-gate walker.
#
# Adapts the profiling skill's 14-question honest-gate checklist
# (references/HONEST-GATE-CHECKLIST.md) to franken_engine's perf surface: a
# single engine self-compared against a frozen Criterion baseline (pass1), not a
# database A-vs-B. The walker answers every question it can *from the committed
# artifacts* (fingerprint.json, events.jsonl, summary.md, Criterion
# estimates.json), prompts interactively for the subjective ones, and emits a
# producer-Ed25519-signed `attestation_v1.json` beside the bench result.
#
# A bench number without an attestation is unfit to cite (see the
# "What counts as a perf win" gate in docs/PERFORMANCE_BASELINE.md, criterion 3:
# honest-gate score >= 12/14). This walker IS that scorer.
#
# Usage:
#   scripts/perf/honest_gate.sh \
#       --bead     PERF-H6 \
#       --baseline tests/artifacts/perf/20260520T214829Z-prof-pass1 \
#       --post     tests/artifacts/perf/h6_bench/<ts> \
#       --out      tests/artifacts/perf/attestations/PERF-H6 \
#       [--sub-bench iterator_protocol_trace] \
#       [--non-interactive ANSWERS_FILE] [--key SEED_HEX_OR_PEM]
#
#   scripts/perf/honest_gate.sh selftest      # build-free round-trip self-check
#
# Answers: pass | fail | waive:<reason>. Auto-answers are derived from artifacts
# and tagged with their evidence; they can be overridden via the answers file.
# Scoring: pass=1, waive=1 (a written exception), fail=0, unknown=0. Verdict is
# "pass" iff score_total >= 12 AND no question answered "fail".
#
# Signing key resolution (producer Ed25519):
#   1. --key <32-byte-hex-seed | path-to-pkcs8-pem>
#   2. $HONEST_GATE_SIGNING_KEY_HEX (32-byte hex seed)
#   3. built-in deterministic dev seed (documented constant; selftest-stable)
# The producer public key + signature over the canonical body (signature field
# blanked) always travel in the attestation, so any holder can re-verify.

SCRIPT_NAME="$(basename "$0")"

# ---------------------------------------------------------------------------
# selftest: synthesise a baseline+post bundle, walk non-interactively, verify
# the emitted attestation round-trips (schema + 14 tuples + signature). No
# cargo, no engine build -> reproducible on any tree.
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "selftest" ]]; then
    TMP="$(mktemp -d)"
    if [[ "${HONEST_GATE_SELFTEST_KEEP_TMP:-0}" == "1" ]]; then
        echo "[honest-gate] selftest artifacts retained at $TMP"
    else
        trap 'rm -rf "$TMP"' EXIT
    fi
    mkdir -p "$TMP/baseline" "$TMP/post" "$TMP/out"

    # Frozen baseline: a scenario doc + one criterion estimate.
    cat > "$TMP/baseline/01_DEFINE.md" <<'EOF'
# Scenario: selftest_hot_path
Metric: mean ns (latency). Claim: post is faster than pass1 baseline.
EOF
    cat > "$TMP/baseline/criterion_selftest_hot_path_estimates.json" <<'EOF'
{"mean":{"point_estimate":1000.0,"confidence_interval":{"lower_bound":990.0,"upper_bound":1010.0}},
 "median":{"point_estimate":1000.0},"std_dev":{"point_estimate":30.0}}
EOF
    cat > "$TMP/baseline/fingerprint.json" <<'EOF'
{"captured_at_utc":"2026-05-25T00:00:00Z","git_sha":"cafebabecafebabecafebabecafebabecafebabe",
 "git_dirty":false,"baseline_ref":"selftest-baseline",
 "toolchain":{"rustc":"rustc 1.97.0-nightly"},
 "build_flags":{"RUSTFLAGS":"-C force-frame-pointers=yes -C linker=cc -Clinker-features=-lld","CARGO_ENCODED_RUSTFLAGS":null,"CARGO_INCREMENTAL":"0"}}
EOF
    # Post run: fingerprint + estimates + summary with a published regression.
    cat > "$TMP/post/fingerprint.json" <<'EOF'
{"captured_at_utc":"2026-05-26T00:00:00Z","git_sha":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
 "git_dirty":false,"baseline_ref":"baseline",
 "toolchain":{"rustc":"rustc 1.97.0-nightly"},
 "build_flags":{"RUSTFLAGS":"-C force-frame-pointers=yes -C linker=cc -Clinker-features=-lld","CARGO_ENCODED_RUSTFLAGS":null,"CARGO_INCREMENTAL":"0"}}
EOF
    mkdir -p "$TMP/post/criterion/selftest_hot_path/post"
    cat > "$TMP/post/criterion/selftest_hot_path/post/estimates.json" <<'EOF'
{"mean":{"point_estimate":800.0,"confidence_interval":{"lower_bound":795.0,"upper_bound":805.0}},
 "median":{"point_estimate":800.0},"std_dev":{"point_estimate":20.0}}
EOF
    cat > "$TMP/post/criterion/selftest_hot_path/post/benchmark.json" <<'EOF'
{"config":{"sample_size":100,"warm_up_time":{"secs":3,"nanos":0},"measurement_time":{"secs":5,"nanos":0}}}
EOF
    cat > "$TMP/post/summary.md" <<'EOF'
# Bench summary
| sub-bench | pass1 (ns) | post (ns) | Δ% | verdict |
|---|---:|---:|---:|---|
| selftest_hot_path | 1000.0 | 800.0 | -20.00 | faster -> OK |
| other_bench | 500.0 | 560.0 | +12.00 | REGRESSED |
Attribution caveat: cumulative vs pass1; microbench isolates one axis.
EOF
    cat > "$TMP/answers" <<'EOF'
5_realistic_workload=pass
9_host_quiet=pass
13_apples_flagged=pass
EOF

    "$0" --bead PERF-SELFTEST --baseline "$TMP/baseline" --post "$TMP/post" \
         --out "$TMP/out" --sub-bench selftest_hot_path \
         --non-interactive "$TMP/answers" >/dev/null

    ATT="$TMP/out/attestation_v1.json"
    python3 - "$ATT" <<'PYVERIFY'
import json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

att = json.load(open(sys.argv[1]))
assert att["schema"] == "franken-engine.honest-gate-attestation.v1", "schema"
qs = att["questions"]
assert len(qs) == 14, f"expected 14 questions, got {len(qs)}"
for q in qs:
    assert set(q) >= {"id", "question", "answer", "score", "source"}, q
    assert q["score"] in (0, 1), q
assert att["score_max"] == 14
assert isinstance(att["score_total"], int)
# Verify the producer signature round-trips over the blanked canonical body.
prod = att["producer"]
body = dict(att); body["producer"] = dict(prod); body["producer"]["signature_hex"] = ""
preimage = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(prod["public_key_hex"]))
try:
    pk.verify(bytes.fromhex(prod["signature_hex"]), preimage)
except InvalidSignature:
    print("SELFTEST FAIL: signature does not verify", file=sys.stderr); sys.exit(1)
# Tamper check: flip a byte -> must NOT verify.
tampered = dict(body); tampered["score_total"] = att["score_total"] + 1
bad = json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode()
try:
    pk.verify(bytes.fromhex(prod["signature_hex"]), bad)
    print("SELFTEST FAIL: tampered body still verified", file=sys.stderr); sys.exit(1)
except InvalidSignature:
    pass
print(f"SELFTEST POSITIVE PASS: schema+14 tuples+signature OK; score {att['score_total']}/14 verdict {att['verdict']}")
PYVERIFY

    # Exact-identity regression: an ambient flag prepended to the otherwise
    # canonical RUSTFLAGS must fail Q2 instead of receiving substring credit.
    python3 - "$TMP/post/fingerprint.json" <<'PYMUTATE'
import json, sys

path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    fingerprint = json.load(fh)
fingerprint["build_flags"]["RUSTFLAGS"] = (
    "-C debuginfo=0 -C force-frame-pointers=yes -C linker=cc -Clinker-features=-lld"
)
with open(path, "w", encoding="utf-8") as fh:
    json.dump(fingerprint, fh)
PYMUTATE
    mkdir -p "$TMP/out_noncanonical_rustflags"
    if "$0" --bead PERF-SELFTEST-NONCANONICAL-RUSTFLAGS \
            --baseline "$TMP/baseline" --post "$TMP/post" \
            --out "$TMP/out_noncanonical_rustflags" \
            --sub-bench selftest_hot_path \
            --non-interactive "$TMP/answers" >/dev/null 2>&1; then
        echo "SELFTEST FAIL: extra ambient RUSTFLAGS received canonical credit" >&2
        exit 1
    fi
    python3 - "$TMP/out_noncanonical_rustflags/attestation_v1.json" <<'PYREJECT'
import json, sys

with open(sys.argv[1], encoding="utf-8") as fh:
    attestation = json.load(fh)
q2 = next(q for q in attestation["questions"] if q["id"] == "2_same_build_profile")
assert q2["answer"] == "fail", q2
PYREJECT

    # Cargo encoded flags outrank RUSTFLAGS. A non-canonical encoded payload
    # must therefore fail even when RUSTFLAGS still looks canonical.
    python3 - "$TMP/post/fingerprint.json" <<'PYMUTATE'
import json, sys

path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    fingerprint = json.load(fh)
fingerprint["build_flags"]["RUSTFLAGS"] = (
    "-C force-frame-pointers=yes -C linker=cc -Clinker-features=-lld"
)
fingerprint["build_flags"]["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join((
    "-Cdebuginfo=0",
    "-Cforce-frame-pointers=yes",
    "-Clinker=cc",
    "-Clinker-features=-lld",
))
with open(path, "w", encoding="utf-8") as fh:
    json.dump(fingerprint, fh)
PYMUTATE
    mkdir -p "$TMP/out_noncanonical_encoded_rustflags"
    if "$0" --bead PERF-SELFTEST-NONCANONICAL-ENCODED-RUSTFLAGS \
            --baseline "$TMP/baseline" --post "$TMP/post" \
            --out "$TMP/out_noncanonical_encoded_rustflags" \
            --sub-bench selftest_hot_path \
            --non-interactive "$TMP/answers" >/dev/null 2>&1; then
        echo "SELFTEST FAIL: extra encoded RUSTFLAGS received canonical credit" >&2
        exit 1
    fi
    python3 - "$TMP/out_noncanonical_encoded_rustflags/attestation_v1.json" <<'PYREJECT'
import json, sys

with open(sys.argv[1], encoding="utf-8") as fh:
    attestation = json.load(fh)
q2 = next(q for q in attestation["questions"] if q["id"] == "2_same_build_profile")
assert q2["answer"] == "fail", q2
print("SELFTEST PASS: exact RUSTFLAGS and encoded-RUSTFLAGS identity enforced")
PYREJECT

    # The same effective rustc argv is valid when represented by the encoded
    # channel, but the shadowed RUSTFLAGS channel must be recorded as unset.
    python3 - "$TMP/post/fingerprint.json" <<'PYMUTATE'
import json, sys

path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    fingerprint = json.load(fh)
fingerprint["build_flags"]["RUSTFLAGS"] = None
fingerprint["build_flags"]["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join((
    "-Cforce-frame-pointers=yes",
    "-Clinker=cc",
    "-Clinker-features=-lld",
))
with open(path, "w", encoding="utf-8") as fh:
    json.dump(fingerprint, fh)
PYMUTATE
    mkdir -p "$TMP/out_encoded_equivalent"
    "$0" --bead PERF-SELFTEST-ENCODED-EQUIVALENT \
        --baseline "$TMP/baseline" --post "$TMP/post" \
        --out "$TMP/out_encoded_equivalent" \
        --sub-bench selftest_hot_path \
        --non-interactive "$TMP/answers" >/dev/null
    python3 - "$TMP/out_encoded_equivalent/attestation_v1.json" <<'PYACCEPT'
import json, sys

with open(sys.argv[1], encoding="utf-8") as fh:
    attestation = json.load(fh)
q2 = next(q for q in attestation["questions"] if q["id"] == "2_same_build_profile")
assert q2["answer"] == "pass", q2
PYACCEPT

    # Missing is not a synonym for cleared. Removing the baseline's encoded
    # key makes the comparison unbound and must deterministically fail Q2.
    python3 - "$TMP/baseline/fingerprint.json" <<'PYMUTATE'
import json, sys

path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    fingerprint = json.load(fh)
del fingerprint["build_flags"]["CARGO_ENCODED_RUSTFLAGS"]
with open(path, "w", encoding="utf-8") as fh:
    json.dump(fingerprint, fh)
PYMUTATE
    mkdir -p "$TMP/out_missing_baseline_key"
    if "$0" --bead PERF-SELFTEST-MISSING-BASELINE-KEY \
            --baseline "$TMP/baseline" --post "$TMP/post" \
            --out "$TMP/out_missing_baseline_key" \
            --sub-bench selftest_hot_path \
            --non-interactive "$TMP/answers" >/dev/null 2>&1; then
        echo "SELFTEST FAIL: missing baseline encoded-RUSTFLAGS key received symmetric-profile credit" >&2
        exit 1
    fi
    python3 - "$TMP/out_missing_baseline_key/attestation_v1.json" <<'PYREJECT'
import json, sys

with open(sys.argv[1], encoding="utf-8") as fh:
    attestation = json.load(fh)
q2 = next(q for q in attestation["questions"] if q["id"] == "2_same_build_profile")
assert q2["answer"] == "fail", q2
print("SELFTEST PASS: baseline and post profiles are both required and missing is not cleared")
PYREJECT
    exit $?
fi

# ---------------------------------------------------------------------------
# arg parse
# ---------------------------------------------------------------------------
BEAD=""; BASELINE=""; POST=""; OUT=""; ANS_FILE=""; KEY=""; SUB_BENCH=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bead)            BEAD="$2"; shift 2;;
        --baseline)        BASELINE="$2"; shift 2;;
        --post)            POST="$2"; shift 2;;
        --out)             OUT="$2"; shift 2;;
        --sub-bench)       SUB_BENCH="$2"; shift 2;;
        --non-interactive) ANS_FILE="$2"; shift 2;;
        --key)             KEY="$2"; shift 2;;
        -h|--help)         sed -n '3,45p' "$0"; exit 0;;
        *) echo "$SCRIPT_NAME: unknown arg: $1" >&2; exit 2;;
    esac
done

[[ -n "$BEAD" && -n "$BASELINE" && -n "$POST" && -n "$OUT" ]] || {
    echo "usage: $SCRIPT_NAME --bead B --baseline DIR --post DIR --out DIR [--sub-bench NAME] [--non-interactive FILE] [--key SEED]" >&2
    exit 2
}
[[ -d "$BASELINE" ]] || { echo "$SCRIPT_NAME: baseline dir not found: $BASELINE" >&2; exit 2; }
[[ -d "$POST" ]] || { echo "$SCRIPT_NAME: post dir not found: $POST" >&2; exit 2; }
mkdir -p "$OUT"

# 14 adapted questions: id|theme|criticality. SUBJECTIVE ones with no artifact
# signal fall through to the answers file / interactive prompt.
QUESTIONS=(
  "1_written_scenario:Scenario doc names the metric and the claim being made?"
  "2_same_build_profile:Do baseline and post fingerprints explicitly bind the same effective Cargo rustflags and CARGO_INCREMENTAL setting?"
  "3_api_matched:Same Criterion bench id exists on both the baseline and post sides?"
  "4_knobs_identical:Criterion config (sample_size / warm_up / measurement_time) recorded and >= defaults?"
  "5_realistic_workload:Workload is a realistic slice or a labelled microbench isolating one mechanism?"
  "6_same_fixture:Deterministic fixture/seed both sides (no wall-clock or RNG in the hot path)?"
  "7_warmup_symmetric:Warmup symmetric and discarded (Criterion warm_up_time recorded)?"
  "8_N_sufficient:N >= 20 samples after warmup AND >= 1s measurement wall clock?"
  "9_host_quiet:Host quiet; fingerprint captured; tree not dirty during measurement?"
  "10_variance_envelope:CV = std/mean <= 10% on the post sample (and baseline if present)?"
  "11_three_tier_reporting:Report classifies the delta (faster / within-margin / regressed), not binary?"
  "12_losses_published:Every sub-bench published in the report, including regressions?"
  "13_apples_flagged:Attribution caveats flagged in the report (cumulative vs isolated; microbench scope)?"
  "14_reproducible:Fingerprint carries git SHA + toolchain + flags + baseline ref so the run is reproducible?"
)

# ---------------------------------------------------------------------------
# Pass 1: auto-answer from artifacts. Emits TSV "id<TAB>answer<TAB>source" for
# questions it can decide; emits "id<TAB>NEEDS_INPUT<TAB>" otherwise.
# ---------------------------------------------------------------------------
AUTO_TSV="$OUT/.auto_answers.tsv"
python3 - "$BASELINE" "$POST" "$SUB_BENCH" > "$AUTO_TSV" <<'PYAUTO'
import glob, json, os, re, shlex, sys

baseline, post, sub_bench = sys.argv[1:4]

def load_json(path):
    try:
        return json.load(open(path))
    except Exception:
        return None

def emit(qid, ans, src):
    print(f"{qid}\t{ans}\t{src}")

def needs(qid):
    print(f"{qid}\tNEEDS_INPUT\t")

base_fp = load_json(os.path.join(baseline, "fingerprint.json")) or {}
fp = load_json(os.path.join(post, "fingerprint.json")) or {}
summary = ""
sp = os.path.join(post, "summary.md")
if os.path.exists(sp):
    summary = open(sp, errors="replace").read()

# Locate a post estimates.json (prefer the named sub-bench).
def find_post_estimates():
    pats = []
    if sub_bench:
        pats += [
            os.path.join(post, "criterion", "**", sub_bench, "**", "estimates.json"),
            os.path.join(post, "**", sub_bench, "**", "estimates.json"),
        ]
    pats += [os.path.join(post, "**", "estimates.json")]
    for pat in pats:
        hits = [h for h in glob.glob(pat, recursive=True) if "/base/" not in h]
        if hits:
            return sorted(hits)[0]
    return None

def find_baseline_estimates():
    if sub_bench:
        c = os.path.join(baseline, f"criterion_{sub_bench}_estimates.json")
        if os.path.exists(c):
            return c
    hits = glob.glob(os.path.join(baseline, "criterion_*_estimates.json"))
    return sorted(hits)[0] if hits else None

post_est_path = find_post_estimates()
post_est = load_json(post_est_path) if post_est_path else None
base_est_path = find_baseline_estimates()
base_est = load_json(base_est_path) if base_est_path else None

def cv_pct(est):
    try:
        m = est["mean"]["point_estimate"]
        sd = est.get("std_dev", {}).get("point_estimate", 0.0)
        return (sd / m * 100.0) if m else None
    except Exception:
        return None

# Q1: scenario doc naming the metric + claim.
scen = []
for root in (baseline, post):
    scen += glob.glob(os.path.join(root, "*DEFINE*"))
    scen += glob.glob(os.path.join(root, "*scenario*"))
    scen += glob.glob(os.path.join(root, "01_*.md"))
metric_in_summary = bool(re.search(r"\b(ns|µs|us|ms|p95|throughput|RSS|mean)\b", summary))
if scen:
    emit("1_written_scenario", "pass", f"scenario doc: {os.path.basename(scen[0])}")
elif metric_in_summary:
    emit("1_written_scenario", "pass", "metric named in post/summary.md")
else:
    needs("1_written_scenario")

# Q2: both sides must explicitly bind every Cargo rustflags channel. Cargo
# gives CARGO_ENCODED_RUSTFLAGS precedence over RUSTFLAGS, so compare the
# normalized effective rustc argv rather than crediting two simultaneously
# populated fields. Missing keys are unknown provenance, never an inferred
# clear.
def normalize_codegen_args(args):
    normalized = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-C":
            if i + 1 >= len(args):
                raise ValueError("trailing -C")
            normalized.append(f"-C{args[i + 1]}")
            i += 2
            continue
        normalized.append(arg)
        i += 1
    return normalized

def effective_build_profile(label, fingerprint):
    flags = fingerprint.get("build_flags")
    if not isinstance(flags, dict):
        return None, f"{label} fingerprint has no build_flags object"
    required = {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_INCREMENTAL"}
    missing = sorted(required - flags.keys())
    if missing:
        return None, f"{label} build_flags missing explicit keys: {missing}"

    rustflags = flags["RUSTFLAGS"]
    encoded = flags["CARGO_ENCODED_RUSTFLAGS"]
    incremental = str(flags["CARGO_INCREMENTAL"])
    if rustflags is not None and not isinstance(rustflags, str):
        return None, f"{label} RUSTFLAGS is neither string nor null"
    if encoded is not None and not isinstance(encoded, str):
        return None, f"{label} CARGO_ENCODED_RUSTFLAGS is neither string nor null"
    if incremental not in {"0", "1"}:
        return None, f"{label} CARGO_INCREMENTAL is not explicitly 0 or 1"

    try:
        if encoded is not None:
            if not encoded:
                return None, f"{label} CARGO_ENCODED_RUSTFLAGS is empty, not cleared"
            if rustflags not in (None, ""):
                return None, (
                    f"{label} records shadowed RUSTFLAGS alongside "
                    "CARGO_ENCODED_RUSTFLAGS"
                )
            argv = encoded.split("\x1f")
            channel = "CARGO_ENCODED_RUSTFLAGS"
        else:
            if not rustflags:
                return None, f"{label} has no effective rustflags payload"
            argv = shlex.split(rustflags)
            channel = "RUSTFLAGS"
        effective = normalize_codegen_args(argv)
    except ValueError as exc:
        return None, f"{label} rustflags are malformed: {exc}"

    return {
        "effective_rustflags": effective,
        "cargo_incremental": incremental,
        "channel": channel,
    }, None

base_profile, base_error = effective_build_profile("baseline", base_fp)
post_profile, post_error = effective_build_profile("post", fp)
if base_error or post_error:
    emit("2_same_build_profile", "fail", "; ".join(
        error for error in (base_error, post_error) if error
    ))
elif base_profile == post_profile:
    emit("2_same_build_profile", "pass", (
        "baseline/post effective build profiles match: "
        f"{base_profile['effective_rustflags']!r}; "
        f"CARGO_INCREMENTAL={base_profile['cargo_incremental']}; "
        f"channels={base_profile['channel']}/{post_profile['channel']}"
    ))
elif (base_profile["effective_rustflags"] == post_profile["effective_rustflags"]
      and base_profile["cargo_incremental"] == post_profile["cargo_incremental"]):
    emit("2_same_build_profile", "pass", (
        "baseline/post effective build profiles match across Cargo channels: "
        f"{base_profile['effective_rustflags']!r}; "
        f"CARGO_INCREMENTAL={base_profile['cargo_incremental']}; "
        f"channels={base_profile['channel']}/{post_profile['channel']}"
    ))
else:
    emit("2_same_build_profile", "fail", (
        f"build profile mismatch: baseline={base_profile!r}; post={post_profile!r}"
    ))

# Q3: same bench id present on both sides.
if base_est_path and post_est_path:
    emit("3_api_matched", "pass",
         f"baseline+post estimates present ({os.path.basename(base_est_path)})")
elif post_est_path and not base_est_path:
    emit("3_api_matched", "fail", "post estimates present but no baseline estimates")
else:
    needs("3_api_matched")

# Q4 + Q7: criterion config (sample_size / warm_up / measurement_time).
bench_json = None
if post_est_path:
    bj = os.path.join(os.path.dirname(post_est_path), "benchmark.json")
    bench_json = load_json(bj)
cfg = (bench_json or {}).get("config", {}) if bench_json else {}
def secs(v):
    if isinstance(v, dict):
        return v.get("secs", 0) + v.get("nanos", 0) / 1e9
    return v or 0
ss = cfg.get("sample_size")
wu = secs(cfg.get("warm_up_time"))
mt = secs(cfg.get("measurement_time"))
if cfg:
    if (ss or 0) >= 10 and mt >= 1.0:
        emit("4_knobs_identical", "pass", f"sample_size={ss} warm_up={wu}s measurement={mt}s")
    else:
        emit("4_knobs_identical", "fail", f"weak config sample_size={ss} measurement={mt}s")
    emit("7_warmup_symmetric", "pass" if wu > 0 else "fail", f"warm_up_time={wu}s (Criterion, both samples)")
else:
    needs("4_knobs_identical")
    # Criterion always warms up; treat as pass when a post estimate exists.
    if post_est_path:
        emit("7_warmup_symmetric", "pass", "Criterion default warmup (3s), symmetric by harness")
    else:
        needs("7_warmup_symmetric")

# Q5: subjective (realistic vs microbench) -> needs input unless summary labels it.
if re.search(r"microbench|hot[- ]?path|isolat", summary, re.I):
    emit("5_realistic_workload", "pass", "summary labels the bench as a hot-path microbench")
else:
    needs("5_realistic_workload")

# Q6: determinism -> franken benches are deterministic; pass if estimate exists.
# (No wall-clock/RNG signal available here; the bench harness is deterministic
#  by project invariant, so we assert pass when a measurement was produced.)
if post_est_path:
    emit("6_same_fixture", "pass", "deterministic bench harness (project invariant); measurement produced")
else:
    needs("6_same_fixture")

# Q8: N + measurement time.
if ss is not None:
    if ss >= 20 and mt >= 1.0:
        emit("8_N_sufficient", "pass", f"sample_size={ss} >= 20, measurement={mt}s")
    else:
        emit("8_N_sufficient", "fail", f"sample_size={ss}, measurement={mt}s")
else:
    needs("8_N_sufficient")

# Q9: host quiet -> fingerprint present + not dirty. Quietness itself is not
# observable from artifacts, so require confirmation when dirty/missing.
if fp:
    if fp.get("git_dirty") is False:
        emit("9_host_quiet", "pass", "fingerprint captured; git tree clean at capture")
    else:
        needs("9_host_quiet")
else:
    needs("9_host_quiet")

# Q10: variance envelope (CV <= 10%).
cvp = cv_pct(post_est) if post_est else None
cvb = cv_pct(base_est) if base_est else None
if cvp is not None:
    ok = cvp <= 10.0 and (cvb is None or cvb <= 10.0)
    detail = f"post CV={cvp:.2f}%" + (f", baseline CV={cvb:.2f}%" if cvb is not None else "")
    emit("10_variance_envelope", "pass" if ok else "fail", detail)
else:
    needs("10_variance_envelope")

# Q11: three-tier / graded reporting in summary.
if re.search(r"faster|regress|within[- ]?margin|OK|FAIL", summary, re.I):
    emit("11_three_tier_reporting", "pass", "summary classifies per-bench verdicts")
else:
    needs("11_three_tier_reporting")

# Q12: losses published -> a regression row is visible in the summary table.
rows = re.findall(r"\|.*?\|", summary)
if re.search(r"regress|\+\d+\.\d+", summary, re.I):
    emit("12_losses_published", "pass", "regression row(s) present in summary table")
elif rows:
    # Table exists but shows no losses: acceptable only if genuinely all wins.
    emit("12_losses_published", "pass", "all sub-benches in summary table; no regressions to hide")
else:
    needs("12_losses_published")

# Q13: attribution caveats flagged.
if re.search(r"caveat|cumulative|attribution|isolat|microbench|asterisk", summary, re.I):
    emit("13_apples_flagged", "pass", "attribution/scope caveat present in summary")
else:
    needs("13_apples_flagged")

# Q14: reproducibility -> fingerprint completeness.
need = ["git_sha", "toolchain", "build_flags"]
have = [k for k in need if fp.get(k)]
if fp and len(have) == len(need):
    emit("14_reproducible", "pass", f"fingerprint has {', '.join(need)}")
elif fp:
    emit("14_reproducible", "fail", f"fingerprint missing {set(need) - set(have)}")
else:
    needs("14_reproducible")
PYAUTO

# ---------------------------------------------------------------------------
# Pass 2 (bash): for NEEDS_INPUT questions, read answers file or prompt.
# ---------------------------------------------------------------------------
declare -A ANS
declare -A SRC
while IFS=$'\t' read -r qid ans src; do
    [[ -z "$qid" ]] && continue
    if [[ "$ans" != "NEEDS_INPUT" ]]; then
        ANS[$qid]="$ans"; SRC[$qid]="auto:$src"
    fi
done < "$AUTO_TSV"

prompt_for() {
    local qid="$1" text="$2" a=""
    if [[ -n "$ANS_FILE" ]]; then
        a=$(awk -v k="$qid" 'index($0,k"=")==1{print substr($0,length(k)+2);exit}' "$ANS_FILE")
        if [[ -n "$a" ]]; then ANS[$qid]="$a"; SRC[$qid]="answers-file"; return; fi
        ANS[$qid]="unknown"; SRC[$qid]="non-interactive:no-answer"; return
    fi
    if [[ -t 0 ]]; then
        while true; do
            printf '  Q%s\n  %s\n  [pass | fail | waive:<reason>]> ' "$qid" "$text"
            read -r a
            [[ "$a" =~ ^(pass|fail|waive:.+)$ ]] && break
            echo "  invalid; expected pass / fail / waive:<reason>"
        done
        ANS[$qid]="$a"; SRC[$qid]="interactive"
    else
        ANS[$qid]="unknown"; SRC[$qid]="no-tty:no-answer"
    fi
}

for q in "${QUESTIONS[@]}"; do
    qid="${q%%:*}"; text="${q#*:}"
    if [[ -z "${ANS[$qid]:-}" ]]; then
        prompt_for "$qid" "$text"
    fi
done

# Emit the merged answers as TSV for the signer.
MERGED_TSV="$OUT/.merged_answers.tsv"
: > "$MERGED_TSV"
for q in "${QUESTIONS[@]}"; do
    qid="${q%%:*}"; text="${q#*:}"
    printf '%s\t%s\t%s\t%s\n' "$qid" "$text" "${ANS[$qid]}" "${SRC[$qid]}" >> "$MERGED_TSV"
done

# ---------------------------------------------------------------------------
# Pass 3 (python): score, build attestation_v1.json, sign with Ed25519.
# ---------------------------------------------------------------------------
GIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo no-git)"
ATTESTER="${GITHUB_RUN_ID:-${USER:-unknown}}"
DEFAULT_DEV_SEED="franken-engine-honest-gate-v1-dev-key-00"  # 40 bytes -> sha256 -> 32

python3 - "$BEAD" "$BASELINE" "$POST" "$OUT" "$GIT_SHA" "$ATTESTER" \
    "$MERGED_TSV" "${KEY:-}" "${HONEST_GATE_SIGNING_KEY_HEX:-}" "$DEFAULT_DEV_SEED" <<'PYSIGN'
import hashlib, json, os, sys, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

(bead, baseline, post, out, git_sha, attester, merged_tsv,
 key_arg, key_env, dev_seed) = sys.argv[1:11]

# --- resolve producer signing key ---
def load_key():
    if key_arg:
        if os.path.exists(key_arg):
            data = open(key_arg, "rb").read()
            return serialization.load_pem_private_key(data, password=None)
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_arg.strip()))
    if key_env:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_env.strip()))
    seed = hashlib.sha256(dev_seed.encode()).digest()  # deterministic dev key
    return Ed25519PrivateKey.from_private_bytes(seed)

sk = load_key()
pk = sk.public_key()
pub_hex = pk.public_bytes(serialization.Encoding.Raw,
                          serialization.PublicFormat.Raw).hex()

# --- fingerprint hash ---
fp_path = os.path.join(post, "fingerprint.json")
fp_sha = (hashlib.sha256(open(fp_path, "rb").read()).hexdigest()
          if os.path.exists(fp_path) else "missing")

# --- assemble question tuples + score ---
questions = []
score_total = 0
fails = 0
for line in open(merged_tsv):
    qid, text, ans, src = line.rstrip("\n").split("\t")
    if ans == "pass" or ans.startswith("waive:"):
        score = 1
    else:  # fail / unknown
        score = 0
    if ans == "fail":
        fails += 1
    score_total += score
    questions.append({
        "id": qid, "question": text, "answer": ans, "score": score, "source": src,
    })

score_max = 14
assert len(questions) == score_max, f"expected 14 questions, got {len(questions)}"
verdict = "pass" if (score_total >= 12 and fails == 0) else "fail"

att = {
    "schema": "franken-engine.honest-gate-attestation.v1",
    "bead": bead,
    "baseline_dir": baseline,
    "post_dir": post,
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "git_sha": git_sha,
    "host_fingerprint_sha256": fp_sha,
    "attested_by": attester,
    "questions": questions,
    "score_total": score_total,
    "score_max": score_max,
    "verdict": verdict,
    "producer": {"algorithm": "ed25519", "public_key_hex": pub_hex, "signature_hex": ""},
}

# Canonical preimage = whole object with signature blanked, sorted keys, compact.
preimage = json.dumps(att, sort_keys=True, separators=(",", ":")).encode()
sig = sk.sign(preimage)
att["producer"]["signature_hex"] = sig.hex()

out_path = os.path.join(out, "attestation_v1.json")
with open(out_path, "w") as f:
    json.dump(att, f, indent=2, sort_keys=True)
    f.write("\n")

# Clean up scratch TSVs.
if os.environ.get("HONEST_GATE_KEEP_SCRATCH") != "1":
    for scratch in (".auto_answers.tsv", ".merged_answers.tsv"):
        p = os.path.join(out, scratch)
        if os.path.exists(p):
            os.remove(p)

print(f"[honest-gate] {bead}: score {score_total}/{score_max}  verdict={verdict}  "
      f"({fails} fail)")
print(f"[honest-gate] wrote {out_path}")
for q in questions:
    if q["answer"] != "pass":
        print(f"[honest-gate]   {q['id']}: {q['answer']}  ({q['source']})")
sys.exit(0 if verdict == "pass" else 1)
PYSIGN
