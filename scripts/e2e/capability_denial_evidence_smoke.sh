#!/usr/bin/env bash
# bd-9vouw.61: End-to-end smoke gate for runtime capability-denial and lowering-rejection
# signed, hash-chained evidence reports and strict replay verification.
#
# Runs three canonical cases under `frankenctl run`:
#   1. `denied_fetch`          — runtime capability denial (`fetch(...)` without network grant)
#   2. `rejected_lowering_env` — lowering-time ambient-authority refusal (`process.env`)
#   3. `allowed_baseline`      — benign allowed script control case
#
# Logs into `artifacts/capability_denial_evidence_smoke/<ts>/`:
#   - `events.jsonl`  (exit_code, outcome, entry_id, signature_key_id, chain_head, guardplane_decision)
#   - `summary.json`  (case counts, chain/signature/replay verification verdicts)
#   - `commands.txt`  (exact CLI commands executed)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}" || exit 1

frankenctl_bin="${FRANKENCTL_BIN:-}"
if [[ -z "${frankenctl_bin}" ]]; then
  if [[ -x "target/release/frankenctl" ]]; then
    frankenctl_bin="target/release/frankenctl"
  else
    for candidate in .rch-target-*/release/frankenctl; do
      if [[ -x "${candidate}" ]]; then
        frankenctl_bin="${candidate}"
        break
      fi
    done
  fi
fi

if [[ -z "${frankenctl_bin}" || ! -x "${frankenctl_bin}" ]]; then
  printf 'frankenctl binary not executable (set FRANKENCTL_BIN=...)\n' >&2
  exit 2
fi
frankenctl_abs="$(cd "$(dirname "${frankenctl_bin}")" && pwd)/$(basename "${frankenctl_bin}")"

run_ts="${CAPABILITY_DENIAL_SMOKE_TS:-$(date -u +%Y%m%dT%H%M%SZ)}"
artifact_root="${CAPABILITY_DENIAL_ARTIFACT_ROOT:-artifacts/capability_denial_evidence_smoke}"
out_dir="${repo_root}/${artifact_root}/${run_ts}"
mkdir -p "${out_dir}"

python3 - "${frankenctl_abs}" "${out_dir}" <<'PY'
import hashlib
import json
import subprocess
import sys
from pathlib import Path

frankenctl = Path(sys.argv[1])
out_dir = Path(sys.argv[2])
inputs_dir = out_dir / "inputs"
cases_dir = out_dir / "cases"
inputs_dir.mkdir(parents=True, exist_ok=True)
cases_dir.mkdir(parents=True, exist_ok=True)

commands_log: list[str] = []
events: list[dict] = []
failures: list[str] = []


def canonical_json_bytes(val) -> bytes:
    if isinstance(val, dict):
        items = ",".join(
            f"{json.dumps(k, ensure_ascii=False)}:{canonical_json_bytes(val[k]).decode('utf-8')}"
            for k in sorted(val.keys())
        )
        return ("{" + items + "}").encode("utf-8")
    if isinstance(val, list):
        return (
            "["
            + ",".join(canonical_json_bytes(item).decode("utf-8") for item in val)
            + "]"
        ).encode("utf-8")
    return json.dumps(val, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def trust_snapshot_digest_hex(trust_path: Path) -> str:
    data = json.loads(trust_path.read_text(encoding="utf-8"))
    payload = b"franken-engine.evidence-trust-snapshot.v1\x00" + canonical_json_bytes(data)
    return hashlib.sha256(payload).hexdigest()


def verify_trust_binding(artifact: dict, trust_path: Path, case_id: str) -> tuple[str, str, str]:
    entries = artifact.get("entries") or []
    receipt = artifact.get("receipt") or {}
    if not entries:
        failures.append(f"{case_id}: evidence_chain_artifact has zero entries")
        return "", "", ""
    first = entries[0]
    entry_id = first.get("entry_id") or ""
    signed_env = first.get("signed_envelope") or {}
    key_prov = signed_env.get("key_provenance") or {}
    key_id = key_prov.get("key_id") or ""
    producer_id = signed_env.get("producer_id") or ""
    chain_head = receipt.get("head_chain_hash") or ""
    receipt_env = receipt.get("signed_envelope") or {}
    if not entry_id or not key_id or not chain_head:
        failures.append(
            f"{case_id}: missing entry_id={entry_id!r}, key_id={key_id!r}, or chain_head={chain_head!r}"
        )
    if (signed_env.get("signature") or {}) == {} or (receipt_env.get("signature") or {}) == {}:
        failures.append(f"{case_id}: missing detached Ed25519 signature envelope")
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    identities = trust.get("identities") or []
    matched = [
        ident
        for ident in identities
        if ident.get("producer_id") == producer_id
        and (ident.get("key_provenance") or {}).get("key_id") == key_id
    ]
    if not matched:
        failures.append(
            f"{case_id}: signer {producer_id}/{key_id} not anchored in emitted trust snapshot"
        )
    links = receipt.get("links") or []
    if len(links) != len(entries):
        failures.append(
            f"{case_id}: receipt len(links)={len(links)} != len(entries)={len(entries)}"
        )
    return entry_id, key_id, chain_head


# 1. Runtime capability denial (`fetch`)
denied_js = inputs_dir / "denied_fetch.js"
denied_js.write_text(
    "console.log('before'); fetch('http://198.51.100.7/ping'); console.log('after');\n",
    encoding="utf-8",
)
denied_report = cases_dir / "denied_fetch.report.json"
denied_trust = cases_dir / "denied_fetch.trust.json"
denied_cmd = [
    str(frankenctl),
    "run",
    "--input",
    str(denied_js),
    "--extension-id",
    "smoke-denied-fetch",
    "--emit-evidence-trust",
    str(denied_trust),
    "--out",
    str(denied_report),
]
commands_log.append(" ".join(denied_cmd))
denied_proc = subprocess.run(denied_cmd, capture_output=True, text=True)
if denied_proc.returncode != 2:
    failures.append(f"denied_fetch: expected exit 2, got {denied_proc.returncode}")
if not denied_report.is_file() or not denied_trust.is_file():
    failures.append("denied_fetch: report or trust snapshot was not written")
else:
    d_json = json.loads(denied_report.read_text(encoding="utf-8"))
    d_outcome = d_json.get("outcome")
    if d_outcome != "capability_denied":
        failures.append(f"denied_fetch: expected outcome=capability_denied, got {d_outcome!r}")
    d_artifact = d_json.get("committed_evidence_chain") or (
        (d_json.get("uncommitted_evidence_chain") or {}).get("artifact")
    ) or {}
    entry_id, key_id, chain_head = verify_trust_binding(
        d_artifact, denied_trust, "denied_fetch"
    )
    d_entries = d_artifact.get("entries") or []
    denial_entry = next(
        (e for e in d_entries if (e.get("metadata") or {}).get("outcome") == "capability_denied"),
        None,
    )
    if denial_entry is None:
        failures.append("denied_fetch: missing capability_denied evidence entry")
        gp_decision = "missing"
    else:
        gp_decision = (denial_entry.get("chosen_action") or {}).get("action_name", "missing")
        denied_cap = (denial_entry.get("metadata") or {}).get("denied_capability", "")
        if "net" not in denied_cap:
            failures.append(f"denied_fetch: expected network capability denial, got {denied_cap!r}")

    d_digest = d_json.get("evidence_trust_snapshot_digest") or trust_snapshot_digest_hex(denied_trust)
    replay_out = cases_dir / "denied_fetch.replay.json"
    replay_cmd = [
        str(frankenctl),
        "replay",
        "run",
        "--trace",
        str(denied_report),
        "--mode",
        "strict",
        "--trust-snapshot",
        str(denied_trust),
        "--expected-trust-digest",
        d_digest,
        "--out",
        str(replay_out),
    ]
    commands_log.append(" ".join(replay_cmd))
    replay_proc = subprocess.run(replay_cmd, capture_output=True, text=True)
    if replay_proc.returncode != 0:
        failures.append(
            f"denied_fetch: strict replay failed rc={replay_proc.returncode}: {replay_proc.stderr.strip()}"
        )
    else:
        r_json = json.loads(replay_out.read_text(encoding="utf-8"))
        if not r_json.get("complete") or not r_json.get("evidence_authenticated"):
            failures.append(f"denied_fetch: strict replay incomplete/unauthenticated: {r_json}")

    # Negative tamper check: mutate expected outcome in a copy and assert strict replay rejects it.
    tampered_report = cases_dir / "denied_fetch.tampered.report.json"
    tampered = json.loads(denied_report.read_text(encoding="utf-8"))
    tampered["evidence_chain_head"] = "0" * 64
    tampered_report.write_text(json.dumps(tampered, indent=2) + "\n", encoding="utf-8")
    tamper_cmd = [
        str(frankenctl),
        "replay",
        "run",
        "--trace",
        str(tampered_report),
        "--mode",
        "strict",
        "--trust-snapshot",
        str(denied_trust),
        "--expected-trust-digest",
        d_digest,
    ]
    commands_log.append(" ".join(tamper_cmd))
    tamper_proc = subprocess.run(tamper_cmd, capture_output=True, text=True)
    if tamper_proc.returncode == 0:
        failures.append("denied_fetch: tampered chain head was unexpectedly accepted by strict replay")

    events.append(
        {
            "case_id": "denied_fetch",
            "exit_code": denied_proc.returncode,
            "outcome": d_outcome,
            "evidence_entry_id": entry_id,
            "signature_key_id": key_id,
            "chain_head": chain_head,
            "guardplane_decision": gp_decision,
            "strict_replay_verified": replay_proc.returncode == 0,
            "tamper_rejected": tamper_proc.returncode != 0,
        }
    )

# 2. Lowering-time rejection (`process.env`)
rejected_js = inputs_dir / "rejected_env.js"
rejected_js.write_text("console.log(Object.keys(process.env).length);\n", encoding="utf-8")
rejected_report = cases_dir / "rejected_env.report.json"
rejected_trust = cases_dir / "rejected_env.trust.json"
rejected_cmd = [
    str(frankenctl),
    "run",
    "--input",
    str(rejected_js),
    "--extension-id",
    "smoke-rejected-env",
    "--emit-evidence-trust",
    str(rejected_trust),
    "--out",
    str(rejected_report),
]
commands_log.append(" ".join(rejected_cmd))
rejected_proc = subprocess.run(rejected_cmd, capture_output=True, text=True)
if rejected_proc.returncode != 2:
    failures.append(f"rejected_lowering_env: expected exit 2, got {rejected_proc.returncode}")
if not rejected_report.is_file() or not rejected_trust.is_file():
    failures.append("rejected_lowering_env: report or trust snapshot was not written")
else:
    rej_json = json.loads(rejected_report.read_text(encoding="utf-8"))
    rej_outcome = rej_json.get("outcome")
    if rej_outcome != "rejected_at_lowering":
        failures.append(
            f"rejected_lowering_env: expected outcome=rejected_at_lowering, got {rej_outcome!r}"
        )
    rej_artifact = rej_json.get("evidence_chain_artifact") or {}
    entry_id, key_id, chain_head = verify_trust_binding(
        rej_artifact, rejected_trust, "rejected_lowering_env"
    )
    rej_entries = rej_artifact.get("entries") or []
    rej_entry = rej_entries[0] if rej_entries else {}
    gp_decision = (rej_entry.get("chosen_action") or {}).get("action_name", "missing")
    rejection_detail = rej_json.get("rejection") or {}
    if rejection_detail.get("accessor") != "process.env":
        failures.append(f"rejected_lowering_env: unexpected rejection payload {rejection_detail}")
    if ((rejection_detail.get("span") or {}).get("start_line")) != 1:
        failures.append(f"rejected_lowering_env: missing source span in {rejection_detail}")

    events.append(
        {
            "case_id": "rejected_lowering_env",
            "exit_code": rejected_proc.returncode,
            "outcome": rej_outcome,
            "evidence_entry_id": entry_id,
            "signature_key_id": key_id,
            "chain_head": chain_head,
            "guardplane_decision": gp_decision,
            "violated_effect": rejection_detail.get("required_effect"),
            "span_start_line": (rejection_detail.get("span") or {}).get("start_line"),
        }
    )

# 3. Allowed control script
allowed_js = inputs_dir / "allowed_ok.js"
allowed_js.write_text("console.log('allowed', 2 + 2);\n", encoding="utf-8")
allowed_report = cases_dir / "allowed_ok.report.json"
allowed_trust = cases_dir / "allowed_ok.trust.json"
allowed_cmd = [
    str(frankenctl),
    "run",
    "--input",
    str(allowed_js),
    "--extension-id",
    "smoke-allowed-ok",
    "--emit-evidence-trust",
    str(allowed_trust),
    "--out",
    str(allowed_report),
]
commands_log.append(" ".join(allowed_cmd))
allowed_proc = subprocess.run(allowed_cmd, capture_output=True, text=True)
if allowed_proc.returncode != 0:
    failures.append(f"allowed_baseline: expected exit 0, got {allowed_proc.returncode}")
if not allowed_report.is_file() or not allowed_trust.is_file():
    failures.append("allowed_baseline: report or trust snapshot was not written")
else:
    ok_json = json.loads(allowed_report.read_text(encoding="utf-8"))
    ok_artifact = ok_json.get("evidence_chain_artifact") or {}
    entry_id, key_id, chain_head = verify_trust_binding(
        ok_artifact, allowed_trust, "allowed_baseline"
    )
    gp_decision = ok_json.get("containment_action", "missing")
    ok_digest = ok_json.get("evidence_trust_snapshot_digest")
    if not ok_digest:
        failures.append("allowed_baseline: missing evidence_trust_snapshot_digest")
        ok_replay_rc = -1
    else:
        ok_replay_out = cases_dir / "allowed_ok.replay.json"
        ok_replay_cmd = [
            str(frankenctl),
            "replay",
            "run",
            "--trace",
            str(allowed_report),
            "--mode",
            "strict",
            "--trust-snapshot",
            str(allowed_trust),
            "--expected-trust-digest",
            ok_digest,
            "--out",
            str(ok_replay_out),
        ]
        commands_log.append(" ".join(ok_replay_cmd))
        ok_replay_proc = subprocess.run(ok_replay_cmd, capture_output=True, text=True)
        ok_replay_rc = ok_replay_proc.returncode
        if ok_replay_rc != 0:
            failures.append(
                f"allowed_baseline: strict replay failed rc={ok_replay_rc}: {ok_replay_proc.stderr.strip()}"
            )

    events.append(
        {
            "case_id": "allowed_baseline",
            "exit_code": allowed_proc.returncode,
            "outcome": "completed",
            "evidence_entry_id": entry_id,
            "signature_key_id": key_id,
            "chain_head": chain_head,
            "guardplane_decision": gp_decision,
            "strict_replay_verified": ok_replay_rc == 0,
        }
    )

(out_dir / "commands.txt").write_text("\n".join(commands_log) + "\n", encoding="utf-8")
(out_dir / "events.jsonl").write_text(
    "\n".join(json.dumps(ev, sort_keys=True) for ev in events) + "\n",
    encoding="utf-8",
)
summary = {
    "schema_version": "franken-engine.capability-denial-evidence-smoke.v1",
    "bead_id": "bd-9vouw.61",
    "case_count": len(events),
    "failure_count": len(failures),
    "failures": failures,
    "pass": len(failures) == 0 and len(events) == 3,
}
(out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2))
if failures:
    sys.exit(1)
PY
