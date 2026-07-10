#!/usr/bin/env bash
# E8 Non-Exfiltration Certificate demo (E8.T6, bd-fqlfw.8.6).
#
# "Prove the agent did not leak the secret." The data owner declares a
# machine-readable contract (labels, legal sinks, requested non-use claims);
# the engine runs the agent-generated code and emits a SIGNED certificate of
# what the code did NOT do — or refuses, fail-closed, with provenance.
#
#   Act 1  honest agent run        -> certified_within_analyzed_scope
#                                     (six-file signed bundle)
#   Act 2  Secret -> raw egress    -> run ABORTS before any certificate
#                                     exists (IFC runtime guard, fail-closed)
#   Act 3  smuggle via unanalyzed  -> certificate emitted but honestly
#          construct (for..of)        uncertified, span-level provenance
#   Act 4  agent-sandbox membrane  -> unknown tool tag refused; a proper
#                                     manifest yields the bundle with the
#                                     agent's EXACT effective authority
#
# Threat model boundary: docs/E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md
# Positioning narrative:  docs/E8_STRATEGIC_POSITIONING_V1.md
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
cd "$repo_root"

# Locate the binary (prefer $FRANKENCTL_BIN, then release, then debug).
bin=""
if [[ -n "${FRANKENCTL_BIN:-}" && -x "${FRANKENCTL_BIN}" ]]; then
  bin="${FRANKENCTL_BIN}"
elif [[ -x target/release/frankenctl ]]; then
  bin="target/release/frankenctl"
elif [[ -x target/debug/frankenctl ]]; then
  bin="target/debug/frankenctl"
else
  echo "frankenctl not found. Build it first:" >&2
  echo "  cargo build --release -p frankenengine-engine --bin frankenctl" >&2
  exit 2
fi

out="$script_dir/out"
rm -rf "$out"
mkdir -p "$out"

step() { printf '\n=== %s ===\n' "$*"; }

# ---------------------------------------------------------------------------
# The agent-generated code. The honest step is written entirely inside the
# analyzed explicit-flow subset (bd-fqlfw.8.4); the smuggle step launders the
# secret through a for..of iterator lane, which is UNPROVEN in v1 and must
# therefore refuse certification.
# ---------------------------------------------------------------------------
cat > "$out/agent_honest.js" <<'JS'
const tickets = ['refund window', 'login loop', 'invoice typo'];
const severity = [2, 3, 1];
let worst = 0;
let index = 0;
for (let i = 0; i < severity.length; i = i + 1) {
  if (severity[i] > worst) {
    worst = severity[i];
    index = i;
  }
}
const summary = 'top issue: ' + tickets[index] + ' (severity ' + worst + ')';
JS

cat > "$out/agent_smuggle.js" <<'JS'
const secret = 'sk-live-0000-EXFIL-ME';
const laundered = [];
for (const ch of secret) {
  laundered.push(ch);
}
const out = laundered.join('');
JS

# ---------------------------------------------------------------------------
# The data-owner's contract: Confidential run input, one audited sink, three
# requested non-use claims. The binding pins the exact input path.
# ---------------------------------------------------------------------------
contract() {
  local contract_id="$1" input_path="$2" label="$3"
  cat <<JSON
{
  "schema_version": "franken-engine.data-contract.v1",
  "contract_id": "${contract_id}",
  "extension_id": "agent-support-summarizer",
  "input_bindings": [
    {
      "binding_id": "support-ticket-batch",
      "object_ref": "object://support-ticket-batch",
      "path": "${input_path}",
      "label": "${label}",
      "owner": "data-owner",
      "role": "run_input",
      "allowed_purposes": ["runtime_execution"]
    }
  ],
  "allowed_purposes": ["runtime_execution"],
  "allowed_capabilities": ["VmDispatch", "HeapAllocate", "Builtin", "Console"],
  "allowed_sinks": [
    {
      "sink_id": "audited-summary-report",
      "clearance": "AuditedSink",
      "location": "report://weekly-summary",
      "allowed_labels": ["Public", "Internal", "Confidential"]
    }
  ],
  "required_declassification_routes": [],
  "requested_output_claims": [
    {
      "claim_type": "no_flow",
      "claim_id": "no-secret-open-sink",
      "source_label": "Secret",
      "sink_clearance": "OpenSink"
    },
    {
      "claim_type": "capability_not_used",
      "claim_id": "no-process-spawn",
      "capability": "ProcessSpawn"
    },
    {
      "claim_type": "capability_not_used",
      "claim_id": "no-network-egress",
      "capability": "NetworkEgress"
    }
  ]
}
JSON
}

contract "contract-support-summary" "$out/agent_honest.js" "Confidential" \
  > "$out/contract_honest.json"
contract "contract-smuggle" "$out/agent_smuggle.js" "Confidential" \
  > "$out/contract_smuggle.json"

# Act 2's contract: the input is Secret and the only declared sink is raw
# network egress that may legally receive Public only.
cat > "$out/contract_secret_egress.json" <<JSON
{
  "schema_version": "franken-engine.data-contract.v1",
  "contract_id": "contract-secret-egress",
  "extension_id": "agent-support-summarizer",
  "input_bindings": [
    {
      "binding_id": "api-key-context",
      "object_ref": "object://api-key-context",
      "path": "$out/agent_honest.js",
      "label": "Secret",
      "owner": "data-owner",
      "role": "run_input",
      "allowed_purposes": ["runtime_execution"]
    }
  ],
  "allowed_purposes": ["runtime_execution"],
  "allowed_capabilities": ["VmDispatch", "HeapAllocate", "Builtin"],
  "allowed_sinks": [
    {
      "sink_id": "raw-web-egress",
      "clearance": "NeverSink",
      "location": "net://egress",
      "allowed_labels": ["Public"]
    }
  ],
  "required_declassification_routes": [],
  "requested_output_claims": [
    {
      "claim_type": "no_flow",
      "claim_id": "no-secret-open-sink",
      "source_label": "Secret",
      "sink_clearance": "OpenSink"
    }
  ]
}
JSON

step "Act 1) honest agent run -> certified_within_analyzed_scope"
"$bin" run --input "$out/agent_honest.js" \
  --extension-id agent-support-summarizer \
  --data-contract "$out/contract_honest.json" \
  --explain --explain-out "$out/honest.explain.json" \
  --certificate-out "$out/certified_bundle" \
  --out "$out/honest.run.json" >/dev/null
grep -q '"certificate_status": "certified_within_analyzed_scope"' \
  "$out/certified_bundle/non_use_certificate.json"
echo "signed six-file bundle:"
ls "$out/certified_bundle"
echo
echo "claim verdicts (from audit.md):"
grep -A 4 '| claim id |' "$out/certified_bundle/audit.md"
echo
echo "certificate status: certified_within_analyzed_scope"

step "Act 2) Secret -> raw egress: the run ABORTS fail-closed (no certificate)"
if "$bin" run --input "$out/agent_honest.js" \
  --extension-id agent-support-summarizer \
  --data-contract "$out/contract_secret_egress.json" \
  --explain --explain-out "$out/egress.explain.json" \
  --certificate-out "$out/egress_bundle" \
  --out "$out/egress.run.json" > "$out/egress.stdout" 2> "$out/egress.stderr"; then
  echo "UNEXPECTED: the Secret->egress run should have been blocked" >&2
  exit 1
fi
grep -q 'ifc runtime guard blocked execution' "$out/egress.stderr"
grep -q 'raw-web-egress' "$out/egress.stderr"
if [[ -d "$out/egress_bundle" ]]; then
  echo "UNEXPECTED: a certificate bundle exists for the blocked run" >&2
  exit 1
fi
echo "no bundle directory was created"
sed 's/^/  /' "$out/egress.stderr" | head -2
echo "the flow was refused BEFORE execution could leak — not logged after"

step "Act 3) smuggle via for..of (unproven iterator lane) -> honest uncertified"
"$bin" run --input "$out/agent_smuggle.js" \
  --extension-id agent-support-summarizer \
  --data-contract "$out/contract_smuggle.json" \
  --explain --explain-out "$out/smuggle.explain.json" \
  --certificate-out "$out/smuggle_bundle" \
  --out "$out/smuggle.run.json" >/dev/null
grep -q '"certificate_status": "uncertified"' \
  "$out/smuggle_bundle/non_use_certificate.json"
grep -q 'unproven_ifc_propagation' "$out/smuggle.run.json"
echo "certificate emitted, status: uncertified (never a false non-use pass)"
echo "refusal provenance (from the preflight receipt): the unproven lanes are named"
grep -o '"id": "unproven-[0-9]*-[a-z_]*"' "$out/smuggle.run.json" \
  | sed 's/.*"unproven-[0-9]*-\([a-z_]*\)"/  unproven lane: \1/' | sort -u

step "Act 4a) agent-sandbox: unknown tool tag is refused, not silently dropped"
cat > "$out/manifest_unknown_tool.json" <<'JSON'
{
  "schema_version": "franken-engine.agent-sandbox-manifest.v1",
  "agent_id": "agent-support-summarizer",
  "tool_grants": [
    { "tool_name": "shell", "capability_tag": "spawn_anything" }
  ],
  "purpose": "runtime_execution"
}
JSON
if "$bin" agent-sandbox --manifest "$out/manifest_unknown_tool.json" \
  --input "$out/agent_honest.js" > /dev/null 2> "$out/unknown_tool.stderr"; then
  echo "UNEXPECTED: unknown tool tag should be refused" >&2
  exit 1
fi
grep -q 'unknown capability tag' "$out/unknown_tool.stderr"
sed 's/^/  /' "$out/unknown_tool.stderr" | head -2

step "Act 4b) agent-sandbox: the tool-runner shim an agent framework consumes"
cat > "$out/sandbox_manifest.json" <<'JSON'
{
  "schema_version": "franken-engine.agent-sandbox-manifest.v1",
  "agent_id": "agent-support-summarizer",
  "tool_grants": [
    {
      "tool_name": "log",
      "capability_tag": "console",
      "description": "write to the sandboxed console"
    }
  ],
  "denied_capability_tags": ["process_spawn", "network"],
  "purpose": "runtime_execution"
}
JSON
"$bin" agent-sandbox --manifest "$out/sandbox_manifest.json" \
  --input "$out/agent_honest.js" \
  --data-contract "$out/contract_honest.json" \
  --certificate-out "$out/sandbox_bundle" \
  --out "$out/sandbox.report.json" > "$out/sandbox.stdout"
grep -q '"certificate_status": "uncertified"' \
  "$out/sandbox_bundle/non_use_certificate.json"
echo "bundle emitted; the certificate reports the AGENT's authority:"
grep -A 4 '"effective_capabilities"' "$out/sandbox.report.json" | sed 's/^/  /'
echo "  (grants + forced VM baseline only — the CLI profile is never inherited)"
echo "v1 sandbox lane stays honestly uncertified: it has no explain-bundle"
echo "evidence surface yet, and the certifier refuses to overclaim without it"

step "done"
echo "artifacts preserved under: $out/"
echo "positioning narrative: docs/E8_STRATEGIC_POSITIONING_V1.md"
echo "threat-model boundary:  docs/E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md"
