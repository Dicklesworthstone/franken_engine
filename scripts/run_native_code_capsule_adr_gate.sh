#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit

strict_gate_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly strict_gate_script_dir

# The strict v2 validator owns parsing, state authorization, mutation tests,
# source verification, and two-phase evidence publication. The historical v1
# body below is intentionally unreachable; AGENTS.md forbids deleting it
# without explicit user permission.
exec python3 "${strict_gate_script_dir}/native_code_capsule_adr_validator.py" "$@"

readonly SCRIPT_SCHEMA="franken-engine.native-code-capsule-adr-gate.v1"
readonly EVENT_SCHEMA="franken-engine.native-code-capsule-adr-event.v1"
readonly MANIFEST_SCHEMA="franken-engine.native-code-capsule-decision.v1"
readonly BEAD_ID="bd-performance-conformance-bridge-tu32j.6.1"
readonly SOURCE_CUTOFF="2026-07-24"
readonly DEFAULT_SEED="1001001"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "${script_dir}/.." && pwd)"
readonly repo_root

mode="check"
require_authorized=false
output_root="${repo_root}/artifacts/native_code_capsule_adr"
decision_path="${repo_root}/docs/adr/native_code_capsule_decision_v1.json"
adr_path="${repo_root}/docs/adr/ADR-0010-native-code-capsule-trust-boundary.md"
plan_path="${repo_root}/docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md"
engine_split_path="${repo_root}/docs/REPO_SPLIT_CONTRACT.md"
node_repo="${FRANKEN_NODE_REPO:-${repo_root}/../franken_node}"
node_split_path="${node_repo}/docs/ENGINE_SPLIT_CONTRACT.md"
seed="${NATIVE_CAPSULE_ADR_SEED:-${DEFAULT_SEED}}"

declare -a validation_codes=()
declare -a validation_messages=()
declare -a self_test_ids=()
declare -a self_test_results=()
declare -a self_test_expected_codes=()
declare -a self_test_observed_codes=()

payload_digest=""
decision_status=""
implementation_authorized="false"

usage() {
  printf '%s\n' \
    "usage: $0 [check|self-test|ci] [options]" \
    "" \
    "Options:" \
    "  --require-authorized       Reject a valid proposed decision." \
    "  --output-root PATH         Root for immutable CI evidence bundles." \
    "  --decision PATH            Override decision JSON." \
    "  --adr PATH                 Override ADR Markdown." \
    "  --plan PATH                Override authoritative plan." \
    "  --engine-split PATH        Override engine split contract." \
    "  --node-split PATH          Override product split contract." \
    "  --seed N                   Deterministic self-test seed." \
    "  -h, --help                 Show this help."
}

if [[ $# -gt 0 && "$1" != --* ]]; then
  mode="$1"
  shift
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-authorized)
      require_authorized=true
      shift
      ;;
    --output-root)
      output_root="${2:?--output-root requires a path}"
      shift 2
      ;;
    --decision)
      decision_path="${2:?--decision requires a path}"
      shift 2
      ;;
    --adr)
      adr_path="${2:?--adr requires a path}"
      shift 2
      ;;
    --plan)
      plan_path="${2:?--plan requires a path}"
      shift 2
      ;;
    --engine-split)
      engine_split_path="${2:?--engine-split requires a path}"
      shift 2
      ;;
    --node-split)
      node_split_path="${2:?--node-split requires a path}"
      shift 2
      ;;
    --seed)
      seed="${2:?--seed requires a value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$mode" in
  check|self-test|ci) ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    usage >&2
    exit 2
    ;;
esac

if [[ ! "$seed" =~ ^[A-Za-z0-9._:-]{1,128}$ ]]; then
  printf 'invalid seed: use 1-128 ASCII letters, digits, dot, underscore, colon, or hyphen\n' >&2
  exit 2
fi

hash_text() {
  printf '%s' "$1" | sha256sum | cut -d' ' -f1
}

hash_file() {
  sha256sum "$1" | cut -d' ' -f1
}

add_error() {
  validation_codes+=("$1")
  validation_messages+=("$2")
}

has_error() {
  local expected="$1"
  local observed
  for observed in "${validation_codes[@]}"; do
    if [[ "$observed" == "$expected" ]]; then
      return 0
    fi
  done
  return 1
}

join_codes() {
  local joined=""
  local code
  for code in "${validation_codes[@]}"; do
    if [[ -n "$joined" ]]; then
      joined+=","
    fi
    joined+="$code"
  done
  printf '%s' "$joined"
}

require_tools() {
  local tool_name
  for tool_name in jq sha256sum python3 sed tr; do
    if ! command -v "$tool_name" >/dev/null 2>&1; then
      add_error "NCC-TOOL-MISSING" "required tool is unavailable: ${tool_name}"
    fi
  done
}

reject_duplicate_json_keys() {
  local manifest_text="$1"
  python3 -c '
import json
import sys

def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

json.load(sys.stdin, object_pairs_hook=reject_duplicates)
' <<<"$manifest_text" >/dev/null
}

compute_proposed_payload_digest() {
  local manifest_text="$1"
  local canonical
  canonical="$(
    jq -cS '
      .status = "proposed"
      | .implementation_authorized = false
      | .approval = null
    ' <<<"$manifest_text"
  )"
  hash_text "$canonical"
}

require_literal() {
  local text="$1"
  local literal="$2"
  local code="$3"
  local message="$4"
  if [[ "$text" == *"$literal"* ]]; then
    return
  fi

  local normalized_text normalized_literal
  normalized_text="$(
    printf '%s' "$text" \
      | tr '\r\n\t' '   ' \
      | sed -E 's/[[:space:]]+/ /g'
  )"
  normalized_literal="$(
    printf '%s' "$literal" \
      | tr '\r\n\t' '   ' \
      | sed -E 's/[[:space:]]+/ /g'
  )"
  if [[ "$normalized_text" != *"$normalized_literal"* ]]; then
    add_error "$code" "$message"
  fi
}

validate_exact_top_level_schema() {
  local manifest_text="$1"
  if ! jq -e '
    (keys | sort) == ([
      "approval",
      "claim_rules",
      "contract_marker",
      "decision_id",
      "dependency_direction",
      "document_sync",
      "engine_authorization",
      "forbidden_dependency_direction",
      "governing_bead",
      "implementation_authorized",
      "lifecycle",
      "packages",
      "platform_owners",
      "process_roles",
      "region_code_object",
      "repositories",
      "research_cutoff",
      "schema_version",
      "selected_backend",
      "source_claims",
      "source_locks",
      "status",
      "trust_profiles",
      "unsafe_boundary"
    ] | sort)
  ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-SCHEMA-TOP-LEVEL" \
      "decision JSON has missing, extra, or renamed top-level fields"
  fi
}

validate_fixed_identity() {
  local manifest_text="$1"
  if ! jq -e --arg schema "$MANIFEST_SCHEMA" --arg bead "$BEAD_ID" \
    --arg cutoff "$SOURCE_CUTOFF" '
      .schema_version == $schema
      and .decision_id == "ADR-0010"
      and .contract_marker == "NCC-ADR-0010-V1"
      and .governing_bead == $bead
      and .research_cutoff == $cutoff
      and .repositories == {
        "capsule": "/dp/franken_native_capsule",
        "engine": "/dp/franken_engine",
        "product": "/dp/franken_node"
      }
      and .packages == {
        "api": "frankenengine-native-capsule-api",
        "runtime": "frankenengine-native-capsule",
        "worker": "franken-native-capsule-worker"
      }
    ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-IDENTITY-DRIFT" \
      "decision identity, repositories, packages, bead, or cutoff drifted"
  fi
}

validate_process_roles() {
  local manifest_text="$1"
  local expected_roles='[
    {
      "id": "capsule-compilation-worker",
      "owner": "franken_native_capsule",
      "package": "franken-native-capsule-worker",
      "contains_javascript_heap": false,
      "runs_untrusted_guest_machine_code": false,
      "loads_capsule_runtime_for_platform_self_tests_only": true,
      "containment_claim": "compiler-fault-containment-only"
    },
    {
      "id": "engine-execution-cell-worker",
      "owner": "franken_engine",
      "contains_javascript_heap": true,
      "runs_untrusted_guest_machine_code": true,
      "loads_capsule_runtime": true,
      "containment_claim": "whole-execution-cell-child-process"
    },
    {
      "id": "product-supervisor",
      "owner": "franken_node",
      "contains_javascript_heap": false,
      "runs_untrusted_guest_machine_code": false,
      "loads_capsule_runtime": false,
      "containment_claim": "parent-supervision-and-exact-prefix-recovery"
    }
  ]'

  if ! jq -e --argjson expected_roles "$expected_roles" '
    .process_roles == $expected_roles
  ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-PROCESS-ROLE-CONFLATION" \
      "compiler isolation, engine-cell execution, or product supervision roles were conflated"
  fi
}

validate_dependency_contract() {
  local manifest_text="$1"
  if ! jq -e '
    .dependency_direction == [
      "franken_node -> franken_engine",
      "franken_engine -> franken_native_capsule"
    ]
    and .forbidden_dependency_direction == [
      "franken_engine -> franken_node",
      "franken_native_capsule -> franken_engine",
      "franken_native_capsule -> franken_node",
      "franken_node -> franken_native_capsule"
    ]
  ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-DEPENDENCY-DIRECTION" \
      "one-way node-to-engine-to-capsule dependency contract drifted"
  fi
}

validate_unsafe_boundary() {
  local manifest_text="$1"
  if ! jq -e '
    .unsafe_boundary.allowed_repository == "/dp/franken_native_capsule"
    and .unsafe_boundary.forbidden_repositories == [
      "/dp/franken_engine",
      "/dp/franken_node"
    ]
    and (.unsafe_boundary.scope | sort) == ([
      "backend adapter",
      "executable memory",
      "native relocation",
      "raw invocation",
      "platform mitigation",
      "quiescent retirement"
    ] | sort)
  ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-UNSAFE-REPO" \
      "unsafe native work is not confined to the separate capsule repository"
  fi
}

validate_backend() {
  local manifest_text="$1"
  if ! jq -e '
    .selected_backend.portable_backend == "cranelift"
    and .selected_backend.evaluation_release_line == "0.134.x"
    and .selected_backend.research_head_commit
      == "bccd12218bb4d16e0f535cd69b4d96994ff3a7ad"
    and .selected_backend.license == "Apache-2.0 WITH LLVM-exception"
    and .selected_backend.direct_jitmodule_exposure == false
    and .selected_backend.custom_backend_is_initial_default == false
    and .selected_backend.tier_b_bakeoff == [
      "copy-and-patch",
      "direct-cranelift",
      "whole-interpreter-partial-evaluation"
    ]
  ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-BACKEND-DECISION" \
      "portable backend or bounded Tier-B bakeoff decision drifted"
  fi
}

validate_rco() {
  local manifest_text="$1"
  if ! jq -e '
    .region_code_object.schema_version
      == "franken-engine.region-code-object.v1"
    and .region_code_object.contains_live_addresses == false
    and .region_code_object.pipeline == [
      "lower",
      "compile",
      "seal",
      "authorize",
      "structural-validate",
      "reserve",
      "relocate",
      "final-image-validate",
      "instruction-cache-sync",
      "write-revoke",
      "cfi-unwind-register",
      "activate",
      "execute",
      "unroute",
      "quiesce",
      "cfi-unwind-unregister",
      "unmap",
      "retire"
    ]
    and .region_code_object.required_domains == [
      "semantics-and-ir-hashes",
      "compiler-backend-generator-hashes",
      "target-and-feature-mask",
      "code-and-rodata",
      "allowlisted-relocations",
      "entrypoints-and-signatures",
      "branch-targets-and-bounds",
      "safepoints-and-stack-maps",
      "deopt-and-materialization",
      "exceptions-osr-and-interrupts",
      "capability-ifc-budget-policy-evidence",
      "assumptions-watchpoints-and-epochs",
      "resource-estimates",
      "debug-and-redaction",
      "provenance-signature-sbom-license"
    ]
  ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-RCO-CONTRACT" \
      "RCO schema, pipeline, address rule, or required domain set drifted"
  fi
}

validate_authorization() {
  local manifest_text="$1"
  if ! jq -e '
    .engine_authorization.schema_version
      == "franken-engine.native-engine-authorization.v1"
    and .engine_authorization.issuer == "franken_engine"
    and .engine_authorization.single_use_or_bounded_replay == true
    and .engine_authorization.signature_is_memory_safety_proof == false
    and .engine_authorization.required_domains == [
      "rco-and-pre-relocation-hashes",
      "tenant-extension-package-realm-cell-authority",
      "tier-and-trust-profile",
      "compiler-backend-capsule-identities",
      "target-feature-abi-rco-schema",
      "helper-table-schema-and-helper-ids",
      "capability-ifc-policy-proof-revocation-security-epochs",
      "code-compile-memory-activation-variant-budgets",
      "time-nonce-attempt-replay",
      "supervisor-and-recovery-contract",
      "engine-signature-and-evidence-linkage"
    ]
  ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-ENGINE-AUTHORIZATION" \
      "ENGINE authorization domains or provenance-versus-safety rule drifted"
  fi
}

validate_tcb_and_profiles() {
  local manifest_text="$1"
  local expected_profiles='[
    {
      "id": "native-throughput",
      "native_execution": true,
      "execution_boundary": "same-process-as-engine-cell",
      "production_eligibility":
        "dedicated-trust-domain-and-explicit-operator-selection",
      "tcb": [
        "engine-lowering",
        "compiler",
        "backend",
        "structural-validator",
        "relocator",
        "platform-adapter",
        "capsule",
        "generated-code",
        "abi-and-helper-table"
      ],
      "fatal_fault_action": "terminate-executing-process",
      "in_process_catch_and_fallback": false,
      "recovery":
        "supervisor-restart-from-exact-durable-effect-evidence-prefix",
      "parent_survival": "only-if-engine-runs-in-supervised-worker"
    },
    {
      "id": "native-crash-contained",
      "native_execution": true,
      "execution_boundary": "whole-execution-cell-child-process",
      "production_eligibility": "default-for-untrusted-native-extensions",
      "tcb": [
        "engine-lowering",
        "compiler",
        "backend",
        "structural-validator",
        "relocator",
        "platform-adapter",
        "capsule",
        "generated-code",
        "abi-and-helper-table"
      ],
      "fatal_fault_action": "terminate-and-reap-cell-process-group",
      "in_process_catch_and_fallback": false,
      "recovery":
        "fresh-cell-restart-from-exact-durable-effect-evidence-prefix",
      "parent_survival": "required"
    },
    {
      "id": "native-aot",
      "native_execution": true,
      "execution_boundary": "declared-throughput-or-crash-contained-topology",
      "production_eligibility": "signed-target-specific-image",
      "tcb": [
        "engine-lowering",
        "compiler",
        "backend",
        "structural-validator",
        "relocator-or-platform-linker",
        "platform-adapter",
        "capsule",
        "generated-code",
        "abi-and-helper-table"
      ],
      "fatal_fault_action": "inherit-declared-native-topology",
      "in_process_catch_and_fallback": false,
      "recovery": "inherit-declared-native-topology",
      "parent_survival": "inherit-declared-native-topology"
    },
    {
      "id": "portable-tier-i",
      "native_execution": false,
      "execution_boundary": "safe-engine",
      "production_eligibility": "universal-fallback",
      "tcb": [
        "safe-engine"
      ],
      "fatal_fault_action": "not-applicable",
      "in_process_catch_and_fallback": false,
      "recovery": "deterministic-tier-i-r-semantics",
      "parent_survival": "not-a-native-claim"
    }
  ]'

  if ! jq -e --argjson expected_profiles "$expected_profiles" '
    .trust_profiles == $expected_profiles
  ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-TCB-AMBIGUOUS" \
      "native TCB, profile identity, fault action, or containment boundary is ambiguous"
  fi
}

validate_claim_rules() {
  local manifest_text="$1"
  if ! jq -e '
    .claim_rules.raw_compute_profile == "native-throughput"
    and .claim_rules.untrusted_production_profile == "native-crash-contained"
    and .claim_rules.aot_profile == "native-aot"
    and .claim_rules.portable_profile == "portable-tier-i"
    and .claim_rules.w_x_is_arbitrary_code_containment == false
    and .claim_rules.cfi_pac_bti_is_arbitrary_code_containment == false
    and .claim_rules.compiler_signature_is_arbitrary_code_containment == false
    and .claim_rules.compilation_worker_is_execution_isolation == false
    and .claim_rules.silent_profile_fallback_allowed == false
    and .claim_rules.post_fault_same_process_resume_allowed == false
  ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-CLAIM-BOUNDARY" \
      "defense-in-depth, isolation, fallback, or post-fault claim rule drifted"
  fi

  if jq -e '.claim_rules.compiler_signature_is_arbitrary_code_containment == true' \
    <<<"$manifest_text" >/dev/null; then
    add_error "NCC-SIGNATURE-SAFETY-LIE" \
      "compiler signature is incorrectly represented as arbitrary-code containment"
  fi
  if jq -e '.claim_rules.compilation_worker_is_execution_isolation == true' \
    <<<"$manifest_text" >/dev/null; then
    add_error "NCC-COMPILE-ISOLATION-LIE" \
      "compilation-worker isolation is incorrectly represented as execution isolation"
  fi
  if jq -e '
    .claim_rules.post_fault_same_process_resume_allowed == true
    or .claim_rules.silent_profile_fallback_allowed == true
    or any(.trust_profiles[]; .in_process_catch_and_fallback == true)
  ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-FAULT-RECOVERY-LIE" \
      "fatal native fault is incorrectly converted into same-process or silent fallback"
  fi
}

validate_platform_owners() {
  local manifest_text="$1"
  if ! jq -e '
    (.platform_owners | map(.platform)) == ["linux", "apple", "windows"]
    and (.platform_owners | map(.platform) | unique | length) == 3
    and (
      .platform_owners
      | map(select(.platform == "linux"))[0]
      | .owner == "franken_native_capsule::platform::linux"
        and .architectures == ["x86_64", "aarch64"]
        and (.required_controls | index("rw-to-rx")) != null
        and (.required_controls | index("process-group-kill-and-reap")) != null
    )
    and (
      .platform_owners
      | map(select(.platform == "apple"))[0]
      | .owner == "franken_native_capsule::platform::apple"
        and .architectures == ["aarch64", "x86_64"]
        and (.required_controls | index("map-jit")) != null
        and (.required_controls | index("jit-write-callback-allowlist")) != null
    )
    and (
      .platform_owners
      | map(select(.platform == "windows"))[0]
      | .owner == "franken_native_capsule::platform::windows"
        and .architectures == ["x86_64", "aarch64-typed-availability"]
        and (
          .required_controls
          | index("cfg-invalid-by-default-exact-target-registration")
        ) != null
        and (
          .required_controls
          | index("dynamic-function-table-registration")
        ) != null
    )
  ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-PLATFORM-OWNERS" \
      "Linux, Apple, or Windows owner/control/support matrix drifted"
  fi
}

validate_lifecycle() {
  local manifest_text="$1"
  if ! jq -e '
    .lifecycle.cache_identity == "immutable-rco-or-aot-content-address"
    and .lifecycle.activation_receipt
      == "franken-engine.native-code-activation-receipt.v1"
    and .lifecycle.retirement_receipt
      == "franken-engine.native-code-retirement-receipt.v1"
    and .lifecycle.activation_atomic == true
    and .lifecycle.patch_in_place == false
    and .lifecycle.retirement_requires_quiescence == true
    and .lifecycle.unknown_liveness_action == "quarantine-and-block-reuse"
    and .lifecycle.required_domains == [
      "authenticate-and-parse",
      "authorization-and-resource-reservation",
      "inactive-population-and-relocation",
      "final-image-hash-and-validation",
      "instruction-cache-and-write-revocation",
      "cfi-unwind-debug-registration",
      "atomic-route-publication",
      "unroute-and-epoch-quiescence",
      "metadata-unregister-and-unmap",
      "quota-refund-and-linked-retirement-receipt"
    ]
  ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-LIFECYCLE" \
      "cache, activation, receipt, quiescence, or retirement contract drifted"
  fi
}

validate_source_locks() {
  local manifest_text="$1"
  declare -A expected_sha=(
    [cranelift-license]="23823edf263108ef7acbefde293225117b4784759c9c5bcd0b4966d0a1e34f55"
    [cranelift-ir]="e2f5d46863cb4bd8a310317e590e678b9c0a0570e83aa4ad7dbfb7f6c3dd0b96"
    [cranelift-jit-backend]="6c04557c1eaa47de216a6d319320dc5ac1e07fa994afe1ef5de39085494e6448"
    [cranelift-module]="a1b165473f5b69acbe3168f4b19f94b3d8ae2bf4185499796a87ede29d3a9a4f"
    [cranelift-object]="cf05796d06d64113b5fc7e6278bab3a5ec2a281a01ef2955c7a4eaf9b67551fb"
    [apple-jit-porting]="101c002b9414846b410c5fd07665d2d60e82fe3b7b59d76840ed27870f39e3ba"
    [apple-pointer-authentication]="dcfa3327860b622e6ea72a1ec598b820b17abff82f6adf161858bdc2dc8336fb"
    [windows-virtualprotect]="f26723e4e9177f09d42a2877d0ad7caa9314d855fc63df8aadfd46a9c161db16"
    [windows-valid-call-targets]="1bfb7ee2e24cc445a9db972d5bc4e144b3030cfc108eb82c0209911e2e104191"
    [windows-flush-instruction-cache]="24f8d11f01a864a4331eadfd8569cbf8bec3e0f4c7f48454eff4f1f2088433d3"
    [windows-dynamic-function-table]="f29647f2898eea354712eef0c1641dede0dfe02104134933e7d2d684d57591a5"
    [windows-control-flow-guard]="62fa60db6e1f5fa194362e7364286e35b4586e0b7432892588197fe76f63db4c"
    [linux-mprotect]="8a5cea5eb745c5272c8204a92610fc3702eb137fd75e708287a59224da626a24"
    [linux-memfd-create]="926a3a2f67e2de64bc3559c5c5448a0c21a8f01debcbd89d808a81d0ebf22896"
    [linux-seccomp]="1693fb82f6cf66c08a44eeeb87944eeb9a8794219ca9591f29362ec59174e6de"
    [copy-and-patch]="019459feb894390013f5dbc15bd086e468103ad5a9badc15053076fb7a62fdd4"
    [druid-baseline-meta-compilation]="c7088cd329182be0fdb3eb0327f45effd2cee5688349934af59655ffc621477d"
  )

  if ! jq -e '
    (.source_locks | length) == 17
    and (.source_locks | map(.id) | unique | length) == 17
    and (.source_locks | map(.url) | unique | length) == 17
    and all(
      .source_locks[];
      (.id | type == "string" and length > 0)
      and (.kind | IN(
        "upstream-source",
        "platform-documentation-snapshot",
        "research-paper"
      ))
      and (.url | startswith("https://"))
      and (.version_or_commit | type == "string" and length > 0)
      and (.sha256 | test("^[0-9a-f]{64}$"))
    )
  ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-SOURCE-LOCK-SCHEMA" \
      "source locks are missing, duplicate, malformed, or unsupported"
    return
  fi

  local source_id observed
  for source_id in "${!expected_sha[@]}"; do
    observed="$(
      jq -r --arg source_id "$source_id" '
        .source_locks[] | select(.id == $source_id) | .sha256
      ' <<<"$manifest_text"
    )"
    if [[ "$observed" != "${expected_sha[$source_id]}" ]]; then
      add_error "NCC-SOURCE-LOCK-DRIFT" \
        "source lock ${source_id} does not match the reviewed 2026-07-24 digest"
    fi
  done
}

validate_source_claims() {
  local manifest_text="$1"
  if ! jq -e '
    (.source_locks | map(.id)) as $source_ids
    | (.source_claims | map(.claim_id)) == [
        "NCC-SRC-001",
        "NCC-SRC-002",
        "NCC-SRC-003",
        "NCC-SRC-004",
        "NCC-SRC-005",
        "NCC-SRC-006",
        "NCC-SRC-007"
      ]
      and (.source_claims | map(.claim_id) | unique | length) == 7
      and all(
        .source_claims[];
        (.claim | type == "string" and length >= 32)
        and (.evidence_class | IN(
          "architecture-input-not-runtime-evidence",
          "supply-chain-input-not-release-approval",
          "platform-input-not-platform-certification",
          "research-hypothesis-not-runtime-evidence"
        ))
        and (.bindings | type == "array" and length >= 1)
        and all(
          .bindings[];
          (.source_id as $source_id
            | ($source_id | type == "string")
              and ($source_ids | index($source_id)) != null)
          and (.locator | type == "string" and length >= 12)
        )
      )
  ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-SOURCE-CLAIM-BINDING" \
      "research or platform claim lacks a locked source and clause/code locator"
  fi
}

validate_document_sync() {
  local manifest_text="$1"
  local adr_text="$2"
  local plan_text="$3"
  local engine_split_text="$4"
  local node_split_text="$5"

  if ! jq -e '
    .document_sync == {
      "adr": "NCC-ADR-0010-V1",
      "plan": "NCC-PLAN-0010-V1",
      "engine_split": "NCC-ENGINE-SPLIT-0010-V1",
      "node_split": "NCC-NODE-SPLIT-0010-V1"
    }
  ' <<<"$manifest_text" >/dev/null; then
    add_error "NCC-DOC-MARKER-SCHEMA" \
      "document synchronization marker map drifted"
  fi

  require_literal "$adr_text" "NCC-ADR-0010-V1" "NCC-DOC-ADR-STALE" \
    "ADR marker is missing or stale"
  require_literal "$plan_text" "NCC-PLAN-0010-V1" "NCC-DOC-PLAN-STALE" \
    "authoritative plan marker is missing or stale"
  require_literal "$engine_split_text" "NCC-ENGINE-SPLIT-0010-V1" \
    "NCC-DOC-ENGINE-SPLIT-STALE" "engine split-contract marker is missing or stale"
  require_literal "$node_split_text" "NCC-NODE-SPLIT-0010-V1" \
    "NCC-DOC-NODE-STALE" "product split-contract marker is missing or stale"

  local shared_literal
  for shared_literal in \
    "/dp/franken_native_capsule" \
    "franken_node -> franken_engine -> franken_native_capsule" \
    "implementation_authorized=false"; do
    require_literal "$adr_text" "$shared_literal" "NCC-DOC-ADR-STALE" \
      "ADR is missing synchronized literal: ${shared_literal}"
    require_literal "$plan_text" "$shared_literal" "NCC-DOC-PLAN-STALE" \
      "plan is missing synchronized literal: ${shared_literal}"
    require_literal "$engine_split_text" "$shared_literal" \
      "NCC-DOC-ENGINE-SPLIT-STALE" \
      "engine split contract is missing synchronized literal: ${shared_literal}"
    require_literal "$node_split_text" "$shared_literal" "NCC-DOC-NODE-STALE" \
      "product split contract is missing synchronized literal: ${shared_literal}"
  done

  require_literal "$adr_text" \
    "Compilation-worker isolation alone does not provide this property." \
    "NCC-COMPILE-ISOLATION-LIE" \
    "ADR does not distinguish compilation from execution isolation"
  require_literal "$adr_text" \
    "no handler may convert a fatal native fault into an in-process JavaScript" \
    "NCC-FAULT-RECOVERY-LIE" \
    "ADR does not forbid same-process recovery from a fatal native fault"
  require_literal "$adr_text" \
    "they do not prove arbitrary machine code memory-safe." \
    "NCC-SIGNATURE-SAFETY-LIE" \
    "ADR does not distinguish defense-in-depth from memory safety"
  require_literal "$plan_text" \
    "A typed interface, signature," \
    "NCC-DOC-PLAN-STALE" \
    "plan lost the explicit typed-interface non-sandbox warning"
  require_literal "$engine_split_text" \
    "Both existing repositories retain \`#![forbid(unsafe_code)]\`" \
    "NCC-UNSAFE-REPO" \
    "engine split contract lost the no-unsafe boundary"
  require_literal "$node_split_text" \
    "depend on or call the capsule directly in production" \
    "NCC-DEPENDENCY-DIRECTION" \
    "product split contract permits a direct capsule runtime call"
}

validate_approval() {
  local manifest_text="$1"
  local adr_text="$2"
  local require_now="$3"
  local approval_text approval_text_hash recorded_text_hash recorded_payload

  decision_status="$(jq -r '.status // ""' <<<"$manifest_text")"
  implementation_authorized="$(
    jq -r '.implementation_authorized // false' <<<"$manifest_text"
  )"
  payload_digest="$(compute_proposed_payload_digest "$manifest_text")"

  case "$decision_status" in
    proposed)
      if [[ "$implementation_authorized" != "false" ]] \
        || ! jq -e '.approval == null' <<<"$manifest_text" >/dev/null; then
        add_error "NCC-APPROVAL-FORGED" \
          "proposed state must be unauthorized with a null approval record"
      fi
      require_literal "$adr_text" "- Status: Proposed" \
        "NCC-APPROVAL-FORGED" "ADR status does not match proposed decision"
      if [[ "$require_now" == "true" ]]; then
        add_error "NCC-APPROVAL-PENDING" \
          "valid proposed decision is not implementation authority"
      fi
      ;;
    accepted)
      if [[ "$implementation_authorized" != "true" ]] \
        || ! jq -e '
          (.approval | type) == "object"
          and (.approval | keys | sort) == ([
            "approval_text",
            "approval_text_sha256",
            "approved_at",
            "approved_payload_sha256",
            "authority"
          ] | sort)
          and .approval.authority == "project-owner"
          and (.approval.approved_at
            | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
          and (.approval.approval_text | type == "string" and length >= 16)
          and (.approval.approval_text_sha256 | test("^[0-9a-f]{64}$"))
          and (.approval.approved_payload_sha256 | test("^[0-9a-f]{64}$"))
        ' <<<"$manifest_text" >/dev/null; then
        add_error "NCC-APPROVAL-FORGED" \
          "accepted state lacks a complete project-owner approval record"
        return
      fi

      approval_text="$(jq -r '.approval.approval_text' <<<"$manifest_text")"
      recorded_text_hash="$(
        jq -r '.approval.approval_text_sha256' <<<"$manifest_text"
      )"
      approval_text_hash="$(hash_text "$approval_text")"
      recorded_payload="$(
        jq -r '.approval.approved_payload_sha256' <<<"$manifest_text"
      )"

      if [[ "$approval_text_hash" != "$recorded_text_hash" ]]; then
        add_error "NCC-APPROVAL-TEXT-MISMATCH" \
          "approval text does not match its recorded digest"
      fi
      if [[ "$payload_digest" != "$recorded_payload" ]]; then
        add_error "NCC-APPROVAL-PAYLOAD-MISMATCH" \
          "accepted decision payload differs from the project-owner-approved payload"
      fi
      require_literal "$adr_text" "- Status: Accepted" \
        "NCC-APPROVAL-FORGED" "ADR status does not match accepted decision"
      require_literal "$adr_text" \
        "- Approved payload digest: \`${recorded_payload}\`" \
        "NCC-APPROVAL-PAYLOAD-MISMATCH" \
        "ADR does not record the approved payload digest"
      require_literal "$adr_text" \
        "- Approval text SHA-256: \`${recorded_text_hash}\`" \
        "NCC-APPROVAL-TEXT-MISMATCH" \
        "ADR does not record the approval text digest"
      ;;
    *)
      add_error "NCC-APPROVAL-STATE" \
        "decision status must be exactly proposed or accepted"
      ;;
  esac
}

validate_contract_texts() {
  local manifest_text="$1"
  local adr_text="$2"
  local plan_text="$3"
  local engine_split_text="$4"
  local node_split_text="$5"
  local require_now="$6"

  validation_codes=()
  validation_messages=()
  payload_digest=""
  decision_status=""
  implementation_authorized="false"

  require_tools
  if ((${#validation_codes[@]} > 0)); then
    return
  fi

  if ! jq -e 'type == "object"' <<<"$manifest_text" >/dev/null 2>&1; then
    add_error "NCC-MANIFEST-MALFORMED" \
      "decision input is not a valid JSON object"
    return
  fi
  if ! reject_duplicate_json_keys "$manifest_text" >/dev/null 2>&1; then
    add_error "NCC-MANIFEST-DUPLICATE-KEY" \
      "decision JSON contains a duplicate object key"
    return
  fi

  validate_exact_top_level_schema "$manifest_text"
  validate_fixed_identity "$manifest_text"
  validate_process_roles "$manifest_text"
  validate_dependency_contract "$manifest_text"
  validate_unsafe_boundary "$manifest_text"
  validate_backend "$manifest_text"
  validate_rco "$manifest_text"
  validate_authorization "$manifest_text"
  validate_tcb_and_profiles "$manifest_text"
  validate_claim_rules "$manifest_text"
  validate_platform_owners "$manifest_text"
  validate_lifecycle "$manifest_text"
  validate_source_locks "$manifest_text"
  validate_source_claims "$manifest_text"
  validate_document_sync \
    "$manifest_text" "$adr_text" "$plan_text" "$engine_split_text" "$node_split_text"
  validate_approval "$manifest_text" "$adr_text" "$require_now"
}

read_required_file() {
  local file_path="$1"
  local label="$2"
  if [[ ! -f "$file_path" ]]; then
    add_error "NCC-INPUT-MISSING" "${label} is missing: ${file_path}"
    return 1
  fi
  if [[ ! -r "$file_path" ]]; then
    add_error "NCC-INPUT-UNREADABLE" "${label} is unreadable: ${file_path}"
    return 1
  fi
  return 0
}

validate_real_files() {
  validation_codes=()
  validation_messages=()
  require_tools

  read_required_file "$decision_path" "decision JSON" || true
  read_required_file "$adr_path" "ADR" || true
  read_required_file "$plan_path" "authoritative plan" || true
  read_required_file "$engine_split_path" "engine split contract" || true
  read_required_file "$node_split_path" "product split contract" || true

  if ((${#validation_codes[@]} > 0)); then
    return
  fi

  local manifest_text adr_text plan_text engine_split_text node_split_text
  manifest_text="$(<"$decision_path")"
  adr_text="$(<"$adr_path")"
  plan_text="$(<"$plan_path")"
  engine_split_text="$(<"$engine_split_path")"
  node_split_text="$(<"$node_split_path")"

  validate_contract_texts \
    "$manifest_text" \
    "$adr_text" \
    "$plan_text" \
    "$engine_split_text" \
    "$node_split_text" \
    "$require_authorized"
}

record_self_test() {
  self_test_ids+=("$1")
  self_test_results+=("$2")
  self_test_expected_codes+=("$3")
  self_test_observed_codes+=("$4")
}

run_mutation_case() {
  local case_id="$1"
  local expected_code="$2"
  local manifest_text="$3"
  local adr_text="$4"
  local plan_text="$5"
  local engine_split_text="$6"
  local node_split_text="$7"
  local require_now="${8:-false}"
  local observed result

  validate_contract_texts \
    "$manifest_text" \
    "$adr_text" \
    "$plan_text" \
    "$engine_split_text" \
    "$node_split_text" \
    "$require_now"
  observed="$(join_codes)"

  if [[ "$expected_code" == "PASS" ]]; then
    if ((${#validation_codes[@]} == 0)); then
      result="pass"
    else
      result="fail"
    fi
  elif has_error "$expected_code"; then
    result="pass"
  else
    result="fail"
  fi

  record_self_test "$case_id" "$result" "$expected_code" "$observed"
}

run_self_tests() {
  local -a saved_validation_codes=("${validation_codes[@]}")
  local -a saved_validation_messages=("${validation_messages[@]}")
  local saved_payload_digest="$payload_digest"
  local saved_decision_status="$decision_status"
  local saved_implementation_authorized="$implementation_authorized"
  local self_test_success=true

  self_test_ids=()
  self_test_results=()
  self_test_expected_codes=()
  self_test_observed_codes=()

  local base_manifest base_adr base_plan base_engine_split base_node_split
  base_manifest="$(
    jq \
      '.status = "proposed"
       | .implementation_authorized = false
       | .approval = null' \
      "$decision_path"
  )"
  base_adr="$(<"$adr_path")"
  base_adr="${base_adr/- Status: Accepted/- Status: Proposed — explicit project-owner approval is required}"
  base_plan="$(<"$plan_path")"
  base_engine_split="$(<"$engine_split_path")"
  base_node_split="$(<"$node_split_path")"

  run_mutation_case "valid-proposed" "PASS" \
    "$base_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  run_mutation_case "proposed-require-authorized" "NCC-APPROVAL-PENDING" \
    "$base_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split" "true"

  local reordered_manifest
  reordered_manifest="$(jq -S . <<<"$base_manifest")"
  run_mutation_case "reordered-object-keys" "PASS" \
    "$reordered_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local malformed_manifest
  malformed_manifest="${base_manifest%?}"
  run_mutation_case "malformed-json" "NCC-MANIFEST-MALFORMED" \
    "$malformed_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local duplicate_key_manifest
  duplicate_key_manifest="$(
    printf '%s' "$base_manifest" \
      | sed '0,/{/s//{\n  "status": "proposed",/'
  )"
  run_mutation_case "duplicate-json-key" "NCC-MANIFEST-DUPLICATE-KEY" \
    "$duplicate_key_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local missing_field_manifest
  missing_field_manifest="$(jq 'del(.engine_authorization)' <<<"$base_manifest")"
  run_mutation_case "missing-required-domain" "NCC-SCHEMA-TOP-LEVEL" \
    "$missing_field_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local duplicate_profile_manifest
  duplicate_profile_manifest="$(
    jq '.trust_profiles += [.trust_profiles[0]]' <<<"$base_manifest"
  )"
  run_mutation_case "duplicate-profile" "NCC-TCB-AMBIGUOUS" \
    "$duplicate_profile_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local conflated_process_manifest
  conflated_process_manifest="$(
    jq '
      (
        .process_roles[]
        | select(.id == "capsule-compilation-worker")
        | .runs_untrusted_guest_machine_code
      ) = true
    ' <<<"$base_manifest"
  )"
  run_mutation_case "compiler-worker-runs-guest-code" \
    "NCC-PROCESS-ROLE-CONFLATION" \
    "$conflated_process_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local unsafe_repo_manifest
  unsafe_repo_manifest="$(
    jq '.unsafe_boundary.allowed_repository = "/dp/franken_engine"' \
      <<<"$base_manifest"
  )"
  run_mutation_case "unsafe-inside-engine" "NCC-UNSAFE-REPO" \
    "$unsafe_repo_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local ambiguous_tcb_manifest
  ambiguous_tcb_manifest="$(
    jq '
      (.trust_profiles[]
        | select(.id == "native-throughput")
        | .tcb) -= ["compiler"]
    ' <<<"$base_manifest"
  )"
  run_mutation_case "compiler-removed-from-tcb" "NCC-TCB-AMBIGUOUS" \
    "$ambiguous_tcb_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local signature_lie_manifest
  signature_lie_manifest="$(
    jq '.claim_rules.compiler_signature_is_arbitrary_code_containment = true' \
      <<<"$base_manifest"
  )"
  run_mutation_case "signature-as-memory-safety" "NCC-SIGNATURE-SAFETY-LIE" \
    "$signature_lie_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local compile_isolation_lie_manifest
  compile_isolation_lie_manifest="$(
    jq '.claim_rules.compilation_worker_is_execution_isolation = true' \
      <<<"$base_manifest"
  )"
  run_mutation_case "compile-worker-as-execution-isolation" \
    "NCC-COMPILE-ISOLATION-LIE" \
    "$compile_isolation_lie_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local catch_fallback_manifest
  catch_fallback_manifest="$(
    jq '
      .claim_rules.post_fault_same_process_resume_allowed = true
      | (
          .trust_profiles[]
          | select(.id == "native-throughput")
          | .in_process_catch_and_fallback
        ) = true
    ' <<<"$base_manifest"
  )"
  run_mutation_case "catch-and-fallback-after-fatal-fault" \
    "NCC-FAULT-RECOVERY-LIE" \
    "$catch_fallback_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local forged_approval_manifest
  forged_approval_manifest="$(
    jq '.status = "accepted" | .implementation_authorized = true' \
      <<<"$base_manifest"
  )"
  run_mutation_case "forged-null-approval" "NCC-APPROVAL-FORGED" \
    "$forged_approval_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local approval_text approval_text_hash accepted_payload_digest
  local accepted_manifest accepted_adr
  approval_text="I explicitly approve ADR-0010 payload for self-test only."
  approval_text_hash="$(hash_text "$approval_text")"
  accepted_payload_digest="$(compute_proposed_payload_digest "$base_manifest")"
  accepted_manifest="$(
    jq \
      --arg approval_text "$approval_text" \
      --arg approval_text_hash "$approval_text_hash" \
      --arg payload_digest "$accepted_payload_digest" '
        .status = "accepted"
        | .implementation_authorized = true
        | .approval = {
            "authority": "project-owner",
            "approved_at": "2026-07-24T00:00:00Z",
            "approval_text": $approval_text,
            "approval_text_sha256": $approval_text_hash,
            "approved_payload_sha256": $payload_digest
          }
      ' <<<"$base_manifest"
  )"
  accepted_adr="${base_adr/- Status: Proposed — explicit project-owner approval is required/- Status: Accepted}"
  accepted_adr+=$'\n'
  accepted_adr+="- Approved payload digest: \`${accepted_payload_digest}\`"
  accepted_adr+=$'\n'
  accepted_adr+="- Approval text SHA-256: \`${approval_text_hash}\`"

  run_mutation_case "valid-accepted" "PASS" \
    "$accepted_manifest" "$accepted_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split" "true"

  local payload_mismatch_manifest
  payload_mismatch_manifest="$(
    jq '.approval.approved_payload_sha256 = ("0" * 64)' <<<"$accepted_manifest"
  )"
  run_mutation_case "approval-payload-mismatch" \
    "NCC-APPROVAL-PAYLOAD-MISMATCH" \
    "$payload_mismatch_manifest" "$accepted_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split" "true"

  local stale_node_split
  stale_node_split="${base_node_split/NCC-NODE-SPLIT-0010-V1/NCC-NODE-SPLIT-STALE}"
  run_mutation_case "stale-product-split-contract" "NCC-DOC-NODE-STALE" \
    "$base_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$stale_node_split"

  local stale_engine_split
  stale_engine_split="${base_engine_split/NCC-ENGINE-SPLIT-0010-V1/NCC-ENGINE-SPLIT-STALE}"
  run_mutation_case "stale-engine-split-contract" \
    "NCC-DOC-ENGINE-SPLIT-STALE" \
    "$base_manifest" "$base_adr" "$base_plan" \
    "$stale_engine_split" "$base_node_split"

  local reversed_dependency_manifest
  reversed_dependency_manifest="$(
    jq '
      .dependency_direction = [
        "franken_node -> franken_engine",
        "franken_native_capsule -> franken_engine"
      ]
    ' <<<"$base_manifest"
  )"
  run_mutation_case "reversed-capsule-dependency" "NCC-DEPENDENCY-DIRECTION" \
    "$reversed_dependency_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local missing_platform_manifest
  missing_platform_manifest="$(
    jq '.platform_owners |= map(select(.platform != "windows"))' \
      <<<"$base_manifest"
  )"
  run_mutation_case "missing-windows-owner" "NCC-PLATFORM-OWNERS" \
    "$missing_platform_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local tampered_source_manifest seeded_tampered_sha
  seeded_tampered_sha="$(hash_text "source-lock:${seed}")"
  tampered_source_manifest="$(
    jq --arg tampered_sha "$seeded_tampered_sha" '
      (
        .source_locks[]
        | select(.id == "cranelift-ir")
        | .sha256
      ) = $tampered_sha
    ' <<<"$base_manifest"
  )"
  run_mutation_case "tampered-source-lock" "NCC-SOURCE-LOCK-DRIFT" \
    "$tampered_source_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local unbound_source_claim_manifest
  unbound_source_claim_manifest="$(
    jq '
      (
        .source_claims[]
        | select(.claim_id == "NCC-SRC-001")
        | .bindings[0].source_id
      ) = "missing-source"
    ' <<<"$base_manifest"
  )"
  run_mutation_case "unbound-source-claim" \
    "NCC-SOURCE-CLAIM-BINDING" \
    "$unbound_source_claim_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local incomplete_rco_manifest
  incomplete_rco_manifest="$(
    jq '.region_code_object.pipeline -= ["activate"]' <<<"$base_manifest"
  )"
  run_mutation_case "missing-rco-activation" "NCC-RCO-CONTRACT" \
    "$incomplete_rco_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local substituted_rco_domain_manifest
  substituted_rco_domain_manifest="$(
    jq '.region_code_object.required_domains[0] = "same-length-impostor"' \
      <<<"$base_manifest"
  )"
  run_mutation_case "substituted-rco-domain" "NCC-RCO-CONTRACT" \
    "$substituted_rco_domain_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local incomplete_lifecycle_manifest
  incomplete_lifecycle_manifest="$(
    jq '.lifecycle.retirement_receipt = null' <<<"$base_manifest"
  )"
  run_mutation_case "missing-retirement-receipt" "NCC-LIFECYCLE" \
    "$incomplete_lifecycle_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local substituted_lifecycle_domain_manifest
  substituted_lifecycle_domain_manifest="$(
    jq '.lifecycle.required_domains[0] = "same-length-impostor"' \
      <<<"$base_manifest"
  )"
  run_mutation_case "substituted-lifecycle-domain" "NCC-LIFECYCLE" \
    "$substituted_lifecycle_domain_manifest" "$base_adr" "$base_plan" \
    "$base_engine_split" "$base_node_split"

  local result
  for result in "${self_test_results[@]}"; do
    if [[ "$result" != "pass" ]]; then
      self_test_success=false
    fi
  done

  validation_codes=("${saved_validation_codes[@]}")
  validation_messages=("${saved_validation_messages[@]}")
  payload_digest="$saved_payload_digest"
  decision_status="$saved_decision_status"
  implementation_authorized="$saved_implementation_authorized"

  [[ "$self_test_success" == "true" ]]
}

emit_check_summary() {
  local outcome="pass"
  local codes_json messages_json
  if ((${#validation_codes[@]} > 0)); then
    outcome="fail"
  fi
  codes_json="$(printf '%s\n' "${validation_codes[@]:-}" | jq -Rsc '
    split("\n") | map(select(length > 0))
  ')"
  messages_json="$(printf '%s\n' "${validation_messages[@]:-}" | jq -Rsc '
    split("\n") | map(select(length > 0))
  ')"
  jq -cn \
    --arg schema "$SCRIPT_SCHEMA" \
    --arg bead_id "$BEAD_ID" \
    --arg outcome "$outcome" \
    --arg status "$decision_status" \
    --argjson authorized "$implementation_authorized" \
    --arg payload_digest "$payload_digest" \
    --argjson reasons "$codes_json" \
    --argjson messages "$messages_json" '{
      schema_version: $schema,
      bead_id: $bead_id,
      outcome: $outcome,
      decision_status: $status,
      implementation_authorized: $authorized,
      proposed_payload_sha256: $payload_digest,
      reasons: $reasons,
      messages: $messages
    }'
}

emit_bundle() {
  local validation_outcome="$1"
  local self_test_outcome="$2"
  local timestamp run_id run_dir events_path sequence=0
  local git_commit dirty_worktree platform_value
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  run_id="native-code-capsule-adr-${timestamp}-$$"
  run_dir="${output_root}/${run_id}"
  events_path="${run_dir}/events.jsonl"
  mkdir -p "$output_root"
  if ! mkdir "$run_dir"; then
    printf 'refusing to reuse evidence directory: %s\n' "$run_dir" >&2
    return 1
  fi

  git_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf unknown)"
  if git -C "$repo_root" diff --quiet --ignore-submodules HEAD -- \
    >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi
  platform_value="$(uname -s)-$(uname -m)"

  emit_event() {
    local test_id="$1"
    local scenario="$2"
    local decision="$3"
    local reason="$4"
    local expected="$5"
    local observed="$6"
    sequence=$((sequence + 1))
    jq -cn \
      --arg schema "$EVENT_SCHEMA" \
      --arg run_id "$run_id" \
      --arg trace_id "trace-${run_id}" \
      --arg test_id "$test_id" \
      --arg scenario "$scenario" \
      --arg seed "$seed" \
      --arg source_cutoff "$SOURCE_CUTOFF" \
      --arg platform "$platform_value" \
      --arg decision "$decision" \
      --arg reason "$reason" \
      --arg expected "$expected" \
      --arg observed "$observed" \
      --argjson sequence "$sequence" \
      --arg decision_hash "$(hash_file "$decision_path")" \
      --arg adr_hash "$(hash_file "$adr_path")" \
      --arg plan_hash "$(hash_file "$plan_path")" \
      --arg engine_split_hash "$(hash_file "$engine_split_path")" \
      --arg node_split_hash "$(hash_file "$node_split_path")" '{
        schema_version: $schema,
        run_id: $run_id,
        trace_id: $trace_id,
        test_id: $test_id,
        scenario: $scenario,
        seed: $seed,
        attempt: 1,
        source_cutoff: $source_cutoff,
        platform: $platform,
        phase: "adr-contract",
        sequence: $sequence,
        decision: $decision,
        reason: $reason,
        duration_ms: 0,
        expected: $expected,
        observed: $observed,
        artifact_hashes: {
          decision: $decision_hash,
          adr: $adr_hash,
          plan: $plan_hash,
          engine_split: $engine_split_hash,
          node_split: $node_split_hash
        }
      }' >>"$events_path"
  }

  local real_reason
  real_reason="$(join_codes)"
  if [[ -z "$real_reason" && "$implementation_authorized" == "false" ]]; then
    real_reason="NCC-APPROVAL-PENDING"
  elif [[ -z "$real_reason" ]]; then
    real_reason="NCC-CONTRACT-VALID"
  fi
  emit_event \
    "real-contract" \
    "current-repository-state" \
    "$validation_outcome" \
    "$real_reason" \
    "valid-contract" \
    "$decision_status"

  local idx
  for idx in "${!self_test_ids[@]}"; do
    emit_event \
      "${self_test_ids[$idx]}" \
      "seeded-contract-mutation" \
      "${self_test_results[$idx]}" \
      "${self_test_expected_codes[$idx]}" \
      "${self_test_expected_codes[$idx]}" \
      "${self_test_observed_codes[$idx]}"
  done

  jq '.source_locks' "$decision_path" >"${run_dir}/source_locks.json"
  jq -n \
    --arg schema "franken-engine.native-code-capsule-review-record.v1" \
    --arg status "$decision_status" \
    --argjson authorized "$implementation_authorized" \
    --arg payload_digest "$payload_digest" '{
      schema_version: $schema,
      decision_status: $status,
      implementation_authorized: $authorized,
      proposed_payload_sha256: $payload_digest,
      reviewer: null,
      review_outcome: (
        if $authorized then "approved" else "awaiting-project-owner-approval" end
      )
    }' >"${run_dir}/review_record.json"

  jq -n '{
    schema_version: "franken-engine.native-code-capsule-provenance-graph.v1",
    nodes: [
      {"id": "decision", "kind": "machine-readable-decision"},
      {"id": "adr", "kind": "architecture-decision-record"},
      {"id": "plan", "kind": "authoritative-plan"},
      {"id": "engine-split", "kind": "engine-split-contract"},
      {"id": "node-split", "kind": "product-split-contract"},
      {"id": "gate", "kind": "contract-validator"},
      {"id": "events", "kind": "verification-events"}
    ],
    edges: [
      {"from": "decision", "to": "adr", "relation": "governs"},
      {"from": "decision", "to": "plan", "relation": "synchronizes"},
      {"from": "decision", "to": "engine-split", "relation": "synchronizes"},
      {"from": "decision", "to": "node-split", "relation": "synchronizes"},
      {"from": "gate", "to": "decision", "relation": "validates"},
      {"from": "gate", "to": "events", "relation": "produces"}
    ]
  }' >"${run_dir}/provenance_graph.json"

  jq -n \
    --arg bash_version "${BASH_VERSION}" \
    --arg jq_version "$(jq --version)" \
    --arg python_version "$(python3 --version 2>&1)" \
    --arg platform "$platform_value" \
    --arg git_commit "$git_commit" \
    --argjson dirty_worktree "$dirty_worktree" '{
      schema_version: "franken-engine.native-code-capsule-env.v1",
      bash: $bash_version,
      jq: $jq_version,
      python: $python_version,
      platform: $platform,
      git_commit: $git_commit,
      dirty_worktree: $dirty_worktree
    }' >"${run_dir}/env.json"

  printf '%s\n' \
    "./scripts/run_native_code_capsule_adr_gate.sh ci --output-root ${output_root}" \
    "./scripts/e2e/native_code_capsule_adr_contract_smoke.sh ${output_root}" \
    >"${run_dir}/commands.txt"

  printf '%s\n' \
    "# Native-Code Capsule ADR Evidence Legal Record" \
    "" \
    "- This bundle contains project-authored validation metadata." \
    "- Cranelift/Wasmtime research input: Apache-2.0 WITH LLVM-exception." \
    "- Platform documentation and research papers are referenced by URL and digest; their content is not redistributed in this bundle." \
    "- This record is not legal advice and does not authorize distribution." \
    >"${run_dir}/LEGAL.md"

  jq -n \
    --arg schema "$SCRIPT_SCHEMA" \
    --arg script_hash "$(hash_file "${script_dir}/run_native_code_capsule_adr_gate.sh")" \
    --arg decision_hash "$(hash_file "$decision_path")" \
    --arg adr_hash "$(hash_file "$adr_path")" \
    --arg plan_hash "$(hash_file "$plan_path")" \
    --arg engine_split_hash "$(hash_file "$engine_split_path")" \
    --arg node_split_hash "$(hash_file "$node_split_path")" '{
      schema_version: $schema,
      script_sha256: $script_hash,
      inputs: {
        decision_sha256: $decision_hash,
        adr_sha256: $adr_hash,
        plan_sha256: $plan_hash,
        engine_split_sha256: $engine_split_hash,
        node_split_sha256: $node_split_hash
      }
    }' >"${run_dir}/repro.lock"

  local artifacts_json
  artifacts_json="$(
    for artifact_name in \
      events.jsonl \
      source_locks.json \
      review_record.json \
      provenance_graph.json \
      env.json \
      commands.txt \
      LEGAL.md \
      repro.lock; do
      jq -cn \
        --arg path "$artifact_name" \
        --arg sha256 "$(hash_file "${run_dir}/${artifact_name}")" \
        --argjson bytes "$(wc -c <"${run_dir}/${artifact_name}")" \
        '{path: $path, sha256: $sha256, bytes: $bytes}'
    done | jq -s .
  )"

  jq -n \
    --arg schema "franken-engine.native-code-capsule-adr-run-manifest.v1" \
    --arg run_id "$run_id" \
    --arg bead_id "$BEAD_ID" \
    --arg created_at "$timestamp" \
    --arg validation_outcome "$validation_outcome" \
    --arg self_test_outcome "$self_test_outcome" \
    --arg status "$decision_status" \
    --argjson authorized "$implementation_authorized" \
    --arg payload_digest "$payload_digest" \
    --argjson artifacts "$artifacts_json" '{
      schema_version: $schema,
      run_id: $run_id,
      bead_id: $bead_id,
      created_at_utc: $created_at,
      complete: true,
      validation_outcome: $validation_outcome,
      self_test_outcome: $self_test_outcome,
      decision_status: $status,
      implementation_authorized: $authorized,
      proposed_payload_sha256: $payload_digest,
      artifacts: $artifacts,
      reproduction_command:
        "./scripts/run_native_code_capsule_adr_gate.sh ci"
    }' >"${run_dir}/run_manifest.json"

  printf '%s\n' "$run_dir"
}

main() {
  local validation_outcome="pass"
  local self_test_outcome="not-run"
  local self_tests_ok=true

  case "$mode" in
    check)
      validate_real_files
      if ((${#validation_codes[@]} > 0)); then
        validation_outcome="fail"
      fi
      emit_check_summary
      [[ "$validation_outcome" == "pass" ]]
      ;;
    self-test)
      if ! run_self_tests; then
        self_tests_ok=false
      fi
      local idx
      for idx in "${!self_test_ids[@]}"; do
        jq -cn \
          --arg test_id "${self_test_ids[$idx]}" \
          --arg result "${self_test_results[$idx]}" \
          --arg expected "${self_test_expected_codes[$idx]}" \
          --arg observed "${self_test_observed_codes[$idx]}" '{
            test_id: $test_id,
            result: $result,
            expected: $expected,
            observed: $observed
          }'
      done
      "$self_tests_ok"
      ;;
    ci)
      validate_real_files
      if ((${#validation_codes[@]} > 0)); then
        validation_outcome="fail"
      fi
      if run_self_tests; then
        self_test_outcome="pass"
      else
        self_test_outcome="fail"
        self_tests_ok=false
      fi
      local bundle_dir
      bundle_dir="$(emit_bundle \
        "$validation_outcome" "$self_test_outcome")"
      jq -cn \
        --arg schema "$SCRIPT_SCHEMA" \
        --arg validation_outcome "$validation_outcome" \
        --arg self_test_outcome "$self_test_outcome" \
        --arg decision_status "$decision_status" \
        --argjson implementation_authorized "$implementation_authorized" \
        --arg payload_digest "$payload_digest" \
        --arg bundle_dir "$bundle_dir" '{
          schema_version: $schema,
          validation_outcome: $validation_outcome,
          self_test_outcome: $self_test_outcome,
          decision_status: $decision_status,
          implementation_authorized: $implementation_authorized,
          proposed_payload_sha256: $payload_digest,
          bundle_dir: $bundle_dir
        }'
      [[ "$validation_outcome" == "pass" && "$self_tests_ok" == "true" ]]
      ;;
  esac
}

main
