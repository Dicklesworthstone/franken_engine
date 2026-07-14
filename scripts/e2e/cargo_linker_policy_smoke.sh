#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
tmp_root="${TMPDIR:-/tmp}/franken-engine-cargo-linker-policy-${timestamp}-$$"
crate_dir="${tmp_root}/crate"
bin_dir="${tmp_root}/bin"
cargo_home="${tmp_root}/cargo-home"
mkdir -p "${crate_dir}/.cargo" "${crate_dir}/src" "$bin_dir" "$cargo_home"

fail() {
  printf 'cargo linker policy smoke failed: %s\n' "$*" >&2
  printf 'retained smoke path: %s\n' "$tmp_root" >&2
  exit 1
}

command -v cargo >/dev/null 2>&1 || fail "cargo not found"
command -v rustc >/dev/null 2>&1 || fail "rustc not found"
real_cc="$(command -v cc || true)"
[[ -n "$real_cc" ]] || fail "cc not found"

source_text_has_effective_lld_optout() {
  local source_text="$1"
  local normalized="$source_text"
  local delimiter token option
  local -a tokens=()
  local index
  local effective_state="unset"

  for delimiter in '"' "'" '\' '{' '}' '(' ')' '[' ']' ',' ';'; do
    normalized="${normalized//"$delimiter"/ }"
  done
  read -r -a tokens <<<"$normalized"
  for ((index = 0; index < ${#tokens[@]}; index += 1)); do
    token="${tokens[index]}"
    case "$token" in
      RUSTFLAGS=*|CARGO_ENCODED_RUSTFLAGS=*|CARGO_BUILD_RUSTFLAGS=*|CARGO_TARGET_*_RUSTFLAGS=*|*rustflags=*)
        option="${token#*=}"
        ;;
      *) option="$token" ;;
    esac
    case "$option" in
      -Clinker-features=-lld) effective_state="disabled" ;;
      -Clinker-features=*) effective_state="other" ;;
      -C)
        case "${tokens[index + 1]:-}" in
          linker-features=-lld) effective_state="disabled" ;;
          linker-features=*) effective_state="other" ;;
        esac
        ;;
    esac
  done
  [[ "$effective_state" == "disabled" ]]
}

source_line_is_rustflags_assignment() {
  local source_line="$1"
  local variable_re='(RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_RUSTFLAGS|CARGO_TARGET_[A-Z0-9_]+_RUSTFLAGS)'
  local direct_assignment_re="(^|[^[:alnum:]_])${variable_re}[[:space:]]*(\\+?=)"
  local quoted_mapping_re="[\"']${variable_re}[\"'][[:space:]]*:"
  local yaml_mapping_re="^[[:space:]]*${variable_re}[[:space:]]*:"
  [[ "$source_line" =~ $direct_assignment_re ]] ||
    [[ "$source_line" =~ $quoted_mapping_re ]] ||
    [[ "$source_line" =~ $yaml_mapping_re ]]
}

source_assignment_record() {
  local path="$1"
  local start_line="$2"

  awk -v start="$start_line" '
    function indentation(value, copy) {
      copy = value
      sub(/[^[:space:]].*$/, "", copy)
      return length(copy)
    }
    function emit() {
      if (!emitted) {
        print record
        emitted = 1
      }
    }
    NR < start { next }
    NR == start {
      record = $0
      base_indent = indentation($0)
      continuation = ($0 ~ /\\[[:space:]]*$/)
      block = ($0 ~ /:[[:space:]]*[|>][-+0-9]*[[:space:]]*$/)
      if (!continuation && !block) {
        emit()
        exit
      }
      next
    }
    continuation {
      record = record " " $0
      continuation = ($0 ~ /\\[[:space:]]*$/)
      if (!continuation && !block) {
        emit()
        exit
      }
      next
    }
    block {
      if ($0 ~ /^[[:space:]]*$/ || indentation($0) > base_indent) {
        record = record " " $0
        next
      }
      emit()
      exit
    }
    END { emit() }
  ' "${repo_root}/${path}"
}

source_line_is_in_negative_fixture_block() {
  local path="$1"
  local line_number="$2"

  awk -v target="$line_number" '
    NR > target { exit }
    /linker-policy-negative-fixtures-begin/ { active = 1 }
    /linker-policy-negative-fixtures-end/ { active = 0 }
    END { exit(active ? 0 : 1) }
  ' "${repo_root}/${path}"
}

assert_repository_policy() {
  local config_path="${repo_root}/.cargo/config.toml"
  local findings_path="${tmp_root}/uncomposed-active-rustflags.txt"

  grep -Fqx 'linker = "cc"' "$config_path" ||
    fail "target config does not select cc"
  grep -Fqx 'rustflags = ["-Clinker-features=-lld"]' "$config_path" ||
    fail "target config does not contain the exact system-cc implicit-LLD opt-out"

  : >"$findings_path"
  while IFS= read -r match; do
    local path="${match%%:*}"
    local rest="${match#*:}"
    local line_number="${rest%%:*}"
    local source_line="${rest#*:}"
    local source_record

    case "$path" in
      scripts/testdata/* | scripts/e2e/testdata/*)
        continue
        ;;
    esac

    source_line_is_rustflags_assignment "$source_line" || continue
    if [[ "$source_line" == *'RUSTFLAGS=*|'* ||
      "$source_line" == *'CARGO_ENCODED_RUSTFLAGS=*|'* ||
      "$source_line" == *'startswith("RUSTFLAGS'* ||
      "$source_line" == *'contains("RUSTFLAGS'* ||
      "$source_line" == *'== "RUSTFLAGS'* ||
      "$source_line" == *'printf '* ||
      "$source_line" == *'echo '* ]]; then
      continue
    fi
    if source_line_is_in_negative_fixture_block "$path" "$line_number"; then
      continue
    fi
    source_record="$(source_assignment_record "$path" "$line_number")"
    if [[ "$source_record" == *"linker-policy-negative-fixture"* ]]; then
      continue
    fi

    # These are literal source-code spellings, not shell expansions.
    # shellcheck disable=SC2016
    if ! source_text_has_effective_lld_optout "$source_record" &&
      [[ "$source_record" != *'${LINKER_POLICY_RUSTFLAG}'* ]] &&
      [[ "$source_record" != *'${linker_policy_rustflag}'* ]] &&
      [[ "$source_record" != *'${required_linker_rustflag}'* ]] &&
      [[ "$source_record" != *'parser_oracle_flags_shell'* ]] &&
      [[ "$source_record" != *'${parser_oracle_flags}'* ]] &&
      [[ "$source_record" != *'writer_flags_shell'* ]] &&
      [[ "$source_record" != *'${writer_flags}'* ]] &&
      [[ "$source_record" != *'parser_parallel_rustflags_shell'* ]] &&
      [[ "$source_record" != *'${parser_parallel_rustflags}'* ]] &&
      [[ "$source_record" != *'compose_linker_policy_rustflags'* ]] &&
      [[ "$source_record" != *'${REPLAY_RUSTFLAGS}'* ]] &&
      [[ "$source_record" != *'$rustflags'* ]] &&
      [[ "$source_record" != *'${rustflags}'* ]] &&
      [[ "$source_record" != *'$RUSTFLAGS'* ]] &&
      [[ "$source_record" != *'${RUSTFLAGS}'* ]] &&
      [[ "$source_record" != *'$CURRENT_RUSTFLAGS'* ]] &&
      [[ "$source_record" != *'${CURRENT_RUSTFLAGS}'* ]] &&
      [[ "$source_record" != *'$CURRENT_ENCODED_RUSTFLAGS'* ]] &&
      [[ "$source_record" != *'${CURRENT_ENCODED_RUSTFLAGS}'* ]] &&
      [[ "$source_record" != *'$gate_rustflags'* ]] &&
      [[ "$source_record" != *'${gate_rustflags}'* ]] &&
      [[ "$source_record" != *'$dw_rustflags'* ]] &&
      [[ "$source_record" != *'${dw_rustflags}'* ]] &&
      [[ "$source_record" != *'$supplied_rustflags'* ]] &&
      [[ "$source_record" != *'${supplied_rustflags}'* ]] &&
      [[ "$source_record" != *'RUSTFLAGS=$(printf'* ]] &&
      [[ "$source_record" != *'parser_parallel_clippy_rustflags'* ]] &&
      [[ "$source_record" != *'RUSTFLAGS=%q'* ]]; then
      printf '%s:%s:%s\n' "$path" "$line_number" "$source_line" >>"$findings_path"
    fi
  done < <(
    git -C "$repo_root" grep -n -I -E \
      '(RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_RUSTFLAGS|CARGO_TARGET_[A-Z0-9_]+_RUSTFLAGS)[[:space:]]*(\+?=|:)' -- \
      .github/workflows scripts runbooks/scripts 2>/dev/null || true
  )

  while IFS= read -r match; do
    local path="${match%%:*}"
    local rest="${match#*:}"
    local line_number="${rest%%:*}"
    local source_line="${rest#*:}"

    case "$path" in
      scripts/testdata/* | scripts/e2e/testdata/*) continue ;;
    esac
    if source_line_is_in_negative_fixture_block "$path" "$line_number" ||
      [[ "$source_line" == *"linker-policy-negative-fixture"* ]]; then
      continue
    fi
    if ! source_text_has_effective_lld_optout "$source_line"; then
      printf '%s:%s:%s\n' "$path" "$line_number" "$source_line" >>"$findings_path"
    fi
  done < <(
    git -C "$repo_root" grep -n -I -E \
      'cargo[^[:cntrl:]]*--config(=|[[:space:]])[^[:cntrl:]]*rustflags' -- \
      .github/workflows scripts runbooks/scripts 2>/dev/null || true
  )

  if [[ -s "$findings_path" ]]; then
    printf 'uncomposed active rustflags overrides:\n' >&2
    sed 's/^/  /' "$findings_path" >&2
    fail "active RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS literals must compose -Clinker-features=-lld"
  fi
}

source_text_has_effective_lld_optout \
  'RUSTFLAGS="-Cdebuginfo=0 -Clinker-features=-lld"' ||
  fail "static exact-token matcher rejected a composed override"
source_text_has_effective_lld_optout \
  'RUSTFLAGS="-Cdebuginfo=0 -C linker-features=-lld"' ||
  fail "static exact-token matcher rejected the documented two-token override"
source_line_is_rustflags_assignment 'RUSTFLAGS="-Dwarnings"' ||
  fail "static assignment matcher missed a direct shell override"
source_line_is_rustflags_assignment '"RUSTFLAGS": "-Dwarnings"' ||
  fail "static assignment matcher missed a quoted mapping override"
if source_text_has_effective_lld_optout \
  'RUSTFLAGS="-Cmetadata=-Clinker-features=-lld"'; then # linker-policy-negative-fixture
  fail "static exact-token matcher accepted a substring-only bypass"
fi
if source_text_has_effective_lld_optout 'RUSTFLAGS="-Dwarnings"'; then # linker-policy-negative-fixture
  fail "static exact-token matcher accepted a non-linker custom override"
fi
if source_line_is_rustflags_assignment \
  'RUSTFLAGS must include -Clinker-features=-lld for proof'; then
  fail "static assignment matcher treated diagnostic prose as an override"
fi
if source_text_has_effective_lld_optout \
  'RUSTFLAGS="-Clinker-features=-lld -Clinker-features=+lld"'; then # linker-policy-negative-fixture
  fail "static exact-token matcher accepted a later linker-feature re-enable"
fi

host_triple="$(rustc -vV | sed -n 's/^host: //p')"
[[ "$host_triple" == "x86_64-unknown-linux-gnu" ]] ||
  fail "unsupported host triple ${host_triple:-unknown}; expected x86_64-unknown-linux-gnu"

assert_repository_policy

linker_identity_log="${tmp_root}/system-linker-identity.log"
if ! "$real_cc" -Wl,--version -x c /dev/null \
  -o "${tmp_root}/system-linker-identity-probe" >"$linker_identity_log" 2>&1; then
  fail "cc could not report the selected system linker; see ${linker_identity_log}"
fi
grep -Fq 'GNU ld' "$linker_identity_log" ||
  fail "supported validation host does not select GNU ld through cc; see ${linker_identity_log}"

cat >"${crate_dir}/Cargo.toml" <<'TOML'
[package]
name = "cargo-linker-policy-smoke"
version = "0.0.0"
edition = "2024"

[[bin]]
name = "cargo-linker-policy-smoke"
path = "src/main.rs"

[workspace]
TOML

cat >"${crate_dir}/Cargo.lock" <<'LOCK'
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "cargo-linker-policy-smoke"
version = "0.0.0"
LOCK

cat >"${crate_dir}/src/main.rs" <<'RS'
fn main() {
    println!("cargo linker policy smoke");
}
RS

cp "${repo_root}/.cargo/config.toml" "${crate_dir}/.cargo/config.toml"

cat >"${bin_dir}/cc" <<'SENTINEL'
#!/usr/bin/env bash
set -euo pipefail
: "${REAL_CC:?REAL_CC must name the system C compiler driver}"
: "${LINKER_SENTINEL_LOG:?LINKER_SENTINEL_LOG must name the invocation log}"
{
  printf '%s\n' '--- cc invocation ---'
  printf '%s\n' "$@"
} >>"$LINKER_SENTINEL_LOG"
for argument in "$@"; do
  if [[ "$argument" == "-fuse-ld=lld" ]]; then
    printf 'sentinel rejected forbidden argument: %s\n' "$argument" >&2
    exit 86
  fi
done
exec "$REAL_CC" "$@"
SENTINEL
chmod +x "${bin_dir}/cc"

run_cargo_without_rustflags() {
  local scenario="$1"
  local output_path="${tmp_root}/${scenario}.log"
  local sentinel_log="${tmp_root}/${scenario}.cc.log"
  : >"$sentinel_log"
  (
    cd "$crate_dir"
    env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
      "PATH=${bin_dir}:${PATH}" \
      "REAL_CC=${real_cc}" \
      "LINKER_SENTINEL_LOG=${sentinel_log}" \
      "CARGO_HOME=${cargo_home}" \
      "CARGO_TARGET_DIR=${tmp_root}/target-${scenario}" \
      CARGO_NET_OFFLINE=true \
      CARGO_TERM_COLOR=never \
      cargo build --offline --locked >"$output_path" 2>&1
  )
}

run_cargo_with_rustflags() {
  local scenario="$1"
  local rustflags="$2"
  local output_path="${tmp_root}/${scenario}.log"
  local sentinel_log="${tmp_root}/${scenario}.cc.log"
  : >"$sentinel_log"
  (
    cd "$crate_dir"
    env -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
      "PATH=${bin_dir}:${PATH}" \
      "REAL_CC=${real_cc}" \
      "LINKER_SENTINEL_LOG=${sentinel_log}" \
      "CARGO_HOME=${cargo_home}" \
      "CARGO_TARGET_DIR=${tmp_root}/target-${scenario}" \
      CARGO_NET_OFFLINE=true \
      CARGO_TERM_COLOR=never \
      "RUSTFLAGS=${rustflags}" \
      cargo build --offline --locked >"$output_path" 2>&1
  )
}

run_cargo_with_encoded_rustflags() {
  local scenario="$1"
  local encoded_rustflags="$2"
  local output_path="${tmp_root}/${scenario}.log"
  local sentinel_log="${tmp_root}/${scenario}.cc.log"
  : >"$sentinel_log"
  (
    cd "$crate_dir"
    env -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
      "PATH=${bin_dir}:${PATH}" \
      "REAL_CC=${real_cc}" \
      "LINKER_SENTINEL_LOG=${sentinel_log}" \
      "CARGO_HOME=${cargo_home}" \
      "CARGO_TARGET_DIR=${tmp_root}/target-${scenario}" \
      CARGO_NET_OFFLINE=true \
      CARGO_TERM_COLOR=never \
      "CARGO_ENCODED_RUSTFLAGS=${encoded_rustflags}" \
      cargo build --offline --locked >"$output_path" 2>&1
  )
}

run_cargo_with_config_rustflags_env() {
  local scenario="$1"
  local variable_name="$2"
  local rustflags="$3"
  local output_path="${tmp_root}/${scenario}.log"
  local sentinel_log="${tmp_root}/${scenario}.cc.log"
  : >"$sentinel_log"
  (
    cd "$crate_dir"
    env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
      "PATH=${bin_dir}:${PATH}" \
      "REAL_CC=${real_cc}" \
      "LINKER_SENTINEL_LOG=${sentinel_log}" \
      "CARGO_HOME=${cargo_home}" \
      "CARGO_TARGET_DIR=${tmp_root}/target-${scenario}" \
      CARGO_NET_OFFLINE=true \
      CARGO_TERM_COLOR=never \
      "${variable_name}=${rustflags}" \
      cargo build --offline --locked >"$output_path" 2>&1
  )
}

run_cargo_without_rustflags config-only ||
  fail "config-only build did not pass; see ${tmp_root}/config-only.log"
[[ -s "${tmp_root}/config-only.cc.log" ]] ||
  fail "config-only build did not invoke the sentinel cc wrapper"
if grep -Fqx -- '-fuse-ld=lld' "${tmp_root}/config-only.cc.log"; then
  fail "config-only build leaked -fuse-ld=lld"
fi

plain_custom_flags='-C link-self-contained=no -C link-arg=-Wl,--build-id=none'
set +e
run_cargo_with_rustflags plain-custom "$plain_custom_flags"
plain_custom_status=$?
set -e
[[ "$plain_custom_status" -ne 0 ]] ||
  fail "plain custom RUSTFLAGS unexpectedly retained target rustflags"
grep -Fqx -- '-fuse-ld=lld' "${tmp_root}/plain-custom.cc.log" ||
  fail "plain custom RUSTFLAGS did not expose replacement via -fuse-ld=lld"
grep -Fq -- 'sentinel rejected forbidden argument: -fuse-ld=lld' \
  "${tmp_root}/plain-custom.log" ||
  fail "plain custom RUSTFLAGS failed without the sentinel rejection"
grep -Fqx -- '-Wl,--build-id=none' "${tmp_root}/plain-custom.cc.log" ||
  fail "plain custom RUSTFLAGS were not forwarded to cc"

substring_bypass_flags='-Cmetadata=-Clinker-features=-lld -C link-arg=-Wl,--build-id=none'
set +e
run_cargo_with_rustflags substring-bypass "$substring_bypass_flags"
substring_bypass_status=$?
set -e
[[ "$substring_bypass_status" -ne 0 ]] ||
  fail "substring-only RUSTFLAGS unexpectedly disabled implicit LLD"
grep -Fqx -- '-fuse-ld=lld' "${tmp_root}/substring-bypass.cc.log" ||
  fail "substring-only RUSTFLAGS did not expose replacement via -fuse-ld=lld"

composed_custom_flags="${plain_custom_flags} -Clinker-features=-lld"
run_cargo_with_rustflags composed-custom "$composed_custom_flags" ||
  fail "composed custom RUSTFLAGS build did not pass; see ${tmp_root}/composed-custom.log"
[[ -s "${tmp_root}/composed-custom.cc.log" ]] ||
  fail "composed custom RUSTFLAGS did not invoke the sentinel cc wrapper"
if grep -Fqx -- '-fuse-ld=lld' "${tmp_root}/composed-custom.cc.log"; then
  fail "composed custom RUSTFLAGS leaked -fuse-ld=lld"
fi
grep -Fqx -- '-Wl,--build-id=none' "${tmp_root}/composed-custom.cc.log" ||
  fail "composed custom RUSTFLAGS did not preserve the caller's link argument"

two_token_custom_flags="${plain_custom_flags} -C linker-features=-lld"
run_cargo_with_rustflags two-token-custom "$two_token_custom_flags" ||
  fail "two-token composed RUSTFLAGS build did not pass; see ${tmp_root}/two-token-custom.log"
if grep -Fqx -- '-fuse-ld=lld' "${tmp_root}/two-token-custom.cc.log"; then
  fail "two-token composed RUSTFLAGS leaked -fuse-ld=lld"
fi

set +e
run_cargo_with_rustflags empty-custom ""
empty_custom_status=$?
set -e
[[ "$empty_custom_status" -ne 0 ]] ||
  fail "empty RUSTFLAGS unexpectedly retained target rustflags"
grep -Fqx -- '-fuse-ld=lld' "${tmp_root}/empty-custom.cc.log" ||
  fail "empty RUSTFLAGS did not expose replacement via -fuse-ld=lld"

later_reenable_flags="${composed_custom_flags} -Z unstable-options -Clinker-features=+lld"
set +e
run_cargo_with_rustflags later-reenable "$later_reenable_flags"
later_reenable_status=$?
set -e
[[ "$later_reenable_status" -ne 0 ]] ||
  fail "later +lld RUSTFLAGS unexpectedly preserved the opt-out"
grep -Fqx -- '-fuse-ld=lld' "${tmp_root}/later-reenable.cc.log" ||
  fail "later +lld RUSTFLAGS did not re-enable implicit LLD"

unit_separator=$'\x1f'
plain_encoded_flags="-Clink-self-contained=no${unit_separator}-Clink-arg=-Wl,--build-id=none"
set +e
run_cargo_with_encoded_rustflags plain-encoded "$plain_encoded_flags"
plain_encoded_status=$?
set -e
[[ "$plain_encoded_status" -ne 0 ]] ||
  fail "plain CARGO_ENCODED_RUSTFLAGS unexpectedly retained target rustflags"
grep -Fqx -- '-fuse-ld=lld' "${tmp_root}/plain-encoded.cc.log" ||
  fail "plain CARGO_ENCODED_RUSTFLAGS did not expose replacement via -fuse-ld=lld"

composed_encoded_flags="${plain_encoded_flags}${unit_separator}-Clinker-features=-lld"
run_cargo_with_encoded_rustflags composed-encoded "$composed_encoded_flags" ||
  fail "composed CARGO_ENCODED_RUSTFLAGS build did not pass; see ${tmp_root}/composed-encoded.log"
if grep -Fqx -- '-fuse-ld=lld' "${tmp_root}/composed-encoded.cc.log"; then
  fail "composed CARGO_ENCODED_RUSTFLAGS leaked -fuse-ld=lld"
fi
grep -Fqx -- '-Wl,--build-id=none' "${tmp_root}/composed-encoded.cc.log" ||
  fail "composed CARGO_ENCODED_RUSTFLAGS did not preserve the caller's link argument"

set +e
run_cargo_with_encoded_rustflags empty-encoded ""
empty_encoded_status=$?
set -e
[[ "$empty_encoded_status" -ne 0 ]] ||
  fail "empty CARGO_ENCODED_RUSTFLAGS unexpectedly retained target rustflags"
grep -Fqx -- '-fuse-ld=lld' "${tmp_root}/empty-encoded.cc.log" ||
  fail "empty CARGO_ENCODED_RUSTFLAGS did not expose replacement via -fuse-ld=lld"

later_reenable_encoded_flags="${composed_encoded_flags}${unit_separator}-Zunstable-options${unit_separator}-Clinker-features=+lld"
set +e
run_cargo_with_encoded_rustflags encoded-later-reenable "$later_reenable_encoded_flags"
encoded_later_reenable_status=$?
set -e
[[ "$encoded_later_reenable_status" -ne 0 ]] ||
  fail "later +lld encoded flags unexpectedly preserved the opt-out"
grep -Fqx -- '-fuse-ld=lld' "${tmp_root}/encoded-later-reenable.cc.log" ||
  fail "later +lld encoded flags did not re-enable implicit LLD"

target_rustflags_variable="CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS"
run_cargo_with_config_rustflags_env target-env-plain "$target_rustflags_variable" "$plain_custom_flags" ||
  fail "target-specific Cargo rustflags env did not merge with target config"
if grep -Fqx -- '-fuse-ld=lld' "${tmp_root}/target-env-plain.cc.log"; then
  fail "target-specific Cargo rustflags env discarded the checked-in opt-out"
fi
grep -Fqx -- '-Wl,--build-id=none' "${tmp_root}/target-env-plain.cc.log" ||
  fail "target-specific Cargo rustflags env was not forwarded"
run_cargo_with_config_rustflags_env target-env-composed "$target_rustflags_variable" "$composed_custom_flags" ||
  fail "composed target-specific Cargo rustflags env failed"

target_env_later_flags="${plain_custom_flags} -Z unstable-options -Clinker-features=+lld"
set +e
run_cargo_with_config_rustflags_env target-env-later "$target_rustflags_variable" "$target_env_later_flags"
target_env_later_status=$?
set -e
[[ "$target_env_later_status" -ne 0 ]] ||
  fail "later +lld target-specific Cargo rustflags env unexpectedly preserved the opt-out"
grep -Fqx -- '-fuse-ld=lld' "${tmp_root}/target-env-later.cc.log" ||
  fail "later +lld target-specific Cargo rustflags env did not re-enable implicit LLD"

run_cargo_with_config_rustflags_env build-env-plain CARGO_BUILD_RUSTFLAGS "$plain_custom_flags" ||
  fail "CARGO_BUILD_RUSTFLAGS should remain subordinate to the target-specific policy"
if grep -Fqx -- '-fuse-ld=lld' "${tmp_root}/build-env-plain.cc.log"; then
  fail "CARGO_BUILD_RUSTFLAGS displaced the target-specific opt-out"
fi
run_cargo_with_config_rustflags_env build-env-composed CARGO_BUILD_RUSTFLAGS "$composed_custom_flags" ||
  fail "composed CARGO_BUILD_RUSTFLAGS failed"

printf 'cargo linker policy smoke passed\n'
printf 'config-only: pass\n'
printf 'plain custom RUSTFLAGS: expected replacement failure (status=%s)\n' "$plain_custom_status"
printf 'substring-only RUSTFLAGS: expected replacement failure (status=%s)\n' "$substring_bypass_status"
printf 'composed custom RUSTFLAGS: pass\n'
printf 'two-token composed RUSTFLAGS: pass\n'
printf 'empty RUSTFLAGS: expected replacement failure (status=%s)\n' "$empty_custom_status"
printf 'later +lld RUSTFLAGS: expected re-enable failure (status=%s)\n' "$later_reenable_status"
printf 'plain CARGO_ENCODED_RUSTFLAGS: expected replacement failure (status=%s)\n' "$plain_encoded_status"
printf 'composed CARGO_ENCODED_RUSTFLAGS: pass\n'
printf 'empty CARGO_ENCODED_RUSTFLAGS: expected replacement failure (status=%s)\n' "$empty_encoded_status"
printf 'later +lld CARGO_ENCODED_RUSTFLAGS: expected re-enable failure (status=%s)\n' "$encoded_later_reenable_status"
printf 'target-specific Cargo rustflags env: merges target opt-out; later +lld status=%s; composed pass\n' "$target_env_later_status"
printf 'CARGO_BUILD_RUSTFLAGS: target-specific policy remains authoritative; composed pass\n'
printf 'retained smoke path: %s\n' "$tmp_root"
