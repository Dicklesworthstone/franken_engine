#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
tmp_root="${TMPDIR:-/tmp}/franken-engine-shell-hygiene-smoke-${timestamp}-$$"
good_dir="${tmp_root}/good"
bad_dir="${tmp_root}/bad"
mkdir -p "$good_dir" "$bad_dir"

cat >"${good_dir}/clean.sh" <<'GOOD'
#!/usr/bin/env bash
set -euo pipefail

name="${1:-world}"
printf 'hello %s\n' "$name"
GOOD

cat >"${bad_dir}/syntax.sh" <<'BAD_SYNTAX'
#!/usr/bin/env bash
set -euo pipefail

echo "unterminated
BAD_SYNTAX

cat >"${bad_dir}/shellcheck.sh" <<'BAD_SHELLCHECK'
#!/usr/bin/env bash
set -euo pipefail

name="${1:-world}"
printf 'hello %s\n' $name
BAD_SHELLCHECK

"${repo_root}/scripts/check_shell_hygiene.sh" --strict --root "$tmp_root" good >/dev/null

if "${repo_root}/scripts/check_shell_hygiene.sh" --strict --root "$tmp_root" bad \
  --report-jsonl "${tmp_root}/strict-report.jsonl" >"${tmp_root}/strict.stdout" 2>"${tmp_root}/strict.stderr"; then
  echo "expected bad shell fixtures to fail strict mode" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if ! grep -q 'bash-n' "${tmp_root}/strict-report.jsonl"; then
  echo "expected bash-n finding in strict report" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if ! grep -q 'shellcheck' "${tmp_root}/strict-report.jsonl"; then
  echo "expected shellcheck finding in strict report" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

"${repo_root}/scripts/check_shell_hygiene.sh" --root "$tmp_root" bad \
  --report-jsonl "${tmp_root}/advisory-report.jsonl" >"${tmp_root}/advisory.stdout" 2>"${tmp_root}/advisory.stderr"

if ! grep -q 'shell hygiene advisory' "${tmp_root}/advisory.stderr"; then
  echo "expected advisory summary for bad fixtures" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

echo "shell hygiene smoke passed"
echo "smoke artifacts: ${tmp_root}"
