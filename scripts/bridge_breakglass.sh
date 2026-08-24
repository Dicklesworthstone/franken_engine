#!/usr/bin/env bash
# Signed break-glass override for the BRIDGE closeout gate.
#
# Owning bead: bd-performance-conformance-bridge-tu32j.22.61
#
# Records a bridge_closeout gate PASS whose provider is `breakglass:<sighex16>`
# so a protected decomposed parent can be closed while incomplete. This path is
# deliberately separate from normal completion:
#   - requires an HMAC-SHA256 signature over (bead, UTC date, reason) made with
#     an operator-held key file;
#   - embeds the full signature, actor, and reason in the append-only gate note;
#   - scripts/bridge_closeout_verify.py flags every break-glass-backed node as
#     `breakglass_not_normal_completion`, so any later verification of the
#     parent FAILS until the underlying work is genuinely completed.
#
# Usage:
#   BRIDGE_BREAKGLASS_KEY_FILE=/path/to/key scripts/bridge_breakglass.sh <bead-id> "<reason>"
#
# Key file: env BRIDGE_BREAKGLASS_KEY_FILE, else
# ~/.config/franken_engine/bridge_breakglass.key. Refuses to run without one.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BEAD_ID="${1:?usage: bridge_breakglass.sh <bead-id> \"<reason>\"}"
REASON="${2:?usage: bridge_breakglass.sh <bead-id> \"<reason>\"}"

KEY_FILE="${BRIDGE_BREAKGLASS_KEY_FILE:-$HOME/.config/franken_engine/bridge_breakglass.key}"
if [[ ! -f "$KEY_FILE" ]]; then
  echo "FAIL break-glass key file not found: $KEY_FILE" >&2
  echo "     break-glass requires an operator-held key; see script header." >&2
  exit 2
fi

if [[ ${#REASON} -lt 20 ]]; then
  echo "FAIL break-glass reason must be at least 20 characters (got ${#REASON})." >&2
  exit 2
fi

DATE_UTC="$(date -u +%Y-%m-%d)"
ACTOR="${BR_AGENT_NAME:-$(id -un)}"
PAYLOAD="breakglass|${BEAD_ID}|${DATE_UTC}|${REASON}"
SIG="$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -hmac "$(cat "$KEY_FILE")" | awk '{print $NF}')"
PROVIDER="breakglass:${SIG:0:16}"
NOTE="sig=${SIG} date=${DATE_UTC} actor=${ACTOR} reason=${REASON}"

echo "BREAK-GLASS recording signed pass for $BEAD_ID" >&2
echo "  provider: $PROVIDER" >&2
echo "  reason:   $REASON" >&2

br gate report "$BEAD_ID" --gate bridge_closeout --provider "$PROVIDER" \
  --status pass --to closed --note "$NOTE" --no-auto-import >/dev/null

br label add "$BEAD_ID" breakglass-closed --no-auto-import >/dev/null 2>&1 || true

cat >&2 <<'EOF'
Recorded. Consequences:
  - `br close` will now accept this bead (--force still needed if children open).
  - The closure is permanently marked breakglass-closed.
  - Every later bridge closeout verification that covers this node DENIES with
    breakglass_not_normal_completion until real completion is verified.
EOF
echo "OK break-glass recorded for $BEAD_ID (${DATE_UTC})"
