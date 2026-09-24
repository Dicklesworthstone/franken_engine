# shellcheck shell=bash
# Resolve a tc39/test262 tree at the pinned commit without mutating any shared
# checkout (bd-9vouw.4).
#
# Several agents share one checkout (default /data/projects/test262_corpus) that
# moves with upstream; `git checkout <pin>` there would silently change every
# other consumer's corpus. Instead, when the given checkout is not at the pin,
# this uses (or creates) a detached worktree of the pinned commit next to it.
# `git worktree add --detach` only adds metadata under the shared .git: the
# shared checkout's HEAD and files are untouched.
#
# Usage:
#   source scripts/lib/test262_pinned_tree.sh
#   tree="$(test262_pinned_tree "$checkout" "$pins_toml")" || exit 2
#
# Prints the resolved tree on stdout, diagnostics on stderr. Returns non-zero
# (never guesses) when the pin cannot be read, the pinned commit is absent from
# the checkout, or the worktree path is occupied by a different revision.
# TEST262_PINNED_WORKTREE overrides the worktree location.

test262_pinned_commit() {
  local pins="$1"
  sed -n 's/^[[:space:]]*test262_commit[[:space:]]*=[[:space:]]*"\{0,1\}\([0-9a-f]\{40\}\)"\{0,1\}.*/\1/p' "$pins" | head -n 1
}

test262_pinned_tree() {
  local checkout="${1%/}" pins="$2" pin actual tree tree_head
  pin="$(test262_pinned_commit "$pins")"
  if [[ -z "$pin" ]]; then
    echo "test262_pinned_tree: no test262_commit pin in $pins" >&2
    return 1
  fi
  actual="$(git -C "$checkout" rev-parse HEAD 2>/dev/null || true)"
  if [[ -z "$actual" ]]; then
    echo "test262_pinned_tree: $checkout is not a git checkout of tc39/test262" >&2
    return 1
  fi
  if [[ "$actual" == "$pin" ]]; then
    printf '%s\n' "$checkout"
    return 0
  fi

  tree="${TEST262_PINNED_WORKTREE:-${checkout}_${pin:0:12}}"
  tree_head="$(git -C "$tree" rev-parse HEAD 2>/dev/null || true)"
  if [[ "$tree_head" == "$pin" ]]; then
    echo "test262_pinned_tree: using pinned worktree $tree ($checkout is at ${actual:0:12})" >&2
    printf '%s\n' "$tree"
    return 0
  fi
  if [[ -e "$tree" ]]; then
    echo "test262_pinned_tree: $tree exists at ${tree_head:-<not a checkout>}, not pinned $pin; set TEST262_PINNED_WORKTREE to another path" >&2
    return 1
  fi
  if ! git -C "$checkout" cat-file -e "${pin}^{commit}" 2>/dev/null; then
    echo "test262_pinned_tree: $checkout lacks pinned commit $pin (fetch it without touching the working tree: git -C $checkout fetch origin $pin)" >&2
    return 1
  fi
  echo "test262_pinned_tree: creating detached worktree of $pin at $tree" >&2
  git -C "$checkout" worktree add --detach "$tree" "$pin" >&2 || return 1
  printf '%s\n' "$tree"
}
