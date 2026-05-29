#!/usr/bin/env bash
#
# frankenctl installer (franken_engine)
#
# One-liner install (with cache buster):
#   curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/franken_engine/main/install.sh?$(date +%s)" | bash
#
# Or without cache buster:
#   curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/franken_engine/main/install.sh | bash
#
# Options:
#   --version vX.Y.Z    Install a specific release tag (default: latest)
#   --prefix PATH       Install under PATH/bin (default: ~/.local).
#   --dest DIR          Install the binary directly into DIR (overrides --prefix).
#   --method MODE       auto (default) tries a checksum-verified GitHub release,
#                       then falls back to a source build. Values: auto|release|source.
#   --ref REF           Git ref for the source build path (default: main).
#   --offline TARBALL   Install from a local release tarball; skip all network access.
#   --easy-mode         Auto-update PATH in shell rc files (~/.zshrc, ~/.bashrc).
#   --verify            Run `frankenctl --version` self-test after install.
#   --force             Reinstall even if the target version is already present.
#   --no-verify         Skip checksum + signature verification (testing only).
#   --quiet             Suppress non-error output.
#   --no-gum            Disable gum formatting even if available.
#   -h, --help          Show this help text.
#
# Release artifacts follow the fleet convention (produced by dsr):
#   asset      : frankenctl-<target-triple>.tar.xz
#   checksum   : frankenctl-<target-triple>.tar.xz.sha256       (sha256sum format)
#   signature  : frankenctl-<target-triple>.tar.xz.sigstore.json (cosign, optional)
#
set -euo pipefail
umask 022
shopt -s lastpipe 2>/dev/null || true

OWNER="${OWNER:-Dicklesworthstone}"
REPO="${REPO:-franken_engine}"
BINARY_NAME="frankenctl"
CARGO_PACKAGE="frankenengine-engine"

VERSION="${VERSION:-}"
DEFAULT_PREFIX="${HOME}/.local"
PREFIX="${DEFAULT_PREFIX}"
DEST=""
METHOD="auto"
SOURCE_REF="${FRANKEN_ENGINE_REF:-main}"
OFFLINE_TARBALL=""
EASY=0
VERIFY=0
FORCE_INSTALL=0
NO_CHECKSUM=0
QUIET=0
NO_GUM=0
WORK_DIR=""
LOCK_DIR="${TMPDIR:-/tmp}/frankenctl-install.lock"
LOCK_HELD=0

COSIGN_IDENTITY_RE="${COSIGN_IDENTITY_RE:-^https://github.com/${OWNER}/${REPO}/.github/workflows/.*@refs/tags/.*$}"
COSIGN_OIDC_ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

# ── Output stack: gum when available, ANSI fallback otherwise ──────────────────
HAS_GUM=0
if command -v gum >/dev/null 2>&1 && [ -t 1 ]; then
  HAS_GUM=1
fi

info() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then gum style --foreground 39 "→ $*"
  else echo -e "\033[0;34m→\033[0m $*"; fi
}
ok() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then gum style --foreground 42 "✓ $*"
  else echo -e "\033[0;32m✓\033[0m $*"; fi
}
warn() {
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then gum style --foreground 214 "⚠ $*" >&2
  else echo -e "\033[1;33m⚠\033[0m $*" >&2; fi
}
err() {
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then gum style --foreground 196 "✗ $*" >&2
  else echo -e "\033[0;31m✗\033[0m $*" >&2; fi
}
die() { err "$*"; exit 1; }

run_with_spinner() {
  local title="$1"; shift
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ] && [ "$QUIET" -eq 0 ]; then
    gum spin --spinner dot --title "$title" -- "$@"
  else
    info "$title"; "$@"
  fi
}

draw_box() {
  local color="$1"; shift
  local lines=("$@")
  local max_width=0 esc; esc=$(printf '\033')
  local strip="s/${esc}\\[[0-9;]*m//g"
  local line stripped len i
  for line in "${lines[@]}"; do
    stripped=$(printf '%b' "$line" | LC_ALL=C sed "$strip"); len=${#stripped}
    [ "$len" -gt "$max_width" ] && max_width=$len
  done
  local inner=$((max_width + 4)) border=""
  for ((i=0; i<inner; i++)); do border+="═"; done
  printf "\033[%sm╔%s╗\033[0m\n" "$color" "$border"
  for line in "${lines[@]}"; do
    stripped=$(printf '%b' "$line" | LC_ALL=C sed "$strip"); len=${#stripped}
    local pad=$((max_width - len)) pad_str=""
    for ((i=0; i<pad; i++)); do pad_str+=" "; done
    printf "\033[%sm║\033[0m  %b%s  \033[%sm║\033[0m\n" "$color" "$line" "$pad_str" "$color"
  done
  printf "\033[%sm╚%s╝\033[0m\n" "$color" "$border"
}

banner() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --border normal --border-foreground 39 --padding "0 1" --margin "1 0" \
      "$(gum style --foreground 42 --bold 'frankenctl installer')" \
      "$(gum style --foreground 245 'franken_engine control-plane CLI')"
  else
    echo
    draw_box "0;36" "\033[1;32mfrankenctl installer\033[0m" "\033[0;90mfranken_engine control-plane CLI\033[0m"
    echo
  fi
}

usage() { sed -n '3,38p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; }

# ── Cleanup / locking ─────────────────────────────────────────────────────────
cleanup() {
  [ "$LOCK_HELD" -eq 1 ] && rmdir "$LOCK_DIR" 2>/dev/null || true
  if [ -n "${WORK_DIR:-}" ] && [ -d "${WORK_DIR}" ]; then
    case "${WORK_DIR}" in
      "${TMPDIR:-/tmp}"/frankenctl-install.*) rm -rf -- "${WORK_DIR}" ;;
      *) warn "refusing to remove unexpected temp dir: ${WORK_DIR}" ;;
    esac
  fi
}
trap cleanup EXIT INT TERM

acquire_lock() {
  local tries=0
  while ! mkdir "$LOCK_DIR" 2>/dev/null; do
    if [ -f "$LOCK_DIR/pid" ]; then
      local opid; opid=$(cat "$LOCK_DIR/pid" 2>/dev/null || echo "")
      if [ -n "$opid" ] && ! kill -0 "$opid" 2>/dev/null; then
        warn "Removing stale install lock (pid $opid gone)"
        rm -rf "$LOCK_DIR" 2>/dev/null || true; continue
      fi
    fi
    tries=$((tries + 1))
    [ "$tries" -gt 30 ] && die "another install is in progress (lock: $LOCK_DIR)"
    sleep 1
  done
  echo "$$" > "$LOCK_DIR/pid"; LOCK_HELD=1
}

# ── Helpers ───────────────────────────────────────────────────────────────────
command_exists() { command -v "$1" >/dev/null 2>&1; }
require_command() { command_exists "$1" || die "required command not found: $1"; }

PROXY_ARGS=()
setup_proxy() {
  if [ -n "${HTTPS_PROXY:-}" ]; then PROXY_ARGS=(--proxy "$HTTPS_PROXY")
  elif [ -n "${HTTP_PROXY:-}" ]; then PROXY_ARGS=(--proxy "$HTTP_PROXY"); fi
}

compute_sha256() {
  local file="$1"
  if command_exists sha256sum; then sha256sum "$file" | awk '{print $1}'
  elif command_exists shasum; then shasum -a 256 "$file" | awk '{print $1}'
  elif command_exists openssl; then openssl dgst -sha256 "$file" | awk '{print $NF}'
  else die "no SHA-256 tool found (install sha256sum, shasum, or openssl)"; fi
}

# frankenctl exposes `frankenctl version` (subcommand), not `--version`.
bin_version() { "$DEST_DIR/$BINARY_NAME" version 2>/dev/null || "$DEST_DIR/$BINARY_NAME" --version 2>/dev/null; }

# Map OS/arch → Rust target triple (matches the dsr release matrix / DCG installer).
detect_platform() {
  local os arch
  os="$(uname -s | tr 'A-Z' 'a-z')"
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    arm64|aarch64|arm64e) arch="aarch64" ;;
    *) die "unsupported architecture: $arch" ;;
  esac
  case "${os}-${arch}" in
    linux-x86_64)   TARGET="x86_64-unknown-linux-musl" ; TARGET_FALLBACK="x86_64-unknown-linux-gnu" ;;
    linux-aarch64)  TARGET="aarch64-unknown-linux-gnu" ; TARGET_FALLBACK="" ;;
    darwin-x86_64)  TARGET="x86_64-apple-darwin"       ; TARGET_FALLBACK="" ;;
    darwin-aarch64) TARGET="aarch64-apple-darwin"      ; TARGET_FALLBACK="" ;;
    *) die "unsupported platform: ${os}/${arch}" ;;
  esac
  if [ "$os" = "linux" ] && grep -qi microsoft /proc/version 2>/dev/null; then
    warn "WSL detected — continuing with the linux build"
  fi
}

asset_name() { printf '%s-%s.tar.xz\n' "$BINARY_NAME" "$1"; }   # arg: target triple
download_url() { printf 'https://github.com/%s/%s/releases/download/%s/%s\n' "$OWNER" "$REPO" "$1" "$2"; }
latest_release_api_url() { printf 'https://api.github.com/repos/%s/%s/releases/latest\n' "$OWNER" "$REPO"; }

download_file() {
  curl -fL --retry 3 --retry-delay 1 --connect-timeout 15 "${PROXY_ARGS[@]}" -o "$2" "$1" 2>/dev/null
}

discover_latest_release_tag() {
  local response tag
  response="$(curl -fsSL "${PROXY_ARGS[@]}" "$(latest_release_api_url)" 2>/dev/null)" || return 1
  tag="$(printf '%s\n' "$response" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  [ -n "$tag" ] || return 1
  printf '%s\n' "$tag"
}

# ── Preflight ─────────────────────────────────────────────────────────────────
resolve_dest_dir() { if [ -n "$DEST" ]; then DEST_DIR="$DEST"; else DEST_DIR="${PREFIX}/bin"; fi; }

preflight_checks() {
  info "Running preflight checks"
  resolve_dest_dir
  local avail_kb
  avail_kb=$(df -Pk "${TMPDIR:-/tmp}" 2>/dev/null | awk 'NR==2 {print $4}')
  if [ -n "$avail_kb" ] && [ "$avail_kb" -lt 81920 ]; then
    warn "low disk space in ${TMPDIR:-/tmp} (${avail_kb}KB free)"
  fi
  mkdir -p "$DEST_DIR" 2>/dev/null || die "cannot create install dir: $DEST_DIR"
  [ -w "$DEST_DIR" ] || die "install dir not writable: $DEST_DIR"
  if [ -x "$DEST_DIR/$BINARY_NAME" ]; then
    info "Existing install: $(bin_version | head -n1 || echo unknown)"
  fi
}

check_already_installed() {
  [ "$FORCE_INSTALL" -eq 1 ] && return 1
  [ -z "$VERSION" ] && return 1
  [ -x "$DEST_DIR/$BINARY_NAME" ] || return 1
  bin_version | grep -qF "${VERSION#v}"
}

# ── Verification ──────────────────────────────────────────────────────────────
verify_checksum() {
  local archive="$1" sha_url="$2"
  [ "$NO_CHECKSUM" -eq 1 ] && { warn "checksum verification skipped (--no-verify)"; return 0; }
  local sha_file; sha_file="${WORK_DIR}/$(basename "$archive").sha256"
  download_file "$sha_url" "$sha_file" || { warn "no .sha256 sidecar for $(basename "$archive")"; return 1; }
  local expected actual
  expected="$(awk '{print $1; exit}' "$sha_file")"
  [ -n "$expected" ] || { warn "empty checksum sidecar"; return 1; }
  actual="$(compute_sha256 "$archive")"
  [ "$actual" = "$expected" ] || die "SHA-256 mismatch: expected $expected, got $actual"
  ok "Checksum verified"
}

verify_sigstore() {
  local archive="$1" sig_url="$2"
  command_exists cosign || { info "cosign not found — skipping signature verification"; return 0; }
  local bundle; bundle="${WORK_DIR}/$(basename "$archive").sigstore.json"
  download_file "$sig_url" "$bundle" || { info "no sigstore bundle published — skipping"; return 0; }
  if cosign verify-blob --bundle "$bundle" \
       --certificate-identity-regexp "$COSIGN_IDENTITY_RE" \
       --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" "$archive" >/dev/null 2>&1; then
    ok "Signature verified (cosign)"
  else
    die "cosign signature verification FAILED"
  fi
}

# ── Install ───────────────────────────────────────────────────────────────────
install_binary() {
  require_command install
  mkdir -p "$DEST_DIR"
  install -m 0755 "$1" "$DEST_DIR/$BINARY_NAME"
  ok "Installed $BINARY_NAME → $DEST_DIR/$BINARY_NAME"
}

extract_and_install() {
  local archive="$1" extract_dir="${WORK_DIR}/extract"
  require_command tar
  mkdir -p "$extract_dir"
  tar -xf "$archive" -C "$extract_dir"   # tar auto-detects .xz/.gz
  local bin
  bin="$(find "$extract_dir" -type f -name "$BINARY_NAME" -perm -u+x | head -n1)"
  [ -n "$bin" ] || die "archive did not contain an executable $BINARY_NAME"
  install_binary "$bin"
}

# Try a single target triple's asset; returns 1 on any miss.
try_release_target() {
  local tag="$1" target="$2" asset url archive
  asset="$(asset_name "$target")"
  url="$(download_url "$tag" "$asset")"
  archive="${WORK_DIR}/${asset}"
  info "Trying release asset ${asset} (${tag})"
  download_file "$url" "$archive" || { warn "asset not found: $asset"; return 1; }
  verify_checksum "$archive" "${url}.sha256" || return 1
  verify_sigstore "$archive" "${url}.sigstore.json"
  extract_and_install "$archive"
}

install_from_release() {
  local tag="$1"
  try_release_target "$tag" "$TARGET" && return 0
  if [ -n "${TARGET_FALLBACK:-}" ]; then
    info "Primary target failed; trying fallback ${TARGET_FALLBACK}"
    try_release_target "$tag" "$TARGET_FALLBACK" && return 0
  fi
  return 1
}

install_from_offline() {
  [ -f "$OFFLINE_TARBALL" ] || die "offline tarball not found: $OFFLINE_TARBALL"
  info "Installing from local tarball: $OFFLINE_TARBALL"
  extract_and_install "$OFFLINE_TARBALL"
}

install_from_source() {
  require_command git
  command_exists cargo || die "cargo is required for the source build; install Rust via rustup, or use a published release"
  local src="${WORK_DIR}/source" url="https://github.com/${OWNER}/${REPO}.git"
  mkdir -p "$src"
  info "Cloning ${REPO}@${SOURCE_REF} for source build"
  if ! git clone --filter=blob:none --depth 1 --branch "$SOURCE_REF" "$url" "$src" 2>/dev/null; then
    (cd "$src" && git init -q && git remote add origin "$url" \
       && git fetch --depth 1 origin "$SOURCE_REF" && git checkout -q --detach FETCH_HEAD) \
      || die "failed to fetch ${REPO}@${SOURCE_REF}"
  fi
  info "Building $BINARY_NAME from source (Standalone Mode — this can take a while)"
  run_with_spinner "cargo build --release" \
    env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo build --release --manifest-path "$src/Cargo.toml" -p "$CARGO_PACKAGE" --bin "$BINARY_NAME"
  local built="$src/target/release/$BINARY_NAME"
  [ -x "$built" ] || die "expected built binary at $built"
  install_binary "$built"
}

# ── Shell integration ─────────────────────────────────────────────────────────
install_completions() {
  local bin="$DEST_DIR/$BINARY_NAME" sh target
  "$bin" completions --help >/dev/null 2>&1 || return 0
  for sh in bash zsh fish; do
    case "$sh" in
      bash) target="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/$BINARY_NAME" ;;
      zsh)  target="${XDG_DATA_HOME:-$HOME/.local/share}/zsh/site-functions/_$BINARY_NAME" ;;
      fish) target="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/$BINARY_NAME.fish" ;;
    esac
    mkdir -p "$(dirname "$target")" 2>/dev/null || continue
    if "$bin" completions "$sh" > "$target" 2>/dev/null; then info "Installed $sh completions"
    else rm -f "$target" 2>/dev/null || true; fi
  done
}

maybe_add_path() {
  case ":$PATH:" in *:"$DEST_DIR":*) return 0 ;; esac
  if [ "$EASY" -eq 1 ]; then
    local rc
    for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
      [ -e "$rc" ] && [ -w "$rc" ] && echo "export PATH=\"$DEST_DIR:\$PATH\"" >> "$rc"
    done
    warn "Added $DEST_DIR to PATH in shell rc files — restart your shell"
  else
    warn "$DEST_DIR is not on PATH. Add it, or re-run with --easy-mode"
  fi
}

self_test() {
  [ "$VERIFY" -eq 1 ] || return 0
  info "Running self-test"
  bin_version >/dev/null 2>&1 \
    && ok "Self-test passed" || warn "Self-test could not run $BINARY_NAME --version"
}

final_summary() {
  [ "$QUIET" -eq 1 ] && return 0
  local ver; ver="$(bin_version | head -n1 || echo "$BINARY_NAME")"
  echo
  draw_box "0;32" \
    "\033[1;32m✓ $BINARY_NAME installed\033[0m" \
    "Version : $ver" \
    "Location: $DEST_DIR/$BINARY_NAME" \
    "" \
    "Run \033[1mfrankenctl --help\033[0m to get started." \
    "Uninstall: rm -f $DEST_DIR/$BINARY_NAME"
  echo
}

# ── Arg parsing ───────────────────────────────────────────────────────────────
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --version) shift; [ $# -gt 0 ] || die "--version requires a tag"; VERSION="$1" ;;
      --prefix)  shift; [ $# -gt 0 ] || die "--prefix requires a path"; PREFIX="$1" ;;
      --dest)    shift; [ $# -gt 0 ] || die "--dest requires a dir"; DEST="$1" ;;
      --method)  shift; [ $# -gt 0 ] || die "--method requires auto|release|source"; METHOD="$1" ;;
      --ref)     shift; [ $# -gt 0 ] || die "--ref requires a git ref"; SOURCE_REF="$1" ;;
      --offline) shift; [ $# -gt 0 ] || die "--offline requires a tarball path"; OFFLINE_TARBALL="$1"; METHOD="offline" ;;
      --easy-mode) EASY=1 ;;
      --verify)    VERIFY=1 ;;
      --force)     FORCE_INSTALL=1 ;;
      --no-verify) NO_CHECKSUM=1 ;;
      --quiet)     QUIET=1 ;;
      --no-gum)    NO_GUM=1 ;;
      -h|--help)   usage; exit 0 ;;
      *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
  done
  case "$METHOD" in auto|release|source|offline) ;; *) die "unsupported --method: $METHOD" ;; esac
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  parse_args "$@"
  require_command curl
  setup_proxy
  banner
  detect_platform
  info "Platform: ${TARGET} — install prefix: ${DEST:-$PREFIX}"

  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/frankenctl-install.XXXXXXXX")"
  acquire_lock
  preflight_checks

  if check_already_installed; then
    ok "$BINARY_NAME $VERSION already installed (use --force to reinstall)"
    install_completions; self_test; exit 0
  fi

  if [ "$METHOD" = "offline" ]; then
    install_from_offline; install_completions; maybe_add_path; self_test; final_summary; return 0
  fi

  if [ "$METHOD" = "auto" ] || [ "$METHOD" = "release" ]; then
    local tag="$VERSION"
    [ -z "$tag" ] && tag="$(discover_latest_release_tag || true)"
    if [ -n "$tag" ]; then
      if install_from_release "$tag"; then
        install_completions; maybe_add_path; self_test; final_summary; return 0
      fi
      [ "$METHOD" = "release" ] && die "release install failed for tag $tag"
      warn "no usable release asset for ${TARGET}; falling back to source build"
    else
      [ "$METHOD" = "release" ] && die "no published GitHub releases found for ${OWNER}/${REPO}"
      warn "no published GitHub releases found; falling back to source build"
    fi
  fi

  install_from_source
  install_completions; maybe_add_path; self_test; final_summary
}

# Run main when executed or piped (curl | bash leaves BASH_SOURCE unset under set -u),
# but not when sourced for testing.
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
  main "$@"
fi
