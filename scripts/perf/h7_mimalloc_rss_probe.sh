#!/bin/bash
set -euo pipefail

# PERF-H7 (bd-o4cbn.3.6): standalone peak-RSS probe isolating the mimalloc
# memory behaviour that the H7.2 bench gate (scripts/perf/h7_bench_validate.sh)
# observed as a uniform ~40 MB "floor" across all eight sub-benches.
#
# WHY a standalone probe: the H7.2 bench compares HEAD (mimalloc) against the
# frozen pass1 baseline (system allocator). That comparison crosses an allocator
# boundary AND uses 6-8 MB micro-bench baselines as the denominator, so a fixed
# multi-MB allocator reserve reads as a +400-600 % "regression" even though the
# absolute footprint is trivial. This probe removes the engine + Criterion from
# the picture and measures the allocator overhead directly, with a workload
# whose logical working set is tiny and constant, so any elevated RSS is purely
# allocator behaviour. It also tests the env-var levers, answering the
# bd-o4cbn.3.6 question "can the floor be tuned away" with reproducible numbers.
#
# Findings this probe reproduces (recorded in docs/PERFORMANCE_BASELINE.md, H7):
#   * mimalloc imposes NO universal fixed RSS floor: a small process stays at
#     ~3.8 MB (single-thread) / ~5 MB (8-thread).
#   * The bench-level elevation is PURGE-DELAY RETENTION, not arena eager-commit:
#     MIMALLOC_ARENA_EAGER_COMMIT=0 does nothing; MIMALLOC_PURGE_DELAY=0 drops
#     RSS at or below the system allocator (immediate decommit of freed pages).
#   * The ~1 GB VmSize is reserved *virtual* address space, never resident.
#
# Usage: scripts/perf/h7_mimalloc_rss_probe.sh [--threads N] [--rounds R]
# Builds a throwaway crate under $TMPDIR (left in place; never deletes anything),
# pinned to the in-tree mimalloc version, and prints a table.

THREADS="${PROBE_THREADS:-8}"
ROUNDS="${PROBE_ROUNDS:-20000}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --threads) THREADS="$2"; shift 2 ;;
        --rounds) ROUNDS="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

CARGO="${CARGO:-/home/ubuntu/.cargo/bin/cargo}"
WORK="${H7_PROBE_DIR:-${TMPDIR:-/tmp}/h7_mimalloc_rss_probe}"
mkdir -p "$WORK/src"

cat > "$WORK/Cargo.toml" <<'EOF'
[package]
name = "h7_mimalloc_rss_probe"
version = "0.0.0"
edition = "2021"

[dependencies]
mimalloc = { version = "0.1", default-features = false, optional = true }

[features]
default = []
mi = ["dep:mimalloc"]

[profile.release]
opt-level = 3
EOF

cat > "$WORK/src/main.rs" <<'EOF'
// Threaded allocate/free churn with a tiny, constant steady working set. Any
// resident memory beyond a few MB is allocator overhead, not logical demand.
#[cfg(feature = "mi")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn vm_kb(key: &str) -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            return rest.trim().trim_end_matches(" kB").trim().parse().unwrap_or(0);
        }
    }
    0
}

fn churn(rounds: usize, seed: usize) -> usize {
    let mut keep: Vec<Vec<u8>> = Vec::new();
    let mut acc = 0usize;
    for r in 0..rounds {
        let n = 256 + ((r + seed) % 64) * 64;
        let mut v = vec![0u8; n];
        let mut i = 0;
        while i < v.len() {
            v[i] = ((r ^ seed) & 0xff) as u8;
            i += 4096;
        }
        acc = acc.wrapping_add(v[0] as usize);
        if r % 16 == 0 { keep.push(v); }
        if keep.len() > 64 { keep.remove(0); }
    }
    acc.wrapping_add(keep.iter().map(|v| v.len()).sum::<usize>())
}

fn main() {
    let nthreads: usize = std::env::var("PROBE_THREADS").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(8);
    let rounds: usize = std::env::var("PROBE_ROUNDS").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(20000);
    let mut acc = churn(rounds, 0);
    let handles: Vec<_> = (0..nthreads)
        .map(|t| std::thread::spawn(move || churn(rounds, t * 7 + 1)))
        .collect();
    for h in handles { acc = acc.wrapping_add(h.join().unwrap()); }
    let alloc = if cfg!(feature = "mi") { "mimalloc" } else { "system" };
    std::hint::black_box(acc);
    println!(
        "alloc={alloc} threads={nthreads} VmHWM_kb={} VmRSS_kb={} VmSize_kb={}",
        vm_kb("VmHWM:"), vm_kb("VmRSS:"), vm_kb("VmSize:")
    );
}
EOF

echo "[h7-probe] build dir: $WORK  (threads=$THREADS rounds=$ROUNDS)"
( cd "$WORK"
  RCH_CARGO_WRAPPER_BYPASS=1 CARGO_INCREMENTAL=0 "$CARGO" build --release --features mi -q
  cp target/release/h7_mimalloc_rss_probe /tmp/h7_probe_mi
  RCH_CARGO_WRAPPER_BYPASS=1 CARGO_INCREMENTAL=0 "$CARGO" build --release -q
  cp target/release/h7_mimalloc_rss_probe /tmp/h7_probe_sys
)

export PROBE_THREADS="$THREADS" PROBE_ROUNDS="$ROUNDS"
echo "[h7-probe] results (VmHWM = peak RSS = what /usr/bin/time reports):"
printf '  %-46s %s\n' "system allocator" "$(/tmp/h7_probe_sys)"
printf '  %-46s %s\n' "mimalloc default" "$(/tmp/h7_probe_mi)"
printf '  %-46s %s\n' "mimalloc ARENA_EAGER_COMMIT=0" \
    "$(MIMALLOC_ARENA_EAGER_COMMIT=0 /tmp/h7_probe_mi)"
printf '  %-46s %s\n' "mimalloc PURGE_DELAY=0" \
    "$(MIMALLOC_PURGE_DELAY=0 /tmp/h7_probe_mi)"
printf '  %-46s %s\n' "mimalloc PURGE_DELAY=0+ARENA_EAGER_COMMIT=0" \
    "$(MIMALLOC_PURGE_DELAY=0 MIMALLOC_ARENA_EAGER_COMMIT=0 /tmp/h7_probe_mi)"
echo "[h7-probe] interpretation: if PURGE_DELAY=0 collapses VmHWM to ~system,"
echo "[h7-probe] the elevation is retained-but-freed pages, not a hard floor."
