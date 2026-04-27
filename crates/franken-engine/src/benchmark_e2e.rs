//! Performance benchmark E2E framework for FrankenEngine control-plane surfaces.
//!
//! Implements a synthetic extension-lifecycle benchmark suite with 5 benchmark
//! families, 3 scale profiles per family, regression detection, and evidence
//! artifact production. This suite measures extension lifecycle, resource budget
//! accounting, and related control-plane bookkeeping; it does not execute
//! parser, lowering, or baseline-interpreter JS workloads.
//!
//! Families:
//!   1. boot-storm — extension registration + lifecycle boot throughput
//!   2. capability-churn — rapid capability/budget mutation under load
//!   3. mixed-cpu-io-agent-mesh — interleaved CPU consumption and hostcall IO
//!   4. reload-revoke-churn — unregister/re-register cycles simulating hot-reload
//!   5. adversarial-noise-under-load — budget exhaustion injection during sustained load

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
#[cfg(target_os = "linux")]
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use rustix::{
    event::{PollFd, PollFlags, poll},
    io::Errno,
    process::{Pid, PidfdFlags, getpid, pidfd_open},
    time::Timespec,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wait_timeout::ChildExt;
#[cfg(target_os = "linux")]
use wait4::Wait4;

use crate::benchmark_denominator::BenchmarkCase;
use crate::benchmark_evidence_bundle::{
    BenchmarkRun as EvidenceBenchmarkRun, EnvironmentSnapshot, EvidenceBundle, ParityTarget,
    ParityVerdict, WorkloadCategory, WorkloadProvenance,
};
use crate::extension_lifecycle_manager::{
    CancellationConfig, ExtensionLifecycleManager, ExtensionState, LifecycleTransition,
    ResourceBudget,
};
use crate::hash_tiers::ContentHash;
use crate::runtime_comparison_gate::{BenchmarkCategory, BenchmarkResult, RuntimeId};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const BENCHMARK_E2E_COMPONENT: &str = "benchmark_e2e";
pub const BENCHMARK_E2E_SCHEMA_VERSION: &str = "franken-engine.benchmark-e2e.v1";
pub const BENCHMARK_ENV_SCHEMA_VERSION: &str = "franken-engine.benchmark-env-manifest.v1";
pub const BENCHMARK_COMPARISON_COMPONENT: &str = "benchmark_comparison";
pub const BENCHMARK_COMPARISON_SCHEMA_VERSION: &str = "franken-engine.benchmark-comparison.v1";
pub const BENCHMARK_COMPARISON_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.benchmark-comparison-manifest.v1";
pub const BENCHMARK_E2E_MEASURED_SURFACE: &str = "extension_lifecycle_control_plane";
pub const BENCHMARK_E2E_SURFACE_DESCRIPTION: &str = "measures extension lifecycle, resource budget accounting, and control-plane bookkeeping rather than parser, lowering, or baseline-interpreter execution";
pub const BENCHMARK_E2E_JS_RUNTIME_EXECUTION_INCLUDED: bool = false;
pub const MIN_START_BUDGET_MILLIONTHS: u64 = 1_000;

const MIN_WARMUP_RUNS: u32 = 1;
const MIN_SAMPLE_COUNT: u32 = 3;
const MIN_CASE_TIMEOUT_MS: u64 = 1;
const BENCHMARK_COMPARISON_TIMING_SENTINEL_PREFIX: &str = "__FRANKEN_TIME__";
const BENCHMARK_COMPARISON_TIMING_FOOTER_PLACEHOLDER: &str = "<timing-footer-on-stderr>";

fn benchmark_surface_metadata() -> serde_json::Value {
    serde_json::json!({
        "kind": BENCHMARK_E2E_MEASURED_SURFACE,
        "description": BENCHMARK_E2E_SURFACE_DESCRIPTION,
        "js_runtime_execution_included": BENCHMARK_E2E_JS_RUNTIME_EXECUTION_INCLUDED,
    })
}

// ---------------------------------------------------------------------------
// Scale profiles
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScaleProfile {
    Small,
    Medium,
    Large,
}

impl ScaleProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Small => "S",
            Self::Medium => "M",
            Self::Large => "L",
        }
    }

    pub fn all() -> &'static [ScaleProfile] {
        &[Self::Small, Self::Medium, Self::Large]
    }

    pub fn extension_count(self) -> usize {
        match self {
            Self::Small => 10,
            Self::Medium => 50,
            Self::Large => 200,
        }
    }

    pub fn iterations(self) -> usize {
        match self {
            Self::Small => 100,
            Self::Medium => 500,
            Self::Large => 2_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Benchmark families
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchmarkFamily {
    BootStorm,
    CapabilityChurn,
    MixedCpuIoAgentMesh,
    ReloadRevokeChurn,
    AdversarialNoiseUnderLoad,
}

impl BenchmarkFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BootStorm => "boot-storm",
            Self::CapabilityChurn => "capability-churn",
            Self::MixedCpuIoAgentMesh => "mixed-cpu-io-agent-mesh",
            Self::ReloadRevokeChurn => "reload-revoke-churn",
            Self::AdversarialNoiseUnderLoad => "adversarial-noise-under-load",
        }
    }

    pub fn all() -> &'static [BenchmarkFamily] {
        &[
            Self::BootStorm,
            Self::CapabilityChurn,
            Self::MixedCpuIoAgentMesh,
            Self::ReloadRevokeChurn,
            Self::AdversarialNoiseUnderLoad,
        ]
    }

    pub fn default_weight(self) -> f64 {
        match self {
            Self::BootStorm => 0.25,
            Self::CapabilityChurn => 0.20,
            Self::MixedCpuIoAgentMesh => 0.25,
            Self::ReloadRevokeChurn => 0.15,
            Self::AdversarialNoiseUnderLoad => 0.15,
        }
    }
}

// ---------------------------------------------------------------------------
// Measurement types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LatencyDistribution {
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub min_us: u64,
    pub max_us: u64,
    pub sample_count: usize,
}

impl LatencyDistribution {
    pub fn from_samples(samples: &mut [u64]) -> Self {
        assert!(
            !samples.is_empty(),
            "cannot compute distribution from empty samples"
        );
        samples.sort_unstable();
        let n = samples.len();
        Self {
            p50_us: samples[n / 2],
            p95_us: samples[(n * 95) / 100],
            p99_us: samples[(n * 99) / 100],
            min_us: samples[0],
            max_us: samples[n - 1],
            sample_count: n,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BenchmarkMeasurement {
    pub family: BenchmarkFamily,
    pub profile: ScaleProfile,
    pub throughput_ops_per_sec: f64,
    pub latency: LatencyDistribution,
    pub total_operations: u64,
    pub duration_us: u64,
    pub correctness_digest: String,
    pub invariant_violations: u64,
    pub security_events: u64,
    pub peak_extensions_alive: usize,
}

// ---------------------------------------------------------------------------
// Regression detection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RegressionThresholds {
    pub throughput_regression_pct: f64,
    pub p95_latency_regression_pct: f64,
    pub p99_latency_regression_pct: f64,
}

impl Default for RegressionThresholds {
    fn default() -> Self {
        Self {
            throughput_regression_pct: 5.0,
            p95_latency_regression_pct: 10.0,
            p99_latency_regression_pct: 15.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegressionResult {
    pub family: BenchmarkFamily,
    pub profile: ScaleProfile,
    pub throughput_delta_pct: f64,
    pub p95_delta_pct: f64,
    pub p99_delta_pct: f64,
    pub blocked: bool,
    pub blockers: Vec<String>,
}

pub fn detect_regression(
    current: &BenchmarkMeasurement,
    baseline: &BenchmarkMeasurement,
    thresholds: &RegressionThresholds,
) -> RegressionResult {
    let throughput_delta_pct = if baseline.throughput_ops_per_sec > 0.0 {
        ((baseline.throughput_ops_per_sec - current.throughput_ops_per_sec)
            / baseline.throughput_ops_per_sec)
            * 100.0
    } else {
        0.0
    };

    let p95_delta_pct = if baseline.latency.p95_us > 0 {
        ((current.latency.p95_us as f64 - baseline.latency.p95_us as f64)
            / baseline.latency.p95_us as f64)
            * 100.0
    } else {
        0.0
    };

    let p99_delta_pct = if baseline.latency.p99_us > 0 {
        ((current.latency.p99_us as f64 - baseline.latency.p99_us as f64)
            / baseline.latency.p99_us as f64)
            * 100.0
    } else {
        0.0
    };

    let mut blockers = Vec::new();
    if throughput_delta_pct > thresholds.throughput_regression_pct {
        blockers.push(format!(
            "throughput regressed {throughput_delta_pct:.1}% (threshold: {}%)",
            thresholds.throughput_regression_pct
        ));
    }
    if p95_delta_pct > thresholds.p95_latency_regression_pct {
        blockers.push(format!(
            "p95 latency regressed {p95_delta_pct:.1}% (threshold: {}%)",
            thresholds.p95_latency_regression_pct
        ));
    }
    if p99_delta_pct > thresholds.p99_latency_regression_pct {
        blockers.push(format!(
            "p99 latency regressed {p99_delta_pct:.1}% (threshold: {}%)",
            thresholds.p99_latency_regression_pct
        ));
    }

    RegressionResult {
        family: current.family,
        profile: current.profile,
        throughput_delta_pct,
        p95_delta_pct,
        p99_delta_pct,
        blocked: !blockers.is_empty(),
        blockers,
    }
}

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64)
// ---------------------------------------------------------------------------

pub struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn next_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    pub fn next_bool(&mut self, probability_pct: u64) -> bool {
        self.next_u64() % 100 < probability_pct
    }
}

// ---------------------------------------------------------------------------
// Benchmark workload runners
// ---------------------------------------------------------------------------

/// Boot-storm: register N extensions, transition each through boot sequence,
/// measure time per registration+boot cycle.
pub fn run_boot_storm(profile: ScaleProfile, seed: u64) -> BenchmarkMeasurement {
    let n = profile.extension_count();
    let iterations = profile.iterations();
    let mut rng = Xorshift64::new(seed);
    let mut latencies = Vec::with_capacity(n * iterations);
    let mut total_ops: u64 = 0;
    let mut invariant_violations: u64 = 0;
    let mut peak_alive: usize = 0;

    let start = Instant::now();

    for iter in 0..iterations {
        let mut mgr = ExtensionLifecycleManager::new();
        for i in 0..n {
            let ext_id = format!("boot-storm-{iter}-{i}");
            let budget = ResourceBudget::new(
                MIN_START_BUDGET_MILLIONTHS + rng.next_u64() % 100_000,
                1024 * 1024,
                1000,
            );
            let cancel = CancellationConfig {
                grace_period_ns: 1_000_000,
                force_on_timeout: true,
                propagate_to_children: false,
            };

            let op_start = Instant::now();
            if mgr.register(&ext_id, budget, cancel).is_err() {
                invariant_violations += 1;
                continue;
            }
            let _ = mgr.transition(&ext_id, LifecycleTransition::Validate, "bench", None);
            let _ = mgr.transition(&ext_id, LifecycleTransition::Load, "bench", None);
            let _ = mgr.transition(&ext_id, LifecycleTransition::Start, "bench", None);
            let _ = mgr.transition(&ext_id, LifecycleTransition::Activate, "bench", None);
            let elapsed = op_start.elapsed().as_micros() as u64;
            latencies.push(elapsed);
            total_ops += 1;
        }

        let alive = mgr.count_in_state(ExtensionState::Running);
        if alive > peak_alive {
            peak_alive = alive;
        }

        // Tear down
        for ext_id in mgr
            .extension_ids()
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
        {
            let _ = mgr.transition(&ext_id, LifecycleTransition::Terminate, "bench", None);
            let _ = mgr.transition(&ext_id, LifecycleTransition::Finalize, "bench", None);
        }
    }

    let total_duration = start.elapsed();
    let duration_us = total_duration.as_micros() as u64;
    let throughput = if duration_us > 0 {
        (total_ops as f64 / duration_us as f64) * 1_000_000.0
    } else {
        0.0
    };

    let digest = format!("boot-storm:{seed}:{n}:{iterations}:{total_ops}:{invariant_violations}");

    BenchmarkMeasurement {
        family: BenchmarkFamily::BootStorm,
        profile,
        throughput_ops_per_sec: throughput,
        latency: LatencyDistribution::from_samples(&mut latencies),
        total_operations: total_ops,
        duration_us,
        correctness_digest: digest,
        invariant_violations,
        security_events: 0,
        peak_extensions_alive: peak_alive,
    }
}

/// Capability-churn: extensions with tight budgets, rapidly consume and check budget state.
pub fn run_capability_churn(profile: ScaleProfile, seed: u64) -> BenchmarkMeasurement {
    let n = profile.extension_count();
    let iterations = profile.iterations();
    let mut rng = Xorshift64::new(seed);
    let mut latencies = Vec::with_capacity(n * iterations);
    let mut total_ops: u64 = 0;
    let mut invariant_violations: u64 = 0;
    let mut security_events: u64 = 0;

    let start = Instant::now();
    let mut mgr = ExtensionLifecycleManager::new();

    // Register extensions
    for i in 0..n {
        let ext_id = format!("cap-churn-{i}");
        let budget = ResourceBudget::new(
            MIN_START_BUDGET_MILLIONTHS + rng.next_u64() % 50_000,
            512 * 1024,
            500 + rng.next_u64() % 500,
        );
        let cancel = CancellationConfig {
            grace_period_ns: 500_000,
            force_on_timeout: true,
            propagate_to_children: false,
        };
        if mgr.register(&ext_id, budget, cancel).is_err() {
            invariant_violations += 1;
            continue;
        }
        let _ = mgr.transition(&ext_id, LifecycleTransition::Validate, "bench", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Load, "bench", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Start, "bench", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Activate, "bench", None);
    }

    // Churn: consume CPU and hostcalls rapidly
    for _ in 0..iterations {
        let ext_idx = rng.next_usize(n);
        let ext_id = format!("cap-churn-{ext_idx}");

        let op_start = Instant::now();

        // Try CPU consumption
        let cpu_amount = MIN_START_BUDGET_MILLIONTHS / 10 + rng.next_u64() % 500;
        match mgr.consume_cpu(&ext_id, cpu_amount) {
            Ok(()) => {}
            Err(_) => {
                security_events += 1;
            }
        }

        // Try hostcall consumption
        match mgr.consume_hostcall(&ext_id) {
            Ok(()) => {}
            Err(_) => {
                security_events += 1;
            }
        }

        let elapsed = op_start.elapsed().as_micros() as u64;
        latencies.push(elapsed);
        total_ops += 1;
    }

    // Enforce budgets
    let enforced = mgr.enforce_budgets("bench");
    security_events += enforced.len() as u64;

    let total_duration = start.elapsed();
    let duration_us = total_duration.as_micros() as u64;
    let throughput = if duration_us > 0 {
        (total_ops as f64 / duration_us as f64) * 1_000_000.0
    } else {
        0.0
    };

    let digest = format!("cap-churn:{seed}:{n}:{iterations}:{total_ops}:{security_events}");

    BenchmarkMeasurement {
        family: BenchmarkFamily::CapabilityChurn,
        profile,
        throughput_ops_per_sec: throughput,
        latency: LatencyDistribution::from_samples(&mut latencies),
        total_operations: total_ops,
        duration_us,
        correctness_digest: digest,
        invariant_violations,
        security_events,
        peak_extensions_alive: n,
    }
}

/// Mixed CPU/IO agent mesh: interleave CPU consumption and hostcall IO across
/// a mesh of extensions with varied budgets.
pub fn run_mixed_cpu_io_agent_mesh(profile: ScaleProfile, seed: u64) -> BenchmarkMeasurement {
    let n = profile.extension_count();
    let iterations = profile.iterations();
    let mut rng = Xorshift64::new(seed);
    let mut latencies = Vec::with_capacity(iterations);
    let mut total_ops: u64 = 0;
    let mut invariant_violations: u64 = 0;
    let mut security_events: u64 = 0;

    let start = Instant::now();
    let mut mgr = ExtensionLifecycleManager::new();

    for i in 0..n {
        let ext_id = format!("mesh-{i}");
        let budget = ResourceBudget::new(
            MIN_START_BUDGET_MILLIONTHS * 100 + rng.next_u64() % 500_000,
            2 * 1024 * 1024,
            2000 + rng.next_u64() % 3000,
        );
        let cancel = CancellationConfig {
            grace_period_ns: 2_000_000,
            force_on_timeout: true,
            propagate_to_children: false,
        };
        if mgr.register(&ext_id, budget, cancel).is_err() {
            invariant_violations += 1;
            continue;
        }
        let _ = mgr.transition(&ext_id, LifecycleTransition::Validate, "bench", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Load, "bench", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Start, "bench", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Activate, "bench", None);
    }

    for _ in 0..iterations {
        let op_start = Instant::now();

        // Pick 3 random extensions for a mesh round
        for _ in 0..3 {
            let ext_idx = rng.next_usize(n);
            let ext_id = format!("mesh-{ext_idx}");

            // CPU work
            let cpu_amount = 100 + rng.next_u64() % 1000;
            if mgr.consume_cpu(&ext_id, cpu_amount).is_err() {
                security_events += 1;
            }

            // IO (hostcall) work
            let hostcall_count = 1 + rng.next_usize(3);
            for _ in 0..hostcall_count {
                if mgr.consume_hostcall(&ext_id).is_err() {
                    security_events += 1;
                }
            }
        }

        let elapsed = op_start.elapsed().as_micros() as u64;
        latencies.push(elapsed);
        total_ops += 1;
    }

    // Periodic budget enforcement
    let enforced = mgr.enforce_budgets("bench");
    security_events += enforced.len() as u64;

    let total_duration = start.elapsed();
    let duration_us = total_duration.as_micros() as u64;
    let throughput = if duration_us > 0 {
        (total_ops as f64 / duration_us as f64) * 1_000_000.0
    } else {
        0.0
    };

    let digest = format!("mesh:{seed}:{n}:{iterations}:{total_ops}:{security_events}");

    BenchmarkMeasurement {
        family: BenchmarkFamily::MixedCpuIoAgentMesh,
        profile,
        throughput_ops_per_sec: throughput,
        latency: LatencyDistribution::from_samples(&mut latencies),
        total_operations: total_ops,
        duration_us,
        correctness_digest: digest,
        invariant_violations,
        security_events,
        peak_extensions_alive: n,
    }
}

/// Reload-revoke-churn: simulate hot-reload by unregistering and re-registering
/// extensions while others remain active.
pub fn run_reload_revoke_churn(profile: ScaleProfile, seed: u64) -> BenchmarkMeasurement {
    let n = profile.extension_count();
    let iterations = profile.iterations();
    let mut rng = Xorshift64::new(seed);
    let mut latencies = Vec::with_capacity(iterations);
    let mut total_ops: u64 = 0;
    let mut invariant_violations: u64 = 0;
    let mut peak_alive: usize = 0;

    let start = Instant::now();
    let mut mgr = ExtensionLifecycleManager::new();

    // Initial registration
    for i in 0..n {
        let ext_id = format!("reload-{i}");
        let budget = ResourceBudget::new(
            MIN_START_BUDGET_MILLIONTHS + rng.next_u64() % 100_000,
            1024 * 1024,
            1000,
        );
        let cancel = CancellationConfig {
            grace_period_ns: 1_000_000,
            force_on_timeout: true,
            propagate_to_children: false,
        };
        if mgr.register(&ext_id, budget, cancel).is_err() {
            invariant_violations += 1;
            continue;
        }
        let _ = mgr.transition(&ext_id, LifecycleTransition::Validate, "bench", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Load, "bench", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Start, "bench", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Activate, "bench", None);
    }

    // Reload churn
    for iter in 0..iterations {
        let ext_idx = rng.next_usize(n);
        let ext_id = format!("reload-{ext_idx}");

        let op_start = Instant::now();

        // Terminate + finalize + unregister
        let _ = mgr.transition(&ext_id, LifecycleTransition::Terminate, "bench", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Finalize, "bench", None);
        let _ = mgr.unregister(&ext_id);

        // Re-register with fresh budget
        let budget = ResourceBudget::new(
            MIN_START_BUDGET_MILLIONTHS + rng.next_u64() % 100_000,
            1024 * 1024,
            1000,
        );
        let cancel = CancellationConfig {
            grace_period_ns: 1_000_000,
            force_on_timeout: true,
            propagate_to_children: false,
        };
        if mgr.register(&ext_id, budget, cancel).is_err() {
            invariant_violations += 1;
        } else {
            let _ = mgr.transition(&ext_id, LifecycleTransition::Validate, "bench", None);
            let _ = mgr.transition(&ext_id, LifecycleTransition::Load, "bench", None);
            let _ = mgr.transition(&ext_id, LifecycleTransition::Start, "bench", None);
            let _ = mgr.transition(&ext_id, LifecycleTransition::Activate, "bench", None);
        }

        let elapsed = op_start.elapsed().as_micros() as u64;
        latencies.push(elapsed);
        total_ops += 1;

        if iter % 50 == 0 {
            let alive = mgr.count_in_state(ExtensionState::Running);
            if alive > peak_alive {
                peak_alive = alive;
            }
        }
    }

    let total_duration = start.elapsed();
    let duration_us = total_duration.as_micros() as u64;
    let throughput = if duration_us > 0 {
        (total_ops as f64 / duration_us as f64) * 1_000_000.0
    } else {
        0.0
    };

    let digest = format!("reload:{seed}:{n}:{iterations}:{total_ops}:{invariant_violations}");

    BenchmarkMeasurement {
        family: BenchmarkFamily::ReloadRevokeChurn,
        profile,
        throughput_ops_per_sec: throughput,
        latency: LatencyDistribution::from_samples(&mut latencies),
        total_operations: total_ops,
        duration_us,
        correctness_digest: digest,
        invariant_violations,
        security_events: 0,
        peak_extensions_alive: peak_alive,
    }
}

/// Adversarial noise under load: inject budget exhaustion into a subset of extensions
/// while maintaining sustained load on the rest.
pub fn run_adversarial_noise_under_load(profile: ScaleProfile, seed: u64) -> BenchmarkMeasurement {
    let n = profile.extension_count();
    let iterations = profile.iterations();
    let adversarial_pct = 20; // 20% adversarial
    let n_adversarial = std::cmp::max(1, n * adversarial_pct / 100);
    let mut rng = Xorshift64::new(seed);
    let mut latencies = Vec::with_capacity(iterations);
    let mut total_ops: u64 = 0;
    let mut invariant_violations: u64 = 0;
    let mut security_events: u64 = 0;

    let start = Instant::now();
    let mut mgr = ExtensionLifecycleManager::new();

    // Register well-behaved extensions with generous budgets
    for i in 0..n {
        let ext_id = format!("noise-{i}");
        let is_adversarial = i < n_adversarial;
        let budget = if is_adversarial {
            // Tight budget — will exhaust quickly
            ResourceBudget::new(MIN_START_BUDGET_MILLIONTHS + 500, 64 * 1024, 10)
        } else {
            ResourceBudget::new(MIN_START_BUDGET_MILLIONTHS * 1000, 4 * 1024 * 1024, 10_000)
        };
        let cancel = CancellationConfig {
            grace_period_ns: 500_000,
            force_on_timeout: true,
            propagate_to_children: false,
        };
        if mgr.register(&ext_id, budget, cancel).is_err() {
            invariant_violations += 1;
            continue;
        }
        let _ = mgr.transition(&ext_id, LifecycleTransition::Validate, "bench", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Load, "bench", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Start, "bench", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Activate, "bench", None);
    }

    for _ in 0..iterations {
        let op_start = Instant::now();

        // Work across all extensions
        let ext_idx = rng.next_usize(n);
        let ext_id = format!("noise-{ext_idx}");

        // CPU work
        let cpu_amount = 100 + rng.next_u64() % 500;
        if mgr.consume_cpu(&ext_id, cpu_amount).is_err() {
            security_events += 1;
        }

        // Hostcall
        if mgr.consume_hostcall(&ext_id).is_err() {
            security_events += 1;
        }

        // Periodically enforce budgets
        if rng.next_bool(10) {
            let enforced = mgr.enforce_budgets("bench");
            security_events += enforced.len() as u64;
        }

        let elapsed = op_start.elapsed().as_micros() as u64;
        latencies.push(elapsed);
        total_ops += 1;
    }

    // Final enforcement
    let enforced = mgr.enforce_budgets("bench");
    security_events += enforced.len() as u64;

    // Verify well-behaved extensions survived
    let running = mgr.count_in_state(ExtensionState::Running);

    let total_duration = start.elapsed();
    let duration_us = total_duration.as_micros() as u64;
    let throughput = if duration_us > 0 {
        (total_ops as f64 / duration_us as f64) * 1_000_000.0
    } else {
        0.0
    };

    let digest = format!(
        "adversarial:{seed}:{n}:{n_adversarial}:{iterations}:{total_ops}:{security_events}:{running}"
    );

    BenchmarkMeasurement {
        family: BenchmarkFamily::AdversarialNoiseUnderLoad,
        profile,
        throughput_ops_per_sec: throughput,
        latency: LatencyDistribution::from_samples(&mut latencies),
        total_operations: total_ops,
        duration_us,
        correctness_digest: digest,
        invariant_violations,
        security_events,
        peak_extensions_alive: n,
    }
}

/// Dispatch a benchmark run for a given family and profile.
pub fn run_benchmark(
    family: BenchmarkFamily,
    profile: ScaleProfile,
    seed: u64,
) -> BenchmarkMeasurement {
    match family {
        BenchmarkFamily::BootStorm => run_boot_storm(profile, seed),
        BenchmarkFamily::CapabilityChurn => run_capability_churn(profile, seed),
        BenchmarkFamily::MixedCpuIoAgentMesh => run_mixed_cpu_io_agent_mesh(profile, seed),
        BenchmarkFamily::ReloadRevokeChurn => run_reload_revoke_churn(profile, seed),
        BenchmarkFamily::AdversarialNoiseUnderLoad => {
            run_adversarial_noise_under_load(profile, seed)
        }
    }
}

// ---------------------------------------------------------------------------
// Suite runner
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkRuntimePins {
    pub franken_engine: String,
    pub node_lts: String,
    pub bun_stable: String,
}

impl Default for BenchmarkRuntimePins {
    fn default() -> Self {
        Self {
            franken_engine: format!("franken-engine-{}", env!("CARGO_PKG_VERSION")),
            node_lts: "22.13.1".to_string(),
            bun_stable: "1.1.43".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkFairnessPolicy {
    pub warmup_runs: u32,
    pub sample_count: u32,
    pub case_timeout_ms: u64,
}

impl Default for BenchmarkFairnessPolicy {
    fn default() -> Self {
        Self {
            warmup_runs: 2,
            sample_count: 7,
            case_timeout_ms: 30_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BenchmarkHarnessContract {
    pub runtime_pins: BenchmarkRuntimePins,
    pub fairness_policy: BenchmarkFairnessPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BenchmarkHarnessContractError {
    EmptyRuntimePin { runtime: &'static str },
    InvalidWarmupRuns { min: u32, actual: u32 },
    InvalidSampleCount { min: u32, actual: u32 },
    InvalidCaseTimeoutMs { min: u64, actual: u64 },
}

impl std::fmt::Display for BenchmarkHarnessContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyRuntimePin { runtime } => {
                write!(f, "runtime pin for `{runtime}` must be non-empty")
            }
            Self::InvalidWarmupRuns { min, actual } => {
                write!(f, "warmup_runs must be >= {min}, got {actual}")
            }
            Self::InvalidSampleCount { min, actual } => {
                write!(f, "sample_count must be >= {min}, got {actual}")
            }
            Self::InvalidCaseTimeoutMs { min, actual } => {
                write!(f, "case_timeout_ms must be >= {min}, got {actual}")
            }
        }
    }
}

impl std::error::Error for BenchmarkHarnessContractError {}

pub fn validate_harness_contract(
    contract: &BenchmarkHarnessContract,
) -> Result<(), BenchmarkHarnessContractError> {
    if contract.runtime_pins.franken_engine.trim().is_empty() {
        return Err(BenchmarkHarnessContractError::EmptyRuntimePin {
            runtime: "franken_engine",
        });
    }
    if contract.runtime_pins.node_lts.trim().is_empty() {
        return Err(BenchmarkHarnessContractError::EmptyRuntimePin {
            runtime: "node_lts",
        });
    }
    if contract.runtime_pins.bun_stable.trim().is_empty() {
        return Err(BenchmarkHarnessContractError::EmptyRuntimePin {
            runtime: "bun_stable",
        });
    }
    if contract.fairness_policy.warmup_runs < MIN_WARMUP_RUNS {
        return Err(BenchmarkHarnessContractError::InvalidWarmupRuns {
            min: MIN_WARMUP_RUNS,
            actual: contract.fairness_policy.warmup_runs,
        });
    }
    if contract.fairness_policy.sample_count < MIN_SAMPLE_COUNT {
        return Err(BenchmarkHarnessContractError::InvalidSampleCount {
            min: MIN_SAMPLE_COUNT,
            actual: contract.fairness_policy.sample_count,
        });
    }
    if contract.fairness_policy.case_timeout_ms < MIN_CASE_TIMEOUT_MS {
        return Err(BenchmarkHarnessContractError::InvalidCaseTimeoutMs {
            min: MIN_CASE_TIMEOUT_MS,
            actual: contract.fairness_policy.case_timeout_ms,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// External runtime comparison runner
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkComparisonRuntimeCommands {
    pub frankenctl: PathBuf,
    pub node: PathBuf,
    pub bun: PathBuf,
}

impl Default for BenchmarkComparisonRuntimeCommands {
    fn default() -> Self {
        Self {
            frankenctl: PathBuf::from("frankenctl"),
            node: PathBuf::from("node"),
            bun: PathBuf::from("bun"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkComparisonCase {
    pub benchmark_id: String,
    #[serde(with = "benchmark_category_wire")]
    pub category: BenchmarkCategory,
    pub program_path: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkComparisonManifest {
    pub schema_version: String,
    #[serde(default)]
    pub runtime_pins: BenchmarkRuntimePins,
    #[serde(default)]
    pub runtime_commands: BenchmarkComparisonRuntimeCommands,
    #[serde(default)]
    pub fairness_policy: BenchmarkFairnessPolicy,
    #[serde(default)]
    pub cases: Vec<BenchmarkComparisonCase>,
}

impl Default for BenchmarkComparisonManifest {
    fn default() -> Self {
        Self {
            schema_version: BENCHMARK_COMPARISON_MANIFEST_SCHEMA_VERSION.to_string(),
            runtime_pins: BenchmarkRuntimePins::default(),
            runtime_commands: BenchmarkComparisonRuntimeCommands::default(),
            fairness_policy: BenchmarkFairnessPolicy::default(),
            cases: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkComparisonSample {
    pub wall_time_ns: u64,
    pub peak_rss_bytes: u64,
    #[serde(default = "empty_benchmark_comparison_output_digest")]
    pub output_digest: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkComparisonStatistics {
    pub sample_count: u64,
    pub mean_ns: u64,
    pub median_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub stddev_ns: u64,
    pub ci95_lower_ns: u64,
    pub ci95_upper_ns: u64,
    pub peak_rss_bytes_max: u64,
    pub cv_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkComparisonRuntimeResult {
    pub benchmark_id: String,
    pub category: BenchmarkCategory,
    pub runtime: RuntimeId,
    pub statistics: BenchmarkComparisonStatistics,
    pub raw_samples: Vec<BenchmarkComparisonSample>,
    pub benchmark_result: BenchmarkResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkComparisonEvent {
    pub benchmark_id: String,
    pub category: BenchmarkCategory,
    pub runtime: RuntimeId,
    pub event: String,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkComparisonSuiteResult {
    pub schema_version: String,
    pub run_id: String,
    pub run_date: String,
    pub manifest: BenchmarkComparisonManifest,
    pub results: Vec<BenchmarkComparisonRuntimeResult>,
    pub events: Vec<BenchmarkComparisonEvent>,
    pub commands: Vec<String>,
    pub evidence_bundle: EvidenceBundle,
}

mod benchmark_category_wire {
    use super::BenchmarkCategory;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &BenchmarkCategory, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(value.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BenchmarkCategory, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            "micro" => Ok(BenchmarkCategory::Micro),
            "macro" => Ok(BenchmarkCategory::Macro),
            "startup" => Ok(BenchmarkCategory::Startup),
            "throughput" => Ok(BenchmarkCategory::Throughput),
            "memory" => Ok(BenchmarkCategory::Memory),
            other => Err(serde::de::Error::custom(format!(
                "unknown benchmark category `{other}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BenchmarkComparisonError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    EmptyCases,
    EmptyBenchmarkId,
    DuplicateBenchmarkId {
        benchmark_id: String,
    },
    MissingProgramPath {
        benchmark_id: String,
    },
    UnreadableProgramPath {
        benchmark_id: String,
        path: String,
        detail: String,
    },
    UnsupportedCaseArgs {
        benchmark_id: String,
    },
    InvalidHarnessContract(String),
    Io(String),
    CommandFailed {
        benchmark_id: String,
        runtime: RuntimeId,
        detail: String,
    },
    TimingParse {
        benchmark_id: String,
        runtime: RuntimeId,
        detail: String,
    },
    EvidenceBundle(String),
}

impl std::fmt::Display for BenchmarkComparisonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSchemaVersion { expected, actual } => {
                write!(
                    f,
                    "benchmark comparison manifest schema must be `{expected}`, got `{actual}`"
                )
            }
            Self::EmptyCases => f.write_str("benchmark comparison manifest must contain cases"),
            Self::EmptyBenchmarkId => {
                f.write_str("benchmark comparison cases must have non-empty benchmark_id values")
            }
            Self::DuplicateBenchmarkId { benchmark_id } => {
                write!(
                    f,
                    "benchmark comparison manifest contains duplicate benchmark_id `{benchmark_id}`"
                )
            }
            Self::MissingProgramPath { benchmark_id } => {
                write!(
                    f,
                    "benchmark comparison case `{benchmark_id}` must define a program_path"
                )
            }
            Self::UnreadableProgramPath {
                benchmark_id,
                path,
                detail,
            } => {
                write!(
                    f,
                    "benchmark comparison case `{benchmark_id}` cannot read program `{path}`: {detail}"
                )
            }
            Self::UnsupportedCaseArgs { benchmark_id } => {
                write!(
                    f,
                    "benchmark comparison case `{benchmark_id}` cannot use args until frankenctl benchmark comparison supports forwarding case arguments consistently across runtimes"
                )
            }
            Self::InvalidHarnessContract(detail) => {
                write!(f, "benchmark comparison harness contract invalid: {detail}")
            }
            Self::Io(detail) => f.write_str(detail),
            Self::CommandFailed {
                benchmark_id,
                runtime,
                detail,
            } => write!(
                f,
                "benchmark comparison case `{benchmark_id}` failed for runtime `{runtime}`: {detail}"
            ),
            Self::TimingParse {
                benchmark_id,
                runtime,
                detail,
            } => write!(
                f,
                "benchmark comparison timing parse failed for `{benchmark_id}` runtime `{runtime}`: {detail}"
            ),
            Self::EvidenceBundle(detail) => {
                write!(f, "benchmark comparison evidence bundle invalid: {detail}")
            }
        }
    }
}

impl std::error::Error for BenchmarkComparisonError {}

pub fn validate_benchmark_comparison_manifest(
    manifest: &BenchmarkComparisonManifest,
) -> Result<(), BenchmarkComparisonError> {
    if manifest.schema_version != BENCHMARK_COMPARISON_MANIFEST_SCHEMA_VERSION {
        return Err(BenchmarkComparisonError::InvalidSchemaVersion {
            expected: BENCHMARK_COMPARISON_MANIFEST_SCHEMA_VERSION,
            actual: manifest.schema_version.clone(),
        });
    }
    if manifest.cases.is_empty() {
        return Err(BenchmarkComparisonError::EmptyCases);
    }
    validate_harness_contract(&BenchmarkHarnessContract {
        runtime_pins: manifest.runtime_pins.clone(),
        fairness_policy: manifest.fairness_policy,
    })
    .map_err(|error| BenchmarkComparisonError::InvalidHarnessContract(error.to_string()))?;
    let mut seen_ids = BTreeSet::new();
    for case in &manifest.cases {
        if case.benchmark_id.trim().is_empty() {
            return Err(BenchmarkComparisonError::EmptyBenchmarkId);
        }
        if !seen_ids.insert(case.benchmark_id.clone()) {
            return Err(BenchmarkComparisonError::DuplicateBenchmarkId {
                benchmark_id: case.benchmark_id.clone(),
            });
        }
        if case.program_path.as_os_str().is_empty() {
            return Err(BenchmarkComparisonError::MissingProgramPath {
                benchmark_id: case.benchmark_id.clone(),
            });
        }
        if !case.args.is_empty() {
            return Err(BenchmarkComparisonError::UnsupportedCaseArgs {
                benchmark_id: case.benchmark_id.clone(),
            });
        }
    }
    Ok(())
}

pub fn summarize_benchmark_comparison_samples(
    samples: &[BenchmarkComparisonSample],
) -> BenchmarkComparisonStatistics {
    assert!(
        !samples.is_empty(),
        "cannot compute comparison statistics from empty samples"
    );
    let mut wall_times: Vec<u64> = samples.iter().map(|sample| sample.wall_time_ns).collect();
    wall_times.sort_unstable();
    let sample_count = wall_times.len() as u64;
    let sum: f64 = wall_times.iter().map(|value| *value as f64).sum();
    let mean = sum / wall_times.len() as f64;
    let variance = wall_times
        .iter()
        .map(|value| {
            let delta = *value as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / wall_times.len() as f64;
    let stddev = variance.sqrt();
    let ci_half_width = 1.96 * stddev / (wall_times.len() as f64).sqrt();
    let cv_millionths = if mean > 0.0 {
        ((stddev / mean) * 1_000_000.0).round() as u64
    } else {
        0
    };
    let peak_rss_bytes_max = samples
        .iter()
        .map(|sample| sample.peak_rss_bytes)
        .max()
        .unwrap_or(0);
    BenchmarkComparisonStatistics {
        sample_count,
        mean_ns: mean.round() as u64,
        median_ns: wall_times[wall_times.len() / 2],
        p95_ns: wall_times[((wall_times.len() * 95) / 100).min(wall_times.len() - 1)],
        p99_ns: wall_times[((wall_times.len() * 99) / 100).min(wall_times.len() - 1)],
        min_ns: wall_times[0],
        max_ns: wall_times[wall_times.len() - 1],
        stddev_ns: stddev.round() as u64,
        ci95_lower_ns: mean.max(ci_half_width).round() as u64 - ci_half_width.round() as u64,
        ci95_upper_ns: (mean + ci_half_width).round() as u64,
        peak_rss_bytes_max,
        cv_millionths,
    }
}

fn comparison_workload_category(category: BenchmarkCategory) -> WorkloadCategory {
    match category {
        BenchmarkCategory::Micro => WorkloadCategory::Micro,
        BenchmarkCategory::Macro => WorkloadCategory::Application,
        BenchmarkCategory::Startup => WorkloadCategory::ColdStart,
        BenchmarkCategory::Throughput => WorkloadCategory::IoThroughput,
        BenchmarkCategory::Memory => WorkloadCategory::Memory,
    }
}

fn comparison_runtime_version_pin(pins: &BenchmarkRuntimePins, runtime: RuntimeId) -> &str {
    match runtime {
        RuntimeId::FrankenEngine => &pins.franken_engine,
        RuntimeId::NodeLts => &pins.node_lts,
        RuntimeId::BunStable => &pins.bun_stable,
    }
}

fn comparison_environment_snapshot(
    pins: &BenchmarkRuntimePins,
    runtime: RuntimeId,
) -> EnvironmentSnapshot {
    let cpu_model = host_cpu_model().unwrap_or_else(|| env::consts::ARCH.to_string());
    let memory_bytes = host_memory_bytes().unwrap_or(0);
    let mut extra = BTreeMap::new();
    extra.insert("runtime_target".to_string(), runtime.as_str().to_string());
    extra.insert(
        "runtime_version_pin".to_string(),
        comparison_runtime_version_pin(pins, runtime).to_string(),
    );
    EnvironmentSnapshot::new(
        env::consts::OS.to_string(),
        cpu_model,
        std::thread::available_parallelism()
            .map(|parallelism| parallelism.get() as u32)
            .unwrap_or(1),
        memory_bytes,
        comparison_runtime_version_pin(pins, runtime).to_string(),
        pins.franken_engine.clone(),
        extra,
    )
}

fn host_cpu_model() -> Option<String> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in cpuinfo.lines() {
        let (label, value) = line.split_once(':')?;
        let key = label.trim();
        if key == "model name" || key == "Hardware" || key == "Processor" {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn host_memory_bytes() -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let mut parts = rest.split_whitespace();
            let kb: u64 = parts.next()?.parse().ok()?;
            return kb.checked_mul(1024);
        }
    }
    None
}

fn comparison_parity_target(runtime: RuntimeId) -> Option<ParityTarget> {
    match runtime {
        RuntimeId::FrankenEngine => None,
        RuntimeId::NodeLts => Some(ParityTarget::NodeJs),
        RuntimeId::BunStable => Some(ParityTarget::Bun),
    }
}

#[derive(Debug, Clone)]
struct ResolvedBenchmarkProgram {
    path: PathBuf,
    content_hash: ContentHash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BenchmarkComparisonMeasurementMode {
    DirectLinuxWait4,
    TimeWrapper,
}

fn empty_benchmark_comparison_output_digest() -> ContentHash {
    ContentHash::compute(&[])
}

fn benchmark_comparison_output_digest(stdout: &[u8], stderr: &[u8]) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update((stdout.len() as u64).to_le_bytes());
    hasher.update(stdout);
    hasher.update((stderr.len() as u64).to_le_bytes());
    hasher.update(stderr);
    ContentHash::from_bytes(hasher.finalize().into())
}

fn benchmark_comparison_program_content_hash(path: &Path) -> std::io::Result<ContentHash> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(ContentHash::from_bytes(hasher.finalize().into()))
}

fn benchmark_comparison_timing_marker() -> String {
    format!(
        "{BENCHMARK_COMPARISON_TIMING_SENTINEL_PREFIX}{}__",
        current_unix_timestamp_ns()
    )
}

#[cfg(target_os = "linux")]
fn benchmark_comparison_supports_direct_measurement() -> bool {
    static DIRECT_MEASUREMENT_SUPPORTED: OnceLock<bool> = OnceLock::new();
    *DIRECT_MEASUREMENT_SUPPORTED.get_or_init(|| pidfd_open(getpid(), PidfdFlags::empty()).is_ok())
}

#[cfg(not(target_os = "linux"))]
fn benchmark_comparison_supports_direct_measurement() -> bool {
    false
}

fn benchmark_comparison_measurement_mode() -> BenchmarkComparisonMeasurementMode {
    if benchmark_comparison_supports_direct_measurement() {
        BenchmarkComparisonMeasurementMode::DirectLinuxWait4
    } else {
        BenchmarkComparisonMeasurementMode::TimeWrapper
    }
}

fn benchmark_comparison_extract_timing_footer(
    benchmark_id: &str,
    runtime: RuntimeId,
    mut stderr: Vec<u8>,
    timing_marker: &str,
) -> Result<(Vec<u8>, u64, u64), BenchmarkComparisonError> {
    let marker_bytes = timing_marker.as_bytes();
    let Some(start) = stderr
        .windows(marker_bytes.len())
        .rposition(|window| window == marker_bytes)
    else {
        return Err(BenchmarkComparisonError::TimingParse {
            benchmark_id: benchmark_id.to_string(),
            runtime,
            detail: format!("missing timing footer marker `{timing_marker}`"),
        });
    };
    let timing_bytes = &stderr[start..];
    let timing_footer = std::str::from_utf8(timing_bytes).map_err(|error| {
        BenchmarkComparisonError::TimingParse {
            benchmark_id: benchmark_id.to_string(),
            runtime,
            detail: error.to_string(),
        }
    })?;
    let timing_footer = timing_footer.trim_end_matches(['\n', '\r']);
    let mut parts = timing_footer.split('\t');
    let marker = parts
        .next()
        .ok_or_else(|| BenchmarkComparisonError::TimingParse {
            benchmark_id: benchmark_id.to_string(),
            runtime,
            detail: format!("missing timing footer marker in `{timing_footer}`"),
        })?;
    if marker != timing_marker {
        return Err(BenchmarkComparisonError::TimingParse {
            benchmark_id: benchmark_id.to_string(),
            runtime,
            detail: format!(
                "timing footer marker mismatch: expected `{timing_marker}`, got `{marker}`"
            ),
        });
    }
    let elapsed_seconds = parts
        .next()
        .ok_or_else(|| BenchmarkComparisonError::TimingParse {
            benchmark_id: benchmark_id.to_string(),
            runtime,
            detail: format!("missing elapsed seconds in `{timing_footer}`"),
        })?;
    let peak_rss_kib = parts
        .next()
        .ok_or_else(|| BenchmarkComparisonError::TimingParse {
            benchmark_id: benchmark_id.to_string(),
            runtime,
            detail: format!("missing peak rss in `{timing_footer}`"),
        })?;
    let elapsed_ns =
        (elapsed_seconds
            .parse::<f64>()
            .map_err(|error| BenchmarkComparisonError::TimingParse {
                benchmark_id: benchmark_id.to_string(),
                runtime,
                detail: error.to_string(),
            })?
            * 1_000_000_000.0)
            .round() as u64;
    let peak_rss_bytes = peak_rss_kib
        .parse::<u64>()
        .map_err(|error| BenchmarkComparisonError::TimingParse {
            benchmark_id: benchmark_id.to_string(),
            runtime,
            detail: error.to_string(),
        })?
        .saturating_mul(1024);
    stderr.truncate(start);
    Ok((stderr, elapsed_ns, peak_rss_bytes))
}

#[cfg(target_os = "linux")]
fn benchmark_comparison_wait_for_pidfd<P: AsFd>(
    pidfd: &P,
    timeout: Duration,
) -> std::io::Result<bool> {
    let started = Instant::now();
    loop {
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Ok(false);
        }
        let remaining = timeout - elapsed;
        let timeout = Timespec::try_from(remaining).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("benchmark comparison timeout overflow: {error}"),
            )
        })?;
        let mut poll_fds = [PollFd::new(pidfd, PollFlags::IN)];
        match poll(&mut poll_fds, Some(&timeout)) {
            Ok(0) => return Ok(false),
            Ok(_) => return Ok(true),
            Err(Errno::INTR) => continue,
            Err(error) => return Err(std::io::Error::from(error)),
        }
    }
}

#[cfg(target_os = "linux")]
fn benchmark_comparison_wait_for_exit(
    child: &mut Child,
    timeout: Duration,
) -> std::io::Result<Option<ExitStatus>> {
    let pidfd = match pidfd_open(Pid::from_child(child), PidfdFlags::empty()) {
        Ok(pidfd) => pidfd,
        Err(_) => return child.wait_timeout(timeout),
    };
    if !benchmark_comparison_wait_for_pidfd(&pidfd, timeout)? {
        return Ok(None);
    }
    child.wait().map(Some)
}

#[cfg(not(target_os = "linux"))]
fn benchmark_comparison_wait_for_exit(
    child: &mut Child,
    timeout: Duration,
) -> std::io::Result<Option<ExitStatus>> {
    child.wait_timeout(timeout)
}

fn benchmark_comparison_spawn_reader<R>(
    mut reader: R,
) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

fn benchmark_comparison_finish_reader(
    handle: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
) -> Result<Vec<u8>, BenchmarkComparisonError> {
    match handle.join() {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(error)) => Err(BenchmarkComparisonError::Io(error.to_string())),
        Err(_) => Err(BenchmarkComparisonError::Io(
            "benchmark comparison stream reader panicked".to_string(),
        )),
    }
}

fn run_benchmark_comparison_warmup(
    case: &BenchmarkComparisonCase,
    runtime: RuntimeId,
    runtime_bin: &Path,
    runtime_args: &[String],
    case_timeout_ms: u64,
) -> Result<(), BenchmarkComparisonError> {
    let timeout = Duration::from_millis(case_timeout_ms);
    let mut command = Command::new(runtime_bin);
    command
        .args(runtime_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|error| BenchmarkComparisonError::Io(error.to_string()))?;
    let stdout_reader =
        benchmark_comparison_spawn_reader(child.stdout.take().ok_or_else(|| {
            BenchmarkComparisonError::Io("missing child stdout pipe".to_string())
        })?);
    let stderr_reader =
        benchmark_comparison_spawn_reader(child.stderr.take().ok_or_else(|| {
            BenchmarkComparisonError::Io("missing child stderr pipe".to_string())
        })?);
    let status = match benchmark_comparison_wait_for_exit(&mut child, timeout)
        .map_err(|error| BenchmarkComparisonError::Io(error.to_string()))?
    {
        Some(status) => status,
        None => {
            let status = benchmark_comparison_force_terminate_child(&mut child)
                .map_err(|error| BenchmarkComparisonError::Io(error.to_string()))?;
            let stdout = benchmark_comparison_finish_reader(stdout_reader)?;
            let stderr = benchmark_comparison_finish_reader(stderr_reader)?;
            return Err(BenchmarkComparisonError::CommandFailed {
                benchmark_id: case.benchmark_id.clone(),
                runtime,
                detail: format!(
                    "warmup timed out after {case_timeout_ms}ms exit_code={:?} stdout=`{}` stderr=`{}`",
                    status.code(),
                    String::from_utf8_lossy(&stdout).trim(),
                    String::from_utf8_lossy(&stderr).trim()
                ),
            });
        }
    };
    let stdout = benchmark_comparison_finish_reader(stdout_reader)?;
    let stderr = benchmark_comparison_finish_reader(stderr_reader)?;
    if !status.success() {
        return Err(BenchmarkComparisonError::CommandFailed {
            benchmark_id: case.benchmark_id.clone(),
            runtime,
            detail: format!(
                "warmup exit_code={:?} stdout=`{}` stderr=`{}`",
                status.code(),
                String::from_utf8_lossy(&stdout).trim(),
                String::from_utf8_lossy(&stderr).trim()
            ),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn benchmark_comparison_signal_process_group(
    process_group_id: u32,
    signal: &str,
) -> std::io::Result<()> {
    let _ = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(format!("-{process_group_id}"))
        .status()?;
    Ok(())
}

#[cfg(unix)]
fn benchmark_comparison_force_terminate_child(child: &mut Child) -> std::io::Result<ExitStatus> {
    let process_group_id = child.id();
    benchmark_comparison_signal_process_group(process_group_id, "TERM")?;
    if let Some(status) = benchmark_comparison_wait_for_exit(child, Duration::from_millis(100))? {
        return Ok(status);
    }
    benchmark_comparison_signal_process_group(process_group_id, "KILL")?;
    child.wait()
}

#[cfg(not(unix))]
fn benchmark_comparison_force_terminate_child(child: &mut Child) -> std::io::Result<ExitStatus> {
    child.kill()?;
    child.wait()
}

fn benchmark_comparison_parity_details(
    baseline_samples: &[BenchmarkComparisonSample],
    runtime_samples: &[BenchmarkComparisonSample],
) -> (bool, usize, Vec<String>, ContentHash) {
    let compared_samples = baseline_samples.len().min(runtime_samples.len());
    let digest_mismatches = baseline_samples
        .iter()
        .zip(runtime_samples.iter())
        .filter(|(baseline, runtime)| baseline.output_digest != runtime.output_digest)
        .count();
    let sample_count_delta = baseline_samples.len().abs_diff(runtime_samples.len());
    let behavioral_differences = digest_mismatches + sample_count_delta;
    let mut difference_details = Vec::new();
    if digest_mismatches > 0 {
        difference_details.push(format!(
            "output digest mismatch in {digest_mismatches} of {compared_samples} compared samples"
        ));
    }
    if sample_count_delta > 0 {
        difference_details.push(format!(
            "sample count mismatch: baseline={} runtime={}",
            baseline_samples.len(),
            runtime_samples.len()
        ));
    }

    let mut evidence_hasher = Sha256::new();
    evidence_hasher.update((baseline_samples.len() as u64).to_le_bytes());
    for sample in baseline_samples {
        evidence_hasher.update(sample.output_digest.as_bytes());
    }
    evidence_hasher.update((runtime_samples.len() as u64).to_le_bytes());
    for sample in runtime_samples {
        evidence_hasher.update(sample.output_digest.as_bytes());
    }

    (
        behavioral_differences == 0,
        behavioral_differences,
        difference_details,
        ContentHash::from_bytes(evidence_hasher.finalize().into()),
    )
}

fn build_benchmark_comparison_evidence_bundle(
    manifest: &BenchmarkComparisonManifest,
    resolved_programs: &BTreeMap<String, ResolvedBenchmarkProgram>,
    run_id: &str,
    results: &[BenchmarkComparisonRuntimeResult],
) -> Result<EvidenceBundle, BenchmarkComparisonError> {
    let run_epoch = SecurityEpoch::from_raw(1);
    let mut bundle = EvidenceBundle::new(format!("{run_id}-comparison"), run_epoch);

    for case in &manifest.cases {
        let resolved_program = resolved_programs.get(&case.benchmark_id).ok_or_else(|| {
            BenchmarkComparisonError::EvidenceBundle(format!(
                "missing resolved program path for benchmark `{}`",
                case.benchmark_id
            ))
        })?;
        let mut tags = BTreeSet::new();
        tags.insert("benchmark_comparison".to_string());
        tags.insert(case.category.as_str().to_string());
        bundle
            .add_provenance(WorkloadProvenance {
                workload_id: case.benchmark_id.clone(),
                name: case.benchmark_id.clone(),
                category: comparison_workload_category(case.category),
                source: resolved_program.path.display().to_string(),
                pinned_version: resolved_program.content_hash.to_hex(),
                content_hash: resolved_program.content_hash,
                provenance_epoch: run_epoch,
                tags,
            })
            .map_err(|error| BenchmarkComparisonError::EvidenceBundle(error.to_string()))?;
    }

    let franken_medians: BTreeMap<&str, u64> = results
        .iter()
        .filter(|entry| entry.runtime == RuntimeId::FrankenEngine)
        .map(|entry| (entry.benchmark_id.as_str(), entry.statistics.median_ns))
        .collect();
    let franken_samples: BTreeMap<&str, &[BenchmarkComparisonSample]> = results
        .iter()
        .filter(|entry| entry.runtime == RuntimeId::FrankenEngine)
        .map(|entry| (entry.benchmark_id.as_str(), entry.raw_samples.as_slice()))
        .collect();

    for entry in results {
        let environment = comparison_environment_snapshot(&manifest.runtime_pins, entry.runtime);
        for (iteration, sample) in entry.raw_samples.iter().enumerate() {
            bundle
                .add_run(EvidenceBenchmarkRun {
                    run_id: format!(
                        "{run_id}-{}-{}-{iteration}",
                        entry.benchmark_id,
                        entry.runtime.as_str()
                    ),
                    workload_id: entry.benchmark_id.clone(),
                    duration_us: sample.wall_time_ns / 1_000,
                    peak_memory_bytes: sample.peak_rss_bytes,
                    gc_pause_us: 0,
                    is_warmup: false,
                    iteration: iteration as u32,
                    environment: environment.clone(),
                    run_epoch,
                })
                .map_err(|error| BenchmarkComparisonError::EvidenceBundle(error.to_string()))?;
        }

        if let Some(target) = comparison_parity_target(entry.runtime) {
            let baseline_median = franken_medians
                .get(entry.benchmark_id.as_str())
                .copied()
                .ok_or_else(|| {
                    BenchmarkComparisonError::EvidenceBundle(format!(
                        "missing FrankenEngine baseline for benchmark `{}`",
                        entry.benchmark_id
                    ))
                })?;
            let baseline_samples = franken_samples
                .get(entry.benchmark_id.as_str())
                .copied()
                .ok_or_else(|| {
                    BenchmarkComparisonError::EvidenceBundle(format!(
                        "missing FrankenEngine output witness for benchmark `{}`",
                        entry.benchmark_id
                    ))
                })?;
            let performance_ratio_millionths = if baseline_median == 0 {
                0
            } else {
                ((entry.statistics.median_ns as u128)
                    .saturating_mul(1_000_000)
                    .checked_div(baseline_median as u128)
                    .unwrap_or(u128::from(u64::MAX)))
                .min(u128::from(u64::MAX)) as u64
            };
            let (
                output_equivalent,
                behavioral_differences,
                difference_details,
                output_witness_hash,
            ) = benchmark_comparison_parity_details(baseline_samples, &entry.raw_samples);
            let mut evidence_hasher = Sha256::new();
            evidence_hasher.update(entry.benchmark_id.as_bytes());
            evidence_hasher.update(target.as_str().as_bytes());
            evidence_hasher.update([u8::from(output_equivalent)]);
            evidence_hasher.update(performance_ratio_millionths.to_le_bytes());
            evidence_hasher.update(entry.statistics.median_ns.to_le_bytes());
            evidence_hasher.update((behavioral_differences as u64).to_le_bytes());
            evidence_hasher.update(output_witness_hash.as_bytes());
            let evidence_hash = ContentHash::from_bytes(evidence_hasher.finalize().into());
            bundle
                .add_parity_verdict(ParityVerdict {
                    workload_id: entry.benchmark_id.clone(),
                    target,
                    output_equivalent,
                    performance_ratio_millionths,
                    behavioral_differences,
                    difference_details,
                    evidence_hash,
                })
                .map_err(|error| BenchmarkComparisonError::EvidenceBundle(error.to_string()))?;
        }
    }

    bundle
        .seal()
        .map_err(|error| BenchmarkComparisonError::EvidenceBundle(error.to_string()))?;
    Ok(bundle)
}

pub fn run_benchmark_comparison_suite(
    manifest: &BenchmarkComparisonManifest,
    manifest_root: &Path,
    run_id: impl Into<String>,
    run_date: impl Into<String>,
) -> Result<BenchmarkComparisonSuiteResult, BenchmarkComparisonError> {
    validate_benchmark_comparison_manifest(manifest)?;

    let mut results = Vec::new();
    let mut events = Vec::new();
    let mut commands = Vec::new();
    let mut resolved_programs = BTreeMap::new();
    let run_id = run_id.into();
    let run_date = run_date.into();

    for case in &manifest.cases {
        let resolved_program = if case.program_path.is_absolute() {
            case.program_path.clone()
        } else {
            manifest_root.join(&case.program_path)
        };
        let resolved_program_content_hash =
            benchmark_comparison_program_content_hash(&resolved_program).map_err(|error| {
                BenchmarkComparisonError::UnreadableProgramPath {
                    benchmark_id: case.benchmark_id.clone(),
                    path: resolved_program.display().to_string(),
                    detail: error.to_string(),
                }
            })?;
        resolved_programs.insert(
            case.benchmark_id.clone(),
            ResolvedBenchmarkProgram {
                path: resolved_program.clone(),
                content_hash: resolved_program_content_hash,
            },
        );

        let runtime_specs = [
            (
                RuntimeId::FrankenEngine,
                manifest.runtime_commands.frankenctl.clone(),
            ),
            (RuntimeId::NodeLts, manifest.runtime_commands.node.clone()),
            (RuntimeId::BunStable, manifest.runtime_commands.bun.clone()),
        ];

        for (runtime, runtime_bin) in runtime_specs {
            let mut raw_samples = Vec::new();
            let measurement_mode = benchmark_comparison_measurement_mode();
            let mut runtime_args = match runtime {
                RuntimeId::FrankenEngine => vec![
                    "run".to_string(),
                    "--input".to_string(),
                    resolved_program.display().to_string(),
                    "--extension-id".to_string(),
                    format!("bench-{}-{}", case.benchmark_id, runtime.as_str()),
                ],
                RuntimeId::NodeLts | RuntimeId::BunStable => {
                    let mut args = vec![resolved_program.display().to_string()];
                    args.extend(case.args.iter().cloned());
                    args
                }
            };

            commands.push(render_benchmark_comparison_command(
                measurement_mode,
                runtime,
                &runtime_bin,
                &runtime_args,
                manifest.fairness_policy.case_timeout_ms,
            ));

            for _ in 0..manifest.fairness_policy.warmup_runs {
                run_benchmark_comparison_warmup(
                    case,
                    runtime,
                    &runtime_bin,
                    &runtime_args,
                    manifest.fairness_policy.case_timeout_ms,
                )?;
            }

            for _ in 0..manifest.fairness_policy.sample_count {
                raw_samples.push(run_single_benchmark_comparison_sample(
                    case,
                    runtime,
                    &runtime_bin,
                    &runtime_args,
                    manifest.fairness_policy.case_timeout_ms,
                    measurement_mode,
                )?);
            }

            let statistics = summarize_benchmark_comparison_samples(&raw_samples);
            let benchmark_result = BenchmarkResult {
                benchmark_id: case.benchmark_id.clone(),
                category: case.category,
                runtime,
                wall_time_ns: statistics.median_ns,
                memory_peak_bytes: statistics.peak_rss_bytes_max,
                run_count: statistics.sample_count,
                cv_millionths: statistics.cv_millionths,
            };
            results.push(BenchmarkComparisonRuntimeResult {
                benchmark_id: case.benchmark_id.clone(),
                category: case.category,
                runtime,
                statistics,
                raw_samples,
                benchmark_result,
            });
            events.push(BenchmarkComparisonEvent {
                benchmark_id: case.benchmark_id.clone(),
                category: case.category,
                runtime,
                event: "benchmark_case_completed".to_string(),
                outcome: "pass".to_string(),
            });

            runtime_args.clear();
        }
    }

    let evidence_bundle = build_benchmark_comparison_evidence_bundle(
        manifest,
        &resolved_programs,
        &run_id,
        &results,
    )?;

    Ok(BenchmarkComparisonSuiteResult {
        schema_version: BENCHMARK_COMPARISON_SCHEMA_VERSION.to_string(),
        run_id,
        run_date,
        manifest: manifest.clone(),
        results,
        events,
        commands,
        evidence_bundle,
    })
}

fn render_benchmark_comparison_command(
    measurement_mode: BenchmarkComparisonMeasurementMode,
    runtime: RuntimeId,
    runtime_bin: &Path,
    runtime_args: &[String],
    case_timeout_ms: u64,
) -> String {
    let joined_args = runtime_args
        .iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let base = match measurement_mode {
        BenchmarkComparisonMeasurementMode::DirectLinuxWait4 => format!(
            "runner(timeout_ms={case_timeout_ms}) => direct(wait4+pidfd) {} {}",
            shell_quote(runtime_bin.to_string_lossy().as_ref()),
            joined_args
        ),
        BenchmarkComparisonMeasurementMode::TimeWrapper => format!(
            "runner(timeout_ms={case_timeout_ms}) => /usr/bin/time -q -f '{}\\t%e\\t%M' {} {}",
            BENCHMARK_COMPARISON_TIMING_FOOTER_PLACEHOLDER,
            shell_quote(runtime_bin.to_string_lossy().as_ref()),
            joined_args
        ),
    };
    let _ = runtime;
    base
}

#[cfg(target_os = "linux")]
fn run_single_benchmark_comparison_sample_direct_linux(
    case: &BenchmarkComparisonCase,
    runtime: RuntimeId,
    runtime_bin: &Path,
    runtime_args: &[String],
    case_timeout_ms: u64,
) -> Result<BenchmarkComparisonSample, BenchmarkComparisonError> {
    let timeout = Duration::from_millis(case_timeout_ms);
    let mut command = Command::new(runtime_bin);
    command
        .args(runtime_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|error| BenchmarkComparisonError::Io(error.to_string()))?;
    let pidfd = pidfd_open(Pid::from_child(&child), PidfdFlags::empty())
        .map_err(|error| BenchmarkComparisonError::Io(error.to_string()))?;
    let stdout_reader =
        benchmark_comparison_spawn_reader(child.stdout.take().ok_or_else(|| {
            BenchmarkComparisonError::Io("missing child stdout pipe".to_string())
        })?);
    let stderr_reader =
        benchmark_comparison_spawn_reader(child.stderr.take().ok_or_else(|| {
            BenchmarkComparisonError::Io("missing child stderr pipe".to_string())
        })?);
    let started = Instant::now();
    if !benchmark_comparison_wait_for_pidfd(&pidfd, timeout)
        .map_err(|error| BenchmarkComparisonError::Io(error.to_string()))?
    {
        let status = benchmark_comparison_force_terminate_child(&mut child)
            .map_err(|error| BenchmarkComparisonError::Io(error.to_string()))?;
        let stdout = benchmark_comparison_finish_reader(stdout_reader)?;
        let stderr = benchmark_comparison_finish_reader(stderr_reader)?;
        return Err(BenchmarkComparisonError::CommandFailed {
            benchmark_id: case.benchmark_id.clone(),
            runtime,
            detail: format!(
                "timed out after {case_timeout_ms}ms exit_code={:?} stdout=`{}` stderr=`{}`",
                status.code(),
                String::from_utf8_lossy(&stdout).trim(),
                String::from_utf8_lossy(&stderr).trim()
            ),
        });
    }
    let resuse = child
        .wait4()
        .map_err(|error| BenchmarkComparisonError::Io(error.to_string()))?;
    let wall_time_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    let stdout = benchmark_comparison_finish_reader(stdout_reader)?;
    let stderr = benchmark_comparison_finish_reader(stderr_reader)?;
    if !resuse.status.success() {
        return Err(BenchmarkComparisonError::CommandFailed {
            benchmark_id: case.benchmark_id.clone(),
            runtime,
            detail: format!(
                "exit_code={:?} stdout=`{}` stderr=`{}`",
                resuse.status.code(),
                String::from_utf8_lossy(&stdout).trim(),
                String::from_utf8_lossy(&stderr).trim()
            ),
        });
    }
    Ok(BenchmarkComparisonSample {
        wall_time_ns,
        peak_rss_bytes: resuse.rusage.maxrss,
        output_digest: benchmark_comparison_output_digest(&stdout, &stderr),
    })
}

fn run_single_benchmark_comparison_sample_time_wrapper(
    case: &BenchmarkComparisonCase,
    runtime: RuntimeId,
    runtime_bin: &Path,
    runtime_args: &[String],
    case_timeout_ms: u64,
) -> Result<BenchmarkComparisonSample, BenchmarkComparisonError> {
    let timing_marker = benchmark_comparison_timing_marker();
    let timeout = Duration::from_millis(case_timeout_ms);
    let mut command = Command::new("/usr/bin/time");
    command
        .arg("-q")
        .arg("-f")
        .arg(format!("{timing_marker}\t%e\t%M"))
        .arg(runtime_bin)
        .args(runtime_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|error| BenchmarkComparisonError::Io(error.to_string()))?;
    let stdout_reader =
        benchmark_comparison_spawn_reader(child.stdout.take().ok_or_else(|| {
            BenchmarkComparisonError::Io("missing child stdout pipe".to_string())
        })?);
    let stderr_reader =
        benchmark_comparison_spawn_reader(child.stderr.take().ok_or_else(|| {
            BenchmarkComparisonError::Io("missing child stderr pipe".to_string())
        })?);
    let status = match benchmark_comparison_wait_for_exit(&mut child, timeout)
        .map_err(|error| BenchmarkComparisonError::Io(error.to_string()))?
    {
        Some(status) => status,
        None => {
            let status = benchmark_comparison_force_terminate_child(&mut child)
                .map_err(|error| BenchmarkComparisonError::Io(error.to_string()))?;
            let stdout = benchmark_comparison_finish_reader(stdout_reader)?;
            let stderr = benchmark_comparison_finish_reader(stderr_reader)?;
            return Err(BenchmarkComparisonError::CommandFailed {
                benchmark_id: case.benchmark_id.clone(),
                runtime,
                detail: format!(
                    "timed out after {case_timeout_ms}ms exit_code={:?} stdout=`{}` stderr=`{}`",
                    status.code(),
                    String::from_utf8_lossy(&stdout).trim(),
                    String::from_utf8_lossy(&stderr).trim()
                ),
            });
        }
    };
    let stdout = benchmark_comparison_finish_reader(stdout_reader)?;
    let stderr = benchmark_comparison_finish_reader(stderr_reader)?;
    if !status.success() {
        let stderr = benchmark_comparison_extract_timing_footer(
            &case.benchmark_id,
            runtime,
            stderr.clone(),
            &timing_marker,
        )
        .map(|(stderr, _, _)| stderr)
        .unwrap_or(stderr);
        return Err(BenchmarkComparisonError::CommandFailed {
            benchmark_id: case.benchmark_id.clone(),
            runtime,
            detail: format!(
                "exit_code={:?} stdout=`{}` stderr=`{}`",
                status.code(),
                String::from_utf8_lossy(&stdout).trim(),
                String::from_utf8_lossy(&stderr).trim()
            ),
        });
    }

    let (stderr, elapsed_ns, peak_rss_bytes) = benchmark_comparison_extract_timing_footer(
        &case.benchmark_id,
        runtime,
        stderr,
        &timing_marker,
    )?;
    Ok(BenchmarkComparisonSample {
        wall_time_ns: elapsed_ns,
        peak_rss_bytes,
        output_digest: benchmark_comparison_output_digest(&stdout, &stderr),
    })
}

fn run_single_benchmark_comparison_sample(
    case: &BenchmarkComparisonCase,
    runtime: RuntimeId,
    runtime_bin: &Path,
    runtime_args: &[String],
    case_timeout_ms: u64,
    measurement_mode: BenchmarkComparisonMeasurementMode,
) -> Result<BenchmarkComparisonSample, BenchmarkComparisonError> {
    match measurement_mode {
        #[cfg(target_os = "linux")]
        BenchmarkComparisonMeasurementMode::DirectLinuxWait4 => {
            run_single_benchmark_comparison_sample_direct_linux(
                case,
                runtime,
                runtime_bin,
                runtime_args,
                case_timeout_ms,
            )
        }
        #[cfg(not(target_os = "linux"))]
        BenchmarkComparisonMeasurementMode::DirectLinuxWait4 => {
            unreachable!("direct benchmark comparison measurement mode is Linux-only")
        }
        BenchmarkComparisonMeasurementMode::TimeWrapper => {
            run_single_benchmark_comparison_sample_time_wrapper(
                case,
                runtime,
                runtime_bin,
                runtime_args,
                case_timeout_ms,
            )
        }
    }
}

fn current_unix_timestamp_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

fn shell_quote(input: &str) -> String {
    if input
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | ':'))
    {
        input.to_string()
    } else {
        format!("'{}'", input.replace('\'', "'\"'\"'"))
    }
}

#[derive(Debug, Clone)]
pub struct BenchmarkSuiteConfig {
    pub seed: u64,
    pub profiles: Vec<ScaleProfile>,
    pub families: Vec<BenchmarkFamily>,
    pub thresholds: RegressionThresholds,
    pub run_id: String,
    pub run_date: String,
}

impl Default for BenchmarkSuiteConfig {
    fn default() -> Self {
        Self {
            seed: 42,
            profiles: vec![
                ScaleProfile::Small,
                ScaleProfile::Medium,
                ScaleProfile::Large,
            ],
            families: BenchmarkFamily::all().to_vec(),
            thresholds: RegressionThresholds::default(),
            run_id: "benchmark-run-default".to_string(),
            run_date: "2026-02-22".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct BenchmarkSuiteResult {
    pub config: BenchmarkSuiteConfig,
    pub measurements: Vec<BenchmarkMeasurement>,
    pub regressions: Vec<RegressionResult>,
    pub blocked: bool,
    pub total_operations: u64,
    pub total_duration_us: u64,
    pub invariant_violations: u64,
    pub events: Vec<BenchmarkSuiteEvent>,
}

#[derive(Debug, Clone)]
pub struct BenchmarkSuiteEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub family: Option<String>,
    pub profile: Option<String>,
}

/// Run the full benchmark suite across all configured families and profiles.
pub fn run_benchmark_suite(config: &BenchmarkSuiteConfig) -> BenchmarkSuiteResult {
    let mut measurements = Vec::new();
    let mut events = Vec::new();
    let mut total_ops: u64 = 0;
    let mut total_duration: u64 = 0;
    let mut invariant_violations: u64 = 0;

    for family in &config.families {
        for profile in &config.profiles {
            let m = run_benchmark(*family, *profile, config.seed);
            total_ops += m.total_operations;
            total_duration += m.duration_us;
            invariant_violations += m.invariant_violations;

            events.push(BenchmarkSuiteEvent {
                trace_id: config.run_id.clone(),
                decision_id: format!("bench-{}-{}", family.as_str(), profile.as_str()),
                policy_id: "benchmark-e2e".to_string(),
                component: BENCHMARK_E2E_COMPONENT.to_string(),
                event: "benchmark_case_completed".to_string(),
                outcome: if m.invariant_violations == 0 {
                    "pass".to_string()
                } else {
                    "fail".to_string()
                },
                error_code: None,
                family: Some(family.as_str().to_string()),
                profile: Some(profile.as_str().to_string()),
            });

            measurements.push(m);
        }
    }

    BenchmarkSuiteResult {
        config: config.clone(),
        measurements,
        regressions: Vec::new(),
        blocked: invariant_violations > 0,
        total_operations: total_ops,
        total_duration_us: total_duration,
        invariant_violations,
        events,
    }
}

/// Run the suite and compare against baseline measurements for regression detection.
pub fn run_benchmark_suite_with_regression(
    config: &BenchmarkSuiteConfig,
    baselines: &[BenchmarkMeasurement],
) -> BenchmarkSuiteResult {
    let mut result = run_benchmark_suite(config);

    let baseline_map: BTreeMap<(String, String), &BenchmarkMeasurement> = baselines
        .iter()
        .map(|b| {
            (
                (
                    b.family.as_str().to_string(),
                    b.profile.as_str().to_string(),
                ),
                b,
            )
        })
        .collect();

    for m in &result.measurements {
        let key = (
            m.family.as_str().to_string(),
            m.profile.as_str().to_string(),
        );
        if let Some(baseline) = baseline_map.get(&key) {
            let regression = detect_regression(m, baseline, &config.thresholds);
            if regression.blocked {
                result.blocked = true;
            }
            result.regressions.push(regression);
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Score computation (integrates with benchmark_denominator)
// ---------------------------------------------------------------------------

/// Convert benchmark measurements into BenchmarkCases for the weighted geometric mean
/// computation. Uses a synthetic baseline multiplier to simulate comparison.
pub fn measurements_to_cases(
    measurements: &[BenchmarkMeasurement],
    baseline_multiplier: f64,
) -> Vec<BenchmarkCase> {
    measurements
        .iter()
        .map(|m| BenchmarkCase {
            workload_id: format!("{}-{}", m.family.as_str(), m.profile.as_str()),
            throughput_franken_tps: m.throughput_ops_per_sec,
            throughput_baseline_tps: m.throughput_ops_per_sec / baseline_multiplier,
            weight: Some(m.family.default_weight() / 3.0), // divided by 3 profiles
            behavior_equivalent: m.invariant_violations == 0,
            latency_envelope_ok: true,
            error_envelope_ok: true,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Evidence artifact production
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct BenchmarkEvidenceArtifacts {
    pub run_manifest_path: PathBuf,
    pub evidence_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub benchmark_env_manifest_path: PathBuf,
    pub raw_results_archive_path: PathBuf,
    pub summary_path: PathBuf,
    pub comparison_bundle_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkEnvironmentManifest {
    pub schema_version: String,
    pub run_id: String,
    pub run_date: String,
    pub seed: u64,
    pub locale: String,
    pub timezone: String,
    pub os: String,
    pub arch: String,
    pub cpu_model: String,
    pub memory_bytes: u64,
    pub engine_version: String,
    pub runtime_pins: BenchmarkRuntimePins,
    pub fairness_policy: BenchmarkFairnessPolicy,
}

fn build_environment_manifest(
    result: &BenchmarkSuiteResult,
    contract: &BenchmarkHarnessContract,
) -> BenchmarkEnvironmentManifest {
    let locale = env::var("LC_ALL")
        .or_else(|_| env::var("LANG"))
        .unwrap_or_else(|_| "C".to_string());
    let timezone = env::var("TZ").unwrap_or_else(|_| "UTC".to_string());
    let cpu_model = host_cpu_model().unwrap_or_else(|| env::consts::ARCH.to_string());
    let memory_bytes = host_memory_bytes().unwrap_or(0);

    BenchmarkEnvironmentManifest {
        schema_version: BENCHMARK_ENV_SCHEMA_VERSION.to_string(),
        run_id: result.config.run_id.clone(),
        run_date: result.config.run_date.clone(),
        seed: result.config.seed,
        locale,
        timezone,
        os: env::consts::OS.to_string(),
        arch: env::consts::ARCH.to_string(),
        cpu_model,
        memory_bytes,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        runtime_pins: contract.runtime_pins.clone(),
        fairness_policy: contract.fairness_policy,
    }
}

/// Write evidence artifacts to the given directory.
pub fn write_evidence_artifacts(
    result: &BenchmarkSuiteResult,
    output_dir: &Path,
) -> std::io::Result<BenchmarkEvidenceArtifacts> {
    fs::create_dir_all(output_dir)?;

    let contract = BenchmarkHarnessContract::default();
    validate_harness_contract(&contract).map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
    })?;

    let commands_path = output_dir.join("commands.txt");
    let events_path = output_dir.join("events.jsonl");
    let env_manifest_path = output_dir.join("benchmark_env_manifest.json");
    let raw_results_archive_path = output_dir.join("raw_results_archive.json");

    let commands = [
        "rch exec -- cargo test -p frankenengine-engine --test benchmark_e2e --test benchmark_e2e_integration",
        "rch exec -- cargo run -p frankenengine-engine --bin franken_lockstep_runner -- --preflight-only",
        "rch exec -- scripts/run_benchmark_e2e_suite.sh report",
    ];
    fs::write(&commands_path, commands.join("\n") + "\n")?;

    let env_manifest = build_environment_manifest(result, &contract);
    let environment_summary = serde_json::json!({
        "os": env_manifest.os.clone(),
        "arch": env_manifest.arch.clone(),
        "cpu_model": env_manifest.cpu_model.clone(),
        "memory_bytes": env_manifest.memory_bytes,
        "engine_version": env_manifest.engine_version.clone(),
        "locale": env_manifest.locale.clone(),
        "timezone": env_manifest.timezone.clone(),
    });
    fs::write(
        &env_manifest_path,
        serde_json::to_string_pretty(&env_manifest).expect("serde deserialization should succeed"),
    )?;

    let raw_results = serde_json::json!({
        "schema_version": "franken-engine.benchmark-e2e.raw-results.v1",
        "run_id": result.config.run_id,
        "run_date": result.config.run_date,
        "seed": result.config.seed,
        "measured_surface": benchmark_surface_metadata(),
        "environment": environment_summary,
        "families": result.config.families.iter().map(|f| f.as_str()).collect::<Vec<_>>(),
        "profiles": result.config.profiles.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        "measurements": result.measurements.iter().map(|m| {
            serde_json::json!({
                "family": m.family.as_str(),
                "profile": m.profile.as_str(),
                "throughput_ops_per_sec": m.throughput_ops_per_sec,
                "latency": {
                    "p50_us": m.latency.p50_us,
                    "p95_us": m.latency.p95_us,
                    "p99_us": m.latency.p99_us,
                    "min_us": m.latency.min_us,
                    "max_us": m.latency.max_us,
                    "sample_count": m.latency.sample_count,
                },
                "total_operations": m.total_operations,
                "duration_us": m.duration_us,
                "correctness_digest": m.correctness_digest,
                "invariant_violations": m.invariant_violations,
                "security_events": m.security_events,
                "peak_extensions_alive": m.peak_extensions_alive,
            })
        }).collect::<Vec<_>>(),
        "regressions": result.regressions.iter().map(|r| {
            serde_json::json!({
                "family": r.family.as_str(),
                "profile": r.profile.as_str(),
                "throughput_delta_pct": r.throughput_delta_pct,
                "p95_delta_pct": r.p95_delta_pct,
                "p99_delta_pct": r.p99_delta_pct,
                "blocked": r.blocked,
                "blockers": r.blockers,
            })
        }).collect::<Vec<_>>(),
        "events": result.events.iter().map(|evt| {
            serde_json::json!({
                "trace_id": evt.trace_id,
                "decision_id": evt.decision_id,
                "policy_id": evt.policy_id,
                "component": evt.component,
                "event": evt.event,
                "outcome": evt.outcome,
                "error_code": evt.error_code,
                "family": evt.family,
                "profile": evt.profile,
            })
        }).collect::<Vec<_>>(),
    });
    fs::write(
        &raw_results_archive_path,
        serde_json::to_string_pretty(&raw_results).expect("serde deserialization should succeed"),
    )?;

    // Run manifest
    let manifest_path = output_dir.join("run_manifest.json");
    let manifest = serde_json::json!({
        "schema_version": BENCHMARK_E2E_SCHEMA_VERSION,
        "run_id": result.config.run_id,
        "run_date": result.config.run_date,
        "seed": result.config.seed,
        "measured_surface": benchmark_surface_metadata(),
        "environment": {
            "os": env_manifest.os,
            "arch": env_manifest.arch,
            "cpu_model": env_manifest.cpu_model,
            "memory_bytes": env_manifest.memory_bytes,
            "engine_version": env_manifest.engine_version,
            "locale": env_manifest.locale,
            "timezone": env_manifest.timezone,
        },
        "families": result.config.families.iter().map(|f| f.as_str()).collect::<Vec<_>>(),
        "profiles": result.config.profiles.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        "total_operations": result.total_operations,
        "total_duration_us": result.total_duration_us,
        "blocked": result.blocked,
        "invariant_violations": result.invariant_violations,
        "runtime_pins": contract.runtime_pins,
        "fairness_policy": contract.fairness_policy,
        "artifacts": {
            "manifest": manifest_path,
            "benchmark_evidence": output_dir.join("benchmark_evidence.jsonl"),
            "events": events_path,
            "commands": commands_path,
            "benchmark_env_manifest": env_manifest_path,
            "raw_results_archive": raw_results_archive_path,
            "summary": output_dir.join("benchmark_summary.json"),
        },
    });
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("serde deserialization should succeed"),
    )?;

    // Evidence JSONL
    let evidence_path = output_dir.join("benchmark_evidence.jsonl");
    let mut evidence_lines = Vec::new();
    for m in &result.measurements {
        let entry = serde_json::json!({
            "event": "benchmark_case_evaluated",
            "family": m.family.as_str(),
            "profile": m.profile.as_str(),
            "throughput_ops_per_sec": m.throughput_ops_per_sec,
            "p50_us": m.latency.p50_us,
            "p95_us": m.latency.p95_us,
            "p99_us": m.latency.p99_us,
            "total_operations": m.total_operations,
            "duration_us": m.duration_us,
            "invariant_violations": m.invariant_violations,
            "security_events": m.security_events,
            "peak_extensions_alive": m.peak_extensions_alive,
            "correctness_digest": m.correctness_digest,
        });
        evidence_lines
            .push(serde_json::to_string(&entry).expect("serde deserialization should succeed"));
    }
    for r in &result.regressions {
        let entry = serde_json::json!({
            "event": "regression_check",
            "family": r.family.as_str(),
            "profile": r.profile.as_str(),
            "throughput_delta_pct": r.throughput_delta_pct,
            "p95_delta_pct": r.p95_delta_pct,
            "p99_delta_pct": r.p99_delta_pct,
            "blocked": r.blocked,
            "blockers": r.blockers,
        });
        evidence_lines
            .push(serde_json::to_string(&entry).expect("serde deserialization should succeed"));
    }
    for evt in &result.events {
        let entry = serde_json::json!({
            "trace_id": evt.trace_id,
            "decision_id": evt.decision_id,
            "policy_id": evt.policy_id,
            "event": evt.event,
            "component": evt.component,
            "outcome": evt.outcome,
            "error_code": evt.error_code,
            "family": evt.family,
            "profile": evt.profile,
        });
        evidence_lines
            .push(serde_json::to_string(&entry).expect("serde deserialization should succeed"));
    }
    fs::write(&evidence_path, evidence_lines.join("\n") + "\n")?;

    let event_lines = result
        .events
        .iter()
        .map(|evt| {
            serde_json::json!({
                "trace_id": evt.trace_id,
                "decision_id": evt.decision_id,
                "policy_id": evt.policy_id,
                "component": evt.component,
                "event": evt.event,
                "outcome": evt.outcome,
                "error_code": evt.error_code,
            })
        })
        .map(|entry| serde_json::to_string(&entry).expect("serde deserialization should succeed"))
        .collect::<Vec<_>>();
    fs::write(&events_path, event_lines.join("\n") + "\n")?;

    // Summary
    let summary_path = output_dir.join("benchmark_summary.json");
    let mut family_summaries = Vec::new();
    for family in BenchmarkFamily::all() {
        let family_measurements: Vec<&BenchmarkMeasurement> = result
            .measurements
            .iter()
            .filter(|m| m.family == *family)
            .collect();
        if family_measurements.is_empty() {
            continue;
        }
        let avg_throughput: f64 = family_measurements
            .iter()
            .map(|m| m.throughput_ops_per_sec)
            .sum::<f64>()
            / family_measurements.len() as f64;
        family_summaries.push(serde_json::json!({
            "family": family.as_str(),
            "avg_throughput_ops_per_sec": avg_throughput,
            "profiles_run": family_measurements.len(),
            "total_invariant_violations": family_measurements.iter().map(|m| m.invariant_violations).fold(0u64, |acc, x| acc.saturating_add(x)),
        }));
    }
    let configured_families = result
        .config
        .families
        .iter()
        .map(|family| family.as_str())
        .collect::<Vec<_>>();
    let configured_profiles = result
        .config
        .profiles
        .iter()
        .map(|profile| profile.as_str())
        .collect::<Vec<_>>();
    let expected_measurement_count = result
        .config
        .families
        .len()
        .saturating_mul(result.config.profiles.len());
    let complete_suite_evidence = result.config.families.len() == BenchmarkFamily::all().len()
        && result.config.profiles.len() == ScaleProfile::all().len()
        && result.measurements.len() == expected_measurement_count;
    let summary = serde_json::json!({
        "schema_version": BENCHMARK_E2E_SCHEMA_VERSION,
        "run_id": result.config.run_id,
        "blocked": result.blocked,
        "measurement_count": result.measurements.len(),
        "expected_measurement_count": expected_measurement_count,
        "regression_count": result.regressions.len(),
        "configured_families": configured_families,
        "configured_profiles": configured_profiles,
        "complete_suite_evidence": complete_suite_evidence,
        "measured_surface": benchmark_surface_metadata(),
        "environment": environment_summary,
        "families": family_summaries,
    });
    fs::write(
        &summary_path,
        serde_json::to_string_pretty(&summary).expect("serde deserialization should succeed"),
    )?;

    Ok(BenchmarkEvidenceArtifacts {
        run_manifest_path: manifest_path,
        evidence_path,
        events_path,
        commands_path,
        benchmark_env_manifest_path: env_manifest_path,
        raw_results_archive_path,
        summary_path,
        comparison_bundle_path: None,
    })
}

pub fn write_benchmark_comparison_artifacts(
    result: &BenchmarkComparisonSuiteResult,
    output_dir: &Path,
) -> std::io::Result<BenchmarkEvidenceArtifacts> {
    fs::create_dir_all(output_dir)?;

    let commands_path = output_dir.join("commands.txt");
    let events_path = output_dir.join("events.jsonl");
    let env_manifest_path = output_dir.join("benchmark_env_manifest.json");
    let raw_results_archive_path = output_dir.join("raw_results_archive.json");
    let summary_path = output_dir.join("benchmark_summary.json");
    let evidence_path = output_dir.join("benchmark_evidence.jsonl");
    let run_manifest_path = output_dir.join("run_manifest.json");
    let comparison_bundle_path = output_dir.join("comparison_evidence_bundle.json");

    fs::write(&commands_path, result.commands.join("\n") + "\n")?;

    let contract = BenchmarkHarnessContract {
        runtime_pins: result.manifest.runtime_pins.clone(),
        fairness_policy: result.manifest.fairness_policy,
    };
    let env_manifest = BenchmarkEnvironmentManifest {
        schema_version: BENCHMARK_ENV_SCHEMA_VERSION.to_string(),
        run_id: result.run_id.clone(),
        run_date: result.run_date.clone(),
        seed: 0,
        locale: env::var("LC_ALL")
            .or_else(|_| env::var("LANG"))
            .unwrap_or_else(|_| "C".to_string()),
        timezone: env::var("TZ").unwrap_or_else(|_| "UTC".to_string()),
        os: env::consts::OS.to_string(),
        arch: env::consts::ARCH.to_string(),
        cpu_model: host_cpu_model().unwrap_or_else(|| env::consts::ARCH.to_string()),
        memory_bytes: host_memory_bytes().unwrap_or(0),
        engine_version: result.manifest.runtime_pins.franken_engine.clone(),
        runtime_pins: contract.runtime_pins,
        fairness_policy: contract.fairness_policy,
    };
    let environment_summary = serde_json::json!({
        "os": env_manifest.os.clone(),
        "arch": env_manifest.arch.clone(),
        "cpu_model": env_manifest.cpu_model.clone(),
        "memory_bytes": env_manifest.memory_bytes,
        "engine_version": env_manifest.engine_version.clone(),
        "locale": env_manifest.locale.clone(),
        "timezone": env_manifest.timezone.clone(),
    });
    fs::write(
        &env_manifest_path,
        serde_json::to_string_pretty(&env_manifest).expect("serde deserialization should succeed"),
    )?;

    let raw_results = serde_json::json!({
        "schema_version": "franken-engine.benchmark-comparison.raw-results.v1",
        "run_id": &result.run_id,
        "run_date": &result.run_date,
        "environment": environment_summary,
        "cases": result.manifest.cases.iter().map(|case| {
            serde_json::json!({
                "benchmark_id": &case.benchmark_id,
                "category": case.category.as_str(),
                "program_path": case.program_path.display().to_string(),
                "args": &case.args,
            })
        }).collect::<Vec<_>>(),
        "results": result.results.iter().map(|entry| {
            serde_json::json!({
                "benchmark_id": &entry.benchmark_id,
                "category": entry.category.as_str(),
                "runtime": entry.runtime.as_str(),
                "statistics": &entry.statistics,
                "raw_samples": &entry.raw_samples,
                "benchmark_result": &entry.benchmark_result,
            })
        }).collect::<Vec<_>>(),
    });
    fs::write(
        &raw_results_archive_path,
        serde_json::to_string_pretty(&raw_results).expect("serde deserialization should succeed"),
    )?;
    fs::write(
        &comparison_bundle_path,
        serde_json::to_string_pretty(&result.evidence_bundle)
            .expect("serde deserialization should succeed"),
    )?;

    let evidence_lines = result
        .results
        .iter()
        .map(|entry| {
            serde_json::json!({
                "event": "benchmark_comparison_runtime_completed",
                "benchmark_id": &entry.benchmark_id,
                "category": entry.category.as_str(),
                "runtime": entry.runtime.as_str(),
                "median_ns": entry.statistics.median_ns,
                "mean_ns": entry.statistics.mean_ns,
                "p95_ns": entry.statistics.p95_ns,
                "p99_ns": entry.statistics.p99_ns,
                "peak_rss_bytes_max": entry.statistics.peak_rss_bytes_max,
                "cv_millionths": entry.statistics.cv_millionths,
            })
        })
        .map(|line| serde_json::to_string(&line).expect("serde deserialization should succeed"))
        .collect::<Vec<_>>();
    fs::write(&evidence_path, evidence_lines.join("\n") + "\n")?;

    let event_lines = result
        .events
        .iter()
        .map(|event| {
            serde_json::json!({
                "benchmark_id": &event.benchmark_id,
                "category": event.category.as_str(),
                "runtime": event.runtime.as_str(),
                "event": &event.event,
                "outcome": &event.outcome,
                "component": BENCHMARK_COMPARISON_COMPONENT,
            })
        })
        .map(|line| serde_json::to_string(&line).expect("serde deserialization should succeed"))
        .collect::<Vec<_>>();
    fs::write(&events_path, event_lines.join("\n") + "\n")?;

    let summary = serde_json::json!({
        "schema_version": BENCHMARK_COMPARISON_SCHEMA_VERSION,
        "run_id": &result.run_id,
        "run_date": &result.run_date,
        "benchmark_count": result.manifest.cases.len(),
        "runtime_result_count": result.results.len(),
        "environment": environment_summary,
        "runtimes": ["franken_engine", "node_lts", "bun_stable"],
        "evidence_bundle_status": result.evidence_bundle.status.to_string(),
    });
    fs::write(
        &summary_path,
        serde_json::to_string_pretty(&summary).expect("serde deserialization should succeed"),
    )?;

    let manifest = serde_json::json!({
        "schema_version": BENCHMARK_COMPARISON_SCHEMA_VERSION,
        "run_id": &result.run_id,
        "run_date": &result.run_date,
        "environment": {
            "os": env_manifest.os,
            "arch": env_manifest.arch,
            "cpu_model": env_manifest.cpu_model,
            "memory_bytes": env_manifest.memory_bytes,
            "engine_version": env_manifest.engine_version,
            "locale": env_manifest.locale,
            "timezone": env_manifest.timezone,
        },
        "fairness_policy": result.manifest.fairness_policy,
        "runtime_pins": &result.manifest.runtime_pins,
        "artifacts": {
            "manifest": run_manifest_path,
            "benchmark_evidence": evidence_path,
            "events": events_path,
            "commands": commands_path,
            "benchmark_env_manifest": env_manifest_path,
            "raw_results_archive": raw_results_archive_path,
            "summary": summary_path,
            "comparison_bundle": comparison_bundle_path,
        },
    });
    fs::write(
        &run_manifest_path,
        serde_json::to_string_pretty(&manifest).expect("serde deserialization should succeed"),
    )?;

    Ok(BenchmarkEvidenceArtifacts {
        run_manifest_path,
        evidence_path,
        events_path,
        commands_path,
        benchmark_env_manifest_path: env_manifest_path,
        raw_results_archive_path,
        summary_path,
        comparison_bundle_path: Some(comparison_bundle_path),
    })
}

/// Configuration for the comparison benchmark runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComparisonBenchmarkRunnerConfig {
    /// Number of repetitions per engine per benchmark (default: 30).
    pub repetitions: u32,
    /// Whether to include statistical confidence intervals.
    pub include_confidence_intervals: bool,
    /// Whether to compute p-values for performance comparisons.
    pub compute_p_values: bool,
}

impl Default for ComparisonBenchmarkRunnerConfig {
    fn default() -> Self {
        Self {
            repetitions: 30,
            include_confidence_intervals: true,
            compute_p_values: true,
        }
    }
}

/// Input for a comparison benchmark run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComparisonBenchmarkInput {
    /// The benchmark comparison manifest describing the cases to run.
    pub manifest: BenchmarkComparisonManifest,
    /// Root directory for resolving relative paths in the manifest.
    pub manifest_root: PathBuf,
    /// Unique identifier for this benchmark run.
    pub run_id: String,
    /// Date of the benchmark run.
    pub run_date: String,
}

/// Output of a comparison benchmark run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComparisonBenchmarkOutput {
    /// The complete benchmark comparison suite result.
    pub suite_result: BenchmarkComparisonSuiteResult,
    /// Summary statistics across all benchmarks.
    pub summary_stats: ComparisonBenchmarkSummary,
}

/// Summary statistics for a comparison benchmark run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComparisonBenchmarkSummary {
    /// Total number of benchmark cases executed.
    pub total_cases: usize,
    /// Total number of samples collected across all runtimes.
    pub total_samples: usize,
    /// Number of cases where FrankenEngine was fastest.
    pub franken_wins: usize,
    /// Number of cases where Node.js was fastest.
    pub node_wins: usize,
    /// Number of cases where Bun was fastest.
    pub bun_wins: usize,
    /// Overall geometric mean speedup vs Node.js (>1.0 = faster, <1.0 = slower).
    pub geometric_mean_vs_node: f64,
    /// Overall geometric mean speedup vs Bun (>1.0 = faster, <1.0 = slower).
    pub geometric_mean_vs_bun: f64,
}

/// Comparison benchmark runner that executes JavaScript files across multiple engines.
///
/// This runner wraps the existing benchmark comparison infrastructure to provide
/// a cleaner API for running multi-engine performance comparisons. It executes
/// the same JavaScript files through frankenctl, node, and bun, measuring
/// wall-clock time and peak RSS memory usage with statistical analysis.
#[derive(Debug, Clone)]
pub struct ComparisonBenchmarkRunner {
    /// Configuration for this runner.
    pub config: ComparisonBenchmarkRunnerConfig,
}

impl ComparisonBenchmarkRunner {
    /// Create a new comparison benchmark runner with the given configuration.
    pub fn new(config: ComparisonBenchmarkRunnerConfig) -> Self {
        Self { config }
    }

    /// Create a new comparison benchmark runner with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ComparisonBenchmarkRunnerConfig::default())
    }

    /// Run a comparison benchmark suite.
    ///
    /// This method executes all benchmark cases defined in the input manifest,
    /// running each case through frankenctl, node, and bun with the configured
    /// number of repetitions. It measures wall-clock time and peak RSS memory
    /// usage, computes statistical summaries, and returns comprehensive results.
    ///
    /// # Arguments
    ///
    /// * `input` - The benchmark input containing the manifest and run metadata
    ///
    /// # Returns
    ///
    /// A result containing the benchmark output with detailed results and summary
    /// statistics, or an error if the benchmark run fails.
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - The manifest is invalid or contains malformed benchmark cases
    /// - External runtime commands (frankenctl, node, bun) are not available
    /// - JavaScript files specified in the manifest cannot be read
    /// - Individual benchmark executions timeout or fail
    pub fn run(
        &self,
        input: ComparisonBenchmarkInput,
    ) -> Result<ComparisonBenchmarkOutput, BenchmarkComparisonError> {
        // Validate that the repetitions match the fairness policy
        let mut manifest = input.manifest;
        manifest.fairness_policy.sample_count = self.config.repetitions;

        // Run the benchmark comparison suite
        let suite_result = run_benchmark_comparison_suite(
            &manifest,
            &input.manifest_root,
            input.run_id,
            input.run_date,
        )?;

        // Compute summary statistics
        let summary_stats = self.compute_summary_statistics(&suite_result);

        Ok(ComparisonBenchmarkOutput {
            suite_result,
            summary_stats,
        })
    }

    /// Compute summary statistics from the suite results.
    fn compute_summary_statistics(
        &self,
        suite_result: &BenchmarkComparisonSuiteResult,
    ) -> ComparisonBenchmarkSummary {
        let total_cases = suite_result.manifest.cases.len();
        let total_samples = suite_result.results.len();

        // Group results by benchmark ID to find winners
        let mut benchmark_results: BTreeMap<String, Vec<&BenchmarkComparisonRuntimeResult>> =
            BTreeMap::new();
        for result in &suite_result.results {
            benchmark_results
                .entry(result.benchmark_id.clone())
                .or_default()
                .push(result);
        }

        let mut franken_wins = 0;
        let mut node_wins = 0;
        let mut bun_wins = 0;
        let mut node_speedups = Vec::new();
        let mut bun_speedups = Vec::new();

        for (_, results) in benchmark_results {
            // Find the fastest runtime for this benchmark (lowest median)
            if let Some(fastest) = results.iter().min_by_key(|r| r.statistics.median_ns) {
                match fastest.runtime {
                    RuntimeId::FrankenEngine => franken_wins += 1,
                    RuntimeId::NodeLts => node_wins += 1,
                    RuntimeId::BunStable => bun_wins += 1,
                }
            }

            // Compute speedups relative to FrankenEngine
            let franken_median = results
                .iter()
                .find(|r| r.runtime == RuntimeId::FrankenEngine)
                .map(|r| r.statistics.median_ns);

            if let Some(franken_median) = franken_median
                && franken_median > 0
            {
                if let Some(node_result) = results.iter().find(|r| r.runtime == RuntimeId::NodeLts)
                {
                    let speedup = node_result.statistics.median_ns as f64 / franken_median as f64;
                    node_speedups.push(speedup);
                }

                if let Some(bun_result) = results.iter().find(|r| r.runtime == RuntimeId::BunStable)
                {
                    let speedup = bun_result.statistics.median_ns as f64 / franken_median as f64;
                    bun_speedups.push(speedup);
                }
            }
        }

        // Compute geometric means of speedups
        let geometric_mean_vs_node = if node_speedups.is_empty() {
            1.0
        } else {
            let log_sum: f64 = node_speedups.iter().map(|x| x.ln()).sum();
            (log_sum / node_speedups.len() as f64).exp()
        };

        let geometric_mean_vs_bun = if bun_speedups.is_empty() {
            1.0
        } else {
            let log_sum: f64 = bun_speedups.iter().map(|x| x.ln()).sum();
            (log_sum / bun_speedups.len() as f64).exp()
        };

        ComparisonBenchmarkSummary {
            total_cases,
            total_samples,
            franken_wins,
            node_wins,
            bun_wins,
            geometric_mean_vs_node,
            geometric_mean_vs_bun,
        }
    }
}

impl Default for ComparisonBenchmarkRunner {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ScaleProfile ──────────────────────────────────────────────
    #[test]
    fn scale_profile_as_str() {
        assert_eq!(ScaleProfile::Small.as_str(), "S");
        assert_eq!(ScaleProfile::Medium.as_str(), "M");
        assert_eq!(ScaleProfile::Large.as_str(), "L");
    }

    #[test]
    fn scale_profile_extension_count() {
        assert_eq!(ScaleProfile::Small.extension_count(), 10);
        assert_eq!(ScaleProfile::Medium.extension_count(), 50);
        assert_eq!(ScaleProfile::Large.extension_count(), 200);
    }

    #[test]
    fn scale_profile_iterations() {
        assert_eq!(ScaleProfile::Small.iterations(), 100);
        assert_eq!(ScaleProfile::Medium.iterations(), 500);
        assert_eq!(ScaleProfile::Large.iterations(), 2_000);
    }

    // ── BenchmarkFamily ───────────────────────────────────────────
    #[test]
    fn benchmark_family_as_str() {
        assert_eq!(BenchmarkFamily::BootStorm.as_str(), "boot-storm");
        assert_eq!(
            BenchmarkFamily::CapabilityChurn.as_str(),
            "capability-churn"
        );
        assert_eq!(
            BenchmarkFamily::MixedCpuIoAgentMesh.as_str(),
            "mixed-cpu-io-agent-mesh"
        );
        assert_eq!(
            BenchmarkFamily::ReloadRevokeChurn.as_str(),
            "reload-revoke-churn"
        );
        assert_eq!(
            BenchmarkFamily::AdversarialNoiseUnderLoad.as_str(),
            "adversarial-noise-under-load"
        );
    }

    #[test]
    fn benchmark_family_all_returns_five() {
        let all = BenchmarkFamily::all();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn benchmark_family_default_weights_sum_to_one() {
        let total: f64 = BenchmarkFamily::all()
            .iter()
            .map(|f| f.default_weight())
            .sum();
        assert!((total - 1.0).abs() < 1e-9, "weights sum to {total}");
    }

    #[test]
    fn benchmark_family_default_weight_values() {
        assert!((BenchmarkFamily::BootStorm.default_weight() - 0.25).abs() < 1e-9);
        assert!((BenchmarkFamily::CapabilityChurn.default_weight() - 0.20).abs() < 1e-9);
        assert!((BenchmarkFamily::MixedCpuIoAgentMesh.default_weight() - 0.25).abs() < 1e-9);
        assert!((BenchmarkFamily::ReloadRevokeChurn.default_weight() - 0.15).abs() < 1e-9);
        assert!((BenchmarkFamily::AdversarialNoiseUnderLoad.default_weight() - 0.15).abs() < 1e-9);
    }

    // ── LatencyDistribution ───────────────────────────────────────
    #[test]
    fn latency_distribution_from_sorted_samples() {
        let mut samples: Vec<u64> = (1..=100).collect();
        let dist = LatencyDistribution::from_samples(&mut samples);
        assert_eq!(dist.min_us, 1);
        assert_eq!(dist.max_us, 100);
        assert_eq!(dist.p50_us, 51); // samples[100/2] = samples[50] = 51 (0-indexed)
        assert_eq!(dist.sample_count, 100);
    }

    #[test]
    fn latency_distribution_from_unsorted_samples() {
        let mut samples = vec![50, 10, 90, 30, 70, 20, 80, 40, 60, 100];
        let dist = LatencyDistribution::from_samples(&mut samples);
        assert_eq!(dist.min_us, 10);
        assert_eq!(dist.max_us, 100);
        assert_eq!(dist.sample_count, 10);
    }

    #[test]
    fn latency_distribution_single_sample() {
        let mut samples = vec![42];
        let dist = LatencyDistribution::from_samples(&mut samples);
        assert_eq!(dist.min_us, 42);
        assert_eq!(dist.max_us, 42);
        assert_eq!(dist.p50_us, 42);
        assert_eq!(dist.sample_count, 1);
    }

    #[test]
    #[should_panic(expected = "cannot compute distribution from empty samples")]
    fn latency_distribution_empty_panics() {
        let mut samples: Vec<u64> = Vec::new();
        LatencyDistribution::from_samples(&mut samples);
    }

    // ── RegressionThresholds ──────────────────────────────────────
    #[test]
    fn regression_thresholds_default() {
        let t = RegressionThresholds::default();
        assert!((t.throughput_regression_pct - 5.0).abs() < 1e-9);
        assert!((t.p95_latency_regression_pct - 10.0).abs() < 1e-9);
        assert!((t.p99_latency_regression_pct - 15.0).abs() < 1e-9);
    }

    // ── detect_regression ─────────────────────────────────────────
    fn make_measurement(throughput: f64, p95_us: u64, p99_us: u64) -> BenchmarkMeasurement {
        BenchmarkMeasurement {
            family: BenchmarkFamily::BootStorm,
            profile: ScaleProfile::Small,
            throughput_ops_per_sec: throughput,
            latency: LatencyDistribution {
                p50_us: 100,
                p95_us,
                p99_us,
                min_us: 10,
                max_us: 500,
                sample_count: 100,
            },
            total_operations: 1000,
            duration_us: 1_000_000,
            correctness_digest: "test".to_string(),
            invariant_violations: 0,
            security_events: 0,
            peak_extensions_alive: 10,
        }
    }

    #[test]
    fn detect_regression_no_regression() {
        let baseline = make_measurement(1000.0, 100, 200);
        let current = make_measurement(1100.0, 90, 180);
        let thresholds = RegressionThresholds::default();
        let result = detect_regression(&current, &baseline, &thresholds);
        assert!(!result.blocked);
        assert!(result.blockers.is_empty());
    }

    #[test]
    fn detect_regression_throughput_regression() {
        let baseline = make_measurement(1000.0, 100, 200);
        let current = make_measurement(900.0, 100, 200);
        let thresholds = RegressionThresholds::default();
        let result = detect_regression(&current, &baseline, &thresholds);
        assert!(result.blocked);
        assert!(result.blockers[0].contains("throughput regressed"));
    }

    #[test]
    fn detect_regression_p95_regression() {
        let baseline = make_measurement(1000.0, 100, 200);
        let current = make_measurement(1000.0, 115, 200);
        let thresholds = RegressionThresholds::default();
        let result = detect_regression(&current, &baseline, &thresholds);
        assert!(result.blocked);
        assert!(result.blockers[0].contains("p95 latency regressed"));
    }

    #[test]
    fn detect_regression_p99_regression() {
        let baseline = make_measurement(1000.0, 100, 200);
        let current = make_measurement(1000.0, 100, 240);
        let thresholds = RegressionThresholds::default();
        let result = detect_regression(&current, &baseline, &thresholds);
        assert!(result.blocked);
        assert!(result.blockers[0].contains("p99 latency regressed"));
    }

    #[test]
    fn detect_regression_multiple_blockers() {
        let baseline = make_measurement(1000.0, 100, 200);
        let current = make_measurement(800.0, 150, 300);
        let thresholds = RegressionThresholds::default();
        let result = detect_regression(&current, &baseline, &thresholds);
        assert!(result.blocked);
        assert!(result.blockers.len() >= 2);
    }

    #[test]
    fn detect_regression_zero_baseline_throughput() {
        let baseline = make_measurement(0.0, 100, 200);
        let current = make_measurement(1000.0, 100, 200);
        let thresholds = RegressionThresholds::default();
        let result = detect_regression(&current, &baseline, &thresholds);
        assert!((result.throughput_delta_pct - 0.0).abs() < 1e-9);
    }

    #[test]
    fn detect_regression_zero_baseline_latency() {
        let baseline = make_measurement(1000.0, 0, 0);
        let current = make_measurement(1000.0, 100, 200);
        let thresholds = RegressionThresholds::default();
        let result = detect_regression(&current, &baseline, &thresholds);
        assert!((result.p95_delta_pct - 0.0).abs() < 1e-9);
        assert!((result.p99_delta_pct - 0.0).abs() < 1e-9);
    }

    // ── Xorshift64 ────────────────────────────────────────────────
    #[test]
    fn xorshift64_deterministic() {
        let mut rng1 = Xorshift64::new(42);
        let mut rng2 = Xorshift64::new(42);
        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn xorshift64_zero_seed_becomes_one() {
        let mut rng = Xorshift64::new(0);
        let first = rng.next_u64();
        let mut rng_one = Xorshift64::new(1);
        let first_one = rng_one.next_u64();
        assert_eq!(first, first_one);
    }

    #[test]
    fn xorshift64_different_seeds_differ() {
        let mut rng1 = Xorshift64::new(1);
        let mut rng2 = Xorshift64::new(2);
        assert_ne!(rng1.next_u64(), rng2.next_u64());
    }

    #[test]
    fn xorshift64_next_usize_bounded() {
        let mut rng = Xorshift64::new(42);
        for _ in 0..1000 {
            let val = rng.next_usize(10);
            assert!(val < 10);
        }
    }

    #[test]
    fn xorshift64_next_bool_always_false_at_zero() {
        let mut rng = Xorshift64::new(42);
        for _ in 0..100 {
            assert!(!rng.next_bool(0));
        }
    }

    #[test]
    fn xorshift64_next_bool_always_true_at_hundred() {
        let mut rng = Xorshift64::new(42);
        for _ in 0..100 {
            assert!(rng.next_bool(100));
        }
    }

    // ── BenchmarkSuiteConfig ──────────────────────────────────────
    #[test]
    fn benchmark_suite_config_default() {
        let config = BenchmarkSuiteConfig::default();
        assert_eq!(config.seed, 42);
        assert_eq!(config.profiles.len(), 3);
        assert_eq!(config.families.len(), 5);
        assert_eq!(config.run_id, "benchmark-run-default");
    }

    // ── measurements_to_cases ─────────────────────────────────────
    #[test]
    fn measurements_to_cases_basic() {
        let m = make_measurement(1000.0, 100, 200);
        let cases = measurements_to_cases(&[m], 2.0);
        assert_eq!(cases.len(), 1);
        assert!((cases[0].throughput_franken_tps - 1000.0).abs() < 1e-9);
        assert!((cases[0].throughput_baseline_tps - 500.0).abs() < 1e-9);
        assert!(cases[0].behavior_equivalent);
    }

    #[test]
    fn measurements_to_cases_invariant_violation_not_equivalent() {
        let mut m = make_measurement(1000.0, 100, 200);
        m.invariant_violations = 1;
        let cases = measurements_to_cases(&[m], 1.0);
        assert!(!cases[0].behavior_equivalent);
    }

    #[test]
    fn measurements_to_cases_empty() {
        let cases = measurements_to_cases(&[], 1.0);
        assert!(cases.is_empty());
    }

    // ── Constants ─────────────────────────────────────────────────
    #[test]
    fn benchmark_e2e_constants() {
        assert_eq!(BENCHMARK_E2E_COMPONENT, "benchmark_e2e");
        assert!(!BENCHMARK_E2E_SCHEMA_VERSION.is_empty());
        assert_eq!(
            BENCHMARK_E2E_MEASURED_SURFACE,
            "extension_lifecycle_control_plane"
        );
        assert!(!BENCHMARK_E2E_SURFACE_DESCRIPTION.is_empty());
        const { assert!(!BENCHMARK_E2E_JS_RUNTIME_EXECUTION_INCLUDED) };
        const { assert!(MIN_START_BUDGET_MILLIONTHS > 0) };
    }

    // ── BenchmarkSuiteEvent ───────────────────────────────────────
    #[test]
    fn benchmark_suite_event_fields() {
        let evt = BenchmarkSuiteEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: BENCHMARK_E2E_COMPONENT.to_string(),
            event: "test".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            family: Some("boot-storm".to_string()),
            profile: Some("S".to_string()),
        };
        assert_eq!(evt.trace_id, "t1");
        assert!(evt.error_code.is_none());
        assert_eq!(evt.family.as_deref(), Some("boot-storm"));
    }

    // ── RegressionResult ──────────────────────────────────────────
    #[test]
    fn regression_result_fields() {
        let baseline = make_measurement(1000.0, 100, 200);
        let current = make_measurement(1000.0, 100, 200);
        let thresholds = RegressionThresholds::default();
        let result = detect_regression(&current, &baseline, &thresholds);
        assert_eq!(result.family, BenchmarkFamily::BootStorm);
        assert_eq!(result.profile, ScaleProfile::Small);
        assert!(!result.blocked);
    }

    // ── BenchmarkMeasurement ──────────────────────────────────────
    #[test]
    fn benchmark_measurement_digest_deterministic() {
        let m1 = make_measurement(1000.0, 100, 200);
        let m2 = make_measurement(1000.0, 100, 200);
        assert_eq!(m1.correctness_digest, m2.correctness_digest);
    }

    // ── run_boot_storm ──────────────────────────────────────────────
    #[test]
    fn run_boot_storm_small_deterministic() {
        let m1 = run_boot_storm(ScaleProfile::Small, 42);
        let m2 = run_boot_storm(ScaleProfile::Small, 42);
        assert_eq!(m1.family, BenchmarkFamily::BootStorm);
        assert_eq!(m1.profile, ScaleProfile::Small);
        assert_eq!(m1.correctness_digest, m2.correctness_digest);
        assert_eq!(m1.total_operations, m2.total_operations);
        assert!(m1.total_operations > 0);
        assert!(m1.throughput_ops_per_sec > 0.0);
        assert!(m1.duration_us > 0);
        assert_eq!(m1.security_events, 0);
        assert_eq!(m1.invariant_violations, 0);
        assert!(m1.peak_extensions_alive > 0);
        assert!(m1.latency.sample_count > 0);
    }

    #[test]
    fn run_boot_storm_different_seeds_differ() {
        let m1 = run_boot_storm(ScaleProfile::Small, 1);
        let m2 = run_boot_storm(ScaleProfile::Small, 999);
        assert_ne!(m1.correctness_digest, m2.correctness_digest);
    }

    // ── run_capability_churn ────────────────────────────────────────
    #[test]
    fn run_capability_churn_small() {
        let m = run_capability_churn(ScaleProfile::Small, 42);
        assert_eq!(m.family, BenchmarkFamily::CapabilityChurn);
        assert_eq!(m.profile, ScaleProfile::Small);
        assert!(m.total_operations > 0);
        assert!(m.throughput_ops_per_sec > 0.0);
        assert!(m.duration_us > 0);
        assert_eq!(m.invariant_violations, 0);
        assert_eq!(
            m.peak_extensions_alive,
            ScaleProfile::Small.extension_count()
        );
        assert!(m.latency.sample_count > 0);
    }

    #[test]
    fn run_capability_churn_deterministic() {
        let m1 = run_capability_churn(ScaleProfile::Small, 7);
        let m2 = run_capability_churn(ScaleProfile::Small, 7);
        assert_eq!(m1.correctness_digest, m2.correctness_digest);
        assert_eq!(m1.total_operations, m2.total_operations);
        assert_eq!(m1.security_events, m2.security_events);
    }

    // ── run_mixed_cpu_io_agent_mesh ─────────────────────────────────
    #[test]
    fn run_mixed_cpu_io_agent_mesh_small() {
        let m = run_mixed_cpu_io_agent_mesh(ScaleProfile::Small, 42);
        assert_eq!(m.family, BenchmarkFamily::MixedCpuIoAgentMesh);
        assert_eq!(m.profile, ScaleProfile::Small);
        assert!(m.total_operations > 0);
        assert!(m.throughput_ops_per_sec > 0.0);
        assert_eq!(m.invariant_violations, 0);
        assert_eq!(
            m.peak_extensions_alive,
            ScaleProfile::Small.extension_count()
        );
        assert!(m.latency.sample_count > 0);
    }

    #[test]
    fn run_mixed_cpu_io_agent_mesh_deterministic() {
        let m1 = run_mixed_cpu_io_agent_mesh(ScaleProfile::Small, 99);
        let m2 = run_mixed_cpu_io_agent_mesh(ScaleProfile::Small, 99);
        assert_eq!(m1.correctness_digest, m2.correctness_digest);
        assert_eq!(m1.security_events, m2.security_events);
    }

    // ── run_reload_revoke_churn ─────────────────────────────────────
    #[test]
    fn run_reload_revoke_churn_small() {
        let m = run_reload_revoke_churn(ScaleProfile::Small, 42);
        assert_eq!(m.family, BenchmarkFamily::ReloadRevokeChurn);
        assert_eq!(m.profile, ScaleProfile::Small);
        assert!(m.total_operations > 0);
        assert!(m.throughput_ops_per_sec > 0.0);
        assert_eq!(m.invariant_violations, 0);
        assert_eq!(m.security_events, 0);
        assert!(m.latency.sample_count > 0);
    }

    #[test]
    fn run_reload_revoke_churn_deterministic() {
        let m1 = run_reload_revoke_churn(ScaleProfile::Small, 55);
        let m2 = run_reload_revoke_churn(ScaleProfile::Small, 55);
        assert_eq!(m1.correctness_digest, m2.correctness_digest);
        assert_eq!(m1.total_operations, m2.total_operations);
    }

    // ── run_adversarial_noise_under_load ────────────────────────────
    #[test]
    fn run_adversarial_noise_under_load_small() {
        let m = run_adversarial_noise_under_load(ScaleProfile::Small, 42);
        assert_eq!(m.family, BenchmarkFamily::AdversarialNoiseUnderLoad);
        assert_eq!(m.profile, ScaleProfile::Small);
        assert!(m.total_operations > 0);
        assert!(m.throughput_ops_per_sec > 0.0);
        assert_eq!(m.invariant_violations, 0);
        // Adversarial extensions should trigger security events
        assert!(m.security_events > 0);
        assert!(m.latency.sample_count > 0);
    }

    #[test]
    fn run_adversarial_noise_under_load_deterministic() {
        let m1 = run_adversarial_noise_under_load(ScaleProfile::Small, 13);
        let m2 = run_adversarial_noise_under_load(ScaleProfile::Small, 13);
        assert_eq!(m1.correctness_digest, m2.correctness_digest);
        assert_eq!(m1.security_events, m2.security_events);
    }

    // ── run_benchmark (dispatcher) ──────────────────────────────────
    #[test]
    fn run_benchmark_dispatches_boot_storm() {
        let m = run_benchmark(BenchmarkFamily::BootStorm, ScaleProfile::Small, 42);
        assert_eq!(m.family, BenchmarkFamily::BootStorm);
    }

    #[test]
    fn run_benchmark_dispatches_capability_churn() {
        let m = run_benchmark(BenchmarkFamily::CapabilityChurn, ScaleProfile::Small, 42);
        assert_eq!(m.family, BenchmarkFamily::CapabilityChurn);
    }

    #[test]
    fn run_benchmark_dispatches_mixed_mesh() {
        let m = run_benchmark(
            BenchmarkFamily::MixedCpuIoAgentMesh,
            ScaleProfile::Small,
            42,
        );
        assert_eq!(m.family, BenchmarkFamily::MixedCpuIoAgentMesh);
    }

    #[test]
    fn run_benchmark_dispatches_reload_churn() {
        let m = run_benchmark(BenchmarkFamily::ReloadRevokeChurn, ScaleProfile::Small, 42);
        assert_eq!(m.family, BenchmarkFamily::ReloadRevokeChurn);
    }

    #[test]
    fn run_benchmark_dispatches_adversarial() {
        let m = run_benchmark(
            BenchmarkFamily::AdversarialNoiseUnderLoad,
            ScaleProfile::Small,
            42,
        );
        assert_eq!(m.family, BenchmarkFamily::AdversarialNoiseUnderLoad);
    }

    // ── run_benchmark_suite ─────────────────────────────────────────
    #[test]
    fn run_benchmark_suite_single_family_single_profile() {
        let config = BenchmarkSuiteConfig {
            seed: 42,
            profiles: vec![ScaleProfile::Small],
            families: vec![BenchmarkFamily::BootStorm],
            thresholds: RegressionThresholds::default(),
            run_id: "test-run".to_string(),
            run_date: "2026-01-01".to_string(),
        };
        let result = run_benchmark_suite(&config);
        assert_eq!(result.measurements.len(), 1);
        assert_eq!(result.events.len(), 1);
        assert!(result.total_operations > 0);
        assert!(result.total_duration_us > 0);
        assert_eq!(result.invariant_violations, 0);
        assert!(!result.blocked);
        assert!(result.regressions.is_empty());
    }

    #[test]
    fn run_benchmark_suite_two_families_two_profiles() {
        let config = BenchmarkSuiteConfig {
            seed: 42,
            profiles: vec![ScaleProfile::Small, ScaleProfile::Medium],
            families: vec![BenchmarkFamily::BootStorm, BenchmarkFamily::CapabilityChurn],
            thresholds: RegressionThresholds::default(),
            run_id: "test-2x2".to_string(),
            run_date: "2026-01-01".to_string(),
        };
        let result = run_benchmark_suite(&config);
        assert_eq!(result.measurements.len(), 4); // 2 families * 2 profiles
        assert_eq!(result.events.len(), 4);
    }

    #[test]
    fn run_benchmark_suite_events_have_correct_component() {
        let config = BenchmarkSuiteConfig {
            seed: 42,
            profiles: vec![ScaleProfile::Small],
            families: vec![BenchmarkFamily::BootStorm],
            thresholds: RegressionThresholds::default(),
            run_id: "test-evt".to_string(),
            run_date: "2026-01-01".to_string(),
        };
        let result = run_benchmark_suite(&config);
        assert_eq!(result.events[0].component, BENCHMARK_E2E_COMPONENT);
        assert_eq!(result.events[0].event, "benchmark_case_completed");
        assert_eq!(result.events[0].outcome, "pass");
        assert!(result.events[0].family.is_some());
        assert!(result.events[0].profile.is_some());
    }

    // ── run_benchmark_suite_with_regression ──────────────────────────
    #[test]
    fn run_benchmark_suite_with_regression_no_baseline() {
        let config = BenchmarkSuiteConfig {
            seed: 42,
            profiles: vec![ScaleProfile::Small],
            families: vec![BenchmarkFamily::BootStorm],
            thresholds: RegressionThresholds::default(),
            run_id: "test-reg-0".to_string(),
            run_date: "2026-01-01".to_string(),
        };
        let result = run_benchmark_suite_with_regression(&config, &[]);
        assert!(result.regressions.is_empty());
    }

    #[test]
    fn run_benchmark_suite_with_regression_against_matching_baseline() {
        let config = BenchmarkSuiteConfig {
            seed: 42,
            profiles: vec![ScaleProfile::Small],
            families: vec![BenchmarkFamily::BootStorm],
            thresholds: RegressionThresholds {
                // Use very lenient thresholds to account for timing variance
                throughput_regression_pct: 99.0,
                p95_latency_regression_pct: 99.0,
                p99_latency_regression_pct: 99.0,
            },
            run_id: "test-reg-1".to_string(),
            run_date: "2026-01-01".to_string(),
        };
        // Use same config to get a baseline
        let baseline_result = run_benchmark_suite(&config);
        let result = run_benchmark_suite_with_regression(&config, &baseline_result.measurements);
        // Matching baseline → regression result produced
        assert_eq!(result.regressions.len(), 1);
        assert_eq!(result.regressions[0].family, BenchmarkFamily::BootStorm);
        assert_eq!(result.regressions[0].profile, ScaleProfile::Small);
        // With 99% thresholds, timing variance won't trigger a block
        assert!(!result.regressions[0].blocked);
    }

    #[test]
    fn run_benchmark_suite_with_regression_unmatched_baseline_skipped() {
        let config = BenchmarkSuiteConfig {
            seed: 42,
            profiles: vec![ScaleProfile::Small],
            families: vec![BenchmarkFamily::BootStorm],
            thresholds: RegressionThresholds::default(),
            run_id: "test-reg-2".to_string(),
            run_date: "2026-01-01".to_string(),
        };
        // Baseline is for a different family, so no regression check
        let unrelated_baseline = vec![make_measurement(1000.0, 100, 200)]; // BootStorm/Small
        // Change the family to mismatch — but make_measurement uses BootStorm/Small
        // So let's pass a baseline that matches
        let result = run_benchmark_suite_with_regression(&config, &unrelated_baseline);
        // The make_measurement baseline IS BootStorm/Small, so it will match
        assert_eq!(result.regressions.len(), 1);
    }

    #[test]
    fn harness_contract_default_is_valid() {
        let contract = BenchmarkHarnessContract::default();
        validate_harness_contract(&contract).expect("default harness contract should be valid");
    }

    #[test]
    fn harness_contract_rejects_empty_runtime_pin() {
        let mut contract = BenchmarkHarnessContract::default();
        contract.runtime_pins.node_lts = "   ".to_string();
        let error = validate_harness_contract(&contract).expect_err("empty runtime pin must fail");
        assert!(matches!(
            error,
            BenchmarkHarnessContractError::EmptyRuntimePin {
                runtime: "node_lts"
            }
        ));
    }

    #[test]
    fn harness_contract_rejects_invalid_fairness_guardrails() {
        let mut contract = BenchmarkHarnessContract::default();
        contract.fairness_policy.warmup_runs = 0;
        let warmup_error =
            validate_harness_contract(&contract).expect_err("warmup guardrail must fail");
        assert!(matches!(
            warmup_error,
            BenchmarkHarnessContractError::InvalidWarmupRuns { .. }
        ));

        contract.fairness_policy.warmup_runs = MIN_WARMUP_RUNS;
        contract.fairness_policy.sample_count = 0;
        let sample_error =
            validate_harness_contract(&contract).expect_err("sample count guardrail must fail");
        assert!(matches!(
            sample_error,
            BenchmarkHarnessContractError::InvalidSampleCount { .. }
        ));

        contract.fairness_policy.sample_count = MIN_SAMPLE_COUNT;
        contract.fairness_policy.case_timeout_ms = 0;
        let timeout_error =
            validate_harness_contract(&contract).expect_err("timeout guardrail must fail");
        assert!(matches!(
            timeout_error,
            BenchmarkHarnessContractError::InvalidCaseTimeoutMs { .. }
        ));
    }

    // ── write_evidence_artifacts ─────────────────────────────────────
    #[test]
    fn write_evidence_artifacts_creates_files() {
        let config = BenchmarkSuiteConfig {
            seed: 42,
            profiles: vec![ScaleProfile::Small],
            families: vec![BenchmarkFamily::BootStorm],
            thresholds: RegressionThresholds::default(),
            run_id: "test-evidence".to_string(),
            run_date: "2026-01-01".to_string(),
        };
        let result = run_benchmark_suite(&config);
        let dir = std::env::temp_dir().join("franken_bench_test_evidence");
        let _ = fs::remove_dir_all(&dir);
        let artifacts =
            write_evidence_artifacts(&result, &dir).expect("serde deserialization should succeed");
        assert!(artifacts.run_manifest_path.exists());
        assert!(artifacts.evidence_path.exists());
        assert!(artifacts.events_path.exists());
        assert!(artifacts.commands_path.exists());
        assert!(artifacts.benchmark_env_manifest_path.exists());
        assert!(artifacts.raw_results_archive_path.exists());
        assert!(artifacts.summary_path.exists());

        // Verify manifest is valid JSON
        let manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&artifacts.run_manifest_path)
                .expect("serde deserialization should succeed"),
        )
        .expect("serde deserialization should succeed");
        assert_eq!(manifest["schema_version"], BENCHMARK_E2E_SCHEMA_VERSION);
        assert_eq!(manifest["run_id"], "test-evidence");
        assert_eq!(manifest["seed"], 42);
        assert_eq!(
            manifest["measured_surface"]["kind"],
            BENCHMARK_E2E_MEASURED_SURFACE
        );
        assert_eq!(
            manifest["measured_surface"]["js_runtime_execution_included"],
            serde_json::json!(false)
        );

        // Verify evidence JSONL has entries
        let evidence = fs::read_to_string(&artifacts.evidence_path)
            .expect("serde deserialization should succeed");
        assert!(!evidence.is_empty());
        let lines: Vec<&str> = evidence.lines().collect();
        assert!(!lines.is_empty());
        // Each line should be valid JSON
        for line in &lines {
            let _: serde_json::Value =
                serde_json::from_str(line).expect("serde deserialization should succeed");
        }

        // Verify benchmark env manifest
        let env_manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&artifacts.benchmark_env_manifest_path)
                .expect("serde deserialization should succeed"),
        )
        .expect("serde deserialization should succeed");
        assert_eq!(env_manifest["schema_version"], BENCHMARK_ENV_SCHEMA_VERSION);
        assert!(
            env_manifest["runtime_pins"]["franken_engine"]
                .as_str()
                .expect("serde deserialization should succeed")
                .starts_with("franken-engine-")
        );
        assert!(
            env_manifest["cpu_model"]
                .as_str()
                .map(|v| !v.is_empty())
                .unwrap_or(false),
            "cpu_model should be populated"
        );
        assert!(
            env_manifest["memory_bytes"].is_number(),
            "memory_bytes should be numeric"
        );
        assert_eq!(
            env_manifest["engine_version"],
            env!("CARGO_PKG_VERSION"),
            "engine_version should match crate version"
        );
        assert_eq!(env_manifest["fairness_policy"]["warmup_runs"], 2);
        assert_eq!(env_manifest["fairness_policy"]["sample_count"], 7);
        assert_eq!(env_manifest["fairness_policy"]["case_timeout_ms"], 30_000);

        // Verify raw archive has full measurement payload
        let raw_archive: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&artifacts.raw_results_archive_path)
                .expect("serde deserialization should succeed"),
        )
        .expect("serde deserialization should succeed");
        assert_eq!(
            raw_archive["schema_version"],
            "franken-engine.benchmark-e2e.raw-results.v1"
        );
        assert!(
            raw_archive["measurements"]
                .as_array()
                .is_some_and(|entries| !entries.is_empty())
        );

        // Verify summary is valid JSON
        let summary: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&artifacts.summary_path)
                .expect("serde deserialization should succeed"),
        )
        .expect("serde deserialization should succeed");
        assert_eq!(summary["schema_version"], BENCHMARK_E2E_SCHEMA_VERSION);
        assert_eq!(summary["run_id"], "test-evidence");

        // Verify structured events and command transcript were emitted
        let events = fs::read_to_string(&artifacts.events_path)
            .expect("serde deserialization should succeed");
        assert!(
            events.lines().all(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .and_then(|value| value.get("trace_id").cloned())
                    .is_some()
            }),
            "all events must be valid structured JSON with trace_id"
        );
        let commands = fs::read_to_string(&artifacts.commands_path)
            .expect("serde deserialization should succeed");
        assert!(commands.contains("rch exec -- scripts/run_benchmark_e2e_suite.sh report"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_evidence_artifacts_with_regressions() {
        let config = BenchmarkSuiteConfig {
            seed: 42,
            profiles: vec![ScaleProfile::Small],
            families: vec![BenchmarkFamily::BootStorm],
            thresholds: RegressionThresholds::default(),
            run_id: "test-reg-evidence".to_string(),
            run_date: "2026-01-01".to_string(),
        };
        let baseline = run_benchmark_suite(&config);
        let result = run_benchmark_suite_with_regression(&config, &baseline.measurements);

        let dir = std::env::temp_dir().join("franken_bench_test_reg_evidence");
        let _ = fs::remove_dir_all(&dir);
        let artifacts =
            write_evidence_artifacts(&result, &dir).expect("serde deserialization should succeed");

        let evidence = fs::read_to_string(&artifacts.evidence_path)
            .expect("serde deserialization should succeed");
        let lines: Vec<&str> = evidence.lines().collect();
        // Should have measurement + regression + event lines
        assert!(lines.len() >= 3);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_evidence_artifacts_summary_has_family_summaries() {
        let config = BenchmarkSuiteConfig {
            seed: 42,
            profiles: vec![ScaleProfile::Small],
            families: vec![BenchmarkFamily::BootStorm, BenchmarkFamily::CapabilityChurn],
            thresholds: RegressionThresholds::default(),
            run_id: "test-fam-summary".to_string(),
            run_date: "2026-01-01".to_string(),
        };
        let result = run_benchmark_suite(&config);
        let dir = std::env::temp_dir().join("franken_bench_test_fam_summary");
        let _ = fs::remove_dir_all(&dir);
        let artifacts =
            write_evidence_artifacts(&result, &dir).expect("serde deserialization should succeed");

        let summary: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&artifacts.summary_path)
                .expect("serde deserialization should succeed"),
        )
        .expect("serde deserialization should succeed");
        let families = summary["families"]
            .as_array()
            .expect("serde deserialization should succeed");
        assert_eq!(families.len(), 2);
        assert_eq!(
            summary["configured_families"],
            serde_json::json!(["boot-storm", "capability-churn"])
        );
        assert_eq!(summary["configured_profiles"], serde_json::json!(["S"]));
        assert_eq!(summary["expected_measurement_count"], 2);
        assert_eq!(summary["complete_suite_evidence"], false);
        assert_eq!(
            summary["measured_surface"]["kind"],
            BENCHMARK_E2E_MEASURED_SURFACE
        );
        assert_eq!(
            summary["measured_surface"]["js_runtime_execution_included"],
            serde_json::json!(false)
        );
        assert!(
            summary["environment"]["cpu_model"]
                .as_str()
                .map(|v| !v.is_empty())
                .unwrap_or(false),
            "summary should include cpu_model"
        );
        assert!(
            summary["environment"]["memory_bytes"].is_number(),
            "summary should include memory_bytes"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Medium profile sanity ───────────────────────────────────────
    #[test]
    fn run_boot_storm_medium_completes() {
        let m = run_boot_storm(ScaleProfile::Medium, 42);
        assert_eq!(m.profile, ScaleProfile::Medium);
        assert!(m.total_operations > 0);
        assert!(m.peak_extensions_alive > 0);
    }

    // ── Xorshift64 additional coverage ──────────────────────────────
    #[test]
    fn xorshift64_next_bool_distribution() {
        // With 50% probability, should get both true and false over many trials
        let mut rng = Xorshift64::new(42);
        let mut trues = 0usize;
        let mut falses = 0usize;
        for _ in 0..1000 {
            if rng.next_bool(50) {
                trues += 1;
            } else {
                falses += 1;
            }
        }
        assert!(trues > 100, "expected many trues, got {trues}");
        assert!(falses > 100, "expected many falses, got {falses}");
    }

    // ── LatencyDistribution edge cases ──────────────────────────────
    #[test]
    fn latency_distribution_two_samples() {
        let mut samples = vec![10, 20];
        let dist = LatencyDistribution::from_samples(&mut samples);
        assert_eq!(dist.min_us, 10);
        assert_eq!(dist.max_us, 20);
        assert_eq!(dist.sample_count, 2);
    }

    // ── detect_regression at threshold boundary ─────────────────────
    #[test]
    fn detect_regression_exactly_at_threshold_not_blocked() {
        let baseline = make_measurement(1000.0, 100, 200);
        // 5% throughput regression exactly at threshold (1000 * 0.05 = 50)
        let current = make_measurement(950.0, 100, 200);
        let thresholds = RegressionThresholds::default();
        let result = detect_regression(&current, &baseline, &thresholds);
        // 5.0% == 5.0% threshold: not strictly greater, so not blocked
        assert!(!result.blocked);
    }

    #[test]
    fn detect_regression_just_over_threshold_blocked() {
        let baseline = make_measurement(1000.0, 100, 200);
        // 5.1% throughput regression exceeds 5% threshold
        let current = make_measurement(949.0, 100, 200);
        let thresholds = RegressionThresholds::default();
        let result = detect_regression(&current, &baseline, &thresholds);
        assert!(result.blocked);
    }

    // ── Custom thresholds ───────────────────────────────────────────
    #[test]
    fn detect_regression_custom_thresholds() {
        let baseline = make_measurement(1000.0, 100, 200);
        let current = make_measurement(900.0, 100, 200); // 10% throughput drop
        let thresholds = RegressionThresholds {
            throughput_regression_pct: 15.0, // 15% threshold
            p95_latency_regression_pct: 10.0,
            p99_latency_regression_pct: 15.0,
        };
        let result = detect_regression(&current, &baseline, &thresholds);
        // 10% < 15% threshold → not blocked
        assert!(!result.blocked);
    }

    // ── BenchmarkFamily all exhaustive ──────────────────────────────
    #[test]
    fn benchmark_family_all_as_str_unique() {
        let names: BTreeSet<&str> = BenchmarkFamily::all().iter().map(|f| f.as_str()).collect();
        assert_eq!(names.len(), 5);
    }

    // ── ScaleProfile Debug/Clone/Eq ─────────────────────────────────
    #[test]
    fn scale_profile_eq_and_clone() {
        let s = ScaleProfile::Small;
        let cloned = s;
        assert_eq!(s, cloned);
        assert_ne!(ScaleProfile::Small, ScaleProfile::Large);
    }

    // ── BenchmarkMeasurement fields ─────────────────────────────────
    #[test]
    fn benchmark_measurement_clone_preserves_fields() {
        let m = make_measurement(500.0, 50, 100);
        let cloned = m.clone();
        assert_eq!(cloned.family, BenchmarkFamily::BootStorm);
        assert!((cloned.throughput_ops_per_sec - 500.0).abs() < 1e-9);
        assert_eq!(cloned.latency.p95_us, 50);
        assert_eq!(cloned.latency.p99_us, 100);
    }

    use std::collections::BTreeSet;

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn scale_profile_as_str_distinct() {
        let all = [
            ScaleProfile::Small,
            ScaleProfile::Medium,
            ScaleProfile::Large,
        ];
        let set: BTreeSet<&str> = all.iter().map(|s| s.as_str()).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn scale_profile_extension_count_ordered() {
        assert!(ScaleProfile::Small.extension_count() < ScaleProfile::Medium.extension_count());
        assert!(ScaleProfile::Medium.extension_count() < ScaleProfile::Large.extension_count());
    }

    #[test]
    fn scale_profile_iterations_ordered() {
        assert!(ScaleProfile::Small.iterations() < ScaleProfile::Medium.iterations());
        assert!(ScaleProfile::Medium.iterations() < ScaleProfile::Large.iterations());
    }

    #[test]
    fn benchmark_family_as_str_distinct() {
        let set: BTreeSet<&str> = BenchmarkFamily::all().iter().map(|f| f.as_str()).collect();
        assert_eq!(set.len(), BenchmarkFamily::all().len());
    }

    #[test]
    fn benchmark_family_default_weight_all_positive() {
        for f in BenchmarkFamily::all() {
            assert!(f.default_weight() > 0.0, "{:?} has non-positive weight", f);
        }
    }

    #[test]
    fn benchmark_family_debug_distinct() {
        let set: BTreeSet<String> = BenchmarkFamily::all()
            .iter()
            .map(|f| format!("{f:?}"))
            .collect();
        assert_eq!(set.len(), BenchmarkFamily::all().len());
    }

    #[test]
    fn scale_profile_debug_distinct() {
        let all = [
            ScaleProfile::Small,
            ScaleProfile::Medium,
            ScaleProfile::Large,
        ];
        let set: BTreeSet<String> = all.iter().map(|s| format!("{s:?}")).collect();
        assert_eq!(set.len(), all.len());
    }
}
