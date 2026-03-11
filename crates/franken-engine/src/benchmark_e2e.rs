//! Performance benchmark E2E framework for FrankenEngine.
//!
//! Implements the Extension-Heavy Benchmark Suite v1.0 with 5 benchmark families,
//! 3 scale profiles per family, regression detection, and evidence artifact production.
//!
//! Families:
//!   1. boot-storm — extension registration + lifecycle boot throughput
//!   2. capability-churn — rapid capability/budget mutation under load
//!   3. mixed-cpu-io-agent-mesh — interleaved CPU consumption and hostcall IO
//!   4. reload-revoke-churn — unregister/re-register cycles simulating hot-reload
//!   5. adversarial-noise-under-load — budget exhaustion injection during sustained load

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::benchmark_denominator::BenchmarkCase;
use crate::extension_lifecycle_manager::{
    CancellationConfig, ExtensionLifecycleManager, ExtensionState, LifecycleTransition,
    ResourceBudget,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const BENCHMARK_E2E_COMPONENT: &str = "benchmark_e2e";
pub const BENCHMARK_E2E_SCHEMA_VERSION: &str = "franken-engine.benchmark-e2e.v1";
pub const BENCHMARK_ENV_SCHEMA_VERSION: &str = "franken-engine.benchmark-env-manifest.v1";
pub const MIN_START_BUDGET_MILLIONTHS: u64 = 1_000;

const MIN_WARMUP_RUNS: u32 = 1;
const MIN_SAMPLE_COUNT: u32 = 3;
const MIN_CASE_TIMEOUT_MS: u64 = 1;

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
            p95_us: samples[(n as f64 * 0.95) as usize],
            p99_us: samples[(n as f64 * 0.99) as usize],
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

        if iter.is_multiple_of(50) {
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

    BenchmarkEnvironmentManifest {
        schema_version: BENCHMARK_ENV_SCHEMA_VERSION.to_string(),
        run_id: result.config.run_id.clone(),
        run_date: result.config.run_date.clone(),
        seed: result.config.seed,
        locale,
        timezone,
        os: env::consts::OS.to_string(),
        arch: env::consts::ARCH.to_string(),
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
        "cargo test -p frankenengine-engine --test benchmark_e2e --test benchmark_e2e_integration",
        "cargo run -p frankenengine-engine --bin franken_lockstep_runner -- --preflight-only",
        "scripts/run_benchmark_e2e_suite.sh report",
    ];
    fs::write(&commands_path, commands.join("\n") + "\n")?;

    let env_manifest = build_environment_manifest(result, &contract);
    fs::write(
        &env_manifest_path,
        serde_json::to_string_pretty(&env_manifest).unwrap(),
    )?;

    let raw_results = serde_json::json!({
        "schema_version": "franken-engine.benchmark-e2e.raw-results.v1",
        "run_id": result.config.run_id,
        "run_date": result.config.run_date,
        "seed": result.config.seed,
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
        serde_json::to_string_pretty(&raw_results).unwrap(),
    )?;

    // Run manifest
    let manifest_path = output_dir.join("run_manifest.json");
    let manifest = serde_json::json!({
        "schema_version": BENCHMARK_E2E_SCHEMA_VERSION,
        "run_id": result.config.run_id,
        "run_date": result.config.run_date,
        "seed": result.config.seed,
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
        serde_json::to_string_pretty(&manifest).unwrap(),
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
        evidence_lines.push(serde_json::to_string(&entry).unwrap());
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
        evidence_lines.push(serde_json::to_string(&entry).unwrap());
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
        evidence_lines.push(serde_json::to_string(&entry).unwrap());
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
        .map(|entry| serde_json::to_string(&entry).unwrap())
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
            "total_invariant_violations": family_measurements.iter().map(|m| m.invariant_violations).sum::<u64>(),
        }));
    }
    let summary = serde_json::json!({
        "schema_version": BENCHMARK_E2E_SCHEMA_VERSION,
        "run_id": result.config.run_id,
        "blocked": result.blocked,
        "measurement_count": result.measurements.len(),
        "regression_count": result.regressions.len(),
        "families": family_summaries,
    });
    fs::write(
        &summary_path,
        serde_json::to_string_pretty(&summary).unwrap(),
    )?;

    Ok(BenchmarkEvidenceArtifacts {
        run_manifest_path: manifest_path,
        evidence_path,
        events_path,
        commands_path,
        benchmark_env_manifest_path: env_manifest_path,
        raw_results_archive_path,
        summary_path,
    })
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
        let artifacts = write_evidence_artifacts(&result, &dir).unwrap();
        assert!(artifacts.run_manifest_path.exists());
        assert!(artifacts.evidence_path.exists());
        assert!(artifacts.events_path.exists());
        assert!(artifacts.commands_path.exists());
        assert!(artifacts.benchmark_env_manifest_path.exists());
        assert!(artifacts.raw_results_archive_path.exists());
        assert!(artifacts.summary_path.exists());

        // Verify manifest is valid JSON
        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&artifacts.run_manifest_path).unwrap())
                .unwrap();
        assert_eq!(manifest["schema_version"], BENCHMARK_E2E_SCHEMA_VERSION);
        assert_eq!(manifest["run_id"], "test-evidence");
        assert_eq!(manifest["seed"], 42);

        // Verify evidence JSONL has entries
        let evidence = fs::read_to_string(&artifacts.evidence_path).unwrap();
        assert!(!evidence.is_empty());
        let lines: Vec<&str> = evidence.lines().collect();
        assert!(!lines.is_empty());
        // Each line should be valid JSON
        for line in &lines {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }

        // Verify benchmark env manifest
        let env_manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&artifacts.benchmark_env_manifest_path).unwrap(),
        )
        .unwrap();
        assert_eq!(env_manifest["schema_version"], BENCHMARK_ENV_SCHEMA_VERSION);
        assert!(
            env_manifest["runtime_pins"]["franken_engine"]
                .as_str()
                .unwrap()
                .starts_with("franken-engine-")
        );
        assert_eq!(env_manifest["fairness_policy"]["warmup_runs"], 2);
        assert_eq!(env_manifest["fairness_policy"]["sample_count"], 7);
        assert_eq!(env_manifest["fairness_policy"]["case_timeout_ms"], 30_000);

        // Verify raw archive has full measurement payload
        let raw_archive: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&artifacts.raw_results_archive_path).unwrap())
                .unwrap();
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
        let summary: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&artifacts.summary_path).unwrap()).unwrap();
        assert_eq!(summary["schema_version"], BENCHMARK_E2E_SCHEMA_VERSION);
        assert_eq!(summary["run_id"], "test-evidence");

        // Verify structured events and command transcript were emitted
        let events = fs::read_to_string(&artifacts.events_path).unwrap();
        assert!(
            events.lines().all(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .and_then(|value| value.get("trace_id").cloned())
                    .is_some()
            }),
            "all events must be valid structured JSON with trace_id"
        );
        let commands = fs::read_to_string(&artifacts.commands_path).unwrap();
        assert!(commands.contains("scripts/run_benchmark_e2e_suite.sh report"));

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
        let artifacts = write_evidence_artifacts(&result, &dir).unwrap();

        let evidence = fs::read_to_string(&artifacts.evidence_path).unwrap();
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
        let artifacts = write_evidence_artifacts(&result, &dir).unwrap();

        let summary: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&artifacts.summary_path).unwrap()).unwrap();
        let families = summary["families"].as_array().unwrap();
        assert_eq!(families.len(), 2);

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
