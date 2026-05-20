//! Profiling infrastructure for FrankenEngine baseline interpreter.
//!
//! Provides hotspot identification, instruction frequency counting, and
//! memory allocation profiling to inform optimization targeting.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::ir_contract::Ir3Instruction;

/// Profiling configuration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilingConfig {
    /// Whether instruction frequency counting is enabled.
    pub enable_instruction_profiling: bool,
    /// Whether interpreter hotspot timing is enabled.
    pub enable_hotspot_profiling: bool,
    /// Whether memory allocation tracking is enabled.
    pub enable_memory_profiling: bool,
    /// Whether to collect call stack samples.
    pub enable_call_stack_profiling: bool,
    /// Sampling interval for hotspot profiling (every N instructions).
    pub hotspot_sampling_interval: u64,
}

impl Default for ProfilingConfig {
    fn default() -> Self {
        Self {
            enable_instruction_profiling: true,
            enable_hotspot_profiling: true,
            enable_memory_profiling: true,
            enable_call_stack_profiling: false, // Can be expensive
            hotspot_sampling_interval: 1000,    // Sample every 1000 instructions
        }
    }
}

/// Statistics for a single instruction type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionStats {
    /// Number of times this instruction was executed.
    pub count: u64,
    /// Total time spent executing this instruction (in nanoseconds).
    pub total_time_ns: u64,
    /// Average time per execution (in nanoseconds).
    pub average_time_ns: u64,
}

/// Memory allocation statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    /// Number of objects allocated.
    pub objects_allocated: u64,
    /// Number of arrays allocated.
    pub arrays_allocated: u64,
    /// Total bytes allocated.
    pub total_bytes_allocated: u64,
    /// Number of garbage collection cycles.
    pub gc_cycles: u64,
    /// Time spent in garbage collection (in nanoseconds).
    pub gc_time_ns: u64,
}

/// Hotspot information for optimization targeting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotInfo {
    /// Human-readable name of the hotspot.
    pub name: String,
    /// Percentage of total execution time.
    pub time_percentage: f64,
    /// Number of times this hotspot was hit.
    pub hit_count: u64,
    /// Average time per hit (in nanoseconds).
    pub average_time_ns: u64,
    /// Optimization recommendation.
    pub recommendation: String,
}

/// Complete profiling report for a benchmark or execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilingReport {
    /// Name of the benchmark or test.
    pub benchmark_name: String,
    /// Total execution time (in nanoseconds).
    pub total_execution_time_ns: u64,
    /// Instruction execution statistics.
    pub instruction_stats: BTreeMap<String, InstructionStats>,
    /// Memory allocation statistics.
    pub memory_stats: MemoryStats,
    /// Top hotspots for optimization.
    pub hotspots: Vec<HotspotInfo>,
    /// Configuration used for this profiling run.
    pub config: ProfilingConfig,
}

/// Profiler state for collecting execution statistics.
#[derive(Debug)]
pub struct Profiler {
    config: ProfilingConfig,
    instruction_counts: BTreeMap<String, u64>,
    instruction_times: BTreeMap<String, Duration>,
    memory_stats: MemoryStats,
    start_time: Instant,
    /// Wall-clock instant of the most recent hotspot sample, or the profiler's
    /// `start_time` if no sample has been taken yet. Advanced inside
    /// `record_instruction` once `hotspot_sampling_interval` instructions have
    /// been observed since the previous sample (or the start of the run).
    last_sample_time: Instant,
    /// Number of hotspot-sample boundaries crossed during this run.
    sample_count: u64,
    instruction_counter: u64,
}

impl Profiler {
    /// Create a new profiler with the given configuration.
    pub fn new(config: ProfilingConfig) -> Self {
        let now = Instant::now();
        Self {
            config,
            instruction_counts: BTreeMap::new(),
            instruction_times: BTreeMap::new(),
            memory_stats: MemoryStats {
                objects_allocated: 0,
                arrays_allocated: 0,
                total_bytes_allocated: 0,
                gc_cycles: 0,
                gc_time_ns: 0,
            },
            start_time: now,
            last_sample_time: now,
            sample_count: 0,
            instruction_counter: 0,
        }
    }

    /// Record execution of an instruction.
    pub fn record_instruction(&mut self, instruction: &Ir3Instruction) {
        if !self.config.enable_instruction_profiling {
            return;
        }

        let name = instruction_name(instruction);
        *self.instruction_counts.entry(name).or_insert(0) += 1;
        self.instruction_counter += 1;

        // Hotspot sampling tick: when hotspot profiling is on and the
        // configured interval has elapsed (in instructions), advance
        // `last_sample_time`. Callers can observe sampling activity via
        // `sample_count()` / `last_sample_time()` / `time_since_last_sample()`.
        if self.config.enable_hotspot_profiling
            && self.config.hotspot_sampling_interval > 0
            && self
                .instruction_counter
                .is_multiple_of(self.config.hotspot_sampling_interval)
        {
            self.last_sample_time = Instant::now();
            self.sample_count = self.sample_count.saturating_add(1);
        }
    }

    /// Wall-clock instant of the most recent hotspot sample tick. Returns the
    /// profiler's start time when no sample has been taken yet.
    pub fn last_sample_time(&self) -> Instant {
        self.last_sample_time
    }

    /// Number of hotspot-sample boundaries crossed since `new`. Zero if
    /// hotspot profiling is disabled, the configured interval is zero, or
    /// fewer than `hotspot_sampling_interval` instructions have been recorded.
    pub fn sample_count(&self) -> u64 {
        self.sample_count
    }

    /// Elapsed wall-clock duration since the most recent hotspot sample tick.
    pub fn time_since_last_sample(&self) -> Duration {
        self.last_sample_time.elapsed()
    }

    /// Record timing for an instruction execution.
    pub fn record_instruction_time(&mut self, instruction: &Ir3Instruction, duration: Duration) {
        if !self.config.enable_hotspot_profiling {
            return;
        }

        let name = instruction_name(instruction);
        *self.instruction_times.entry(name).or_insert(Duration::ZERO) += duration;
    }

    /// Record object allocation.
    pub fn record_object_allocation(&mut self, size_bytes: u64) {
        if !self.config.enable_memory_profiling {
            return;
        }

        self.memory_stats.objects_allocated += 1;
        self.memory_stats.total_bytes_allocated += size_bytes;
    }

    /// Record array allocation.
    pub fn record_array_allocation(&mut self, size_bytes: u64) {
        if !self.config.enable_memory_profiling {
            return;
        }

        self.memory_stats.arrays_allocated += 1;
        self.memory_stats.total_bytes_allocated += size_bytes;
    }

    /// Record garbage collection.
    pub fn record_gc_cycle(&mut self, duration: Duration) {
        if !self.config.enable_memory_profiling {
            return;
        }

        self.memory_stats.gc_cycles += 1;
        self.memory_stats.gc_time_ns += duration.as_nanos() as u64;
    }

    /// Generate a profiling report.
    pub fn generate_report(&self, benchmark_name: String) -> ProfilingReport {
        let total_execution_time = self.start_time.elapsed();
        let total_execution_time_ns = total_execution_time.as_nanos() as u64;

        // Convert instruction counts and times to stats
        let mut instruction_stats = BTreeMap::new();
        for (name, &count) in &self.instruction_counts {
            let total_time = self
                .instruction_times
                .get(name)
                .copied()
                .unwrap_or(Duration::ZERO);
            let total_time_ns = total_time.as_nanos() as u64;
            let average_time_ns = total_time_ns.checked_div(count).unwrap_or(0);

            instruction_stats.insert(
                name.clone(),
                InstructionStats {
                    count,
                    total_time_ns,
                    average_time_ns,
                },
            );
        }

        // Generate hotspots (top 10 by total time)
        let mut hotspots = Vec::new();
        let mut instruction_times_vec: Vec<_> = self.instruction_times.iter().collect();
        instruction_times_vec.sort_by(|a, b| b.1.cmp(a.1)); // Sort by time descending

        for (name, total_time) in instruction_times_vec.iter().take(10) {
            let total_time_ns = total_time.as_nanos() as u64;
            let count = self.instruction_counts.get(*name).copied().unwrap_or(0);
            let time_percentage = if total_execution_time_ns > 0 {
                (total_time_ns as f64 / total_execution_time_ns as f64) * 100.0
            } else {
                0.0
            };
            let average_time_ns = total_time_ns.checked_div(count).unwrap_or(0);

            let recommendation = if time_percentage > 5.0 {
                "High-priority optimization target".to_string()
            } else if time_percentage > 1.0 {
                "Medium-priority optimization target".to_string()
            } else {
                "Low-priority optimization target".to_string()
            };

            hotspots.push(HotspotInfo {
                name: (*name).clone(),
                time_percentage,
                hit_count: count,
                average_time_ns,
                recommendation,
            });
        }

        ProfilingReport {
            benchmark_name,
            total_execution_time_ns,
            instruction_stats,
            memory_stats: self.memory_stats.clone(),
            hotspots,
            config: self.config.clone(),
        }
    }
}

/// Get a human-readable name for an instruction.
pub fn instruction_name(instruction: &Ir3Instruction) -> String {
    // Use Debug formatting to extract instruction name
    let debug_str = format!("{:?}", instruction);
    if let Some(brace_pos) = debug_str.find(" {") {
        debug_str[..brace_pos].to_string()
    } else if let Some(brace_pos) = debug_str.find("(") {
        debug_str[..brace_pos].to_string()
    } else {
        debug_str
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profiler_instruction_counting() {
        let config = ProfilingConfig::default();
        let mut profiler = Profiler::new(config);

        let load_int = Ir3Instruction::LoadInt { dst: 0, value: 42 };
        let add = Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        };

        profiler.record_instruction(&load_int);
        profiler.record_instruction(&add);
        profiler.record_instruction(&load_int);

        let report = profiler.generate_report("test".to_string());
        assert_eq!(
            report
                .instruction_stats
                .get("LoadInt")
                .expect("serde deserialization should succeed")
                .count,
            2
        );
        assert_eq!(
            report
                .instruction_stats
                .get("Add")
                .expect("serde deserialization should succeed")
                .count,
            1
        );
    }

    #[test]
    fn test_profiler_memory_tracking() {
        let config = ProfilingConfig::default();
        let mut profiler = Profiler::new(config);

        profiler.record_object_allocation(100);
        profiler.record_array_allocation(200);
        profiler.record_gc_cycle(Duration::from_millis(5));

        let report = profiler.generate_report("memory_test".to_string());
        assert_eq!(report.memory_stats.objects_allocated, 1);
        assert_eq!(report.memory_stats.arrays_allocated, 1);
        assert_eq!(report.memory_stats.total_bytes_allocated, 300);
        assert_eq!(report.memory_stats.gc_cycles, 1);
    }

    #[test]
    fn test_instruction_name_extraction() {
        let load_int = Ir3Instruction::LoadInt { dst: 0, value: 42 };
        assert_eq!(instruction_name(&load_int), "LoadInt");

        let add = Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        };
        assert_eq!(instruction_name(&add), "Add");
    }

    // bd-y9jj9: hotspot sampling was previously a vestigial config knob —
    // `last_sample_time` was initialized but never updated and the
    // `hotspot_sampling_interval` field gated nothing. record_instruction
    // now advances the sample tick once every N instructions while hotspot
    // profiling is enabled.

    #[test]
    fn hotspot_sampling_ticks_at_configured_interval() {
        let config = ProfilingConfig {
            hotspot_sampling_interval: 4,
            ..Default::default()
        };
        let mut profiler = Profiler::new(config);
        assert_eq!(profiler.sample_count(), 0);

        let load_int = Ir3Instruction::LoadInt { dst: 0, value: 1 };
        // 3 instructions: still below the interval, no sample yet.
        for _ in 0..3 {
            profiler.record_instruction(&load_int);
        }
        assert_eq!(profiler.sample_count(), 0);

        // 4th instruction crosses the boundary — exactly one sample.
        profiler.record_instruction(&load_int);
        assert_eq!(profiler.sample_count(), 1);

        // 4 more instructions → second sample.
        for _ in 0..4 {
            profiler.record_instruction(&load_int);
        }
        assert_eq!(profiler.sample_count(), 2);
    }

    #[test]
    fn hotspot_sampling_inactive_when_disabled() {
        let config = ProfilingConfig {
            enable_hotspot_profiling: false,
            hotspot_sampling_interval: 1, // would otherwise tick every instruction
            ..Default::default()
        };
        let mut profiler = Profiler::new(config);

        let load_int = Ir3Instruction::LoadInt { dst: 0, value: 1 };
        for _ in 0..10 {
            profiler.record_instruction(&load_int);
        }
        assert_eq!(profiler.sample_count(), 0);
    }

    #[test]
    fn hotspot_sampling_inactive_when_interval_zero() {
        // A zero interval is a misconfiguration — silently treating it as
        // "sample never" is more useful than dividing-by-zero or sampling
        // every instruction.
        let config = ProfilingConfig {
            hotspot_sampling_interval: 0,
            ..Default::default()
        };
        let mut profiler = Profiler::new(config);

        let load_int = Ir3Instruction::LoadInt { dst: 0, value: 1 };
        for _ in 0..10 {
            profiler.record_instruction(&load_int);
        }
        assert_eq!(profiler.sample_count(), 0);
    }

    #[test]
    fn last_sample_time_advances_with_samples() {
        let config = ProfilingConfig {
            hotspot_sampling_interval: 1, // sample every instruction
            ..Default::default()
        };
        let mut profiler = Profiler::new(config);
        let before = profiler.last_sample_time();

        // Burn a small amount of wall time then take a sample.
        std::thread::sleep(Duration::from_millis(2));
        let load_int = Ir3Instruction::LoadInt { dst: 0, value: 1 };
        profiler.record_instruction(&load_int);

        let after = profiler.last_sample_time();
        assert!(
            after > before,
            "last_sample_time must advance when a sample is taken"
        );
    }
}
