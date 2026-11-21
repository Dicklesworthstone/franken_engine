//! Profiling infrastructure for FrankenEngine baseline interpreter.
//!
//! Provides hotspot identification, instruction frequency counting, and
//! memory allocation profiling to inform optimization targeting.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::ir_contract::Ir3Instruction;

mod opcode;

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
    /// Number of times this instruction was dispatched, including attempts
    /// that threw or ended execution.
    pub count: u64,
    /// Sum of recorded handler timing samples, in nanoseconds. Terminal or
    /// faulting dispatches without a handler-end sample still contribute to
    /// `count`, but not to this timing total.
    pub total_time_ns: u64,
    /// Recorded timing total divided by the dispatched instruction count.
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

// A single initialization-time allocation keeps the interpreter's optional
// profiler small. Opcode recording only updates this fixed-size table.
#[derive(Debug)]
struct OpcodeCounters {
    counts: [u64; opcode::NAMES.len()],
    times: [Option<Duration>; opcode::NAMES.len()],
}

/// Profiler state for collecting execution statistics.
#[derive(Debug)]
pub struct Profiler {
    config: ProfilingConfig,
    // Recording must not allocate, format operands, or compare string keys.
    // Preserve the distinction between an untimed opcode and a zero-time sample.
    opcodes: Box<OpcodeCounters>,
    memory_stats: MemoryStats,
    start_time: Instant,
    /// Wall-clock instant of the most recent hotspot sample, or the profiler's
    /// `start_time` if no sample has been taken yet. Advanced inside
    /// `record_instruction` once `hotspot_sampling_interval` instructions have
    /// been observed since the previous sample (or the start of the run).
    last_sample_time: Instant,
    /// Number of hotspot-sample boundaries crossed during this run.
    sample_count: u64,
    /// Zero disables sampling; otherwise count down to the next sample.
    instructions_until_sample: u64,
    /// Router reports retain a stable public handle while fresh interpreter
    /// cores collect locally. No shared lock is taken on the opcode hot path.
    completed_profiles: Option<Arc<Mutex<CompletedProfiles>>>,
}

#[derive(Debug)]
struct CompletedProfiles {
    profiler: Profiler,
    execution_time: Duration,
}

/// A router session's completion sink. Each core owns an ordinary dense
/// profiler and publishes it exactly once, including on a typed failure.
#[derive(Debug, Clone)]
pub(crate) struct ProfileCollector {
    config: ProfilingConfig,
    completed: Arc<Mutex<CompletedProfiles>>,
}

impl ProfileCollector {
    pub(crate) fn start_execution(&self) -> Profiler {
        Profiler::new(self.config.clone())
    }

    pub(crate) fn finish_execution(&self, profiler: Profiler) {
        let execution_time = profiler.start_time.elapsed();
        let mut completed = self
            .completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        completed.execution_time = completed.execution_time.saturating_add(execution_time);
        completed.profiler.merge_execution(&profiler);
    }
}

impl Profiler {
    /// Create a new profiler with the given configuration.
    pub fn new(config: ProfilingConfig) -> Self {
        let now = Instant::now();
        let instructions_until_sample = if config.enable_hotspot_profiling {
            config.hotspot_sampling_interval
        } else {
            0
        };
        Self {
            config,
            opcodes: Box::new(OpcodeCounters {
                counts: [0; opcode::NAMES.len()],
                times: [None; opcode::NAMES.len()],
            }),
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
            instructions_until_sample,
            completed_profiles: None,
        }
    }

    /// Keep the public borrowed-report API without sharing mutable opcode
    /// counters with worker threads. The collector's storage is bounded by
    /// the opcode set, regardless of the number of completed executions.
    pub(crate) fn router_session(config: ProfilingConfig) -> (Self, ProfileCollector) {
        let completed = Arc::new(Mutex::new(CompletedProfiles {
            profiler: Self::new(config.clone()),
            execution_time: Duration::ZERO,
        }));
        let collector = ProfileCollector {
            config: config.clone(),
            completed: Arc::clone(&completed),
        };
        let mut handle = Self::new(config);
        handle.completed_profiles = Some(completed);
        (handle, collector)
    }

    fn merge_execution(&mut self, execution: &Self) {
        for (total, count) in self.opcodes.counts.iter_mut().zip(execution.opcodes.counts) {
            *total = total.saturating_add(count);
        }
        for (total, time) in self.opcodes.times.iter_mut().zip(execution.opcodes.times) {
            if let Some(time) = time {
                let total = total.get_or_insert(Duration::ZERO);
                *total = total.saturating_add(time);
            }
        }
        let total = &mut self.memory_stats;
        let run = &execution.memory_stats;
        total.objects_allocated = total
            .objects_allocated
            .saturating_add(run.objects_allocated);
        total.arrays_allocated = total.arrays_allocated.saturating_add(run.arrays_allocated);
        total.total_bytes_allocated = total
            .total_bytes_allocated
            .saturating_add(run.total_bytes_allocated);
        total.gc_cycles = total.gc_cycles.saturating_add(run.gc_cycles);
        total.gc_time_ns = total.gc_time_ns.saturating_add(run.gc_time_ns);
        self.sample_count = self.sample_count.saturating_add(execution.sample_count);
        if execution.sample_count != 0 {
            self.last_sample_time = self.last_sample_time.max(execution.last_sample_time);
        }
    }

    /// Record one instruction dispatch, even if it later throws or terminates.
    #[inline]
    pub fn record_instruction(&mut self, instruction: &Ir3Instruction) {
        if !self.config.enable_instruction_profiling {
            return;
        }
        if let Some(completed) = &self.completed_profiles {
            completed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .profiler
                .record_instruction(instruction);
            return;
        }

        self.opcodes.counts[opcode::index(instruction)] += 1;

        // Preserve the bd-y9jj9 sample boundaries without variable division
        // on every opcode. Configuration is immutable after construction;
        // zero intervals and disabled hotspot profiling leave a zero countdown.
        if self.instructions_until_sample != 0 {
            self.instructions_until_sample -= 1;
            if self.instructions_until_sample == 0 {
                self.instructions_until_sample = self.config.hotspot_sampling_interval;
                self.last_sample_time = Instant::now();
                self.sample_count = self.sample_count.saturating_add(1);
            }
        }
    }

    /// Wall-clock instant of the most recent hotspot sample tick. Returns the
    /// profiler's start time when no sample has been taken yet.
    pub fn last_sample_time(&self) -> Instant {
        if let Some(completed) = &self.completed_profiles {
            return completed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .profiler
                .last_sample_time;
        }
        self.last_sample_time
    }

    /// Number of hotspot-sample boundaries crossed since `new`. Zero if
    /// hotspot profiling is disabled, the configured interval is zero, or
    /// fewer than `hotspot_sampling_interval` instructions have been recorded.
    pub fn sample_count(&self) -> u64 {
        if let Some(completed) = &self.completed_profiles {
            return completed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .profiler
                .sample_count;
        }
        self.sample_count
    }

    /// Elapsed wall-clock duration since the most recent hotspot sample tick.
    pub fn time_since_last_sample(&self) -> Duration {
        self.last_sample_time().elapsed()
    }

    /// Record timing for an instruction execution.
    pub fn record_instruction_time(&mut self, instruction: &Ir3Instruction, duration: Duration) {
        if !self.config.enable_hotspot_profiling {
            return;
        }
        if let Some(completed) = &self.completed_profiles {
            completed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .profiler
                .record_instruction_time(instruction, duration);
            return;
        }

        *self.opcodes.times[opcode::index(instruction)].get_or_insert(Duration::ZERO) += duration;
    }

    /// Record object allocation.
    pub fn record_object_allocation(&mut self, size_bytes: u64) {
        if !self.config.enable_memory_profiling {
            return;
        }
        if let Some(completed) = &self.completed_profiles {
            completed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .profiler
                .record_object_allocation(size_bytes);
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
        if let Some(completed) = &self.completed_profiles {
            completed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .profiler
                .record_array_allocation(size_bytes);
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
        if let Some(completed) = &self.completed_profiles {
            completed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .profiler
                .record_gc_cycle(duration);
            return;
        }

        self.memory_stats.gc_cycles += 1;
        self.memory_stats.gc_time_ns += duration.as_nanos() as u64;
    }

    /// Generate a profiling report.
    pub fn generate_report(&self, benchmark_name: String) -> ProfilingReport {
        if let Some(completed) = &self.completed_profiles {
            let completed = completed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            return completed
                .profiler
                .report_with_elapsed(benchmark_name, completed.execution_time);
        }
        self.report_with_elapsed(benchmark_name, self.start_time.elapsed())
    }

    fn report_with_elapsed(
        &self,
        benchmark_name: String,
        total_execution_time: Duration,
    ) -> ProfilingReport {
        let total_execution_time_ns = total_execution_time.as_nanos() as u64;

        // Allocate names and ordered maps only at the reporting boundary.
        let mut instruction_stats = BTreeMap::new();
        for (index, &name) in opcode::NAMES.iter().enumerate() {
            let count = self.opcodes.counts[index];
            if count == 0 {
                continue;
            }
            let total_time = self.opcodes.times[index].unwrap_or(Duration::ZERO);
            let total_time_ns = total_time.as_nanos() as u64;
            let average_time_ns = total_time_ns.checked_div(count).unwrap_or(0);

            instruction_stats.insert(
                name.to_string(),
                InstructionStats {
                    count,
                    total_time_ns,
                    average_time_ns,
                },
            );
        }

        // Preserve the old stable BTreeMap ordering for equal-duration ties,
        // including timing-only and explicitly recorded zero-duration samples.
        let mut hotspots = Vec::new();
        let mut instruction_times_vec: Vec<_> = self
            .opcodes
            .times
            .iter()
            .enumerate()
            .filter_map(|(index, time)| time.map(|time| (index, time)))
            .collect();
        instruction_times_vec.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| opcode::NAMES[a.0].cmp(opcode::NAMES[b.0]))
        });

        for &(index, total_time) in instruction_times_vec.iter().take(10) {
            let name = opcode::NAMES[index];
            let total_time_ns = total_time.as_nanos() as u64;
            let count = self.opcodes.counts[index];
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
                name: name.to_string(),
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
    opcode::NAMES[opcode::index(instruction)].to_string()
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
                .expect("operation should succeed for valid inputs")
                .count,
            2
        );
        assert_eq!(
            report
                .instruction_stats
                .get("Add")
                .expect("operation should succeed for valid inputs")
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

    #[test]
    fn router_session_publishes_completed_runs_and_preserves_zero_timing() {
        let (session, collector) = Profiler::router_session(ProfilingConfig {
            hotspot_sampling_interval: 2,
            ..Default::default()
        });
        let operation = Ir3Instruction::LoadInt { dst: 0, value: 3 };
        let mut first = collector.start_execution();
        first.record_instruction(&operation);
        first.record_instruction_time(&operation, Duration::ZERO);
        first.record_object_allocation(17);
        assert!(
            session
                .generate_report("running".into())
                .instruction_stats
                .is_empty()
        );
        collector.finish_execution(first);
        let first_report = session.generate_report("first".into());
        assert_eq!(first_report.instruction_stats["LoadInt"].count, 1);
        assert_eq!(first_report.hotspots.len(), 1);
        assert_eq!(first_report.hotspots[0].name, "LoadInt");
        assert_eq!(session.sample_count(), 0);

        let mut second = collector.start_execution();
        second.record_instruction(&operation);
        second.record_instruction(&operation);
        second.record_instruction_time(&operation, Duration::from_nanos(10));
        second.record_array_allocation(23);
        second.record_gc_cycle(Duration::from_nanos(7));
        let last_sample = second.last_sample_time();
        collector.finish_execution(second);
        let report = session.generate_report("completed".into());
        assert_eq!(report.instruction_stats["LoadInt"].count, 3);
        assert_eq!(report.instruction_stats["LoadInt"].total_time_ns, 10);
        assert_eq!(report.memory_stats.objects_allocated, 1);
        assert_eq!(report.memory_stats.arrays_allocated, 1);
        assert_eq!(report.memory_stats.total_bytes_allocated, 40);
        assert_eq!(report.memory_stats.gc_cycles, 1);
        assert_eq!(report.memory_stats.gc_time_ns, 7);
        assert_eq!(session.sample_count(), 1);
        assert_eq!(session.last_sample_time(), last_sample);
        assert_eq!(
            session
                .generate_report("idle".into())
                .total_execution_time_ns,
            report.total_execution_time_ns,
            "time between executions is not runtime cost"
        );
    }

    #[test]
    fn router_session_merges_parallel_workers_without_losing_counts() {
        let (session, collector) = Profiler::router_session(ProfilingConfig {
            hotspot_sampling_interval: 4,
            ..Default::default()
        });
        let workers: Vec<_> = (0..8)
            .map(|value| {
                let collector = collector.clone();
                std::thread::spawn(move || {
                    let mut profiler = collector.start_execution();
                    for _ in 0..10 {
                        profiler.record_instruction(&Ir3Instruction::LoadInt { dst: 0, value });
                    }
                    collector.finish_execution(profiler);
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("profiling worker finishes");
        }
        let report = session.generate_report("parallel".into());
        assert_eq!(report.instruction_stats["LoadInt"].count, 80);
        assert_eq!(session.sample_count(), 16);
    }

    #[test]
    fn returned_session_profiler_accepts_explicit_recording() {
        let (mut session, collector) = Profiler::router_session(ProfilingConfig::default());
        let operation = Ir3Instruction::LoadInt { dst: 0, value: 1 };
        let mut execution = collector.start_execution();
        execution.record_instruction(&operation);
        collector.finish_execution(execution);
        drop(collector);

        session.record_instruction(&operation);
        session.record_instruction_time(&operation, Duration::from_nanos(6));
        session.record_object_allocation(10);
        session.record_array_allocation(20);
        session.record_gc_cycle(Duration::from_nanos(4));
        let report = session.generate_report("continued-recording".into());
        assert_eq!(report.instruction_stats["LoadInt"].count, 2);
        assert_eq!(report.instruction_stats["LoadInt"].total_time_ns, 6);
        assert_eq!(report.memory_stats.objects_allocated, 1);
        assert_eq!(report.memory_stats.arrays_allocated, 1);
        assert_eq!(report.memory_stats.total_bytes_allocated, 30);
        assert_eq!(report.memory_stats.gc_cycles, 1);
        assert_eq!(report.memory_stats.gc_time_ns, 4);
    }
}

#[cfg(test)]
#[path = "profiling/regressions.rs"]
mod dense_profiling_regressions;

#[cfg(test)]
#[path = "profiling/sampling_regressions.rs"]
mod sampling_countdown_regressions;
