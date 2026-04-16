//! Profiling infrastructure for FrankenEngine baseline interpreter.
//!
//! Provides hotspot identification, instruction frequency counting, and
//! memory allocation profiling to inform optimization targeting.
//!
//! The profiler is designed to be low-overhead in production builds
//! and comprehensive in profiling builds.

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
            hotspot_sampling_interval: 1000, // Sample every 1000 instructions
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
    pub avg_time_ns: f64,
    /// Percentage of total execution time.
    pub percentage: f64,
}

impl InstructionStats {
    fn new() -> Self {
        Self {
            count: 0,
            total_time_ns: 0,
            avg_time_ns: 0.0,
            percentage: 0.0,
        }
    }

    fn record_execution(&mut self, duration: Duration) {
        self.count += 1;
        self.total_time_ns += duration.as_nanos() as u64;
        self.avg_time_ns = self.total_time_ns as f64 / self.count as f64;
    }

    fn finalize(&mut self, total_time_ns: u64) {
        if total_time_ns > 0 {
            self.percentage = (self.total_time_ns as f64 / total_time_ns as f64) * 100.0;
        }
    }
}

/// Memory allocation statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    /// Number of heap objects allocated.
    pub heap_objects_allocated: u64,
    /// Number of strings allocated.
    pub strings_allocated: u64,
    /// Number of arrays allocated.
    pub arrays_allocated: u64,
    /// Number of functions allocated.
    pub functions_allocated: u64,
    /// Total estimated memory usage in bytes.
    pub total_memory_estimate: u64,
    /// Peak memory usage during execution.
    pub peak_memory_estimate: u64,
    /// Number of potential GC pressure points.
    pub gc_pressure_points: u64,
}

impl Default for MemoryStats {
    fn default() -> Self {
        Self {
            heap_objects_allocated: 0,
            strings_allocated: 0,
            arrays_allocated: 0,
            functions_allocated: 0,
            total_memory_estimate: 0,
            peak_memory_estimate: 0,
            gc_pressure_points: 0,
        }
    }
}

impl MemoryStats {
    /// Record allocation of a heap object.
    pub fn record_object_allocation(&mut self, size_estimate: u64) {
        self.heap_objects_allocated += 1;
        self.total_memory_estimate += size_estimate;
        if self.total_memory_estimate > self.peak_memory_estimate {
            self.peak_memory_estimate = self.total_memory_estimate;
        }
    }

    /// Record allocation of a string.
    pub fn record_string_allocation(&mut self, length: usize) {
        self.strings_allocated += 1;
        let size_estimate = 24 + length as u64; // Base overhead + content
        self.record_object_allocation(size_estimate);
    }

    /// Record allocation of an array.
    pub fn record_array_allocation(&mut self, capacity: usize) {
        self.arrays_allocated += 1;
        let size_estimate = 64 + (capacity as u64 * 8); // Base overhead + elements
        self.record_object_allocation(size_estimate);
    }

    /// Record allocation of a function.
    pub fn record_function_allocation(&mut self) {
        self.functions_allocated += 1;
        self.record_object_allocation(128); // Estimated function overhead
    }

    /// Record a potential GC pressure point.
    pub fn record_gc_pressure(&mut self) {
        self.gc_pressure_points += 1;
    }
}

/// Call stack profiling information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallStackSample {
    /// Instruction pointer when sample was taken.
    pub ip: usize,
    /// Call stack depth.
    pub call_depth: usize,
    /// Current instruction being executed.
    pub instruction_name: String,
    /// Timestamp when sample was taken.
    pub timestamp_ns: u64,
}

/// Comprehensive profiling data for a benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilingData {
    /// Configuration used for this profiling session.
    pub config: ProfilingConfig,
    /// Statistics per instruction type.
    pub instruction_stats: BTreeMap<String, InstructionStats>,
    /// Memory allocation statistics.
    pub memory_stats: MemoryStats,
    /// Call stack samples (if enabled).
    pub call_stack_samples: Vec<CallStackSample>,
    /// Total execution time for the profiled run.
    pub total_execution_time_ns: u64,
    /// Total instructions executed.
    pub total_instructions: u64,
    /// Top 10 most frequent instructions.
    pub top_instructions_by_frequency: Vec<(String, u64)>,
    /// Top 10 most time-consuming instructions.
    pub top_instructions_by_time: Vec<(String, f64)>,
}

impl ProfilingData {
    /// Create a new profiling data collection.
    pub fn new(config: ProfilingConfig) -> Self {
        Self {
            config,
            instruction_stats: BTreeMap::new(),
            memory_stats: MemoryStats::default(),
            call_stack_samples: Vec::new(),
            total_execution_time_ns: 0,
            total_instructions: 0,
            top_instructions_by_frequency: Vec::new(),
            top_instructions_by_time: Vec::new(),
        }
    }

    /// Finalize profiling data and compute derived statistics.
    pub fn finalize(&mut self) {
        // Finalize instruction statistics
        for stats in self.instruction_stats.values_mut() {
            stats.finalize(self.total_execution_time_ns);
        }

        // Compute top instructions by frequency
        let mut by_frequency: Vec<_> = self.instruction_stats.iter()
            .map(|(name, stats)| (name.clone(), stats.count))
            .collect();
        by_frequency.sort_by(|a, b| b.1.cmp(&a.1));
        self.top_instructions_by_frequency = by_frequency.into_iter().take(10).collect();

        // Compute top instructions by time percentage
        let mut by_time: Vec<_> = self.instruction_stats.iter()
            .map(|(name, stats)| (name.clone(), stats.percentage))
            .collect();
        by_time.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        self.top_instructions_by_time = by_time.into_iter().take(10).collect();
    }

    /// Generate optimization target report.
    pub fn generate_optimization_report(&self) -> OptimizationReport {
        let mut targets = Vec::new();

        // Analyze instruction hotspots
        for (instruction, stats) in &self.instruction_stats {
            if stats.percentage > 1.0 { // Instructions taking >1% of time
                targets.push(OptimizationTarget {
                    category: OptimizationCategory::InstructionHotspot,
                    description: format!("Optimize {} instruction execution", instruction),
                    expected_impact: ExpectedImpact::from_percentage(stats.percentage),
                    metrics: OptimizationMetrics {
                        frequency: stats.count,
                        time_percentage: stats.percentage,
                        memory_impact: 0,
                    },
                    implementation_notes: vec![
                        format!("Executed {} times ({:.2}% of total time)", stats.count, stats.percentage),
                        format!("Average execution time: {:.2}ns", stats.avg_time_ns),
                        "Consider specialized fast path for common cases".to_string(),
                    ],
                });
            }
        }

        // Analyze memory pressure
        if self.memory_stats.gc_pressure_points > 0 {
            targets.push(OptimizationTarget {
                category: OptimizationCategory::MemoryManagement,
                description: "Reduce GC pressure through object pooling".to_string(),
                expected_impact: ExpectedImpact::Medium,
                metrics: OptimizationMetrics {
                    frequency: self.memory_stats.heap_objects_allocated,
                    time_percentage: 0.0, // Indirect impact
                    memory_impact: self.memory_stats.peak_memory_estimate,
                },
                implementation_notes: vec![
                    format!("Allocated {} heap objects", self.memory_stats.heap_objects_allocated),
                    format!("Peak memory: {} bytes", self.memory_stats.peak_memory_estimate),
                    format!("{} GC pressure points identified", self.memory_stats.gc_pressure_points),
                    "Consider object pooling for frequently allocated types".to_string(),
                ],
            });
        }

        // Sort targets by expected impact
        targets.sort_by(|a, b| {
            let impact_order = |impact: &ExpectedImpact| match impact {
                ExpectedImpact::High => 3,
                ExpectedImpact::Medium => 2,
                ExpectedImpact::Low => 1,
            };
            impact_order(&b.expected_impact).cmp(&impact_order(&a.expected_impact))
        });

        OptimizationReport {
            targets: targets.into_iter().take(10).collect(), // Top 10 targets
            summary: OptimizationSummary {
                total_instructions: self.total_instructions,
                execution_time_ms: self.total_execution_time_ns / 1_000_000,
                memory_peak_kb: self.memory_stats.peak_memory_estimate / 1024,
                top_hotspot_percentage: self.top_instructions_by_time.first()
                    .map(|(_, pct)| *pct)
                    .unwrap_or(0.0),
            },
        }
    }
}

/// Categories of optimization opportunities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationCategory {
    InstructionHotspot,
    MemoryManagement,
    CallOverhead,
    TypeSpecialization,
}

/// Expected impact of an optimization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExpectedImpact {
    High,   // >5% performance improvement expected
    Medium, // 1-5% performance improvement expected
    Low,    // <1% performance improvement expected
}

impl ExpectedImpact {
    fn from_percentage(percentage: f64) -> Self {
        if percentage > 5.0 {
            ExpectedImpact::High
        } else if percentage > 1.0 {
            ExpectedImpact::Medium
        } else {
            ExpectedImpact::Low
        }
    }
}

/// Metrics associated with an optimization target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationMetrics {
    /// Frequency of the operation.
    pub frequency: u64,
    /// Percentage of total execution time.
    pub time_percentage: f64,
    /// Memory impact in bytes.
    pub memory_impact: u64,
}

/// A specific optimization opportunity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationTarget {
    /// Category of optimization.
    pub category: OptimizationCategory,
    /// Description of the optimization opportunity.
    pub description: String,
    /// Expected performance impact.
    pub expected_impact: ExpectedImpact,
    /// Associated metrics.
    pub metrics: OptimizationMetrics,
    /// Implementation notes and suggestions.
    pub implementation_notes: Vec<String>,
}

/// Summary statistics for optimization targeting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationSummary {
    /// Total instructions executed.
    pub total_instructions: u64,
    /// Total execution time in milliseconds.
    pub execution_time_ms: u64,
    /// Peak memory usage in KB.
    pub memory_peak_kb: u64,
    /// Percentage of time spent in top hotspot.
    pub top_hotspot_percentage: f64,
}

/// Complete optimization report with ranked targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationReport {
    /// Ranked list of optimization targets.
    pub targets: Vec<OptimizationTarget>,
    /// Summary statistics.
    pub summary: OptimizationSummary,
}

/// Runtime profiler that collects data during interpreter execution.
pub struct RuntimeProfiler {
    data: ProfilingData,
    start_time: Option<Instant>,
    last_sample_time: Instant,
}

impl RuntimeProfiler {
    /// Create a new runtime profiler.
    pub fn new(config: ProfilingConfig) -> Self {
        Self {
            data: ProfilingData::new(config),
            start_time: None,
            last_sample_time: Instant::now(),
        }
    }

    /// Start profiling session.
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
        self.last_sample_time = Instant::now();
    }

    /// Record execution of an instruction.
    pub fn record_instruction(&mut self, instruction: &Ir3Instruction, duration: Duration) {
        if !self.data.config.enable_instruction_profiling {
            return;
        }

        let instruction_name = instruction_name(instruction);
        let stats = self.data.instruction_stats.entry(instruction_name).or_insert_with(InstructionStats::new);
        stats.record_execution(duration);
        self.data.total_instructions += 1;
    }

    /// Record memory allocation.
    pub fn record_memory_allocation(&mut self, size_estimate: u64) {
        if self.data.config.enable_memory_profiling {
            self.data.memory_stats.record_object_allocation(size_estimate);
        }
    }

    /// Record string allocation.
    pub fn record_string_allocation(&mut self, length: usize) {
        if self.data.config.enable_memory_profiling {
            self.data.memory_stats.record_string_allocation(length);
        }
    }

    /// Record call stack sample (if sampling is enabled).
    pub fn maybe_record_call_stack(&mut self, ip: usize, call_depth: usize, instruction: &Ir3Instruction) {
        if !self.data.config.enable_call_stack_profiling {
            return;
        }

        // Sample based on instruction count
        if self.data.total_instructions % self.data.config.hotspot_sampling_interval == 0 {
            let sample = CallStackSample {
                ip,
                call_depth,
                instruction_name: instruction_name(instruction),
                timestamp_ns: self.last_sample_time.elapsed().as_nanos() as u64,
            };
            self.data.call_stack_samples.push(sample);
        }
    }

    /// Finish profiling and return collected data.
    pub fn finish(mut self) -> ProfilingData {
        if let Some(start_time) = self.start_time {
            self.data.total_execution_time_ns = start_time.elapsed().as_nanos() as u64;
        }
        self.data.finalize();
        self.data
    }
}

/// Get a human-readable name for an instruction.
fn instruction_name(instruction: &Ir3Instruction) -> String {
    match instruction {
        Ir3Instruction::LoadInt { .. } => "LoadInt".to_string(),
        Ir3Instruction::LoadFloat { .. } => "LoadFloat".to_string(),
        Ir3Instruction::LoadStr { .. } => "LoadStr".to_string(),
        Ir3Instruction::LoadBool { .. } => "LoadBool".to_string(),
        Ir3Instruction::LoadNull { .. } => "LoadNull".to_string(),
        Ir3Instruction::LoadUndefined { .. } => "LoadUndefined".to_string(),
        Ir3Instruction::Add { .. } => "Add".to_string(),
        Ir3Instruction::Sub { .. } => "Sub".to_string(),
        Ir3Instruction::Mul { .. } => "Mul".to_string(),
        Ir3Instruction::Div { .. } => "Div".to_string(),
        Ir3Instruction::Mod { .. } => "Mod".to_string(),
        Ir3Instruction::Exp { .. } => "Exp".to_string(),
        Ir3Instruction::Lt { .. } => "Lt".to_string(),
        Ir3Instruction::Lte { .. } => "Lte".to_string(),
        Ir3Instruction::Gt { .. } => "Gt".to_string(),
        Ir3Instruction::Gte { .. } => "Gte".to_string(),
        Ir3Instruction::Eq { .. } => "Eq".to_string(),
        Ir3Instruction::StrictEq { .. } => "StrictEq".to_string(),
        Ir3Instruction::NotEq { .. } => "NotEq".to_string(),
        Ir3Instruction::StrictNotEq { .. } => "StrictNotEq".to_string(),
        Ir3Instruction::BitAnd { .. } => "BitAnd".to_string(),
        Ir3Instruction::BitOr { .. } => "BitOr".to_string(),
        Ir3Instruction::BitXor { .. } => "BitXor".to_string(),
        Ir3Instruction::Shl { .. } => "Shl".to_string(),
        Ir3Instruction::Shr { .. } => "Shr".to_string(),
        Ir3Instruction::Ushr { .. } => "Ushr".to_string(),
        Ir3Instruction::InstanceOf { .. } => "InstanceOf".to_string(),
        Ir3Instruction::InOp { .. } => "InOp".to_string(),
        Ir3Instruction::Construct { .. } => "Construct".to_string(),
        Ir3Instruction::Copy { .. } => "Copy".to_string(),
        Ir3Instruction::Call { .. } => "Call".to_string(),
        Ir3Instruction::Jump { .. } => "Jump".to_string(),
        Ir3Instruction::JumpIf { .. } => "JumpIf".to_string(),
        Ir3Instruction::JumpIfNot { .. } => "JumpIfNot".to_string(),
        Ir3Instruction::Return { .. } => "Return".to_string(),
        Ir3Instruction::GetProperty { .. } => "GetProperty".to_string(),
        Ir3Instruction::SetProperty { .. } => "SetProperty".to_string(),
        Ir3Instruction::GetElement { .. } => "GetElement".to_string(),
        Ir3Instruction::SetElement { .. } => "SetElement".to_string(),
        Ir3Instruction::CreateObject { .. } => "CreateObject".to_string(),
        Ir3Instruction::CreateArray { .. } => "CreateArray".to_string(),
        Ir3Instruction::CreateFunction { .. } => "CreateFunction".to_string(),
        Ir3Instruction::DeclareVar { .. } => "DeclareVar".to_string(),
        Ir3Instruction::GetVar { .. } => "GetVar".to_string(),
        Ir3Instruction::SetVar { .. } => "SetVar".to_string(),
        Ir3Instruction::CreatePromise { .. } => "CreatePromise".to_string(),
        Ir3Instruction::AwaitValue { .. } => "AwaitValue".to_string(),
        Ir3Instruction::AsyncReturn { .. } => "AsyncReturn".to_string(),
        Ir3Instruction::AsyncThrow { .. } => "AsyncThrow".to_string(),
        Ir3Instruction::CreateAsyncFunction { .. } => "CreateAsyncFunction".to_string(),
        Ir3Instruction::YieldValue { .. } => "YieldValue".to_string(),
        Ir3Instruction::CreateGenerator { .. } => "CreateGenerator".to_string(),
        Ir3Instruction::ForInInit { .. } => "ForInInit".to_string(),
        Ir3Instruction::ForInNext { .. } => "ForInNext".to_string(),
        Ir3Instruction::ForOfInit { .. } => "ForOfInit".to_string(),
        Ir3Instruction::ForOfNext { .. } => "ForOfNext".to_string(),
        Ir3Instruction::IteratorClose { .. } => "IteratorClose".to_string(),
        Ir3Instruction::BeginTry { .. } => "BeginTry".to_string(),
        Ir3Instruction::EndTry { .. } => "EndTry".to_string(),
        Ir3Instruction::BeginCatch { .. } => "BeginCatch".to_string(),
        Ir3Instruction::EndCatch { .. } => "EndCatch".to_string(),
        Ir3Instruction::EnterFinally { .. } => "EnterFinally".to_string(),
        Ir3Instruction::EndFinally { .. } => "EndFinally".to_string(),
        Ir3Instruction::ThrowException { .. } => "ThrowException".to_string(),
        Ir3Instruction::ArraySpread { .. } => "ArraySpread".to_string(),
        Ir3Instruction::ObjectSpread { .. } => "ObjectSpread".to_string(),
    }
}