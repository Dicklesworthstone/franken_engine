// Demonstration of profiling infrastructure for RC-3.5
use std::time::Duration;
use frankenengine_engine::profiling::{Profiler, ProfilingConfig};
use frankenengine_engine::ir_contract::{Ir3Instruction, Reg};

fn main() {
    let config = ProfilingConfig::default();
    let mut profiler = Profiler::new(config);

    // Simulate some interpreter execution
    let load_int = Ir3Instruction::LoadInt { dst: Reg(0), value: 42 };
    let add = Ir3Instruction::Add { dst: Reg(0), lhs: Reg(1), rhs: Reg(2) };
    let call = Ir3Instruction::Call {
        callee: Reg(0),
        args: (Reg(1), Reg(3)),
        dst: Reg(4)
    };

    // Record instruction executions (simulating a hot loop)
    for _ in 0..1000 {
        profiler.record_instruction(&load_int);
        profiler.record_instruction_time(&load_int, Duration::from_nanos(10));
    }

    for _ in 0..500 {
        profiler.record_instruction(&add);
        profiler.record_instruction_time(&add, Duration::from_nanos(15));
    }

    for _ in 0..100 {
        profiler.record_instruction(&call);
        profiler.record_instruction_time(&call, Duration::from_nanos(50));
    }

    // Record memory allocations
    profiler.record_object_allocation(64);
    profiler.record_array_allocation(128);
    profiler.record_gc_cycle(Duration::from_millis(2));

    // Generate profiling report
    let report = profiler.generate_report("demo_benchmark".to_string());

    println!("Profiling Report for: {}", report.benchmark_name);
    println!("Total execution time: {} ns", report.total_execution_time_ns);
    println!("\nInstruction Statistics:");
    for (name, stats) in &report.instruction_stats {
        println!("  {}: {} executions, avg {} ns", name, stats.count, stats.average_time_ns);
    }

    println!("\nMemory Statistics:");
    println!("  Objects allocated: {}", report.memory_stats.objects_allocated);
    println!("  Arrays allocated: {}", report.memory_stats.arrays_allocated);
    println!("  Total bytes: {}", report.memory_stats.total_bytes_allocated);
    println!("  GC cycles: {}", report.memory_stats.gc_cycles);

    println!("\nTop Optimization Targets:");
    for hotspot in &report.hotspots {
        println!("  {} - {:.2}% of execution time ({} hits, {} ns avg)",
                hotspot.name, hotspot.time_percentage, hotspot.hit_count, hotspot.average_time_ns);
        println!("    Recommendation: {}", hotspot.recommendation);
    }

    // Save report as JSON
    let json = serde_json::to_string_pretty(&report).unwrap();
    println!("\nJSON Report:\n{}", json);
}