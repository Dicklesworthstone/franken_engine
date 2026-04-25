//! Resource Budget Escalation Demo
//!
//! Demonstrates the deterministic resource budget escalation API:
//! throttle → sandbox → suspend → terminate
//!
//! This shows how FrankenEngine provides unified resource governance
//! that Node/Bun cannot offer by default.

use std::env;
use std::process;

use frankenengine_engine::resource_certificate_governance::ResourceDimension;
use frankenengine_engine::resource_escalation_control::ResourceEscalationController;
use frankenengine_engine::runtime_decision_theory::{DecisionContext, DecisionContextConfig};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <workload_id>", args[0]);
        eprintln!("Example: {} demo:budget-exhaustion", args[0]);
        process::exit(1);
    }

    let workload_id = args[1].clone();

    // Set up the escalation controller
    let epoch = SecurityEpoch::from_raw(1);
    let config = DecisionContextConfig::default();
    let decision_context = DecisionContext::new(config, epoch);
    let mut controller = ResourceEscalationController::new(epoch, decision_context);

    // Define bounded resource dimensions
    let bounded_dimensions = vec![ResourceDimension::CpuTime, ResourceDimension::HeapMemory];

    // Execute the full escalation sequence
    let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos() as u64;

    let log = controller.execute_escalation(workload_id, bounded_dimensions, current_timestamp);

    // Output the escalation log as JSON
    let json = serde_json::to_string_pretty(&log).expect("Failed to serialize escalation log");
    println!("{}", json);

    // Verify the log is valid
    if !log.is_complete() {
        eprintln!("WARNING: Escalation sequence incomplete");
        process::exit(1);
    }

    if !log.has_monotonic_timestamps() {
        eprintln!("WARNING: Timestamps are not monotonic");
        process::exit(1);
    }
}
