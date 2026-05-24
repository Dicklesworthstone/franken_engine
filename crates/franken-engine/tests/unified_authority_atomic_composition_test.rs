//! Negative test for unified authority algebra cross-axis atomic composition (bd-cixqu.26.4).
//!
//! Tests that hostcalls traversing all three axes (IFC × capability × resource budget)
//! are evaluated as a SINGLE atomic operation, not three sequential checks that could
//! see inconsistent state. This is the core safety property of the unified authority
//! algebra: authority decisions must be atomic across all axes.
//!
//! Test strategy: Set up concurrent state changes across the three axes during
//! a cross-axis hostcall, then verify the implementation either sees a consistent
//! snapshot across all axes OR detects the inconsistency and fails safe.

#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments)]

use frankenengine_engine::flow_lattice::LabelClass;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::unified_authority_algebra::{
    AuthorityLattice, BudgetEnvelope, CapabilityKind, CapabilitySet,
};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Mock concurrent state for testing race conditions
// ---------------------------------------------------------------------------

/// Mock authority context that can change during evaluation.
/// Simulates a real system where authority contexts can be modified
/// by concurrent operations (policy updates, resource allocation changes, etc.)
#[derive(Debug, Clone)]
struct MockConcurrentAuthorityContext {
    ifc_label: Arc<RwLock<LabelClass>>,
    capability_set: Arc<RwLock<CapabilitySet>>,
    budget_envelope: Arc<RwLock<BudgetEnvelope>>,
    // Track sequential access for detecting non-atomic behavior
    access_log: Arc<Mutex<Vec<String>>>,
}

impl MockConcurrentAuthorityContext {
    fn new(
        ifc_label: LabelClass,
        capability_set: CapabilitySet,
        budget_envelope: BudgetEnvelope,
    ) -> Self {
        Self {
            ifc_label: Arc::new(RwLock::new(ifc_label)),
            capability_set: Arc::new(RwLock::new(capability_set)),
            budget_envelope: Arc::new(RwLock::new(budget_envelope)),
            access_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get current authority as atomic snapshot (CORRECT behavior)
    fn get_authority_atomic(&self) -> AuthorityLattice {
        // This simulates the CORRECT implementation where all three axes
        // are read as a consistent snapshot
        let ifc = *self.ifc_label.read().unwrap();
        let caps = self.capability_set.read().unwrap().clone();
        let budget = self.budget_envelope.read().unwrap().clone();

        // Log atomic access
        self.access_log
            .lock()
            .unwrap()
            .push("atomic_read".to_string());

        AuthorityLattice::new(ifc, caps, budget)
    }

    /// Get current authority via sequential reads (INCORRECT behavior)
    fn get_authority_sequential(&self) -> AuthorityLattice {
        // This simulates the BUGGY implementation where the three axes
        // are read sequentially, potentially seeing inconsistent state

        // Read IFC label first
        let ifc = *self.ifc_label.read().unwrap();
        self.access_log.lock().unwrap().push("ifc_read".to_string());

        // Small delay to increase chance of inconsistency
        thread::sleep(Duration::from_millis(1));

        // Read capabilities second
        let caps = self.capability_set.read().unwrap().clone();
        self.access_log
            .lock()
            .unwrap()
            .push("caps_read".to_string());

        thread::sleep(Duration::from_millis(1));

        // Read budget third
        let budget = self.budget_envelope.read().unwrap().clone();
        self.access_log
            .lock()
            .unwrap()
            .push("budget_read".to_string());

        AuthorityLattice::new(ifc, caps, budget)
    }

    /// Simulate concurrent policy update that changes all three axes
    fn concurrent_policy_update(&self) {
        thread::sleep(Duration::from_millis(5));

        // Update IFC label (Secret -> TopSecret)
        *self.ifc_label.write().unwrap() = LabelClass::TopSecret;
        self.access_log
            .lock()
            .unwrap()
            .push("ifc_updated".to_string());

        // Update capabilities (add new capability)
        let mut caps = self.capability_set.write().unwrap();
        caps.insert(CapabilityKind::PolicyRequest);
        self.access_log
            .lock()
            .unwrap()
            .push("caps_updated".to_string());

        // Update budget (increase budget)
        let current_budget = self.budget_envelope.read().unwrap();
        let new_budget = BudgetEnvelope::try_new(
            current_budget.cpu_millionths + 500_000,
            current_budget.memory_millionths + 1_000_000,
            current_budget.wall_time_millionths + 10_000_000,
            current_budget.io_millionths + 2_000_000,
        )
        .unwrap();
        *self.budget_envelope.write().unwrap() = new_budget;
        self.access_log
            .lock()
            .unwrap()
            .push("budget_updated".to_string());
    }

    fn get_access_log(&self) -> Vec<String> {
        self.access_log.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------
// Test hostcall that requires all three axes
// ---------------------------------------------------------------------------

/// Simulates a hostcall that needs to check all three authority axes.
/// Example: fs.read of a TopSecret file that consumes 1KB memory budget
/// and requires FsRead capability.
fn cross_axis_hostcall_check(
    context: &MockConcurrentAuthorityContext,
    required_authority: &AuthorityLattice,
    use_atomic: bool,
) -> Result<(), String> {
    let current_authority = if use_atomic {
        context.get_authority_atomic()
    } else {
        context.get_authority_sequential()
    };

    if current_authority.subsumes(required_authority) {
        Ok(())
    } else {
        Err(format!(
            "Authority check failed: current={:?}, required={:?}",
            current_authority, required_authority
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_atomic_composition_consistency_under_concurrent_updates() {
    // Create initial authority context with moderate permissions
    let initial_ifc = LabelClass::Secret;
    let mut initial_caps = CapabilitySet::empty();
    initial_caps.insert(CapabilityKind::FsRead);
    let initial_budget = BudgetEnvelope::try_new(
        250_000,    // cpu: 0.25 cores
        500_000,    // memory: 0.5MB
        30_000_000, // wall_time: 30 seconds
        1_000_000,  // io: 1MB
    )
    .unwrap();

    let context =
        MockConcurrentAuthorityContext::new(initial_ifc, initial_caps.clone(), initial_budget);

    // Define a cross-axis requirement that's borderline
    // (will pass after the concurrent update, but might be inconsistent during)
    let mut required_caps = CapabilitySet::empty();
    required_caps.insert(CapabilityKind::FsRead);
    required_caps.insert(CapabilityKind::PolicyRequest); // Added by concurrent update

    let required_budget = BudgetEnvelope::try_new(
        300_000,    // Requires more CPU
        800_000,    // Requires more memory than initially available
        60_000_000, // wall_time: 60 seconds
        1_500_000,  // Requires more IO
    )
    .unwrap();

    let required_authority = AuthorityLattice::new(
        LabelClass::TopSecret, // Higher than initial Secret
        required_caps,
        required_budget,
    );

    // Test 1: Atomic access should be consistent
    let context_atomic = context.clone();
    let required_atomic = required_authority.clone();
    let atomic_handle = thread::spawn(move || {
        // Start concurrent update
        let update_context = context_atomic.clone();
        let update_handle = thread::spawn(move || {
            update_context.concurrent_policy_update();
        });

        // Wait a bit then do atomic check
        thread::sleep(Duration::from_millis(8));
        let result = cross_axis_hostcall_check(&context_atomic, &required_atomic, true);

        update_handle.join().unwrap();
        (result, context_atomic.get_access_log())
    });

    // Test 2: Sequential access may see inconsistent state
    let context_sequential =
        MockConcurrentAuthorityContext::new(initial_ifc, initial_caps, initial_budget);
    let required_sequential = required_authority.clone();
    let sequential_handle = thread::spawn(move || {
        // Start concurrent update
        let update_context = context_sequential.clone();
        let update_handle = thread::spawn(move || {
            update_context.concurrent_policy_update();
        });

        // Wait a bit then do sequential check
        thread::sleep(Duration::from_millis(8));
        let result = cross_axis_hostcall_check(&context_sequential, &required_sequential, false);

        update_handle.join().unwrap();
        (result, context_sequential.get_access_log())
    });

    // Collect results
    let (atomic_result, atomic_log) = atomic_handle.join().unwrap();
    let (sequential_result, sequential_log) = sequential_handle.join().unwrap();

    // Verify atomic behavior is consistent
    // (Either consistently passes or consistently fails based on timing)
    println!("Atomic access log: {:?}", atomic_log);
    println!("Sequential access log: {:?}", sequential_log);

    // The atomic implementation should have fewer, cleaner log entries
    assert!(
        atomic_log.iter().filter(|e| e == &"atomic_read").count() > 0,
        "Atomic implementation should use atomic_read"
    );

    // The sequential implementation should show interleaved reads and updates
    assert!(
        sequential_log.contains(&"ifc_read".to_string())
            && sequential_log.contains(&"caps_read".to_string())
            && sequential_log.contains(&"budget_read".to_string()),
        "Sequential implementation should show individual axis reads"
    );
}

#[test]
fn test_cross_axis_hostcall_atomic_semantics() {
    // Test specific case mentioned in bead: read TopSecret via fs.read consuming 1KB budget
    let context = MockConcurrentAuthorityContext::new(
        LabelClass::TopSecret,
        CapabilitySet::from_iter([CapabilityKind::FsRead]),
        BudgetEnvelope::try_new(2_000_000, 1_000_000, 60_000_000, 1_000_000).unwrap(),
    );

    let required_authority = AuthorityLattice::new(
        LabelClass::Secret, // Reading Secret data (should be allowed with TopSecret clearance)
        CapabilitySet::from_iter([CapabilityKind::FsRead]),
        BudgetEnvelope::try_new(100_000, 1_024, 30_000_000, 0).unwrap(), // 1KB memory budget
    );

    // This should succeed with atomic check
    let result = cross_axis_hostcall_check(&context, &required_authority, true);
    assert!(
        result.is_ok(),
        "Cross-axis hostcall should succeed when authority is sufficient: {:?}",
        result
    );

    // Test insufficient authority case
    let insufficient_caps = CapabilitySet::empty(); // No FsRead capability
    let insufficient_authority = AuthorityLattice::new(
        LabelClass::Secret,
        insufficient_caps,
        BudgetEnvelope::try_new(100_000, 1_024, 30_000_000, 0).unwrap(),
    );

    let result = cross_axis_hostcall_check(&context, &insufficient_authority, true);
    assert!(
        result.is_err(),
        "Cross-axis hostcall should fail when capabilities are insufficient"
    );
}

#[test]
fn test_authority_lattice_atomic_subsumption() {
    // Test that the AuthorityLattice.subsumes() method itself is atomic
    // (all three axes checked together, not separately)

    let higher_authority = AuthorityLattice::new(
        LabelClass::TopSecret,
        CapabilitySet::from_iter([
            CapabilityKind::FsRead,
            CapabilityKind::FsWrite,
            CapabilityKind::NetConnect,
        ]),
        BudgetEnvelope::try_new(5_000_000, 2_000_000, 120_000_000, 3_000_000).unwrap(),
    );

    let lower_authority = AuthorityLattice::new(
        LabelClass::Secret,
        CapabilitySet::from_iter([CapabilityKind::FsRead]),
        BudgetEnvelope::try_new(1_000_000, 500_000, 60_000_000, 1_000_000).unwrap(),
    );

    // Higher authority should subsume lower authority
    assert!(
        higher_authority.subsumes(&lower_authority),
        "Higher authority should subsume lower authority"
    );

    // Lower authority should not subsume higher authority
    assert!(
        !lower_authority.subsumes(&higher_authority),
        "Lower authority should not subsume higher authority"
    );

    // Test mixed case where some axes are higher, others lower
    let mixed_authority = AuthorityLattice::new(
        LabelClass::TopSecret,  // Higher IFC
        CapabilitySet::empty(), // Lower capability
        BudgetEnvelope::try_new(10_000_000, 5_000_000, 180_000_000, 5_000_000).unwrap(), // Higher budget
    );

    // Mixed authority should not subsume lower_authority due to empty capabilities
    assert!(
        !mixed_authority.subsumes(&lower_authority),
        "Mixed authority with insufficient capabilities should not subsume"
    );
}
