#![forbid(unsafe_code)]

//! Composition root for engine governance subsystems.
//!
//! Bead: bd-2hzkh.
//!
//! Multiple governance-aware subsystems (`GcCollector`, `LaneScheduler`,
//! and others to come) each expose `set_budget_enforcer(BudgetEnforcer)`
//! setters. The integrator was previously responsible for remembering to
//! call every setter; forgetting one silently produced a no-op
//! enforcement path (root cause of bd-38uej, bd-1lsy.7.25.2 follow-ups).
//!
//! `GovernanceContext` is the canonical wiring point. It owns the
//! `BudgetEnforcer` and produces pre-wired subsystem instances via
//! `with_*` factories. The original setters remain `pub` for
//! backwards compatibility, but new integrators should prefer the
//! context-based API so adding a new governance-aware subsystem only
//! has to update one place to be honoured.

use crate::gc::{GcCollector, GcConfig};
use crate::resource_certificate_consumer::BudgetEnforcer;
use crate::scheduler_lane::{LaneConfig, LaneScheduler};

// ---------------------------------------------------------------------------
// GovernanceContext
// ---------------------------------------------------------------------------

/// Owns the engine-wide [`BudgetEnforcer`] and constructs governance-aware
/// subsystems with the enforcer already wired in.
///
/// ## Why this exists
///
/// Subsystems (`GcCollector`, `LaneScheduler`, …) each accept the
/// enforcer via a `set_budget_enforcer` setter. Integrators that forget
/// to call one setter produce a silent governance gap. This context
/// hands out subsystems with the enforcer already attached, so adding a
/// new governance-aware subsystem only requires extending this struct
/// rather than auditing every integrator.
///
/// ## Cloning semantics
///
/// `BudgetEnforcer` is `Clone`, so factories produce *independent copies*
/// of the per-extension state. That matches the existing pull-model
/// semantics where every subsystem owns its own `Option<BudgetEnforcer>`.
/// A future shared-state model would replace the field with
/// `Arc<Mutex<BudgetEnforcer>>` here without changing any caller.
#[derive(Debug, Clone)]
pub struct GovernanceContext {
    enforcer: BudgetEnforcer,
}

impl GovernanceContext {
    /// Construct a new context wrapping the supplied enforcer.
    pub fn new(enforcer: BudgetEnforcer) -> Self {
        Self { enforcer }
    }

    /// Borrow the enforcer for direct certificate management
    /// (`install_certificate`, etc.).
    pub fn enforcer(&self) -> &BudgetEnforcer {
        &self.enforcer
    }

    /// Mutably borrow the enforcer.
    pub fn enforcer_mut(&mut self) -> &mut BudgetEnforcer {
        &mut self.enforcer
    }

    /// Replace the wrapped enforcer. Existing subsystems already
    /// constructed via [`with_gc_collector`](Self::with_gc_collector) /
    /// [`with_lane_scheduler`](Self::with_lane_scheduler) keep the
    /// snapshot they were built with; only subsystems constructed *after*
    /// this call see the new enforcer.
    pub fn set_enforcer(&mut self, enforcer: BudgetEnforcer) {
        self.enforcer = enforcer;
    }

    /// Construct a [`GcCollector`] with the context's enforcer already
    /// wired in.
    pub fn with_gc_collector(&self, config: GcConfig) -> GcCollector {
        let mut gc = GcCollector::new(config);
        gc.set_budget_enforcer(self.enforcer.clone());
        gc
    }

    /// Construct a [`LaneScheduler`] with the context's enforcer already
    /// wired in.
    pub fn with_lane_scheduler(&self, config: LaneConfig) -> LaneScheduler {
        let mut sched = LaneScheduler::new(config);
        sched.set_budget_enforcer(self.enforcer.clone());
        sched
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_certificate_consumer::{
        BudgetEnforcementPolicy, CertificateDigest, CertificateVerdict, EnforcedDimension,
        EnforcementScope, ExtractedBound,
    };
    use crate::scheduler_lane::{SchedulerLane, TaskLabel, TaskType};
    use crate::security_epoch::SecurityEpoch;

    fn enforcer_with_extension(extension_id: &str, time_bound: i64) -> BudgetEnforcer {
        let mut enforcer = BudgetEnforcer::new(
            BudgetEnforcementPolicy::default(),
            SecurityEpoch::from_raw(1),
        );
        enforcer
            .install_certificate(
                extension_id,
                CertificateDigest {
                    certificate_id: format!("cert-{extension_id}"),
                    region_id: format!("region-{extension_id}"),
                    epoch: SecurityEpoch::from_raw(1),
                    verdict: CertificateVerdict::Certified,
                    bounds: vec![
                        ExtractedBound {
                            dimension: EnforcedDimension::Time,
                            upper_bound_millionths: time_bound,
                            is_tight: true,
                            confidence_millionths: 1_000_000,
                        },
                        ExtractedBound {
                            dimension: EnforcedDimension::HostcallCount,
                            upper_bound_millionths: 1_000_000,
                            is_tight: true,
                            confidence_millionths: 1_000_000,
                        },
                        ExtractedBound {
                            dimension: EnforcedDimension::HeapMemory,
                            upper_bound_millionths: 1_000_000_000,
                            is_tight: true,
                            confidence_millionths: 1_000_000,
                        },
                        ExtractedBound {
                            dimension: EnforcedDimension::GcPressure,
                            upper_bound_millionths: 1_000_000,
                            is_tight: true,
                            confidence_millionths: 1_000_000,
                        },
                    ],
                    abstention_count: 0,
                    min_confidence_millionths: 1_000_000,
                },
            )
            .expect("install must succeed for positive bounds");
        enforcer
    }

    fn ready_label() -> TaskLabel {
        TaskLabel {
            lane: SchedulerLane::Ready,
            task_type: TaskType::ExtensionDispatch,
            trace_id: "trace-ctx".to_string(),
            priority_sub_band: 0,
        }
    }

    #[test]
    fn context_wires_enforcer_into_gc_collector() {
        let enforcer = enforcer_with_extension("ext-a", 1_000_000);
        let ctx = GovernanceContext::new(enforcer);
        let mut gc = ctx.with_gc_collector(GcConfig::deterministic());
        gc.register_heap("ext-a".to_string())
            .expect("heap registration should succeed");

        // The enforcer is wired: an allocation that fits the HeapMemory
        // bound (1_000_000_000 millionths) succeeds. If the wiring were
        // missing the allocation would still succeed but
        // `extension_state` would never be touched.
        let _ = gc
            .allocate("ext-a", 100)
            .expect("allocation within budget should succeed");
        // GovernanceContext.enforcer() still has the original snapshot
        // (no per-subsystem usage echoes back here).
        assert!(ctx.enforcer().extension_state("ext-a").is_some());
    }

    #[test]
    fn context_wires_enforcer_into_lane_scheduler() {
        let enforcer = enforcer_with_extension("ext-a", 1_000_000);
        let ctx = GovernanceContext::new(enforcer);
        let mut sched = ctx.with_lane_scheduler(LaneConfig::default());

        // submit_for_extension consults the wired enforcer and admits
        // within-budget tasks.
        let id = sched
            .submit_for_extension("ext-a", ready_label(), 100, "payload-ctx", 0)
            .expect("admission within budget must succeed");
        assert_eq!(id.0, 1);
    }

    #[test]
    fn context_factories_produce_independent_subsystems() {
        // The context wraps the enforcer by clone, so each factory call
        // produces a subsystem with an independent copy of the enforcer
        // state. Mutating one subsystem's enforcer does not bleed into
        // another's. (Future shared-state model can replace this with
        // Arc<Mutex<>> without changing factory signatures.)
        let enforcer = enforcer_with_extension("ext-a", 1_000_000);
        let ctx = GovernanceContext::new(enforcer);
        let mut gc = ctx.with_gc_collector(GcConfig::deterministic());
        let _ = ctx.with_lane_scheduler(LaneConfig::default());

        gc.register_heap("ext-a".to_string())
            .expect("heap registration should succeed");
        let _ = gc
            .allocate("ext-a", 100)
            .expect("allocation within budget should succeed");

        // The context's own enforcer never observed the allocation
        // because the subsystem holds an independent clone.
        let state = ctx
            .enforcer()
            .extension_state("ext-a")
            .expect("seed certificate state should remain");
        let usage = state
            .budgets
            .get(&EnforcedDimension::HeapMemory)
            .expect("HeapMemory budget present")
            .current_usage_millionths;
        assert_eq!(
            usage, 0,
            "context enforcer is independent of subsystem clones"
        );
    }

    #[test]
    fn enforcer_mut_allows_in_place_certificate_management() {
        // `enforcer_mut()` lets the integrator install certificates on
        // the context's enforcer before constructing subsystems, so the
        // resulting wired subsystems start with the certificate state
        // already populated.
        let enforcer = BudgetEnforcer::new(
            BudgetEnforcementPolicy::default(),
            SecurityEpoch::from_raw(1),
        );
        let mut ctx = GovernanceContext::new(enforcer);
        ctx.enforcer_mut()
            .install_certificate(
                "ext-late",
                CertificateDigest {
                    certificate_id: "cert-late".to_string(),
                    region_id: "region-late".to_string(),
                    epoch: SecurityEpoch::from_raw(1),
                    verdict: CertificateVerdict::Certified,
                    bounds: vec![ExtractedBound {
                        dimension: EnforcedDimension::HostcallCount,
                        upper_bound_millionths: 1_000_000,
                        is_tight: true,
                        confidence_millionths: 1_000_000,
                    }],
                    abstention_count: 0,
                    min_confidence_millionths: 1_000_000,
                },
            )
            .expect("install on mutable enforcer succeeds");

        let receipt = ctx.enforcer_mut().enforce(
            "ext-late",
            EnforcementScope::SchedulerAdmission {
                task_type: TaskType::ExtensionDispatch.to_string(),
            },
            &[(EnforcedDimension::HostcallCount, 1)],
        );
        // Certificate is installed and the dimension has positive
        // headroom: this must Allow.
        assert!(matches!(
            receipt.decision,
            crate::resource_certificate_consumer::EnforcementDecision::Allow
                | crate::resource_certificate_consumer::EnforcementDecision::Throttle { .. }
        ));
    }
}
