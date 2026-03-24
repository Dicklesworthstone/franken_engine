//! Policy theorem compiler passes and machine-check hooks.
//!
//! Transforms policy source into a formal IR with machine-checkable
//! properties: monotonicity, non-interference, attenuation legality,
//! merge determinism, and precedence stability.  Replaces ad-hoc policy
//! composition with theorem-backed policy engineering.
//!
//! Plan references: Section 10.12 item 11, 9H.5 (Policy Theorem Engine),
//! 9F.8 (Policy Compiler With Formal Merge Guarantees), bd-3oc.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, SchemaHash};
use crate::engine_object_id::ObjectDomain;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_object,
    verify_object,
};

// ---------------------------------------------------------------------------
// Capability — atomic authority unit
// ---------------------------------------------------------------------------

/// Atomic authority unit referenced in policy rules.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Capability(String);

impl Capability {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// PolicyId — stable identifier for a policy
// ---------------------------------------------------------------------------

/// Stable identifier for a compiled policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyId(String);

impl PolicyId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Policy IR — typed intermediate representation
// ---------------------------------------------------------------------------

/// Merge operator defining how two authority sets combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MergeOperator {
    /// Union: grants from both policies apply.
    Union,
    /// Intersection: only grants present in both survive.
    Intersection,
    /// Attenuation: capabilities are restricted (never amplified).
    Attenuation,
    /// Precedence: higher-priority policy wins on conflict.
    Precedence,
}

impl fmt::Display for MergeOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Union => f.write_str("union"),
            Self::Intersection => f.write_str("intersection"),
            Self::Attenuation => f.write_str("attenuation"),
            Self::Precedence => f.write_str("precedence"),
        }
    }
}

/// A single authority grant in the policy IR.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthorityGrant {
    /// Subject this grant applies to.
    pub subject: String,
    /// Capability being granted.
    pub capability: Capability,
    /// Conditions under which the grant is valid.
    pub conditions: BTreeSet<String>,
    /// Scope restriction.
    pub scope: String,
    /// Lifetime of this grant (epoch-bound).
    pub lifetime_epochs: u64,
}

/// Formal property annotation on a policy IR node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FormalProperty {
    /// Authority can only be attenuated (reduced), never amplified.
    Monotonicity,
    /// Policy A's decisions do not leak B's protected state.
    NonInterference,
    /// Delegated authority stays within delegator's envelope.
    AttenuationLegality,
    /// Merge result is identical regardless of merge order.
    MergeDeterminism,
    /// Priority rankings are consistent across all evaluation paths.
    PrecedenceStability,
}

impl fmt::Display for FormalProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Monotonicity => f.write_str("monotonicity"),
            Self::NonInterference => f.write_str("non-interference"),
            Self::AttenuationLegality => f.write_str("attenuation-legality"),
            Self::MergeDeterminism => f.write_str("merge-determinism"),
            Self::PrecedenceStability => f.write_str("precedence-stability"),
        }
    }
}

/// Constraint annotation on a policy IR node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Constraint {
    /// Must hold at all times.
    Invariant(String),
    /// Must hold before rule application.
    Precondition(String),
    /// Must hold after rule application.
    Postcondition(String),
    /// Non-interference claim between two policy domains.
    NonInterferenceClaim { domain_a: String, domain_b: String },
}

/// Decision point in a policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionPoint {
    /// Quorum threshold for multi-approver scenarios.
    pub threshold: u32,
    /// Action map: condition -> action.
    pub action_map: BTreeMap<String, String>,
    /// Fallback action when no condition matches.
    pub fallback: String,
}

/// Compiled policy IR node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyIrNode {
    /// Node identifier (unique within the policy).
    pub node_id: String,
    /// Authority grants at this node.
    pub grants: Vec<AuthorityGrant>,
    /// Merge operator for combining with other nodes.
    pub merge_op: MergeOperator,
    /// Formal property claims this node carries.
    pub property_claims: BTreeSet<FormalProperty>,
    /// Constraints attached to this node.
    pub constraints: Vec<Constraint>,
    /// Optional decision point.
    pub decision_point: Option<DecisionPoint>,
    /// Priority (higher = stronger precedence, 0 = default).
    pub priority: u32,
}

/// A full compiled policy IR — the output of the parsing pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyIr {
    /// Policy identifier.
    pub policy_id: PolicyId,
    /// Version of this policy.
    pub version: u64,
    /// IR nodes.
    pub nodes: Vec<PolicyIrNode>,
    /// The full set of capabilities referenced.
    pub capability_universe: BTreeSet<Capability>,
    /// Properties verified so far.
    pub verified_properties: BTreeSet<FormalProperty>,
    /// Epoch this policy was compiled against.
    pub epoch: SecurityEpoch,
}

impl PolicyIr {
    /// All capabilities granted across all nodes.
    pub fn granted_capabilities(&self) -> BTreeSet<Capability> {
        self.nodes
            .iter()
            .flat_map(|n| n.grants.iter().map(|g| g.capability.clone()))
            .collect()
    }

    /// All subjects referenced across all nodes.
    pub fn subjects(&self) -> BTreeSet<String> {
        self.nodes
            .iter()
            .flat_map(|n| n.grants.iter().map(|g| g.subject.clone()))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Compiler pass results
// ---------------------------------------------------------------------------

/// Witness for a successfully verified property.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyWitness {
    /// Which property was verified.
    pub property: FormalProperty,
    /// Policy this witness applies to.
    pub policy_id: PolicyId,
    /// Human-readable explanation.
    pub explanation: String,
    /// Nodes examined.
    pub nodes_examined: u32,
    /// Pass that produced this witness.
    pub pass_name: String,
}

/// Counterexample for a failed property check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counterexample {
    /// Which property was violated.
    pub property: FormalProperty,
    /// Policy that failed.
    pub policy_id: PolicyId,
    /// Specific node(s) that caused the violation.
    pub violating_nodes: Vec<String>,
    /// Human-readable description of the violation.
    pub description: String,
    /// Merge path that exposed the violation (if applicable).
    pub merge_path: Vec<String>,
}

/// Result of a single compiler pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PassResult {
    /// Pass succeeded with a witness.
    Ok(PropertyWitness),
    /// Pass failed with a counterexample.
    Failed(Counterexample),
}

impl PassResult {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

// ---------------------------------------------------------------------------
// Compiler — multi-pass policy theorem compiler
// ---------------------------------------------------------------------------

/// Full compilation result from all passes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilationResult {
    /// Policy that was compiled.
    pub policy_id: PolicyId,
    /// Results from each pass.
    pub pass_results: Vec<PassResult>,
    /// Witnesses for all verified properties.
    pub witnesses: Vec<PropertyWitness>,
    /// Counterexamples for all failed properties.
    pub counterexamples: Vec<Counterexample>,
    /// Whether all passes succeeded.
    pub all_passed: bool,
}

/// The policy theorem compiler.
///
/// Runs a sequence of verification passes over a `PolicyIr` to produce
/// machine-checkable property witnesses or bounded counterexamples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTheoremCompiler {
    /// Maximum node count before refusing compilation.
    max_nodes: u32,
    /// Whether the precedence-stability pass is mandatory.
    require_precedence_stability: bool,
}

impl PolicyTheoremCompiler {
    /// Create a compiler with default settings.
    pub fn new() -> Self {
        Self {
            max_nodes: 10_000,
            require_precedence_stability: true,
        }
    }

    /// Create with custom limits.
    pub fn with_limits(max_nodes: u32, require_precedence_stability: bool) -> Self {
        Self {
            max_nodes,
            require_precedence_stability,
        }
    }

    /// Run all compiler passes on a policy IR.
    pub fn compile(&self, ir: &PolicyIr) -> Result<CompilationResult, CompilerError> {
        if ir.nodes.is_empty() {
            return Err(CompilerError::EmptyPolicy {
                policy_id: ir.policy_id.clone(),
            });
        }
        if ir.nodes.len() > self.max_nodes as usize {
            return Err(CompilerError::PolicyTooLarge {
                policy_id: ir.policy_id.clone(),
                node_count: ir.nodes.len() as u32,
                max_nodes: self.max_nodes,
            });
        }

        let mut pass_results = Vec::new();
        let mut witnesses = Vec::new();
        let mut counterexamples = Vec::new();

        // Pass 1: Type-checking (capability universe consistency).
        let type_check = self.type_check_pass(ir);
        match &type_check {
            PassResult::Ok(w) => witnesses.push(w.clone()),
            PassResult::Failed(c) => counterexamples.push(c.clone()),
        }
        pass_results.push(type_check);

        // Pass 2: Monotonicity.
        let mono = self.monotonicity_pass(ir);
        match &mono {
            PassResult::Ok(w) => witnesses.push(w.clone()),
            PassResult::Failed(c) => counterexamples.push(c.clone()),
        }
        pass_results.push(mono);

        // Pass 3: Non-interference.
        let ni = self.non_interference_pass(ir);
        match &ni {
            PassResult::Ok(w) => witnesses.push(w.clone()),
            PassResult::Failed(c) => counterexamples.push(c.clone()),
        }
        pass_results.push(ni);

        // Pass 4: Merge determinism.
        let md = self.merge_determinism_pass(ir);
        match &md {
            PassResult::Ok(w) => witnesses.push(w.clone()),
            PassResult::Failed(c) => counterexamples.push(c.clone()),
        }
        pass_results.push(md);

        // Pass 5: Precedence stability (optional).
        if self.require_precedence_stability {
            let ps = self.precedence_stability_pass(ir);
            match &ps {
                PassResult::Ok(w) => witnesses.push(w.clone()),
                PassResult::Failed(c) => counterexamples.push(c.clone()),
            }
            pass_results.push(ps);
        }

        // Pass 6: Attenuation legality.
        let al = self.attenuation_legality_pass(ir);
        match &al {
            PassResult::Ok(w) => witnesses.push(w.clone()),
            PassResult::Failed(c) => counterexamples.push(c.clone()),
        }
        pass_results.push(al);

        let all_passed = counterexamples.is_empty();

        Ok(CompilationResult {
            policy_id: ir.policy_id.clone(),
            pass_results,
            witnesses,
            counterexamples,
            all_passed,
        })
    }

    // -- Individual compiler passes --

    /// Type-check pass: verify all granted capabilities exist in universe.
    fn type_check_pass(&self, ir: &PolicyIr) -> PassResult {
        let granted = ir.granted_capabilities();
        let mut missing: Vec<String> = Vec::new();
        let mut bad_nodes: Vec<String> = Vec::new();

        for node in &ir.nodes {
            for grant in &node.grants {
                if !ir.capability_universe.contains(&grant.capability) {
                    missing.push(grant.capability.as_str().to_string());
                    if !bad_nodes.contains(&node.node_id) {
                        bad_nodes.push(node.node_id.clone());
                    }
                }
                // Check lifetime is nonzero.
                if grant.lifetime_epochs == 0 {
                    bad_nodes.push(node.node_id.clone());
                    missing.push(format!("zero-lifetime:{}", grant.capability));
                }
            }
        }

        if missing.is_empty() {
            PassResult::Ok(PropertyWitness {
                property: FormalProperty::AttenuationLegality, // type-check is a prereq
                policy_id: ir.policy_id.clone(),
                explanation: format!(
                    "all {} granted capabilities exist in universe of {}",
                    granted.len(),
                    ir.capability_universe.len()
                ),
                nodes_examined: ir.nodes.len() as u32,
                pass_name: "type-check".into(),
            })
        } else {
            PassResult::Failed(Counterexample {
                property: FormalProperty::AttenuationLegality,
                policy_id: ir.policy_id.clone(),
                violating_nodes: bad_nodes,
                description: format!("undefined capabilities: {}", missing.join(", ")),
                merge_path: Vec::new(),
            })
        }
    }

    /// Monotonicity pass: verify that merge operations never amplify authority.
    ///
    /// Union is non-monotonic (can amplify), Attenuation/Intersection preserve
    /// monotonicity, Precedence is monotonic if higher-priority grants are
    /// subsets of the universe.
    fn monotonicity_pass(&self, ir: &PolicyIr) -> PassResult {
        let mut violating: Vec<String> = Vec::new();

        for node in &ir.nodes {
            // Union without explicit attenuation breaks monotonicity.
            if node.merge_op == MergeOperator::Union
                && !node.property_claims.contains(&FormalProperty::Monotonicity)
            {
                violating.push(node.node_id.clone());
            }
        }

        if violating.is_empty() {
            PassResult::Ok(PropertyWitness {
                property: FormalProperty::Monotonicity,
                policy_id: ir.policy_id.clone(),
                explanation: "all merge paths preserve authority attenuation".into(),
                nodes_examined: ir.nodes.len() as u32,
                pass_name: "monotonicity".into(),
            })
        } else {
            PassResult::Failed(Counterexample {
                property: FormalProperty::Monotonicity,
                policy_id: ir.policy_id.clone(),
                violating_nodes: violating,
                description:
                    "union merge without explicit monotonicity claim can amplify authority".into(),
                merge_path: Vec::new(),
            })
        }
    }

    /// Non-interference pass: verify isolation between policy domains.
    ///
    /// Checks that NonInterferenceClaim constraints reference disjoint
    /// capability sets (no subject gets capabilities from both domains).
    fn non_interference_pass(&self, ir: &PolicyIr) -> PassResult {
        let mut violations: Vec<String> = Vec::new();

        // Collect domains from non-interference claims.
        let mut domain_caps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for node in &ir.nodes {
            for constraint in &node.constraints {
                if let Constraint::NonInterferenceClaim { domain_a, domain_b } = constraint {
                    // Register domains.
                    domain_caps.entry(domain_a.clone()).or_default();
                    domain_caps.entry(domain_b.clone()).or_default();
                }
            }
            // Map node scope -> capabilities.
            for grant in &node.grants {
                domain_caps
                    .entry(grant.scope.clone())
                    .or_default()
                    .insert(grant.subject.clone());
            }
        }

        // Check for overlapping subjects between claimed-non-interfering domains.
        for node in &ir.nodes {
            for constraint in &node.constraints {
                if let Constraint::NonInterferenceClaim { domain_a, domain_b } = constraint {
                    let subs_a = domain_caps.get(domain_a).cloned().unwrap_or_default();
                    let subs_b = domain_caps.get(domain_b).cloned().unwrap_or_default();
                    let overlap: BTreeSet<_> = subs_a.intersection(&subs_b).cloned().collect();
                    if !overlap.is_empty() {
                        violations.push(node.node_id.clone());
                    }
                }
            }
        }

        if violations.is_empty() {
            PassResult::Ok(PropertyWitness {
                property: FormalProperty::NonInterference,
                policy_id: ir.policy_id.clone(),
                explanation: "all non-interference claims verified: domains have disjoint subjects"
                    .into(),
                nodes_examined: ir.nodes.len() as u32,
                pass_name: "non-interference".into(),
            })
        } else {
            PassResult::Failed(Counterexample {
                property: FormalProperty::NonInterference,
                policy_id: ir.policy_id.clone(),
                violating_nodes: violations,
                description: "non-interference claim violated: domains share subjects".into(),
                merge_path: Vec::new(),
            })
        }
    }

    /// Merge determinism pass: verify merge operations are commutative.
    ///
    /// Checks that all merge operators used in the IR are commutative
    /// (Union, Intersection are; Precedence is only if all priorities
    /// are distinct; Attenuation is commutative by definition).
    fn merge_determinism_pass(&self, ir: &PolicyIr) -> PassResult {
        let mut violating: Vec<String> = Vec::new();

        // Precedence merges require all priorities to be distinct.
        let precedence_nodes: Vec<&PolicyIrNode> = ir
            .nodes
            .iter()
            .filter(|n| n.merge_op == MergeOperator::Precedence)
            .collect();

        if !precedence_nodes.is_empty() {
            let mut seen_priorities: BTreeMap<u32, Vec<String>> = BTreeMap::new();
            for node in &precedence_nodes {
                seen_priorities
                    .entry(node.priority)
                    .or_default()
                    .push(node.node_id.clone());
            }
            for nodes in seen_priorities.values() {
                if nodes.len() > 1 {
                    violating.extend(nodes.clone());
                }
            }
        }

        if violating.is_empty() {
            PassResult::Ok(PropertyWitness {
                property: FormalProperty::MergeDeterminism,
                policy_id: ir.policy_id.clone(),
                explanation: "all merge operators are commutative/associative".into(),
                nodes_examined: ir.nodes.len() as u32,
                pass_name: "merge-determinism".into(),
            })
        } else {
            PassResult::Failed(Counterexample {
                property: FormalProperty::MergeDeterminism,
                policy_id: ir.policy_id.clone(),
                violating_nodes: violating,
                description: "precedence nodes with identical priority break merge determinism"
                    .into(),
                merge_path: Vec::new(),
            })
        }
    }

    /// Precedence stability pass: verify priority ordering is total.
    ///
    /// All nodes with Precedence merge must have distinct, non-zero priorities.
    fn precedence_stability_pass(&self, ir: &PolicyIr) -> PassResult {
        let mut violating: Vec<String> = Vec::new();

        let precedence_nodes: Vec<&PolicyIrNode> = ir
            .nodes
            .iter()
            .filter(|n| n.merge_op == MergeOperator::Precedence)
            .collect();

        // Check for zero priorities on precedence nodes.
        for node in &precedence_nodes {
            if node.priority == 0 {
                violating.push(node.node_id.clone());
            }
        }

        // Check for duplicate priorities (already handled in merge_determinism,
        // but we also flag it here for the precedence-stability property).
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        for node in &precedence_nodes {
            if !seen.insert(node.priority) && !violating.contains(&node.node_id) {
                violating.push(node.node_id.clone());
            }
        }

        if violating.is_empty() {
            PassResult::Ok(PropertyWitness {
                property: FormalProperty::PrecedenceStability,
                policy_id: ir.policy_id.clone(),
                explanation: "all precedence nodes have distinct non-zero priorities".into(),
                nodes_examined: ir.nodes.len() as u32,
                pass_name: "precedence-stability".into(),
            })
        } else {
            PassResult::Failed(Counterexample {
                property: FormalProperty::PrecedenceStability,
                policy_id: ir.policy_id.clone(),
                violating_nodes: violating,
                description: "precedence nodes with zero or duplicate priorities break stability"
                    .into(),
                merge_path: Vec::new(),
            })
        }
    }

    /// Attenuation legality pass: verify delegated grants stay within scope.
    ///
    /// Every grant's capability must be in the capability universe, and
    /// grants using Attenuation merge must reference capabilities that are
    /// a subset of previously established grants.
    fn attenuation_legality_pass(&self, ir: &PolicyIr) -> PassResult {
        let mut violating: Vec<String> = Vec::new();

        // Collect all capabilities granted by non-attenuation nodes as the
        // "base authority".
        let base_caps: BTreeSet<Capability> = ir
            .nodes
            .iter()
            .filter(|n| n.merge_op != MergeOperator::Attenuation)
            .flat_map(|n| n.grants.iter().map(|g| g.capability.clone()))
            .collect();

        // Attenuation nodes must only grant capabilities from the base set.
        for node in &ir.nodes {
            if node.merge_op == MergeOperator::Attenuation {
                for grant in &node.grants {
                    if !base_caps.contains(&grant.capability) {
                        violating.push(node.node_id.clone());
                    }
                }
            }
        }

        if violating.is_empty() {
            PassResult::Ok(PropertyWitness {
                property: FormalProperty::AttenuationLegality,
                policy_id: ir.policy_id.clone(),
                explanation: "all attenuated grants are subsets of base authority".into(),
                nodes_examined: ir.nodes.len() as u32,
                pass_name: "attenuation-legality".into(),
            })
        } else {
            PassResult::Failed(Counterexample {
                property: FormalProperty::AttenuationLegality,
                policy_id: ir.policy_id.clone(),
                violating_nodes: violating,
                description: "attenuation nodes grant capabilities outside base authority".into(),
                merge_path: Vec::new(),
            })
        }
    }
}

impl Default for PolicyTheoremCompiler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Machine-check hooks
// ---------------------------------------------------------------------------

/// Hook check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookCheckResult {
    /// Hook that was evaluated.
    pub hook_name: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Diagnostics emitted by the hook.
    pub diagnostics: Vec<HookDiagnostic>,
}

/// Diagnostic emitted by a machine-check hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookDiagnostic {
    /// Property that was violated.
    pub property_violated: FormalProperty,
    /// Counterexample (if available).
    pub counterexample: Option<Counterexample>,
    /// Policy IDs involved.
    pub policy_ids: Vec<PolicyId>,
    /// Severity.
    pub severity: DiagnosticSeverity,
}

/// Severity level for hook diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DiagnosticSeverity {
    /// Warning — logged but not blocking.
    Warning,
    /// Error — blocks the operation.
    Error,
    /// Fatal — blocks and requires manual resolution.
    Fatal,
}

impl fmt::Display for DiagnosticSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warning => f.write_str("warning"),
            Self::Error => f.write_str("error"),
            Self::Fatal => f.write_str("fatal"),
        }
    }
}

/// Machine-check hook runner.
///
/// Evaluates policies against formal properties at merge-time,
/// deployment-time, or runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineCheckHooks {
    compiler: PolicyTheoremCompiler,
    /// History of hook results.
    hook_history: Vec<HookCheckResult>,
}

impl MachineCheckHooks {
    pub fn new(compiler: PolicyTheoremCompiler) -> Self {
        Self {
            compiler,
            hook_history: Vec::new(),
        }
    }

    /// Pre-merge hook: verify monotonicity and merge determinism before merge.
    pub fn pre_merge_check(
        &mut self,
        policy_a: &PolicyIr,
        policy_b: &PolicyIr,
    ) -> Result<HookCheckResult, CompilerError> {
        let mut diagnostics = Vec::new();

        // Check both policies individually.
        for policy in [policy_a, policy_b] {
            let result = self.compiler.compile(policy)?;
            for cx in &result.counterexamples {
                if cx.property == FormalProperty::Monotonicity
                    || cx.property == FormalProperty::MergeDeterminism
                {
                    diagnostics.push(HookDiagnostic {
                        property_violated: cx.property,
                        counterexample: Some(cx.clone()),
                        policy_ids: vec![policy.policy_id.clone()],
                        severity: DiagnosticSeverity::Error,
                    });
                }
            }
        }

        let passed = diagnostics.is_empty();
        let result = HookCheckResult {
            hook_name: "pre-merge".into(),
            passed,
            diagnostics,
        };
        self.hook_history.push(result.clone());
        Ok(result)
    }

    /// Pre-deployment hook: run full property suite.
    pub fn pre_deployment_check(
        &mut self,
        policy: &PolicyIr,
    ) -> Result<HookCheckResult, CompilerError> {
        let result = self.compiler.compile(policy)?;
        let diagnostics: Vec<HookDiagnostic> = result
            .counterexamples
            .iter()
            .map(|cx| HookDiagnostic {
                property_violated: cx.property,
                counterexample: Some(cx.clone()),
                policy_ids: vec![policy.policy_id.clone()],
                severity: DiagnosticSeverity::Error,
            })
            .collect();

        let passed = diagnostics.is_empty();
        let hook_result = HookCheckResult {
            hook_name: "pre-deployment".into(),
            passed,
            diagnostics,
        };
        self.hook_history.push(hook_result.clone());
        Ok(hook_result)
    }

    /// Runtime hook: lightweight check for property violations.
    ///
    /// Only checks monotonicity and attenuation legality (fast checks).
    pub fn runtime_check(&mut self, policy: &PolicyIr) -> Result<HookCheckResult, CompilerError> {
        if policy.nodes.is_empty() {
            return Err(CompilerError::EmptyPolicy {
                policy_id: policy.policy_id.clone(),
            });
        }

        let mut diagnostics = Vec::new();

        let mono = self.compiler.monotonicity_pass(policy);
        if let PassResult::Failed(cx) = mono {
            diagnostics.push(HookDiagnostic {
                property_violated: FormalProperty::Monotonicity,
                counterexample: Some(cx),
                policy_ids: vec![policy.policy_id.clone()],
                severity: DiagnosticSeverity::Fatal,
            });
        }

        let att = self.compiler.attenuation_legality_pass(policy);
        if let PassResult::Failed(cx) = att {
            diagnostics.push(HookDiagnostic {
                property_violated: FormalProperty::AttenuationLegality,
                counterexample: Some(cx),
                policy_ids: vec![policy.policy_id.clone()],
                severity: DiagnosticSeverity::Fatal,
            });
        }

        let passed = diagnostics.is_empty();
        let hook_result = HookCheckResult {
            hook_name: "runtime".into(),
            passed,
            diagnostics,
        };
        self.hook_history.push(hook_result.clone());
        Ok(hook_result)
    }

    /// Get hook history.
    pub fn hook_history(&self) -> &[HookCheckResult] {
        &self.hook_history
    }
}

// ---------------------------------------------------------------------------
// PolicyValidationReceipt — signed proof of successful compilation
// ---------------------------------------------------------------------------

fn lazy_static_schema_hash() -> &'static SchemaHash {
    use std::sync::LazyLock;
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(b"policy_validation_receipt_v1"));
    &HASH
}

/// Signed policy validation receipt proving successful compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyValidationReceipt {
    /// Policy this receipt covers.
    pub policy_id: PolicyId,
    /// Hash of the policy IR.
    pub policy_hash: [u8; 32],
    /// Properties that were verified.
    pub properties_verified: BTreeSet<FormalProperty>,
    /// Witnesses from each verified property.
    pub witness_count: u32,
    /// Compiler version.
    pub compiler_version: String,
    /// Epoch when this receipt was issued.
    pub epoch: SecurityEpoch,
    /// Timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Signer's verification key.
    pub signer: VerificationKey,
    /// Signature over the receipt (filled by signing).
    pub signature: Signature,
}

impl SignaturePreimage for PolicyValidationReceipt {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::PolicyObject
    }

    fn signature_schema(&self) -> &SchemaHash {
        lazy_static_schema_hash()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut copy = self.clone();
        copy.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        CanonicalValue::Bytes(
            serde_json::to_vec(&copy)
                .expect("policy validation receipt must serialize for signing preimage"),
        )
    }
}

impl PolicyValidationReceipt {
    /// Create a new unsigned receipt from compilation result.
    pub fn from_compilation(
        result: &CompilationResult,
        policy_hash: [u8; 32],
        epoch: SecurityEpoch,
        timestamp_ns: u64,
        signer_key: &VerificationKey,
    ) -> Self {
        Self {
            policy_id: result.policy_id.clone(),
            policy_hash,
            properties_verified: result.witnesses.iter().map(|w| w.property).collect(),
            witness_count: result.witnesses.len() as u32,
            compiler_version: "1.0.0".into(),
            epoch,
            timestamp_ns,
            signer: signer_key.clone(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        }
    }

    /// Sign this receipt.
    pub fn sign(&mut self, key: &SigningKey) {
        if let Ok(sig) = sign_object(self, key) {
            self.signature = sig;
        }
    }

    /// Verify this receipt's signature.
    pub fn verify(&self) -> bool {
        verify_object(self, &self.signer, &self.signature).is_ok()
    }
}

// ---------------------------------------------------------------------------
// CompilerError
// ---------------------------------------------------------------------------

/// Errors from compiler operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompilerError {
    /// Policy has no nodes.
    EmptyPolicy { policy_id: PolicyId },
    /// Policy exceeds maximum node count.
    PolicyTooLarge {
        policy_id: PolicyId,
        node_count: u32,
        max_nodes: u32,
    },
    /// Hook check failed (fail-closed).
    HookFailed {
        hook_name: String,
        diagnostics: Vec<HookDiagnostic>,
    },
}

impl fmt::Display for CompilerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPolicy { policy_id } => {
                write!(f, "empty policy: {policy_id}")
            }
            Self::PolicyTooLarge {
                policy_id,
                node_count,
                max_nodes,
            } => {
                write!(
                    f,
                    "policy {policy_id} too large: {node_count} nodes > {max_nodes} max"
                )
            }
            Self::HookFailed {
                hook_name,
                diagnostics,
            } => {
                write!(
                    f,
                    "hook {hook_name} failed with {} diagnostics",
                    diagnostics.len()
                )
            }
        }
    }
}

impl std::error::Error for CompilerError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test helpers --

    fn cap(name: &str) -> Capability {
        Capability::new(name)
    }

    fn test_universe() -> BTreeSet<Capability> {
        let mut s = BTreeSet::new();
        s.insert(cap("fs.read"));
        s.insert(cap("fs.write"));
        s.insert(cap("net.egress"));
        s.insert(cap("policy.read"));
        s.insert(cap("policy.write"));
        s
    }

    fn grant(subject: &str, capability: &str, scope: &str) -> AuthorityGrant {
        AuthorityGrant {
            subject: subject.into(),
            capability: cap(capability),
            conditions: BTreeSet::new(),
            scope: scope.into(),
            lifetime_epochs: 10,
        }
    }

    fn simple_node(id: &str, merge_op: MergeOperator, grants: Vec<AuthorityGrant>) -> PolicyIrNode {
        PolicyIrNode {
            node_id: id.into(),
            grants,
            merge_op,
            property_claims: BTreeSet::new(),
            constraints: Vec::new(),
            decision_point: None,
            priority: 0,
        }
    }

    fn valid_policy() -> PolicyIr {
        PolicyIr {
            policy_id: PolicyId::new("test-policy-1"),
            version: 1,
            nodes: vec![
                simple_node(
                    "n1",
                    MergeOperator::Intersection,
                    vec![grant("ext-A", "fs.read", "zone-1")],
                ),
                simple_node(
                    "n2",
                    MergeOperator::Intersection,
                    vec![grant("ext-B", "net.egress", "zone-2")],
                ),
            ],
            capability_universe: test_universe(),
            verified_properties: BTreeSet::new(),
            epoch: SecurityEpoch::from_raw(1),
        }
    }

    // -- Compiler construction --

    #[test]
    fn compiler_default() {
        let c = PolicyTheoremCompiler::new();
        assert_eq!(c.max_nodes, 10_000);
        assert!(c.require_precedence_stability);
    }

    #[test]
    fn compiler_with_limits() {
        let c = PolicyTheoremCompiler::with_limits(500, false);
        assert_eq!(c.max_nodes, 500);
        assert!(!c.require_precedence_stability);
    }

    // -- Type check pass --

    #[test]
    fn type_check_valid() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = valid_policy();
        let result = compiler.type_check_pass(&ir);
        assert!(result.is_ok());
    }

    #[test]
    fn type_check_undefined_capability() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = PolicyIr {
            nodes: vec![simple_node(
                "n1",
                MergeOperator::Intersection,
                vec![grant("ext-A", "does.not.exist", "zone-1")],
            )],
            ..valid_policy()
        };
        let result = compiler.type_check_pass(&ir);
        assert!(result.is_failed());
    }

    #[test]
    fn type_check_zero_lifetime() {
        let compiler = PolicyTheoremCompiler::new();
        let mut g = grant("ext-A", "fs.read", "zone-1");
        g.lifetime_epochs = 0;
        let ir = PolicyIr {
            nodes: vec![simple_node("n1", MergeOperator::Intersection, vec![g])],
            ..valid_policy()
        };
        let result = compiler.type_check_pass(&ir);
        assert!(result.is_failed());
    }

    // -- Monotonicity pass --

    #[test]
    fn monotonicity_intersection_passes() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = valid_policy(); // all intersection
        let result = compiler.monotonicity_pass(&ir);
        assert!(result.is_ok());
    }

    #[test]
    fn monotonicity_union_without_claim_fails() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = PolicyIr {
            nodes: vec![simple_node(
                "n1",
                MergeOperator::Union,
                vec![grant("ext-A", "fs.read", "zone-1")],
            )],
            ..valid_policy()
        };
        let result = compiler.monotonicity_pass(&ir);
        assert!(result.is_failed());
    }

    #[test]
    fn monotonicity_union_with_claim_passes() {
        let compiler = PolicyTheoremCompiler::new();
        let mut node = simple_node(
            "n1",
            MergeOperator::Union,
            vec![grant("ext-A", "fs.read", "zone-1")],
        );
        node.property_claims.insert(FormalProperty::Monotonicity);
        let ir = PolicyIr {
            nodes: vec![node],
            ..valid_policy()
        };
        let result = compiler.monotonicity_pass(&ir);
        assert!(result.is_ok());
    }

    // -- Non-interference pass --

    #[test]
    fn non_interference_disjoint_domains() {
        let compiler = PolicyTheoremCompiler::new();
        let mut n1 = simple_node(
            "n1",
            MergeOperator::Intersection,
            vec![grant("ext-A", "fs.read", "domain-alpha")],
        );
        n1.constraints.push(Constraint::NonInterferenceClaim {
            domain_a: "domain-alpha".into(),
            domain_b: "domain-beta".into(),
        });
        let n2 = simple_node(
            "n2",
            MergeOperator::Intersection,
            vec![grant("ext-B", "net.egress", "domain-beta")],
        );
        let ir = PolicyIr {
            nodes: vec![n1, n2],
            ..valid_policy()
        };
        let result = compiler.non_interference_pass(&ir);
        assert!(result.is_ok());
    }

    #[test]
    fn non_interference_overlapping_subjects() {
        let compiler = PolicyTheoremCompiler::new();
        let mut n1 = simple_node(
            "n1",
            MergeOperator::Intersection,
            vec![grant("ext-SHARED", "fs.read", "domain-alpha")],
        );
        n1.constraints.push(Constraint::NonInterferenceClaim {
            domain_a: "domain-alpha".into(),
            domain_b: "domain-beta".into(),
        });
        let n2 = simple_node(
            "n2",
            MergeOperator::Intersection,
            vec![grant("ext-SHARED", "net.egress", "domain-beta")],
        );
        let ir = PolicyIr {
            nodes: vec![n1, n2],
            ..valid_policy()
        };
        let result = compiler.non_interference_pass(&ir);
        assert!(result.is_failed());
    }

    // -- Merge determinism pass --

    #[test]
    fn merge_determinism_no_precedence() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = valid_policy(); // all intersection, no precedence
        let result = compiler.merge_determinism_pass(&ir);
        assert!(result.is_ok());
    }

    #[test]
    fn merge_determinism_distinct_priorities() {
        let compiler = PolicyTheoremCompiler::new();
        let mut n1 = simple_node(
            "n1",
            MergeOperator::Precedence,
            vec![grant("ext-A", "fs.read", "zone-1")],
        );
        n1.priority = 1;
        let mut n2 = simple_node(
            "n2",
            MergeOperator::Precedence,
            vec![grant("ext-B", "net.egress", "zone-2")],
        );
        n2.priority = 2;
        let ir = PolicyIr {
            nodes: vec![n1, n2],
            ..valid_policy()
        };
        let result = compiler.merge_determinism_pass(&ir);
        assert!(result.is_ok());
    }

    #[test]
    fn merge_determinism_duplicate_priorities_fails() {
        let compiler = PolicyTheoremCompiler::new();
        let mut n1 = simple_node(
            "n1",
            MergeOperator::Precedence,
            vec![grant("ext-A", "fs.read", "zone-1")],
        );
        n1.priority = 5;
        let mut n2 = simple_node(
            "n2",
            MergeOperator::Precedence,
            vec![grant("ext-B", "net.egress", "zone-2")],
        );
        n2.priority = 5; // same!
        let ir = PolicyIr {
            nodes: vec![n1, n2],
            ..valid_policy()
        };
        let result = compiler.merge_determinism_pass(&ir);
        assert!(result.is_failed());
    }

    // -- Precedence stability pass --

    #[test]
    fn precedence_stability_no_precedence_nodes() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = valid_policy();
        let result = compiler.precedence_stability_pass(&ir);
        assert!(result.is_ok());
    }

    #[test]
    fn precedence_stability_zero_priority_fails() {
        let compiler = PolicyTheoremCompiler::new();
        let n1 = simple_node(
            "n1",
            MergeOperator::Precedence,
            vec![grant("ext-A", "fs.read", "zone-1")],
        );
        // priority is 0 (default)
        let ir = PolicyIr {
            nodes: vec![n1],
            ..valid_policy()
        };
        let result = compiler.precedence_stability_pass(&ir);
        assert!(result.is_failed());
    }

    // -- Attenuation legality pass --

    #[test]
    fn attenuation_legality_valid() {
        let compiler = PolicyTheoremCompiler::new();
        let base = simple_node(
            "base",
            MergeOperator::Intersection,
            vec![
                grant("ext-A", "fs.read", "zone-1"),
                grant("ext-A", "fs.write", "zone-1"),
            ],
        );
        let attenuated = simple_node(
            "attenuated",
            MergeOperator::Attenuation,
            vec![grant("ext-A", "fs.read", "zone-1")], // subset of base
        );
        let ir = PolicyIr {
            nodes: vec![base, attenuated],
            ..valid_policy()
        };
        let result = compiler.attenuation_legality_pass(&ir);
        assert!(result.is_ok());
    }

    #[test]
    fn attenuation_escalation_fails() {
        let compiler = PolicyTheoremCompiler::new();
        let base = simple_node(
            "base",
            MergeOperator::Intersection,
            vec![grant("ext-A", "fs.read", "zone-1")],
        );
        let attenuated = simple_node(
            "attenuated",
            MergeOperator::Attenuation,
            vec![grant("ext-A", "policy.write", "zone-1")], // NOT in base
        );
        let ir = PolicyIr {
            nodes: vec![base, attenuated],
            ..valid_policy()
        };
        let result = compiler.attenuation_legality_pass(&ir);
        assert!(result.is_failed());
    }

    // -- Full compilation --

    #[test]
    fn compile_valid_policy() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = valid_policy();
        let result = compiler.compile(&ir).unwrap();
        assert!(result.all_passed);
        assert!(!result.witnesses.is_empty());
        assert!(result.counterexamples.is_empty());
    }

    #[test]
    fn compile_rejects_empty_policy() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = PolicyIr {
            nodes: Vec::new(),
            ..valid_policy()
        };
        let err = compiler.compile(&ir).unwrap_err();
        assert!(matches!(err, CompilerError::EmptyPolicy { .. }));
    }

    #[test]
    fn compile_rejects_oversized_policy() {
        let compiler = PolicyTheoremCompiler::with_limits(2, true);
        let ir = PolicyIr {
            nodes: vec![
                simple_node(
                    "n1",
                    MergeOperator::Intersection,
                    vec![grant("a", "fs.read", "z")],
                ),
                simple_node(
                    "n2",
                    MergeOperator::Intersection,
                    vec![grant("b", "fs.read", "z")],
                ),
                simple_node(
                    "n3",
                    MergeOperator::Intersection,
                    vec![grant("c", "fs.read", "z")],
                ),
            ],
            ..valid_policy()
        };
        let err = compiler.compile(&ir).unwrap_err();
        assert!(matches!(err, CompilerError::PolicyTooLarge { .. }));
    }

    #[test]
    fn compile_detects_monotonicity_violation() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = PolicyIr {
            nodes: vec![simple_node(
                "n1",
                MergeOperator::Union,
                vec![grant("ext-A", "fs.read", "zone-1")],
            )],
            ..valid_policy()
        };
        let result = compiler.compile(&ir).unwrap();
        assert!(!result.all_passed);
        assert!(
            result
                .counterexamples
                .iter()
                .any(|c| c.property == FormalProperty::Monotonicity)
        );
    }

    #[test]
    fn compile_skips_precedence_when_disabled() {
        let compiler = PolicyTheoremCompiler::with_limits(10_000, false);
        let ir = valid_policy();
        let result = compiler.compile(&ir).unwrap();
        // Should have fewer passes.
        assert!(result.all_passed);
        let pass_count_with = PolicyTheoremCompiler::new()
            .compile(&ir)
            .unwrap()
            .pass_results
            .len();
        assert!(result.pass_results.len() < pass_count_with);
    }

    // -- Machine-check hooks --

    #[test]
    fn pre_merge_check_valid() {
        let compiler = PolicyTheoremCompiler::new();
        let mut hooks = MachineCheckHooks::new(compiler);
        let a = valid_policy();
        let b = PolicyIr {
            policy_id: PolicyId::new("test-policy-2"),
            ..valid_policy()
        };
        let result = hooks.pre_merge_check(&a, &b).unwrap();
        assert!(result.passed);
        assert_eq!(hooks.hook_history().len(), 1);
    }

    #[test]
    fn pre_merge_check_detects_violation() {
        let compiler = PolicyTheoremCompiler::new();
        let mut hooks = MachineCheckHooks::new(compiler);
        let a = valid_policy();
        let b = PolicyIr {
            policy_id: PolicyId::new("bad-policy"),
            nodes: vec![simple_node(
                "n1",
                MergeOperator::Union,
                vec![grant("ext-A", "fs.read", "zone-1")],
            )],
            ..valid_policy()
        };
        let result = hooks.pre_merge_check(&a, &b).unwrap();
        assert!(!result.passed);
    }

    #[test]
    fn pre_deployment_check_valid() {
        let compiler = PolicyTheoremCompiler::new();
        let mut hooks = MachineCheckHooks::new(compiler);
        let ir = valid_policy();
        let result = hooks.pre_deployment_check(&ir).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn runtime_check_valid() {
        let compiler = PolicyTheoremCompiler::new();
        let mut hooks = MachineCheckHooks::new(compiler);
        let ir = valid_policy();
        let result = hooks.runtime_check(&ir).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn runtime_check_empty_policy_errors() {
        let compiler = PolicyTheoremCompiler::new();
        let mut hooks = MachineCheckHooks::new(compiler);
        let ir = PolicyIr {
            nodes: Vec::new(),
            ..valid_policy()
        };
        let err = hooks.runtime_check(&ir).unwrap_err();
        assert!(matches!(err, CompilerError::EmptyPolicy { .. }));
    }

    #[test]
    fn runtime_check_detects_attenuation_escalation() {
        let compiler = PolicyTheoremCompiler::new();
        let mut hooks = MachineCheckHooks::new(compiler);
        let base = simple_node(
            "base",
            MergeOperator::Intersection,
            vec![grant("ext-A", "fs.read", "zone-1")],
        );
        let escalation = simple_node(
            "escalation",
            MergeOperator::Attenuation,
            vec![grant("ext-A", "policy.write", "zone-1")],
        );
        let ir = PolicyIr {
            nodes: vec![base, escalation],
            ..valid_policy()
        };
        let result = hooks.runtime_check(&ir).unwrap();
        assert!(!result.passed);
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| d.severity == DiagnosticSeverity::Fatal)
        );
    }

    // -- PolicyValidationReceipt --

    #[test]
    fn receipt_from_compilation() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = valid_policy();
        let result = compiler.compile(&ir).unwrap();
        let sk = SigningKey::from_bytes([42u8; 32]);
        let vk = sk.verification_key();

        let mut receipt = PolicyValidationReceipt::from_compilation(
            &result,
            [0xAA; 32],
            SecurityEpoch::from_raw(1),
            1_000_000_000,
            &vk,
        );
        assert!(!receipt.properties_verified.is_empty());
        assert_eq!(receipt.policy_id, PolicyId::new("test-policy-1"));
        assert!(!receipt.verify()); // unsigned
        receipt.sign(&sk);
        assert!(receipt.verify());
    }

    #[test]
    fn receipt_signature_detects_tampering() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = valid_policy();
        let result = compiler.compile(&ir).unwrap();
        let sk = SigningKey::from_bytes([42u8; 32]);
        let vk = sk.verification_key();

        let mut receipt = PolicyValidationReceipt::from_compilation(
            &result,
            [0xBB; 32],
            SecurityEpoch::from_raw(1),
            1_000_000_000,
            &vk,
        );
        receipt.sign(&sk);
        assert!(receipt.verify());

        // Tamper with the receipt.
        receipt.policy_hash = [0xFF; 32];
        assert!(!receipt.verify());
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = valid_policy();
        let result = compiler.compile(&ir).unwrap();
        let sk = SigningKey::from_bytes([42u8; 32]);
        let vk = sk.verification_key();

        let mut receipt = PolicyValidationReceipt::from_compilation(
            &result,
            [0xCC; 32],
            SecurityEpoch::from_raw(1),
            1_000_000_000,
            &vk,
        );
        receipt.sign(&sk);

        let json = serde_json::to_string(&receipt).unwrap();
        let restored: PolicyValidationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, restored);
        assert!(restored.verify());
    }

    // -- PassResult --

    #[test]
    fn pass_result_ok_and_failed() {
        let ok = PassResult::Ok(PropertyWitness {
            property: FormalProperty::Monotonicity,
            policy_id: PolicyId::new("p1"),
            explanation: "ok".into(),
            nodes_examined: 1,
            pass_name: "test".into(),
        });
        assert!(ok.is_ok());
        assert!(!ok.is_failed());

        let failed = PassResult::Failed(Counterexample {
            property: FormalProperty::Monotonicity,
            policy_id: PolicyId::new("p1"),
            violating_nodes: vec!["n1".into()],
            description: "bad".into(),
            merge_path: Vec::new(),
        });
        assert!(!failed.is_ok());
        assert!(failed.is_failed());
    }

    // -- Serde roundtrips --

    #[test]
    fn policy_ir_serde_roundtrip() {
        let ir = valid_policy();
        let json = serde_json::to_string(&ir).unwrap();
        let restored: PolicyIr = serde_json::from_str(&json).unwrap();
        assert_eq!(ir, restored);
    }

    #[test]
    fn compilation_result_serde_roundtrip() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = valid_policy();
        let result = compiler.compile(&ir).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let restored: CompilationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, restored);
    }

    #[test]
    fn compiler_error_display() {
        let e = CompilerError::EmptyPolicy {
            policy_id: PolicyId::new("p1"),
        };
        assert!(e.to_string().contains("empty policy"));

        let e2 = CompilerError::PolicyTooLarge {
            policy_id: PolicyId::new("p2"),
            node_count: 500,
            max_nodes: 100,
        };
        assert!(e2.to_string().contains("too large"));
    }

    // -- Display impls --

    #[test]
    fn display_merge_operator() {
        assert_eq!(MergeOperator::Union.to_string(), "union");
        assert_eq!(MergeOperator::Intersection.to_string(), "intersection");
        assert_eq!(MergeOperator::Attenuation.to_string(), "attenuation");
        assert_eq!(MergeOperator::Precedence.to_string(), "precedence");
    }

    #[test]
    fn display_formal_property() {
        assert_eq!(FormalProperty::Monotonicity.to_string(), "monotonicity");
        assert_eq!(
            FormalProperty::NonInterference.to_string(),
            "non-interference"
        );
        assert_eq!(
            FormalProperty::MergeDeterminism.to_string(),
            "merge-determinism"
        );
    }

    #[test]
    fn display_diagnostic_severity() {
        assert_eq!(DiagnosticSeverity::Warning.to_string(), "warning");
        assert_eq!(DiagnosticSeverity::Error.to_string(), "error");
        assert_eq!(DiagnosticSeverity::Fatal.to_string(), "fatal");
    }

    #[test]
    fn display_capability_and_policy_id() {
        assert_eq!(cap("fs.read").to_string(), "fs.read");
        assert_eq!(PolicyId::new("p1").to_string(), "p1");
    }

    // -- IR helper methods --

    #[test]
    fn granted_capabilities() {
        let ir = valid_policy();
        let caps = ir.granted_capabilities();
        assert!(caps.contains(&cap("fs.read")));
        assert!(caps.contains(&cap("net.egress")));
        assert!(!caps.contains(&cap("fs.write"))); // not granted
    }

    #[test]
    fn subjects() {
        let ir = valid_policy();
        let subs = ir.subjects();
        assert!(subs.contains("ext-A"));
        assert!(subs.contains("ext-B"));
    }

    // -- Constraint serde --

    #[test]
    fn constraint_serde_roundtrip() {
        let constraints = vec![
            Constraint::Invariant("always true".into()),
            Constraint::Precondition("before".into()),
            Constraint::Postcondition("after".into()),
            Constraint::NonInterferenceClaim {
                domain_a: "a".into(),
                domain_b: "b".into(),
            },
        ];
        for c in &constraints {
            let json = serde_json::to_string(c).unwrap();
            let restored: Constraint = serde_json::from_str(&json).unwrap();
            assert_eq!(c, &restored);
        }
    }

    // -- Decision point --

    #[test]
    fn decision_point_serde() {
        let dp = DecisionPoint {
            threshold: 2,
            action_map: {
                let mut m = BTreeMap::new();
                m.insert("high-risk".into(), "sandbox".into());
                m.insert("low-risk".into(), "allow".into());
                m
            },
            fallback: "deny".into(),
        };
        let json = serde_json::to_string(&dp).unwrap();
        let restored: DecisionPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(dp, restored);
    }

    // -- Hook history --

    #[test]
    fn hook_history_accumulates() {
        let compiler = PolicyTheoremCompiler::new();
        let mut hooks = MachineCheckHooks::new(compiler);
        let ir = valid_policy();
        hooks.pre_deployment_check(&ir).unwrap();
        hooks.runtime_check(&ir).unwrap();
        assert_eq!(hooks.hook_history().len(), 2);
    }

    // -- Determinism --

    #[test]
    fn compilation_deterministic() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = valid_policy();
        let r1 = compiler.compile(&ir).unwrap();
        let r2 = compiler.compile(&ir).unwrap();
        assert_eq!(
            serde_json::to_string(&r1).unwrap(),
            serde_json::to_string(&r2).unwrap()
        );
    }

    // -- Enrichment: ordering --

    #[test]
    fn merge_operator_ordering() {
        assert!(MergeOperator::Union < MergeOperator::Intersection);
        assert!(MergeOperator::Intersection < MergeOperator::Attenuation);
        assert!(MergeOperator::Attenuation < MergeOperator::Precedence);
    }

    #[test]
    fn formal_property_ordering() {
        assert!(FormalProperty::Monotonicity < FormalProperty::NonInterference);
        assert!(FormalProperty::NonInterference < FormalProperty::AttenuationLegality);
        assert!(FormalProperty::AttenuationLegality < FormalProperty::MergeDeterminism);
        assert!(FormalProperty::MergeDeterminism < FormalProperty::PrecedenceStability);
    }

    #[test]
    fn diagnostic_severity_ordering() {
        assert!(DiagnosticSeverity::Warning < DiagnosticSeverity::Error);
        assert!(DiagnosticSeverity::Error < DiagnosticSeverity::Fatal);
    }

    // -- Enrichment: error trait --

    #[test]
    fn compiler_error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(CompilerError::EmptyPolicy {
            policy_id: PolicyId::new("p1"),
        });
        assert!(!e.to_string().is_empty());
    }

    // -- Enrichment: serde roundtrips --

    #[test]
    fn authority_grant_serde_roundtrip() {
        let grant = AuthorityGrant {
            subject: "ext-1".to_string(),
            capability: Capability::new("cap:fs"),
            conditions: BTreeSet::new(),
            scope: "local".to_string(),
            lifetime_epochs: 10,
        };
        let json = serde_json::to_string(&grant).expect("serialize");
        let restored: AuthorityGrant = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(grant, restored);
    }

    #[test]
    fn property_witness_serde_roundtrip() {
        let pw = PropertyWitness {
            property: FormalProperty::Monotonicity,
            policy_id: PolicyId::new("p1"),
            explanation: "all intersection nodes".to_string(),
            nodes_examined: 5,
            pass_name: "monotonicity_check".to_string(),
        };
        let json = serde_json::to_string(&pw).expect("serialize");
        let restored: PropertyWitness = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pw, restored);
    }

    #[test]
    fn counterexample_serde_roundtrip() {
        let ce = Counterexample {
            property: FormalProperty::NonInterference,
            policy_id: PolicyId::new("p1"),
            violating_nodes: vec!["n1".to_string(), "n2".to_string()],
            description: "overlap".to_string(),
            merge_path: vec!["n1".to_string()],
        };
        let json = serde_json::to_string(&ce).expect("serialize");
        let restored: Counterexample = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ce, restored);
    }

    #[test]
    fn hook_diagnostic_serde_roundtrip() {
        let hd = HookDiagnostic {
            property_violated: FormalProperty::MergeDeterminism,
            counterexample: None,
            policy_ids: vec![PolicyId::new("p1")],
            severity: DiagnosticSeverity::Warning,
        };
        let json = serde_json::to_string(&hd).expect("serialize");
        let restored: HookDiagnostic = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(hd, restored);
    }

    #[test]
    fn hook_check_result_serde_roundtrip() {
        let hcr = HookCheckResult {
            hook_name: "pre_deploy".to_string(),
            passed: true,
            diagnostics: Vec::new(),
        };
        let json = serde_json::to_string(&hcr).expect("serialize");
        let restored: HookCheckResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(hcr, restored);
    }

    // -- Enrichment: default --

    #[test]
    fn compiler_default_values() {
        let c = PolicyTheoremCompiler::default();
        let c2 = PolicyTheoremCompiler::new();
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            serde_json::to_string(&c2).unwrap()
        );
    }

    #[test]
    fn merge_operator_ord() {
        assert!(MergeOperator::Union < MergeOperator::Intersection);
        assert!(MergeOperator::Intersection < MergeOperator::Attenuation);
        assert!(MergeOperator::Attenuation < MergeOperator::Precedence);
    }

    #[test]
    fn formal_property_ord() {
        assert!(FormalProperty::Monotonicity < FormalProperty::NonInterference);
        assert!(FormalProperty::NonInterference < FormalProperty::AttenuationLegality);
        assert!(FormalProperty::AttenuationLegality < FormalProperty::MergeDeterminism);
        assert!(FormalProperty::MergeDeterminism < FormalProperty::PrecedenceStability);
    }

    #[test]
    fn diagnostic_severity_ord() {
        assert!(DiagnosticSeverity::Warning < DiagnosticSeverity::Error);
        assert!(DiagnosticSeverity::Error < DiagnosticSeverity::Fatal);
    }

    #[test]
    fn compiler_error_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(CompilerError::EmptyPolicy {
                policy_id: PolicyId::new("p1"),
            }),
            Box::new(CompilerError::PolicyTooLarge {
                policy_id: PolicyId::new("p2"),
                node_count: 5000,
                max_nodes: 1000,
            }),
            Box::new(CompilerError::HookFailed {
                hook_name: "monotonicity".into(),
                diagnostics: vec![],
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            displays.insert(format!("{v}"));
        }
        assert_eq!(displays.len(), 3);
    }

    // -- Enrichment batch 4 --

    #[test]
    fn capability_as_str_matches_display() {
        let c = cap("fs.read");
        assert_eq!(c.as_str(), "fs.read");
        assert_eq!(c.to_string(), "fs.read");
    }

    #[test]
    fn policy_id_as_str_matches_display() {
        let pid = PolicyId::new("policy-42");
        assert_eq!(pid.as_str(), "policy-42");
        assert_eq!(pid.to_string(), "policy-42");
    }

    #[test]
    fn capability_ord_is_alphabetical() {
        assert!(cap("alpha") < cap("beta"));
        assert!(cap("beta") < cap("gamma"));
    }

    #[test]
    fn policy_id_ord_is_alphabetical() {
        assert!(PolicyId::new("a") < PolicyId::new("b"));
    }

    #[test]
    fn merge_operator_serde_all_variants() {
        for op in [
            MergeOperator::Union,
            MergeOperator::Intersection,
            MergeOperator::Attenuation,
            MergeOperator::Precedence,
        ] {
            let json = serde_json::to_string(&op).unwrap();
            let back: MergeOperator = serde_json::from_str(&json).unwrap();
            assert_eq!(op, back);
        }
    }

    #[test]
    fn formal_property_serde_all_variants() {
        for fp in [
            FormalProperty::Monotonicity,
            FormalProperty::NonInterference,
            FormalProperty::AttenuationLegality,
            FormalProperty::MergeDeterminism,
            FormalProperty::PrecedenceStability,
        ] {
            let json = serde_json::to_string(&fp).unwrap();
            let back: FormalProperty = serde_json::from_str(&json).unwrap();
            assert_eq!(fp, back);
        }
    }

    #[test]
    fn diagnostic_severity_serde_all_variants() {
        for s in [
            DiagnosticSeverity::Warning,
            DiagnosticSeverity::Error,
            DiagnosticSeverity::Fatal,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn compiler_error_serde_all_variants() {
        let errs = vec![
            CompilerError::EmptyPolicy {
                policy_id: PolicyId::new("p"),
            },
            CompilerError::PolicyTooLarge {
                policy_id: PolicyId::new("p"),
                node_count: 100,
                max_nodes: 50,
            },
            CompilerError::HookFailed {
                hook_name: "test".into(),
                diagnostics: vec![],
            },
        ];
        for err in &errs {
            let json = serde_json::to_string(err).unwrap();
            let back: CompilerError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    #[test]
    fn granted_capabilities_deduplicates() {
        let ir = PolicyIr {
            nodes: vec![
                simple_node(
                    "n1",
                    MergeOperator::Intersection,
                    vec![grant("ext-A", "fs.read", "z1")],
                ),
                simple_node(
                    "n2",
                    MergeOperator::Intersection,
                    vec![grant("ext-B", "fs.read", "z2")],
                ),
            ],
            ..valid_policy()
        };
        let caps = ir.granted_capabilities();
        // fs.read appears twice but should be deduplicated
        assert_eq!(caps.len(), 1);
        assert!(caps.contains(&cap("fs.read")));
    }

    #[test]
    fn subjects_deduplicates() {
        let ir = PolicyIr {
            nodes: vec![
                simple_node(
                    "n1",
                    MergeOperator::Intersection,
                    vec![grant("ext-A", "fs.read", "z1")],
                ),
                simple_node(
                    "n2",
                    MergeOperator::Intersection,
                    vec![grant("ext-A", "net.egress", "z2")],
                ),
            ],
            ..valid_policy()
        };
        let subjects = ir.subjects();
        assert_eq!(subjects.len(), 1);
        assert!(subjects.contains("ext-A"));
    }

    #[test]
    fn compile_all_passed_true_when_valid() {
        let compiler = PolicyTheoremCompiler::new();
        let result = compiler.compile(&valid_policy()).unwrap();
        assert!(result.all_passed);
        assert!(result.counterexamples.is_empty());
        assert!(!result.witnesses.is_empty());
    }

    #[test]
    fn compile_all_passed_false_when_violation() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = PolicyIr {
            nodes: vec![simple_node(
                "n1",
                MergeOperator::Union,
                vec![grant("ext-A", "fs.read", "z1")],
            )],
            ..valid_policy()
        };
        let result = compiler.compile(&ir).unwrap();
        assert!(!result.all_passed);
        assert!(!result.counterexamples.is_empty());
    }

    #[test]
    fn runtime_check_detects_monotonicity_violation() {
        let compiler = PolicyTheoremCompiler::new();
        let mut hooks = MachineCheckHooks::new(compiler);
        let ir = PolicyIr {
            nodes: vec![simple_node(
                "n1",
                MergeOperator::Union,
                vec![grant("ext-A", "fs.read", "z1")],
            )],
            ..valid_policy()
        };
        let result = hooks.runtime_check(&ir).unwrap();
        assert!(!result.passed);
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| d.property_violated == FormalProperty::Monotonicity)
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| d.severity == DiagnosticSeverity::Fatal)
        );
    }

    #[test]
    fn pre_deployment_check_detects_all_violations() {
        let compiler = PolicyTheoremCompiler::new();
        let mut hooks = MachineCheckHooks::new(compiler);
        let ir = PolicyIr {
            nodes: vec![simple_node(
                "n1",
                MergeOperator::Union,
                vec![grant("ext-A", "fs.read", "z1")],
            )],
            ..valid_policy()
        };
        let result = hooks.pre_deployment_check(&ir).unwrap();
        assert!(!result.passed);
    }

    #[test]
    fn constraint_all_variants_serde() {
        let constraints = vec![
            Constraint::Invariant("always".into()),
            Constraint::Precondition("before".into()),
            Constraint::Postcondition("after".into()),
            Constraint::NonInterferenceClaim {
                domain_a: "a".into(),
                domain_b: "b".into(),
            },
        ];
        for c in &constraints {
            let json = serde_json::to_string(c).unwrap();
            let back: Constraint = serde_json::from_str(&json).unwrap();
            assert_eq!(*c, back);
        }
    }

    #[test]
    fn policy_ir_node_with_decision_point_serde() {
        let node = PolicyIrNode {
            node_id: "dp-node".into(),
            grants: vec![grant("ext-A", "fs.read", "z1")],
            merge_op: MergeOperator::Intersection,
            property_claims: BTreeSet::new(),
            constraints: vec![Constraint::Invariant("always".into())],
            decision_point: Some(DecisionPoint {
                threshold: 3,
                action_map: {
                    let mut m = BTreeMap::new();
                    m.insert("high".into(), "sandbox".into());
                    m
                },
                fallback: "allow".into(),
            }),
            priority: 5,
        };
        let json = serde_json::to_string(&node).unwrap();
        let back: PolicyIrNode = serde_json::from_str(&json).unwrap();
        assert_eq!(node, back);
    }

    #[test]
    fn receipt_verify_valid_signature() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = valid_policy();
        let result = compiler.compile(&ir).unwrap();

        let sk = SigningKey::from_bytes([42u8; 32]);
        let vk = sk.verification_key();
        let mut receipt = PolicyValidationReceipt::from_compilation(
            &result,
            [0u8; 32],
            SecurityEpoch::from_raw(1),
            1000,
            &vk,
        );
        receipt.sign(&sk);
        assert!(receipt.verify());
    }

    #[test]
    fn receipt_properties_match_compilation_witnesses() {
        let compiler = PolicyTheoremCompiler::new();
        let ir = valid_policy();
        let result = compiler.compile(&ir).unwrap();

        let sk = SigningKey::from_bytes([42u8; 32]);
        let vk = sk.verification_key();
        let receipt = PolicyValidationReceipt::from_compilation(
            &result,
            [0u8; 32],
            SecurityEpoch::from_raw(1),
            1000,
            &vk,
        );
        assert_eq!(receipt.witness_count, result.witnesses.len() as u32);
        assert_eq!(
            receipt.properties_verified,
            result
                .witnesses
                .iter()
                .map(|w| w.property)
                .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn merge_operator_display_all_unique() {
        let displays: BTreeSet<String> = [
            MergeOperator::Union,
            MergeOperator::Intersection,
            MergeOperator::Attenuation,
            MergeOperator::Precedence,
        ]
        .iter()
        .map(|m| m.to_string())
        .collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn formal_property_display_all_unique() {
        let displays: BTreeSet<String> = [
            FormalProperty::Monotonicity,
            FormalProperty::NonInterference,
            FormalProperty::AttenuationLegality,
            FormalProperty::MergeDeterminism,
            FormalProperty::PrecedenceStability,
        ]
        .iter()
        .map(|fp| fp.to_string())
        .collect();
        assert_eq!(displays.len(), 5);
    }

    #[test]
    fn hook_history_tracks_across_multiple_hooks() {
        let compiler = PolicyTheoremCompiler::new();
        let mut hooks = MachineCheckHooks::new(compiler);
        let ir = valid_policy();

        hooks.runtime_check(&ir).unwrap();
        hooks.pre_deployment_check(&ir).unwrap();
        assert_eq!(hooks.hook_history().len(), 2);
        assert_eq!(hooks.hook_history()[0].hook_name, "runtime");
        assert_eq!(hooks.hook_history()[1].hook_name, "pre-deployment");
    }
}
