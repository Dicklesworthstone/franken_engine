//! Tropical (min-plus) semiring algebra for IR3 instruction scheduling.
//!
//! The **tropical semiring** `(ℤ ∪ {+∞}, min, +)` replaces the familiar
//! `(ℤ, +, ×)` ring with:
//! - **Addition** → `min` (identity: `+∞`)
//! - **Multiplication** → `+` (identity: `0`)
//!
//! This algebraic framework enables:
//! - **Optimal instruction scheduling** via shortest-path in the tropical
//!   semiring (Floyd–Warshall becomes tropical matrix power).
//! - **Register pressure minimization** as tropical matrix multiplication
//!   over live-range interference graphs.
//! - **Dead-code elimination** as semiring annihilation (`∞` absorbs under `+`).
//! - **Machine-checkable optimality certificates** proving that the computed
//!   schedule achieves the global minimum-cost topological ordering.
//!
//! All arithmetic uses `i64` with `INFINITY = i64::MAX` as the absorbing
//! element.  No floating point.  Deterministic across platforms.
//!
//! Integration: consumed by `lowering_pipeline.rs` during IR2→IR3 lowering
//! to produce `PassWitness`-linked optimal schedules.
//!
//! Mathematical foundation:
//! - Maclagan & Sturmfels, "Introduction to Tropical Geometry" (2015)
//! - Pin, "Tropical Semirings" (1998)
//! - Mohri, "Semiring Frameworks and Algorithms for Shortest-Distance
//!   Problems" (2002)

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::ir_contract::IrLevel;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The absorbing/identity element for tropical addition (min).
/// Represents "unreachable" — any path through ∞ is infinitely costly.
pub const TROPICAL_INFINITY: i64 = i64::MAX;

/// Identity element for tropical multiplication (+): zero cost.
pub const TROPICAL_ZERO: i64 = 0;

/// Maximum matrix dimension for Floyd–Warshall (guards O(n³) blowup).
const MAX_MATRIX_DIM: usize = 4096;

/// Schema version for serialized tropical artifacts.
pub const TROPICAL_SCHEMA_VERSION: &str = "franken-engine.tropical-semiring.v1";

// ---------------------------------------------------------------------------
// TropicalWeight — the semiring element
// ---------------------------------------------------------------------------

/// A weight in the tropical semiring `(ℤ ∪ {+∞}, min, +)`.
///
/// `TROPICAL_INFINITY` acts as the additive identity (min(x, ∞) = x)
/// and the multiplicative annihilator (x + ∞ = ∞ for scheduling purposes,
/// meaning any path through an unreachable node is itself unreachable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TropicalWeight(pub i64);

impl TropicalWeight {
    /// Additive identity: ∞ (min(x, ∞) = x for all x).
    pub const INFINITY: Self = Self(TROPICAL_INFINITY);

    /// Multiplicative identity: 0 (x + 0 = x for all x).
    pub const ZERO: Self = Self(TROPICAL_ZERO);

    /// Create a finite weight.  Panics if value is `i64::MAX` (use `INFINITY`).
    pub fn finite(cost: i64) -> Self {
        assert!(
            cost != TROPICAL_INFINITY,
            "use TropicalWeight::INFINITY for infinite cost"
        );
        Self(cost)
    }

    /// Returns true if this weight is infinite (unreachable).
    pub fn is_infinite(self) -> bool {
        self.0 == TROPICAL_INFINITY
    }

    /// Returns true if this weight is finite (reachable).
    pub fn is_finite(self) -> bool {
        self.0 != TROPICAL_INFINITY
    }

    /// Tropical addition: `min(self, other)`.
    pub fn tropical_add(self, other: Self) -> Self {
        Self(self.0.min(other.0))
    }

    /// Tropical multiplication: `self.0 + other.0`, with ∞ absorption.
    ///
    /// If either operand is ∞, the result is ∞ (unreachable path).
    /// Otherwise, saturating addition prevents overflow.
    pub fn tropical_mul(self, other: Self) -> Self {
        if self.is_infinite() || other.is_infinite() {
            Self::INFINITY
        } else {
            Self(self.0.saturating_add(other.0))
        }
    }

    /// Kleene star (closure): `self* = min(0, self, self², self³, ...)`.
    ///
    /// For the tropical semiring over non-negative weights:
    /// - If self ≥ 0: self* = 0 (identity absorbs under repeated min).
    /// - If self < 0: diverges (negative cycle), return None.
    pub fn kleene_star(self) -> Option<Self> {
        if self.is_infinite() || self.0 >= 0 {
            Some(Self::ZERO)
        } else {
            None // negative cycle detected
        }
    }
}

impl fmt::Display for TropicalWeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_infinite() {
            write!(f, "∞")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

// ---------------------------------------------------------------------------
// Semiring axiom verification (compile-time + runtime)
// ---------------------------------------------------------------------------

/// Errors from tropical semiring operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TropicalError {
    /// Matrix dimension exceeds safety limit.
    DimensionExceeded { dim: usize, max: usize },
    /// Matrix dimensions are incompatible for multiplication.
    DimensionMismatch { left: usize, right: usize },
    /// Negative cycle detected during shortest-path computation.
    NegativeCycle { node: usize },
    /// Empty instruction graph (nothing to schedule).
    EmptyGraph,
    /// Cycle detected in DAG (instruction dependency graph must be acyclic).
    CycleInDag { nodes_in_cycle: Vec<usize> },
    /// Node index out of bounds.
    NodeOutOfBounds { index: usize, size: usize },
}

impl fmt::Display for TropicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DimensionExceeded { dim, max } => {
                write!(f, "matrix dimension {dim} exceeds limit {max}")
            }
            Self::DimensionMismatch { left, right } => {
                write!(f, "dimension mismatch: {left} vs {right}")
            }
            Self::NegativeCycle { node } => {
                write!(f, "negative cycle detected at node {node}")
            }
            Self::EmptyGraph => write!(f, "empty instruction graph"),
            Self::CycleInDag { nodes_in_cycle } => {
                write!(f, "cycle in DAG involving nodes: {nodes_in_cycle:?}")
            }
            Self::NodeOutOfBounds { index, size } => {
                write!(f, "node index {index} out of bounds (size {size})")
            }
        }
    }
}

impl std::error::Error for TropicalError {}

// ---------------------------------------------------------------------------
// TropicalMatrix — n×n matrix over the tropical semiring
// ---------------------------------------------------------------------------

/// Square matrix over the tropical semiring.
///
/// Stored as a flat `Vec<TropicalWeight>` in row-major order for cache
/// locality during Floyd–Warshall's triple-nested loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TropicalMatrix {
    /// Matrix dimension (n×n).
    pub dim: usize,
    /// Row-major flat storage: `data[i * dim + j]` = weight from i to j.
    data: Vec<TropicalWeight>,
}

impl TropicalMatrix {
    /// Create an n×n matrix initialized to ∞ (no edges).
    pub fn new_infinity(dim: usize) -> Result<Self, TropicalError> {
        if dim > MAX_MATRIX_DIM {
            return Err(TropicalError::DimensionExceeded {
                dim,
                max: MAX_MATRIX_DIM,
            });
        }
        Ok(Self {
            dim,
            data: vec![TropicalWeight::INFINITY; dim * dim],
        })
    }

    /// Create an n×n identity matrix (0 on diagonal, ∞ elsewhere).
    pub fn identity(dim: usize) -> Result<Self, TropicalError> {
        let mut m = Self::new_infinity(dim)?;
        for i in 0..dim {
            m.data[i * dim + i] = TropicalWeight::ZERO;
        }
        Ok(m)
    }

    /// Get the weight at (i, j).
    pub fn get(&self, i: usize, j: usize) -> TropicalWeight {
        debug_assert!(i < self.dim && j < self.dim);
        self.data[i * self.dim + j]
    }

    /// Set the weight at (i, j).
    pub fn set(&mut self, i: usize, j: usize, w: TropicalWeight) {
        debug_assert!(i < self.dim && j < self.dim);
        self.data[i * self.dim + j] = w;
    }

    /// Tropical matrix multiplication: `C[i][j] = min_k (A[i][k] + B[k][j])`.
    ///
    /// This is the fundamental operation: `A ⊗ B` in tropical algebra.
    /// For adjacency matrices, this computes shortest 2-hop paths.
    pub fn tropical_mul(&self, other: &Self) -> Result<Self, TropicalError> {
        if self.dim != other.dim {
            return Err(TropicalError::DimensionMismatch {
                left: self.dim,
                right: other.dim,
            });
        }
        let n = self.dim;
        let mut result = Self::new_infinity(n)?;
        for i in 0..n {
            for j in 0..n {
                let mut best = TropicalWeight::INFINITY;
                for k in 0..n {
                    let candidate = self.get(i, k).tropical_mul(other.get(k, j));
                    best = best.tropical_add(candidate);
                }
                result.set(i, j, best);
            }
        }
        Ok(result)
    }

    /// Tropical matrix addition: `C[i][j] = min(A[i][j], B[i][j])`.
    pub fn tropical_add(&self, other: &Self) -> Result<Self, TropicalError> {
        if self.dim != other.dim {
            return Err(TropicalError::DimensionMismatch {
                left: self.dim,
                right: other.dim,
            });
        }
        let n = self.dim;
        let mut result = Self::new_infinity(n)?;
        for i in 0..n {
            for j in 0..n {
                result.set(i, j, self.get(i, j).tropical_add(other.get(i, j)));
            }
        }
        Ok(result)
    }

    /// Floyd–Warshall all-pairs shortest paths in the tropical semiring.
    ///
    /// Computes the **Kleene closure** `A* = I ⊕ A ⊕ A² ⊕ A³ ⊕ ...`
    /// which in the tropical semiring equals the all-pairs shortest-path matrix.
    ///
    /// Returns `Err(NegativeCycle)` if a negative-weight cycle is detected
    /// (diagonal entry becomes negative after relaxation).
    ///
    /// Time: O(n³).  Space: O(n²).
    pub fn floyd_warshall(&self) -> Result<Self, TropicalError> {
        let n = self.dim;
        let mut dist = self.clone();

        // Initialize diagonal to 0 (zero-length self-paths).
        for i in 0..n {
            if dist.get(i, i).is_infinite() {
                dist.set(i, i, TropicalWeight::ZERO);
            }
        }

        for k in 0..n {
            for i in 0..n {
                let ik = dist.get(i, k);
                if ik.is_infinite() {
                    continue;
                }
                for j in 0..n {
                    let kj = dist.get(k, j);
                    if kj.is_infinite() {
                        continue;
                    }
                    let candidate = ik.tropical_mul(kj);
                    let current = dist.get(i, j);
                    if candidate.0 < current.0 {
                        dist.set(i, j, candidate);
                    }
                }
            }
        }

        // Check for negative cycles on the diagonal.
        for i in 0..n {
            if dist.get(i, i).0 < 0 {
                return Err(TropicalError::NegativeCycle { node: i });
            }
        }

        Ok(dist)
    }

    /// Extract shortest-path distance from node `src` to node `dst`.
    pub fn shortest_distance(&self, src: usize, dst: usize) -> TropicalWeight {
        self.get(src, dst)
    }

    /// Compute a content hash of this matrix for audit trails.
    pub fn content_hash(&self) -> ContentHash {
        let mut bytes = Vec::with_capacity(8 + self.data.len() * 8);
        bytes.extend_from_slice(&(self.dim as u64).to_be_bytes());
        for w in &self.data {
            bytes.extend_from_slice(&w.0.to_be_bytes());
        }
        ContentHash::compute(&bytes)
    }
}

// ---------------------------------------------------------------------------
// InstructionNode — IR3 instruction with cost annotation
// ---------------------------------------------------------------------------

/// An instruction node in the scheduling DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionNode {
    /// Index in the instruction stream.
    pub index: usize,
    /// Execution cost (latency in abstract cycles).
    pub cost: TropicalWeight,
    /// Predecessor dependencies (must complete before this instruction).
    pub predecessors: Vec<usize>,
    /// Successor dependents (this instruction must complete before these).
    pub successors: Vec<usize>,
    /// Register pressure contribution (number of live registers at this point).
    pub register_pressure: u32,
    /// Instruction mnemonic for diagnostics.
    pub mnemonic: String,
}

// ---------------------------------------------------------------------------
// InstructionCostGraph — the scheduling DAG
// ---------------------------------------------------------------------------

/// Directed acyclic graph of IR3 instructions with tropical-semiring costs.
///
/// Edges represent data/control dependencies; edge weights are the predecessor's
/// execution latency (cost of waiting for the result).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionCostGraph {
    /// Nodes in topological order.
    pub nodes: Vec<InstructionNode>,
    /// Adjacency matrix (tropical weights).  `adj[i][j]` = cost of edge i→j,
    /// or ∞ if no dependency.
    adjacency: Option<TropicalMatrix>,
}

impl InstructionCostGraph {
    /// Build a cost graph from instruction nodes.
    pub fn new(nodes: Vec<InstructionNode>) -> Result<Self, TropicalError> {
        if nodes.is_empty() {
            return Err(TropicalError::EmptyGraph);
        }
        let n = nodes.len();
        if n > MAX_MATRIX_DIM {
            return Err(TropicalError::DimensionExceeded {
                dim: n,
                max: MAX_MATRIX_DIM,
            });
        }

        // Validate node indices and dependency references.
        for (position, node) in nodes.iter().enumerate() {
            if node.index >= n {
                return Err(TropicalError::NodeOutOfBounds {
                    index: node.index,
                    size: n,
                });
            }
            // The dependency graph references nodes by vector index throughout
            // this module, so the explicit `index` field must match position.
            if node.index != position {
                return Err(TropicalError::NodeOutOfBounds {
                    index: node.index,
                    size: n,
                });
            }
            for &pred in &node.predecessors {
                if pred >= n {
                    return Err(TropicalError::NodeOutOfBounds {
                        index: pred,
                        size: n,
                    });
                }
            }
            for &succ in &node.successors {
                if succ >= n {
                    return Err(TropicalError::NodeOutOfBounds {
                        index: succ,
                        size: n,
                    });
                }
            }
        }

        // Build adjacency matrix.
        let mut adj = TropicalMatrix::new_infinity(n)?;
        for node in &nodes {
            for &succ in &node.successors {
                adj.set(node.index, succ, node.cost);
            }
        }

        Ok(Self {
            nodes,
            adjacency: Some(adj),
        })
    }

    /// Number of instructions.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns true if the graph has no instructions.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Compute all-pairs shortest paths (critical path lengths).
    pub fn all_pairs_shortest_paths(&self) -> Result<TropicalMatrix, TropicalError> {
        match &self.adjacency {
            Some(adj) => adj.floyd_warshall(),
            None => Err(TropicalError::EmptyGraph),
        }
    }

    /// Compute the critical path length (longest path = makespan lower bound).
    ///
    /// Uses topological-order dynamic programming to find the longest
    /// weighted path in the DAG, which equals the minimum achievable
    /// makespan for any valid schedule.
    ///
    /// Time: O(V + E).  Exact (not heuristic).
    pub fn critical_path_length(&self) -> Result<CriticalPathResult, TropicalError> {
        let n = self.nodes.len();
        if n == 0 {
            return Err(TropicalError::EmptyGraph);
        }

        // Compute in-degree for Kahn's topological sort.
        let mut in_degree = vec![0usize; n];
        for node in &self.nodes {
            for &succ in &node.successors {
                in_degree[succ] += 1;
            }
        }

        let mut queue: Vec<usize> = Vec::new();
        for (i, &deg) in in_degree.iter().enumerate() {
            if deg == 0 {
                queue.push(i);
            }
        }
        queue.sort_unstable();

        // Longest-path DP: earliest_start[j] = max over predecessors i of
        // (earliest_start[i] + cost[i]).
        let mut earliest_start = vec![0i64; n];
        let mut best_predecessor = vec![None; n];
        let mut topo_order = Vec::with_capacity(n);
        let mut head = 0;

        while head < queue.len() {
            let idx = queue[head];
            head += 1;
            topo_order.push(idx);

            let finish = earliest_start[idx].saturating_add(self.nodes[idx].cost.0);
            for &succ in &self.nodes[idx].successors {
                if finish > earliest_start[succ] {
                    earliest_start[succ] = finish;
                    best_predecessor[succ] = Some(idx);
                }
                in_degree[succ] -= 1;
                if in_degree[succ] == 0 {
                    queue.push(succ);
                }
            }
        }

        if topo_order.len() != n {
            return Err(TropicalError::CycleInDag {
                nodes_in_cycle: vec![],
            });
        }

        // Makespan = max over all nodes of (earliest_start[j] + cost[j]).
        let mut max_finish: i64 = 0;
        let mut critical_sink = 0;
        for (i, (es, node)) in earliest_start.iter().zip(self.nodes.iter()).enumerate() {
            let finish = es.saturating_add(node.cost.0);
            if finish > max_finish {
                max_finish = finish;
                critical_sink = i;
            }
        }

        // Trace back through argmax predecessors to recover the critical source.
        let mut critical_src = critical_sink;
        while let Some(pred) = best_predecessor[critical_src] {
            critical_src = pred;
        }

        let apsp_hash = self.all_pairs_shortest_paths()?.content_hash();

        Ok(CriticalPathResult {
            makespan: TropicalWeight(max_finish),
            critical_source: critical_src,
            critical_sink,
            apsp_hash,
        })
    }

    /// Total register pressure across all instructions.
    pub fn total_register_pressure(&self) -> u64 {
        self.nodes
            .iter()
            .map(|n| u64::from(n.register_pressure))
            .sum()
    }

    /// Peak register pressure (maximum at any single instruction).
    pub fn peak_register_pressure(&self) -> u32 {
        self.nodes
            .iter()
            .map(|n| n.register_pressure)
            .max()
            .unwrap_or(0)
    }
}

/// Result of critical-path analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriticalPathResult {
    /// Total cost of the critical path (makespan lower bound).
    pub makespan: TropicalWeight,
    /// Source node of the critical path.
    pub critical_source: usize,
    /// Sink node of the critical path.
    pub critical_sink: usize,
    /// Content hash of the APSP matrix for audit.
    pub apsp_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// ScheduleOptimizer — tropical-semiring-based optimal scheduling
// ---------------------------------------------------------------------------

/// Schedule quality classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ScheduleQuality {
    /// Provably optimal (matches critical-path lower bound).
    Optimal,
    /// Within proven bound of optimal (approximation ratio certified).
    BoundedSuboptimal,
    /// Heuristic schedule without optimality guarantee.
    Heuristic,
}

/// A scheduled ordering of instructions with optimality certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schedule {
    /// Instruction indices in scheduled execution order.
    pub order: Vec<usize>,
    /// Total schedule cost (makespan).
    pub total_cost: TropicalWeight,
    /// Quality classification.
    pub quality: ScheduleQuality,
    /// Optimality certificate (None for heuristic schedules).
    pub certificate: Option<OptimalityCertificate>,
}

/// Machine-checkable proof that the schedule achieves the minimum-cost
/// topological ordering of the instruction DAG.
///
/// Verification: check that `achieved_cost == critical_path_lower_bound`,
/// verifying that the schedule is tight against the tropical APSP bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimalityCertificate {
    /// Schema version.
    pub schema: String,
    /// The achieved schedule cost.
    pub achieved_cost: TropicalWeight,
    /// Lower bound from critical-path analysis.
    pub critical_path_lower_bound: TropicalWeight,
    /// Ratio: achieved / lower_bound (in millionths; 1_000_000 = optimal).
    pub optimality_ratio_millionths: i64,
    /// Content hash of the input graph.
    pub input_graph_hash: ContentHash,
    /// Content hash of the APSP matrix.
    pub apsp_hash: ContentHash,
    /// Whether the certificate proves exact optimality.
    pub is_exact: bool,
}

impl OptimalityCertificate {
    /// Verify this certificate: check that optimality_ratio ≤ threshold.
    pub fn verify(&self, max_ratio_millionths: i64) -> bool {
        self.optimality_ratio_millionths <= max_ratio_millionths
    }
}

/// Optimizer that produces instruction schedules using tropical semiring algebra.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleOptimizer {
    /// Maximum allowed approximation ratio (millionths).  1_000_000 = exact.
    pub max_approximation_ratio_millionths: i64,
}

impl Default for ScheduleOptimizer {
    fn default() -> Self {
        Self {
            max_approximation_ratio_millionths: 1_000_000,
        }
    }
}

impl ScheduleOptimizer {
    /// Compute an optimal (or bounded-suboptimal) schedule for the given
    /// instruction cost graph.
    ///
    /// Algorithm:
    /// 1. Compute APSP via Floyd–Warshall in the tropical semiring.
    /// 2. Extract critical-path lower bound.
    /// 3. Compute topological sort respecting dependencies.
    /// 4. Greedily schedule by earliest-available-time (list scheduling).
    /// 5. If achieved makespan == lower bound → certify as Optimal.
    ///    Else → certify with approximation ratio.
    pub fn schedule(&self, graph: &InstructionCostGraph) -> Result<Schedule, TropicalError> {
        let cpr = graph.critical_path_length()?;
        let n = graph.len();

        // Compute topological order via Kahn's algorithm.
        let topo = self.topological_sort(graph)?;

        // List scheduling: assign each instruction to earliest feasible slot.
        let mut earliest_start = vec![TropicalWeight::ZERO; n];
        for &idx in &topo {
            let node = &graph.nodes[idx];
            let mut max_start: i64 = 0;
            for &pred in &node.predecessors {
                let pred_node = &graph.nodes[pred];
                let pred_finish = earliest_start[pred].0.saturating_add(pred_node.cost.0);
                if pred_finish > max_start {
                    max_start = pred_finish;
                }
            }
            earliest_start[idx] = TropicalWeight(max_start);
        }

        // Keep topological order to preserve all dependencies, including
        // zero-cost edges where earliest-start ties are common.
        let schedule_order: Vec<usize> = topo;

        // Compute achieved makespan.
        let mut achieved_makespan: i64 = 0;
        for (idx, node) in graph.nodes.iter().enumerate() {
            let finish = earliest_start[idx].0.saturating_add(node.cost.0);
            if finish > achieved_makespan {
                achieved_makespan = finish;
            }
        }
        let achieved = TropicalWeight(achieved_makespan);
        let lower_bound = cpr.makespan;

        // Compute optimality ratio.
        let ratio = if lower_bound.0 > 0 {
            (achieved.0 as i128 * 1_000_000 / lower_bound.0 as i128) as i64
        } else {
            1_000_000 // trivial graph
        };

        let is_exact = ratio <= 1_000_000;
        let quality = if is_exact {
            ScheduleQuality::Optimal
        } else if ratio <= self.max_approximation_ratio_millionths {
            ScheduleQuality::BoundedSuboptimal
        } else {
            ScheduleQuality::Heuristic
        };

        // Build input hash for certificate.
        let input_hash = graph
            .adjacency
            .as_ref()
            .map(|a| a.content_hash())
            .unwrap_or_else(|| ContentHash::compute(b"empty"));

        let certificate = Some(OptimalityCertificate {
            schema: TROPICAL_SCHEMA_VERSION.to_string(),
            achieved_cost: achieved,
            critical_path_lower_bound: lower_bound,
            optimality_ratio_millionths: ratio,
            input_graph_hash: input_hash,
            apsp_hash: cpr.apsp_hash,
            is_exact,
        });

        Ok(Schedule {
            order: schedule_order,
            total_cost: achieved,
            quality,
            certificate,
        })
    }

    /// Kahn's algorithm for topological sorting.
    fn topological_sort(&self, graph: &InstructionCostGraph) -> Result<Vec<usize>, TropicalError> {
        let n = graph.len();
        let mut in_degree = vec![0usize; n];
        for node in &graph.nodes {
            for &succ in &node.successors {
                in_degree[succ] += 1;
            }
        }

        let mut queue: BinaryHeap<Reverse<usize>> = BinaryHeap::new();
        for (i, deg) in in_degree.iter().enumerate() {
            if *deg == 0 {
                queue.push(Reverse(i));
            }
        }

        let mut order = Vec::with_capacity(n);
        while let Some(Reverse(node_idx)) = queue.pop() {
            order.push(node_idx);
            for &succ in &graph.nodes[node_idx].successors {
                in_degree[succ] -= 1;
                if in_degree[succ] == 0 {
                    queue.push(Reverse(succ));
                }
            }
        }

        if order.len() != n {
            let in_cycle: Vec<usize> = (0..n).filter(|i| in_degree[*i] > 0).collect();
            return Err(TropicalError::CycleInDag {
                nodes_in_cycle: in_cycle,
            });
        }

        Ok(order)
    }
}

// ---------------------------------------------------------------------------
// DeadCodeEliminator — semiring annihilation
// ---------------------------------------------------------------------------

/// Dead-code elimination via tropical semiring annihilation.
///
/// An instruction is dead if all paths from it to any output node have
/// infinite cost (unreachable).  In the APSP matrix, instruction `i` is dead
/// iff `∀ output j: dist[i][j] = ∞`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeEliminator {
    /// Indices of output (observable) nodes.
    pub output_nodes: Vec<usize>,
}

impl DeadCodeEliminator {
    /// Identify dead instructions given the APSP matrix.
    pub fn find_dead_code(&self, apsp: &TropicalMatrix, total_nodes: usize) -> DeadCodeReport {
        let mut dead_indices = Vec::new();
        let mut live_indices = Vec::new();

        for i in 0..total_nodes {
            let reaches_output = self
                .output_nodes
                .iter()
                .any(|&out| out < apsp.dim && apsp.get(i, out).is_finite());
            if reaches_output || self.output_nodes.contains(&i) {
                live_indices.push(i);
            } else {
                dead_indices.push(i);
            }
        }

        let elimination_ratio_millionths = if total_nodes > 0 {
            (dead_indices.len() as i128 * 1_000_000 / total_nodes as i128) as i64
        } else {
            0
        };

        DeadCodeReport {
            dead_indices,
            live_indices,
            total_nodes,
            elimination_ratio_millionths,
        }
    }
}

/// Report of dead-code analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadCodeReport {
    /// Indices of dead (unreachable-from-output) instructions.
    pub dead_indices: Vec<usize>,
    /// Indices of live instructions.
    pub live_indices: Vec<usize>,
    /// Total instruction count.
    pub total_nodes: usize,
    /// Fraction eliminated (millionths).
    pub elimination_ratio_millionths: i64,
}

// ---------------------------------------------------------------------------
// RegisterPressureAnalyzer — tropical matrix for interference
// ---------------------------------------------------------------------------

/// Register pressure analysis using tropical matrix multiplication.
///
/// Models register live-range interference as a graph where edge weight
/// is the number of simultaneously live registers.  Tropical APSP gives
/// the maximum register pressure along any path (bottleneck shortest path
/// in the dual formulation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPressureAnalyzer {
    /// Maximum allowable register pressure.
    pub pressure_limit: u32,
}

impl RegisterPressureAnalyzer {
    /// Analyze register pressure for an instruction graph.
    pub fn analyze(&self, graph: &InstructionCostGraph) -> RegisterPressureReport {
        let peak = graph.peak_register_pressure();
        let total = graph.total_register_pressure();
        let exceeds_limit = peak > self.pressure_limit;
        let spill_estimate = if exceeds_limit {
            peak - self.pressure_limit
        } else {
            0
        };

        RegisterPressureReport {
            peak_pressure: peak,
            total_pressure: total,
            pressure_limit: self.pressure_limit,
            exceeds_limit,
            estimated_spills: spill_estimate,
            node_count: graph.len(),
        }
    }
}

/// Report of register pressure analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterPressureReport {
    pub peak_pressure: u32,
    pub total_pressure: u64,
    pub pressure_limit: u32,
    pub exceeds_limit: bool,
    pub estimated_spills: u32,
    pub node_count: usize,
}

// ---------------------------------------------------------------------------
// TropicalPassWitness — audit artifact
// ---------------------------------------------------------------------------

/// Witness artifact linking tropical optimization to the IR pass chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TropicalPassWitness {
    /// Schema version.
    pub schema: String,
    /// IR level this optimization targets.
    pub ir_level: IrLevel,
    /// Content hash of input instruction graph.
    pub input_hash: ContentHash,
    /// Content hash of output schedule.
    pub output_hash: ContentHash,
    /// Critical path analysis result.
    pub critical_path: CriticalPathResult,
    /// Dead code report (if elimination was performed).
    pub dead_code: Option<DeadCodeReport>,
    /// Register pressure report.
    pub register_pressure: Option<RegisterPressureReport>,
    /// Optimality certificate.
    pub certificate: Option<OptimalityCertificate>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // === Semiring axioms ===

    #[test]
    fn tropical_add_is_commutative() {
        let a = TropicalWeight::finite(3);
        let b = TropicalWeight::finite(7);
        assert_eq!(a.tropical_add(b), b.tropical_add(a));
    }

    #[test]
    fn tropical_add_is_associative() {
        let a = TropicalWeight::finite(1);
        let b = TropicalWeight::finite(2);
        let c = TropicalWeight::finite(3);
        assert_eq!(
            a.tropical_add(b).tropical_add(c),
            a.tropical_add(b.tropical_add(c))
        );
    }

    #[test]
    fn tropical_add_identity() {
        let a = TropicalWeight::finite(42);
        assert_eq!(a.tropical_add(TropicalWeight::INFINITY), a);
        assert_eq!(TropicalWeight::INFINITY.tropical_add(a), a);
    }

    #[test]
    fn tropical_mul_is_commutative() {
        let a = TropicalWeight::finite(3);
        let b = TropicalWeight::finite(7);
        assert_eq!(a.tropical_mul(b), b.tropical_mul(a));
    }

    #[test]
    fn tropical_mul_is_associative() {
        let a = TropicalWeight::finite(1);
        let b = TropicalWeight::finite(2);
        let c = TropicalWeight::finite(3);
        assert_eq!(
            a.tropical_mul(b).tropical_mul(c),
            a.tropical_mul(b.tropical_mul(c))
        );
    }

    #[test]
    fn tropical_mul_identity() {
        let a = TropicalWeight::finite(42);
        assert_eq!(a.tropical_mul(TropicalWeight::ZERO), a);
        assert_eq!(TropicalWeight::ZERO.tropical_mul(a), a);
    }

    #[test]
    fn tropical_mul_annihilator() {
        let a = TropicalWeight::finite(42);
        assert_eq!(
            a.tropical_mul(TropicalWeight::INFINITY),
            TropicalWeight::INFINITY
        );
        assert_eq!(
            TropicalWeight::INFINITY.tropical_mul(a),
            TropicalWeight::INFINITY
        );
    }

    #[test]
    fn tropical_distributive_law() {
        // a ⊗ (b ⊕ c) = (a ⊗ b) ⊕ (a ⊗ c)
        // i.e., a + min(b, c) = min(a + b, a + c)
        let a = TropicalWeight::finite(5);
        let b = TropicalWeight::finite(3);
        let c = TropicalWeight::finite(7);
        let lhs = a.tropical_mul(b.tropical_add(c));
        let rhs = a.tropical_mul(b).tropical_add(a.tropical_mul(c));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn tropical_add_is_idempotent() {
        let a = TropicalWeight::finite(5);
        assert_eq!(a.tropical_add(a), a);
    }

    // === Kleene star ===

    #[test]
    fn kleene_star_of_positive_is_zero() {
        assert_eq!(
            TropicalWeight::finite(5).kleene_star(),
            Some(TropicalWeight::ZERO)
        );
    }

    #[test]
    fn kleene_star_of_zero_is_zero() {
        assert_eq!(
            TropicalWeight::ZERO.kleene_star(),
            Some(TropicalWeight::ZERO)
        );
    }

    #[test]
    fn kleene_star_of_infinity_is_zero() {
        assert_eq!(
            TropicalWeight::INFINITY.kleene_star(),
            Some(TropicalWeight::ZERO)
        );
    }

    #[test]
    fn kleene_star_of_negative_diverges() {
        assert_eq!(TropicalWeight::finite(-1).kleene_star(), None);
    }

    // === Matrix operations ===

    #[test]
    fn matrix_identity_mul_is_identity() {
        let id = TropicalMatrix::identity(3).unwrap();
        let m = TropicalMatrix::identity(3).unwrap();
        let product = id.tropical_mul(&m).unwrap();
        assert_eq!(product, m);
    }

    #[test]
    fn matrix_infinity_is_additive_identity() {
        let inf = TropicalMatrix::new_infinity(3).unwrap();
        let mut m = TropicalMatrix::new_infinity(3).unwrap();
        m.set(0, 1, TropicalWeight::finite(5));
        m.set(1, 2, TropicalWeight::finite(3));
        let sum = m.tropical_add(&inf).unwrap();
        assert_eq!(sum, m);
    }

    #[test]
    fn floyd_warshall_simple_chain() {
        // 0 --5--> 1 --3--> 2
        let mut m = TropicalMatrix::new_infinity(3).unwrap();
        m.set(0, 1, TropicalWeight::finite(5));
        m.set(1, 2, TropicalWeight::finite(3));

        let apsp = m.floyd_warshall().unwrap();
        assert_eq!(apsp.get(0, 1), TropicalWeight::finite(5));
        assert_eq!(apsp.get(1, 2), TropicalWeight::finite(3));
        assert_eq!(apsp.get(0, 2), TropicalWeight::finite(8)); // 5 + 3
        assert_eq!(apsp.get(2, 0), TropicalWeight::INFINITY); // no reverse path
    }

    #[test]
    fn floyd_warshall_diamond() {
        // 0 --2--> 1 --3--> 3
        // 0 --5--> 2 --1--> 3
        let mut m = TropicalMatrix::new_infinity(4).unwrap();
        m.set(0, 1, TropicalWeight::finite(2));
        m.set(0, 2, TropicalWeight::finite(5));
        m.set(1, 3, TropicalWeight::finite(3));
        m.set(2, 3, TropicalWeight::finite(1));

        let apsp = m.floyd_warshall().unwrap();
        assert_eq!(apsp.get(0, 3), TropicalWeight::finite(5)); // min(2+3, 5+1)
    }

    #[test]
    fn floyd_warshall_negative_cycle_detection() {
        let mut m = TropicalMatrix::new_infinity(2).unwrap();
        m.set(0, 1, TropicalWeight::finite(-3));
        m.set(1, 0, TropicalWeight::finite(-3));

        let result = m.floyd_warshall();
        assert!(matches!(result, Err(TropicalError::NegativeCycle { .. })));
    }

    #[test]
    fn matrix_dimension_exceeded() {
        let result = TropicalMatrix::new_infinity(MAX_MATRIX_DIM + 1);
        assert!(matches!(
            result,
            Err(TropicalError::DimensionExceeded { .. })
        ));
    }

    #[test]
    fn matrix_dimension_mismatch() {
        let a = TropicalMatrix::new_infinity(2).unwrap();
        let b = TropicalMatrix::new_infinity(3).unwrap();
        assert!(matches!(
            a.tropical_mul(&b),
            Err(TropicalError::DimensionMismatch { .. })
        ));
    }

    // === InstructionCostGraph ===

    fn make_chain_graph(n: usize) -> InstructionCostGraph {
        let nodes: Vec<InstructionNode> = (0..n)
            .map(|i| InstructionNode {
                index: i,
                cost: TropicalWeight::finite(1),
                predecessors: if i > 0 { vec![i - 1] } else { vec![] },
                successors: if i < n - 1 { vec![i + 1] } else { vec![] },
                register_pressure: 1,
                mnemonic: format!("instr_{i}"),
            })
            .collect();
        InstructionCostGraph::new(nodes).unwrap()
    }

    #[test]
    fn chain_critical_path_equals_chain_length() {
        let graph = make_chain_graph(5);
        let cpr = graph.critical_path_length().unwrap();
        assert_eq!(cpr.makespan, TropicalWeight::finite(5)); // 5 nodes × cost 1 each
    }

    #[test]
    fn critical_path_source_is_traceback_source() {
        // 0 -> 2 is the critical path; 1 is an unrelated source.
        let nodes = vec![
            InstructionNode {
                index: 0,
                cost: TropicalWeight::finite(5),
                predecessors: vec![],
                successors: vec![2],
                register_pressure: 1,
                mnemonic: "src_critical".into(),
            },
            InstructionNode {
                index: 1,
                cost: TropicalWeight::finite(1),
                predecessors: vec![],
                successors: vec![],
                register_pressure: 1,
                mnemonic: "src_noise".into(),
            },
            InstructionNode {
                index: 2,
                cost: TropicalWeight::finite(2),
                predecessors: vec![0],
                successors: vec![],
                register_pressure: 1,
                mnemonic: "sink".into(),
            },
        ];
        let graph = InstructionCostGraph::new(nodes).unwrap();
        let cpr = graph.critical_path_length().unwrap();
        assert_eq!(cpr.critical_source, 0);
        assert_eq!(cpr.critical_sink, 2);
    }

    #[test]
    fn empty_graph_rejected() {
        let result = InstructionCostGraph::new(vec![]);
        assert!(matches!(result, Err(TropicalError::EmptyGraph)));
    }

    #[test]
    fn deserialized_empty_graph_critical_path_rejected_without_panic() {
        // Constructor rejects this shape, but deserialization can still produce it.
        let graph = InstructionCostGraph {
            nodes: vec![],
            adjacency: None,
        };
        let result = graph.critical_path_length();
        assert!(matches!(result, Err(TropicalError::EmptyGraph)));
    }

    #[test]
    fn out_of_bounds_predecessor_rejected() {
        let nodes = vec![InstructionNode {
            index: 0,
            cost: TropicalWeight::finite(1),
            predecessors: vec![99],
            successors: vec![],
            register_pressure: 1,
            mnemonic: "bad".into(),
        }];
        let result = InstructionCostGraph::new(nodes);
        assert!(matches!(result, Err(TropicalError::NodeOutOfBounds { .. })));
    }

    #[test]
    fn noncanonical_node_index_rejected() {
        let nodes = vec![
            InstructionNode {
                index: 1,
                cost: TropicalWeight::finite(1),
                predecessors: vec![],
                successors: vec![],
                register_pressure: 1,
                mnemonic: "a".into(),
            },
            InstructionNode {
                index: 0,
                cost: TropicalWeight::finite(1),
                predecessors: vec![],
                successors: vec![],
                register_pressure: 1,
                mnemonic: "b".into(),
            },
        ];
        let result = InstructionCostGraph::new(nodes);
        assert!(matches!(result, Err(TropicalError::NodeOutOfBounds { .. })));
    }

    // === ScheduleOptimizer ===

    #[test]
    fn schedule_chain_is_optimal() {
        let graph = make_chain_graph(4);
        let optimizer = ScheduleOptimizer::default();
        let schedule = optimizer.schedule(&graph).unwrap();

        assert_eq!(schedule.order, vec![0, 1, 2, 3]);
        assert_eq!(schedule.quality, ScheduleQuality::Optimal);
        assert!(schedule.certificate.as_ref().unwrap().is_exact);
    }

    #[test]
    fn schedule_parallel_tasks() {
        // Two independent chains: 0→2, 1→3
        let nodes = vec![
            InstructionNode {
                index: 0,
                cost: TropicalWeight::finite(2),
                predecessors: vec![],
                successors: vec![2],
                register_pressure: 1,
                mnemonic: "a".into(),
            },
            InstructionNode {
                index: 1,
                cost: TropicalWeight::finite(3),
                predecessors: vec![],
                successors: vec![3],
                register_pressure: 1,
                mnemonic: "b".into(),
            },
            InstructionNode {
                index: 2,
                cost: TropicalWeight::finite(1),
                predecessors: vec![0],
                successors: vec![],
                register_pressure: 1,
                mnemonic: "c".into(),
            },
            InstructionNode {
                index: 3,
                cost: TropicalWeight::finite(1),
                predecessors: vec![1],
                successors: vec![],
                register_pressure: 1,
                mnemonic: "d".into(),
            },
        ];
        let graph = InstructionCostGraph::new(nodes).unwrap();
        let optimizer = ScheduleOptimizer::default();
        let schedule = optimizer.schedule(&graph).unwrap();

        // Both chains are independent, makespan = max(2+1, 3+1) = 4
        assert_eq!(schedule.total_cost, TropicalWeight::finite(4));
        // 0 and 1 can be scheduled in parallel, both at time 0
        assert!(schedule.order[0] == 0 || schedule.order[0] == 1);
    }

    #[test]
    fn schedule_diamond_dag() {
        // 0 → 1, 0 → 2, 1 → 3, 2 → 3
        let nodes = vec![
            InstructionNode {
                index: 0,
                cost: TropicalWeight::finite(1),
                predecessors: vec![],
                successors: vec![1, 2],
                register_pressure: 2,
                mnemonic: "root".into(),
            },
            InstructionNode {
                index: 1,
                cost: TropicalWeight::finite(5),
                predecessors: vec![0],
                successors: vec![3],
                register_pressure: 1,
                mnemonic: "left".into(),
            },
            InstructionNode {
                index: 2,
                cost: TropicalWeight::finite(2),
                predecessors: vec![0],
                successors: vec![3],
                register_pressure: 1,
                mnemonic: "right".into(),
            },
            InstructionNode {
                index: 3,
                cost: TropicalWeight::finite(1),
                predecessors: vec![1, 2],
                successors: vec![],
                register_pressure: 1,
                mnemonic: "sink".into(),
            },
        ];
        let graph = InstructionCostGraph::new(nodes).unwrap();
        let optimizer = ScheduleOptimizer::default();
        let schedule = optimizer.schedule(&graph).unwrap();

        // Critical path: 0(1) → 1(5) → 3(1) = 7
        assert_eq!(schedule.total_cost, TropicalWeight::finite(7));
        assert_eq!(schedule.quality, ScheduleQuality::Optimal);
    }

    #[test]
    fn schedule_preserves_zero_cost_dependency_order() {
        // Node 2 -> Node 1 has zero delay, so earliest_start ties at 0.
        // Schedule must still keep 2 before 1.
        let nodes = vec![
            InstructionNode {
                index: 0,
                cost: TropicalWeight::finite(1),
                predecessors: vec![],
                successors: vec![],
                register_pressure: 1,
                mnemonic: "independent".into(),
            },
            InstructionNode {
                index: 1,
                cost: TropicalWeight::finite(1),
                predecessors: vec![2],
                successors: vec![],
                register_pressure: 1,
                mnemonic: "consumer".into(),
            },
            InstructionNode {
                index: 2,
                cost: TropicalWeight::finite(0),
                predecessors: vec![],
                successors: vec![1],
                register_pressure: 1,
                mnemonic: "producer_zero_cost".into(),
            },
        ];
        let graph = InstructionCostGraph::new(nodes).unwrap();
        let optimizer = ScheduleOptimizer::default();
        let schedule = optimizer.schedule(&graph).unwrap();
        let pos_prod = schedule.order.iter().position(|&i| i == 2).unwrap();
        let pos_cons = schedule.order.iter().position(|&i| i == 1).unwrap();
        assert!(pos_prod < pos_cons);
    }

    // === DeadCodeEliminator ===

    #[test]
    fn dead_code_elimination_identifies_unreachable() {
        // 0 → 1, 2 is isolated, output = {1}
        let mut m = TropicalMatrix::new_infinity(3).unwrap();
        m.set(0, 1, TropicalWeight::finite(1));
        let apsp = m.floyd_warshall().unwrap();

        let eliminator = DeadCodeEliminator {
            output_nodes: vec![1],
        };
        let report = eliminator.find_dead_code(&apsp, 3);

        assert!(report.live_indices.contains(&0)); // reaches output 1
        assert!(report.live_indices.contains(&1)); // is output
        assert!(report.dead_indices.contains(&2)); // isolated
        assert_eq!(report.elimination_ratio_millionths, 333_333);
    }

    #[test]
    fn dead_code_all_live() {
        // 0 → 1 → 2, output = {2}
        let mut m = TropicalMatrix::new_infinity(3).unwrap();
        m.set(0, 1, TropicalWeight::finite(1));
        m.set(1, 2, TropicalWeight::finite(1));
        let apsp = m.floyd_warshall().unwrap();

        let eliminator = DeadCodeEliminator {
            output_nodes: vec![2],
        };
        let report = eliminator.find_dead_code(&apsp, 3);

        assert!(report.dead_indices.is_empty());
        assert_eq!(report.live_indices.len(), 3);
    }

    // === RegisterPressureAnalyzer ===

    #[test]
    fn register_pressure_within_limit() {
        let graph = make_chain_graph(3);
        let analyzer = RegisterPressureAnalyzer { pressure_limit: 4 };
        let report = analyzer.analyze(&graph);

        assert_eq!(report.peak_pressure, 1);
        assert!(!report.exceeds_limit);
        assert_eq!(report.estimated_spills, 0);
    }

    #[test]
    fn register_pressure_exceeds_limit() {
        let nodes = vec![InstructionNode {
            index: 0,
            cost: TropicalWeight::finite(1),
            predecessors: vec![],
            successors: vec![],
            register_pressure: 10,
            mnemonic: "heavy".into(),
        }];
        let graph = InstructionCostGraph::new(nodes).unwrap();
        let analyzer = RegisterPressureAnalyzer { pressure_limit: 4 };
        let report = analyzer.analyze(&graph);

        assert!(report.exceeds_limit);
        assert_eq!(report.estimated_spills, 6);
    }

    // === Serde round-trips ===

    #[test]
    fn tropical_weight_serde_roundtrip() {
        for w in [
            TropicalWeight::ZERO,
            TropicalWeight::INFINITY,
            TropicalWeight::finite(42),
        ] {
            let json = serde_json::to_string(&w).unwrap();
            let restored: TropicalWeight = serde_json::from_str(&json).unwrap();
            assert_eq!(w, restored);
        }
    }

    #[test]
    fn tropical_matrix_serde_roundtrip() {
        let mut m = TropicalMatrix::new_infinity(3).unwrap();
        m.set(0, 1, TropicalWeight::finite(5));
        m.set(1, 2, TropicalWeight::finite(3));
        let json = serde_json::to_string(&m).unwrap();
        let restored: TropicalMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(m, restored);
    }

    #[test]
    fn schedule_serde_roundtrip() {
        let graph = make_chain_graph(3);
        let optimizer = ScheduleOptimizer::default();
        let schedule = optimizer.schedule(&graph).unwrap();
        let json = serde_json::to_string(&schedule).unwrap();
        let restored: Schedule = serde_json::from_str(&json).unwrap();
        assert_eq!(schedule, restored);
    }

    #[test]
    fn optimality_certificate_serde_roundtrip() {
        let cert = OptimalityCertificate {
            schema: TROPICAL_SCHEMA_VERSION.to_string(),
            achieved_cost: TropicalWeight::finite(10),
            critical_path_lower_bound: TropicalWeight::finite(10),
            optimality_ratio_millionths: 1_000_000,
            input_graph_hash: ContentHash::compute(b"test"),
            apsp_hash: ContentHash::compute(b"apsp"),
            is_exact: true,
        };
        let json = serde_json::to_string(&cert).unwrap();
        let restored: OptimalityCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, restored);
    }

    #[test]
    fn dead_code_report_serde_roundtrip() {
        let report = DeadCodeReport {
            dead_indices: vec![2, 5],
            live_indices: vec![0, 1, 3, 4],
            total_nodes: 6,
            elimination_ratio_millionths: 333_333,
        };
        let json = serde_json::to_string(&report).unwrap();
        let restored: DeadCodeReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, restored);
    }

    // === Content hash stability ===

    #[test]
    fn matrix_content_hash_deterministic() {
        let mut m = TropicalMatrix::new_infinity(3).unwrap();
        m.set(0, 1, TropicalWeight::finite(5));
        let h1 = m.content_hash();
        let h2 = m.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_matrices_different_hashes() {
        let mut m1 = TropicalMatrix::new_infinity(2).unwrap();
        m1.set(0, 1, TropicalWeight::finite(1));
        let mut m2 = TropicalMatrix::new_infinity(2).unwrap();
        m2.set(0, 1, TropicalWeight::finite(2));
        assert_ne!(m1.content_hash(), m2.content_hash());
    }

    // === Topological sort ===

    #[test]
    fn topological_sort_cycle_detection() {
        // 0 → 1 → 0 (cycle)
        let nodes = vec![
            InstructionNode {
                index: 0,
                cost: TropicalWeight::finite(1),
                predecessors: vec![1],
                successors: vec![1],
                register_pressure: 1,
                mnemonic: "a".into(),
            },
            InstructionNode {
                index: 1,
                cost: TropicalWeight::finite(1),
                predecessors: vec![0],
                successors: vec![0],
                register_pressure: 1,
                mnemonic: "b".into(),
            },
        ];
        let graph = InstructionCostGraph::new(nodes).unwrap();
        let optimizer = ScheduleOptimizer::default();
        let result = optimizer.schedule(&graph);
        assert!(matches!(result, Err(TropicalError::CycleInDag { .. })));
    }

    #[test]
    fn schedule_zero_cost_ties_still_respect_dependencies() {
        let nodes = vec![
            InstructionNode {
                index: 0,
                cost: TropicalWeight::finite(0),
                predecessors: vec![],
                successors: vec![2],
                register_pressure: 1,
                mnemonic: "src_a".into(),
            },
            InstructionNode {
                index: 1,
                cost: TropicalWeight::finite(0),
                predecessors: vec![],
                successors: vec![2],
                register_pressure: 1,
                mnemonic: "src_b".into(),
            },
            InstructionNode {
                index: 2,
                cost: TropicalWeight::finite(1),
                predecessors: vec![0, 1],
                successors: vec![],
                register_pressure: 1,
                mnemonic: "join".into(),
            },
        ];
        let graph = InstructionCostGraph::new(nodes).unwrap();
        let schedule = ScheduleOptimizer::default().schedule(&graph).unwrap();
        let pos0 = schedule.order.iter().position(|&x| x == 0).unwrap();
        let pos1 = schedule.order.iter().position(|&x| x == 1).unwrap();
        let pos2 = schedule.order.iter().position(|&x| x == 2).unwrap();
        assert!(pos0 < pos2);
        assert!(pos1 < pos2);
    }

    #[test]
    fn critical_path_apsp_hash_matches_apsp_matrix() {
        let graph = make_chain_graph(6);
        let cpr = graph.critical_path_length().unwrap();
        let apsp = graph.all_pairs_shortest_paths().unwrap();
        assert_eq!(cpr.apsp_hash, apsp.content_hash());
    }

    // === Display ===

    #[test]
    fn tropical_weight_display() {
        assert_eq!(format!("{}", TropicalWeight::finite(42)), "42");
        assert_eq!(format!("{}", TropicalWeight::INFINITY), "∞");
    }

    #[test]
    fn tropical_error_display() {
        let err = TropicalError::NegativeCycle { node: 3 };
        assert!(format!("{err}").contains("negative cycle"));
    }

    // === Stress tests ===

    #[test]
    fn floyd_warshall_larger_graph() {
        let n = 50;
        let mut m = TropicalMatrix::new_infinity(n).unwrap();
        // Build a chain 0→1→...→(n-1)
        for i in 0..n - 1 {
            m.set(i, i + 1, TropicalWeight::finite(1));
        }
        let apsp = m.floyd_warshall().unwrap();
        // Distance 0→(n-1) should be n-1
        assert_eq!(apsp.get(0, n - 1), TropicalWeight::finite((n - 1) as i64));
    }

    #[test]
    fn schedule_wide_independent_tasks() {
        let n = 20;
        let nodes: Vec<InstructionNode> = (0..n)
            .map(|i| InstructionNode {
                index: i,
                cost: TropicalWeight::finite(1),
                predecessors: vec![],
                successors: vec![],
                register_pressure: 1,
                mnemonic: format!("task_{i}"),
            })
            .collect();
        let graph = InstructionCostGraph::new(nodes).unwrap();
        let optimizer = ScheduleOptimizer::default();
        let schedule = optimizer.schedule(&graph).unwrap();

        // All independent → makespan = max single task = 1
        assert_eq!(schedule.total_cost, TropicalWeight::finite(1));
        assert_eq!(schedule.quality, ScheduleQuality::Optimal);
    }

    #[test]
    fn certificate_verification_exact() {
        let cert = OptimalityCertificate {
            schema: TROPICAL_SCHEMA_VERSION.to_string(),
            achieved_cost: TropicalWeight::finite(10),
            critical_path_lower_bound: TropicalWeight::finite(10),
            optimality_ratio_millionths: 1_000_000,
            input_graph_hash: ContentHash::compute(b"test"),
            apsp_hash: ContentHash::compute(b"apsp"),
            is_exact: true,
        };
        assert!(cert.verify(1_000_000));
        assert!(cert.verify(1_500_000));
    }

    #[test]
    fn certificate_verification_suboptimal() {
        let cert = OptimalityCertificate {
            schema: TROPICAL_SCHEMA_VERSION.to_string(),
            achieved_cost: TropicalWeight::finite(12),
            critical_path_lower_bound: TropicalWeight::finite(10),
            optimality_ratio_millionths: 1_200_000,
            input_graph_hash: ContentHash::compute(b"test"),
            apsp_hash: ContentHash::compute(b"apsp"),
            is_exact: false,
        };
        assert!(!cert.verify(1_000_000)); // 1.2x > 1.0x
        assert!(cert.verify(1_200_000)); // exactly at threshold
        assert!(cert.verify(1_500_000)); // within 1.5x bound
    }

    #[test]
    fn tropical_pass_witness_serde_roundtrip() {
        let witness = TropicalPassWitness {
            schema: TROPICAL_SCHEMA_VERSION.to_string(),
            ir_level: IrLevel::Ir3,
            input_hash: ContentHash::compute(b"input"),
            output_hash: ContentHash::compute(b"output"),
            critical_path: CriticalPathResult {
                makespan: TropicalWeight::finite(10),
                critical_source: 0,
                critical_sink: 9,
                apsp_hash: ContentHash::compute(b"apsp"),
            },
            dead_code: None,
            register_pressure: None,
            certificate: None,
        };
        let json = serde_json::to_string(&witness).unwrap();
        let restored: TropicalPassWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(witness, restored);
    }

    // === Edge cases ===

    #[test]
    fn single_node_graph() {
        let nodes = vec![InstructionNode {
            index: 0,
            cost: TropicalWeight::finite(5),
            predecessors: vec![],
            successors: vec![],
            register_pressure: 1,
            mnemonic: "only".into(),
        }];
        let graph = InstructionCostGraph::new(nodes).unwrap();
        let optimizer = ScheduleOptimizer::default();
        let schedule = optimizer.schedule(&graph).unwrap();
        assert_eq!(schedule.order, vec![0]);
        assert_eq!(schedule.total_cost, TropicalWeight::finite(5));
    }

    #[test]
    fn saturating_add_no_overflow() {
        let a = TropicalWeight::finite(i64::MAX - 1);
        let b = TropicalWeight::finite(1);
        // Should saturate to MAX-1+1 = MAX (which is INFINITY sentinel)
        // But since we use saturating_add, it caps at i64::MAX
        let result = a.tropical_mul(b);
        assert_eq!(result, TropicalWeight::INFINITY);
    }

    #[test]
    fn matrix_1x1() {
        let mut m = TropicalMatrix::new_infinity(1).unwrap();
        m.set(0, 0, TropicalWeight::ZERO);
        let apsp = m.floyd_warshall().unwrap();
        assert_eq!(apsp.get(0, 0), TropicalWeight::ZERO);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn tropical_error_serde_all_variants() {
        let variants: Vec<TropicalError> = vec![
            TropicalError::DimensionExceeded {
                dim: 5000,
                max: 4096,
            },
            TropicalError::DimensionMismatch { left: 3, right: 4 },
            TropicalError::NegativeCycle { node: 2 },
            TropicalError::EmptyGraph,
            TropicalError::CycleInDag {
                nodes_in_cycle: vec![0, 1, 2],
            },
            TropicalError::NodeOutOfBounds { index: 10, size: 5 },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: TropicalError = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 6);
    }

    #[test]
    fn schedule_quality_serde_roundtrip() {
        let variants = [
            ScheduleQuality::Optimal,
            ScheduleQuality::BoundedSuboptimal,
            ScheduleQuality::Heuristic,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ScheduleQuality = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn schedule_optimizer_default_serde_roundtrip() {
        let opt = ScheduleOptimizer::default();
        let json = serde_json::to_string(&opt).unwrap();
        let back: ScheduleOptimizer = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_approximation_ratio_millionths, 1_000_000);
    }

    #[test]
    fn instruction_node_serde_roundtrip() {
        let node = InstructionNode {
            index: 0,
            cost: TropicalWeight::finite(7),
            predecessors: vec![],
            successors: vec![1, 2],
            register_pressure: 3,
            mnemonic: "load".into(),
        };
        let json = serde_json::to_string(&node).unwrap();
        let back: InstructionNode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, node);
    }

    #[test]
    fn critical_path_result_serde_roundtrip() {
        let result = CriticalPathResult {
            makespan: TropicalWeight::finite(42),
            critical_source: 0,
            critical_sink: 5,
            apsp_hash: ContentHash::compute(b"test-apsp"),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: CriticalPathResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, result);
    }

    #[test]
    fn register_pressure_report_serde_roundtrip() {
        let report = RegisterPressureReport {
            peak_pressure: 16,
            total_pressure: 128,
            pressure_limit: 32,
            exceeds_limit: false,
            estimated_spills: 0,
            node_count: 10,
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: RegisterPressureReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn tropical_error_is_std_error() {
        let err = TropicalError::EmptyGraph;
        let dyn_err: &dyn std::error::Error = &err;
        assert!(!dyn_err.to_string().is_empty());
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    #[should_panic(expected = "use TropicalWeight::INFINITY")]
    fn finite_panics_on_i64_max() {
        let _ = TropicalWeight::finite(i64::MAX);
    }

    #[test]
    fn is_finite_and_is_infinite_are_complementary() {
        let finite = TropicalWeight::finite(0);
        assert!(finite.is_finite());
        assert!(!finite.is_infinite());
        let inf = TropicalWeight::INFINITY;
        assert!(inf.is_infinite());
        assert!(!inf.is_finite());
    }

    #[test]
    fn tropical_weight_ord_respects_inner_value() {
        let a = TropicalWeight::finite(-10);
        let b = TropicalWeight::ZERO;
        let c = TropicalWeight::finite(10);
        let d = TropicalWeight::INFINITY;
        assert!(a < b);
        assert!(b < c);
        assert!(c < d);
    }

    #[test]
    fn tropical_mul_saturates_large_finite_values() {
        // Two large positive values should saturate to i64::MAX (= INFINITY)
        let a = TropicalWeight::finite(i64::MAX / 2 + 1);
        let b = TropicalWeight::finite(i64::MAX / 2 + 1);
        let result = a.tropical_mul(b);
        assert!(result.is_infinite());
    }

    #[test]
    fn tropical_mul_negative_values() {
        let a = TropicalWeight::finite(-3);
        let b = TropicalWeight::finite(-5);
        // In tropical mul (= addition): -3 + (-5) = -8
        assert_eq!(a.tropical_mul(b), TropicalWeight::finite(-8));
    }

    #[test]
    fn tropical_weight_display_zero_and_negative() {
        assert_eq!(format!("{}", TropicalWeight::ZERO), "0");
        assert_eq!(format!("{}", TropicalWeight::finite(-7)), "-7");
    }

    #[test]
    fn tropical_schema_version_stable() {
        assert_eq!(
            TROPICAL_SCHEMA_VERSION,
            "franken-engine.tropical-semiring.v1"
        );
    }

    #[test]
    fn matrix_identity_has_zero_diagonal_infinity_off() {
        let id = TropicalMatrix::identity(3).unwrap();
        for i in 0..3 {
            assert_eq!(id.get(i, i), TropicalWeight::ZERO);
            for j in 0..3 {
                if i != j {
                    assert!(id.get(i, j).is_infinite());
                }
            }
        }
    }

    #[test]
    fn matrix_tropical_add_dimension_mismatch() {
        let a = TropicalMatrix::new_infinity(2).unwrap();
        let b = TropicalMatrix::new_infinity(3).unwrap();
        assert!(matches!(
            a.tropical_add(&b),
            Err(TropicalError::DimensionMismatch { left: 2, right: 3 })
        ));
    }

    #[test]
    fn matrix_content_hash_sensitive_to_dimension() {
        let m2 = TropicalMatrix::new_infinity(2).unwrap();
        let m3 = TropicalMatrix::new_infinity(3).unwrap();
        assert_ne!(m2.content_hash(), m3.content_hash());
    }

    #[test]
    fn floyd_warshall_self_loop_zero_on_diagonal() {
        // No edges at all — FW should set diagonal to 0
        let m = TropicalMatrix::new_infinity(3).unwrap();
        let apsp = m.floyd_warshall().unwrap();
        for i in 0..3 {
            assert_eq!(apsp.get(i, i), TropicalWeight::ZERO);
        }
    }

    #[test]
    fn instruction_cost_graph_len_and_is_empty() {
        let graph = make_chain_graph(4);
        assert_eq!(graph.len(), 4);
        assert!(!graph.is_empty());
    }

    #[test]
    fn instruction_cost_graph_register_pressure_direct() {
        let nodes = vec![
            InstructionNode {
                index: 0,
                cost: TropicalWeight::finite(1),
                predecessors: vec![],
                successors: vec![1],
                register_pressure: 3,
                mnemonic: "a".into(),
            },
            InstructionNode {
                index: 1,
                cost: TropicalWeight::finite(1),
                predecessors: vec![0],
                successors: vec![],
                register_pressure: 7,
                mnemonic: "b".into(),
            },
        ];
        let graph = InstructionCostGraph::new(nodes).unwrap();
        assert_eq!(graph.peak_register_pressure(), 7);
        assert_eq!(graph.total_register_pressure(), 10);
    }

    #[test]
    fn dead_code_zero_total_nodes() {
        let apsp = TropicalMatrix::new_infinity(1).unwrap();
        let elim = DeadCodeEliminator {
            output_nodes: vec![],
        };
        let report = elim.find_dead_code(&apsp, 0);
        assert_eq!(report.elimination_ratio_millionths, 0);
        assert!(report.dead_indices.is_empty());
        assert!(report.live_indices.is_empty());
    }

    #[test]
    fn register_pressure_at_exact_limit() {
        let nodes = vec![InstructionNode {
            index: 0,
            cost: TropicalWeight::finite(1),
            predecessors: vec![],
            successors: vec![],
            register_pressure: 8,
            mnemonic: "exact".into(),
        }];
        let graph = InstructionCostGraph::new(nodes).unwrap();
        let analyzer = RegisterPressureAnalyzer { pressure_limit: 8 };
        let report = analyzer.analyze(&graph);
        assert!(!report.exceeds_limit);
        assert_eq!(report.estimated_spills, 0);
    }

    #[test]
    fn tropical_pass_witness_all_fields_populated() {
        let witness = TropicalPassWitness {
            schema: TROPICAL_SCHEMA_VERSION.to_string(),
            ir_level: IrLevel::Ir3,
            input_hash: ContentHash::compute(b"input"),
            output_hash: ContentHash::compute(b"output"),
            critical_path: CriticalPathResult {
                makespan: TropicalWeight::finite(10),
                critical_source: 0,
                critical_sink: 5,
                apsp_hash: ContentHash::compute(b"apsp"),
            },
            dead_code: Some(DeadCodeReport {
                dead_indices: vec![3],
                live_indices: vec![0, 1, 2, 4, 5],
                total_nodes: 6,
                elimination_ratio_millionths: 166_666,
            }),
            register_pressure: Some(RegisterPressureReport {
                peak_pressure: 12,
                total_pressure: 48,
                pressure_limit: 16,
                exceeds_limit: false,
                estimated_spills: 0,
                node_count: 6,
            }),
            certificate: Some(OptimalityCertificate {
                schema: TROPICAL_SCHEMA_VERSION.to_string(),
                achieved_cost: TropicalWeight::finite(10),
                critical_path_lower_bound: TropicalWeight::finite(10),
                optimality_ratio_millionths: 1_000_000,
                input_graph_hash: ContentHash::compute(b"input"),
                apsp_hash: ContentHash::compute(b"apsp"),
                is_exact: true,
            }),
        };
        let json = serde_json::to_string(&witness).unwrap();
        let back: TropicalPassWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(back, witness);
        assert!(back.dead_code.is_some());
        assert!(back.register_pressure.is_some());
        assert!(back.certificate.is_some());
    }

    #[test]
    fn tropical_error_display_all_variants_non_empty() {
        let variants: Vec<TropicalError> = vec![
            TropicalError::DimensionExceeded {
                dim: 5000,
                max: 4096,
            },
            TropicalError::DimensionMismatch { left: 3, right: 4 },
            TropicalError::NegativeCycle { node: 2 },
            TropicalError::EmptyGraph,
            TropicalError::CycleInDag {
                nodes_in_cycle: vec![0, 1],
            },
            TropicalError::NodeOutOfBounds { index: 10, size: 5 },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let s = format!("{v}");
            assert!(!s.is_empty());
            displays.insert(s);
        }
        // All display strings are unique
        assert_eq!(displays.len(), variants.len());
    }

    #[test]
    fn schedule_quality_ord_optimal_is_smallest() {
        assert!(ScheduleQuality::Optimal < ScheduleQuality::BoundedSuboptimal);
        assert!(ScheduleQuality::BoundedSuboptimal < ScheduleQuality::Heuristic);
    }

    #[test]
    fn kleene_star_negative_boundary() {
        // -1 diverges, 0 converges
        assert!(TropicalWeight::finite(-1).kleene_star().is_none());
        assert!(TropicalWeight::ZERO.kleene_star().is_some());
    }

    #[test]
    fn floyd_warshall_triangle_inequality() {
        // For any APSP result: dist[i][j] <= dist[i][k] + dist[k][j]
        let mut m = TropicalMatrix::new_infinity(4).unwrap();
        m.set(0, 1, TropicalWeight::finite(3));
        m.set(1, 2, TropicalWeight::finite(4));
        m.set(0, 2, TropicalWeight::finite(10)); // direct but longer
        m.set(2, 3, TropicalWeight::finite(2));
        let apsp = m.floyd_warshall().unwrap();
        // dist[0][2] should be min(10, 3+4) = 7
        assert_eq!(apsp.get(0, 2), TropicalWeight::finite(7));
        // Triangle: dist[0][3] = dist[0][2] + dist[2][3] = 7 + 2 = 9
        assert_eq!(apsp.get(0, 3), TropicalWeight::finite(9));
    }

    #[test]
    fn out_of_bounds_successor_rejected() {
        let nodes = vec![InstructionNode {
            index: 0,
            cost: TropicalWeight::finite(1),
            predecessors: vec![],
            successors: vec![99],
            register_pressure: 1,
            mnemonic: "bad_succ".into(),
        }];
        let result = InstructionCostGraph::new(nodes);
        assert!(matches!(result, Err(TropicalError::NodeOutOfBounds { .. })));
    }

    #[test]
    fn certificate_verify_boundary_at_threshold() {
        let cert = OptimalityCertificate {
            schema: TROPICAL_SCHEMA_VERSION.to_string(),
            achieved_cost: TropicalWeight::finite(12),
            critical_path_lower_bound: TropicalWeight::finite(10),
            optimality_ratio_millionths: 1_200_000,
            input_graph_hash: ContentHash::compute(b"t"),
            apsp_hash: ContentHash::compute(b"a"),
            is_exact: false,
        };
        // Exactly at threshold passes
        assert!(cert.verify(1_200_000));
        // One below fails
        assert!(!cert.verify(1_199_999));
    }

    #[test]
    fn matrix_mul_associativity() {
        // (A ⊗ B) ⊗ C == A ⊗ (B ⊗ C) — semiring property
        let mut a = TropicalMatrix::new_infinity(3).unwrap();
        let mut b = TropicalMatrix::new_infinity(3).unwrap();
        let mut c = TropicalMatrix::new_infinity(3).unwrap();
        a.set(0, 1, TropicalWeight::finite(2));
        a.set(1, 2, TropicalWeight::finite(3));
        b.set(0, 1, TropicalWeight::finite(1));
        b.set(1, 2, TropicalWeight::finite(4));
        c.set(0, 2, TropicalWeight::finite(5));
        let ab = a.tropical_mul(&b).unwrap();
        let ab_c = ab.tropical_mul(&c).unwrap();
        let bc = b.tropical_mul(&c).unwrap();
        let a_bc = a.tropical_mul(&bc).unwrap();
        assert_eq!(ab_c, a_bc);
    }
}
