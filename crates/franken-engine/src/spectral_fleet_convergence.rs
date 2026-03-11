//! Spectral mixing bounds for fleet gossip convergence.
//!
//! Applies spectral graph theory to the fleet gossip topology to provide
//! **mathematically guaranteed convergence SLAs** rather than empirical ones.
//!
//! Key results:
//! - **Algebraic connectivity**: `λ₂` (the Fiedler value) of the Laplacian.
//! - **Mixing proxy bound**: `t_mix = O((λ_max/λ₂) · ln n)` for weighted
//!   gossip-like diffusion dynamics.
//! - **Cheeger-style conductance bounds** on the normalized gap:
//!   `λ₂_norm / 2 ≤ h ≤ sqrt(2 · λ₂_norm)`.
//! - **Fiedler partition detection**: The sign structure of the Fiedler
//!   vector reveals natural network partitions.
//!
//! All arithmetic uses fixed-point millionths.  No floating point.
//! Deterministic across platforms.
//!
//! Integration: consumed by `fleet_immune_protocol.rs` and
//! `fleet_convergence.rs` to produce convergence SLA certificates.
//!
//! Mathematical references:
//! - Fiedler, "Algebraic connectivity of graphs" (1973)
//! - Cheeger, "A lower bound for the smallest eigenvalue" (1970)
//! - Levin, Peres & Wilmer, "Markov Chains and Mixing Times" (2009), Ch. 12–13

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

/// Schema version for serialized spectral artifacts.
pub const SPECTRAL_SCHEMA_VERSION: &str = "franken-engine.spectral-fleet-convergence.v1";

/// Maximum number of nodes for spectral analysis (guards O(n²) memory).
const MAX_NODES: usize = 1024;

/// Number of power iterations for eigenvalue estimation.
const POWER_ITERATIONS: usize = 100;

/// Convergence threshold for power iteration (millionths).
const CONVERGENCE_THRESHOLD_MILLIONTHS: i64 = 100; // 0.0001

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from spectral analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpectralError {
    /// Too many nodes for analysis.
    TooManyNodes { count: usize, max: usize },
    /// Graph has no nodes.
    EmptyGraph,
    /// Graph is disconnected (no mixing possible).
    Disconnected { components: usize },
    /// Node index out of bounds.
    NodeOutOfBounds { index: usize, size: usize },
    /// Edge weight must be strictly positive.
    InvalidEdgeWeight { weight_millionths: i64 },
    /// Power iteration did not converge.
    ConvergenceFailure { iterations: usize },
    /// Spectral gap is zero or negative (degenerate graph).
    DegenerateSpectralGap,
}

impl fmt::Display for SpectralError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyNodes { count, max } => {
                write!(f, "{count} nodes exceeds limit {max}")
            }
            Self::EmptyGraph => write!(f, "empty graph"),
            Self::Disconnected { components } => {
                write!(f, "graph is disconnected ({components} components)")
            }
            Self::NodeOutOfBounds { index, size } => {
                write!(f, "node {index} out of bounds (size {size})")
            }
            Self::InvalidEdgeWeight { weight_millionths } => {
                write!(f, "invalid edge weight {weight_millionths}; expected > 0")
            }
            Self::ConvergenceFailure { iterations } => {
                write!(
                    f,
                    "power iteration did not converge after {iterations} iterations"
                )
            }
            Self::DegenerateSpectralGap => {
                write!(f, "spectral gap is zero or negative")
            }
        }
    }
}

impl std::error::Error for SpectralError {}

// ---------------------------------------------------------------------------
// GossipTopology — the fleet communication graph
// ---------------------------------------------------------------------------

/// Fleet gossip topology as an undirected weighted graph.
///
/// Nodes are fleet members; edges represent active gossip channels.
/// Edge weights represent communication quality (higher = better).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipTopology {
    /// Number of nodes.
    pub num_nodes: usize,
    /// Node identifiers (sorted for determinism).
    pub node_ids: Vec<String>,
    /// Adjacency list: node → [(neighbor, weight_millionths)].
    pub adjacency: BTreeMap<usize, Vec<(usize, i64)>>,
}

impl GossipTopology {
    /// Create a new topology with the given nodes.
    pub fn new(node_ids: Vec<String>) -> Result<Self, SpectralError> {
        let n = node_ids.len();
        if n == 0 {
            return Err(SpectralError::EmptyGraph);
        }
        if n > MAX_NODES {
            return Err(SpectralError::TooManyNodes {
                count: n,
                max: MAX_NODES,
            });
        }
        Ok(Self {
            num_nodes: n,
            node_ids,
            adjacency: BTreeMap::new(),
        })
    }

    /// Add an undirected edge between two nodes.
    pub fn add_edge(
        &mut self,
        from: usize,
        to: usize,
        weight_millionths: i64,
    ) -> Result<(), SpectralError> {
        if weight_millionths <= 0 {
            return Err(SpectralError::InvalidEdgeWeight { weight_millionths });
        }
        if from >= self.num_nodes {
            return Err(SpectralError::NodeOutOfBounds {
                index: from,
                size: self.num_nodes,
            });
        }
        if to >= self.num_nodes {
            return Err(SpectralError::NodeOutOfBounds {
                index: to,
                size: self.num_nodes,
            });
        }
        self.adjacency
            .entry(from)
            .or_default()
            .push((to, weight_millionths));
        if from != to {
            self.adjacency
                .entry(to)
                .or_default()
                .push((from, weight_millionths));
        }
        Ok(())
    }

    /// Compute the degree of a node (sum of edge weights in millionths).
    pub fn degree(&self, node: usize) -> i64 {
        self.adjacency
            .get(&node)
            .map(|edges| edges.iter().map(|(_, w)| *w).sum())
            .unwrap_or(0)
    }

    /// Check connectivity via BFS.
    pub fn is_connected(&self) -> bool {
        if self.num_nodes <= 1 {
            return true;
        }
        let mut visited = vec![false; self.num_nodes];
        let mut stack = vec![0usize];
        visited[0] = true;
        let mut count = 1;

        while let Some(node) = stack.pop() {
            if let Some(edges) = self.adjacency.get(&node) {
                for &(neighbor, _) in edges {
                    if !visited[neighbor] {
                        visited[neighbor] = true;
                        count += 1;
                        stack.push(neighbor);
                    }
                }
            }
        }
        count == self.num_nodes
    }

    /// Count connected components.
    pub fn connected_components(&self) -> usize {
        let mut visited = vec![false; self.num_nodes];
        let mut components = 0;

        for start in 0..self.num_nodes {
            if visited[start] {
                continue;
            }
            components += 1;
            let mut stack = vec![start];
            visited[start] = true;
            while let Some(node) = stack.pop() {
                if let Some(edges) = self.adjacency.get(&node) {
                    for &(neighbor, _) in edges {
                        if !visited[neighbor] {
                            visited[neighbor] = true;
                            stack.push(neighbor);
                        }
                    }
                }
            }
        }
        components
    }
}

// ---------------------------------------------------------------------------
// LaplacianMatrix — the graph Laplacian
// ---------------------------------------------------------------------------

/// Graph Laplacian matrix L = D - A, stored in row-major flat format.
///
/// The Laplacian is positive semi-definite with eigenvalues
/// 0 = λ₁ ≤ λ₂ ≤ ... ≤ λ_n.
///
/// The algebraic connectivity (Fiedler value) is λ₂.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaplacianMatrix {
    /// Matrix dimension.
    pub dim: usize,
    /// Row-major flat storage in millionths.
    data: Vec<i64>,
}

impl LaplacianMatrix {
    /// Construct the Laplacian from a gossip topology.
    pub fn from_topology(topology: &GossipTopology) -> Result<Self, SpectralError> {
        let n = topology.num_nodes;
        if n == 0 {
            return Err(SpectralError::EmptyGraph);
        }

        let mut data = vec![0i64; n * n];

        // Set off-diagonal entries: L[i][j] = -sum(w(i,j))
        // Accumulate weights to handle multiple edges between the same pair.
        for (&node, edges) in &topology.adjacency {
            for &(neighbor, weight) in edges {
                if node != neighbor {
                    data[node * n + neighbor] -= weight;
                }
            }
        }

        // Set diagonal entries: L[i][i] = degree(i)
        for i in 0..n {
            let degree = topology.degree(i);
            data[i * n + i] = degree;
        }

        Ok(Self { dim: n, data })
    }

    /// Get element at (i, j).
    pub fn get(&self, i: usize, j: usize) -> i64 {
        self.data[i * self.dim + j]
    }

    /// Compute a content hash for audit.
    pub fn content_hash(&self) -> ContentHash {
        let mut bytes = Vec::with_capacity(8 + self.data.len() * 8);
        bytes.extend_from_slice(&(self.dim as u64).to_be_bytes());
        for &v in &self.data {
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        ContentHash::compute(&bytes)
    }
}

// ---------------------------------------------------------------------------
// SpectralGap — the core spectral analysis
// ---------------------------------------------------------------------------

/// Result of spectral analysis on the gossip topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpectralAnalysis {
    /// Schema version.
    pub schema: String,
    /// Number of nodes.
    pub num_nodes: usize,
    /// Algebraic connectivity (Fiedler value) λ₂ in millionths.
    pub algebraic_connectivity_millionths: i64,
    /// Spectral gap proxy in millionths (here: λ₂, the algebraic connectivity).
    pub spectral_gap_millionths: i64,
    /// Mixing-time proxy upper bound: ceil((λ_max / λ₂) · ln(n)).
    pub mixing_time_bound: u64,
    /// Largest Laplacian eigenvalue λ_max in millionths.
    pub lambda_max_millionths: i64,
    /// Iterations used by λ_max power iteration.
    pub lambda_max_iterations: usize,
    /// Iterations used by Fiedler iteration.
    pub fiedler_iterations: usize,
    /// Infinity-norm residual ||L v₂ - λ₂ v₂||∞ in millionths.
    pub fiedler_residual_millionths: i64,
    /// Cheeger conductance lower bound: λ₂_norm / 2 in millionths.
    pub cheeger_lower_bound_millionths: i64,
    /// Cheeger conductance upper bound: √(2 · λ₂_norm) in millionths.
    pub cheeger_upper_bound_millionths: i64,
    /// Fiedler vector (eigenvector of λ₂) for partition detection.
    pub fiedler_vector_millionths: Vec<i64>,
    /// Detected partition (nodes with negative Fiedler components).
    pub partition_a: Vec<usize>,
    /// Nodes with non-negative Fiedler components.
    pub partition_b: Vec<usize>,
    /// Laplacian content hash for audit.
    pub laplacian_hash: ContentHash,
}

/// Spectral analyzer for gossip topologies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpectralAnalyzer {
    /// Number of power iterations.
    pub max_iterations: usize,
    /// Convergence threshold in millionths.
    pub convergence_threshold_millionths: i64,
}

impl Default for SpectralAnalyzer {
    fn default() -> Self {
        Self {
            max_iterations: POWER_ITERATIONS,
            convergence_threshold_millionths: CONVERGENCE_THRESHOLD_MILLIONTHS,
        }
    }
}

impl SpectralAnalyzer {
    /// Perform full spectral analysis on a gossip topology.
    pub fn analyze(&self, topology: &GossipTopology) -> Result<SpectralAnalysis, SpectralError> {
        if !topology.is_connected() {
            return Err(SpectralError::Disconnected {
                components: topology.connected_components(),
            });
        }

        let laplacian = LaplacianMatrix::from_topology(topology)?;
        let laplacian_hash = laplacian.content_hash();
        let n = laplacian.dim;

        // Find λ₂ (second-smallest eigenvalue) and its eigenvector
        // using inverse power iteration with deflation.

        // Step 1: Find λ_max via standard power iteration.
        let (lambda_max_est, _, lambda_max_iterations) = self.power_iteration_max(&laplacian)?;

        // Step 2: Find Fiedler value (λ₂) via shifted inverse iteration.
        // We use the property that the all-ones vector is the eigenvector
        // of λ₁ = 0, so we deflate by projecting out the uniform component.
        let (fiedler_value, fiedler_vector, fiedler_iterations) =
            self.fiedler_computation(&laplacian)?;
        // Numerical guard: by spectral theory λ_max >= λ₂ for symmetric
        // Laplacians; enforce this invariant under fixed-point approximation.
        let lambda_max = lambda_max_est.max(fiedler_value);
        let fiedler_residual =
            eigen_residual_inf_norm_millionths(&laplacian, &fiedler_vector, fiedler_value);

        // Spectral gap = λ₂ (algebraic connectivity).
        // For connected graphs, λ₂ > 0 by Fiedler's theorem.
        let spectral_gap = fiedler_value;

        if spectral_gap <= 0 {
            return Err(SpectralError::DegenerateSpectralGap);
        }

        // Mixing time bound: t_mix ≈ ceil(λ_max / λ₂ · ln(n)).
        let ln_n = integer_ln_millionths(n as u64);
        let mixing_time = if spectral_gap > 0 {
            let ratio = lambda_max as i128 * MILLION as i128 / spectral_gap as i128; // λ_max/λ₂ in millionths
            let mixed = ratio.saturating_mul(ln_n as i128) / MILLION as i128;
            #[allow(clippy::manual_div_ceil)]
            let rounds = (mixed + MILLION as i128 - 1) / MILLION as i128;
            rounds.min(i64::MAX as i128) as i64
        } else {
            i64::MAX
        };

        // Cheeger bounds (normalized):
        // λ₂_norm / 2 ≤ h ≤ sqrt(2 * λ₂_norm)
        // using λ₂_norm ≈ λ₂ / λ_max.
        let normalized_gap = if lambda_max > 0 {
            let ng = (fiedler_value as i128 * MILLION as i128) / lambda_max as i128;
            ng.clamp(i64::MIN as i128, i64::MAX as i128) as i64
        } else {
            0
        };
        let cheeger_lower = normalized_gap / 2;
        let cheeger_upper = integer_sqrt_millionths(normalized_gap.saturating_mul(2).max(0));

        // Partition detection via Fiedler vector sign.
        let mut partition_a = Vec::new();
        let mut partition_b = Vec::new();
        for (i, &v) in fiedler_vector.iter().enumerate() {
            if v < 0 {
                partition_a.push(i);
            } else {
                partition_b.push(i);
            }
        }

        Ok(SpectralAnalysis {
            schema: SPECTRAL_SCHEMA_VERSION.to_string(),
            num_nodes: n,
            algebraic_connectivity_millionths: fiedler_value,
            spectral_gap_millionths: spectral_gap,
            mixing_time_bound: mixing_time.max(1) as u64,
            lambda_max_millionths: lambda_max,
            lambda_max_iterations,
            fiedler_iterations,
            fiedler_residual_millionths: fiedler_residual,
            cheeger_lower_bound_millionths: cheeger_lower,
            cheeger_upper_bound_millionths: cheeger_upper,
            fiedler_vector_millionths: fiedler_vector,
            partition_a,
            partition_b,
            laplacian_hash,
        })
    }

    /// Standard power iteration to find the largest eigenvalue.
    fn power_iteration_max(
        &self,
        laplacian: &LaplacianMatrix,
    ) -> Result<(i64, Vec<i64>, usize), SpectralError> {
        let n = laplacian.dim;
        let mut v: Vec<i64> = (0..n).map(|i| MILLION / n as i64 + i as i64).collect();
        normalize_vector_millionths(&mut v);

        let mut lambda = 0i64;
        #[allow(clippy::needless_range_loop)]
        for iter in 0..self.max_iterations {
            let mut new_v = vec![0i64; n];
            for i in 0..n {
                let mut sum = 0i128;
                for j in 0..n {
                    sum += laplacian.get(i, j) as i128 * v[j] as i128;
                }
                new_v[i] = (sum / MILLION as i128) as i64;
            }

            normalize_vector_millionths(&mut new_v);
            // Use Rayleigh quotient on the normalized iterate for a stable
            // eigenvalue estimate of the symmetric Laplacian.
            let new_lambda = rayleigh_quotient_millionths(laplacian, &new_v);

            if (new_lambda - lambda).abs() < self.convergence_threshold_millionths {
                return Ok((new_lambda.max(0), new_v, iter + 1));
            }
            lambda = new_lambda;
            v = new_v;
        }

        Err(SpectralError::ConvergenceFailure {
            iterations: self.max_iterations,
        })
    }

    /// Compute the Fiedler value (second-smallest eigenvalue) and vector.
    ///
    /// Uses power iteration on (λ_max·I - L) with deflation of the
    /// constant eigenvector (corresponding to λ₁ = 0).
    fn fiedler_computation(
        &self,
        laplacian: &LaplacianMatrix,
    ) -> Result<(i64, Vec<i64>, usize), SpectralError> {
        let n = laplacian.dim;

        // First get λ_max.
        let (lambda_max, _, _) = self.power_iteration_max(laplacian)?;

        // Initialize with non-uniform vector orthogonal to all-ones.
        let mut v: Vec<i64> = (0..n)
            .map(|i| (i as i64 * 2 - n as i64) * MILLION / n as i64)
            .collect();
        // Project out the uniform component.
        deflate_uniform(&mut v, n);
        normalize_vector_millionths(&mut v);

        // Pre-compute the Rayleigh quotient of the initial deflated vector.
        // For graphs where λ₂ = λ_max (e.g. complete graphs), the shifted
        // operator (λ_max·I - L) maps the Fiedler space to zero, so the
        // iterate collapses. We use this initial estimate as a fallback.
        let initial_rq = rayleigh_quotient_millionths(laplacian, &v);

        let mut lambda = 0i64;
        #[allow(clippy::needless_range_loop)]
        for iter in 0..self.max_iterations {
            // Multiply by (λ_max · I - L).
            let mut new_v = vec![0i64; n];
            for i in 0..n {
                let mut sum = 0i128;
                for j in 0..n {
                    let entry = if i == j {
                        lambda_max - laplacian.get(i, j)
                    } else {
                        -laplacian.get(i, j)
                    };
                    sum += entry as i128 * v[j] as i128;
                }
                new_v[i] = (sum / MILLION as i128) as i64;
            }

            // Deflate uniform component.
            deflate_uniform(&mut new_v, n);

            // Check if the iterate collapsed to near-zero. This happens when
            // λ₂ ≈ λ_max (e.g. complete graphs where all non-trivial
            // eigenvalues are equal). In that case, use the Rayleigh quotient
            // of the pre-collapse vector as the Fiedler value.
            let norm_sq: i128 = new_v.iter().map(|&x| x as i128 * x as i128).sum();
            if norm_sq < (MILLION as i128 / 100) {
                // The iterate is effectively zero — λ₂ ≈ λ_max.
                // Return the Rayleigh quotient from the last good vector.
                let fiedler_value = rayleigh_quotient_millionths(laplacian, &v);
                let fallback = fiedler_value.max(initial_rq).max(0);
                return Ok((fallback, v, iter + 1));
            }

            // Rayleigh quotient estimate on the shifted operator before
            // renormalization. Using the normalized vector here biases λ₂.
            let new_lambda = dot_product_millionths(&new_v, &v);
            normalize_vector_millionths(&mut new_v);
            if (new_lambda - lambda).abs() < self.convergence_threshold_millionths {
                // Recover λ₂ from the converged vector using the Rayleigh
                // quotient on the original Laplacian for numerical robustness.
                let fiedler_value = rayleigh_quotient_millionths(laplacian, &new_v);
                return Ok((fiedler_value.max(0), new_v, iter + 1));
            }
            lambda = new_lambda;
            v = new_v;
        }

        Err(SpectralError::ConvergenceFailure {
            iterations: self.max_iterations,
        })
    }
}

// ---------------------------------------------------------------------------
// Convergence SLA certificate
// ---------------------------------------------------------------------------

/// Machine-checkable convergence SLA certificate.
///
/// Guarantees that gossip dissemination reaches all nodes within
/// `mixing_time_bound` rounds with high probability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceCertificate {
    pub schema: String,
    /// Number of fleet nodes.
    pub num_nodes: usize,
    /// Guaranteed mixing time (rounds).
    pub mixing_time_rounds: u64,
    /// Spectral gap (millionths).
    pub spectral_gap_millionths: i64,
    /// Conductance bounds (Cheeger inequality).
    pub cheeger_lower_millionths: i64,
    pub cheeger_upper_millionths: i64,
    /// Largest Laplacian eigenvalue λ_max in millionths.
    pub lambda_max_millionths: i64,
    /// Iteration count used to compute λ₂.
    pub fiedler_iterations: usize,
    /// Infinity-norm residual for the certified Fiedler pair.
    pub fiedler_residual_millionths: i64,
    /// Whether the graph has a natural partition.
    pub has_natural_partition: bool,
    /// Partition sizes (if detected).
    pub partition_sizes: (usize, usize),
    /// Epoch at which this certificate was computed.
    pub epoch: SecurityEpoch,
    /// Content hash for audit.
    pub certificate_hash: ContentHash,
}

impl ConvergenceCertificate {
    /// Build a convergence certificate from spectral analysis.
    pub fn from_analysis(analysis: &SpectralAnalysis, epoch: SecurityEpoch) -> Self {
        let has_partition = !analysis.partition_a.is_empty() && !analysis.partition_b.is_empty();
        let partition_sizes = (analysis.partition_a.len(), analysis.partition_b.len());

        let cert_bytes = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            analysis.num_nodes,
            analysis.spectral_gap_millionths,
            analysis.mixing_time_bound,
            analysis.lambda_max_millionths,
            analysis.fiedler_iterations,
            analysis.fiedler_residual_millionths,
            epoch.as_u64()
        );

        Self {
            schema: SPECTRAL_SCHEMA_VERSION.to_string(),
            num_nodes: analysis.num_nodes,
            mixing_time_rounds: analysis.mixing_time_bound,
            spectral_gap_millionths: analysis.spectral_gap_millionths,
            cheeger_lower_millionths: analysis.cheeger_lower_bound_millionths,
            cheeger_upper_millionths: analysis.cheeger_upper_bound_millionths,
            lambda_max_millionths: analysis.lambda_max_millionths,
            fiedler_iterations: analysis.fiedler_iterations,
            fiedler_residual_millionths: analysis.fiedler_residual_millionths,
            has_natural_partition: has_partition,
            partition_sizes,
            epoch,
            certificate_hash: ContentHash::compute(cert_bytes.as_bytes()),
        }
    }

    /// Verify that mixing time is within the SLA target (in rounds).
    pub fn meets_sla(&self, max_rounds: u64) -> bool {
        self.mixing_time_rounds <= max_rounds
    }
}

// ---------------------------------------------------------------------------
// Helper functions (no floating point)
// ---------------------------------------------------------------------------

/// Normalize a vector to unit length in millionths.
fn normalize_vector_millionths(v: &mut [i64]) {
    let norm_sq: i128 = v.iter().map(|&x| x as i128 * x as i128).sum();
    if norm_sq == 0 {
        return;
    }
    let norm = isqrt_i128(norm_sq);
    if norm == 0 {
        return;
    }
    for x in v.iter_mut() {
        *x = (*x as i128 * MILLION as i128 / norm) as i64;
    }
}

/// Deflate the uniform component from a vector.
fn deflate_uniform(v: &mut [i64], n: usize) {
    if n == 0 {
        return;
    }
    let mean: i64 = v.iter().sum::<i64>() / n as i64;
    for x in v.iter_mut() {
        *x -= mean;
    }
}

/// Dot product in millionths: (a · b) / MILLION.
fn dot_product_millionths(a: &[i64], b: &[i64]) -> i64 {
    let sum: i128 = a
        .iter()
        .zip(b.iter())
        .map(|(&ai, &bi)| ai as i128 * bi as i128)
        .sum();
    (sum / MILLION as i128) as i64
}

/// Apply Laplacian matrix to a vector in millionths.
fn apply_laplacian_millionths(laplacian: &LaplacianMatrix, v: &[i64]) -> Vec<i64> {
    let n = laplacian.dim;
    let mut out = vec![0i64; n];
    #[allow(clippy::needless_range_loop)]
    for i in 0..n {
        let mut sum = 0i128;
        #[allow(clippy::needless_range_loop)]
        for j in 0..n {
            sum += laplacian.get(i, j) as i128 * v[j] as i128;
        }
        out[i] = (sum / MILLION as i128) as i64;
    }
    out
}

/// Rayleigh quotient v^T L v / v^T v in millionths.
fn rayleigh_quotient_millionths(laplacian: &LaplacianMatrix, v: &[i64]) -> i64 {
    let lv = apply_laplacian_millionths(laplacian, v);
    let numerator = dot_product_millionths(&lv, v) as i128;
    let denominator = dot_product_millionths(v, v).max(1) as i128;
    (numerator * MILLION as i128 / denominator) as i64
}

/// Infinity norm of the eigen residual `L v - λ v` in millionths.
fn eigen_residual_inf_norm_millionths(
    laplacian: &LaplacianMatrix,
    v: &[i64],
    lambda_millionths: i64,
) -> i64 {
    let lv = apply_laplacian_millionths(laplacian, v);
    let mut max_abs = 0i64;
    for (&lvi, &vi) in lv.iter().zip(v.iter()) {
        let rhs = (lambda_millionths as i128 * vi as i128) / MILLION as i128;
        let resid = (lvi as i128 - rhs).abs().clamp(0, i64::MAX as i128) as i64;
        if resid > max_abs {
            max_abs = resid;
        }
    }
    max_abs
}

/// Integer square root of i128.
fn isqrt_i128(n: i128) -> i128 {
    if n <= 0 {
        return 0;
    }
    let bits = 128 - n.leading_zeros();
    let mut x = 1i128 << bits.div_ceil(2);
    for _ in 0..20 {
        if x == 0 {
            break;
        }
        let next = (x + n / x) / 2;
        if next >= x {
            break;
        }
        x = next;
    }
    x
}

/// Integer log₂(n) in millionths using fractional-bit extraction.
fn integer_log2_millionths(n: u64) -> i64 {
    if n <= 1 {
        return 0;
    }
    let bits = 64 - n.leading_zeros();
    let integer_part = (bits - 1) as i64 * MILLION;

    let power_of_two = 1u64 << (bits - 1);
    if n == power_of_two {
        return integer_part;
    }

    let mut mantissa: u64 = if bits - 1 <= 32 {
        n << (32 - (bits - 1))
    } else {
        n >> ((bits - 1) - 32)
    };
    let threshold: u64 = 1u64 << 33;

    let mut frac: i64 = 0;
    let mut bit_value: i64 = 500_000;
    for _ in 0..20 {
        mantissa = ((mantissa as u128 * mantissa as u128) >> 32) as u64;
        if mantissa >= threshold {
            frac += bit_value;
            mantissa >>= 1;
        }
        bit_value /= 2;
        if bit_value == 0 {
            break;
        }
    }

    integer_part + frac
}

/// Integer ln(n) in millionths.
fn integer_ln_millionths(n: u64) -> i64 {
    const LN_2_MILLIONTHS: i64 = 693_147;
    integer_log2_millionths(n) * LN_2_MILLIONTHS / MILLION
}

/// Integer sqrt of millionths-scaled value.
fn integer_sqrt_millionths(n: i64) -> i64 {
    if n <= 0 {
        return 0;
    }
    let wide = n as i128 * MILLION as i128;
    isqrt_i128(wide) as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_complete_graph(n: usize) -> GossipTopology {
        let node_ids: Vec<String> = (0..n).map(|i| format!("node_{i}")).collect();
        let mut topo = GossipTopology::new(node_ids).unwrap();
        for i in 0..n {
            for j in (i + 1)..n {
                topo.add_edge(i, j, MILLION).unwrap();
            }
        }
        topo
    }

    fn make_cycle_graph(n: usize) -> GossipTopology {
        let node_ids: Vec<String> = (0..n).map(|i| format!("node_{i}")).collect();
        let mut topo = GossipTopology::new(node_ids).unwrap();
        for i in 0..n {
            topo.add_edge(i, (i + 1) % n, MILLION).unwrap();
        }
        topo
    }

    fn make_path_graph(n: usize) -> GossipTopology {
        let node_ids: Vec<String> = (0..n).map(|i| format!("node_{i}")).collect();
        let mut topo = GossipTopology::new(node_ids).unwrap();
        for i in 0..n - 1 {
            topo.add_edge(i, i + 1, MILLION).unwrap();
        }
        topo
    }

    // === Topology ===

    #[test]
    fn complete_graph_is_connected() {
        let topo = make_complete_graph(5);
        assert!(topo.is_connected());
        assert_eq!(topo.connected_components(), 1);
    }

    #[test]
    fn disconnected_graph_detected() {
        let node_ids: Vec<String> = (0..4).map(|i| format!("node_{i}")).collect();
        let mut topo = GossipTopology::new(node_ids).unwrap();
        topo.add_edge(0, 1, MILLION).unwrap();
        topo.add_edge(2, 3, MILLION).unwrap();
        // 0-1 and 2-3 are disconnected.
        assert!(!topo.is_connected());
        assert_eq!(topo.connected_components(), 2);
    }

    #[test]
    fn cycle_graph_is_connected() {
        let topo = make_cycle_graph(6);
        assert!(topo.is_connected());
    }

    #[test]
    fn empty_graph_rejected() {
        assert!(matches!(
            GossipTopology::new(vec![]),
            Err(SpectralError::EmptyGraph)
        ));
    }

    #[test]
    fn node_out_of_bounds() {
        let topo = GossipTopology::new(vec!["a".into(), "b".into()]).unwrap();
        let mut topo = topo;
        assert!(matches!(
            topo.add_edge(0, 5, MILLION),
            Err(SpectralError::NodeOutOfBounds { .. })
        ));
    }

    #[test]
    fn nonpositive_edge_weight_rejected() {
        let mut topo = GossipTopology::new(vec!["a".into(), "b".into()]).unwrap();
        assert!(matches!(
            topo.add_edge(0, 1, 0),
            Err(SpectralError::InvalidEdgeWeight { .. })
        ));
        assert!(matches!(
            topo.add_edge(0, 1, -5),
            Err(SpectralError::InvalidEdgeWeight { .. })
        ));
    }

    #[test]
    fn degree_computation() {
        let mut topo = GossipTopology::new(vec!["a".into(), "b".into(), "c".into()]).unwrap();
        topo.add_edge(0, 1, MILLION).unwrap();
        topo.add_edge(0, 2, 500_000).unwrap();
        assert_eq!(topo.degree(0), 1_500_000);
        assert_eq!(topo.degree(1), MILLION);
    }

    // === Laplacian ===

    #[test]
    fn laplacian_row_sums_to_zero() {
        let topo = make_complete_graph(4);
        let laplacian = LaplacianMatrix::from_topology(&topo).unwrap();
        for i in 0..4 {
            let row_sum: i64 = (0..4).map(|j| laplacian.get(i, j)).sum();
            assert_eq!(row_sum, 0, "row {i} should sum to zero");
        }
    }

    #[test]
    fn laplacian_is_symmetric() {
        let topo = make_cycle_graph(5);
        let laplacian = LaplacianMatrix::from_topology(&topo).unwrap();
        for i in 0..5 {
            for j in 0..5 {
                assert_eq!(
                    laplacian.get(i, j),
                    laplacian.get(j, i),
                    "L[{i},{j}] != L[{j},{i}]"
                );
            }
        }
    }

    #[test]
    fn laplacian_diagonal_is_degree() {
        let topo = make_complete_graph(3);
        let laplacian = LaplacianMatrix::from_topology(&topo).unwrap();
        // In complete graph K3, each node has degree 2 (two edges of weight 1M).
        for i in 0..3 {
            assert_eq!(laplacian.get(i, i), 2 * MILLION);
        }
    }

    #[test]
    fn laplacian_content_hash_deterministic() {
        let topo = make_complete_graph(3);
        let l1 = LaplacianMatrix::from_topology(&topo).unwrap();
        let l2 = LaplacianMatrix::from_topology(&topo).unwrap();
        assert_eq!(l1.content_hash(), l2.content_hash());
    }

    // === Spectral Analysis ===

    #[test]
    fn complete_graph_spectral_analysis() {
        let topo = make_complete_graph(4);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();

        assert_eq!(analysis.num_nodes, 4);
        // Complete graph has high algebraic connectivity.
        assert!(analysis.algebraic_connectivity_millionths > 0);
        assert!(analysis.spectral_gap_millionths > 0);
        // Mixing time should be low for complete graph.
        assert!(analysis.mixing_time_bound < 100);
        assert!(analysis.lambda_max_millionths >= analysis.algebraic_connectivity_millionths);
        assert!(analysis.lambda_max_iterations >= 1);
        assert!(analysis.lambda_max_iterations <= analyzer.max_iterations);
        assert!(analysis.fiedler_iterations >= 1);
        assert!(analysis.fiedler_iterations <= analyzer.max_iterations);
        assert!(analysis.fiedler_residual_millionths >= 0);
    }

    #[test]
    fn path_graph_slower_mixing() {
        let complete = make_complete_graph(6);
        let path = make_path_graph(6);
        let analyzer = SpectralAnalyzer::default();

        let complete_analysis = analyzer.analyze(&complete).unwrap();
        let path_analysis = analyzer.analyze(&path).unwrap();

        // Path graph should have higher mixing time than complete graph.
        assert!(
            path_analysis.mixing_time_bound >= complete_analysis.mixing_time_bound,
            "path ({}) should mix slower than complete ({})",
            path_analysis.mixing_time_bound,
            complete_analysis.mixing_time_bound
        );
    }

    #[test]
    fn disconnected_graph_rejected() {
        let node_ids: Vec<String> = (0..4).map(|i| format!("node_{i}")).collect();
        let mut topo = GossipTopology::new(node_ids).unwrap();
        topo.add_edge(0, 1, MILLION).unwrap();
        // 2 and 3 are isolated.
        let analyzer = SpectralAnalyzer::default();
        assert!(matches!(
            analyzer.analyze(&topo),
            Err(SpectralError::Disconnected { .. })
        ));
    }

    #[test]
    fn fiedler_vector_partitions_barbell() {
        // Barbell: 0-1-2 connected, 3-4-5 connected, with one bridge 2-3.
        let node_ids: Vec<String> = (0..6).map(|i| format!("node_{i}")).collect();
        let mut topo = GossipTopology::new(node_ids).unwrap();
        // Clique 1.
        topo.add_edge(0, 1, MILLION).unwrap();
        topo.add_edge(1, 2, MILLION).unwrap();
        topo.add_edge(0, 2, MILLION).unwrap();
        // Bridge.
        topo.add_edge(2, 3, MILLION).unwrap();
        // Clique 2.
        topo.add_edge(3, 4, MILLION).unwrap();
        topo.add_edge(4, 5, MILLION).unwrap();
        topo.add_edge(3, 5, MILLION).unwrap();

        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();

        // Fiedler vector should partition into two groups roughly {0,1,2} and {3,4,5}.
        assert!(!analysis.partition_a.is_empty());
        assert!(!analysis.partition_b.is_empty());
    }

    // === Convergence Certificate ===

    #[test]
    fn convergence_certificate_from_analysis() {
        let topo = make_complete_graph(5);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));

        assert_eq!(cert.num_nodes, 5);
        assert!(cert.spectral_gap_millionths > 0);
        assert_eq!(cert.lambda_max_millionths, analysis.lambda_max_millionths);
        assert_eq!(cert.fiedler_iterations, analysis.fiedler_iterations);
        assert_eq!(
            cert.fiedler_residual_millionths,
            analysis.fiedler_residual_millionths
        );
    }

    #[test]
    fn convergence_certificate_sla_check() {
        let topo = make_complete_graph(5);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));

        // Complete graph should meet a generous SLA.
        assert!(cert.meets_sla(1000));
    }

    #[test]
    fn convergence_certificate_serde_roundtrip() {
        let topo = make_complete_graph(4);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(42));

        let json = serde_json::to_string(&cert).unwrap();
        let restored: ConvergenceCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, restored);
    }

    #[test]
    fn spectral_analysis_serde_roundtrip() {
        let topo = make_complete_graph(3);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();

        let json = serde_json::to_string(&analysis).unwrap();
        let restored: SpectralAnalysis = serde_json::from_str(&json).unwrap();
        assert_eq!(analysis, restored);
    }

    // === Cheeger inequality ===

    #[test]
    fn cheeger_bounds_consistent() {
        let topo = make_complete_graph(5);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();

        // λ₂_norm / 2 ≤ h ≤ sqrt(2 * λ₂_norm)
        assert!(analysis.cheeger_lower_bound_millionths >= 0);
        assert!(analysis.cheeger_upper_bound_millionths >= analysis.cheeger_lower_bound_millionths);
    }

    // === Edge cases ===

    #[test]
    fn single_node_graph() {
        let topo = GossipTopology::new(vec!["solo".into()]).unwrap();
        assert!(topo.is_connected());
        // Spectral analysis on 1-node graph: no edges, but connected.
        // Laplacian is [0], which has spectral gap issues.
        let analyzer = SpectralAnalyzer::default();
        let result = analyzer.analyze(&topo);
        // Expected to fail with degenerate spectral gap (λ_max = 0).
        assert!(result.is_err());
    }

    #[test]
    fn two_node_graph() {
        let mut topo = GossipTopology::new(vec!["a".into(), "b".into()]).unwrap();
        topo.add_edge(0, 1, MILLION).unwrap();
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();

        assert_eq!(analysis.num_nodes, 2);
        assert!(analysis.algebraic_connectivity_millionths > 0);
        // For a 2-node graph with unit weight, Laplacian eigenvalues are 0 and 2.
        assert!((analysis.algebraic_connectivity_millionths - 2 * MILLION).abs() < 200_000);
    }

    #[test]
    fn mixing_time_bound_avoids_overflow_on_large_weights() {
        let mut topo = GossipTopology::new(vec!["a".into(), "b".into(), "c".into()]).unwrap();
        let w = i64::MAX / 16;
        topo.add_edge(0, 1, w).unwrap();
        topo.add_edge(1, 2, w).unwrap();
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        assert!(analysis.mixing_time_bound >= 1);
    }

    // === Helper functions ===

    #[test]
    fn normalize_vector_basic() {
        let mut v = vec![MILLION, 0];
        normalize_vector_millionths(&mut v);
        // Should be close to [1M, 0] (unit vector).
        assert!(v[0].abs() > 900_000);
        assert!(v[1].abs() < 100_000);
    }

    #[test]
    fn deflate_uniform_removes_mean() {
        let mut v = vec![MILLION, 2 * MILLION, 3 * MILLION];
        deflate_uniform(&mut v, 3);
        let sum: i64 = v.iter().sum();
        assert!(sum.abs() < 3); // should be ~0 (rounding).
    }

    #[test]
    fn dot_product_basic() {
        let a = vec![MILLION, 0];
        let b = vec![MILLION, 0];
        let dot = dot_product_millionths(&a, &b);
        assert_eq!(dot, MILLION); // 1·1 + 0·0 = 1
    }

    #[test]
    fn integer_ln_basic_values() {
        assert_eq!(integer_ln_millionths(1), 0);
        let ln2 = integer_ln_millionths(2);
        assert!((ln2 - 693_147).abs() < 20_000);
        let ln4 = integer_ln_millionths(4);
        assert!((ln4 - 2 * 693_147).abs() < 30_000);
        assert!(integer_ln_millionths(16) > integer_ln_millionths(4));
    }

    #[test]
    fn integer_log2_large_values_stay_normalized() {
        let n = (1u64 << 40) + 1;
        let l = integer_log2_millionths(n);
        assert!(l >= 40 * MILLION);
        assert!(l < 40 * MILLION + 20_000);
    }

    #[test]
    fn integer_ln_large_values_reasonable() {
        let n = 1u64 << 40;
        let ln = integer_ln_millionths(n);
        let expected = 40 * 693_147;
        assert!((ln - expected).abs() < 40_000);
    }

    #[test]
    fn isqrt_basic() {
        assert_eq!(isqrt_i128(0), 0);
        assert_eq!(isqrt_i128(1), 1);
        assert_eq!(isqrt_i128(4), 2);
        assert_eq!(isqrt_i128(9), 3);
        assert_eq!(isqrt_i128(100), 10);
    }

    #[test]
    fn topology_serde_roundtrip() {
        let topo = make_complete_graph(3);
        let json = serde_json::to_string(&topo).unwrap();
        let restored: GossipTopology = serde_json::from_str(&json).unwrap();
        assert_eq!(topo, restored);
    }

    #[test]
    fn spectral_error_display() {
        let err = SpectralError::Disconnected { components: 3 };
        assert!(format!("{err}").contains("disconnected"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: SpectralError display all variants
    // -----------------------------------------------------------------------

    #[test]
    fn spectral_error_display_all_variants() {
        let displays: std::collections::BTreeSet<String> = vec![
            SpectralError::EmptyGraph,
            SpectralError::NodeOutOfBounds { index: 5, size: 3 },
            SpectralError::InvalidEdgeWeight {
                weight_millionths: -1,
            },
            SpectralError::Disconnected { components: 2 },
            SpectralError::DegenerateSpectralGap,
        ]
        .into_iter()
        .map(|e| e.to_string())
        .collect();
        assert_eq!(displays.len(), 5, "all 5 variants have distinct Display");
    }

    // -----------------------------------------------------------------------
    // Enrichment: SpectralError serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn spectral_error_serde_all_variants() {
        let errors = vec![
            SpectralError::EmptyGraph,
            SpectralError::NodeOutOfBounds { index: 5, size: 3 },
            SpectralError::InvalidEdgeWeight {
                weight_millionths: -1,
            },
            SpectralError::Disconnected { components: 2 },
            SpectralError::DegenerateSpectralGap,
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: SpectralError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: SpectralError implements std::error::Error
    // -----------------------------------------------------------------------

    #[test]
    fn spectral_error_implements_std_error() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(SpectralError::EmptyGraph),
            Box::new(SpectralError::NodeOutOfBounds { index: 0, size: 0 }),
            Box::new(SpectralError::InvalidEdgeWeight {
                weight_millionths: 0,
            }),
            Box::new(SpectralError::Disconnected { components: 3 }),
            Box::new(SpectralError::DegenerateSpectralGap),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: cycle has lower connectivity than complete
    // -----------------------------------------------------------------------

    #[test]
    fn cycle_lower_connectivity_than_complete() {
        let analyzer = SpectralAnalyzer::default();
        let complete = analyzer.analyze(&make_complete_graph(6)).unwrap();
        let cycle = analyzer.analyze(&make_cycle_graph(6)).unwrap();
        assert!(
            cycle.algebraic_connectivity_millionths < complete.algebraic_connectivity_millionths,
            "cycle ({}) should have lower λ₂ than complete ({})",
            cycle.algebraic_connectivity_millionths,
            complete.algebraic_connectivity_millionths
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: ConvergenceCertificate fails tight SLA
    // -----------------------------------------------------------------------

    #[test]
    fn convergence_certificate_fails_tight_sla() {
        let topo = make_path_graph(10);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
        // Path graph with 10 nodes has slow mixing — should fail SLA of 1 round.
        assert!(
            !cert.meets_sla(1),
            "path graph should not meet SLA of 1: mixing_time={}",
            cert.mixing_time_rounds
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: LaplacianMatrix serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn laplacian_matrix_serde_roundtrip() {
        let topo = make_complete_graph(3);
        let lap = LaplacianMatrix::from_topology(&topo).unwrap();
        let json = serde_json::to_string(&lap).unwrap();
        let back: LaplacianMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(lap, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: self-loop rejected
    // -----------------------------------------------------------------------

    #[test]
    fn self_loop_accepted_or_handled() {
        let mut topo = GossipTopology::new(vec!["a".into(), "b".into()]).unwrap();
        // Self-loop: edge from node 0 to itself.
        // Depending on implementation, either rejected or added.
        let result = topo.add_edge(0, 0, MILLION);
        // Just verify it doesn't panic.
        let _ = result;
    }

    // -----------------------------------------------------------------------
    // Enrichment: topology node count
    // -----------------------------------------------------------------------

    #[test]
    fn topology_node_count() {
        let topo = make_complete_graph(5);
        assert_eq!(topo.node_ids.len(), 5);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Cheeger bounds for path graph
    // -----------------------------------------------------------------------

    #[test]
    fn cheeger_bounds_for_path_graph() {
        let topo = make_path_graph(6);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        assert!(analysis.cheeger_lower_bound_millionths >= 0);
        assert!(analysis.cheeger_upper_bound_millionths >= analysis.cheeger_lower_bound_millionths);
    }

    // -----------------------------------------------------------------------
    // Enrichment: spectral analysis deterministic
    // -----------------------------------------------------------------------

    #[test]
    fn spectral_analysis_deterministic() {
        let analyzer = SpectralAnalyzer::default();
        let topo = make_complete_graph(5);
        let a1 = analyzer.analyze(&topo).unwrap();
        let a2 = analyzer.analyze(&topo).unwrap();
        assert_eq!(a1, a2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: dot_product with mixed signs
    // -----------------------------------------------------------------------

    #[test]
    fn dot_product_mixed_signs() {
        let a = vec![MILLION, -MILLION];
        let b = vec![MILLION, MILLION];
        let dot = dot_product_millionths(&a, &b);
        // 1*1 + (-1)*1 = 0
        assert_eq!(dot, 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: schema version constant
    // -----------------------------------------------------------------------

    #[test]
    fn schema_version_constant() {
        assert!(!SPECTRAL_SCHEMA_VERSION.is_empty());
        assert!(SPECTRAL_SCHEMA_VERSION.contains("spectral"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: weighted graph with non-uniform weights
    // -----------------------------------------------------------------------

    #[test]
    fn non_uniform_weights_analysis() {
        let node_ids: Vec<String> = (0..4).map(|i| format!("node_{i}")).collect();
        let mut topo = GossipTopology::new(node_ids).unwrap();
        // Strong connections in one group, weak bridge
        topo.add_edge(0, 1, 10 * MILLION).unwrap();
        topo.add_edge(2, 3, 10 * MILLION).unwrap();
        topo.add_edge(1, 2, MILLION / 10).unwrap(); // weak bridge
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        assert!(analysis.algebraic_connectivity_millionths > 0);
        // Weak bridge should produce low connectivity
        assert!(analysis.algebraic_connectivity_millionths < 5 * MILLION);
    }

    // -----------------------------------------------------------------------
    // Enrichment: star graph topology
    // -----------------------------------------------------------------------

    #[test]
    fn star_graph_connected_analysis() {
        let n = 5;
        let node_ids: Vec<String> = (0..n).map(|i| format!("node_{i}")).collect();
        let mut topo = GossipTopology::new(node_ids).unwrap();
        // Node 0 is the center, connected to all others
        for i in 1..n {
            topo.add_edge(0, i, MILLION).unwrap();
        }
        assert!(topo.is_connected());
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        assert!(analysis.algebraic_connectivity_millionths > 0);
        assert_eq!(analysis.num_nodes, n);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Fiedler vector length matches num_nodes
    // -----------------------------------------------------------------------

    #[test]
    fn fiedler_vector_length_matches_nodes() {
        let topo = make_complete_graph(6);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        assert_eq!(analysis.fiedler_vector_millionths.len(), 6);
    }

    // -----------------------------------------------------------------------
    // Enrichment: partitions cover all nodes
    // -----------------------------------------------------------------------

    #[test]
    fn partitions_cover_all_nodes() {
        let topo = make_path_graph(8);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        assert_eq!(
            analysis.partition_a.len() + analysis.partition_b.len(),
            8,
            "partitions should cover all nodes"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: certificate epoch stored correctly
    // -----------------------------------------------------------------------

    #[test]
    fn certificate_epoch_stored() {
        let topo = make_complete_graph(4);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(99));
        assert_eq!(cert.epoch, SecurityEpoch::from_raw(99));
    }

    // -----------------------------------------------------------------------
    // Enrichment: certificate hash deterministic
    // -----------------------------------------------------------------------

    #[test]
    fn certificate_hash_deterministic() {
        let topo = make_complete_graph(4);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        let cert1 = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
        let cert2 = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
        assert_eq!(cert1.certificate_hash, cert2.certificate_hash);
    }

    // -----------------------------------------------------------------------
    // Enrichment: certificate has_natural_partition
    // -----------------------------------------------------------------------

    #[test]
    fn certificate_partition_field() {
        let topo = make_path_graph(6);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
        // Path graph always produces a natural partition
        assert!(cert.has_natural_partition);
        assert!(cert.partition_sizes.0 > 0);
        assert!(cert.partition_sizes.1 > 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: degree of isolated node
    // -----------------------------------------------------------------------

    #[test]
    fn degree_of_isolated_node_is_zero() {
        let topo = GossipTopology::new(vec!["a".into(), "b".into(), "c".into()]).unwrap();
        // No edges added — all nodes isolated
        assert_eq!(topo.degree(0), 0);
        assert_eq!(topo.degree(1), 0);
        assert_eq!(topo.degree(2), 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: connected_components all isolated
    // -----------------------------------------------------------------------

    #[test]
    fn all_isolated_nodes_components() {
        let topo = GossipTopology::new(vec!["a".into(), "b".into(), "c".into()]).unwrap();
        assert!(!topo.is_connected());
        assert_eq!(topo.connected_components(), 3);
    }

    // -----------------------------------------------------------------------
    // Enrichment: integer_sqrt_millionths edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn integer_sqrt_millionths_edge_cases() {
        assert_eq!(integer_sqrt_millionths(0), 0);
        assert_eq!(integer_sqrt_millionths(-5), 0);
        // sqrt(1M) in millionths = sqrt(1.0) = 1.0 = 1M
        let result = integer_sqrt_millionths(MILLION);
        assert!((result - MILLION).abs() < 1000);
    }

    // -----------------------------------------------------------------------
    // Enrichment: integer_log2_millionths edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn integer_log2_edge_cases() {
        assert_eq!(integer_log2_millionths(0), 0);
        assert_eq!(integer_log2_millionths(1), 0);
        // log2(2) = 1.0 = 1M
        assert_eq!(integer_log2_millionths(2), MILLION);
        // log2(4) = 2.0 = 2M
        assert_eq!(integer_log2_millionths(4), 2 * MILLION);
        // log2(8) = 3.0 = 3M
        assert_eq!(integer_log2_millionths(8), 3 * MILLION);
    }

    // -----------------------------------------------------------------------
    // Enrichment: isqrt_i128 large value
    // -----------------------------------------------------------------------

    #[test]
    fn isqrt_i128_large_value() {
        let n: i128 = 1_000_000_000_000;
        let s = isqrt_i128(n);
        assert_eq!(s, 1_000_000); // sqrt(10^12) = 10^6
    }

    // -----------------------------------------------------------------------
    // Enrichment: SpectralAnalyzer clone
    // -----------------------------------------------------------------------

    #[test]
    fn spectral_analyzer_clone() {
        let a = SpectralAnalyzer::default();
        let b = a.clone();
        assert_eq!(a.max_iterations, b.max_iterations);
        assert_eq!(
            a.convergence_threshold_millionths,
            b.convergence_threshold_millionths
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: analysis schema field
    // -----------------------------------------------------------------------

    #[test]
    fn analysis_schema_field_set() {
        let topo = make_complete_graph(3);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        assert_eq!(analysis.schema, SPECTRAL_SCHEMA_VERSION);
    }

    // ── Enrichment: Copy/Clone/Debug/Serde/Display/Hash/Edge ──

    #[test]
    fn spectral_error_debug_distinct() {
        let variants: Vec<SpectralError> = vec![
            SpectralError::TooManyNodes { count: 1, max: 1 },
            SpectralError::EmptyGraph,
            SpectralError::Disconnected { components: 2 },
            SpectralError::NodeOutOfBounds { index: 0, size: 0 },
            SpectralError::InvalidEdgeWeight {
                weight_millionths: -1,
            },
            SpectralError::ConvergenceFailure { iterations: 10 },
            SpectralError::DegenerateSpectralGap,
        ];
        let set: std::collections::BTreeSet<String> =
            variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), 7);
    }

    #[test]
    fn spectral_error_serde_variant_distinct() {
        let variants: Vec<SpectralError> = vec![
            SpectralError::TooManyNodes { count: 1, max: 1 },
            SpectralError::EmptyGraph,
            SpectralError::Disconnected { components: 2 },
            SpectralError::NodeOutOfBounds { index: 0, size: 0 },
            SpectralError::InvalidEdgeWeight {
                weight_millionths: -1,
            },
            SpectralError::ConvergenceFailure { iterations: 10 },
            SpectralError::DegenerateSpectralGap,
        ];
        let set: std::collections::BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(set.len(), 7);
    }

    #[test]
    fn spectral_error_display_exact_too_many_nodes() {
        let e = SpectralError::TooManyNodes {
            count: 2000,
            max: 1024,
        };
        assert_eq!(e.to_string(), "2000 nodes exceeds limit 1024");
    }

    #[test]
    fn spectral_error_display_exact_empty_graph() {
        assert_eq!(SpectralError::EmptyGraph.to_string(), "empty graph");
    }

    #[test]
    fn spectral_error_display_exact_disconnected() {
        let e = SpectralError::Disconnected { components: 3 };
        assert_eq!(e.to_string(), "graph is disconnected (3 components)");
    }

    #[test]
    fn spectral_error_display_exact_node_out_of_bounds() {
        let e = SpectralError::NodeOutOfBounds { index: 5, size: 3 };
        assert_eq!(e.to_string(), "node 5 out of bounds (size 3)");
    }

    #[test]
    fn spectral_error_display_exact_invalid_edge_weight() {
        let e = SpectralError::InvalidEdgeWeight {
            weight_millionths: -100,
        };
        assert_eq!(e.to_string(), "invalid edge weight -100; expected > 0");
    }

    #[test]
    fn spectral_error_display_exact_convergence_failure() {
        let e = SpectralError::ConvergenceFailure { iterations: 100 };
        assert_eq!(
            e.to_string(),
            "power iteration did not converge after 100 iterations"
        );
    }

    #[test]
    fn spectral_error_display_exact_degenerate() {
        assert_eq!(
            SpectralError::DegenerateSpectralGap.to_string(),
            "spectral gap is zero or negative"
        );
    }

    #[test]
    fn spectral_error_clone_independence() {
        let a = SpectralError::Disconnected { components: 5 };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn spectral_error_std_error_source_is_none() {
        let e: &dyn std::error::Error = &SpectralError::EmptyGraph;
        assert!(e.source().is_none());
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn gossip_topology_clone_independence() {
        let t = make_complete_graph(3);
        let t2 = t.clone();
        assert_eq!(t, t2);
    }

    #[test]
    fn gossip_topology_json_field_names() {
        let t = GossipTopology::new(vec!["a".to_string()]).unwrap();
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("\"num_nodes\""));
        assert!(json.contains("\"node_ids\""));
        assert!(json.contains("\"adjacency\""));
    }

    #[test]
    fn spectral_analysis_clone_independence() {
        let topo = make_complete_graph(3);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        let clone = analysis.clone();
        assert_eq!(analysis, clone);
    }

    #[test]
    fn spectral_analysis_json_field_names() {
        let topo = make_complete_graph(3);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        let json = serde_json::to_string(&analysis).unwrap();
        assert!(json.contains("\"schema\""));
        assert!(json.contains("\"num_nodes\""));
        assert!(json.contains("\"algebraic_connectivity_millionths\""));
        assert!(json.contains("\"spectral_gap_millionths\""));
        assert!(json.contains("\"mixing_time_bound\""));
        assert!(json.contains("\"lambda_max_millionths\""));
        assert!(json.contains("\"fiedler_vector_millionths\""));
        assert!(json.contains("\"partition_a\""));
        assert!(json.contains("\"partition_b\""));
        assert!(json.contains("\"laplacian_hash\""));
    }

    #[test]
    fn spectral_analysis_serde_roundtrip_enriched() {
        let topo = make_complete_graph(3);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        let json = serde_json::to_string(&analysis).unwrap();
        let back: SpectralAnalysis = serde_json::from_str(&json).unwrap();
        assert_eq!(analysis, back);
    }

    #[test]
    fn spectral_analyzer_default_values() {
        let a = SpectralAnalyzer::default();
        assert_eq!(a.max_iterations, POWER_ITERATIONS);
        assert_eq!(
            a.convergence_threshold_millionths,
            CONVERGENCE_THRESHOLD_MILLIONTHS
        );
    }

    #[test]
    fn spectral_analyzer_json_field_names() {
        let a = SpectralAnalyzer::default();
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.contains("\"max_iterations\""));
        assert!(json.contains("\"convergence_threshold_millionths\""));
    }

    #[test]
    fn laplacian_matrix_clone_independence() {
        let topo = make_complete_graph(3);
        let l = LaplacianMatrix::from_topology(&topo).unwrap();
        let l2 = l.clone();
        assert_eq!(l, l2);
    }

    #[test]
    fn laplacian_matrix_serde_roundtrip_enriched() {
        let topo = make_complete_graph(3);
        let l = LaplacianMatrix::from_topology(&topo).unwrap();
        let json = serde_json::to_string(&l).unwrap();
        let back: LaplacianMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(l, back);
    }

    #[test]
    fn laplacian_content_hash_deterministic_enriched() {
        let topo = make_complete_graph(3);
        let l = LaplacianMatrix::from_topology(&topo).unwrap();
        let h1 = l.content_hash();
        let h2 = l.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn debug_nonempty_spectral_error() {
        assert!(!format!("{:?}", SpectralError::EmptyGraph).is_empty());
    }

    #[test]
    fn debug_nonempty_gossip_topology() {
        let t = GossipTopology::new(vec!["a".to_string()]).unwrap();
        assert!(!format!("{t:?}").is_empty());
    }

    #[test]
    fn debug_nonempty_laplacian_matrix() {
        let topo = make_complete_graph(2);
        let l = LaplacianMatrix::from_topology(&topo).unwrap();
        assert!(!format!("{l:?}").is_empty());
    }

    #[test]
    fn debug_nonempty_spectral_analyzer() {
        assert!(!format!("{:?}", SpectralAnalyzer::default()).is_empty());
    }

    #[test]
    fn debug_nonempty_spectral_analysis() {
        let topo = make_complete_graph(3);
        let analyzer = SpectralAnalyzer::default();
        let a = analyzer.analyze(&topo).unwrap();
        assert!(!format!("{a:?}").is_empty());
    }

    #[test]
    fn boundary_single_node_graph() {
        let topo = GossipTopology::new(vec!["solo".to_string()]).unwrap();
        assert!(topo.is_connected());
        assert_eq!(topo.connected_components(), 1);
        assert_eq!(topo.degree(0), 0);
    }

    #[test]
    fn boundary_self_loop_edge() {
        let mut topo = GossipTopology::new(vec!["a".to_string()]).unwrap();
        topo.add_edge(0, 0, MILLION).unwrap();
        assert_eq!(topo.degree(0), MILLION);
    }

    #[test]
    fn boundary_edge_weight_zero_rejected() {
        let mut topo = GossipTopology::new(vec!["a".to_string(), "b".to_string()]).unwrap();
        let err = topo.add_edge(0, 1, 0).unwrap_err();
        assert!(matches!(
            err,
            SpectralError::InvalidEdgeWeight {
                weight_millionths: 0
            }
        ));
    }

    #[test]
    fn boundary_negative_edge_weight_rejected() {
        let mut topo = GossipTopology::new(vec!["a".to_string(), "b".to_string()]).unwrap();
        let err = topo.add_edge(0, 1, -1).unwrap_err();
        assert!(matches!(
            err,
            SpectralError::InvalidEdgeWeight {
                weight_millionths: -1
            }
        ));
    }

    #[test]
    fn boundary_node_out_of_bounds_from() {
        let mut topo = GossipTopology::new(vec!["a".to_string()]).unwrap();
        let err = topo.add_edge(5, 0, MILLION).unwrap_err();
        assert!(matches!(
            err,
            SpectralError::NodeOutOfBounds { index: 5, .. }
        ));
    }

    #[test]
    fn boundary_node_out_of_bounds_to() {
        let mut topo = GossipTopology::new(vec!["a".to_string()]).unwrap();
        let err = topo.add_edge(0, 5, MILLION).unwrap_err();
        assert!(matches!(
            err,
            SpectralError::NodeOutOfBounds { index: 5, .. }
        ));
    }

    #[test]
    fn disconnected_graph_analysis_error() {
        let topo = GossipTopology::new(vec!["a".to_string(), "b".to_string()]).unwrap();
        assert!(!topo.is_connected());
        assert_eq!(topo.connected_components(), 2);
        let analyzer = SpectralAnalyzer::default();
        let err = analyzer.analyze(&topo).unwrap_err();
        assert!(matches!(err, SpectralError::Disconnected { components: 2 }));
    }

    #[test]
    fn schema_version_constant_stable() {
        assert_eq!(
            SPECTRAL_SCHEMA_VERSION,
            "franken-engine.spectral-fleet-convergence.v1"
        );
    }

    #[test]
    fn partitions_cover_all_nodes_k4() {
        let topo = make_complete_graph(4);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        let total = analysis.partition_a.len() + analysis.partition_b.len();
        assert_eq!(total, 4);
    }

    #[test]
    fn spectral_error_serde_roundtrip_all_variants() {
        let variants: Vec<SpectralError> = vec![
            SpectralError::TooManyNodes {
                count: 2000,
                max: 1024,
            },
            SpectralError::EmptyGraph,
            SpectralError::Disconnected { components: 3 },
            SpectralError::NodeOutOfBounds { index: 5, size: 3 },
            SpectralError::InvalidEdgeWeight {
                weight_millionths: -100,
            },
            SpectralError::ConvergenceFailure { iterations: 100 },
            SpectralError::DegenerateSpectralGap,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: SpectralError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn complete_graph_k4_positive_algebraic_connectivity() {
        let topo = make_complete_graph(4);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        assert!(analysis.algebraic_connectivity_millionths > 0);
        assert!(analysis.mixing_time_bound >= 1);
    }

    #[test]
    fn complete_graph_k4_cheeger_bounds_ordered() {
        let topo = make_complete_graph(4);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        assert!(analysis.cheeger_lower_bound_millionths <= analysis.cheeger_upper_bound_millionths);
    }

    #[test]
    fn gossip_topology_serde_roundtrip() {
        let topo = make_complete_graph(3);
        let json = serde_json::to_string(&topo).unwrap();
        let back: GossipTopology = serde_json::from_str(&json).unwrap();
        assert_eq!(topo, back);
    }

    #[test]
    fn spectral_analyzer_serde_roundtrip() {
        let a = SpectralAnalyzer::default();
        let json = serde_json::to_string(&a).unwrap();
        let back: SpectralAnalyzer = serde_json::from_str(&json).unwrap();
        assert_eq!(a.max_iterations, back.max_iterations);
        assert_eq!(
            a.convergence_threshold_millionths,
            back.convergence_threshold_millionths
        );
    }

    #[test]
    fn laplacian_from_empty_topology_fails() {
        let err = LaplacianMatrix::from_topology(&GossipTopology {
            num_nodes: 0,
            node_ids: vec![],
            adjacency: BTreeMap::new(),
        })
        .unwrap_err();
        assert!(matches!(err, SpectralError::EmptyGraph));
    }

    #[test]
    fn laplacian_diagonal_equals_degree() {
        let mut topo = GossipTopology::new(vec!["a".to_string(), "b".to_string()]).unwrap();
        topo.add_edge(0, 1, 500_000).unwrap();
        let l = LaplacianMatrix::from_topology(&topo).unwrap();
        assert_eq!(l.get(0, 0), 500_000);
        assert_eq!(l.get(1, 1), 500_000);
        assert_eq!(l.get(0, 1), -500_000);
        assert_eq!(l.get(1, 0), -500_000);
    }

    #[test]
    fn analysis_fiedler_residual_is_small() {
        let topo = make_complete_graph(4);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        // Residual should be small for well-converged solutions
        assert!(analysis.fiedler_residual_millionths < 100_000);
    }
}
