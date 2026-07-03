#![forbid(unsafe_code)]

//! Bandwidth-efficiency accounting for erasure-coded vs full-replication gossip
//! (`bd-cixqu.35.3`, Track II.3).
//!
//! This module quantifies the wire-byte cost of disseminating a fleet gossip
//! payload two ways — as **full replicas** and as **erasure-coded shards** — and
//! computes the bandwidth savings across documented fleet and payload sizes. It
//! is built directly on the shipped erasure encoder
//! ([`crate::fleet_immune_protocol::encode_erasure_shards`]) and measures the
//! *actual* serialized [`FleetMessage`] wire size of every shard: no byte count
//! in the produced report is estimated or hand-tuned.
//!
//! ## Honest coding-scheme labeling (load-bearing)
//!
//! The shipped erasure lane is a **systematic XOR single-parity** code
//! ([`crate::erasure_reconstruction_receipts::XOR_SINGLE_PARITY_SCHEME`],
//! `xor-single-parity-v1`). It computes exactly **one** parity chunk (the XOR of
//! all `k` data chunks) and recovers **at most one** missing data shard. When the
//! tuned plan allocates more than one parity slot, those extra slots carry
//! *identical* copies of that single parity chunk — they add duplication, not
//! recovery capacity.
//!
//! This is **not** Reed–Solomon over `GF(2^8)`. The bandwidth math here therefore
//! reports the *real* fault-tolerance-normalized savings ceiling for a
//! single-parity code, which is
//!
//! ```text
//!     ceiling(k) = (k - 1) / (2k)   →   0.5 as k → ∞
//! ```
//!
//! and **not** the 60–70% figure that some upstream prose attributes to a tunable
//! Reed–Solomon code. That figure is out of reach for the shipped scheme; the
//! report records this explicitly rather than fabricating Reed–Solomon behavior.
//!
//! ## What is compared
//!
//! For each `(fleet_size, payload_bytes)` cell the module derives the real coding
//! plan via [`ErasureCodingPlan::tuned`] (exactly the plan the live gossip lane
//! uses in [`crate::fleet_immune_protocol::FleetProtocolState::encode_evidence_for_erasure_gossip`]),
//! encodes a deterministic payload into real shards, and measures:
//!
//! - **Primary lens — fault-tolerance-normalized redundancy** (both strategies
//!   configured to survive one lost message): full replication sends two full
//!   copies; erasure sends `k` data shards plus one parity shard. The reported
//!   `savings_ratio` is over these two quantities.
//! - **Context lens — raw dissemination volume** (explicitly *not*
//!   reliability-normalized): a full broadcast sends one full copy to every node,
//!   while the erasure lane emits `n` shards once. These numbers favor erasure by
//!   a wide margin but at a fraction of the fault tolerance, so they are reported
//!   as context only, never as the headline savings.
//!
//! Every quantity is deterministic (fixed origin, sequence, timestamp, shard-set
//! id, and a fixed byte pattern for the payload), so the signed report replays
//! byte-for-byte — the property the gate's deterministic-replay lane depends on.

use serde::{Deserialize, Serialize};

use crate::erasure_reconstruction_receipts::XOR_SINGLE_PARITY_SCHEME;
use crate::fleet_immune_protocol::{
    ErasureCodingPlan, FleetMessage, NodeId, encode_erasure_shards,
};
use crate::hash_tiers::ContentHash;
use crate::signature_preimage::{SigningKey, sign_preimage};

/// Schema id for the bandwidth-efficiency report artifact.
pub const BANDWIDTH_REPORT_SCHEMA: &str = "franken-engine.erasure-bandwidth-efficiency-report.v1";

/// Fixed timestamp for deterministic shard encoding (nanoseconds).
const FIXED_TIMESTAMP_NS: u64 = 1_000_000;
/// Fixed first sequence number for deterministic shard encoding.
const FIXED_FIRST_SEQUENCE: u64 = 1;
/// Fixed origin node id for deterministic shard encoding.
const FIXED_ORIGIN_NODE: &str = "bandwidth-origin";
/// Fixed shard-set id for deterministic shard encoding.
const FIXED_SHARD_SET_ID: &str = "bandwidth-set";
/// Fixed report generation timestamp (deterministic; not wall-clock).
const FIXED_GENERATED_AT_UTC: &str = "2026-05-24T00:00:00Z";
/// Fixed signing key material for the report (benchmark-scoped, not a fleet key).
const REPORT_SIGNING_KEY_BYTES: [u8; 32] = [0x35; 32];
/// Stable id recorded alongside the signature.
const REPORT_SIGNING_KEY_ID: &str = "erasure-bandwidth-benchmark-fixed-key-v1";

/// Configuration for a bandwidth comparison sweep.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandwidthComparisonConfig {
    /// Fleet sizes (node counts) to evaluate.
    pub fleet_sizes: Vec<u64>,
    /// Message payload sizes in bytes to evaluate.
    pub payload_sizes: Vec<u64>,
    /// Gossip fan-out (peers per forwarding hop); see [`crate::fleet_immune_protocol::GossipConfig`].
    pub fanout: u32,
}

impl Default for BandwidthComparisonConfig {
    fn default() -> Self {
        Self {
            fleet_sizes: vec![10, 50, 100, 500, 1000],
            payload_sizes: vec![1_024, 10_240, 102_400, 1_048_576],
            fanout: 3,
        }
    }
}

impl BandwidthComparisonConfig {
    /// Validate the configuration, returning an explanatory error on any empty
    /// axis or a zero fan-out / zero fleet size (which cannot describe a fleet).
    pub fn validate(&self) -> Result<(), BandwidthError> {
        if self.fleet_sizes.is_empty() {
            return Err(BandwidthError::InvalidConfig {
                reason: "fleet_sizes must not be empty".to_string(),
            });
        }
        if self.payload_sizes.is_empty() {
            return Err(BandwidthError::InvalidConfig {
                reason: "payload_sizes must not be empty".to_string(),
            });
        }
        if self.fanout == 0 {
            return Err(BandwidthError::InvalidConfig {
                reason: "fanout must be at least 1".to_string(),
            });
        }
        if self.fleet_sizes.contains(&0) {
            return Err(BandwidthError::InvalidConfig {
                reason: "fleet size must be at least 1".to_string(),
            });
        }
        Ok(())
    }
}

/// Error surface for bandwidth accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BandwidthError {
    /// The comparison configuration is malformed.
    InvalidConfig {
        /// Human-readable reason.
        reason: String,
    },
    /// A shard set could not be encoded from the shipped erasure encoder.
    EncodeFailed {
        /// Human-readable reason.
        reason: String,
    },
}

impl std::fmt::Display for BandwidthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig { reason } => write!(f, "invalid bandwidth config: {reason}"),
            Self::EncodeFailed { reason } => write!(f, "erasure encode failed: {reason}"),
        }
    }
}

impl std::error::Error for BandwidthError {}

/// A single `(fleet_size, payload_bytes)` bandwidth measurement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandwidthCell {
    /// Fleet size (node count) for this measurement.
    pub fleet_size: u64,
    /// Payload size in bytes.
    pub payload_bytes: u64,
    /// Data shards `k` required to reconstruct (from the tuned plan).
    pub data_shards: u16,
    /// Total shards `n` emitted by the tuned plan.
    pub total_shards: u16,
    /// Parity slots `n - k` (identical XOR copies).
    pub parity_shards: u16,
    /// Distinct parity chunks that carry recovery information. Always `1` for the
    /// XOR single-parity scheme when any parity exists (honest-labeling field).
    pub unique_parity_chunks: u16,
    /// Erasures tolerated by the shipped scheme for this plan (`0` or `1`).
    pub fault_tolerance_erasures: u16,
    /// Per-shard chunk length in bytes (`ceil(payload / k)`).
    pub chunk_len: u64,
    /// Total serialized wire bytes of the `k` data shards.
    pub data_shard_wire_bytes: u64,
    /// Serialized wire bytes of one parity shard (`0` when no parity slot exists).
    pub parity_shard_wire_bytes: u64,
    /// Serialized wire bytes of one full-payload copy (a `(1,1)` encoding).
    pub full_copy_wire_bytes: u64,
    /// Non-payload framing overhead of a single data shard (`wire - chunk_len`).
    pub shard_metadata_overhead_bytes: u64,
    /// Primary lens: erasure redundancy bytes to survive one loss (`k` data + 1 parity).
    pub erasure_coded_bytes: u64,
    /// Primary lens: replication redundancy bytes to survive one loss.
    pub full_replication_bytes: u64,
    /// Savings ratio in millionths (signed; negative when framing overhead dominates).
    pub savings_ratio_millionths: i64,
    /// True when erasure redundancy is at least as costly as replication (small
    /// payload / large `k` regime where framing overhead exceeds the savings).
    pub overhead_exceeds_savings: bool,
    /// Metadata-free theoretical savings ceiling in millionths, `(k-1)/(2k)`.
    pub theoretical_savings_ceiling_millionths: u64,
    /// Context lens (NOT reliability-normalized): total wire bytes of all `n` shards.
    pub erasure_as_emitted_bytes: u64,
    /// Context lens (NOT reliability-normalized): one full copy to every node.
    pub full_broadcast_bytes: u64,
}

/// Per-fleet-size scaling summary across the payload axis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalingPoint {
    /// Fleet size.
    pub fleet_size: u64,
    /// Data shards `k` from the tuned plan.
    pub data_shards: u16,
    /// Metadata-free theoretical savings ceiling in millionths, `(k-1)/(2k)`.
    pub theoretical_savings_ceiling_millionths: u64,
    /// Mean measured savings across all payloads (millionths, signed).
    pub mean_measured_savings_millionths: i64,
    /// Payload size (bytes) with the best measured savings for this fleet size.
    pub best_payload_bytes: u64,
    /// Best measured savings across payloads (millionths, signed).
    pub best_measured_savings_millionths: i64,
    /// Count of payloads where erasure framing overhead exceeds the savings.
    pub payloads_overhead_dominated: u64,
}

/// Analytical gossip-convergence estimate for a fleet size.
///
/// This is an explicit analytical model (`analytical_model = true`), **not** a
/// live network simulation. `full_replication_rounds` is a deterministic
/// optimistic epidemic-push bound; `erasure_convergence_rounds` adds the rounds a
/// node needs to gather `k` distinct shards at `fanout` per round.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergencePoint {
    /// Fleet size.
    pub fleet_size: u64,
    /// Gossip fan-out.
    pub fanout: u32,
    /// Data shards `k`.
    pub data_shards: u16,
    /// Payload size used for the bandwidth columns.
    pub reference_payload_bytes: u64,
    /// Always `true`: these figures come from an analytical model, not a live net.
    pub analytical_model: bool,
    /// Optimistic epidemic-push rounds to inform the whole fleet.
    pub full_replication_rounds: u64,
    /// Estimated rounds for every node to reconstruct under erasure gossip.
    pub erasure_convergence_rounds: u64,
    /// Total wire bytes to broadcast one full copy to every node.
    pub full_replication_total_bytes: u64,
    /// Total wire bytes for the erasure lane's emitted shard set.
    pub erasure_total_bytes: u64,
}

/// The unsigned bandwidth-efficiency report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandwidthEfficiencyReport {
    /// Schema id.
    pub schema_version: String,
    /// Deterministic (non-wall-clock) generation timestamp.
    pub generated_at_utc: String,
    /// Coding scheme actually measured (`xor-single-parity-v1`).
    pub coding_scheme: String,
    /// Erasures the shipped scheme tolerates per shard set (`1`).
    pub scheme_fault_tolerance_erasures: u16,
    /// Honest-labeling notes recorded alongside the numbers.
    pub honesty_notes: Vec<String>,
    /// Methodology statements.
    pub methodology: Vec<String>,
    /// Configuration that produced the cells.
    pub config: BandwidthComparisonConfig,
    /// Per-cell measurements.
    pub cells: Vec<BandwidthCell>,
    /// Per-fleet-size scaling summary.
    pub scaling_analysis: Vec<ScalingPoint>,
    /// Analytical convergence-vs-bandwidth model.
    pub convergence_model: Vec<ConvergencePoint>,
}

/// The report plus its content hash and signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBandwidthReport {
    /// The report body.
    pub report: BandwidthEfficiencyReport,
    /// Hex content hash of the canonical serialization of `report`.
    pub report_hash: String,
    /// Stable id of the signing key.
    pub signing_key_id: String,
    /// Hex verification key.
    pub verification_key: String,
    /// Hex signature over the canonical serialization of `report`.
    pub signature_hex: String,
}

/// Produce a deterministic payload of `len` bytes.
fn deterministic_payload(len: u64) -> Vec<u8> {
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    let mut payload = Vec::with_capacity(len);
    for i in 0..len {
        payload.push((i % 251) as u8);
    }
    payload
}

/// Wire length of a shard as it travels on the gossip lane: the raw coded
/// payload bytes plus the serialized metadata framing.
///
/// The coded payload is counted as its raw byte length (what a byte-oriented
/// transport transmits), while the framing — shard-set id, origin, sequence,
/// index, plan, role, payload length, the two content hashes, timestamp,
/// signature, protocol version, and extensions — is measured by serializing the
/// shard with an emptied payload. Counting the payload raw (rather than through
/// `serde_json`, which would expand a `Vec<u8>` into a JSON number array) keeps
/// the byte totals representative of an on-wire encoding rather than a debug
/// serialization.
fn shard_wire_len(
    shard: &crate::fleet_immune_protocol::ErasureShard,
) -> Result<u64, BandwidthError> {
    let payload_len = shard.shard_payload.len() as u64;
    let mut framing_probe = shard.clone();
    framing_probe.shard_payload = Vec::new();
    let framing = serde_json::to_vec(&FleetMessage::ErasureShard(framing_probe))
        .map_err(|err| BandwidthError::EncodeFailed {
            reason: format!("serializing shard framing for wire measurement: {err}"),
        })?
        .len() as u64;
    Ok(framing.saturating_add(payload_len))
}

/// Public, infallible wire-size measurement for a shard. Used by callers and
/// tests that need the exact byte accounting the report is built from.
pub fn shard_wire_bytes(shard: &crate::fleet_immune_protocol::ErasureShard) -> u64 {
    shard_wire_len(shard).unwrap_or(shard.shard_payload.len() as u64)
}

/// The chunk length the shipped encoder uses for `(payload_bytes, data_shards)`.
fn chunk_len_for(payload_bytes: u64, data_shards: u16) -> u64 {
    if payload_bytes == 0 || data_shards == 0 {
        0
    } else {
        payload_bytes.div_ceil(u64::from(data_shards))
    }
}

/// Metadata-free theoretical savings ceiling for a single-parity code, `(k-1)/(2k)`.
fn theoretical_ceiling_millionths(data_shards: u16, fault_tolerance: u16) -> u64 {
    if fault_tolerance == 0 || data_shards == 0 {
        return 0;
    }
    let k = u64::from(data_shards);
    (k - 1).saturating_mul(1_000_000) / (2 * k)
}

/// Compute the savings ratio in millionths (signed).
fn savings_millionths(full: u64, erasure: u64) -> i64 {
    if full == 0 {
        return 0;
    }
    let numerator = i128::from(full) - i128::from(erasure);
    let scaled = numerator.saturating_mul(1_000_000) / i128::from(full);
    i64::try_from(scaled).unwrap_or(if scaled.is_negative() {
        i64::MIN
    } else {
        i64::MAX
    })
}

/// Measure one `(fleet_size, payload_bytes)` cell against the shipped encoder.
pub fn measure_cell(
    fleet_size: u64,
    payload_bytes: u64,
    _fanout: u32,
) -> Result<BandwidthCell, BandwidthError> {
    let fleet_usize = usize::try_from(fleet_size).unwrap_or(usize::MAX);
    let plan = ErasureCodingPlan::tuned(fleet_usize, 0);
    let k = plan.data_shards;
    let n = plan.total_shards;
    let parity = plan.parity_shards();
    let fault_tolerance = parity.min(1);

    let payload = deterministic_payload(payload_bytes);
    let origin = NodeId::new(FIXED_ORIGIN_NODE);

    let shards = encode_erasure_shards(
        FIXED_SHARD_SET_ID,
        origin.clone(),
        FIXED_FIRST_SEQUENCE,
        FIXED_TIMESTAMP_NS,
        &payload,
        plan,
    )
    .map_err(|err| BandwidthError::EncodeFailed {
        reason: format!("fleet_size={fleet_size} payload={payload_bytes}: {err}"),
    })?;

    // Real serialized wire size of every emitted shard.
    let mut per_shard_wire = Vec::with_capacity(shards.len());
    for shard in &shards {
        per_shard_wire.push(shard_wire_len(shard)?);
    }

    let k_usize = usize::from(k);
    let data_shard_wire_bytes: u64 = per_shard_wire.iter().take(k_usize).sum();
    let erasure_as_emitted_bytes: u64 = per_shard_wire.iter().sum();
    let single_data_wire = per_shard_wire.first().copied().unwrap_or(0);
    let parity_shard_wire_bytes = if fault_tolerance >= 1 && k_usize < per_shard_wire.len() {
        per_shard_wire[k_usize]
    } else {
        0
    };

    // A full replica is a single (1,1) shard carrying the whole payload — the
    // same envelope struct, so the comparison isolates chunking + parity.
    let full_plan = ErasureCodingPlan::new(1, 1).map_err(|err| BandwidthError::EncodeFailed {
        reason: format!("constructing full-copy plan: {err}"),
    })?;
    let full_shards = encode_erasure_shards(
        FIXED_SHARD_SET_ID,
        origin,
        FIXED_FIRST_SEQUENCE,
        FIXED_TIMESTAMP_NS,
        &payload,
        full_plan,
    )
    .map_err(|err| BandwidthError::EncodeFailed {
        reason: format!("full-copy encode fleet_size={fleet_size}: {err}"),
    })?;
    let full_copy_wire_bytes = match full_shards.first() {
        Some(shard) => shard_wire_len(shard)?,
        None => {
            return Err(BandwidthError::EncodeFailed {
                reason: "full-copy encoding produced no shard".to_string(),
            });
        }
    };

    let chunk_len = chunk_len_for(payload_bytes, k);
    let shard_metadata_overhead_bytes = single_data_wire.saturating_sub(chunk_len);

    // Primary lens: redundancy bytes to survive `fault_tolerance` erasures.
    let erasure_coded_bytes = data_shard_wire_bytes.saturating_add(parity_shard_wire_bytes);
    let full_replication_bytes =
        (u64::from(fault_tolerance) + 1).saturating_mul(full_copy_wire_bytes);
    let savings_ratio_millionths = savings_millionths(full_replication_bytes, erasure_coded_bytes);
    let overhead_exceeds_savings = erasure_coded_bytes >= full_replication_bytes;

    // Context lens: raw dissemination volume (not reliability-normalized).
    let full_broadcast_bytes = fleet_size.saturating_mul(full_copy_wire_bytes);

    Ok(BandwidthCell {
        fleet_size,
        payload_bytes,
        data_shards: k,
        total_shards: n,
        parity_shards: parity,
        unique_parity_chunks: u16::from(parity >= 1),
        fault_tolerance_erasures: fault_tolerance,
        chunk_len,
        data_shard_wire_bytes,
        parity_shard_wire_bytes,
        full_copy_wire_bytes,
        shard_metadata_overhead_bytes,
        erasure_coded_bytes,
        full_replication_bytes,
        savings_ratio_millionths,
        overhead_exceeds_savings,
        theoretical_savings_ceiling_millionths: theoretical_ceiling_millionths(k, fault_tolerance),
        erasure_as_emitted_bytes,
        full_broadcast_bytes,
    })
}

/// Optimistic epidemic-push rounds to inform an entire fleet.
pub fn full_replication_rounds(fleet_size: u64, fanout: u32) -> u64 {
    if fleet_size <= 1 {
        return 0;
    }
    let n = u128::from(fleet_size);
    let f = u128::from(fanout.max(1));
    let mut informed: u128 = 1;
    let mut rounds: u64 = 0;
    while informed < n {
        let capacity = informed.saturating_mul(f);
        let newly = capacity.min(n - informed);
        informed += newly;
        rounds += 1;
        if rounds > 10_000_000 {
            break;
        }
    }
    rounds
}

/// Estimated rounds for every node to reconstruct under erasure gossip: the
/// dissemination rounds plus the rounds to gather `k` distinct shards at
/// `fanout` per round. Analytical, not a live simulation.
pub fn erasure_convergence_rounds(fleet_size: u64, data_shards: u16, fanout: u32) -> u64 {
    let dissemination = full_replication_rounds(fleet_size, fanout);
    let f = u64::from(fanout.max(1));
    let gather = u64::from(data_shards).div_ceil(f);
    dissemination.saturating_add(gather)
}

/// Build a full bandwidth-efficiency report from a configuration.
pub fn build_report(
    config: &BandwidthComparisonConfig,
) -> Result<BandwidthEfficiencyReport, BandwidthError> {
    config.validate()?;

    let mut cells = Vec::new();
    for &fleet_size in &config.fleet_sizes {
        for &payload_bytes in &config.payload_sizes {
            cells.push(measure_cell(fleet_size, payload_bytes, config.fanout)?);
        }
    }

    let scaling_analysis = build_scaling_analysis(&config.fleet_sizes, &cells);
    let convergence_model = build_convergence_model(config, &cells);

    Ok(BandwidthEfficiencyReport {
        schema_version: BANDWIDTH_REPORT_SCHEMA.to_string(),
        generated_at_utc: FIXED_GENERATED_AT_UTC.to_string(),
        coding_scheme: XOR_SINGLE_PARITY_SCHEME.to_string(),
        scheme_fault_tolerance_erasures: 1,
        honesty_notes: honesty_notes(),
        methodology: methodology(),
        config: config.clone(),
        cells,
        scaling_analysis,
        convergence_model,
    })
}

fn build_scaling_analysis(fleet_sizes: &[u64], cells: &[BandwidthCell]) -> Vec<ScalingPoint> {
    let mut points = Vec::new();
    for &fleet_size in fleet_sizes {
        let fleet_cells: Vec<&BandwidthCell> = cells
            .iter()
            .filter(|c| c.fleet_size == fleet_size)
            .collect();
        if fleet_cells.is_empty() {
            continue;
        }
        let data_shards = fleet_cells[0].data_shards;
        let ceiling = fleet_cells[0].theoretical_savings_ceiling_millionths;
        let count = fleet_cells.len() as i64;
        let sum: i64 = fleet_cells.iter().map(|c| c.savings_ratio_millionths).sum();
        let mean = if count == 0 { 0 } else { sum / count };
        let best = fleet_cells
            .iter()
            .max_by_key(|c| c.savings_ratio_millionths)
            .expect("fleet_cells is non-empty");
        let overhead_dominated = fleet_cells
            .iter()
            .filter(|c| c.overhead_exceeds_savings)
            .count() as u64;
        points.push(ScalingPoint {
            fleet_size,
            data_shards,
            theoretical_savings_ceiling_millionths: ceiling,
            mean_measured_savings_millionths: mean,
            best_payload_bytes: best.payload_bytes,
            best_measured_savings_millionths: best.savings_ratio_millionths,
            payloads_overhead_dominated: overhead_dominated,
        });
    }
    points
}

fn build_convergence_model(
    config: &BandwidthComparisonConfig,
    cells: &[BandwidthCell],
) -> Vec<ConvergencePoint> {
    let reference_payload = config.payload_sizes.iter().copied().max().unwrap_or(0);
    let mut points = Vec::new();
    for &fleet_size in &config.fleet_sizes {
        let Some(cell) = cells
            .iter()
            .find(|c| c.fleet_size == fleet_size && c.payload_bytes == reference_payload)
        else {
            continue;
        };
        points.push(ConvergencePoint {
            fleet_size,
            fanout: config.fanout,
            data_shards: cell.data_shards,
            reference_payload_bytes: reference_payload,
            analytical_model: true,
            full_replication_rounds: full_replication_rounds(fleet_size, config.fanout),
            erasure_convergence_rounds: erasure_convergence_rounds(
                fleet_size,
                cell.data_shards,
                config.fanout,
            ),
            full_replication_total_bytes: cell.full_broadcast_bytes,
            erasure_total_bytes: cell.erasure_as_emitted_bytes,
        });
    }
    points
}

fn honesty_notes() -> Vec<String> {
    vec![
        format!(
            "The measured erasure lane is a systematic XOR single-parity code ({XOR_SINGLE_PARITY_SCHEME}); \
             it computes one parity chunk and recovers at most one missing data shard."
        ),
        "Extra parity slots emitted by the tuned plan carry identical copies of the single parity \
         chunk; they add duplication, not recovery capacity."
            .to_string(),
        "This is NOT Reed-Solomon over GF(2^8). The fault-tolerance-normalized savings ceiling for \
         the shipped single-parity scheme is (k-1)/(2k), which approaches 0.5 (50%), not the \
         60-70% attributed to a tunable Reed-Solomon code."
            .to_string(),
        "No Reed-Solomon polynomial coefficients are computed or reported anywhere in this benchmark."
            .to_string(),
        "For small payloads with a large data-shard count, per-shard framing overhead can exceed \
         the transmission savings (overhead_exceeds_savings=true); erasure coding is not \
         worthwhile there."
            .to_string(),
    ]
}

fn methodology() -> Vec<String> {
    vec![
        "Coding plan derived from ErasureCodingPlan::tuned(fleet_size, 0) — the plan the live \
         gossip lane uses in encode_evidence_for_erasure_gossip."
            .to_string(),
        "Shards produced by the shipped encode_erasure_shards; wire size measured as \
         serde_json::to_vec(FleetMessage::ErasureShard(..)).len(), matching the lane's canonical \
         serialization."
            .to_string(),
        "A full replica is a (1,1) erasure encoding of the whole payload — the same envelope \
         struct — so the comparison isolates chunking and parity."
            .to_string(),
        "Primary savings lens is fault-tolerance-normalized: both strategies configured to survive \
         one lost message (replication = 2 copies; erasure = k data shards + 1 parity)."
            .to_string(),
        "Context lens (full_broadcast_bytes vs erasure_as_emitted_bytes) is raw dissemination \
         volume and is NOT reliability-normalized."
            .to_string(),
        "Convergence figures are an analytical epidemic-push model (analytical_model=true), not a \
         live network simulation."
            .to_string(),
        "All inputs are fixed (origin, sequence, timestamp, shard-set id, deterministic payload \
         byte pattern) so the signed report replays byte-for-byte."
            .to_string(),
    ]
}

/// Deterministically sign a bandwidth report.
pub fn sign_report(
    report: BandwidthEfficiencyReport,
) -> Result<SignedBandwidthReport, BandwidthError> {
    let bytes = serde_json::to_vec(&report).map_err(|err| BandwidthError::EncodeFailed {
        reason: format!("serializing report for signing: {err}"),
    })?;
    let report_hash = ContentHash::compute(&bytes).to_hex();
    let key = SigningKey::from_bytes(REPORT_SIGNING_KEY_BYTES).map_err(|err| {
        BandwidthError::EncodeFailed {
            reason: format!("constructing report signing key: {err}"),
        }
    })?;
    let signature = sign_preimage(&key, &bytes).map_err(|err| BandwidthError::EncodeFailed {
        reason: format!("signing report: {err}"),
    })?;
    Ok(SignedBandwidthReport {
        report,
        report_hash,
        signing_key_id: REPORT_SIGNING_KEY_ID.to_string(),
        verification_key: key.verification_key().to_hex(),
        signature_hex: hex::encode(signature.to_bytes()),
    })
}

/// Build and sign a report from a configuration in one step.
pub fn build_signed_report(
    config: &BandwidthComparisonConfig,
) -> Result<SignedBandwidthReport, BandwidthError> {
    sign_report(build_report(config)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_config() -> BandwidthComparisonConfig {
        BandwidthComparisonConfig {
            fleet_sizes: vec![10, 100],
            payload_sizes: vec![1_024, 1_048_576],
            fanout: 3,
        }
    }

    #[test]
    fn default_config_matches_bead_axes() {
        let config = BandwidthComparisonConfig::default();
        assert_eq!(config.fleet_sizes, vec![10, 50, 100, 500, 1000]);
        assert_eq!(
            config.payload_sizes,
            vec![1_024, 10_240, 102_400, 1_048_576]
        );
        assert_eq!(config.fanout, 3);
        config.validate().unwrap();
    }

    #[test]
    fn validate_rejects_empty_fleet_axis() {
        let config = BandwidthComparisonConfig {
            fleet_sizes: vec![],
            ..Default::default()
        };
        assert!(matches!(
            config.validate(),
            Err(BandwidthError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn validate_rejects_empty_payload_axis() {
        let config = BandwidthComparisonConfig {
            payload_sizes: vec![],
            ..Default::default()
        };
        assert!(matches!(
            config.validate(),
            Err(BandwidthError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn validate_rejects_zero_fanout() {
        let config = BandwidthComparisonConfig {
            fanout: 0,
            ..Default::default()
        };
        assert!(matches!(
            config.validate(),
            Err(BandwidthError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn validate_rejects_zero_fleet_size() {
        let config = BandwidthComparisonConfig {
            fleet_sizes: vec![0, 10],
            ..Default::default()
        };
        assert!(matches!(
            config.validate(),
            Err(BandwidthError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn deterministic_payload_pattern_is_stable_and_bounded() {
        let payload = deterministic_payload(512);
        assert_eq!(payload.len(), 512);
        assert_eq!(payload[0], 0);
        assert_eq!(payload[250], 250);
        assert_eq!(payload[251], 0);
        assert!(payload.iter().all(|&b| b < 251));
    }

    #[test]
    fn chunk_len_uses_ceiling_division() {
        assert_eq!(chunk_len_for(0, 7), 0);
        assert_eq!(chunk_len_for(1_024, 7), 147); // ceil(1024/7)
        assert_eq!(chunk_len_for(1_048_576, 667), 1_573); // ceil
        assert_eq!(chunk_len_for(100, 0), 0);
    }

    #[test]
    fn theoretical_ceiling_matches_closed_form() {
        // (k-1)/(2k) in millionths.
        assert_eq!(theoretical_ceiling_millionths(1, 1), 0);
        assert_eq!(theoretical_ceiling_millionths(2, 1), 250_000);
        assert_eq!(theoretical_ceiling_millionths(10, 1), 450_000);
        assert_eq!(theoretical_ceiling_millionths(100, 1), 495_000);
        // Fault tolerance zero → no theoretical saving.
        assert_eq!(theoretical_ceiling_millionths(100, 0), 0);
    }

    #[test]
    fn theoretical_ceiling_is_monotone_and_below_half() {
        let mut prev = 0;
        for k in [2u16, 4, 8, 16, 64, 256, 1024] {
            let c = theoretical_ceiling_millionths(k, 1);
            assert!(c >= prev, "ceiling must be non-decreasing in k");
            assert!(c < 500_000, "single-parity ceiling stays below 50%");
            prev = c;
        }
    }

    #[test]
    fn savings_millionths_signs_and_zero_guard() {
        assert_eq!(savings_millionths(0, 100), 0);
        assert_eq!(savings_millionths(200, 100), 500_000); // 50% saving
        assert_eq!(savings_millionths(100, 100), 0);
        assert_eq!(savings_millionths(100, 200), -1_000_000); // -100% (overhead)
    }

    #[test]
    fn measure_cell_reports_real_xor_single_parity_shape() {
        let cell = measure_cell(100, 1_048_576, 3).unwrap();
        // tuned(100,0): total=100, parity=33, data=67.
        assert_eq!(cell.total_shards, 100);
        assert_eq!(cell.parity_shards, 33);
        assert_eq!(cell.data_shards, 67);
        // Single-parity honesty invariants.
        assert_eq!(cell.unique_parity_chunks, 1);
        assert_eq!(cell.fault_tolerance_erasures, 1);
        assert_eq!(cell.chunk_len, 1_048_576u64.div_ceil(67));
    }

    #[test]
    fn measure_cell_large_payload_saves_bandwidth() {
        // A 1 MiB payload over a moderate fleet should show a positive saving.
        let cell = measure_cell(100, 1_048_576, 3).unwrap();
        assert!(
            cell.savings_ratio_millionths > 0,
            "expected positive savings, got {}",
            cell.savings_ratio_millionths
        );
        assert!(!cell.overhead_exceeds_savings);
        // Measured savings cannot beat the metadata-free ceiling.
        assert!(
            cell.savings_ratio_millionths
                <= i64::try_from(cell.theoretical_savings_ceiling_millionths).unwrap(),
            "measured {} exceeded ceiling {}",
            cell.savings_ratio_millionths,
            cell.theoretical_savings_ceiling_millionths
        );
    }

    #[test]
    fn measure_cell_tiny_payload_large_fleet_overhead_dominates() {
        // 1 KiB over a 1000-node fleet: chunk_len is a couple of bytes but each
        // shard still pays full framing → erasure loses badly.
        let cell = measure_cell(1000, 1_024, 3).unwrap();
        assert!(cell.overhead_exceeds_savings);
        assert!(cell.savings_ratio_millionths < 0);
    }

    #[test]
    fn measure_cell_wire_bytes_are_nonzero_and_consistent() {
        let cell = measure_cell(50, 102_400, 3).unwrap();
        assert!(cell.full_copy_wire_bytes > 0);
        assert!(cell.data_shard_wire_bytes > 0);
        assert!(cell.parity_shard_wire_bytes > 0);
        // Emitted-set bytes must cover the data shards.
        assert!(cell.erasure_as_emitted_bytes >= cell.data_shard_wire_bytes);
        // Broadcast to N nodes is N full copies.
        assert_eq!(
            cell.full_broadcast_bytes,
            cell.fleet_size * cell.full_copy_wire_bytes
        );
        // Redundancy-to-survive-one-loss is 2 full copies.
        assert_eq!(cell.full_replication_bytes, 2 * cell.full_copy_wire_bytes);
    }

    #[test]
    fn measure_cell_metadata_overhead_is_wire_minus_chunk() {
        let cell = measure_cell(100, 102_400, 3).unwrap();
        // A single data shard's wire size is chunk_len payload + framing.
        let single = cell.data_shard_wire_bytes / u64::from(cell.data_shards);
        // Overhead is positive: framing (hashes, signature, ids) is always present.
        assert!(cell.shard_metadata_overhead_bytes > 0);
        // Sanity: overhead is less than one shard's total wire size.
        assert!(cell.shard_metadata_overhead_bytes < single + cell.chunk_len + 1);
    }

    #[test]
    fn measure_cell_is_deterministic() {
        let a = measure_cell(500, 10_240, 3).unwrap();
        let b = measure_cell(500, 10_240, 3).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn measure_cell_fleet_of_one_has_no_parity() {
        // tuned(1,0): total=1, parity=0, data=1 — a degenerate no-redundancy case.
        let cell = measure_cell(1, 4_096, 3).unwrap();
        assert_eq!(cell.total_shards, 1);
        assert_eq!(cell.parity_shards, 0);
        assert_eq!(cell.fault_tolerance_erasures, 0);
        assert_eq!(cell.unique_parity_chunks, 0);
        assert_eq!(cell.parity_shard_wire_bytes, 0);
        // With no parity, redundancy is a single copy on both sides.
        assert_eq!(cell.full_replication_bytes, cell.full_copy_wire_bytes);
    }

    #[test]
    fn measure_cell_empty_payload_is_encodable() {
        let cell = measure_cell(10, 0, 3).unwrap();
        assert_eq!(cell.payload_bytes, 0);
        assert_eq!(cell.chunk_len, 0);
        // Empty payload still carries full framing per shard.
        assert!(cell.erasure_as_emitted_bytes > 0);
    }

    #[test]
    fn full_replication_rounds_epidemic_growth() {
        assert_eq!(full_replication_rounds(1, 3), 0);
        assert_eq!(full_replication_rounds(0, 3), 0);
        // fanout 3 → each round multiplies informed by 4 (optimistic).
        // 1 -> 4 -> 16 -> 64 -> 256 ... reach 10 in 2 rounds (1->4->16).
        assert_eq!(full_replication_rounds(10, 3), 2);
        assert_eq!(full_replication_rounds(16, 3), 2);
        assert_eq!(full_replication_rounds(17, 3), 3);
    }

    #[test]
    fn full_replication_rounds_grow_with_fleet() {
        let r10 = full_replication_rounds(10, 3);
        let r1000 = full_replication_rounds(1000, 3);
        assert!(r1000 > r10);
    }

    #[test]
    fn erasure_convergence_adds_gather_rounds() {
        let disseminate = full_replication_rounds(100, 3);
        let converge = erasure_convergence_rounds(100, 67, 3);
        // Gather term is ceil(k/fanout) = ceil(67/3) = 23.
        assert_eq!(converge, disseminate + 23);
    }

    #[test]
    fn build_report_populates_all_axes() {
        let config = tiny_config();
        let report = build_report(&config).unwrap();
        assert_eq!(report.schema_version, BANDWIDTH_REPORT_SCHEMA);
        assert_eq!(report.coding_scheme, XOR_SINGLE_PARITY_SCHEME);
        assert_eq!(report.scheme_fault_tolerance_erasures, 1);
        assert_eq!(report.cells.len(), 4); // 2 fleet sizes x 2 payloads
        assert_eq!(report.scaling_analysis.len(), 2);
        assert_eq!(report.convergence_model.len(), 2);
        assert!(!report.honesty_notes.is_empty());
        assert!(!report.methodology.is_empty());
    }

    #[test]
    fn build_report_never_claims_reed_solomon() {
        let report = build_report(&tiny_config()).unwrap();
        let serialized = serde_json::to_string(&report).unwrap().to_lowercase();
        // The honest notes may MENTION Reed-Solomon to disclaim it, but the coding
        // scheme itself must be the XOR single-parity id and never an RS scheme id.
        assert_eq!(report.coding_scheme, "xor-single-parity-v1");
        assert!(!serialized.contains("\"coding_scheme\":\"reed-solomon")); // never an RS scheme value
        assert!(
            report
                .honesty_notes
                .iter()
                .any(|n| n.contains("NOT Reed-Solomon"))
        );
    }

    #[test]
    fn scaling_analysis_ceiling_grows_with_fleet() {
        let config = BandwidthComparisonConfig {
            fleet_sizes: vec![10, 100, 1000],
            payload_sizes: vec![1_048_576],
            fanout: 3,
        };
        let report = build_report(&config).unwrap();
        let ceilings: Vec<u64> = report
            .scaling_analysis
            .iter()
            .map(|s| s.theoretical_savings_ceiling_millionths)
            .collect();
        assert_eq!(ceilings.len(), 3);
        assert!(ceilings[0] < ceilings[1]);
        assert!(ceilings[1] < ceilings[2]);
    }

    #[test]
    fn signed_report_round_trips_and_is_deterministic() {
        let config = tiny_config();
        let a = build_signed_report(&config).unwrap();
        let b = build_signed_report(&config).unwrap();
        assert_eq!(a, b, "signed report must be byte-deterministic");
        // Serialize/deserialize round trip.
        let json = serde_json::to_string(&a).unwrap();
        let restored: SignedBandwidthReport = serde_json::from_str(&json).unwrap();
        assert_eq!(a, restored);
    }

    #[test]
    fn signed_report_hash_matches_report_body() {
        let signed = build_signed_report(&tiny_config()).unwrap();
        let bytes = serde_json::to_vec(&signed.report).unwrap();
        let expected = ContentHash::compute(&bytes).to_hex();
        assert_eq!(signed.report_hash, expected);
        assert_eq!(signed.signing_key_id, REPORT_SIGNING_KEY_ID);
        assert!(!signed.verification_key.is_empty());
        assert!(!signed.signature_hex.is_empty());
    }

    #[test]
    fn every_cell_respects_the_single_parity_ceiling() {
        let report = build_report(&BandwidthComparisonConfig::default()).unwrap();
        for cell in &report.cells {
            if cell.fault_tolerance_erasures == 1 {
                assert_eq!(cell.unique_parity_chunks, 1);
                assert!(
                    cell.savings_ratio_millionths
                        <= i64::try_from(cell.theoretical_savings_ceiling_millionths).unwrap(),
                    "cell fleet={} payload={} savings {} exceeded ceiling {}",
                    cell.fleet_size,
                    cell.payload_bytes,
                    cell.savings_ratio_millionths,
                    cell.theoretical_savings_ceiling_millionths
                );
            }
        }
    }
}
