//! Structured-concurrency parallel parsing with deterministic partitioning,
//! merge semantics, and bounded task orchestration.
//!
//! Partitions large source inputs into deterministic chunks, lexes each chunk
//! independently using the SIMD/SWAR lexer, then merges results with a stable
//! key-sorted canonicalization pass. Serial fallback is triggered on budget
//! exhaustion, parity mismatch, or small-file routing policy.
//!
//! ## Architecture
//!
//! 1. **Partition**: input split at deterministic depth-aware boundaries.
//! 2. **Parallel lex**: each chunk lexed independently (simulated, no threads).
//! 3. **Merge**: chunk results merged by start offset with boundary token repair.
//! 4. **Parity check**: merged output compared against serial reference.
//! 5. **Fallback**: on any mismatch, fallback to serial output with evidence.
//!
//! ## Related beads
//!
//! - bd-1vfi (this module)
//! - bd-19ba (SIMD lexer — upstream)
//! - bd-3rjg (parallel interference gate — downstream)
//! - bd-1gfn (error recovery — downstream)

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::simd_lexer::{self, LexerConfig, LexerMode, LexerOutput, Token, TokenKind};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const COMPONENT: &str = "parallel_parser";

/// Schema version for serde stability.
pub const SCHEMA_VERSION: &str = "franken-engine.parallel-parser.v1";

/// Default minimum input size (bytes) before parallel mode activates.
pub const DEFAULT_MIN_PARALLEL_BYTES: u64 = 4096;

/// Default maximum worker count.
pub const DEFAULT_MAX_WORKERS: u32 = 8;

/// Default per-chunk compute budget (microseconds).
pub const DEFAULT_CHUNK_BUDGET_US: u64 = 50_000;

/// Default merge buffer size (bytes).
pub const DEFAULT_MERGE_BUFFER_BYTES: u64 = 1_048_576;

/// Default small-file overhead threshold (percent, fixed-point millionths).
pub const DEFAULT_OVERHEAD_THRESHOLD_MILLIONTHS: u64 = 100_000; // 10%

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the parallel parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParallelConfig {
    /// Minimum input size (bytes) to enable parallel mode.
    pub min_parallel_bytes: u64,
    /// Maximum number of worker tasks.
    pub max_workers: u32,
    /// Per-chunk compute budget in microseconds.
    pub chunk_budget_us: u64,
    /// Maximum merge buffer size in bytes.
    pub merge_buffer_bytes: u64,
    /// Small-file overhead threshold (millionths, 1_000_000 = 100%).
    pub overhead_threshold_millionths: u64,
    /// Schedule seed for deterministic task ordering.
    pub schedule_seed: u64,
    /// Inner lexer configuration.
    pub lexer_config: LexerConfig,
    /// Whether to force serial parity check on every run.
    pub always_check_parity: bool,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            min_parallel_bytes: DEFAULT_MIN_PARALLEL_BYTES,
            max_workers: DEFAULT_MAX_WORKERS,
            chunk_budget_us: DEFAULT_CHUNK_BUDGET_US,
            merge_buffer_bytes: DEFAULT_MERGE_BUFFER_BYTES,
            overhead_threshold_millionths: DEFAULT_OVERHEAD_THRESHOLD_MILLIONTHS,
            schedule_seed: 0,
            lexer_config: LexerConfig::default(),
            always_check_parity: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Parser mode and routing
// ---------------------------------------------------------------------------

/// Routing decision for a parse request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ParserMode {
    /// Serial (single-threaded) parsing.
    Serial,
    /// Parallel (multi-chunk) parsing.
    Parallel,
}

impl fmt::Display for ParserMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serial => write!(f, "serial"),
            Self::Parallel => write!(f, "parallel"),
        }
    }
}

/// Reason a request was routed to serial mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerialReason {
    /// Input below minimum size for parallel.
    InputBelowThreshold { input_bytes: u64, threshold: u64 },
    /// Worker count configured to 1 or less.
    SingleWorker,
    /// No safe deterministic split points were found.
    NoDeterministicSplitPoints,
    /// Budget exhausted during parallel execution.
    BudgetExhausted { budget_us: u64 },
    /// Parity mismatch detected; fell back to serial.
    ParityMismatch { mismatch_index: u64 },
    /// Merge buffer exceeded.
    MergeBufferExceeded { buffer_bytes: u64, limit: u64 },
    /// Deterministic schedule transcript replay diverged from invariants.
    TranscriptDivergence { detail: String },
}

impl fmt::Display for SerialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputBelowThreshold {
                input_bytes,
                threshold,
            } => write!(f, "input {input_bytes}B below threshold {threshold}B"),
            Self::SingleWorker => write!(f, "single worker configured"),
            Self::NoDeterministicSplitPoints => write!(f, "no deterministic split points"),
            Self::BudgetExhausted { budget_us } => {
                write!(f, "budget exhausted ({budget_us}us)")
            }
            Self::ParityMismatch { mismatch_index } => {
                write!(f, "parity mismatch at token {mismatch_index}")
            }
            Self::MergeBufferExceeded {
                buffer_bytes,
                limit,
            } => write!(f, "merge buffer {buffer_bytes}B exceeds {limit}B"),
            Self::TranscriptDivergence { detail } => {
                write!(f, "transcript divergence: {detail}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Chunk partitioning
// ---------------------------------------------------------------------------

/// A deterministic partition of the input into chunks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkPlan {
    /// Chunk boundaries: (start_byte, end_byte) pairs.
    pub chunks: Vec<(u64, u64)>,
    /// Hash of the partition plan for determinism verification.
    pub plan_hash: ContentHash,
    /// Number of workers.
    pub worker_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundaryKind {
    Newline,
    StatementTerminator,
    BlockBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PartitionBoundary {
    end: u64,
    depth: u32,
    kind: BoundaryKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PartitionScanState {
    paren_depth: u32,
    brace_depth: u32,
    bracket_depth: u32,
    in_single_quote: bool,
    in_double_quote: bool,
    in_template_quote: bool,
    in_line_comment: bool,
    in_block_comment: bool,
    escape_next: bool,
}

impl PartitionScanState {
    #[must_use]
    const fn current_depth(self) -> u32 {
        self.paren_depth + self.brace_depth + self.bracket_depth
    }
}

fn collect_partition_boundaries(input: &[u8]) -> Vec<PartitionBoundary> {
    let mut state = PartitionScanState {
        paren_depth: 0,
        brace_depth: 0,
        bracket_depth: 0,
        in_single_quote: false,
        in_double_quote: false,
        in_template_quote: false,
        in_line_comment: false,
        in_block_comment: false,
        escape_next: false,
    };
    let mut boundaries = Vec::new();
    let mut idx = 0usize;

    while idx < input.len() {
        let byte = input[idx];
        let next = input.get(idx + 1).copied();

        if state.in_line_comment {
            if byte == b'\n' {
                state.in_line_comment = false;
                boundaries.push(PartitionBoundary {
                    end: (idx + 1) as u64,
                    depth: state.current_depth(),
                    kind: BoundaryKind::Newline,
                });
            }
            idx += 1;
            continue;
        }

        if state.in_block_comment {
            if byte == b'*' && next == Some(b'/') {
                state.in_block_comment = false;
                idx += 2;
                continue;
            }
            idx += 1;
            continue;
        }

        if state.in_single_quote {
            if state.escape_next {
                state.escape_next = false;
            } else if byte == b'\\' {
                state.escape_next = true;
            } else if byte == b'\'' {
                state.in_single_quote = false;
            }
            idx += 1;
            continue;
        }

        if state.in_double_quote {
            if state.escape_next {
                state.escape_next = false;
            } else if byte == b'\\' {
                state.escape_next = true;
            } else if byte == b'"' {
                state.in_double_quote = false;
            }
            idx += 1;
            continue;
        }

        if state.in_template_quote {
            if state.escape_next {
                state.escape_next = false;
            } else if byte == b'\\' {
                state.escape_next = true;
            } else if byte == b'`' {
                state.in_template_quote = false;
            }
            idx += 1;
            continue;
        }

        if byte == b'/' && next == Some(b'/') {
            state.in_line_comment = true;
            idx += 2;
            continue;
        }
        if byte == b'/' && next == Some(b'*') {
            state.in_block_comment = true;
            idx += 2;
            continue;
        }
        if byte == b'\'' {
            state.in_single_quote = true;
            idx += 1;
            continue;
        }
        if byte == b'"' {
            state.in_double_quote = true;
            idx += 1;
            continue;
        }
        if byte == b'`' {
            state.in_template_quote = true;
            idx += 1;
            continue;
        }

        match byte {
            b'(' => state.paren_depth = state.paren_depth.saturating_add(1),
            b')' => state.paren_depth = state.paren_depth.saturating_sub(1),
            b'{' => state.brace_depth = state.brace_depth.saturating_add(1),
            b'}' => state.brace_depth = state.brace_depth.saturating_sub(1),
            b'[' => state.bracket_depth = state.bracket_depth.saturating_add(1),
            b']' => state.bracket_depth = state.bracket_depth.saturating_sub(1),
            _ => {}
        }

        let maybe_kind = match byte {
            b'\n' => Some(BoundaryKind::Newline),
            b';' => Some(BoundaryKind::StatementTerminator),
            b'}' => Some(BoundaryKind::BlockBoundary),
            _ => None,
        };
        if let Some(kind) = maybe_kind {
            boundaries.push(PartitionBoundary {
                end: (idx + 1) as u64,
                depth: state.current_depth(),
                kind,
            });
        }

        idx += 1;
    }

    boundaries.sort_by_key(|boundary| boundary.end);
    boundaries.dedup_by_key(|boundary| boundary.end);
    boundaries
}

fn select_partition_end(
    boundaries: &[PartitionBoundary],
    start: u64,
    ideal: u64,
    max_end: u64,
) -> Option<u64> {
    boundaries
        .iter()
        .filter(|boundary| boundary.end > start && boundary.end <= max_end)
        .min_by_key(|boundary| {
            let after_penalty = if boundary.end >= ideal { 0u8 } else { 1u8 };
            let distance = boundary.end.abs_diff(ideal);
            let kind_bias = match boundary.kind {
                BoundaryKind::BlockBoundary => 0u8,
                BoundaryKind::StatementTerminator => 1u8,
                BoundaryKind::Newline => 2u8,
            };
            (
                boundary.depth,
                after_penalty,
                distance,
                kind_bias,
                boundary.end,
            )
        })
        .map(|boundary| boundary.end)
}

fn has_deterministic_split_points(input: &[u8]) -> bool {
    !collect_partition_boundaries(input).is_empty()
}

/// Compute deterministic chunk boundaries using depth-aware split points.
pub fn compute_chunk_plan(input: &[u8], max_workers: u32) -> ChunkPlan {
    let len = input.len() as u64;
    if len == 0 || max_workers <= 1 {
        let chunks = if len == 0 { vec![] } else { vec![(0, len)] };
        let hash = compute_plan_hash(&chunks);
        return ChunkPlan {
            chunks,
            plan_hash: hash,
            worker_count: 1,
        };
    }

    let mut boundaries = collect_partition_boundaries(input);
    boundaries.retain(|boundary| boundary.end < len);
    if boundaries.is_empty() {
        let chunks = vec![(0, len)];
        let plan_hash = compute_plan_hash(&chunks);
        return ChunkPlan {
            chunks,
            plan_hash,
            worker_count: 1,
        };
    }
    let worker_count = max_workers.min(len as u32).min(boundaries.len() as u32 + 1);

    let mut chunks = Vec::new();
    let mut start = 0u64;

    for i in 0..worker_count {
        let remaining_chunks = (worker_count - i) as u64;
        if remaining_chunks == 0 {
            break;
        }

        if i == worker_count - 1 {
            // Last chunk takes the remainder.
            if start < len {
                chunks.push((start, len));
            }
        } else {
            let ideal = start + ((len - start) / remaining_chunks);
            let max_end = len.saturating_sub(remaining_chunks - 1);
            let selected = match select_partition_end(&boundaries, start, ideal, max_end) {
                Some(end) => end,
                None => {
                    let chunks = vec![(0, len)];
                    let plan_hash = compute_plan_hash(&chunks);
                    return ChunkPlan {
                        chunks,
                        plan_hash,
                        worker_count: 1,
                    };
                }
            };
            let end = selected.max(start + 1).min(max_end);
            chunks.push((start, end));
            start = end;
        }
    }

    // Edge case: if alignment pushed us past the end, ensure no empty chunks.
    if chunks.is_empty() && len > 0 {
        chunks.push((0, len));
    }

    let plan_hash = compute_plan_hash(&chunks);
    ChunkPlan {
        chunks,
        plan_hash,
        worker_count,
    }
}

fn compute_plan_hash(chunks: &[(u64, u64)]) -> ContentHash {
    let mut parts = Vec::new();
    for (s, e) in chunks {
        parts.push(format!("{s}:{e}"));
    }
    ContentHash::compute(parts.join("|").as_bytes())
}

// ---------------------------------------------------------------------------
// Chunk result and merge
// ---------------------------------------------------------------------------

/// Result of lexing a single chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkResult {
    /// Chunk index (0-based).
    pub chunk_index: u32,
    /// Start byte offset in the original input.
    pub chunk_start: u64,
    /// End byte offset in the original input.
    pub chunk_end: u64,
    /// Tokens produced (offsets are relative to chunk_start).
    pub tokens: Vec<Token>,
    /// Token count.
    pub token_count: u64,
}

/// Merge chunk results into a single ordered token stream.
/// Adjusts token offsets to be absolute (relative to input start).
pub fn merge_chunks(chunks: &[ChunkResult]) -> Vec<Token> {
    #[derive(Debug, Clone)]
    struct MergeEntry {
        token: Token,
        chunk_index: u32,
        token_ordinal: u32,
    }

    let mut entries = Vec::new();
    for chunk in chunks {
        for (token_ordinal, token) in chunk.tokens.iter().enumerate() {
            entries.push(MergeEntry {
                token: Token {
                    kind: token.kind,
                    start: token.start + chunk.chunk_start,
                    end: token.end + chunk.chunk_start,
                },
                chunk_index: chunk.chunk_index,
                token_ordinal: token_ordinal as u32,
            });
        }
    }

    // Canonical source-order merge key: absolute span first, then chunk and local order.
    entries.sort_by_key(|entry| {
        (
            entry.token.start,
            entry.token.end,
            entry.chunk_index,
            entry.token_ordinal,
        )
    });
    entries.into_iter().map(|entry| entry.token).collect()
}

#[must_use]
fn token_kind_code(kind: TokenKind) -> u8 {
    match kind {
        TokenKind::Identifier => 0,
        TokenKind::NumericLiteral => 1,
        TokenKind::StringLiteral => 2,
        TokenKind::UnterminatedString => 3,
        TokenKind::TwoCharOperator => 4,
        TokenKind::Punctuation => 5,
    }
}

#[must_use]
fn compute_chunk_hash(chunk: &ChunkResult) -> ContentHash {
    let mut bytes = Vec::with_capacity(32 + chunk.tokens.len() * 24);
    bytes.extend_from_slice(&chunk.chunk_index.to_le_bytes());
    bytes.extend_from_slice(&chunk.chunk_start.to_le_bytes());
    bytes.extend_from_slice(&chunk.chunk_end.to_le_bytes());
    bytes.extend_from_slice(&chunk.token_count.to_le_bytes());
    for token in &chunk.tokens {
        bytes.push(token_kind_code(token.kind));
        bytes.extend_from_slice(&token.start.to_le_bytes());
        bytes.extend_from_slice(&token.end.to_le_bytes());
    }
    ContentHash::compute(&bytes)
}

#[must_use]
fn compute_merge_witness_hash(
    chunks: &[ChunkResult],
    merged_hash: &ContentHash,
    boundary_repairs: u64,
    total_tokens: u64,
) -> ContentHash {
    let mut ordered_chunks: Vec<&ChunkResult> = chunks.iter().collect();
    ordered_chunks.sort_by_key(|chunk| chunk.chunk_index);

    let mut bytes = Vec::with_capacity(64 + ordered_chunks.len() * 40);
    bytes.extend_from_slice(merged_hash.as_bytes());
    bytes.extend_from_slice(&boundary_repairs.to_le_bytes());
    bytes.extend_from_slice(&total_tokens.to_le_bytes());
    bytes.extend_from_slice(&(ordered_chunks.len() as u32).to_le_bytes());
    for chunk in ordered_chunks {
        bytes.extend_from_slice(&chunk.chunk_index.to_le_bytes());
        bytes.extend_from_slice(compute_chunk_hash(chunk).as_bytes());
    }
    ContentHash::compute(&bytes)
}

/// Repair boundary tokens where a multi-character token was split across chunks.
/// Adjacent tokens that overlap or are contiguous with the same kind are merged.
pub fn repair_boundary_tokens(tokens: &mut Vec<Token>) {
    if tokens.len() < 2 {
        return;
    }
    let mut write = 0;
    for read in 1..tokens.len() {
        if tokens[write].kind == tokens[read].kind && tokens[write].end >= tokens[read].start {
            // Merge: extend the write token to cover both.
            tokens[write].end = tokens[write].end.max(tokens[read].end);
        } else {
            write += 1;
            tokens[write] = tokens[read].clone();
        }
    }
    tokens.truncate(write + 1);
}

// ---------------------------------------------------------------------------
// Witness and evidence
// ---------------------------------------------------------------------------

/// Merge witness: deterministic record of the merge operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeWitness {
    /// Hash of the merged token stream.
    pub merged_hash: ContentHash,
    /// Hash of merge inputs + metadata for witness verification.
    pub witness_hash: ContentHash,
    /// Number of chunks merged.
    pub chunk_count: u32,
    /// Number of boundary repairs performed.
    pub boundary_repairs: u64,
    /// Total tokens after merge.
    pub total_tokens: u64,
}

/// Schedule transcript: deterministic record of task scheduling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleTranscript {
    /// Schedule seed used.
    pub seed: u64,
    /// Worker count.
    pub worker_count: u32,
    /// Chunk plan hash.
    pub plan_hash: ContentHash,
    /// Execution order (chunk indices in execution order).
    pub execution_order: Vec<u32>,
    /// Per-step deterministic worker dispatch decisions.
    pub dispatches: Vec<ScheduleDispatch>,
    /// Hash of the full transcript payload.
    pub transcript_hash: ContentHash,
}

/// One deterministic scheduler dispatch decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleDispatch {
    /// Zero-based dispatch sequence index.
    pub step_index: u32,
    /// Chunk index dispatched at this step.
    pub chunk_index: u32,
    /// Worker slot selected for this step.
    pub worker_slot: u32,
}

#[must_use]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[must_use]
fn schedule_rank(seed: u64, plan_hash: &ContentHash, chunk_index: u32) -> u64 {
    let hash_words = plan_hash.as_bytes();
    let word_offset = (chunk_index as usize % 4) * 8;
    let mut word_bytes = [0_u8; 8];
    word_bytes.copy_from_slice(&hash_words[word_offset..word_offset + 8]);
    let hash_word = u64::from_be_bytes(word_bytes);
    let chunk_component = (chunk_index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    splitmix64(seed ^ hash_word ^ chunk_component)
}

#[must_use]
fn deterministic_execution_order(chunk_count: u32, seed: u64, plan_hash: &ContentHash) -> Vec<u32> {
    let mut order: Vec<u32> = (0..chunk_count).collect();
    order.sort_by_key(|chunk_index| {
        (
            schedule_rank(seed, plan_hash, *chunk_index),
            *chunk_index as u64,
        )
    });
    order
}

#[must_use]
fn build_schedule_dispatches(execution_order: &[u32], worker_count: u32) -> Vec<ScheduleDispatch> {
    let mut dispatches = Vec::with_capacity(execution_order.len());
    for (step_index, chunk_index) in execution_order.iter().enumerate() {
        let worker_slot = if worker_count == 0 {
            0
        } else {
            (step_index as u32) % worker_count
        };
        dispatches.push(ScheduleDispatch {
            step_index: step_index as u32,
            chunk_index: *chunk_index,
            worker_slot,
        });
    }
    dispatches
}

#[must_use]
fn compute_schedule_transcript_hash(
    seed: u64,
    worker_count: u32,
    plan_hash: &ContentHash,
    execution_order: &[u32],
    dispatches: &[ScheduleDispatch],
) -> ContentHash {
    let mut bytes = Vec::with_capacity(16 + 32 + execution_order.len() * 4 + dispatches.len() * 12);
    bytes.extend_from_slice(&seed.to_le_bytes());
    bytes.extend_from_slice(&worker_count.to_le_bytes());
    bytes.extend_from_slice(plan_hash.as_bytes());
    bytes.extend_from_slice(&(execution_order.len() as u32).to_le_bytes());
    for chunk_index in execution_order {
        bytes.extend_from_slice(&chunk_index.to_le_bytes());
    }
    bytes.extend_from_slice(&(dispatches.len() as u32).to_le_bytes());
    for dispatch in dispatches {
        bytes.extend_from_slice(&dispatch.step_index.to_le_bytes());
        bytes.extend_from_slice(&dispatch.chunk_index.to_le_bytes());
        bytes.extend_from_slice(&dispatch.worker_slot.to_le_bytes());
    }
    ContentHash::compute(&bytes)
}

/// Build a deterministic scheduler transcript from a chunk plan and seed.
#[must_use]
pub fn build_schedule_transcript(chunk_plan: &ChunkPlan, seed: u64) -> ScheduleTranscript {
    let chunk_count = chunk_plan.chunks.len() as u32;
    let execution_order = deterministic_execution_order(chunk_count, seed, &chunk_plan.plan_hash);
    let dispatches = build_schedule_dispatches(&execution_order, chunk_plan.worker_count);
    let transcript_hash = compute_schedule_transcript_hash(
        seed,
        chunk_plan.worker_count,
        &chunk_plan.plan_hash,
        &execution_order,
        &dispatches,
    );
    ScheduleTranscript {
        seed,
        worker_count: chunk_plan.worker_count,
        plan_hash: chunk_plan.plan_hash,
        execution_order,
        dispatches,
        transcript_hash,
    }
}

/// Transcript replay validation failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TranscriptReplayError {
    PlanHashMismatch {
        expected: ContentHash,
        actual: ContentHash,
    },
    WorkerCountMismatch {
        expected: u32,
        actual: u32,
    },
    InvalidExecutionOrderLength {
        expected_chunks: u32,
        actual_entries: u32,
    },
    InvalidDispatchCount {
        expected_steps: u32,
        actual_steps: u32,
    },
    InvalidChunkReference {
        step_index: u32,
        chunk_index: u32,
        chunk_count: u32,
    },
    DuplicateChunkReference {
        chunk_index: u32,
    },
    MissingChunkReference {
        chunk_index: u32,
    },
    DispatchStepMismatch {
        expected_step: u32,
        actual_step: u32,
    },
    DispatchChunkMismatch {
        step_index: u32,
        expected_chunk: u32,
        actual_chunk: u32,
    },
    WorkerSlotOutOfRange {
        step_index: u32,
        worker_slot: u32,
        worker_count: u32,
    },
    TranscriptHashMismatch {
        expected: ContentHash,
        actual: ContentHash,
    },
}

impl fmt::Display for TranscriptReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlanHashMismatch { .. } => write!(f, "plan hash mismatch"),
            Self::WorkerCountMismatch { expected, actual } => {
                write!(
                    f,
                    "worker count mismatch: expected {expected}, got {actual}"
                )
            }
            Self::InvalidExecutionOrderLength {
                expected_chunks,
                actual_entries,
            } => write!(
                f,
                "execution order length mismatch: expected {expected_chunks}, got {actual_entries}"
            ),
            Self::InvalidDispatchCount {
                expected_steps,
                actual_steps,
            } => write!(
                f,
                "dispatch count mismatch: expected {expected_steps}, got {actual_steps}"
            ),
            Self::InvalidChunkReference {
                step_index,
                chunk_index,
                chunk_count,
            } => write!(
                f,
                "invalid chunk reference at step {step_index}: chunk {chunk_index} >= {chunk_count}"
            ),
            Self::DuplicateChunkReference { chunk_index } => {
                write!(f, "duplicate chunk reference in transcript: {chunk_index}")
            }
            Self::MissingChunkReference { chunk_index } => {
                write!(f, "missing chunk reference in transcript: {chunk_index}")
            }
            Self::DispatchStepMismatch {
                expected_step,
                actual_step,
            } => write!(
                f,
                "dispatch step mismatch: expected {expected_step}, got {actual_step}"
            ),
            Self::DispatchChunkMismatch {
                step_index,
                expected_chunk,
                actual_chunk,
            } => write!(
                f,
                "dispatch chunk mismatch at step {step_index}: expected {expected_chunk}, got {actual_chunk}"
            ),
            Self::WorkerSlotOutOfRange {
                step_index,
                worker_slot,
                worker_count,
            } => write!(
                f,
                "worker slot out of range at step {step_index}: {worker_slot} >= {worker_count}"
            ),
            Self::TranscriptHashMismatch { .. } => write!(f, "transcript hash mismatch"),
        }
    }
}

/// Replay and validate a scheduler transcript against a chunk plan.
///
/// Returns the replay execution order if all transcript invariants hold.
pub fn replay_schedule_transcript(
    transcript: &ScheduleTranscript,
    chunk_plan: &ChunkPlan,
) -> Result<Vec<u32>, TranscriptReplayError> {
    if transcript.plan_hash != chunk_plan.plan_hash {
        return Err(TranscriptReplayError::PlanHashMismatch {
            expected: chunk_plan.plan_hash,
            actual: transcript.plan_hash,
        });
    }
    if transcript.worker_count != chunk_plan.worker_count {
        return Err(TranscriptReplayError::WorkerCountMismatch {
            expected: chunk_plan.worker_count,
            actual: transcript.worker_count,
        });
    }

    let chunk_count = chunk_plan.chunks.len() as u32;
    if transcript.execution_order.len() as u32 != chunk_count {
        return Err(TranscriptReplayError::InvalidExecutionOrderLength {
            expected_chunks: chunk_count,
            actual_entries: transcript.execution_order.len() as u32,
        });
    }
    if transcript.dispatches.len() != transcript.execution_order.len() {
        return Err(TranscriptReplayError::InvalidDispatchCount {
            expected_steps: transcript.execution_order.len() as u32,
            actual_steps: transcript.dispatches.len() as u32,
        });
    }

    let mut seen = vec![false; chunk_count as usize];
    for (step_index, chunk_index) in transcript.execution_order.iter().copied().enumerate() {
        if chunk_index >= chunk_count {
            return Err(TranscriptReplayError::InvalidChunkReference {
                step_index: step_index as u32,
                chunk_index,
                chunk_count,
            });
        }
        if seen[chunk_index as usize] {
            return Err(TranscriptReplayError::DuplicateChunkReference { chunk_index });
        }
        seen[chunk_index as usize] = true;

        let dispatch = &transcript.dispatches[step_index];
        if dispatch.step_index != step_index as u32 {
            return Err(TranscriptReplayError::DispatchStepMismatch {
                expected_step: step_index as u32,
                actual_step: dispatch.step_index,
            });
        }
        if dispatch.chunk_index != chunk_index {
            return Err(TranscriptReplayError::DispatchChunkMismatch {
                step_index: step_index as u32,
                expected_chunk: chunk_index,
                actual_chunk: dispatch.chunk_index,
            });
        }
        if transcript.worker_count > 0 && dispatch.worker_slot >= transcript.worker_count {
            return Err(TranscriptReplayError::WorkerSlotOutOfRange {
                step_index: step_index as u32,
                worker_slot: dispatch.worker_slot,
                worker_count: transcript.worker_count,
            });
        }
    }

    for (chunk_index, observed) in seen.iter().enumerate() {
        if !*observed {
            return Err(TranscriptReplayError::MissingChunkReference {
                chunk_index: chunk_index as u32,
            });
        }
    }

    let expected_hash = compute_schedule_transcript_hash(
        transcript.seed,
        transcript.worker_count,
        &transcript.plan_hash,
        &transcript.execution_order,
        &transcript.dispatches,
    );
    if transcript.transcript_hash != expected_hash {
        return Err(TranscriptReplayError::TranscriptHashMismatch {
            expected: expected_hash,
            actual: transcript.transcript_hash,
        });
    }

    Ok(transcript.execution_order.clone())
}

/// Parity result: comparison between parallel and serial outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityResult {
    /// Whether parity holds.
    pub parity_ok: bool,
    /// Index of first mismatched token (if any).
    pub mismatch_index: Option<u64>,
    /// Parallel token count.
    pub parallel_count: u64,
    /// Serial token count.
    pub serial_count: u64,
}

// ---------------------------------------------------------------------------
// Fallback
// ---------------------------------------------------------------------------

/// Fallback cause taxonomy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FallbackCause {
    /// Routing decision (before parallel attempt).
    Routing(SerialReason),
    /// Parity failure (after parallel attempt).
    ParityFailure { mismatch_index: u64 },
    /// Budget/resource limit.
    ResourceLimit(SerialReason),
    /// Deterministic transcript replay divergence.
    TranscriptDivergence { detail: String },
}

impl fmt::Display for FallbackCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Routing(r) => write!(f, "routing: {r}"),
            Self::ParityFailure { mismatch_index } => {
                write!(f, "parity failure at token {mismatch_index}")
            }
            Self::ResourceLimit(r) => write!(f, "resource limit: {r}"),
            Self::TranscriptDivergence { detail } => {
                write!(f, "transcript divergence: {detail}")
            }
        }
    }
}

/// Stable trigger taxonomy for deterministic serial failover controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FailoverTriggerClass {
    Timeout,
    TranscriptDivergence,
    WitnessMismatch,
    SafetyPolicyViolation,
    ParityMismatch,
    ResourceLimit,
}

impl fmt::Display for FailoverTriggerClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "timeout"),
            Self::TranscriptDivergence => write!(f, "transcript-divergence"),
            Self::WitnessMismatch => write!(f, "witness-mismatch"),
            Self::SafetyPolicyViolation => write!(f, "safety-policy-violation"),
            Self::ParityMismatch => write!(f, "parity-mismatch"),
            Self::ResourceLimit => write!(f, "resource-limit"),
        }
    }
}

/// Classified failover trigger with deterministic detail payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailoverTrigger {
    pub class: FailoverTriggerClass,
    pub detail: String,
}

/// Deterministic transition path taken by the serial failover controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FailoverState {
    ParallelAttempted,
    TriggerClassified,
    SerialFallbackRequested,
    SerialFallbackCompleted,
}

impl fmt::Display for FailoverState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParallelAttempted => write!(f, "parallel-attempted"),
            Self::TriggerClassified => write!(f, "trigger-classified"),
            Self::SerialFallbackRequested => write!(f, "serial-fallback-requested"),
            Self::SerialFallbackCompleted => write!(f, "serial-fallback-completed"),
        }
    }
}

/// Replayable decision artifact emitted whenever failover is triggered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailoverDecision {
    pub trigger: FailoverTrigger,
    pub transition_path: Vec<FailoverState>,
    pub witness_ids: Vec<String>,
    pub replay_command: String,
}

// ---------------------------------------------------------------------------
// Timeout / cancellation policy
// ---------------------------------------------------------------------------

/// Timeout policy for parallel chunk processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutPolicy {
    /// Maximum wall-clock microseconds for the entire parallel phase.
    pub max_total_us: u64,
    /// Maximum wall-clock microseconds per chunk.
    pub max_chunk_us: u64,
    /// Whether to allow graceful drain before hard cancel.
    pub allow_drain: bool,
}

impl Default for TimeoutPolicy {
    fn default() -> Self {
        Self {
            max_total_us: 500_000,
            max_chunk_us: 100_000,
            allow_drain: true,
        }
    }
}

/// State of a cancellation lifecycle: request → drain → finalize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CancellationState {
    /// No cancellation requested.
    None,
    /// Cancellation requested, workers draining.
    Requested,
    /// Workers have drained, finalizing.
    Draining,
    /// Cancellation complete, results discarded or partial.
    Finalized,
}

impl fmt::Display for CancellationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Requested => write!(f, "requested"),
            Self::Draining => write!(f, "draining"),
            Self::Finalized => write!(f, "finalized"),
        }
    }
}

/// Record of a timeout/cancellation event during parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationRecord {
    /// Final cancellation state reached.
    pub state: CancellationState,
    /// Elapsed microseconds at cancellation.
    pub elapsed_us: u64,
    /// Chunk that triggered the timeout (if per-chunk).
    pub trigger_chunk: Option<u32>,
    /// Whether drain was completed before finalization.
    pub drain_completed: bool,
}

// ---------------------------------------------------------------------------
// Backpressure instrumentation
// ---------------------------------------------------------------------------

/// Backpressure state for the parallel work queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BackpressureLevel {
    /// Normal operating conditions.
    Normal,
    /// Approaching capacity limits.
    Elevated,
    /// At capacity, new work will be delayed.
    Critical,
}

impl fmt::Display for BackpressureLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => write!(f, "normal"),
            Self::Elevated => write!(f, "elevated"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Queue and backpressure metrics for a parse run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureSnapshot {
    /// Current queue depth (pending chunks).
    pub queue_depth: u32,
    /// Maximum observed queue depth during this run.
    pub peak_queue_depth: u32,
    /// Backpressure level.
    pub level: BackpressureLevel,
    /// Number of chunks that experienced queueing delay.
    pub delayed_chunks: u32,
    /// Total queueing delay in microseconds.
    pub total_delay_us: u64,
}

// ---------------------------------------------------------------------------
// Workload routing digest
// ---------------------------------------------------------------------------

/// Why a specific input was routed to serial or parallel mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingDigest {
    /// Input size in bytes.
    pub input_bytes: u64,
    /// Configured threshold for parallel activation.
    pub parallel_threshold: u64,
    /// Configured worker count.
    pub configured_workers: u32,
    /// Effective worker count (may be reduced for small inputs).
    pub effective_workers: u32,
    /// Final routing decision.
    pub decision: ParserMode,
    /// Human-readable rationale.
    pub rationale: String,
    /// Whether the input contains deterministic safe split points.
    pub has_partition_points: bool,
    /// Estimated overhead ratio (millionths, 1_000_000 = 100%).
    pub estimated_overhead_millionths: u64,
}

// ---------------------------------------------------------------------------
// Performance instrumentation
// ---------------------------------------------------------------------------

/// Throughput sample for a single parse run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputSample {
    /// Bytes processed.
    pub bytes: u64,
    /// Tokens produced.
    pub tokens: u64,
    /// Total elapsed microseconds (wall clock).
    pub elapsed_us: u64,
    /// Throughput: bytes per second (fixed-point millionths).
    pub bytes_per_sec_millionths: u64,
    /// Throughput: tokens per second (fixed-point millionths).
    pub tokens_per_sec_millionths: u64,
}

impl ThroughputSample {
    /// Compute a throughput sample from raw measurements.
    pub fn compute(bytes: u64, tokens: u64, elapsed_us: u64) -> Self {
        let bytes_per_sec_millionths = if elapsed_us > 0 {
            bytes
                .checked_mul(1_000_000_000_000)
                .and_then(|n| n.checked_div(elapsed_us))
                .unwrap_or(0)
        } else {
            0
        };
        let tokens_per_sec_millionths = if elapsed_us > 0 {
            tokens
                .checked_mul(1_000_000_000_000)
                .and_then(|n| n.checked_div(elapsed_us))
                .unwrap_or(0)
        } else {
            0
        };
        Self {
            bytes,
            tokens,
            elapsed_us,
            bytes_per_sec_millionths,
            tokens_per_sec_millionths,
        }
    }
}

/// Per-chunk timing for performance analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkTiming {
    /// Chunk index.
    pub chunk_index: u32,
    /// Chunk size in bytes.
    pub chunk_bytes: u64,
    /// Tokens produced by this chunk.
    pub token_count: u64,
    /// Elapsed microseconds for this chunk's lexing.
    pub elapsed_us: u64,
}

/// Aggregated performance report for a parse run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceReport {
    /// Overall throughput.
    pub throughput: ThroughputSample,
    /// Per-chunk timings (parallel mode only).
    pub chunk_timings: Vec<ChunkTiming>,
    /// Merge phase elapsed microseconds.
    pub merge_elapsed_us: u64,
    /// Parity check elapsed microseconds.
    pub parity_check_elapsed_us: u64,
}

// ---------------------------------------------------------------------------
// Replay envelope
// ---------------------------------------------------------------------------

/// Full replay envelope: contains everything needed to reproduce a parse run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEnvelope {
    /// Schema version.
    pub schema_version: String,
    /// Input content hash (NOT the input itself — too large).
    pub input_hash: ContentHash,
    /// Input size in bytes.
    pub input_bytes: u64,
    /// Configuration used.
    pub config: ParallelConfig,
    /// Security epoch.
    pub epoch_raw: u64,
    /// Trace identifier.
    pub trace_id: String,
    /// Run identifier.
    pub run_id: String,
    /// Chunk plan used (if parallel).
    pub chunk_plan: Option<ChunkPlan>,
    /// Schedule transcript (if parallel).
    pub schedule_transcript: Option<ScheduleTranscript>,
    /// Merge witness (if parallel).
    pub merge_witness: Option<MergeWitness>,
    /// Parity result (if checked).
    pub parity_result: Option<ParityResult>,
    /// Routing digest.
    pub routing_digest: RoutingDigest,
    /// Cancellation record (if any).
    pub cancellation: Option<CancellationRecord>,
    /// Deterministic failover decision (if fallback triggered).
    pub failover_decision: Option<FailoverDecision>,
    /// Output hash for verification.
    pub output_hash: ContentHash,
    /// Replay command hint.
    pub replay_command: String,
}

/// Build a replay envelope from a completed parse.
pub fn build_replay_envelope(
    input: &ParseInput<'_>,
    output: &ParseOutput,
    routing_digest: &RoutingDigest,
) -> ReplayEnvelope {
    let transcript_hash = output
        .schedule_transcript
        .as_ref()
        .map(|t| t.transcript_hash.to_hex())
        .unwrap_or_else(|| "none".to_string());
    ReplayEnvelope {
        schema_version: SCHEMA_VERSION.to_string(),
        input_hash: ContentHash::compute(input.source.as_bytes()),
        input_bytes: input.source.len() as u64,
        config: input.config.clone(),
        epoch_raw: input.epoch.as_u64(),
        trace_id: input.trace_id.to_string(),
        run_id: input.run_id.to_string(),
        chunk_plan: output.chunk_plan.clone(),
        schedule_transcript: output.schedule_transcript.clone(),
        merge_witness: output.merge_witness.clone(),
        parity_result: output.parity_result.clone(),
        routing_digest: routing_digest.clone(),
        cancellation: output.cancellation.clone(),
        failover_decision: output.failover_decision.clone(),
        output_hash: output.output_hash,
        replay_command: format!(
            "franken-engine parallel-parse --trace-id {} --run-id {} --seed {} --workers {} --transcript-hash {}",
            input.trace_id,
            input.run_id,
            input.config.schedule_seed,
            input.config.max_workers,
            transcript_hash,
        ),
    }
}

// ---------------------------------------------------------------------------
// Rollback control
// ---------------------------------------------------------------------------

/// Rollback control: can disable parallel mode at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackControl {
    /// Whether parallel mode is currently disabled.
    pub parallel_disabled: bool,
    /// Reason for disabling (if disabled).
    pub disable_reason: Option<String>,
    /// Number of consecutive parity failures that triggered rollback.
    pub consecutive_failures: u32,
    /// Threshold of consecutive failures before auto-rollback.
    pub auto_rollback_threshold: u32,
    /// Set of trace IDs that triggered failures.
    pub failure_trace_ids: BTreeSet<String>,
}

impl Default for RollbackControl {
    fn default() -> Self {
        Self {
            parallel_disabled: false,
            disable_reason: None,
            consecutive_failures: 0,
            auto_rollback_threshold: 3,
            failure_trace_ids: BTreeSet::new(),
        }
    }
}

impl RollbackControl {
    /// Record a parity failure. Returns true if auto-rollback was triggered.
    pub fn record_failure(&mut self, trace_id: &str) -> bool {
        self.consecutive_failures += 1;
        self.failure_trace_ids.insert(trace_id.to_string());
        if self.consecutive_failures >= self.auto_rollback_threshold {
            self.parallel_disabled = true;
            self.disable_reason = Some(format!(
                "auto-rollback after {} consecutive parity failures",
                self.consecutive_failures
            ));
            true
        } else {
            false
        }
    }

    /// Record a successful parallel parse, resetting the failure counter.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
    }

    /// Manually disable parallel mode.
    pub fn force_disable(&mut self, reason: &str) {
        self.parallel_disabled = true;
        self.disable_reason = Some(reason.to_string());
    }

    /// Re-enable parallel mode.
    pub fn re_enable(&mut self) {
        self.parallel_disabled = false;
        self.disable_reason = None;
        self.consecutive_failures = 0;
        self.failure_trace_ids.clear();
    }
}

// ---------------------------------------------------------------------------
// Parse output
// ---------------------------------------------------------------------------

/// Full output of a parallel parse operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseOutput {
    /// Schema version.
    pub schema_version: String,
    /// Mode actually used.
    pub mode: ParserMode,
    /// If serial was used, why.
    pub serial_reason: Option<SerialReason>,
    /// Fallback cause (if fallback occurred).
    pub fallback_cause: Option<FallbackCause>,
    /// Final tokens.
    pub tokens: Vec<Token>,
    /// Token count.
    pub token_count: u64,
    /// Bytes scanned.
    pub bytes_scanned: u64,
    /// Chunk plan (if parallel was attempted).
    pub chunk_plan: Option<ChunkPlan>,
    /// Merge witness (if parallel was attempted).
    pub merge_witness: Option<MergeWitness>,
    /// Schedule transcript (if parallel was attempted).
    pub schedule_transcript: Option<ScheduleTranscript>,
    /// Parity result (if parity check was performed).
    pub parity_result: Option<ParityResult>,
    /// Deterministic failover decision log (if fallback triggered).
    pub failover_decision: Option<FailoverDecision>,
    /// Timeout policy projected for replayable diagnostics (parallel path only).
    pub timeout_policy: Option<TimeoutPolicy>,
    /// Cancellation record if timeout/failover cancellation occurred.
    pub cancellation: Option<CancellationRecord>,
    /// Backpressure snapshot for deterministic queue behavior.
    pub backpressure: Option<BackpressureSnapshot>,
    /// Content hash of the output token stream.
    pub output_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Structured logging
// ---------------------------------------------------------------------------

/// Structured log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseLogEntry {
    pub trace_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub parser_mode: Option<String>,
    pub worker_count: Option<u32>,
    pub input_bytes: Option<u64>,
    pub token_count: Option<u64>,
    pub fallback_reason: Option<String>,
    pub failover_trigger: Option<String>,
    pub failover_transition_path: Option<Vec<String>>,
    pub failover_witness_ids: Option<Vec<String>>,
    pub replay_command: Option<String>,
    pub parity_result: Option<String>,
    pub cancellation_state: Option<String>,
    pub cancellation_elapsed_us: Option<u64>,
    pub backpressure_level: Option<String>,
    pub backpressure_peak_queue_depth: Option<u32>,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors during parallel parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseError {
    /// Lexer error in a chunk.
    LexerError { chunk_index: u32, detail: String },
    /// Input too large for configured limits.
    InputTooLarge { size: u64, max: u64 },
    /// Invalid configuration.
    InvalidConfig { detail: String },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LexerError {
                chunk_index,
                detail,
            } => write!(f, "lexer error in chunk {chunk_index}: {detail}"),
            Self::InputTooLarge { size, max } => {
                write!(f, "input too large: {size}B exceeds {max}B")
            }
            Self::InvalidConfig { detail } => write!(f, "invalid config: {detail}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Parse input
// ---------------------------------------------------------------------------

/// Input for a parse operation.
#[derive(Debug, Clone)]
pub struct ParseInput<'a> {
    /// Source text to parse.
    pub source: &'a str,
    /// Trace identifier for structured logging.
    pub trace_id: &'a str,
    /// Run identifier.
    pub run_id: &'a str,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Configuration.
    pub config: &'a ParallelConfig,
}

fn build_failover_decision(
    input: &ParseInput<'_>,
    trigger: FailoverTrigger,
    schedule_transcript: Option<&ScheduleTranscript>,
    merge_witness: Option<&MergeWitness>,
    output_hash: &ContentHash,
) -> FailoverDecision {
    let mut witness_ids = Vec::new();
    if let Some(transcript) = schedule_transcript {
        witness_ids.push(format!(
            "schedule_transcript:{}",
            transcript.transcript_hash.to_hex()
        ));
    }
    if let Some(witness) = merge_witness {
        witness_ids.push(format!("merge_witness:{}", witness.witness_hash.to_hex()));
    }
    witness_ids.push(format!("output_hash:{}", output_hash.to_hex()));

    let replay_command = format!(
        "franken-engine parallel-parse --trace-id {} --run-id {} --seed {} --workers {}",
        input.trace_id, input.run_id, input.config.schedule_seed, input.config.max_workers
    );

    FailoverDecision {
        trigger,
        transition_path: vec![
            FailoverState::ParallelAttempted,
            FailoverState::TriggerClassified,
            FailoverState::SerialFallbackRequested,
            FailoverState::SerialFallbackCompleted,
        ],
        witness_ids,
        replay_command,
    }
}

fn derive_timeout_policy(config: &ParallelConfig, chunk_count: usize) -> TimeoutPolicy {
    let max_chunk_us = config.chunk_budget_us.max(1);
    let max_total_us = max_chunk_us
        .saturating_mul(chunk_count as u64)
        .saturating_add(max_chunk_us / 2);
    TimeoutPolicy {
        max_total_us,
        max_chunk_us,
        allow_drain: true,
    }
}

fn deterministic_chunk_elapsed_us(chunk_bytes: u64, token_count: u64, step_index: usize) -> u64 {
    let byte_component = chunk_bytes.saturating_mul(2);
    let token_component = token_count.saturating_mul(3);
    let step_component = (step_index as u64 + 1).saturating_mul(17);
    byte_component
        .saturating_add(token_component)
        .saturating_add(step_component)
        .saturating_add(50)
}

fn classify_backpressure_level(peak_queue_depth: u32) -> BackpressureLevel {
    if peak_queue_depth >= 12 {
        BackpressureLevel::Critical
    } else if peak_queue_depth >= 2 {
        BackpressureLevel::Elevated
    } else {
        BackpressureLevel::Normal
    }
}

fn compute_backpressure_snapshot(
    chunk_timings: &[ChunkTiming],
    timeout_policy: &TimeoutPolicy,
) -> BackpressureSnapshot {
    let delay_quantum_us = (timeout_policy.max_chunk_us / 4).max(1);
    let mut queue_depth = 0u32;
    let mut peak_queue_depth = 0u32;
    let mut delayed_chunks = 0u32;
    let mut total_delay_us = 0u64;

    for timing in chunk_timings {
        let overload_units = timing.elapsed_us / delay_quantum_us;
        let current_depth = u32::try_from(overload_units.saturating_sub(1)).unwrap_or(u32::MAX);
        queue_depth = current_depth;
        peak_queue_depth = peak_queue_depth.max(current_depth);
        if current_depth > 0 {
            delayed_chunks = delayed_chunks.saturating_add(1);
            total_delay_us =
                total_delay_us.saturating_add(timing.elapsed_us.saturating_sub(delay_quantum_us));
        }
    }

    BackpressureSnapshot {
        queue_depth,
        peak_queue_depth,
        level: classify_backpressure_level(peak_queue_depth),
        delayed_chunks,
        total_delay_us,
    }
}

fn build_timeout_cancellation_record(
    timeout_policy: &TimeoutPolicy,
    elapsed_us: u64,
    trigger_chunk: Option<u32>,
) -> CancellationRecord {
    CancellationRecord {
        state: if timeout_policy.allow_drain {
            CancellationState::Finalized
        } else {
            CancellationState::Requested
        },
        elapsed_us,
        trigger_chunk,
        drain_completed: timeout_policy.allow_drain,
    }
}

// ---------------------------------------------------------------------------
// Core parse logic
// ---------------------------------------------------------------------------

/// Parse source input using the parallel parser.
///
/// Routes to serial or parallel mode based on configuration and input size.
/// If parallel mode is used, performs a parity check against the serial
/// reference and falls back if mismatch is detected.
pub fn parse(input: &ParseInput<'_>) -> Result<ParseOutput, ParseError> {
    let source = input.source;
    let bytes = source.as_bytes();
    let config = input.config;

    // Validate configuration.
    if config.max_workers == 0 {
        return Err(ParseError::InvalidConfig {
            detail: "max_workers must be >= 1".to_string(),
        });
    }
    if config.chunk_budget_us == 0 {
        return Err(ParseError::InvalidConfig {
            detail: "chunk_budget_us must be >= 1".to_string(),
        });
    }

    // Check input size.
    if bytes.len() as u64 > config.lexer_config.max_source_bytes {
        return Err(ParseError::InputTooLarge {
            size: bytes.len() as u64,
            max: config.lexer_config.max_source_bytes,
        });
    }

    // Routing decision.
    let has_split_points = has_deterministic_split_points(bytes);
    let should_parallel = bytes.len() as u64 >= config.min_parallel_bytes
        && config.max_workers > 1
        && has_split_points;

    if !should_parallel {
        let reason = if config.max_workers <= 1 {
            SerialReason::SingleWorker
        } else if !has_split_points {
            SerialReason::NoDeterministicSplitPoints
        } else {
            SerialReason::InputBelowThreshold {
                input_bytes: bytes.len() as u64,
                threshold: config.min_parallel_bytes,
            }
        };
        return serial_parse(source, &config.lexer_config, Some(reason));
    }

    // --- Parallel path ---

    // 1. Compute chunk plan.
    let chunk_plan = compute_chunk_plan(bytes, config.max_workers);
    let timeout_policy = derive_timeout_policy(config, chunk_plan.chunks.len());
    let mut backpressure_snapshot = compute_backpressure_snapshot(&[], &timeout_policy);

    // 2. Build deterministic schedule transcript and self-validate replay invariants.
    let schedule_transcript = build_schedule_transcript(&chunk_plan, config.schedule_seed);
    let replay_order = match replay_schedule_transcript(&schedule_transcript, &chunk_plan) {
        Ok(order) => order,
        Err(err) => {
            let detail = err.to_string();
            let serial = serial_parse_inner(source, &config.lexer_config)?;
            let output_hash = compute_token_hash(&serial.tokens);
            let trigger = FailoverTrigger {
                class: FailoverTriggerClass::TranscriptDivergence,
                detail: detail.clone(),
            };
            let failover_decision = build_failover_decision(
                input,
                trigger,
                Some(&schedule_transcript),
                None,
                &output_hash,
            );
            return Ok(ParseOutput {
                schema_version: SCHEMA_VERSION.to_string(),
                mode: ParserMode::Serial,
                serial_reason: Some(SerialReason::TranscriptDivergence {
                    detail: detail.clone(),
                }),
                fallback_cause: Some(FallbackCause::TranscriptDivergence { detail }),
                tokens: serial.tokens,
                token_count: serial.token_count,
                bytes_scanned: serial.bytes_scanned,
                chunk_plan: Some(chunk_plan),
                merge_witness: None,
                schedule_transcript: Some(schedule_transcript),
                parity_result: None,
                failover_decision: Some(failover_decision),
                timeout_policy: Some(timeout_policy.clone()),
                cancellation: None,
                backpressure: Some(backpressure_snapshot.clone()),
                output_hash,
            });
        }
    };

    // 3. Lex each chunk independently using transcripted execution order.
    let mut chunk_results = Vec::new();
    let mut chunk_timings = Vec::new();
    let mut total_elapsed_us = 0u64;
    let mut lexer_config = config.lexer_config.clone();
    lexer_config.emit_tokens = true;

    for chunk_index in replay_order {
        let (start, end) = chunk_plan.chunks[chunk_index as usize];
        let chunk_bytes = &bytes[start as usize..end as usize];
        let chunk_str = std::str::from_utf8(chunk_bytes).map_err(|err| ParseError::LexerError {
            chunk_index,
            detail: format!("chunk split invalid UTF-8: {err}"),
        })?;
        match simd_lexer::lex(chunk_str, &lexer_config) {
            Ok(output) => {
                let elapsed_us = deterministic_chunk_elapsed_us(
                    end.saturating_sub(start),
                    output.token_count,
                    chunk_timings.len(),
                );
                total_elapsed_us = total_elapsed_us.saturating_add(elapsed_us);
                chunk_timings.push(ChunkTiming {
                    chunk_index,
                    chunk_bytes: end.saturating_sub(start),
                    token_count: output.token_count,
                    elapsed_us,
                });
                backpressure_snapshot =
                    compute_backpressure_snapshot(&chunk_timings, &timeout_policy);

                let chunk_budget_exceeded = elapsed_us > timeout_policy.max_chunk_us;
                let total_budget_exceeded = total_elapsed_us > timeout_policy.max_total_us;
                let critical_backpressure =
                    backpressure_snapshot.level == BackpressureLevel::Critical;

                if chunk_budget_exceeded || total_budget_exceeded || critical_backpressure {
                    let trigger = if critical_backpressure {
                        FailoverTrigger {
                            class: FailoverTriggerClass::ResourceLimit,
                            detail: format!(
                                "critical backpressure: peak_queue_depth={} delayed_chunks={} total_delay_us={}",
                                backpressure_snapshot.peak_queue_depth,
                                backpressure_snapshot.delayed_chunks,
                                backpressure_snapshot.total_delay_us
                            ),
                        }
                    } else if chunk_budget_exceeded {
                        FailoverTrigger {
                            class: FailoverTriggerClass::Timeout,
                            detail: format!(
                                "chunk {} elapsed {}us exceeded chunk budget {}us",
                                chunk_index, elapsed_us, timeout_policy.max_chunk_us
                            ),
                        }
                    } else {
                        FailoverTrigger {
                            class: FailoverTriggerClass::Timeout,
                            detail: format!(
                                "total elapsed {}us exceeded total budget {}us",
                                total_elapsed_us, timeout_policy.max_total_us
                            ),
                        }
                    };
                    let cancellation = if critical_backpressure {
                        None
                    } else {
                        Some(build_timeout_cancellation_record(
                            &timeout_policy,
                            total_elapsed_us,
                            if chunk_budget_exceeded {
                                Some(chunk_index)
                            } else {
                                None
                            },
                        ))
                    };
                    let budget_us = if chunk_budget_exceeded || critical_backpressure {
                        timeout_policy.max_chunk_us
                    } else {
                        timeout_policy.max_total_us
                    };
                    let reason = SerialReason::BudgetExhausted { budget_us };
                    let serial = serial_parse_inner(source, &config.lexer_config)?;
                    let output_hash = compute_token_hash(&serial.tokens);
                    let failover_decision = build_failover_decision(
                        input,
                        trigger,
                        Some(&schedule_transcript),
                        None,
                        &output_hash,
                    );
                    return Ok(ParseOutput {
                        schema_version: SCHEMA_VERSION.to_string(),
                        mode: ParserMode::Serial,
                        serial_reason: Some(reason.clone()),
                        fallback_cause: Some(FallbackCause::ResourceLimit(reason)),
                        tokens: serial.tokens,
                        token_count: serial.token_count,
                        bytes_scanned: serial.bytes_scanned,
                        chunk_plan: Some(chunk_plan),
                        merge_witness: None,
                        schedule_transcript: Some(schedule_transcript),
                        parity_result: None,
                        failover_decision: Some(failover_decision),
                        timeout_policy: Some(timeout_policy.clone()),
                        cancellation,
                        backpressure: Some(backpressure_snapshot.clone()),
                        output_hash,
                    });
                }

                chunk_results.push(ChunkResult {
                    chunk_index,
                    chunk_start: start,
                    chunk_end: end,
                    tokens: output.tokens,
                    token_count: output.token_count,
                });
            }
            Err(e) => {
                return Err(ParseError::LexerError {
                    chunk_index,
                    detail: format!("{e:?}"),
                });
            }
        }
    }

    // 4. Merge chunks.
    let mut merged_tokens = merge_chunks(&chunk_results);
    let pre_repair_count = merged_tokens.len() as u64;
    repair_boundary_tokens(&mut merged_tokens);
    let post_repair_count = merged_tokens.len() as u64;
    let boundary_repairs = pre_repair_count.saturating_sub(post_repair_count);
    let merged_hash = compute_token_hash(&merged_tokens);
    let witness_hash = compute_merge_witness_hash(
        &chunk_results,
        &merged_hash,
        boundary_repairs,
        merged_tokens.len() as u64,
    );
    let merge_witness = MergeWitness {
        merged_hash,
        witness_hash,
        chunk_count: chunk_plan.chunks.len() as u32,
        boundary_repairs,
        total_tokens: merged_tokens.len() as u64,
    };

    // Check merge buffer.
    let merge_buffer_size = merged_tokens.len() as u64 * 24; // approximate Token size
    if merge_buffer_size > config.merge_buffer_bytes {
        let reason = SerialReason::MergeBufferExceeded {
            buffer_bytes: merge_buffer_size,
            limit: config.merge_buffer_bytes,
        };
        let serial = serial_parse_inner(source, &config.lexer_config)?;
        let output_hash = compute_token_hash(&serial.tokens);
        let trigger = FailoverTrigger {
            class: FailoverTriggerClass::ResourceLimit,
            detail: reason.to_string(),
        };
        let failover_decision = build_failover_decision(
            input,
            trigger,
            Some(&schedule_transcript),
            Some(&merge_witness),
            &output_hash,
        );
        return Ok(ParseOutput {
            schema_version: SCHEMA_VERSION.to_string(),
            mode: ParserMode::Serial,
            serial_reason: Some(reason.clone()),
            fallback_cause: Some(FallbackCause::ResourceLimit(reason)),
            tokens: serial.tokens,
            token_count: serial.token_count,
            bytes_scanned: serial.bytes_scanned,
            chunk_plan: Some(chunk_plan),
            merge_witness: Some(merge_witness),
            schedule_transcript: Some(schedule_transcript),
            parity_result: None,
            failover_decision: Some(failover_decision),
            timeout_policy: Some(timeout_policy.clone()),
            cancellation: None,
            backpressure: Some(backpressure_snapshot.clone()),
            output_hash,
        });
    }

    // 5. Parity check against serial reference.
    let parity_result = if config.always_check_parity {
        let serial_output = serial_parse_inner(source, &config.lexer_config)?;
        let parity = check_parity(&merged_tokens, &serial_output.tokens);
        Some(parity)
    } else {
        None
    };

    // 6. Handle parity failure.
    if let Some(ref pr) = parity_result
        && !pr.parity_ok
    {
        let mismatch_index = pr.mismatch_index.unwrap_or(0);
        // Fall back to serial output.
        let serial = serial_parse_inner(source, &config.lexer_config)?;
        let output_hash = compute_token_hash(&serial.tokens);
        let trigger = FailoverTrigger {
            class: FailoverTriggerClass::ParityMismatch,
            detail: format!("mismatch_index={mismatch_index}"),
        };
        let failover_decision = build_failover_decision(
            input,
            trigger,
            Some(&schedule_transcript),
            Some(&merge_witness),
            &output_hash,
        );
        return Ok(ParseOutput {
            schema_version: SCHEMA_VERSION.to_string(),
            mode: ParserMode::Serial,
            serial_reason: Some(SerialReason::ParityMismatch { mismatch_index }),
            fallback_cause: Some(FallbackCause::ParityFailure { mismatch_index }),
            tokens: serial.tokens,
            token_count: serial.token_count,
            bytes_scanned: serial.bytes_scanned,
            chunk_plan: Some(chunk_plan),
            merge_witness: Some(merge_witness),
            schedule_transcript: Some(schedule_transcript),
            parity_result: Some(pr.clone()),
            failover_decision: Some(failover_decision),
            timeout_policy: Some(timeout_policy.clone()),
            cancellation: None,
            backpressure: Some(backpressure_snapshot.clone()),
            output_hash,
        });
    }

    // 7. Success — return parallel output.
    let output_hash = merged_hash;
    Ok(ParseOutput {
        schema_version: SCHEMA_VERSION.to_string(),
        mode: ParserMode::Parallel,
        serial_reason: None,
        fallback_cause: None,
        tokens: merged_tokens.clone(),
        token_count: merged_tokens.len() as u64,
        bytes_scanned: bytes.len() as u64,
        chunk_plan: Some(chunk_plan),
        merge_witness: Some(merge_witness),
        schedule_transcript: Some(schedule_transcript),
        parity_result,
        failover_decision: None,
        timeout_policy: Some(timeout_policy),
        cancellation: None,
        backpressure: Some(backpressure_snapshot),
        output_hash,
    })
}

/// Serial parse (direct single-threaded path).
fn serial_parse(
    source: &str,
    lexer_config: &LexerConfig,
    reason: Option<SerialReason>,
) -> Result<ParseOutput, ParseError> {
    let output = serial_parse_inner(source, lexer_config)?;
    let output_hash = compute_token_hash(&output.tokens);
    Ok(ParseOutput {
        schema_version: SCHEMA_VERSION.to_string(),
        mode: ParserMode::Serial,
        serial_reason: reason,
        fallback_cause: None,
        tokens: output.tokens,
        token_count: output.token_count,
        bytes_scanned: output.bytes_scanned,
        chunk_plan: None,
        merge_witness: None,
        schedule_transcript: None,
        parity_result: None,
        failover_decision: None,
        timeout_policy: None,
        cancellation: None,
        backpressure: None,
        output_hash,
    })
}

/// Inner serial parse returning raw lexer output.
fn serial_parse_inner(source: &str, lexer_config: &LexerConfig) -> Result<LexerOutput, ParseError> {
    let mut config = lexer_config.clone();
    config.emit_tokens = true;
    config.mode = LexerMode::Scalar;
    simd_lexer::lex(source, &config).map_err(|e| ParseError::LexerError {
        chunk_index: 0,
        detail: format!("{e:?}"),
    })
}

/// Compute a content hash over a token stream.
fn compute_token_hash(tokens: &[Token]) -> ContentHash {
    let mut parts = Vec::new();
    for token in tokens {
        parts.push(format!("{}:{}:{}", token.kind, token.start, token.end));
    }
    ContentHash::compute(parts.join("|").as_bytes())
}

/// Check parity between parallel-merged and serial token streams.
fn check_parity(parallel: &[Token], serial: &[Token]) -> ParityResult {
    let parallel_count = parallel.len() as u64;
    let serial_count = serial.len() as u64;

    let min_len = parallel.len().min(serial.len());
    for i in 0..min_len {
        if parallel[i] != serial[i] {
            return ParityResult {
                parity_ok: false,
                mismatch_index: Some(i as u64),
                parallel_count,
                serial_count,
            };
        }
    }

    if parallel_count != serial_count {
        return ParityResult {
            parity_ok: false,
            mismatch_index: Some(min_len as u64),
            parallel_count,
            serial_count,
        };
    }

    ParityResult {
        parity_ok: true,
        mismatch_index: None,
        parallel_count,
        serial_count,
    }
}

/// Compute a routing digest for the given input and configuration.
pub fn compute_routing_digest(source: &str, config: &ParallelConfig) -> RoutingDigest {
    let input_bytes = source.len() as u64;
    let has_partition_points = has_deterministic_split_points(source.as_bytes());
    let should_parallel =
        input_bytes >= config.min_parallel_bytes && config.max_workers > 1 && has_partition_points;

    let effective_workers = if should_parallel {
        config.max_workers.min(input_bytes as u32)
    } else {
        1
    };

    let decision = if should_parallel {
        ParserMode::Parallel
    } else {
        ParserMode::Serial
    };

    let rationale = if config.max_workers <= 1 {
        "single worker configured".to_string()
    } else if input_bytes < config.min_parallel_bytes {
        format!(
            "input {}B below threshold {}B",
            input_bytes, config.min_parallel_bytes
        )
    } else if !has_partition_points {
        "no deterministic split points".to_string()
    } else {
        format!("parallel with {} effective workers", effective_workers)
    };

    // Rough overhead estimate: parallel has ~20% overhead for small inputs.
    let estimated_overhead_millionths = if input_bytes < config.min_parallel_bytes * 2 {
        200_000 // 20%
    } else if input_bytes < config.min_parallel_bytes * 4 {
        100_000 // 10%
    } else {
        50_000 // 5%
    };

    RoutingDigest {
        input_bytes,
        parallel_threshold: config.min_parallel_bytes,
        configured_workers: config.max_workers,
        effective_workers,
        decision,
        rationale,
        has_partition_points,
        estimated_overhead_millionths,
    }
}

/// Generate structured log entries from a parse output.
pub fn generate_log_entries(trace_id: &str, output: &ParseOutput) -> Vec<ParseLogEntry> {
    let mut entries = Vec::new();
    let failover = output.failover_decision.as_ref();
    let cancellation_state = output.cancellation.as_ref().map(|c| c.state.to_string());
    let cancellation_elapsed_us = output.cancellation.as_ref().map(|c| c.elapsed_us);
    let backpressure_level = output.backpressure.as_ref().map(|b| b.level.to_string());
    let backpressure_peak_queue_depth = output.backpressure.as_ref().map(|b| b.peak_queue_depth);

    entries.push(ParseLogEntry {
        trace_id: trace_id.to_string(),
        component: COMPONENT.to_string(),
        event: "parse_complete".to_string(),
        outcome: if output.fallback_cause.is_some() {
            "fallback".to_string()
        } else {
            "ok".to_string()
        },
        parser_mode: Some(format!("{}", output.mode)),
        worker_count: output.chunk_plan.as_ref().map(|p| p.worker_count),
        input_bytes: Some(output.bytes_scanned),
        token_count: Some(output.token_count),
        fallback_reason: output.fallback_cause.as_ref().map(|c| format!("{c}")),
        failover_trigger: failover.map(|d| format!("{}: {}", d.trigger.class, d.trigger.detail)),
        failover_transition_path: failover.map(|d| {
            d.transition_path
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        }),
        failover_witness_ids: failover.map(|d| d.witness_ids.clone()),
        replay_command: failover.map(|d| d.replay_command.clone()),
        parity_result: output
            .parity_result
            .as_ref()
            .map(|p| if p.parity_ok { "ok" } else { "mismatch" }.to_string()),
        cancellation_state: cancellation_state.clone(),
        cancellation_elapsed_us,
        backpressure_level: backpressure_level.clone(),
        backpressure_peak_queue_depth,
        error_code: None,
    });

    if let Some(ref cause) = output.fallback_cause {
        entries.push(ParseLogEntry {
            trace_id: trace_id.to_string(),
            component: COMPONENT.to_string(),
            event: "fallback_triggered".to_string(),
            outcome: "fallback".to_string(),
            parser_mode: None,
            worker_count: None,
            input_bytes: None,
            token_count: None,
            fallback_reason: Some(format!("{cause}")),
            failover_trigger: failover
                .map(|d| format!("{}: {}", d.trigger.class, d.trigger.detail)),
            failover_transition_path: failover.map(|d| {
                d.transition_path
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            }),
            failover_witness_ids: failover.map(|d| d.witness_ids.clone()),
            replay_command: failover.map(|d| d.replay_command.clone()),
            parity_result: None,
            cancellation_state,
            cancellation_elapsed_us,
            backpressure_level,
            backpressure_peak_queue_depth,
            error_code: Some("fallback".to_string()),
        });
    }

    entries
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> ParallelConfig {
        ParallelConfig::default()
    }

    fn small_config() -> ParallelConfig {
        ParallelConfig {
            min_parallel_bytes: 10,
            max_workers: 4,
            always_check_parity: true,
            ..default_config()
        }
    }

    fn make_input<'a>(source: &'a str, config: &'a ParallelConfig) -> ParseInput<'a> {
        ParseInput {
            source,
            trace_id: "test-trace",
            run_id: "test-run",
            epoch: SecurityEpoch::from_raw(1),
            config,
        }
    }

    // --- Configuration tests ---

    #[test]
    fn default_config_reasonable() {
        let config = default_config();
        assert_eq!(config.min_parallel_bytes, DEFAULT_MIN_PARALLEL_BYTES);
        assert_eq!(config.max_workers, DEFAULT_MAX_WORKERS);
        assert!(config.always_check_parity);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = default_config();
        let json = serde_json::to_string(&config).unwrap();
        let back: ParallelConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // --- Routing tests ---

    #[test]
    fn small_input_routes_to_serial() {
        let config = default_config();
        let input = make_input("var x = 1;", &config);
        let output = parse(&input).unwrap();
        assert_eq!(output.mode, ParserMode::Serial);
        assert!(output.serial_reason.is_some());
    }

    #[test]
    fn no_split_points_route_to_serial() {
        let config = ParallelConfig {
            min_parallel_bytes: 1,
            max_workers: 8,
            ..default_config()
        };
        let input = make_input("identifier_without_any_delimiters", &config);
        let output = parse(&input).unwrap();
        assert_eq!(output.mode, ParserMode::Serial);
        assert!(matches!(
            output.serial_reason,
            Some(SerialReason::NoDeterministicSplitPoints)
        ));
    }

    #[test]
    fn single_worker_routes_to_serial() {
        let config = ParallelConfig {
            max_workers: 1,
            min_parallel_bytes: 0,
            ..default_config()
        };
        let input = make_input("var x = 1; var y = 2;", &config);
        let output = parse(&input).unwrap();
        assert_eq!(output.mode, ParserMode::Serial);
        assert!(matches!(
            output.serial_reason,
            Some(SerialReason::SingleWorker)
        ));
    }

    #[test]
    fn zero_workers_is_error() {
        let config = ParallelConfig {
            max_workers: 0,
            ..default_config()
        };
        let input = make_input("x", &config);
        assert!(matches!(
            parse(&input),
            Err(ParseError::InvalidConfig { .. })
        ));
    }

    // --- Chunk plan tests ---

    #[test]
    fn chunk_plan_empty_input() {
        let plan = compute_chunk_plan(b"", 4);
        assert!(plan.chunks.is_empty());
        assert_eq!(plan.worker_count, 1);
    }

    #[test]
    fn chunk_plan_single_worker() {
        let plan = compute_chunk_plan(b"hello world", 1);
        assert_eq!(plan.chunks.len(), 1);
        assert_eq!(plan.chunks[0], (0, 11));
    }

    #[test]
    fn chunk_plan_two_workers() {
        let input = b"line one\nline two\nline three\n";
        let plan = compute_chunk_plan(input, 2);
        assert_eq!(plan.chunks.len(), 2);
        // First chunk ends at a newline boundary.
        let (_, end) = plan.chunks[0];
        assert!(end > 0);
        assert_eq!(input[end as usize - 1], b'\n');
        // Second chunk starts where first ended.
        assert_eq!(plan.chunks[1].0, end);
        assert_eq!(plan.chunks[1].1, input.len() as u64);
    }

    #[test]
    fn chunk_plan_deterministic() {
        let input = b"a\nb\nc\nd\ne\nf\ng\n";
        let p1 = compute_chunk_plan(input, 3);
        let p2 = compute_chunk_plan(input, 3);
        assert_eq!(p1.plan_hash, p2.plan_hash);
        assert_eq!(p1.chunks, p2.chunks);
    }

    #[test]
    fn chunk_plan_covers_entire_input() {
        let input = b"line1\nline2\nline3\nline4\nline5\n";
        let plan = compute_chunk_plan(input, 3);
        assert_eq!(plan.chunks.first().unwrap().0, 0);
        assert_eq!(plan.chunks.last().unwrap().1, input.len() as u64);
        // Chunks are contiguous.
        for w in plan.chunks.windows(2) {
            assert_eq!(w[0].1, w[1].0);
        }
    }

    #[test]
    fn chunk_plan_no_newlines() {
        let input = b"abcdefghij"; // no newlines
        let plan = compute_chunk_plan(input, 2);
        // No deterministic split points => single deterministic chunk.
        assert_eq!(plan.chunks.len(), 1);
        assert_eq!(plan.chunks.last().unwrap().1, 10);
    }

    #[test]
    fn chunk_plan_prefers_low_depth_boundaries() {
        let source =
            b"function outer() {\n  if (x) {\n    return y;\n  }\n}\nconst z = 1;\nconst q = 2;\n";
        let plan = compute_chunk_plan(source, 2);
        assert_eq!(plan.chunks.len(), 2);

        let split = plan.chunks[0].1 as usize;
        let first_chunk = std::str::from_utf8(&source[..split]).unwrap();
        assert!(
            first_chunk.contains("}\n"),
            "expected split to occur on/after a block boundary, got: {first_chunk:?}"
        );
    }

    #[test]
    fn chunk_plan_boundaries_are_safe_split_points() {
        let source = b"const s = \"a;b;c\";\n// comment ;;;\nconst x = 1;\nconst y = 2;\n";
        let plan = compute_chunk_plan(source, 3);
        let boundaries = collect_partition_boundaries(source);
        let boundary_set: BTreeSet<u64> = boundaries.iter().map(|boundary| boundary.end).collect();
        for &(_, end) in plan.chunks.iter().take(plan.chunks.len().saturating_sub(1)) {
            assert!(
                boundary_set.contains(&end),
                "chunk boundary {end} was not a validated safe split point"
            );
        }
    }

    // --- Merge tests ---

    #[test]
    fn merge_empty_chunks() {
        let merged = merge_chunks(&[]);
        assert!(merged.is_empty());
    }

    #[test]
    fn merge_single_chunk() {
        let tokens = vec![Token {
            kind: simd_lexer::TokenKind::Identifier,
            start: 0,
            end: 3,
        }];
        let chunk = ChunkResult {
            chunk_index: 0,
            chunk_start: 10,
            chunk_end: 20,
            tokens,
            token_count: 1,
        };
        let merged = merge_chunks(&[chunk]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].start, 10); // offset adjusted
        assert_eq!(merged[0].end, 13);
    }

    #[test]
    fn merge_preserves_order() {
        let chunk1 = ChunkResult {
            chunk_index: 0,
            chunk_start: 0,
            chunk_end: 10,
            tokens: vec![Token {
                kind: simd_lexer::TokenKind::Identifier,
                start: 0,
                end: 3,
            }],
            token_count: 1,
        };
        let chunk2 = ChunkResult {
            chunk_index: 1,
            chunk_start: 10,
            chunk_end: 20,
            tokens: vec![Token {
                kind: simd_lexer::TokenKind::NumericLiteral,
                start: 2,
                end: 5,
            }],
            token_count: 1,
        };
        let merged = merge_chunks(&[chunk1, chunk2]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].start, 0); // from chunk1
        assert_eq!(merged[1].start, 12); // from chunk2 (10 + 2)
    }

    #[test]
    fn merge_is_source_order_deterministic_across_chunk_iteration_order() {
        let chunk0 = ChunkResult {
            chunk_index: 0,
            chunk_start: 0,
            chunk_end: 10,
            tokens: vec![
                Token {
                    kind: simd_lexer::TokenKind::Identifier,
                    start: 0,
                    end: 1,
                },
                Token {
                    kind: simd_lexer::TokenKind::Punctuation,
                    start: 1,
                    end: 2,
                },
            ],
            token_count: 2,
        };
        let chunk1 = ChunkResult {
            chunk_index: 1,
            chunk_start: 10,
            chunk_end: 20,
            tokens: vec![
                Token {
                    kind: simd_lexer::TokenKind::Identifier,
                    start: 0,
                    end: 1,
                },
                Token {
                    kind: simd_lexer::TokenKind::Punctuation,
                    start: 1,
                    end: 2,
                },
            ],
            token_count: 2,
        };

        let ordered = merge_chunks(&[chunk0.clone(), chunk1.clone()]);
        let reversed = merge_chunks(&[chunk1, chunk0]);
        assert_eq!(ordered, reversed);
    }

    // --- Boundary repair tests ---

    #[test]
    fn repair_no_overlaps() {
        let mut tokens = vec![
            Token {
                kind: simd_lexer::TokenKind::Identifier,
                start: 0,
                end: 3,
            },
            Token {
                kind: simd_lexer::TokenKind::Punctuation,
                start: 4,
                end: 5,
            },
        ];
        repair_boundary_tokens(&mut tokens);
        assert_eq!(tokens.len(), 2);
    }

    #[test]
    fn repair_merges_overlapping_same_kind() {
        let mut tokens = vec![
            Token {
                kind: simd_lexer::TokenKind::Identifier,
                start: 0,
                end: 5,
            },
            Token {
                kind: simd_lexer::TokenKind::Identifier,
                start: 3,
                end: 8,
            },
        ];
        repair_boundary_tokens(&mut tokens);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].start, 0);
        assert_eq!(tokens[0].end, 8);
    }

    #[test]
    fn repair_does_not_merge_different_kinds() {
        let mut tokens = vec![
            Token {
                kind: simd_lexer::TokenKind::Identifier,
                start: 0,
                end: 5,
            },
            Token {
                kind: simd_lexer::TokenKind::Punctuation,
                start: 3,
                end: 8,
            },
        ];
        repair_boundary_tokens(&mut tokens);
        assert_eq!(tokens.len(), 2);
    }

    #[test]
    fn repair_empty_tokens() {
        let mut tokens: Vec<Token> = vec![];
        repair_boundary_tokens(&mut tokens);
        assert!(tokens.is_empty());
    }

    #[test]
    fn repair_single_token() {
        let mut tokens = vec![Token {
            kind: simd_lexer::TokenKind::Identifier,
            start: 0,
            end: 5,
        }];
        repair_boundary_tokens(&mut tokens);
        assert_eq!(tokens.len(), 1);
    }

    // --- Parity check tests ---

    #[test]
    fn parity_check_identical() {
        let tokens = vec![Token {
            kind: simd_lexer::TokenKind::Identifier,
            start: 0,
            end: 3,
        }];
        let result = check_parity(&tokens, &tokens);
        assert!(result.parity_ok);
        assert_eq!(result.mismatch_index, None);
    }

    #[test]
    fn parity_check_different_count() {
        let parallel = vec![Token {
            kind: simd_lexer::TokenKind::Identifier,
            start: 0,
            end: 3,
        }];
        let serial = vec![];
        let result = check_parity(&parallel, &serial);
        assert!(!result.parity_ok);
        assert_eq!(result.mismatch_index, Some(0));
    }

    #[test]
    fn parity_check_different_kind() {
        let parallel = vec![Token {
            kind: simd_lexer::TokenKind::Identifier,
            start: 0,
            end: 3,
        }];
        let serial = vec![Token {
            kind: simd_lexer::TokenKind::NumericLiteral,
            start: 0,
            end: 3,
        }];
        let result = check_parity(&parallel, &serial);
        assert!(!result.parity_ok);
        assert_eq!(result.mismatch_index, Some(0));
    }

    // --- Full parallel parse tests ---

    #[test]
    fn parallel_parse_large_input_with_newlines() {
        let mut source = String::new();
        for i in 0..100 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let config = small_config();
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        // Should attempt parallel and succeed (or fall back).
        assert!(output.token_count > 0);
        assert!(output.chunk_plan.is_some());
    }

    #[test]
    fn parallel_parse_deterministic() {
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let config = small_config();
        let input = make_input(&source, &config);
        let o1 = parse(&input).unwrap();
        let o2 = parse(&input).unwrap();
        assert_eq!(o1.output_hash, o2.output_hash);
        assert_eq!(o1.token_count, o2.token_count);
    }

    #[test]
    fn parallel_parse_serial_fallback_small_input() {
        let config = default_config(); // default 4096 threshold
        let input = make_input("x + y", &config);
        let output = parse(&input).unwrap();
        assert_eq!(output.mode, ParserMode::Serial);
        assert!(output.chunk_plan.is_none());
    }

    #[test]
    fn parallel_parse_tokens_match_serial() {
        let mut source = String::new();
        for i in 0..100 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let config = small_config();
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();

        // Also parse serially.
        let serial_config = ParallelConfig {
            max_workers: 1,
            min_parallel_bytes: 0,
            ..small_config()
        };
        let serial_input = make_input(&source, &serial_config);
        let serial_output = parse(&serial_input).unwrap();

        // Token counts should match.
        assert_eq!(output.token_count, serial_output.token_count);
    }

    #[test]
    fn parallel_parse_with_operators() {
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("x{} == y{} && z{} != w{}\n", i, i, i, i));
        }
        let config = small_config();
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        assert!(output.token_count > 0);
    }

    #[test]
    fn parallel_parse_with_strings() {
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("var s{} = \"hello{}\";\n", i, i));
        }
        let config = small_config();
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        assert!(output.token_count > 0);
    }

    // --- Schedule transcript tests ---

    #[test]
    fn schedule_transcript_serde_roundtrip() {
        let execution_order = vec![0, 1, 2, 3];
        let dispatches = vec![
            ScheduleDispatch {
                step_index: 0,
                chunk_index: 0,
                worker_slot: 0,
            },
            ScheduleDispatch {
                step_index: 1,
                chunk_index: 1,
                worker_slot: 1,
            },
            ScheduleDispatch {
                step_index: 2,
                chunk_index: 2,
                worker_slot: 2,
            },
            ScheduleDispatch {
                step_index: 3,
                chunk_index: 3,
                worker_slot: 3,
            },
        ];
        let plan_hash = ContentHash::compute(b"test");
        let transcript = ScheduleTranscript {
            seed: 42,
            worker_count: 4,
            plan_hash,
            execution_order: execution_order.clone(),
            dispatches: dispatches.clone(),
            transcript_hash: compute_schedule_transcript_hash(
                42,
                4,
                &plan_hash,
                &execution_order,
                &dispatches,
            ),
        };
        let json = serde_json::to_string(&transcript).unwrap();
        let back: ScheduleTranscript = serde_json::from_str(&json).unwrap();
        assert_eq!(transcript, back);
    }

    #[test]
    fn schedule_transcript_build_and_replay_roundtrip() {
        let source = "a=1;\nb=2;\nc=3;\nd=4;\ne=5;\nf=6;\n";
        let chunk_plan = compute_chunk_plan(source.as_bytes(), 4);
        let transcript = build_schedule_transcript(&chunk_plan, 1234);
        let replay_order = replay_schedule_transcript(&transcript, &chunk_plan).unwrap();
        assert_eq!(replay_order, transcript.execution_order);
        assert_eq!(replay_order.len(), chunk_plan.chunks.len());
    }

    #[test]
    fn schedule_transcript_deterministic_same_seed_same_plan() {
        let source = "a=1;\nb=2;\nc=3;\nd=4;\ne=5;\nf=6;\ng=7;\nh=8;\n";
        let chunk_plan = compute_chunk_plan(source.as_bytes(), 4);
        let t1 = build_schedule_transcript(&chunk_plan, 2026);
        let t2 = build_schedule_transcript(&chunk_plan, 2026);
        assert_eq!(t1, t2);
    }

    #[test]
    fn schedule_transcript_seed_changes_execution_order() {
        let source = "a=1;\nb=2;\nc=3;\nd=4;\ne=5;\nf=6;\ng=7;\nh=8;\ni=9;\nj=10;\nk=11;\nl=12;\n";
        let chunk_plan = compute_chunk_plan(source.as_bytes(), 8);
        let t1 = build_schedule_transcript(&chunk_plan, 11);
        let t2 = build_schedule_transcript(&chunk_plan, 29);
        assert_ne!(t1.execution_order, t2.execution_order);
    }

    #[test]
    fn schedule_transcript_replay_rejects_plan_hash_mismatch() {
        let source = "a=1;\nb=2;\nc=3;\nd=4;\n";
        let chunk_plan = compute_chunk_plan(source.as_bytes(), 4);
        let transcript = build_schedule_transcript(&chunk_plan, 0);
        let mut wrong_plan = chunk_plan.clone();
        wrong_plan.plan_hash = ContentHash::compute(b"different-plan");
        let err = replay_schedule_transcript(&transcript, &wrong_plan).unwrap_err();
        assert!(matches!(
            err,
            TranscriptReplayError::PlanHashMismatch { .. }
        ));
    }

    #[test]
    fn schedule_transcript_replay_rejects_hash_tamper() {
        let source = "a=1;\nb=2;\nc=3;\nd=4;\n";
        let chunk_plan = compute_chunk_plan(source.as_bytes(), 4);
        let mut transcript = build_schedule_transcript(&chunk_plan, 7);
        transcript.transcript_hash = ContentHash::compute(b"tampered");
        let err = replay_schedule_transcript(&transcript, &chunk_plan).unwrap_err();
        assert!(matches!(
            err,
            TranscriptReplayError::TranscriptHashMismatch { .. }
        ));
    }

    // --- Merge witness tests ---

    #[test]
    fn merge_witness_serde_roundtrip() {
        let witness = MergeWitness {
            merged_hash: ContentHash::compute(b"test"),
            witness_hash: ContentHash::compute(b"merge-witness-test"),
            chunk_count: 3,
            boundary_repairs: 1,
            total_tokens: 42,
        };
        let json = serde_json::to_string(&witness).unwrap();
        let back: MergeWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(witness, back);
    }

    #[test]
    fn merge_witness_hash_deterministic_for_fixed_input() {
        let mut source = String::new();
        for i in 0..80 {
            source.push_str(&format!("const x{i} = {i};\n"));
        }
        let config = small_config();
        let input = make_input(&source, &config);
        let o1 = parse(&input).unwrap();
        let o2 = parse(&input).unwrap();

        if let (Some(w1), Some(w2)) = (&o1.merge_witness, &o2.merge_witness) {
            assert_eq!(w1.witness_hash, w2.witness_hash);
            assert_eq!(w1.merged_hash, w2.merged_hash);
        }
    }

    // --- Parity result tests ---

    #[test]
    fn parity_result_serde_roundtrip() {
        let result = ParityResult {
            parity_ok: true,
            mismatch_index: None,
            parallel_count: 100,
            serial_count: 100,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ParityResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // --- ParseOutput tests ---

    #[test]
    fn parse_output_serde_roundtrip() {
        let config = small_config();
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        let json = serde_json::to_string(&output).unwrap();
        let back: ParseOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(output, back);
    }

    // --- Log entry tests ---

    #[test]
    fn log_entries_for_serial() {
        let config = default_config();
        let input = make_input("x + y", &config);
        let output = parse(&input).unwrap();
        let entries = generate_log_entries("trace-1", &output);
        assert!(!entries.is_empty());
        assert!(entries.iter().any(|e| e.event == "parse_complete"));
        assert!(entries[0].parser_mode.as_deref() == Some("serial"));
    }

    #[test]
    fn log_entries_for_parallel() {
        let mut source = String::new();
        for i in 0..100 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let config = small_config();
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        let entries = generate_log_entries("trace-1", &output);
        assert!(!entries.is_empty());
    }

    #[test]
    fn log_entries_trace_id_consistent() {
        let config = default_config();
        let input = make_input("x + y", &config);
        let output = parse(&input).unwrap();
        let entries = generate_log_entries("trace-42", &output);
        assert!(entries.iter().all(|e| e.trace_id == "trace-42"));
    }

    // --- Display tests ---

    #[test]
    fn parser_mode_display() {
        assert_eq!(ParserMode::Serial.to_string(), "serial");
        assert_eq!(ParserMode::Parallel.to_string(), "parallel");
    }

    #[test]
    fn serial_reason_display() {
        let reason = SerialReason::InputBelowThreshold {
            input_bytes: 100,
            threshold: 4096,
        };
        assert!(reason.to_string().contains("100B below threshold 4096B"));
    }

    #[test]
    fn fallback_cause_display() {
        let cause = FallbackCause::ParityFailure { mismatch_index: 42 };
        assert!(cause.to_string().contains("parity failure"));
    }

    #[test]
    fn parse_error_display() {
        let e = ParseError::LexerError {
            chunk_index: 2,
            detail: "bad".to_string(),
        };
        assert!(e.to_string().contains("chunk 2"));
    }

    // --- Error tests ---

    #[test]
    fn error_serde_roundtrip() {
        let e = ParseError::InputTooLarge {
            size: 1000,
            max: 500,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: ParseError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- Schema version ---

    #[test]
    fn schema_version_in_output() {
        let config = default_config();
        let input = make_input("x", &config);
        let output = parse(&input).unwrap();
        assert_eq!(output.schema_version, SCHEMA_VERSION);
    }

    // --- Chunk plan hash ---

    #[test]
    fn chunk_plan_hash_differs_for_different_plans() {
        let input1 = b"a\nbcdefghijk\n";
        let input2 = b"abcdefghij\nk\n";
        let p1 = compute_chunk_plan(input1, 2);
        let p2 = compute_chunk_plan(input2, 2);
        // Different split-point layouts produce different chunk boundaries.
        assert_ne!(p1.chunks, p2.chunks);
        assert_ne!(p1.plan_hash, p2.plan_hash);
    }

    // --- Worker count invariance ---

    #[test]
    fn different_worker_counts_same_tokens() {
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let config2 = ParallelConfig {
            max_workers: 2,
            min_parallel_bytes: 10,
            always_check_parity: true,
            ..default_config()
        };
        let config4 = ParallelConfig {
            max_workers: 4,
            min_parallel_bytes: 10,
            always_check_parity: true,
            ..default_config()
        };
        let input2 = make_input(&source, &config2);
        let input4 = make_input(&source, &config4);
        let o2 = parse(&input2).unwrap();
        let o4 = parse(&input4).unwrap();
        assert_eq!(o2.token_count, o4.token_count);
    }

    // ===================================================================
    // Enrichment tests (bd-1vfi structured concurrency extensions)
    // ===================================================================

    #[test]
    fn timeout_policy_default() {
        let tp = TimeoutPolicy::default();
        assert_eq!(tp.max_total_us, 500_000);
        assert_eq!(tp.max_chunk_us, 100_000);
        assert!(tp.allow_drain);
    }

    #[test]
    fn timeout_policy_serde_roundtrip() {
        let tp = TimeoutPolicy {
            max_total_us: 1_000_000,
            max_chunk_us: 200_000,
            allow_drain: false,
        };
        let json = serde_json::to_string(&tp).unwrap();
        let back: TimeoutPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(tp, back);
    }

    #[test]
    fn cancellation_state_ordering() {
        assert!(CancellationState::None < CancellationState::Requested);
        assert!(CancellationState::Requested < CancellationState::Draining);
        assert!(CancellationState::Draining < CancellationState::Finalized);
    }

    #[test]
    fn cancellation_state_display() {
        assert_eq!(CancellationState::None.to_string(), "none");
        assert_eq!(CancellationState::Requested.to_string(), "requested");
        assert_eq!(CancellationState::Draining.to_string(), "draining");
        assert_eq!(CancellationState::Finalized.to_string(), "finalized");
    }

    #[test]
    fn cancellation_record_serde_roundtrip() {
        let cr = CancellationRecord {
            state: CancellationState::Finalized,
            elapsed_us: 42_000,
            trigger_chunk: Some(2),
            drain_completed: true,
        };
        let json = serde_json::to_string(&cr).unwrap();
        let back: CancellationRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(cr, back);
    }

    #[test]
    fn cancellation_record_no_trigger_chunk() {
        let cr = CancellationRecord {
            state: CancellationState::Requested,
            elapsed_us: 500_000,
            trigger_chunk: None,
            drain_completed: false,
        };
        let json = serde_json::to_string(&cr).unwrap();
        assert!(json.contains("\"trigger_chunk\":null"));
        let back: CancellationRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(cr, back);
    }

    #[test]
    fn backpressure_level_ordering() {
        assert!(BackpressureLevel::Normal < BackpressureLevel::Elevated);
        assert!(BackpressureLevel::Elevated < BackpressureLevel::Critical);
    }

    #[test]
    fn backpressure_level_display() {
        assert_eq!(BackpressureLevel::Normal.to_string(), "normal");
        assert_eq!(BackpressureLevel::Elevated.to_string(), "elevated");
        assert_eq!(BackpressureLevel::Critical.to_string(), "critical");
    }

    #[test]
    fn backpressure_snapshot_serde_roundtrip() {
        let bp = BackpressureSnapshot {
            queue_depth: 3,
            peak_queue_depth: 5,
            level: BackpressureLevel::Elevated,
            delayed_chunks: 2,
            total_delay_us: 15_000,
        };
        let json = serde_json::to_string(&bp).unwrap();
        let back: BackpressureSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(bp, back);
    }

    #[test]
    fn backpressure_snapshot_zero_delay() {
        let bp = BackpressureSnapshot {
            queue_depth: 0,
            peak_queue_depth: 0,
            level: BackpressureLevel::Normal,
            delayed_chunks: 0,
            total_delay_us: 0,
        };
        assert_eq!(bp.total_delay_us, 0);
        assert_eq!(bp.level, BackpressureLevel::Normal);
    }

    #[test]
    fn parse_timeout_budget_exhaustion_records_cancellation() {
        let config = ParallelConfig {
            min_parallel_bytes: 10,
            max_workers: 2,
            chunk_budget_us: 1_500,
            always_check_parity: true,
            ..default_config()
        };
        let mut source = String::new();
        for i in 0..120 {
            source.push_str(&format!("var timeout_{i} = {i};\n"));
        }
        let input = make_input(&source, &config);
        let output = parse(&input).expect("parse should complete with deterministic fallback");
        assert_eq!(output.mode, ParserMode::Serial);
        assert!(matches!(
            output.serial_reason.as_ref(),
            Some(SerialReason::BudgetExhausted { budget_us }) if *budget_us == 1_500
        ));
        let failover = output
            .failover_decision
            .as_ref()
            .expect("timeout fallback should emit failover decision");
        assert_eq!(failover.trigger.class, FailoverTriggerClass::Timeout);
        let cancellation = output
            .cancellation
            .as_ref()
            .expect("timeout fallback should emit cancellation");
        assert_eq!(cancellation.state, CancellationState::Finalized);
        assert!(cancellation.drain_completed);
        assert!(cancellation.trigger_chunk.is_some());
        let backpressure = output
            .backpressure
            .as_ref()
            .expect("backpressure should be captured");
        assert_eq!(backpressure.level, BackpressureLevel::Elevated);
    }

    #[test]
    fn parse_critical_backpressure_triggers_resource_limit_failover() {
        let config = ParallelConfig {
            min_parallel_bytes: 10,
            max_workers: 2,
            chunk_budget_us: 200,
            always_check_parity: true,
            ..default_config()
        };
        let mut source = String::new();
        for i in 0..140 {
            source.push_str(&format!("var backlog_{i} = {i};\n"));
        }
        let input = make_input(&source, &config);
        let output = parse(&input).expect("parse should complete with deterministic fallback");
        assert_eq!(output.mode, ParserMode::Serial);
        assert!(matches!(
            output.serial_reason.as_ref(),
            Some(SerialReason::BudgetExhausted { budget_us }) if *budget_us == 200
        ));
        let failover = output
            .failover_decision
            .as_ref()
            .expect("resource-limit fallback should emit failover decision");
        assert_eq!(failover.trigger.class, FailoverTriggerClass::ResourceLimit);
        let backpressure = output
            .backpressure
            .as_ref()
            .expect("backpressure should be captured");
        assert_eq!(backpressure.level, BackpressureLevel::Critical);
        assert!(output.cancellation.is_none());
    }

    #[test]
    fn routing_digest_serial_small_input() {
        let config = default_config();
        let digest = compute_routing_digest("x = 1", &config);
        assert_eq!(digest.decision, ParserMode::Serial);
        assert_eq!(digest.effective_workers, 1);
        assert!(digest.rationale.contains("below threshold"));
    }

    #[test]
    fn routing_digest_serial_single_worker() {
        let config = ParallelConfig {
            max_workers: 1,
            ..default_config()
        };
        let digest = compute_routing_digest("x = 1\ny = 2\n", &config);
        assert_eq!(digest.decision, ParserMode::Serial);
        assert!(digest.rationale.contains("single worker"));
    }

    #[test]
    fn routing_digest_parallel_large_input() {
        let config = small_config();
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let digest = compute_routing_digest(&source, &config);
        assert_eq!(digest.decision, ParserMode::Parallel);
        assert!(digest.effective_workers > 1);
        assert!(digest.has_partition_points);
    }

    #[test]
    fn routing_digest_serial_no_newlines() {
        let config = ParallelConfig {
            min_parallel_bytes: 5,
            max_workers: 4,
            ..default_config()
        };
        let digest = compute_routing_digest("abcdefghijklmnop", &config);
        assert_eq!(digest.decision, ParserMode::Serial);
        assert!(!digest.has_partition_points);
        assert!(digest.rationale.contains("no deterministic split points"));
    }

    #[test]
    fn routing_digest_serde_roundtrip() {
        let config = small_config();
        let digest = compute_routing_digest("x\ny\nz\n", &config);
        let json = serde_json::to_string(&digest).unwrap();
        let back: RoutingDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(digest, back);
    }

    #[test]
    fn routing_digest_overhead_decreases_with_size() {
        let config = ParallelConfig {
            min_parallel_bytes: 10,
            max_workers: 4,
            ..default_config()
        };
        let small_src = "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\n";
        let d_small = compute_routing_digest(small_src, &config);

        let mut large_src = String::new();
        for i in 0..200 {
            large_src.push_str(&format!("var longVariableName{} = {};\n", i, i));
        }
        let d_large = compute_routing_digest(&large_src, &config);

        assert!(d_small.estimated_overhead_millionths >= d_large.estimated_overhead_millionths);
    }

    #[test]
    fn throughput_sample_zero_elapsed() {
        let sample = ThroughputSample::compute(1000, 50, 0);
        assert_eq!(sample.bytes_per_sec_millionths, 0);
        assert_eq!(sample.tokens_per_sec_millionths, 0);
    }

    #[test]
    fn throughput_sample_normal() {
        let sample = ThroughputSample::compute(1000, 50, 1000);
        assert!(sample.bytes_per_sec_millionths > 0);
        assert!(sample.tokens_per_sec_millionths > 0);
    }

    #[test]
    fn throughput_sample_serde_roundtrip() {
        let sample = ThroughputSample::compute(500, 25, 2000);
        let json = serde_json::to_string(&sample).unwrap();
        let back: ThroughputSample = serde_json::from_str(&json).unwrap();
        assert_eq!(sample, back);
    }

    #[test]
    fn throughput_sample_proportional() {
        let s1 = ThroughputSample::compute(1000, 50, 1000);
        let s2 = ThroughputSample::compute(2000, 100, 1000);
        assert!(s2.bytes_per_sec_millionths > s1.bytes_per_sec_millionths);
    }

    #[test]
    fn chunk_timing_serde_roundtrip() {
        let ct = ChunkTiming {
            chunk_index: 2,
            chunk_bytes: 1024,
            token_count: 50,
            elapsed_us: 3500,
        };
        let json = serde_json::to_string(&ct).unwrap();
        let back: ChunkTiming = serde_json::from_str(&json).unwrap();
        assert_eq!(ct, back);
    }

    #[test]
    fn performance_report_serde_roundtrip() {
        let report = PerformanceReport {
            throughput: ThroughputSample::compute(1000, 50, 2000),
            chunk_timings: vec![
                ChunkTiming {
                    chunk_index: 0,
                    chunk_bytes: 500,
                    token_count: 25,
                    elapsed_us: 1000,
                },
                ChunkTiming {
                    chunk_index: 1,
                    chunk_bytes: 500,
                    token_count: 25,
                    elapsed_us: 1000,
                },
            ],
            merge_elapsed_us: 200,
            parity_check_elapsed_us: 300,
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: PerformanceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn replay_envelope_from_serial_parse() {
        let config = default_config();
        let input = make_input("x + y", &config);
        let output = parse(&input).unwrap();
        let digest = compute_routing_digest(input.source, &config);
        let envelope = build_replay_envelope(&input, &output, &digest);
        assert_eq!(envelope.schema_version, SCHEMA_VERSION);
        assert_eq!(envelope.input_bytes, 5);
        assert!(envelope.replay_command.contains("--trace-id"));
        assert!(envelope.replay_command.contains("--workers"));
    }

    #[test]
    fn replay_envelope_from_parallel_parse() {
        let config = small_config();
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        let digest = compute_routing_digest(input.source, &config);
        let envelope = build_replay_envelope(&input, &output, &digest);
        assert!(envelope.input_bytes > 100);
        assert_eq!(envelope.output_hash, output.output_hash);
    }

    #[test]
    fn replay_envelope_serde_roundtrip() {
        let config = default_config();
        let input = make_input("x", &config);
        let output = parse(&input).unwrap();
        let digest = compute_routing_digest(input.source, &config);
        let envelope = build_replay_envelope(&input, &output, &digest);
        let json = serde_json::to_string(&envelope).unwrap();
        let back: ReplayEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope, back);
    }

    #[test]
    fn replay_envelope_deterministic() {
        let config = default_config();
        let input = make_input("var a = 1;", &config);
        let output = parse(&input).unwrap();
        let digest = compute_routing_digest(input.source, &config);
        let e1 = build_replay_envelope(&input, &output, &digest);
        let e2 = build_replay_envelope(&input, &output, &digest);
        assert_eq!(e1.input_hash, e2.input_hash);
        assert_eq!(e1.output_hash, e2.output_hash);
    }

    #[test]
    fn rollback_default_not_disabled() {
        let rc = RollbackControl::default();
        assert!(!rc.parallel_disabled);
        assert_eq!(rc.consecutive_failures, 0);
        assert_eq!(rc.auto_rollback_threshold, 3);
    }

    #[test]
    fn rollback_record_failure_below_threshold() {
        let mut rc = RollbackControl::default();
        let triggered = rc.record_failure("trace-1");
        assert!(!triggered);
        assert_eq!(rc.consecutive_failures, 1);
        assert!(!rc.parallel_disabled);
    }

    #[test]
    fn rollback_auto_trigger_at_threshold() {
        let mut rc = RollbackControl::default();
        rc.record_failure("trace-1");
        rc.record_failure("trace-2");
        let triggered = rc.record_failure("trace-3");
        assert!(triggered);
        assert!(rc.parallel_disabled);
        assert!(
            rc.disable_reason
                .as_ref()
                .unwrap()
                .contains("3 consecutive")
        );
        assert_eq!(rc.failure_trace_ids.len(), 3);
    }

    #[test]
    fn rollback_success_resets_counter() {
        let mut rc = RollbackControl::default();
        rc.record_failure("trace-1");
        rc.record_failure("trace-2");
        rc.record_success();
        assert_eq!(rc.consecutive_failures, 0);
        assert!(!rc.parallel_disabled);
    }

    #[test]
    fn rollback_force_disable() {
        let mut rc = RollbackControl::default();
        rc.force_disable("manual intervention");
        assert!(rc.parallel_disabled);
        assert_eq!(rc.disable_reason.as_deref(), Some("manual intervention"));
    }

    #[test]
    fn rollback_re_enable_clears_state() {
        let mut rc = RollbackControl::default();
        rc.record_failure("t1");
        rc.record_failure("t2");
        rc.record_failure("t3");
        assert!(rc.parallel_disabled);
        rc.re_enable();
        assert!(!rc.parallel_disabled);
        assert!(rc.disable_reason.is_none());
        assert_eq!(rc.consecutive_failures, 0);
        assert!(rc.failure_trace_ids.is_empty());
    }

    #[test]
    fn rollback_serde_roundtrip() {
        let mut rc = RollbackControl::default();
        rc.record_failure("trace-1");
        let json = serde_json::to_string(&rc).unwrap();
        let back: RollbackControl = serde_json::from_str(&json).unwrap();
        assert_eq!(rc, back);
    }

    #[test]
    fn rollback_custom_threshold() {
        let mut rc = RollbackControl {
            auto_rollback_threshold: 5,
            ..Default::default()
        };
        for i in 0..4 {
            let triggered = rc.record_failure(&format!("t{}", i));
            assert!(!triggered);
        }
        let triggered = rc.record_failure("t4");
        assert!(triggered);
        assert!(rc.parallel_disabled);
    }

    #[test]
    fn full_pipeline_serial_small() {
        let config = default_config();
        let source = "x = 1;";
        let digest = compute_routing_digest(source, &config);
        assert_eq!(digest.decision, ParserMode::Serial);

        let input = make_input(source, &config);
        let output = parse(&input).unwrap();
        assert_eq!(output.mode, ParserMode::Serial);

        let envelope = build_replay_envelope(&input, &output, &digest);
        assert_eq!(envelope.input_bytes, source.len() as u64);
    }

    #[test]
    fn full_pipeline_parallel_large() {
        let config = small_config();
        let mut source = String::new();
        for i in 0..100 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let digest = compute_routing_digest(&source, &config);
        assert_eq!(digest.decision, ParserMode::Parallel);

        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        assert!(output.token_count > 0);

        let envelope = build_replay_envelope(&input, &output, &digest);
        assert_eq!(envelope.output_hash, output.output_hash);
        assert!(envelope.replay_command.contains("--workers 4"));
    }

    #[test]
    fn rollback_integration_with_parse() {
        let mut rc = RollbackControl::default();
        let config = small_config();
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }

        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        assert!(output.token_count > 0);
        rc.record_success();
        assert!(!rc.parallel_disabled);

        for i in 0..3 {
            rc.record_failure(&format!("fail-{i}"));
        }
        assert!(rc.parallel_disabled);
    }

    #[test]
    fn parallel_determinism_across_seeds() {
        let mut source = String::new();
        for i in 0..100 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let config1 = ParallelConfig {
            schedule_seed: 42,
            ..small_config()
        };
        let config2 = ParallelConfig {
            schedule_seed: 99,
            ..small_config()
        };
        let i1 = make_input(&source, &config1);
        let i2 = make_input(&source, &config2);
        let o1 = parse(&i1).unwrap();
        let o2 = parse(&i2).unwrap();
        assert_eq!(o1.token_count, o2.token_count);
    }

    #[test]
    fn parallel_parse_eight_workers() {
        let mut source = String::new();
        for i in 0..200 {
            source.push_str(&format!("let value{} = compute({});\n", i, i));
        }
        let config = ParallelConfig {
            max_workers: 8,
            min_parallel_bytes: 10,
            always_check_parity: true,
            ..default_config()
        };
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        assert!(output.token_count > 0);
        if let Some(ref plan) = output.chunk_plan {
            assert!(plan.worker_count <= 8);
        }
    }

    #[test]
    fn chunk_plan_large_worker_count_capped_by_input() {
        let input = b"a\nb\nc\n";
        let plan = compute_chunk_plan(input, 100);
        assert!(plan.worker_count <= 6);
    }

    #[test]
    fn parallel_parse_only_newlines() {
        let source = "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
        let config = ParallelConfig {
            min_parallel_bytes: 5,
            max_workers: 4,
            always_check_parity: true,
            ..default_config()
        };
        let input = make_input(source, &config);
        let output = parse(&input).unwrap();
        assert_eq!(output.token_count, 0);
    }

    #[test]
    fn parallel_parse_mixed_content_types() {
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!(
                "var s{} = \"hello\"; x{} == {} && y{} != z{};\n",
                i, i, i, i, i
            ));
        }
        let config = small_config();
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        assert!(output.token_count > 0);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn parser_mode_serde_roundtrip() {
        for v in &[ParserMode::Serial, ParserMode::Parallel] {
            let json = serde_json::to_string(v).unwrap();
            let back: ParserMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn serial_reason_serde_roundtrip() {
        let variants = vec![
            SerialReason::InputBelowThreshold {
                input_bytes: 10,
                threshold: 100,
            },
            SerialReason::SingleWorker,
            SerialReason::NoDeterministicSplitPoints,
            SerialReason::BudgetExhausted { budget_us: 500 },
            SerialReason::ParityMismatch { mismatch_index: 7 },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: SerialReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn failover_trigger_class_serde_roundtrip() {
        let variants = [
            FailoverTriggerClass::Timeout,
            FailoverTriggerClass::TranscriptDivergence,
            FailoverTriggerClass::WitnessMismatch,
            FailoverTriggerClass::SafetyPolicyViolation,
            FailoverTriggerClass::ParityMismatch,
            FailoverTriggerClass::ResourceLimit,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: FailoverTriggerClass = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn failover_state_serde_roundtrip() {
        let variants = [
            FailoverState::ParallelAttempted,
            FailoverState::TriggerClassified,
            FailoverState::SerialFallbackRequested,
            FailoverState::SerialFallbackCompleted,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: FailoverState = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn backpressure_level_serde_roundtrip() {
        let variants = [
            BackpressureLevel::Normal,
            BackpressureLevel::Elevated,
            BackpressureLevel::Critical,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: BackpressureLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn fallback_cause_serde_roundtrip() {
        let variants = vec![
            FallbackCause::Routing(SerialReason::SingleWorker),
            FallbackCause::ParityFailure { mismatch_index: 5 },
            FallbackCause::ResourceLimit(SerialReason::BudgetExhausted { budget_us: 100 }),
            FallbackCause::TranscriptDivergence {
                detail: "chunk mismatch".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: FallbackCause = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn failover_trigger_class_display_all_distinct() {
        let variants = [
            FailoverTriggerClass::Timeout,
            FailoverTriggerClass::TranscriptDivergence,
            FailoverTriggerClass::WitnessMismatch,
            FailoverTriggerClass::SafetyPolicyViolation,
            FailoverTriggerClass::ParityMismatch,
            FailoverTriggerClass::ResourceLimit,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn failover_state_display_all_distinct() {
        let variants = [
            FailoverState::ParallelAttempted,
            FailoverState::TriggerClassified,
            FailoverState::SerialFallbackRequested,
            FailoverState::SerialFallbackCompleted,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn backpressure_level_display_all_distinct() {
        let variants = [
            BackpressureLevel::Normal,
            BackpressureLevel::Elevated,
            BackpressureLevel::Critical,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    // -- Enrichment: PearlTower 2026-02-26 session 6 --

    #[test]
    fn log_entries_for_fallback_include_fallback_triggered_event() {
        // Trigger a budget-exhaustion fallback to get a fallback_cause on the output.
        let config = ParallelConfig {
            min_parallel_bytes: 10,
            max_workers: 2,
            chunk_budget_us: 1_500,
            always_check_parity: true,
            ..default_config()
        };
        let mut source = String::new();
        for i in 0..120 {
            source.push_str(&format!("var log_{i} = {i};\n"));
        }
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        assert!(output.fallback_cause.is_some(), "expected a fallback");

        let entries = generate_log_entries("trace-fb", &output);
        assert!(entries.len() >= 2, "fallback should emit >=2 log entries");
        assert_eq!(entries[0].event, "parse_complete");
        assert_eq!(entries[1].event, "fallback_triggered");
        assert_eq!(entries[1].outcome, "fallback");
        assert!(entries[1].error_code.as_deref() == Some("fallback"));
        assert!(entries[1].failover_trigger.is_some());
    }

    #[test]
    fn replay_transcript_rejects_worker_count_mismatch() {
        let source = "a=1;\nb=2;\nc=3;\nd=4;\n";
        let chunk_plan = compute_chunk_plan(source.as_bytes(), 4);
        let transcript = build_schedule_transcript(&chunk_plan, 0);
        let mut wrong_plan = chunk_plan.clone();
        wrong_plan.worker_count = 99;
        let err = replay_schedule_transcript(&transcript, &wrong_plan).unwrap_err();
        assert!(matches!(
            err,
            TranscriptReplayError::WorkerCountMismatch {
                expected: 99,
                actual: _
            }
        ));
    }

    #[test]
    fn replay_transcript_rejects_duplicate_chunk_reference() {
        let source = "a=1;\nb=2;\nc=3;\nd=4;\n";
        let chunk_plan = compute_chunk_plan(source.as_bytes(), 2);
        let mut transcript = build_schedule_transcript(&chunk_plan, 0);
        // Tamper: make both execution_order entries reference chunk 0.
        if transcript.execution_order.len() >= 2 {
            transcript.execution_order[1] = transcript.execution_order[0];
            transcript.dispatches[1].chunk_index = transcript.dispatches[0].chunk_index;
            // Recompute the hash so it doesn't fail on hash mismatch first.
            transcript.transcript_hash = compute_schedule_transcript_hash(
                transcript.seed,
                transcript.worker_count,
                &transcript.plan_hash,
                &transcript.execution_order,
                &transcript.dispatches,
            );
        }
        let err = replay_schedule_transcript(&transcript, &chunk_plan).unwrap_err();
        assert!(matches!(
            err,
            TranscriptReplayError::DuplicateChunkReference { .. }
        ));
    }

    #[test]
    fn repair_boundary_tokens_multiple_consecutive_merges() {
        // Three overlapping same-kind tokens should merge into one.
        let mut tokens = vec![
            Token {
                kind: TokenKind::Identifier,
                start: 0,
                end: 3,
            },
            Token {
                kind: TokenKind::Identifier,
                start: 2,
                end: 5,
            },
            Token {
                kind: TokenKind::Identifier,
                start: 4,
                end: 8,
            },
        ];
        repair_boundary_tokens(&mut tokens);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].start, 0);
        assert_eq!(tokens[0].end, 8);
    }

    #[test]
    fn throughput_sample_compute_handles_overflow() {
        // Near-u64-max bytes should not panic; overflow is clamped via checked_mul.
        let sample = ThroughputSample::compute(u64::MAX, u64::MAX, 1);
        // checked_mul overflows → unwrap_or(0)
        assert_eq!(sample.bytes_per_sec_millionths, 0);
        assert_eq!(sample.tokens_per_sec_millionths, 0);
        assert_eq!(sample.bytes, u64::MAX);
    }

    #[test]
    fn rollback_failure_accumulates_distinct_trace_ids() {
        let mut rc = RollbackControl::default();
        rc.record_failure("trace-a");
        rc.record_failure("trace-b");
        rc.record_failure("trace-a"); // duplicate
        // consecutive_failures still increments even for duplicate trace_id
        assert_eq!(rc.consecutive_failures, 3);
        // but failure_trace_ids deduplicates
        assert_eq!(rc.failure_trace_ids.len(), 2);
        assert!(rc.failure_trace_ids.contains("trace-a"));
        assert!(rc.failure_trace_ids.contains("trace-b"));
    }

    #[test]
    fn chunk_plan_worker_count_capped_to_input_bytes() {
        // 6 bytes with 8 workers: worker_count should be capped to 6.
        let plan = compute_chunk_plan(b"a\nb\nc\n", 8);
        assert!(plan.worker_count <= 6);
        // Chunks must cover entire input.
        assert!(!plan.chunks.is_empty());
        let first_start = plan.chunks[0].0;
        let last_end = plan.chunks.last().unwrap().1;
        assert_eq!(first_start, 0);
        assert_eq!(last_end, 6);
    }

    #[test]
    fn replay_envelope_contains_transcript_hash_in_replay_command() {
        let config = small_config();
        let mut source = String::new();
        for i in 0..100 {
            source.push_str(&format!("var env_{i} = {i};\n"));
        }
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        let digest = compute_routing_digest(&source, &config);
        let envelope = build_replay_envelope(&input, &output, &digest);
        // The replay command should include --transcript-hash when a transcript exists.
        assert!(envelope.replay_command.contains("--transcript-hash"));
        if let Some(ref transcript) = output.schedule_transcript {
            assert!(
                envelope
                    .replay_command
                    .contains(&transcript.transcript_hash.to_hex())
            );
        }
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn serial_reason_display_single_worker() {
        assert_eq!(
            SerialReason::SingleWorker.to_string(),
            "single worker configured"
        );
    }

    #[test]
    fn serial_reason_display_no_deterministic_split_points() {
        assert_eq!(
            SerialReason::NoDeterministicSplitPoints.to_string(),
            "no deterministic split points"
        );
    }

    #[test]
    fn serial_reason_display_budget_exhausted() {
        let reason = SerialReason::BudgetExhausted { budget_us: 50_000 };
        assert_eq!(reason.to_string(), "budget exhausted (50000us)");
    }

    #[test]
    fn serial_reason_display_parity_mismatch() {
        let reason = SerialReason::ParityMismatch { mismatch_index: 7 };
        assert_eq!(reason.to_string(), "parity mismatch at token 7");
    }

    #[test]
    fn serial_reason_display_merge_buffer_exceeded() {
        let reason = SerialReason::MergeBufferExceeded {
            buffer_bytes: 2_000_000,
            limit: 1_048_576,
        };
        assert!(reason.to_string().contains("2000000B exceeds 1048576B"));
    }

    #[test]
    fn serial_reason_display_transcript_divergence() {
        let reason = SerialReason::TranscriptDivergence {
            detail: "hash mismatch".to_string(),
        };
        assert!(reason.to_string().contains("hash mismatch"));
    }

    #[test]
    fn serial_reason_serde_merge_buffer_and_transcript() {
        let variants = vec![
            SerialReason::MergeBufferExceeded {
                buffer_bytes: 2_000_000,
                limit: 1_000_000,
            },
            SerialReason::TranscriptDivergence {
                detail: "diverged".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: SerialReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn fallback_cause_display_routing() {
        let cause = FallbackCause::Routing(SerialReason::SingleWorker);
        assert_eq!(cause.to_string(), "routing: single worker configured");
    }

    #[test]
    fn fallback_cause_display_resource_limit() {
        let cause = FallbackCause::ResourceLimit(SerialReason::BudgetExhausted { budget_us: 100 });
        assert_eq!(
            cause.to_string(),
            "resource limit: budget exhausted (100us)"
        );
    }

    #[test]
    fn fallback_cause_display_transcript_divergence() {
        let cause = FallbackCause::TranscriptDivergence {
            detail: "bad hash".to_string(),
        };
        assert!(cause.to_string().contains("transcript divergence"));
        assert!(cause.to_string().contains("bad hash"));
    }

    #[test]
    fn parse_error_display_input_too_large() {
        let e = ParseError::InputTooLarge {
            size: 5000,
            max: 1000,
        };
        assert!(e.to_string().contains("5000B exceeds 1000B"));
    }

    #[test]
    fn parse_error_display_invalid_config() {
        let e = ParseError::InvalidConfig {
            detail: "max_workers must be >= 1".to_string(),
        };
        assert!(e.to_string().contains("invalid config"));
        assert!(e.to_string().contains("max_workers"));
    }

    #[test]
    fn transcript_replay_error_display_all_distinct() {
        let hash_a = ContentHash::compute(b"a");
        let hash_b = ContentHash::compute(b"b");
        let variants: Vec<TranscriptReplayError> = vec![
            TranscriptReplayError::PlanHashMismatch {
                expected: hash_a,
                actual: hash_b,
            },
            TranscriptReplayError::WorkerCountMismatch {
                expected: 4,
                actual: 2,
            },
            TranscriptReplayError::InvalidExecutionOrderLength {
                expected_chunks: 4,
                actual_entries: 3,
            },
            TranscriptReplayError::InvalidDispatchCount {
                expected_steps: 4,
                actual_steps: 3,
            },
            TranscriptReplayError::InvalidChunkReference {
                step_index: 0,
                chunk_index: 10,
                chunk_count: 4,
            },
            TranscriptReplayError::DuplicateChunkReference { chunk_index: 2 },
            TranscriptReplayError::MissingChunkReference { chunk_index: 3 },
            TranscriptReplayError::DispatchStepMismatch {
                expected_step: 0,
                actual_step: 1,
            },
            TranscriptReplayError::DispatchChunkMismatch {
                step_index: 0,
                expected_chunk: 1,
                actual_chunk: 2,
            },
            TranscriptReplayError::WorkerSlotOutOfRange {
                step_index: 0,
                worker_slot: 5,
                worker_count: 4,
            },
            TranscriptReplayError::TranscriptHashMismatch {
                expected: hash_a,
                actual: hash_b,
            },
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn transcript_replay_error_serde_roundtrip() {
        let hash = ContentHash::compute(b"test");
        let variants = vec![
            TranscriptReplayError::PlanHashMismatch {
                expected: hash,
                actual: hash,
            },
            TranscriptReplayError::WorkerCountMismatch {
                expected: 4,
                actual: 2,
            },
            TranscriptReplayError::DuplicateChunkReference { chunk_index: 1 },
            TranscriptReplayError::MissingChunkReference { chunk_index: 3 },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: TranscriptReplayError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn chunk_result_serde_roundtrip() {
        let cr = ChunkResult {
            chunk_index: 1,
            chunk_start: 100,
            chunk_end: 200,
            tokens: vec![Token {
                kind: TokenKind::Identifier,
                start: 0,
                end: 5,
            }],
            token_count: 1,
        };
        let json = serde_json::to_string(&cr).unwrap();
        let back: ChunkResult = serde_json::from_str(&json).unwrap();
        assert_eq!(cr, back);
    }

    #[test]
    fn schedule_dispatch_serde_roundtrip() {
        let dispatch = ScheduleDispatch {
            step_index: 3,
            chunk_index: 1,
            worker_slot: 2,
        };
        let json = serde_json::to_string(&dispatch).unwrap();
        let back: ScheduleDispatch = serde_json::from_str(&json).unwrap();
        assert_eq!(dispatch, back);
    }

    #[test]
    fn failover_trigger_serde_roundtrip() {
        let trigger = FailoverTrigger {
            class: FailoverTriggerClass::Timeout,
            detail: "chunk 0 exceeded budget".to_string(),
        };
        let json = serde_json::to_string(&trigger).unwrap();
        let back: FailoverTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(trigger, back);
    }

    #[test]
    fn failover_decision_serde_roundtrip() {
        let decision = FailoverDecision {
            trigger: FailoverTrigger {
                class: FailoverTriggerClass::ParityMismatch,
                detail: "token 42".to_string(),
            },
            transition_path: vec![
                FailoverState::ParallelAttempted,
                FailoverState::TriggerClassified,
                FailoverState::SerialFallbackRequested,
                FailoverState::SerialFallbackCompleted,
            ],
            witness_ids: vec!["w1".to_string(), "w2".to_string()],
            replay_command: "franken-engine replay --trace t1".to_string(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let back: FailoverDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    #[test]
    fn parse_log_entry_serde_roundtrip() {
        let entry = ParseLogEntry {
            trace_id: "t1".into(),
            component: COMPONENT.into(),
            event: "parse_complete".into(),
            outcome: "ok".into(),
            parser_mode: Some("parallel".into()),
            worker_count: Some(4),
            input_bytes: Some(1000),
            token_count: Some(50),
            fallback_reason: None,
            failover_trigger: None,
            failover_transition_path: None,
            failover_witness_ids: None,
            replay_command: None,
            parity_result: Some("ok".into()),
            cancellation_state: None,
            cancellation_elapsed_us: None,
            backpressure_level: Some("normal".into()),
            backpressure_peak_queue_depth: Some(0),
            error_code: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ParseLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn check_parity_both_empty_is_ok() {
        let result = check_parity(&[], &[]);
        assert!(result.parity_ok);
        assert_eq!(result.mismatch_index, None);
        assert_eq!(result.parallel_count, 0);
        assert_eq!(result.serial_count, 0);
    }

    #[test]
    fn classify_backpressure_level_normal() {
        assert_eq!(classify_backpressure_level(0), BackpressureLevel::Normal);
        assert_eq!(classify_backpressure_level(1), BackpressureLevel::Normal);
    }

    #[test]
    fn classify_backpressure_level_elevated() {
        assert_eq!(classify_backpressure_level(2), BackpressureLevel::Elevated);
        assert_eq!(classify_backpressure_level(11), BackpressureLevel::Elevated);
    }

    #[test]
    fn classify_backpressure_level_critical() {
        assert_eq!(classify_backpressure_level(12), BackpressureLevel::Critical);
        assert_eq!(
            classify_backpressure_level(100),
            BackpressureLevel::Critical
        );
    }

    #[test]
    fn token_kind_code_all_variants() {
        assert_eq!(token_kind_code(TokenKind::Identifier), 0);
        assert_eq!(token_kind_code(TokenKind::NumericLiteral), 1);
        assert_eq!(token_kind_code(TokenKind::StringLiteral), 2);
        assert_eq!(token_kind_code(TokenKind::UnterminatedString), 3);
        assert_eq!(token_kind_code(TokenKind::TwoCharOperator), 4);
        assert_eq!(token_kind_code(TokenKind::Punctuation), 5);
    }

    #[test]
    fn splitmix64_deterministic() {
        let a = splitmix64(42);
        let b = splitmix64(42);
        assert_eq!(a, b);
        // Different inputs produce different outputs.
        assert_ne!(splitmix64(0), splitmix64(1));
    }

    #[test]
    fn deterministic_chunk_elapsed_us_increases_with_step() {
        let t0 = deterministic_chunk_elapsed_us(100, 10, 0);
        let t1 = deterministic_chunk_elapsed_us(100, 10, 1);
        let t2 = deterministic_chunk_elapsed_us(100, 10, 2);
        assert!(t0 < t1);
        assert!(t1 < t2);
    }

    #[test]
    fn zero_budget_is_error() {
        let config = ParallelConfig {
            chunk_budget_us: 0,
            ..default_config()
        };
        let input = make_input("x", &config);
        assert!(matches!(
            parse(&input),
            Err(ParseError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn parse_error_serde_all_variants() {
        let variants = vec![
            ParseError::LexerError {
                chunk_index: 0,
                detail: "bad".into(),
            },
            ParseError::InputTooLarge {
                size: 1000,
                max: 500,
            },
            ParseError::InvalidConfig {
                detail: "zero workers".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ParseError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }
}
