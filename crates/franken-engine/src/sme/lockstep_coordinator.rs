#![forbid(unsafe_code)]

//! Deterministic lockstep coordinator for secure multi-execution runtime copies.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::secure_multi_execution_kernel::{
    HostcallInvocation, HostcallSignature, LabeledHostcallOutput, SecureMultiExecutionKernel,
    SecurityLevel, SmeKernelError, SmeStepReceipt,
};
use crate::security_epoch::SecurityEpoch;

pub const SME_LOCKSTEP_SCHEMA_VERSION: &str = "franken-engine.secure-multi-execution-lockstep.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockstepInstruction {
    pub instruction_id: String,
    pub opcode_hash: ContentHash,
    pub input_hash: ContentHash,
}

impl LockstepInstruction {
    pub fn new(instruction_id: impl Into<String>, opcode_bytes: &[u8], input_bytes: &[u8]) -> Self {
        Self {
            instruction_id: instruction_id.into(),
            opcode_hash: ContentHash::compute(opcode_bytes),
            input_hash: ContentHash::compute(input_bytes),
        }
    }

    fn step_hash(&self, step_index: u64) -> ContentHash {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SME_LOCKSTEP_SCHEMA_VERSION.as_bytes());
        bytes.extend_from_slice(&step_index.to_be_bytes());
        bytes.extend_from_slice(&(self.instruction_id.len() as u64).to_be_bytes());
        bytes.extend_from_slice(self.instruction_id.as_bytes());
        bytes.extend_from_slice(self.opcode_hash.as_bytes());
        bytes.extend_from_slice(self.input_hash.as_bytes());
        ContentHash::compute(&bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LockstepBarrierKind {
    Instruction,
    Hostcall,
    MemoryAccess,
    Synchronization,
}

impl LockstepBarrierKind {
    pub fn stable_name(self) -> &'static str {
        match self {
            Self::Instruction => "instruction",
            Self::Hostcall => "hostcall",
            Self::MemoryAccess => "memory_access",
            Self::Synchronization => "synchronization",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockstepRuntimeState {
    pub level: SecurityLevel,
    pub next_instruction_index: u64,
    pub instruction_hashes: Vec<ContentHash>,
    pub barrier_hashes: Vec<ContentHash>,
}

impl LockstepRuntimeState {
    pub fn new(level: SecurityLevel) -> Self {
        Self {
            level,
            next_instruction_index: 0,
            instruction_hashes: Vec::new(),
            barrier_hashes: Vec::new(),
        }
    }

    fn append_barrier(&mut self, instruction_hash: ContentHash, barrier_hash: ContentHash) {
        self.instruction_hashes.push(instruction_hash);
        self.barrier_hashes.push(barrier_hash);
        self.next_instruction_index += 1;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockstepStepReceipt {
    pub schema_version: String,
    pub epoch: SecurityEpoch,
    pub step_index: u64,
    pub instruction_id: String,
    pub barrier_kind: LockstepBarrierKind,
    pub instruction_hash: ContentHash,
    pub barrier_hash: ContentHash,
    pub synchronized_levels: BTreeSet<SecurityLevel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockstepOperationReceipt {
    pub lockstep: LockstepStepReceipt,
    pub sme: SmeStepReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmeLockstepCoordinator {
    pub schema_version: String,
    pub epoch: SecurityEpoch,
    pub kernel: SecureMultiExecutionKernel,
    pub runtimes: BTreeMap<SecurityLevel, LockstepRuntimeState>,
    pub step_receipts: Vec<LockstepStepReceipt>,
}

impl SmeLockstepCoordinator {
    pub fn new(
        levels: impl IntoIterator<Item = SecurityLevel>,
        epoch: SecurityEpoch,
    ) -> Result<Self, SmeLockstepError> {
        let levels = levels.into_iter().collect::<BTreeSet<_>>();
        if levels.is_empty() {
            return Err(SmeLockstepError::NoRuntimeCopies);
        }

        let runtimes = levels
            .iter()
            .copied()
            .map(|level| (level, LockstepRuntimeState::new(level)))
            .collect::<BTreeMap<_, _>>();

        Ok(Self {
            schema_version: SME_LOCKSTEP_SCHEMA_VERSION.to_string(),
            epoch,
            kernel: SecureMultiExecutionKernel::new(levels, epoch),
            runtimes,
            step_receipts: Vec::new(),
        })
    }

    pub fn with_standard_levels(epoch: SecurityEpoch) -> Self {
        Self::new(SecurityLevel::all().iter().copied(), epoch)
            .expect("standard SME security levels are non-empty")
    }

    pub fn runtime_count(&self) -> usize {
        self.runtimes.len()
    }

    pub fn step_count(&self) -> usize {
        self.step_receipts.len()
    }

    pub fn register_hostcall(&mut self, signature: HostcallSignature) {
        self.kernel.register_hostcall(signature);
    }

    pub fn register_standard_hostcalls(&mut self) {
        self.kernel.register_standard_hostcalls();
    }

    pub fn visible_outputs(&self, level: SecurityLevel) -> Option<&[LabeledHostcallOutput]> {
        self.kernel.visible_outputs(level)
    }

    pub fn runtime_state(&self, level: SecurityLevel) -> Option<&LockstepRuntimeState> {
        self.runtimes.get(&level)
    }

    pub fn execute_instruction(
        &mut self,
        instruction: LockstepInstruction,
    ) -> Result<LockstepStepReceipt, SmeLockstepError> {
        self.record_barrier(instruction, LockstepBarrierKind::Instruction)
    }

    pub fn synchronize_barrier(
        &mut self,
        barrier_id: impl Into<String>,
        barrier_kind: LockstepBarrierKind,
    ) -> Result<LockstepStepReceipt, SmeLockstepError> {
        let barrier_id = barrier_id.into();
        let instruction = LockstepInstruction::new(
            barrier_id.clone(),
            barrier_kind.stable_name().as_bytes(),
            barrier_id.as_bytes(),
        );
        self.record_barrier(instruction, barrier_kind)
    }

    pub fn execute_hostcall_at_barrier(
        &mut self,
        instruction: LockstepInstruction,
        invocation: HostcallInvocation,
        output_bytes: impl Into<Vec<u8>>,
    ) -> Result<LockstepOperationReceipt, SmeLockstepError> {
        self.ensure_runtime_level(invocation.caller_level)?;

        let mut candidate_kernel = self.kernel.clone();
        let sme = candidate_kernel.execute_hostcall(invocation, output_bytes.into())?;
        if !candidate_kernel.isolation_holds() {
            return Err(SmeLockstepError::IsolationViolation);
        }

        let lockstep = self.record_barrier(instruction, LockstepBarrierKind::Hostcall)?;
        self.kernel = candidate_kernel;
        Ok(LockstepOperationReceipt { lockstep, sme })
    }

    pub fn deliver_labeled_output_at_barrier(
        &mut self,
        instruction: LockstepInstruction,
        invocation: &HostcallInvocation,
        output_label: SecurityLevel,
        output_bytes: Vec<u8>,
    ) -> Result<LockstepOperationReceipt, SmeLockstepError> {
        self.ensure_runtime_level(invocation.caller_level)?;

        let mut candidate_kernel = self.kernel.clone();
        let sme =
            candidate_kernel.deliver_labeled_output(invocation, output_label, output_bytes)?;
        if !candidate_kernel.isolation_holds() {
            return Err(SmeLockstepError::IsolationViolation);
        }

        let lockstep = self.record_barrier(instruction, LockstepBarrierKind::MemoryAccess)?;
        self.kernel = candidate_kernel;
        Ok(LockstepOperationReceipt { lockstep, sme })
    }

    pub fn is_synchronized(&self) -> bool {
        let Some(first) = self.runtimes.values().next() else {
            return false;
        };

        self.runtimes.values().all(|state| {
            state.next_instruction_index == first.next_instruction_index
                && state.instruction_hashes == first.instruction_hashes
                && state.barrier_hashes == first.barrier_hashes
        })
    }

    fn record_barrier(
        &mut self,
        instruction: LockstepInstruction,
        barrier_kind: LockstepBarrierKind,
    ) -> Result<LockstepStepReceipt, SmeLockstepError> {
        let step_index = self.step_receipts.len() as u64;
        for (level, state) in &self.runtimes {
            if state.next_instruction_index != step_index {
                return Err(SmeLockstepError::RuntimeOutOfLockstep {
                    level: *level,
                    expected: step_index,
                    actual: state.next_instruction_index,
                });
            }
        }

        let instruction_hash = instruction.step_hash(step_index);
        let synchronized_levels = self.runtimes.keys().copied().collect::<BTreeSet<_>>();
        let barrier_hash = compute_barrier_hash(
            self.epoch,
            step_index,
            barrier_kind,
            &instruction.instruction_id,
            instruction_hash,
            &synchronized_levels,
        );

        for state in self.runtimes.values_mut() {
            state.append_barrier(instruction_hash, barrier_hash);
        }

        let receipt = LockstepStepReceipt {
            schema_version: SME_LOCKSTEP_SCHEMA_VERSION.to_string(),
            epoch: self.epoch,
            step_index,
            instruction_id: instruction.instruction_id,
            barrier_kind,
            instruction_hash,
            barrier_hash,
            synchronized_levels,
        };
        self.step_receipts.push(receipt.clone());
        Ok(receipt)
    }

    fn ensure_runtime_level(&self, level: SecurityLevel) -> Result<(), SmeLockstepError> {
        if self.runtimes.contains_key(&level) {
            Ok(())
        } else {
            Err(SmeLockstepError::MissingRuntimeLevel(level))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmeLockstepError {
    NoRuntimeCopies,
    MissingRuntimeLevel(SecurityLevel),
    RuntimeOutOfLockstep {
        level: SecurityLevel,
        expected: u64,
        actual: u64,
    },
    Kernel(SmeKernelError),
    IsolationViolation,
}

impl fmt::Display for SmeLockstepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRuntimeCopies => f.write_str("SME lockstep coordinator has no runtimes"),
            Self::MissingRuntimeLevel(level) => {
                write!(f, "SME lockstep runtime level `{level}` is not configured")
            }
            Self::RuntimeOutOfLockstep {
                level,
                expected,
                actual,
            } => write!(
                f,
                "SME runtime `{level}` is out of lockstep: expected step {expected}, found {actual}"
            ),
            Self::Kernel(err) => write!(f, "SME kernel error: {err}"),
            Self::IsolationViolation => {
                f.write_str("SME kernel isolation invariant failed after lockstep operation")
            }
        }
    }
}

impl std::error::Error for SmeLockstepError {}

impl From<SmeKernelError> for SmeLockstepError {
    fn from(value: SmeKernelError) -> Self {
        Self::Kernel(value)
    }
}

fn compute_barrier_hash(
    epoch: SecurityEpoch,
    step_index: u64,
    barrier_kind: LockstepBarrierKind,
    instruction_id: &str,
    instruction_hash: ContentHash,
    synchronized_levels: &BTreeSet<SecurityLevel>,
) -> ContentHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SME_LOCKSTEP_SCHEMA_VERSION.as_bytes());
    bytes.extend_from_slice(&epoch.as_u64().to_be_bytes());
    bytes.extend_from_slice(&step_index.to_be_bytes());
    bytes.extend_from_slice(barrier_kind.stable_name().as_bytes());
    bytes.extend_from_slice(&(instruction_id.len() as u64).to_be_bytes());
    bytes.extend_from_slice(instruction_id.as_bytes());
    bytes.extend_from_slice(instruction_hash.as_bytes());
    for level in synchronized_levels {
        bytes.extend_from_slice(level.stable_name().as_bytes());
    }
    ContentHash::compute(&bytes)
}
