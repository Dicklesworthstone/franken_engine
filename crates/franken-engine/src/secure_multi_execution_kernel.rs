#![forbid(unsafe_code)]

//! Secure multi-execution kernel for label-isolated runtime copies.
//!
//! Each configured security level owns an independent runtime copy. Labeled
//! hostcall outputs are delivered only to copies whose level dominates the
//! output label.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

pub const SME_KERNEL_SCHEMA_VERSION: &str = "franken-engine.secure-multi-execution-kernel.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityLevel {
    Public,
    Internal,
    Confidential,
    Secret,
}

impl SecurityLevel {
    pub const ALL: [Self; 4] = [
        Self::Public,
        Self::Internal,
        Self::Confidential,
        Self::Secret,
    ];

    pub fn all() -> &'static [Self; 4] {
        &Self::ALL
    }

    pub fn dominates(self, other: Self) -> bool {
        self >= other
    }

    pub fn stable_name(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Confidential => "confidential",
            Self::Secret => "secret",
        }
    }
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SmeHostcallKind {
    FsRead,
    FsWrite,
    NetConnect,
    NetListen,
    ProcSpawn,
    EnvRead,
    EnvWrite,
    PolicyRequest,
    ClockRead,
    RandomRead,
    Custom(String),
}

impl SmeHostcallKind {
    pub fn stable_name(&self) -> &str {
        match self {
            Self::FsRead => "fs.read",
            Self::FsWrite => "fs.write",
            Self::NetConnect => "net.connect",
            Self::NetListen => "net.listen",
            Self::ProcSpawn => "proc.spawn",
            Self::EnvRead => "env.read",
            Self::EnvWrite => "env.write",
            Self::PolicyRequest => "policy.request",
            Self::ClockRead => "clock.read",
            Self::RandomRead => "random.read",
            Self::Custom(name) => name.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostcallSignature {
    pub kind: SmeHostcallKind,
    pub minimum_level: SecurityLevel,
    pub output_label: SecurityLevel,
}

impl HostcallSignature {
    pub fn new(
        kind: SmeHostcallKind,
        minimum_level: SecurityLevel,
        output_label: SecurityLevel,
    ) -> Self {
        Self {
            kind,
            minimum_level,
            output_label,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostcallInvocation {
    pub invocation_id: String,
    pub kind: SmeHostcallKind,
    pub caller_level: SecurityLevel,
    pub argument_hash: ContentHash,
}

impl HostcallInvocation {
    pub fn new(
        invocation_id: impl Into<String>,
        kind: SmeHostcallKind,
        caller_level: SecurityLevel,
        arguments: &[u8],
    ) -> Self {
        Self {
            invocation_id: invocation_id.into(),
            kind,
            caller_level,
            argument_hash: ContentHash::compute(arguments),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabeledHostcallOutput {
    pub invocation_id: String,
    pub kind: SmeHostcallKind,
    pub label: SecurityLevel,
    pub output_hash: ContentHash,
    pub bytes: Vec<u8>,
}

impl LabeledHostcallOutput {
    pub fn new(invocation: &HostcallInvocation, label: SecurityLevel, bytes: Vec<u8>) -> Self {
        let output_hash = ContentHash::compute(&bytes);
        Self {
            invocation_id: invocation.invocation_id.clone(),
            kind: invocation.kind.clone(),
            label,
            output_hash,
            bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolatedRuntimeCopy {
    pub level: SecurityLevel,
    pub delivered_outputs: Vec<LabeledHostcallOutput>,
    pub transcript_hashes: Vec<ContentHash>,
}

impl IsolatedRuntimeCopy {
    pub fn new(level: SecurityLevel) -> Self {
        Self {
            level,
            delivered_outputs: Vec::new(),
            transcript_hashes: Vec::new(),
        }
    }

    pub fn visible_output_count(&self) -> usize {
        self.delivered_outputs.len()
    }

    pub fn can_observe(&self, label: SecurityLevel) -> bool {
        self.level.dominates(label)
    }

    fn append_output(&mut self, output: LabeledHostcallOutput) {
        self.transcript_hashes.push(output.output_hash);
        self.delivered_outputs.push(output);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmeStepReceipt {
    pub schema_version: String,
    pub epoch: SecurityEpoch,
    pub invocation_id: String,
    pub output_label: SecurityLevel,
    pub delivered_to: BTreeSet<SecurityLevel>,
    pub suppressed_from: BTreeSet<SecurityLevel>,
    pub output_hash: ContentHash,
    pub receipt_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureMultiExecutionKernel {
    pub schema_version: String,
    pub epoch: SecurityEpoch,
    pub runtimes: BTreeMap<SecurityLevel, IsolatedRuntimeCopy>,
    pub hostcalls: BTreeMap<SmeHostcallKind, HostcallSignature>,
    pub receipts: Vec<SmeStepReceipt>,
}

impl SecureMultiExecutionKernel {
    pub fn new(levels: impl IntoIterator<Item = SecurityLevel>, epoch: SecurityEpoch) -> Self {
        let mut runtimes = BTreeMap::new();
        for level in levels {
            runtimes.insert(level, IsolatedRuntimeCopy::new(level));
        }
        Self {
            schema_version: SME_KERNEL_SCHEMA_VERSION.to_string(),
            epoch,
            runtimes,
            hostcalls: BTreeMap::new(),
            receipts: Vec::new(),
        }
    }

    pub fn with_standard_levels(epoch: SecurityEpoch) -> Self {
        Self::new(SecurityLevel::all().iter().copied(), epoch)
    }

    pub fn register_hostcall(&mut self, signature: HostcallSignature) {
        self.hostcalls.insert(signature.kind.clone(), signature);
    }

    pub fn register_standard_hostcalls(&mut self) {
        for signature in standard_hostcall_signatures() {
            self.register_hostcall(signature);
        }
    }

    pub fn runtime(&self, level: SecurityLevel) -> Option<&IsolatedRuntimeCopy> {
        self.runtimes.get(&level)
    }

    pub fn visible_outputs(&self, level: SecurityLevel) -> Option<&[LabeledHostcallOutput]> {
        self.runtime(level)
            .map(|runtime| runtime.delivered_outputs.as_slice())
    }

    pub fn execute_hostcall(
        &mut self,
        invocation: HostcallInvocation,
        output_bytes: impl Into<Vec<u8>>,
    ) -> Result<SmeStepReceipt, SmeKernelError> {
        let signature = self
            .hostcalls
            .get(&invocation.kind)
            .ok_or_else(|| SmeKernelError::UnknownHostcall(invocation.kind.stable_name().into()))?
            .clone();

        if !invocation.caller_level.dominates(signature.minimum_level) {
            return Err(SmeKernelError::InsufficientAuthority {
                invocation_id: invocation.invocation_id,
                caller_level: invocation.caller_level,
                required_level: signature.minimum_level,
            });
        }

        self.deliver_labeled_output(&invocation, signature.output_label, output_bytes.into())
    }

    pub fn deliver_labeled_output(
        &mut self,
        invocation: &HostcallInvocation,
        output_label: SecurityLevel,
        output_bytes: Vec<u8>,
    ) -> Result<SmeStepReceipt, SmeKernelError> {
        if self.runtimes.is_empty() {
            return Err(SmeKernelError::NoRuntimeCopies);
        }

        let output = LabeledHostcallOutput::new(invocation, output_label, output_bytes);
        let mut delivered_to = BTreeSet::new();
        let mut suppressed_from = BTreeSet::new();

        for (runtime_level, runtime) in &mut self.runtimes {
            if runtime.can_observe(output_label) {
                runtime.append_output(output.clone());
                delivered_to.insert(*runtime_level);
            } else {
                suppressed_from.insert(*runtime_level);
            }
        }

        let receipt_hash = compute_receipt_hash(
            self.epoch,
            &invocation.invocation_id,
            output_label,
            output.output_hash,
            &delivered_to,
            &suppressed_from,
        );

        let receipt = SmeStepReceipt {
            schema_version: SME_KERNEL_SCHEMA_VERSION.to_string(),
            epoch: self.epoch,
            invocation_id: invocation.invocation_id.clone(),
            output_label,
            delivered_to,
            suppressed_from,
            output_hash: output.output_hash,
            receipt_hash,
        };
        self.receipts.push(receipt.clone());
        Ok(receipt)
    }

    pub fn isolation_holds(&self) -> bool {
        self.runtimes.iter().all(|(level, runtime)| {
            runtime
                .delivered_outputs
                .iter()
                .all(|output| level.dominates(output.label))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmeKernelError {
    NoRuntimeCopies,
    UnknownHostcall(String),
    InsufficientAuthority {
        invocation_id: String,
        caller_level: SecurityLevel,
        required_level: SecurityLevel,
    },
}

impl fmt::Display for SmeKernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRuntimeCopies => f.write_str("secure multi-execution kernel has no runtimes"),
            Self::UnknownHostcall(kind) => write!(f, "unknown SME hostcall `{kind}`"),
            Self::InsufficientAuthority {
                invocation_id,
                caller_level,
                required_level,
            } => write!(
                f,
                "SME invocation `{invocation_id}` from `{caller_level}` requires `{required_level}`"
            ),
        }
    }
}

impl std::error::Error for SmeKernelError {}

pub fn standard_hostcall_signatures() -> Vec<HostcallSignature> {
    vec![
        HostcallSignature::new(
            SmeHostcallKind::FsRead,
            SecurityLevel::Internal,
            SecurityLevel::Internal,
        ),
        HostcallSignature::new(
            SmeHostcallKind::FsWrite,
            SecurityLevel::Confidential,
            SecurityLevel::Confidential,
        ),
        HostcallSignature::new(
            SmeHostcallKind::NetConnect,
            SecurityLevel::Internal,
            SecurityLevel::Internal,
        ),
        HostcallSignature::new(
            SmeHostcallKind::NetListen,
            SecurityLevel::Confidential,
            SecurityLevel::Confidential,
        ),
        HostcallSignature::new(
            SmeHostcallKind::ProcSpawn,
            SecurityLevel::Secret,
            SecurityLevel::Secret,
        ),
        HostcallSignature::new(
            SmeHostcallKind::EnvRead,
            SecurityLevel::Internal,
            SecurityLevel::Internal,
        ),
        HostcallSignature::new(
            SmeHostcallKind::EnvWrite,
            SecurityLevel::Confidential,
            SecurityLevel::Confidential,
        ),
        HostcallSignature::new(
            SmeHostcallKind::PolicyRequest,
            SecurityLevel::Public,
            SecurityLevel::Public,
        ),
        HostcallSignature::new(
            SmeHostcallKind::ClockRead,
            SecurityLevel::Public,
            SecurityLevel::Public,
        ),
        HostcallSignature::new(
            SmeHostcallKind::RandomRead,
            SecurityLevel::Public,
            SecurityLevel::Public,
        ),
    ]
}

fn compute_receipt_hash(
    epoch: SecurityEpoch,
    invocation_id: &str,
    output_label: SecurityLevel,
    output_hash: ContentHash,
    delivered_to: &BTreeSet<SecurityLevel>,
    suppressed_from: &BTreeSet<SecurityLevel>,
) -> ContentHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SME_KERNEL_SCHEMA_VERSION.as_bytes());
    bytes.extend_from_slice(&epoch.as_u64().to_be_bytes());
    bytes.extend_from_slice(&(invocation_id.len() as u64).to_be_bytes());
    bytes.extend_from_slice(invocation_id.as_bytes());
    bytes.extend_from_slice(output_label.stable_name().as_bytes());
    bytes.extend_from_slice(output_hash.as_bytes());
    for level in delivered_to {
        bytes.extend_from_slice(b"+");
        bytes.extend_from_slice(level.stable_name().as_bytes());
    }
    for level in suppressed_from {
        bytes.extend_from_slice(b"-");
        bytes.extend_from_slice(level.stable_name().as_bytes());
    }
    ContentHash::compute(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel() -> SecureMultiExecutionKernel {
        let mut kernel =
            SecureMultiExecutionKernel::with_standard_levels(SecurityEpoch::from_raw(7));
        kernel.register_standard_hostcalls();
        kernel
    }

    fn invocation(
        id: &str,
        kind: SmeHostcallKind,
        caller_level: SecurityLevel,
    ) -> HostcallInvocation {
        HostcallInvocation::new(id, kind, caller_level, id.as_bytes())
    }

    #[test]
    fn security_level_order_is_lattice_order() {
        assert!(SecurityLevel::Secret.dominates(SecurityLevel::Public));
        assert!(SecurityLevel::Confidential.dominates(SecurityLevel::Internal));
        assert!(!SecurityLevel::Public.dominates(SecurityLevel::Internal));
    }

    #[test]
    fn standard_kernel_has_four_runtime_copies() {
        let kernel = SecureMultiExecutionKernel::with_standard_levels(SecurityEpoch::GENESIS);
        assert_eq!(kernel.runtimes.len(), 4);
        assert!(kernel.runtime(SecurityLevel::Secret).is_some());
    }

    #[test]
    fn public_output_reaches_all_runtime_copies() {
        let mut kernel = kernel();
        let receipt = kernel
            .execute_hostcall(
                invocation("clock", SmeHostcallKind::ClockRead, SecurityLevel::Public),
                b"now".to_vec(),
            )
            .expect("public hostcall should execute");
        assert_eq!(receipt.delivered_to.len(), 4);
        assert!(receipt.suppressed_from.is_empty());
    }

    #[test]
    fn internal_output_is_hidden_from_public_copy() {
        let mut kernel = kernel();
        let receipt = kernel
            .execute_hostcall(
                invocation("fs-read", SmeHostcallKind::FsRead, SecurityLevel::Internal),
                b"file".to_vec(),
            )
            .expect("internal hostcall should execute");
        assert!(receipt.suppressed_from.contains(&SecurityLevel::Public));
        assert!(!receipt.delivered_to.contains(&SecurityLevel::Public));
    }

    #[test]
    fn confidential_output_reaches_confidential_and_secret() {
        let mut kernel = kernel();
        let receipt = kernel
            .execute_hostcall(
                invocation(
                    "fs-write",
                    SmeHostcallKind::FsWrite,
                    SecurityLevel::Confidential,
                ),
                b"written".to_vec(),
            )
            .expect("confidential hostcall should execute");
        assert_eq!(
            receipt.delivered_to,
            BTreeSet::from([SecurityLevel::Confidential, SecurityLevel::Secret])
        );
    }

    #[test]
    fn secret_output_reaches_only_secret_copy() {
        let mut kernel = kernel();
        let receipt = kernel
            .execute_hostcall(
                invocation("spawn", SmeHostcallKind::ProcSpawn, SecurityLevel::Secret),
                b"pid".to_vec(),
            )
            .expect("secret hostcall should execute");
        assert_eq!(
            receipt.delivered_to,
            BTreeSet::from([SecurityLevel::Secret])
        );
        assert_eq!(receipt.suppressed_from.len(), 3);
    }

    #[test]
    fn isolation_holds_after_mixed_outputs() {
        let mut kernel = kernel();
        kernel
            .execute_hostcall(
                invocation("clock", SmeHostcallKind::ClockRead, SecurityLevel::Public),
                b"now".to_vec(),
            )
            .unwrap();
        kernel
            .execute_hostcall(
                invocation("spawn", SmeHostcallKind::ProcSpawn, SecurityLevel::Secret),
                b"pid".to_vec(),
            )
            .unwrap();
        assert!(kernel.isolation_holds());
    }

    #[test]
    fn insufficient_authority_fails_closed() {
        let mut kernel = kernel();
        let err = kernel
            .execute_hostcall(
                invocation("bad", SmeHostcallKind::ProcSpawn, SecurityLevel::Public),
                b"pid".to_vec(),
            )
            .expect_err("public caller cannot spawn process");
        assert!(matches!(err, SmeKernelError::InsufficientAuthority { .. }));
    }

    #[test]
    fn unknown_hostcall_fails_closed() {
        let mut kernel = kernel();
        let err = kernel
            .execute_hostcall(
                invocation(
                    "custom",
                    SmeHostcallKind::Custom("missing".to_string()),
                    SecurityLevel::Secret,
                ),
                b"x".to_vec(),
            )
            .expect_err("unregistered hostcall should fail");
        assert_eq!(err, SmeKernelError::UnknownHostcall("missing".to_string()));
    }

    #[test]
    fn no_runtime_copies_fails_closed() {
        let mut kernel = SecureMultiExecutionKernel::new([], SecurityEpoch::GENESIS);
        let invocation = invocation("x", SmeHostcallKind::ClockRead, SecurityLevel::Public);
        let err = kernel
            .deliver_labeled_output(&invocation, SecurityLevel::Public, Vec::new())
            .expect_err("empty kernel cannot deliver");
        assert_eq!(err, SmeKernelError::NoRuntimeCopies);
    }

    #[test]
    fn receipt_hash_is_deterministic() {
        let mut a = kernel();
        let mut b = kernel();
        let invocation = invocation("same", SmeHostcallKind::ClockRead, SecurityLevel::Public);
        let receipt_a = a
            .execute_hostcall(invocation.clone(), b"same".to_vec())
            .unwrap();
        let receipt_b = b.execute_hostcall(invocation, b"same".to_vec()).unwrap();
        assert_eq!(receipt_a.receipt_hash, receipt_b.receipt_hash);
    }

    #[test]
    fn receipt_hash_changes_with_output_bytes() {
        let mut a = kernel();
        let mut b = kernel();
        let invocation = invocation("same", SmeHostcallKind::ClockRead, SecurityLevel::Public);
        let receipt_a = a
            .execute_hostcall(invocation.clone(), b"a".to_vec())
            .unwrap();
        let receipt_b = b.execute_hostcall(invocation, b"b".to_vec()).unwrap();
        assert_ne!(receipt_a.receipt_hash, receipt_b.receipt_hash);
    }

    #[test]
    fn visible_outputs_are_level_scoped() {
        let mut kernel = kernel();
        kernel
            .execute_hostcall(
                invocation("fs", SmeHostcallKind::FsRead, SecurityLevel::Internal),
                b"file".to_vec(),
            )
            .unwrap();
        assert_eq!(
            kernel.visible_outputs(SecurityLevel::Public).unwrap().len(),
            0
        );
        assert_eq!(
            kernel
                .visible_outputs(SecurityLevel::Internal)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn runtime_transcript_tracks_delivered_hashes() {
        let mut kernel = kernel();
        kernel
            .execute_hostcall(
                invocation("clock", SmeHostcallKind::ClockRead, SecurityLevel::Public),
                b"now".to_vec(),
            )
            .unwrap();
        let public = kernel.runtime(SecurityLevel::Public).unwrap();
        assert_eq!(
            public.transcript_hashes.len(),
            public.delivered_outputs.len()
        );
    }

    #[test]
    fn standard_hostcall_set_has_ten_representatives() {
        let signatures = standard_hostcall_signatures();
        let kinds = signatures
            .iter()
            .map(|signature| signature.kind.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(signatures.len(), 10);
        assert_eq!(kinds.len(), 10);
    }

    #[test]
    fn standard_hostcall_registration_is_idempotent() {
        let mut kernel = kernel();
        kernel.register_standard_hostcalls();
        kernel.register_standard_hostcalls();
        assert_eq!(kernel.hostcalls.len(), 10);
    }

    #[test]
    fn custom_hostcall_can_be_registered() {
        let mut kernel = kernel();
        let custom = SmeHostcallKind::Custom("tenant.audit".to_string());
        kernel.register_hostcall(HostcallSignature::new(
            custom.clone(),
            SecurityLevel::Confidential,
            SecurityLevel::Confidential,
        ));
        assert!(kernel.hostcalls.contains_key(&custom));
    }

    #[test]
    fn custom_hostcall_obeys_registered_label() {
        let mut kernel = kernel();
        let custom = SmeHostcallKind::Custom("tenant.audit".to_string());
        kernel.register_hostcall(HostcallSignature::new(
            custom.clone(),
            SecurityLevel::Confidential,
            SecurityLevel::Confidential,
        ));
        let receipt = kernel
            .execute_hostcall(
                invocation("audit", custom, SecurityLevel::Confidential),
                b"audit".to_vec(),
            )
            .unwrap();
        assert_eq!(
            receipt.delivered_to,
            BTreeSet::from([SecurityLevel::Confidential, SecurityLevel::Secret])
        );
    }

    #[test]
    fn serde_roundtrip_preserves_kernel_state() {
        let mut kernel = kernel();
        kernel
            .execute_hostcall(
                invocation("clock", SmeHostcallKind::ClockRead, SecurityLevel::Public),
                b"now".to_vec(),
            )
            .unwrap();
        let encoded = serde_json::to_string(&kernel).unwrap();
        let decoded: SecureMultiExecutionKernel = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, kernel);
    }

    #[test]
    fn direct_labeled_delivery_bypasses_hostcall_registry_but_keeps_isolation() {
        let mut kernel = SecureMultiExecutionKernel::with_standard_levels(SecurityEpoch::GENESIS);
        let invocation = invocation("direct", SmeHostcallKind::FsRead, SecurityLevel::Public);
        let receipt = kernel
            .deliver_labeled_output(&invocation, SecurityLevel::Secret, b"secret".to_vec())
            .unwrap();
        assert_eq!(
            receipt.delivered_to,
            BTreeSet::from([SecurityLevel::Secret])
        );
        assert!(kernel.isolation_holds());
    }

    #[test]
    fn lower_runtime_never_receives_higher_output_over_many_labels() {
        let mut kernel = kernel();
        for (index, label) in SecurityLevel::all().iter().copied().enumerate() {
            let invocation = invocation(
                &format!("direct-{index}"),
                SmeHostcallKind::ClockRead,
                SecurityLevel::Secret,
            );
            kernel
                .deliver_labeled_output(&invocation, label, vec![index as u8])
                .unwrap();
        }
        assert!(kernel.isolation_holds());
    }

    #[test]
    fn receipt_records_suppressed_public_for_internal_output() {
        let mut kernel = kernel();
        let receipt = kernel
            .execute_hostcall(
                invocation("env", SmeHostcallKind::EnvRead, SecurityLevel::Internal),
                b"HOME".to_vec(),
            )
            .unwrap();
        assert_eq!(
            receipt.suppressed_from,
            BTreeSet::from([SecurityLevel::Public])
        );
    }
}
