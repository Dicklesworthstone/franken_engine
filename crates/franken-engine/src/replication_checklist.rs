#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicationChecklist {
    pub claim_id: String,
    pub artifact_bundle: String,
    pub independent_reviewer: String,
}

impl ReplicationChecklist {
    pub fn new(
        claim_id: impl Into<String>,
        artifact_bundle: impl Into<String>,
        independent_reviewer: impl Into<String>,
    ) -> Self {
        Self {
            claim_id: claim_id.into(),
            artifact_bundle: artifact_bundle.into(),
            independent_reviewer: independent_reviewer.into(),
        }
    }

    pub fn is_ready_for_replication(&self) -> bool {
        !self.claim_id.trim().is_empty()
            && !self.artifact_bundle.trim().is_empty()
            && !self.independent_reviewer.trim().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replication_checklist_requires_claim_bundle_and_reviewer() {
        let ready = ReplicationChecklist::new(
            "containment-latency-p99",
            "artifacts/scientific_contribution_targets/20260402T041113Z",
            "external-lab",
        );
        let missing_reviewer = ReplicationChecklist::new(
            "containment-latency-p99",
            "artifacts/scientific_contribution_targets/20260402T041113Z",
            " ",
        );

        assert!(ready.is_ready_for_replication());
        assert!(!missing_reviewer.is_ready_for_replication());
    }
}
