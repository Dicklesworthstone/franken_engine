#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> CacheContext {
        CacheContext::new("trace-cache", "decision-cache", "policy-cache")
    }

    fn source_hash(seed: &str) -> ContentHash {
        ContentHash::compute(seed.as_bytes())
    }

    fn trace_key(
        module_id: &str,
        source_seed: &str,
        policy_version: u64,
        trust_revision: u64,
    ) -> ModuleCacheKey {
        ModuleCacheKey::new(
            module_id,
            ModuleVersionFingerprint::new(source_hash(source_seed), policy_version, trust_revision),
        )
    }

    #[test]
    fn cache_trace_corpus_manifest_hash_is_deterministic() {
        let case = CacheTraceCase {
            trace_id: "trace-cache-corpus".to_string(),
            workload_class: CacheWorkloadClass::ColdCompile,
            accesses: vec![
                CacheTraceAccess {
                    sequence: 0,
                    key: trace_key("mod:a", "s1", 1, 1),
                    locality: CacheLocalityClass::Warm,
                },
                CacheTraceAccess {
                    sequence: 1,
                    key: trace_key("mod:b", "s2", 1, 1),
                    locality: CacheLocalityClass::Hot,
                },
            ],
        };

        let left = CacheTraceCorpusManifest::new("corpus.det", vec![case.clone()])
            .expect("serde serialization should succeed");
        let right = CacheTraceCorpusManifest::new("corpus.det", vec![case])
            .expect("serde serialization should succeed");

        assert_eq!(left.corpus_hash, right.corpus_hash);
        assert!(left.validate().is_ok());
    }

    #[test]
    fn cache_trace_corpus_manifest_rejects_duplicate_trace_ids() {
        let case = CacheTraceCase {
            trace_id: "trace-dup".to_string(),
            workload_class: CacheWorkloadClass::WarmRun,
            accesses: vec![CacheTraceAccess {
                sequence: 1,
                key: trace_key("mod:a", "s1", 1, 1),
                locality: CacheLocalityClass::Warm,
            }],
        };

        let err =
            CacheTraceCorpusManifest::new("corpus.dup", vec![case.clone(), case]).unwrap_err();
        match err {
            CachePolicyReportError::DuplicateTraceId { trace_id } => {
                assert_eq!(trace_id, "trace-dup")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn cache_trace_case_rejects_non_monotonic_sequence_numbers() {
        let err = CacheTraceCorpusManifest::new(
            "corpus.sequence",
            vec![CacheTraceCase {
                trace_id: "trace-sequence".to_string(),
                workload_class: CacheWorkloadClass::WarmRun,
                accesses: vec![
                    CacheTraceAccess {
                        sequence: 2,
                        key: trace_key("mod:a", "s1", 1, 1),
                        locality: CacheLocalityClass::Warm,
                    },
                    CacheTraceAccess {
                        sequence: 2,
                        key: trace_key("mod:b", "s2", 1, 1),
                        locality: CacheLocalityClass::Warm,
                    },
                ],
            }],
        )
        .unwrap_err();

        match err {
            CachePolicyReportError::NonMonotonicTraceSequence {
                trace_id,
                previous,
                actual,
            } => {
                assert_eq!(trace_id, "trace-sequence");
                assert_eq!(previous, 2);
                assert_eq!(actual, 2);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn s3fifo_adoption_wedge_default_is_valid() {
        let wedge = S3FifoAdoptionWedgeContract::default();
        assert!(wedge.validate().is_ok());
    }

    #[test]
    fn default_s3fifo_corpus_covers_declared_workloads_deterministically() {
        let left = default_s3fifo_trace_corpus_manifest().expect("corpus should be valid");
        let right = default_s3fifo_trace_corpus_manifest().expect("corpus should be valid");

        assert_eq!(left, right);
        assert_eq!(left.cases.len(), 5);
        assert_eq!(
            left.cases[0].workload_class,
            CacheWorkloadClass::ColdCompile
        );
        assert_eq!(left.cases[1].workload_class, CacheWorkloadClass::WarmRun);
        assert_eq!(
            left.cases[2].workload_class,
            CacheWorkloadClass::PackageGraph
        );
        assert_eq!(left.cases[3].workload_class, CacheWorkloadClass::ReactApp);
        assert_eq!(left.cases[4].workload_class, CacheWorkloadClass::ScanHeavy);
    }

    #[test]
    fn default_s3fifo_baseline_report_is_reproducible() {
        let manifest = default_s3fifo_trace_corpus_manifest().expect("corpus should be valid");
        let left = default_s3fifo_baseline_report().expect("left report should build");
        let right = default_s3fifo_baseline_report().expect("right report should build");

        assert_eq!(left, right);
        assert_eq!(left.baseline_policy_name, "single_queue_fifo");
        assert_eq!(left.candidate_policy_name, "s3_fifo");
        left.validate(&manifest).expect("report should validate");
    }

    #[test]
    fn evaluate_s3fifo_baseline_rejects_invalid_candidate_config() {
        let manifest = CacheTraceCorpusManifest::new(
            "corpus.invalid",
            vec![CacheTraceCase {
                trace_id: "trace-invalid".to_string(),
                workload_class: CacheWorkloadClass::WarmRun,
                accesses: vec![CacheTraceAccess {
                    sequence: 0,
                    key: trace_key("mod:a", "s1", 1, 1),
                    locality: CacheLocalityClass::Warm,
                }],
            }],
        )
        .expect("serde serialization should succeed");

        let err = evaluate_s3fifo_baseline(
            &manifest,
            &SingleQueueFifoConfig {
                capacity_entries: 2,
            },
            &S3FifoConfig {
                resident_capacity_entries: 2,
                small_queue_entries: 2,
                ghost_queue_entries: 1,
            },
            &S3FifoAdoptionWedgeContract::default(),
        )
        .unwrap_err();

        match err {
            CachePolicyReportError::InvalidConfig { field, .. } => {
                assert_eq!(field, "small_queue_entries")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn s3fifo_candidate_records_ghost_hits() {
        let manifest = CacheTraceCorpusManifest::new(
            "corpus.ghost-hit",
            vec![CacheTraceCase {
                trace_id: "trace-ghost-hit".to_string(),
                workload_class: CacheWorkloadClass::ScanHeavy,
                accesses: vec![
                    CacheTraceAccess {
                        sequence: 0,
                        key: trace_key("mod:a", "s1", 1, 1),
                        locality: CacheLocalityClass::Warm,
                    },
                    CacheTraceAccess {
                        sequence: 1,
                        key: trace_key("mod:b", "s2", 1, 1),
                        locality: CacheLocalityClass::Warm,
                    },
                    CacheTraceAccess {
                        sequence: 2,
                        key: trace_key("mod:c", "s3", 1, 1),
                        locality: CacheLocalityClass::Warm,
                    },
                    CacheTraceAccess {
                        sequence: 3,
                        key: trace_key("mod:a", "s1", 1, 1),
                        locality: CacheLocalityClass::Warm,
                    },
                ],
            }],
        )
        .expect("serde serialization should succeed");

        let report = evaluate_s3fifo_baseline(
            &manifest,
            &SingleQueueFifoConfig {
                capacity_entries: 2,
            },
            &S3FifoConfig {
                resident_capacity_entries: 2,
                small_queue_entries: 1,
                ghost_queue_entries: 2,
            },
            &S3FifoAdoptionWedgeContract::default(),
        )
        .expect("serde serialization should succeed");

        assert_eq!(report.cases.len(), 1);
        assert_eq!(report.cases[0].candidate.ghost_hit_count, 1);
        assert_eq!(report.cases[0].baseline.ghost_hit_count, 0);
        assert!(report.validate(&manifest).is_ok());
    }

    #[test]
    fn s3fifo_candidate_improves_hot_retention_and_scan_pollution() {
        let manifest = CacheTraceCorpusManifest::new(
            "corpus.hot-scan",
            vec![CacheTraceCase {
                trace_id: "trace-hot-scan".to_string(),
                workload_class: CacheWorkloadClass::ReactApp,
                accesses: vec![
                    CacheTraceAccess {
                        sequence: 0,
                        key: trace_key("mod:a", "s1", 1, 1),
                        locality: CacheLocalityClass::Hot,
                    },
                    CacheTraceAccess {
                        sequence: 1,
                        key: trace_key("mod:b", "s2", 1, 1),
                        locality: CacheLocalityClass::Hot,
                    },
                    CacheTraceAccess {
                        sequence: 2,
                        key: trace_key("mod:a", "s1", 1, 1),
                        locality: CacheLocalityClass::Hot,
                    },
                    CacheTraceAccess {
                        sequence: 3,
                        key: trace_key("mod:b", "s2", 1, 1),
                        locality: CacheLocalityClass::Hot,
                    },
                    CacheTraceAccess {
                        sequence: 4,
                        key: trace_key("mod:c", "s3", 1, 1),
                        locality: CacheLocalityClass::Scan,
                    },
                    CacheTraceAccess {
                        sequence: 5,
                        key: trace_key("mod:d", "s4", 1, 1),
                        locality: CacheLocalityClass::Scan,
                    },
                    CacheTraceAccess {
                        sequence: 6,
                        key: trace_key("mod:e", "s5", 1, 1),
                        locality: CacheLocalityClass::Scan,
                    },
                    CacheTraceAccess {
                        sequence: 7,
                        key: trace_key("mod:f", "s6", 1, 1),
                        locality: CacheLocalityClass::Scan,
                    },
                ],
            }],
        )
        .expect("serde serialization should succeed");

        let report = evaluate_s3fifo_baseline(
            &manifest,
            &SingleQueueFifoConfig {
                capacity_entries: 4,
            },
            &S3FifoConfig {
                resident_capacity_entries: 4,
                small_queue_entries: 2,
                ghost_queue_entries: 4,
            },
            &S3FifoAdoptionWedgeContract::default(),
        )
        .expect("serde serialization should succeed");

        let case = &report.cases[0];
        assert_eq!(case.baseline.hot_retention_millionths, 0);
        assert_eq!(case.candidate.hot_retention_millionths, 1_000_000);
        assert!(case.candidate.scan_pollution_millionths < case.baseline.scan_pollution_millionths);
        assert_eq!(report.aggregate.improved_hot_retention_cases, 1);
        assert_eq!(report.aggregate.reduced_scan_pollution_cases, 1);
        assert!(report.validate(&manifest).is_ok());
    }

    #[test]
    fn cache_hit_then_miss_after_source_update() {
        let mut cache = ModuleCache::new();
        let v1 = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);

        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:a",
                    v1.clone(),
                    ContentHash::compute(b"artifact-a"),
                    "/app/a.js",
                ),
                &context(),
            )
            .expect("serde serialization should succeed");
        assert!(cache.get("mod:a", &v1).is_some());

        let v2_hash = source_hash("v2");
        cache.invalidate_source_update("mod:a", v2_hash, &context());
        assert!(cache.get("mod:a", &v1).is_none());

        let v2 = ModuleVersionFingerprint::new(v2_hash, 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:a",
                    v2.clone(),
                    ContentHash::compute(b"artifact-a-v2"),
                    "/app/a.js",
                ),
                &context(),
            )
            .expect("serde serialization should succeed");
        assert!(cache.get("mod:a", &v2).is_some());
    }

    #[test]
    fn trust_revocation_removes_entries_and_blocks_insert() {
        let mut cache = ModuleCache::new();
        let version = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);

        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:revoked",
                    version.clone(),
                    ContentHash::compute(b"artifact"),
                    "/app/revoked.js",
                ),
                &context(),
            )
            .expect("serde serialization should succeed");

        cache.invalidate_trust_revocation("mod:revoked", 2, &context());
        assert!(cache.get("mod:revoked", &version).is_none());

        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "mod:revoked",
                    ModuleVersionFingerprint::new(source_hash("v2"), 1, 2),
                    ContentHash::compute(b"artifact2"),
                    "/app/revoked.js",
                ),
                &context(),
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::ModuleRevoked);

        cache.restore_trust("mod:revoked", 3, &context());
        let restored = ModuleVersionFingerprint::new(source_hash("v2"), 1, 3);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:revoked",
                    restored.clone(),
                    ContentHash::compute(b"artifact3"),
                    "/app/revoked.js",
                ),
                &context(),
            )
            .expect("serde serialization should succeed");
        assert!(cache.get("mod:revoked", &restored).is_some());
    }

    #[test]
    fn policy_change_invalidates_stale_entries() {
        let mut cache = ModuleCache::new();
        let v1 = ModuleVersionFingerprint::new(source_hash("stable"), 1, 1);

        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:p",
                    v1.clone(),
                    ContentHash::compute(b"artifact-p"),
                    "/app/p.js",
                ),
                &context(),
            )
            .expect("serde serialization should succeed");

        cache.invalidate_policy_change("mod:p", 2, &context());
        assert!(cache.get("mod:p", &v1).is_none());

        let v2 = ModuleVersionFingerprint::new(source_hash("stable"), 2, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:p",
                    v2.clone(),
                    ContentHash::compute(b"artifact-p2"),
                    "/app/p.js",
                ),
                &context(),
            )
            .expect("serde serialization should succeed");
        assert!(cache.get("mod:p", &v2).is_some());
    }

    #[test]
    fn policy_change_is_monotonic_on_version() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let latest = ModuleVersionFingerprint::new(source_hash("stable"), 5, 1);

        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:p-monotonic",
                    latest.clone(),
                    ContentHash::compute(b"artifact-p5"),
                    "/app/p.js",
                ),
                &ctx,
            )
            .expect("serde serialization should succeed");

        cache.invalidate_policy_change("mod:p-monotonic", 3, &ctx);

        let snap = cache.snapshot();
        assert_eq!(
            snap.latest_versions["mod:p-monotonic"].policy_version,
            latest.policy_version
        );
        assert!(cache.get("mod:p-monotonic", &latest).is_some());

        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "mod:p-monotonic",
                    ModuleVersionFingerprint::new(source_hash("older"), 4, 1),
                    ContentHash::compute(b"artifact-p4"),
                    "/app/p.js",
                ),
                &ctx,
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::VersionRegression);
    }

    #[test]
    fn deterministic_state_hash_for_identical_sequences() {
        let build = || {
            let mut cache = ModuleCache::new();
            let ctx = context();
            let v1 = ModuleVersionFingerprint::new(source_hash("s1"), 1, 1);
            cache
                .insert(
                    CacheInsertRequest::new(
                        "mod:x",
                        v1,
                        ContentHash::compute(b"artifact-x"),
                        "/app/x.js",
                    ),
                    &ctx,
                )
                .expect("serde serialization should succeed");
            cache.invalidate_policy_change("mod:x", 2, &ctx);
            let v2 = ModuleVersionFingerprint::new(source_hash("s1"), 2, 1);
            cache
                .insert(
                    CacheInsertRequest::new(
                        "mod:x",
                        v2,
                        ContentHash::compute(b"artifact-x2"),
                        "/app/x.js",
                    ),
                    &ctx,
                )
                .expect("serde serialization should succeed");
            cache.state_hash()
        };

        assert_eq!(build(), build());
    }

    #[test]
    fn snapshot_merge_converges_revocation_state() {
        let ctx = context();

        let mut a = ModuleCache::new();
        let mut b = ModuleCache::new();

        let version = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        a.insert(
            CacheInsertRequest::new(
                "mod:c",
                version,
                ContentHash::compute(b"artifact-c"),
                "/app/c.js",
            ),
            &ctx,
        )
        .expect("serde serialization should succeed");

        b.invalidate_trust_revocation("mod:c", 2, &ctx);

        let b_snapshot = b.snapshot();
        a.merge_snapshot(&b_snapshot, &ctx);

        let a_snapshot = a.snapshot();
        b.merge_snapshot(&a_snapshot, &ctx);

        assert_eq!(a.state_hash(), b.state_hash());
        assert!(a.revoked_modules.contains("mod:c"));
        assert!(b.revoked_modules.contains("mod:c"));
    }

    #[test]
    fn events_emit_required_structured_fields() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        cache.invalidate_trust_revocation("mod:e", 1, &ctx);

        let event = cache
            .events()
            .last()
            .expect("serde serialization should succeed");
        assert_eq!(event.component, "module_cache");
        assert_eq!(event.trace_id, "trace-cache");
        assert_eq!(event.decision_id, "decision-cache");
        assert_eq!(event.policy_id, "policy-cache");
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
        assert!(!event.error_code.is_empty());
    }

    // -----------------------------------------------------------------------
    // Empty module ID rejection
    // -----------------------------------------------------------------------

    #[test]
    fn insert_empty_module_id_returns_empty_module_id_error() {
        let mut cache = ModuleCache::new();
        let version = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "",
                    version,
                    ContentHash::compute(b"artifact"),
                    "/app/empty.js",
                ),
                &context(),
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::EmptyModuleId);
        assert_eq!(err.code.stable_code(), "FE-MODCACHE-0003");
    }

    #[test]
    fn insert_whitespace_only_module_id_returns_empty_module_id_error() {
        let mut cache = ModuleCache::new();
        let version = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "   ",
                    version,
                    ContentHash::compute(b"artifact"),
                    "/app/ws.js",
                ),
                &context(),
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::EmptyModuleId);
    }

    // -----------------------------------------------------------------------
    // Version regression
    // -----------------------------------------------------------------------

    #[test]
    fn policy_version_regression_returns_version_regression_error() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 5, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:reg", v1, ContentHash::compute(b"a1"), "/app/reg.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");

        let v2_regressed = ModuleVersionFingerprint::new(source_hash("s2"), 3, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "mod:reg",
                    v2_regressed,
                    ContentHash::compute(b"a2"),
                    "/app/reg.js",
                ),
                &ctx,
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::VersionRegression);
        assert_eq!(err.code.stable_code(), "FE-MODCACHE-0002");
    }

    #[test]
    fn trust_revision_regression_returns_version_regression_error() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 1, 5);
        cache
            .insert(
                CacheInsertRequest::new("mod:tr", v1, ContentHash::compute(b"a1"), "/app/tr.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");

        let v2_regressed = ModuleVersionFingerprint::new(source_hash("s2"), 1, 3);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "mod:tr",
                    v2_regressed,
                    ContentHash::compute(b"a2"),
                    "/app/tr.js",
                ),
                &ctx,
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::VersionRegression);
    }

    // -----------------------------------------------------------------------
    // Get edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn get_unknown_module_returns_none() {
        let cache = ModuleCache::new();
        let version = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        assert!(cache.get("mod:unknown", &version).is_none());
    }

    #[test]
    fn get_with_stale_version_returns_none() {
        let mut cache = ModuleCache::new();
        let v1 = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:stale",
                    v1.clone(),
                    ContentHash::compute(b"a1"),
                    "/app/stale.js",
                ),
                &context(),
            )
            .expect("serde serialization should succeed");

        let v2 = ModuleVersionFingerprint::new(source_hash("v2"), 2, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:stale",
                    v2,
                    ContentHash::compute(b"a2"),
                    "/app/stale.js",
                ),
                &context(),
            )
            .expect("serde serialization should succeed");

        // v1 is now stale
        assert!(cache.get("mod:stale", &v1).is_none());
    }

    // -----------------------------------------------------------------------
    // Multiple modules
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_modules_coexist_independently() {
        let mut cache = ModuleCache::new();
        let ctx = context();

        let va = ModuleVersionFingerprint::new(source_hash("a"), 1, 1);
        let vb = ModuleVersionFingerprint::new(source_hash("b"), 1, 1);

        cache
            .insert(
                CacheInsertRequest::new("mod:a", va.clone(), ContentHash::compute(b"aa"), "/a.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        cache
            .insert(
                CacheInsertRequest::new("mod:b", vb.clone(), ContentHash::compute(b"bb"), "/b.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");

        assert!(cache.get("mod:a", &va).is_some());
        assert!(cache.get("mod:b", &vb).is_some());

        // Revoke a, b should still be accessible
        cache.invalidate_trust_revocation("mod:a", 2, &ctx);
        assert!(cache.get("mod:a", &va).is_none());
        assert!(cache.get("mod:b", &vb).is_some());
    }

    // -----------------------------------------------------------------------
    // CacheErrorCode stable codes
    // -----------------------------------------------------------------------

    #[test]
    fn all_cache_error_codes_have_fe_modcache_prefix() {
        let codes = [
            CacheErrorCode::ModuleRevoked,
            CacheErrorCode::VersionRegression,
            CacheErrorCode::EmptyModuleId,
        ];
        for code in &codes {
            let stable = code.stable_code();
            assert!(
                stable.starts_with("FE-MODCACHE-"),
                "stable_code {} must start with FE-MODCACHE-",
                stable
            );
        }
    }

    #[test]
    fn cache_error_codes_are_unique() {
        let codes = [
            CacheErrorCode::ModuleRevoked.stable_code(),
            CacheErrorCode::VersionRegression.stable_code(),
            CacheErrorCode::EmptyModuleId.stable_code(),
        ];
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len(), "all stable codes must be unique");
    }

    // -----------------------------------------------------------------------
    // CacheError Display
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_display_includes_stable_code_and_message() {
        let mut cache = ModuleCache::new();
        let version = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new("", version, ContentHash::compute(b"a"), "/app/e.js"),
                &context(),
            )
            .unwrap_err();
        let display = format!("{err}");
        assert!(display.contains("FE-MODCACHE-0003"));
        assert!(display.contains("must not be empty"));
    }

    // -----------------------------------------------------------------------
    // Snapshot
    // -----------------------------------------------------------------------

    #[test]
    fn empty_cache_snapshot_has_deterministic_state_hash() {
        let a = ModuleCache::new();
        let b = ModuleCache::new();
        assert_eq!(a.state_hash(), b.state_hash());
        let snap = a.snapshot();
        assert!(snap.entries.is_empty());
        assert!(snap.latest_versions.is_empty());
        assert!(snap.revoked_modules.is_empty());
    }

    #[test]
    fn snapshot_contains_all_current_entries() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s1"), 1, 1);
        let v2 = ModuleVersionFingerprint::new(source_hash("s2"), 1, 1);

        cache
            .insert(
                CacheInsertRequest::new("mod:x", v1, ContentHash::compute(b"ax"), "/x.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        cache
            .insert(
                CacheInsertRequest::new("mod:y", v2, ContentHash::compute(b"ay"), "/y.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");

        let snap = cache.snapshot();
        assert_eq!(snap.entries.len(), 2);
        assert_eq!(snap.latest_versions.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Merge snapshot
    // -----------------------------------------------------------------------

    #[test]
    fn merge_snapshot_adopts_newer_versions() {
        let ctx = context();
        let mut local = ModuleCache::new();
        let mut remote = ModuleCache::new();

        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let v2 = ModuleVersionFingerprint::new(source_hash("s"), 2, 1);

        local
            .insert(
                CacheInsertRequest::new("mod:m", v1.clone(), ContentHash::compute(b"a1"), "/m.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        remote
            .insert(
                CacheInsertRequest::new("mod:m", v2.clone(), ContentHash::compute(b"a2"), "/m.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");

        let remote_snap = remote.snapshot();
        local.merge_snapshot(&remote_snap, &ctx);

        // After merge, only v2 should be accessible (v1 is stale)
        assert!(local.get("mod:m", &v1).is_none());
        assert!(local.get("mod:m", &v2).is_some());
    }

    // -----------------------------------------------------------------------
    // Canonical value determinism
    // -----------------------------------------------------------------------

    #[test]
    fn module_version_fingerprint_canonical_value_is_deterministic() {
        let fp1 = ModuleVersionFingerprint::new(source_hash("stable"), 3, 7);
        let fp2 = ModuleVersionFingerprint::new(source_hash("stable"), 3, 7);
        assert_eq!(
            encode_value(&fp1.canonical_value()),
            encode_value(&fp2.canonical_value())
        );
    }

    #[test]
    fn module_cache_key_canonical_value_is_deterministic() {
        let version = ModuleVersionFingerprint::new(source_hash("k"), 1, 1);
        let k1 = ModuleCacheKey::new("mod:det", version.clone());
        let k2 = ModuleCacheKey::new("mod:det", version);
        assert_eq!(
            encode_value(&k1.canonical_value()),
            encode_value(&k2.canonical_value())
        );
    }

    // -----------------------------------------------------------------------
    // Event sequence monotonicity
    // -----------------------------------------------------------------------

    #[test]
    fn event_sequences_are_monotonically_increasing() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("ev"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:ev", v1, ContentHash::compute(b"a"), "/ev.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        cache.invalidate_trust_revocation("mod:ev", 2, &ctx);
        cache.restore_trust("mod:ev", 3, &ctx);

        let seqs: Vec<u64> = cache.events().iter().map(|e| e.seq).collect();
        for window in seqs.windows(2) {
            assert!(
                window[1] > window[0],
                "event seq must be monotonically increasing: {:?}",
                seqs
            );
        }
    }

    // -----------------------------------------------------------------------
    // Serde round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_code_serde_round_trip() {
        let codes = [
            CacheErrorCode::ModuleRevoked,
            CacheErrorCode::VersionRegression,
            CacheErrorCode::EmptyModuleId,
        ];
        for code in &codes {
            let json = serde_json::to_string(code).expect("serde serialization should succeed");
            let decoded: CacheErrorCode =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(&decoded, code);
        }
    }

    #[test]
    fn module_version_fingerprint_serde_round_trip() {
        let fp = ModuleVersionFingerprint::new(source_hash("serde-test"), 42, 7);
        let json = serde_json::to_string(&fp).expect("serde serialization should succeed");
        let decoded: ModuleVersionFingerprint =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded, fp);
    }

    #[test]
    fn cache_snapshot_serde_round_trip() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("snap"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:snap", v, ContentHash::compute(b"as"), "/snap.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");

        let snap = cache.snapshot();
        let json = serde_json::to_string(&snap).expect("serde serialization should succeed");
        let decoded: CacheSnapshot =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded, snap);
    }

    // -----------------------------------------------------------------------
    // Invalidate source update on unknown module
    // -----------------------------------------------------------------------

    #[test]
    fn invalidate_source_update_on_unknown_module_creates_version_entry() {
        let mut cache = ModuleCache::new();
        cache.invalidate_source_update("mod:new", source_hash("fresh"), &context());
        let snap = cache.snapshot();
        assert!(snap.latest_versions.contains_key("mod:new"));
    }

    // -----------------------------------------------------------------------
    // Forward version upgrade succeeds
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Serde round-trips (enrichment)
    // -----------------------------------------------------------------------

    #[test]
    fn module_cache_key_serde_round_trip() {
        let key = ModuleCacheKey::new(
            "mod:serde",
            ModuleVersionFingerprint::new(source_hash("k"), 3, 7),
        );
        let json = serde_json::to_string(&key).expect("serde serialization should succeed");
        let decoded: ModuleCacheKey =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded, key);
    }

    #[test]
    fn module_cache_entry_serde_round_trip() {
        let key = ModuleCacheKey::new(
            "mod:entry",
            ModuleVersionFingerprint::new(source_hash("e"), 1, 1),
        );
        let entry = ModuleCacheEntry {
            key,
            artifact_hash: ContentHash::compute(b"artifact-serde"),
            resolved_specifier: "/app/entry.js".to_string(),
            inserted_seq: 42,
        };
        let json = serde_json::to_string(&entry).expect("serde serialization should succeed");
        let decoded: ModuleCacheEntry =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded, entry);
    }

    #[test]
    fn cache_insert_request_serde_round_trip() {
        let req = CacheInsertRequest::new(
            "mod:req",
            ModuleVersionFingerprint::new(source_hash("r"), 2, 3),
            ContentHash::compute(b"art-req"),
            "/req.js",
        );
        let json = serde_json::to_string(&req).expect("serde serialization should succeed");
        let decoded: CacheInsertRequest =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded, req);
    }

    #[test]
    fn cache_context_serde_round_trip() {
        let ctx = CacheContext::new("t1", "d1", "p1");
        let json = serde_json::to_string(&ctx).expect("serde serialization should succeed");
        let decoded: CacheContext =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded, ctx);
    }

    #[test]
    fn cache_event_serde_round_trip() {
        let mut cache = ModuleCache::new();
        cache.invalidate_source_update("mod:ev-serde", source_hash("x"), &context());
        let event = cache
            .events()
            .last()
            .expect("serde serialization should succeed")
            .clone();
        let json = serde_json::to_string(&event).expect("serde serialization should succeed");
        let decoded: CacheEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded, event);
    }

    #[test]
    fn cache_error_serde_round_trip() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new("", v, ContentHash::compute(b"a"), "/e.js"),
                &context(),
            )
            .unwrap_err();
        let json = serde_json::to_string(&*err).expect("serde serialization should succeed");
        let decoded: CacheError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded, *err);
    }

    #[test]
    fn module_cache_snapshot_captures_revoked_and_entries() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("mc"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:mc", v, ContentHash::compute(b"art"), "/mc.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        cache.invalidate_trust_revocation("mod:revoked", 1, &ctx);
        let snap = cache.snapshot();
        // Snapshot roundtrips through JSON (unlike ModuleCache which has non-string map keys)
        let json = serde_json::to_string(&snap).expect("serde serialization should succeed");
        let decoded: CacheSnapshot =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded, snap);
        assert_eq!(snap.entries.len(), 1);
        assert!(snap.revoked_modules.contains("mod:revoked"));
    }

    // -----------------------------------------------------------------------
    // CacheErrorCode serde uses snake_case
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_code_serde_uses_snake_case() {
        let json = serde_json::to_string(&CacheErrorCode::ModuleRevoked)
            .expect("serde serialization should succeed");
        assert_eq!(json, "\"module_revoked\"");
        let json = serde_json::to_string(&CacheErrorCode::VersionRegression)
            .expect("serde serialization should succeed");
        assert_eq!(json, "\"version_regression\"");
        let json = serde_json::to_string(&CacheErrorCode::EmptyModuleId)
            .expect("serde serialization should succeed");
        assert_eq!(json, "\"empty_module_id\"");
    }

    // -----------------------------------------------------------------------
    // CacheError Display for all error codes
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_display_module_revoked() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:rd", v, ContentHash::compute(b"a"), "/r.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        cache.invalidate_trust_revocation("mod:rd", 2, &ctx);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "mod:rd",
                    ModuleVersionFingerprint::new(source_hash("s2"), 1, 2),
                    ContentHash::compute(b"a2"),
                    "/r.js",
                ),
                &ctx,
            )
            .unwrap_err();
        let display = format!("{err}");
        assert!(display.contains("FE-MODCACHE-0001"), "got: {display}");
        assert!(display.contains("revoked"), "got: {display}");
    }

    #[test]
    fn cache_error_display_version_regression() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 5, 5);
        cache
            .insert(
                CacheInsertRequest::new("mod:vr", v1, ContentHash::compute(b"a1"), "/vr.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        let v2 = ModuleVersionFingerprint::new(source_hash("s2"), 3, 5);
        let err = cache
            .insert(
                CacheInsertRequest::new("mod:vr", v2, ContentHash::compute(b"a2"), "/vr.js"),
                &ctx,
            )
            .unwrap_err();
        let display = format!("{err}");
        assert!(display.contains("FE-MODCACHE-0002"), "got: {display}");
        assert!(display.contains("regression"), "got: {display}");
    }

    // -----------------------------------------------------------------------
    // Default trait
    // -----------------------------------------------------------------------

    #[test]
    fn module_cache_default_equals_new() {
        let a = ModuleCache::new();
        let b = ModuleCache::default();
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------------
    // Invalidation on unknown modules
    // -----------------------------------------------------------------------

    #[test]
    fn invalidate_policy_change_on_unknown_module_creates_version_entry() {
        let mut cache = ModuleCache::new();
        cache.invalidate_policy_change("mod:unknown-policy", 5, &context());
        let snap = cache.snapshot();
        assert!(snap.latest_versions.contains_key("mod:unknown-policy"));
        assert_eq!(snap.latest_versions["mod:unknown-policy"].policy_version, 5);
    }

    #[test]
    fn invalidate_trust_revocation_on_unknown_module_marks_revoked() {
        let mut cache = ModuleCache::new();
        cache.invalidate_trust_revocation("mod:unknown-trust", 3, &context());
        let snap = cache.snapshot();
        assert!(snap.revoked_modules.contains("mod:unknown-trust"));
        assert!(snap.latest_versions.contains_key("mod:unknown-trust"));
    }

    // -----------------------------------------------------------------------
    // restore_trust edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn restore_trust_on_non_revoked_module_is_harmless() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:nr", v.clone(), ContentHash::compute(b"a"), "/nr.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        let hash_before = cache.state_hash();
        cache.restore_trust("mod:nr", 2, &ctx);
        // Module still accessible, trust_revision may advance
        assert!(cache.get("mod:nr", &v).is_none()); // version changed (trust_revision bumped)
        // But hash should differ since latest_versions changed
        assert_ne!(cache.state_hash(), hash_before);
    }

    #[test]
    fn restore_trust_on_unknown_module_creates_entry() {
        let mut cache = ModuleCache::new();
        cache.restore_trust("mod:ghost", 1, &context());
        let snap = cache.snapshot();
        assert!(snap.latest_versions.contains_key("mod:ghost"));
        assert!(!snap.revoked_modules.contains("mod:ghost"));
    }

    // -----------------------------------------------------------------------
    // Merge snapshot edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn merge_empty_remote_snapshot_is_noop() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:local",
                    v.clone(),
                    ContentHash::compute(b"a"),
                    "/l.js",
                ),
                &ctx,
            )
            .expect("serde serialization should succeed");
        let hash_before = cache.state_hash();
        let empty_snap = ModuleCache::new().snapshot();
        cache.merge_snapshot(&empty_snap, &ctx);
        assert_eq!(cache.state_hash(), hash_before);
        assert!(cache.get("mod:local", &v).is_some());
    }

    #[test]
    fn merge_into_empty_local_adopts_remote_entries() {
        let mut remote = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("r"), 1, 1);
        remote
            .insert(
                CacheInsertRequest::new(
                    "mod:remote",
                    v.clone(),
                    ContentHash::compute(b"ar"),
                    "/r.js",
                ),
                &ctx,
            )
            .expect("serde serialization should succeed");
        let remote_snap = remote.snapshot();

        let mut local = ModuleCache::new();
        local.merge_snapshot(&remote_snap, &ctx);
        assert!(local.get("mod:remote", &v).is_some());
    }

    #[test]
    fn merge_does_not_import_revoked_module_entries() {
        let mut remote = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        remote
            .insert(
                CacheInsertRequest::new("mod:willrevoke", v, ContentHash::compute(b"a"), "/w.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        remote.invalidate_trust_revocation("mod:willrevoke", 2, &ctx);
        let remote_snap = remote.snapshot();

        let mut local = ModuleCache::new();
        local.merge_snapshot(&remote_snap, &ctx);
        assert!(local.revoked_modules.contains("mod:willrevoke"));
        assert!(local.entries.is_empty());
    }

    // -----------------------------------------------------------------------
    // State hash changes after operations
    // -----------------------------------------------------------------------

    #[test]
    fn state_hash_changes_after_insert() {
        let mut cache = ModuleCache::new();
        let hash_empty = cache.state_hash();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:sh", v, ContentHash::compute(b"a"), "/sh.js"),
                &context(),
            )
            .expect("serde serialization should succeed");
        assert_ne!(cache.state_hash(), hash_empty);
    }

    #[test]
    fn state_hash_changes_after_revocation() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:hr", v, ContentHash::compute(b"a"), "/hr.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        let hash_before = cache.state_hash();
        cache.invalidate_trust_revocation("mod:hr", 2, &ctx);
        assert_ne!(cache.state_hash(), hash_before);
    }

    // -----------------------------------------------------------------------
    // Ordering tests
    // -----------------------------------------------------------------------

    #[test]
    fn module_version_fingerprint_ordering() {
        let a = ModuleVersionFingerprint::new(source_hash("a"), 1, 1);
        let b = ModuleVersionFingerprint::new(source_hash("a"), 2, 1);
        let c = ModuleVersionFingerprint::new(source_hash("a"), 2, 2);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn module_cache_key_ordering() {
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let ka = ModuleCacheKey::new("aaa", v.clone());
        let kb = ModuleCacheKey::new("bbb", v);
        assert!(ka < kb);
    }

    // -----------------------------------------------------------------------
    // Error event fields
    // -----------------------------------------------------------------------

    #[test]
    fn error_event_records_correct_fields() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let _ = cache.insert(
            CacheInsertRequest::new("", v, ContentHash::compute(b"a"), "/e.js"),
            &context(),
        );
        let event = cache
            .events()
            .last()
            .expect("serde serialization should succeed");
        assert_eq!(event.component, "module_cache");
        assert_eq!(event.event, "cache_insert");
        assert_eq!(event.outcome, "deny");
        assert_eq!(event.error_code, "FE-MODCACHE-0003");
        assert_eq!(event.module_id, "<empty>");
    }

    // -----------------------------------------------------------------------
    // ModuleCacheEntry canonical value determinism
    // -----------------------------------------------------------------------

    #[test]
    fn module_cache_entry_canonical_value_is_deterministic() {
        let key = ModuleCacheKey::new(
            "mod:det2",
            ModuleVersionFingerprint::new(source_hash("d"), 1, 1),
        );
        let entry = ModuleCacheEntry {
            key,
            artifact_hash: ContentHash::compute(b"det-artifact"),
            resolved_specifier: "/det.js".to_string(),
            inserted_seq: 99,
        };
        let bytes1 = encode_value(&entry.canonical_value());
        let bytes2 = encode_value(&entry.canonical_value());
        assert_eq!(bytes1, bytes2);
    }

    // -----------------------------------------------------------------------
    // Forward version upgrade succeeds (existing)
    // -----------------------------------------------------------------------

    #[test]
    fn forward_version_upgrade_succeeds() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:up", v1, ContentHash::compute(b"a1"), "/up.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");

        let v2 = ModuleVersionFingerprint::new(source_hash("s2"), 2, 2);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:up",
                    v2.clone(),
                    ContentHash::compute(b"a2"),
                    "/up.js",
                ),
                &ctx,
            )
            .expect("serde serialization should succeed");

        assert!(cache.get("mod:up", &v2).is_some());
    }

    // -- Enrichment: Display uniqueness, edge cases, std::error --

    #[test]
    fn cache_error_code_display_uniqueness() {
        let codes = [
            CacheErrorCode::ModuleRevoked,
            CacheErrorCode::VersionRegression,
            CacheErrorCode::EmptyModuleId,
        ];
        let displays: BTreeSet<String> =
            codes.iter().map(|c| c.stable_code().to_string()).collect();
        assert_eq!(
            displays.len(),
            3,
            "all 3 error codes produce distinct stable codes"
        );
    }

    #[test]
    fn cache_error_implements_std_error() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new("", v, ContentHash::compute(b"a"), "/e.js"),
                &context(),
            )
            .unwrap_err();
        let dyn_err: &dyn std::error::Error = &*err;
        assert!(!dyn_err.to_string().is_empty());
    }

    #[test]
    fn cache_context_fields_match_construction() {
        let ctx = CacheContext::new("t-abc", "d-def", "p-ghi");
        assert_eq!(ctx.trace_id, "t-abc");
        assert_eq!(ctx.decision_id, "d-def");
        assert_eq!(ctx.policy_id, "p-ghi");
    }

    #[test]
    fn insert_same_version_twice_overwrites() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("same"), 1, 1);
        let art1 = ContentHash::compute(b"artifact-1");
        let art2 = ContentHash::compute(b"artifact-2");

        cache
            .insert(
                CacheInsertRequest::new("mod:dup", v.clone(), art1, "/dup.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        cache
            .insert(
                CacheInsertRequest::new("mod:dup", v.clone(), art2, "/dup.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");

        let entry = cache
            .get("mod:dup", &v)
            .expect("serde serialization should succeed");
        assert_eq!(
            entry.artifact_hash, art2,
            "second insert should overwrite first"
        );
    }

    #[test]
    fn empty_cache_has_no_events() {
        let cache = ModuleCache::new();
        assert!(cache.events().is_empty());
    }

    #[test]
    fn snapshot_revoked_modules_is_btree_set() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        cache.invalidate_trust_revocation("mod:b", 1, &ctx);
        cache.invalidate_trust_revocation("mod:a", 2, &ctx);
        let snap = cache.snapshot();
        let revoked: Vec<&str> = snap.revoked_modules.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            revoked,
            ["mod:a", "mod:b"],
            "revoked modules should be sorted"
        );
    }

    #[test]
    fn module_version_fingerprint_display_fields() {
        let fp = ModuleVersionFingerprint::new(source_hash("display-test"), 10, 20);
        assert_eq!(fp.policy_version, 10);
        assert_eq!(fp.trust_revision, 20);
    }

    // -----------------------------------------------------------------------
    // Copy semantics — CacheErrorCode is Copy
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_code_is_copy() {
        let original = CacheErrorCode::ModuleRevoked;
        let copied = original;
        assert_eq!(original, copied);
    }

    #[test]
    fn cache_error_code_copy_all_variants() {
        let a = CacheErrorCode::VersionRegression;
        let b = a;
        assert_eq!(a.stable_code(), b.stable_code());

        let c = CacheErrorCode::EmptyModuleId;
        let d = c;
        assert_eq!(c.stable_code(), d.stable_code());
    }

    // -----------------------------------------------------------------------
    // Debug distinctness — all enum variants produce distinct Debug output
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_code_debug_is_distinct() {
        let variants = [
            CacheErrorCode::ModuleRevoked,
            CacheErrorCode::VersionRegression,
            CacheErrorCode::EmptyModuleId,
        ];
        let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(
            debugs.len(),
            3,
            "all CacheErrorCode variants have distinct Debug output"
        );
    }

    // -----------------------------------------------------------------------
    // Serde variant distinctness — all enum variants serialize to distinct JSON
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_code_serde_variants_distinct() {
        let variants = [
            CacheErrorCode::ModuleRevoked,
            CacheErrorCode::VersionRegression,
            CacheErrorCode::EmptyModuleId,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).expect("serde serialization should succeed"))
            .collect();
        assert_eq!(
            jsons.len(),
            3,
            "all CacheErrorCode variants serialize to distinct JSON"
        );
    }

    // -----------------------------------------------------------------------
    // Clone independence — mutating a clone doesn't affect the original
    // -----------------------------------------------------------------------

    #[test]
    fn module_version_fingerprint_clone_independence() {
        let original = ModuleVersionFingerprint::new(source_hash("orig"), 3, 7);
        let mut cloned = original.clone();
        cloned.policy_version = 99;
        assert_eq!(original.policy_version, 3);
        assert_ne!(original.policy_version, cloned.policy_version);
    }

    #[test]
    fn cache_context_clone_independence() {
        let original = CacheContext::new("trace-orig", "dec-orig", "pol-orig");
        let mut cloned = original.clone();
        cloned.trace_id = "trace-mutated".to_string();
        assert_eq!(original.trace_id, "trace-orig");
        assert_eq!(cloned.trace_id, "trace-mutated");
    }

    #[test]
    fn module_cache_key_clone_independence() {
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let original = ModuleCacheKey::new("mod:clone-orig", v);
        let mut cloned = original.clone();
        cloned.module_id = "mod:clone-mutated".to_string();
        assert_eq!(original.module_id, "mod:clone-orig");
        assert_eq!(cloned.module_id, "mod:clone-mutated");
    }

    #[test]
    fn cache_insert_request_clone_independence() {
        let req = CacheInsertRequest::new(
            "mod:clone-req",
            ModuleVersionFingerprint::new(source_hash("r"), 1, 1),
            ContentHash::compute(b"art"),
            "/clone.js",
        );
        let mut cloned = req.clone();
        cloned.module_id = "mod:mutated".to_string();
        assert_eq!(req.module_id, "mod:clone-req");
        assert_eq!(cloned.module_id, "mod:mutated");
    }

    // -----------------------------------------------------------------------
    // JSON field-name stability — assert exact field names in serialized output
    // -----------------------------------------------------------------------

    #[test]
    fn module_version_fingerprint_json_field_names() {
        let fp = ModuleVersionFingerprint::new(source_hash("fields"), 1, 1);
        let json = serde_json::to_string(&fp).expect("serde serialization should succeed");
        assert!(json.contains("\"source_hash\""), "got: {json}");
        assert!(json.contains("\"policy_version\""), "got: {json}");
        assert!(json.contains("\"trust_revision\""), "got: {json}");
    }

    #[test]
    fn module_cache_key_json_field_names() {
        let key = ModuleCacheKey::new(
            "mod:fields",
            ModuleVersionFingerprint::new(source_hash("f"), 1, 1),
        );
        let json = serde_json::to_string(&key).expect("serde serialization should succeed");
        assert!(json.contains("\"module_id\""), "got: {json}");
        assert!(json.contains("\"version\""), "got: {json}");
    }

    #[test]
    fn module_cache_entry_json_field_names() {
        let key = ModuleCacheKey::new(
            "mod:entry-fields",
            ModuleVersionFingerprint::new(source_hash("ef"), 1, 1),
        );
        let entry = ModuleCacheEntry {
            key,
            artifact_hash: ContentHash::compute(b"art-f"),
            resolved_specifier: "/entry-f.js".to_string(),
            inserted_seq: 5,
        };
        let json = serde_json::to_string(&entry).expect("serde serialization should succeed");
        assert!(json.contains("\"key\""), "got: {json}");
        assert!(json.contains("\"artifact_hash\""), "got: {json}");
        assert!(json.contains("\"resolved_specifier\""), "got: {json}");
        assert!(json.contains("\"inserted_seq\""), "got: {json}");
    }

    #[test]
    fn cache_context_json_field_names() {
        let ctx = CacheContext::new("t", "d", "p");
        let json = serde_json::to_string(&ctx).expect("serde serialization should succeed");
        assert!(json.contains("\"trace_id\""), "got: {json}");
        assert!(json.contains("\"decision_id\""), "got: {json}");
        assert!(json.contains("\"policy_id\""), "got: {json}");
    }

    #[test]
    fn cache_error_json_field_names() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new("", v, ContentHash::compute(b"a"), "/e.js"),
                &context(),
            )
            .unwrap_err();
        let json = serde_json::to_string(&*err).expect("serde serialization should succeed");
        assert!(json.contains("\"code\""), "got: {json}");
        assert!(json.contains("\"message\""), "got: {json}");
        assert!(json.contains("\"event\""), "got: {json}");
    }

    #[test]
    fn cache_snapshot_json_field_names() {
        let snap = ModuleCache::new().snapshot();
        let json = serde_json::to_string(&snap).expect("serde serialization should succeed");
        assert!(json.contains("\"entries\""), "got: {json}");
        assert!(json.contains("\"latest_versions\""), "got: {json}");
        assert!(json.contains("\"revoked_modules\""), "got: {json}");
        assert!(json.contains("\"state_hash\""), "got: {json}");
    }

    // -----------------------------------------------------------------------
    // Display format checks — exact string assertions for Display impls
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_display_format_exact_separator() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new("", v, ContentHash::compute(b"a"), "/e.js"),
                &context(),
            )
            .unwrap_err();
        let display = format!("{err}");
        // Format is "<stable_code>: <message>"
        assert!(
            display.contains(": "),
            "display must contain ': ' separator; got: {display}"
        );
        assert!(
            display.starts_with("FE-MODCACHE-"),
            "display must start with FE-MODCACHE-; got: {display}"
        );
    }

    #[test]
    fn cache_error_display_module_revoked_code_prefix() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        cache.invalidate_trust_revocation("mod:disp", 1, &ctx);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "mod:disp",
                    ModuleVersionFingerprint::new(source_hash("s"), 1, 1),
                    ContentHash::compute(b"a"),
                    "/d.js",
                ),
                &ctx,
            )
            .unwrap_err();
        let display = format!("{err}");
        assert_eq!(
            display
                .split(": ")
                .next()
                .expect("serde serialization should succeed"),
            "FE-MODCACHE-0001",
            "exact code prefix; got: {display}"
        );
    }

    // -----------------------------------------------------------------------
    // Hash consistency — canonical encoding of equal values is identical
    // (types don't derive Hash; use canonical_value determinism as proxy)
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_code_equality_consistent_with_serde() {
        let a = CacheErrorCode::VersionRegression;
        let b = CacheErrorCode::VersionRegression;
        // Two equal values must serialize identically (our hash-consistency proxy)
        let ja = serde_json::to_string(&a).expect("serde serialization should succeed");
        let jb = serde_json::to_string(&b).expect("serde serialization should succeed");
        assert_eq!(ja, jb);
    }

    #[test]
    fn module_version_fingerprint_equal_values_canonical_identical() {
        let fp1 = ModuleVersionFingerprint::new(source_hash("hash-test"), 7, 13);
        let fp2 = ModuleVersionFingerprint::new(source_hash("hash-test"), 7, 13);
        // Canonical encoding acts as deterministic hash
        assert_eq!(
            encode_value(&fp1.canonical_value()),
            encode_value(&fp2.canonical_value())
        );
    }

    #[test]
    fn module_cache_key_equal_values_canonical_identical() {
        let v1 = ModuleVersionFingerprint::new(source_hash("hk"), 1, 1);
        let v2 = ModuleVersionFingerprint::new(source_hash("hk"), 1, 1);
        let k1 = ModuleCacheKey::new("mod:hash-key", v1);
        let k2 = ModuleCacheKey::new("mod:hash-key", v2);
        assert_eq!(
            encode_value(&k1.canonical_value()),
            encode_value(&k2.canonical_value())
        );
    }

    // -----------------------------------------------------------------------
    // Boundary/edge cases — zero values, u64::MAX, empty strings
    // -----------------------------------------------------------------------

    #[test]
    fn module_version_fingerprint_zero_values() {
        let fp = ModuleVersionFingerprint::new(source_hash("zero"), 0, 0);
        assert_eq!(fp.policy_version, 0);
        assert_eq!(fp.trust_revision, 0);
        let json = serde_json::to_string(&fp).expect("serde serialization should succeed");
        let decoded: ModuleVersionFingerprint =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded, fp);
    }

    #[test]
    fn module_version_fingerprint_u64_max_values() {
        let fp = ModuleVersionFingerprint::new(source_hash("max"), u64::MAX, u64::MAX);
        assert_eq!(fp.policy_version, u64::MAX);
        assert_eq!(fp.trust_revision, u64::MAX);
        let json = serde_json::to_string(&fp).expect("serde serialization should succeed");
        let decoded: ModuleVersionFingerprint =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded, fp);
    }

    #[test]
    fn cache_event_empty_detail_allowed() {
        let mut cache = ModuleCache::new();
        // Trigger an event to check the event detail field type
        cache.invalidate_source_update("mod:edge", source_hash("e"), &context());
        let event = cache
            .events()
            .last()
            .expect("serde serialization should succeed");
        // detail is always a String, even if empty would be allowed
        assert!(event.detail.contains("removed"));
    }

    #[test]
    fn restore_trust_with_zero_revision_preserves_revocation() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:zero-tr",
                    v.clone(),
                    ContentHash::compute(b"a"),
                    "/z.js",
                ),
                &ctx,
            )
            .expect("serde serialization should succeed");
        cache.invalidate_trust_revocation("mod:zero-tr", 1, &ctx);
        let before = cache.snapshot();
        cache.restore_trust("mod:zero-tr", 0, &ctx);
        let snap = cache.snapshot();
        assert!(snap.revoked_modules.contains("mod:zero-tr"));
        assert_eq!(snap, before);
        assert_eq!(cache.events().last().unwrap().outcome, "deny");
    }

    #[test]
    fn insert_after_restore_with_updated_revision() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 1, 5);
        cache
            .insert(
                CacheInsertRequest::new("mod:restore2", v1, ContentHash::compute(b"a1"), "/r2.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        cache.invalidate_trust_revocation("mod:restore2", 10, &ctx);
        // Replaying the revocation's own revision cannot authorize re-admission.
        let before = cache.snapshot();
        cache.restore_trust("mod:restore2", 10, &ctx);
        assert_eq!(cache.snapshot(), before);
        cache.try_restore_trust("mod:restore2", 11, &ctx).unwrap();
        let v2 = ModuleVersionFingerprint::new(source_hash("s2"), 1, 11);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:restore2",
                    v2.clone(),
                    ContentHash::compute(b"a2"),
                    "/r2.js",
                ),
                &ctx,
            )
            .expect("serde serialization should succeed");
        assert!(cache.get("mod:restore2", &v2).is_some());
    }

    #[test]
    fn insert_with_u64_max_policy_version_succeeds() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("max-pol"), u64::MAX, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:max-pol",
                    v.clone(),
                    ContentHash::compute(b"amax"),
                    "/max.js",
                ),
                &ctx,
            )
            .expect("serde serialization should succeed");
        assert!(cache.get("mod:max-pol", &v).is_some());
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips — complex populated structs
    // -----------------------------------------------------------------------

    #[test]
    fn cache_snapshot_with_revoked_and_entries_roundtrip() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        // Insert two modules
        let va = ModuleVersionFingerprint::new(source_hash("sa"), 1, 1);
        let vb = ModuleVersionFingerprint::new(source_hash("sb"), 2, 3);
        cache
            .insert(
                CacheInsertRequest::new("mod:sn-a", va, ContentHash::compute(b"art-a"), "/sn-a.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        cache
            .insert(
                CacheInsertRequest::new("mod:sn-b", vb, ContentHash::compute(b"art-b"), "/sn-b.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        // Revoke one
        cache.invalidate_trust_revocation("mod:sn-revoked", 1, &ctx);
        let snap = cache.snapshot();
        let json = serde_json::to_string(&snap).expect("serde serialization should succeed");
        let decoded: CacheSnapshot =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded.entries.len(), snap.entries.len());
        assert_eq!(decoded.revoked_modules, snap.revoked_modules);
        assert_eq!(decoded.state_hash, snap.state_hash);
        assert_eq!(decoded.latest_versions, snap.latest_versions);
    }

    #[test]
    fn cache_event_serde_all_fields() {
        let mut cache = ModuleCache::new();
        let ctx = CacheContext::new("trace-ev-all", "dec-ev-all", "pol-ev-all");
        let v = ModuleVersionFingerprint::new(source_hash("ev-all"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:ev-all",
                    v,
                    ContentHash::compute(b"art-ev"),
                    "/ev-all.js",
                ),
                &ctx,
            )
            .expect("serde serialization should succeed");
        let event = cache
            .events()
            .last()
            .expect("serde serialization should succeed")
            .clone();
        let json = serde_json::to_string(&event).expect("serde serialization should succeed");
        let decoded: CacheEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded.trace_id, "trace-ev-all");
        assert_eq!(decoded.decision_id, "dec-ev-all");
        assert_eq!(decoded.policy_id, "pol-ev-all");
        assert_eq!(decoded.component, "module_cache");
    }

    // -----------------------------------------------------------------------
    // Debug nonempty — all types produce non-empty Debug output
    // -----------------------------------------------------------------------

    #[test]
    fn module_version_fingerprint_debug_nonempty() {
        let fp = ModuleVersionFingerprint::new(source_hash("dbg"), 1, 1);
        assert!(!format!("{fp:?}").is_empty());
    }

    #[test]
    fn module_cache_key_debug_nonempty() {
        let v = ModuleVersionFingerprint::new(source_hash("dbg-k"), 1, 1);
        let key = ModuleCacheKey::new("mod:dbg", v);
        assert!(!format!("{key:?}").is_empty());
    }

    #[test]
    fn module_cache_entry_debug_nonempty() {
        let key = ModuleCacheKey::new(
            "mod:dbg-e",
            ModuleVersionFingerprint::new(source_hash("dbg-e"), 1, 1),
        );
        let entry = ModuleCacheEntry {
            key,
            artifact_hash: ContentHash::compute(b"dbg-art"),
            resolved_specifier: "/dbg.js".to_string(),
            inserted_seq: 0,
        };
        assert!(!format!("{entry:?}").is_empty());
    }

    #[test]
    fn cache_insert_request_debug_nonempty() {
        let req = CacheInsertRequest::new(
            "mod:dbg-req",
            ModuleVersionFingerprint::new(source_hash("dbg-r"), 1, 1),
            ContentHash::compute(b"dbg-r"),
            "/dbg-r.js",
        );
        assert!(!format!("{req:?}").is_empty());
    }

    #[test]
    fn cache_context_debug_nonempty() {
        let ctx = CacheContext::new("t", "d", "p");
        assert!(!format!("{ctx:?}").is_empty());
    }

    #[test]
    fn cache_event_debug_nonempty() {
        let mut cache = ModuleCache::new();
        cache.invalidate_trust_revocation("mod:dbg-ev", 1, &context());
        let event = cache
            .events()
            .last()
            .expect("serde serialization should succeed");
        assert!(!format!("{event:?}").is_empty());
    }

    #[test]
    fn cache_error_code_debug_nonempty() {
        assert!(!format!("{:?}", CacheErrorCode::ModuleRevoked).is_empty());
        assert!(!format!("{:?}", CacheErrorCode::VersionRegression).is_empty());
        assert!(!format!("{:?}", CacheErrorCode::EmptyModuleId).is_empty());
    }

    #[test]
    fn cache_error_debug_nonempty() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new("", v, ContentHash::compute(b"a"), "/e.js"),
                &context(),
            )
            .unwrap_err();
        assert!(!format!("{err:?}").is_empty());
    }

    #[test]
    fn cache_snapshot_debug_nonempty() {
        let snap = ModuleCache::new().snapshot();
        assert!(!format!("{snap:?}").is_empty());
    }

    #[test]
    fn module_cache_debug_nonempty() {
        let cache = ModuleCache::new();
        assert!(!format!("{cache:?}").is_empty());
    }

    // -----------------------------------------------------------------------
    // Additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_insertions_same_module_event_count_grows() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s1"), 1, 1);
        let v2 = ModuleVersionFingerprint::new(source_hash("s1"), 2, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:evcount", v1, ContentHash::compute(b"a1"), "/ev.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        let count_after_1 = cache.events().len();
        cache
            .insert(
                CacheInsertRequest::new("mod:evcount", v2, ContentHash::compute(b"a2"), "/ev.js"),
                &ctx,
            )
            .expect("serde serialization should succeed");
        let count_after_2 = cache.events().len();
        assert!(count_after_2 > count_after_1);
    }

    #[test]
    fn state_hash_two_empty_caches_are_equal() {
        let a = ModuleCache::new();
        let b = ModuleCache::new();
        assert_eq!(a.state_hash(), b.state_hash());
    }

    #[test]
    fn invalidate_policy_change_preserves_other_modules() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let va = ModuleVersionFingerprint::new(source_hash("sa"), 1, 1);
        let vb = ModuleVersionFingerprint::new(source_hash("sb"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:pol-a",
                    va.clone(),
                    ContentHash::compute(b"aa"),
                    "/a.js",
                ),
                &ctx,
            )
            .expect("serde serialization should succeed");
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:pol-b",
                    vb.clone(),
                    ContentHash::compute(b"bb"),
                    "/b.js",
                ),
                &ctx,
            )
            .expect("serde serialization should succeed");
        cache.invalidate_policy_change("mod:pol-a", 5, &ctx);
        // mod:pol-b should still be accessible at its version
        assert!(cache.get("mod:pol-b", &vb).is_some());
        // mod:pol-a with old version should be gone
        assert!(cache.get("mod:pol-a", &va).is_none());
    }

    #[test]
    fn cache_error_code_equality_reflexive() {
        let code = CacheErrorCode::EmptyModuleId;
        assert_eq!(code, code);
    }

    #[test]
    fn module_cache_entry_inserted_seq_is_zero_on_first_insert() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("seq0"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:seq0",
                    v.clone(),
                    ContentHash::compute(b"a"),
                    "/s0.js",
                ),
                &context(),
            )
            .expect("serde serialization should succeed");
        let entry = cache
            .get("mod:seq0", &v)
            .expect("serde serialization should succeed");
        assert_eq!(entry.inserted_seq, 0);
    }

    #[test]
    fn events_field_names_present_in_event_json() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        cache.invalidate_source_update("mod:field-check", source_hash("fc"), &ctx);
        let event = cache
            .events()
            .last()
            .expect("serde serialization should succeed");
        let json = serde_json::to_string(event).expect("serde serialization should succeed");
        assert!(json.contains("\"seq\""), "got: {json}");
        assert!(json.contains("\"trace_id\""), "got: {json}");
        assert!(json.contains("\"decision_id\""), "got: {json}");
        assert!(json.contains("\"policy_id\""), "got: {json}");
        assert!(json.contains("\"component\""), "got: {json}");
        assert!(json.contains("\"event\""), "got: {json}");
        assert!(json.contains("\"outcome\""), "got: {json}");
        assert!(json.contains("\"error_code\""), "got: {json}");
        assert!(json.contains("\"module_id\""), "got: {json}");
        assert!(json.contains("\"detail\""), "got: {json}");
    }

    // -----------------------------------------------------------------------
    // Adaptive S3-FIFO tests (RGC-620B / bd-1lsy.7.20.2)
    // -----------------------------------------------------------------------

    fn adaptive_key(module_id: &str, seed: &str, policy: u64, trust: u64) -> ModuleCacheKey {
        ModuleCacheKey::new(
            module_id,
            ModuleVersionFingerprint::new(source_hash(seed), policy, trust),
        )
    }

    fn adaptive_access(
        seq: u64,
        module_id: &str,
        seed: &str,
        locality: CacheLocalityClass,
        value: u32,
    ) -> ValueAnnotatedTraceAccess {
        ValueAnnotatedTraceAccess {
            sequence: seq,
            key: adaptive_key(module_id, seed, 1, 1),
            locality,
            value_millionths: value,
        }
    }

    #[test]
    fn adaptive_config_default_validates() {
        let cfg = S3FifoAdaptiveConfig::default();
        cfg.validate().expect("serde serialization should succeed");
    }

    #[test]
    fn adaptive_config_invalid_zero_capacity() {
        let cfg = S3FifoAdaptiveConfig {
            resident_capacity_entries: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn adaptive_config_invalid_small_too_large() {
        let mut cfg = S3FifoAdaptiveConfig::default();
        cfg.initial_small_queue_entries = cfg.resident_capacity_entries;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn adaptive_config_invalid_zero_ghost() {
        let cfg = S3FifoAdaptiveConfig {
            ghost_queue_entries: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn adaptive_split_config_invalid_bounds() {
        let mut cfg = S3FifoAdaptiveConfig::default();
        cfg.adaptive_split.min_small_fraction_millionths = 600_000;
        cfg.adaptive_split.max_small_fraction_millionths = 400_000;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn adaptive_split_config_invalid_max_exceeds_million() {
        let mut cfg = S3FifoAdaptiveConfig::default();
        cfg.adaptive_split.max_small_fraction_millionths = 1_000_001;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn adaptive_split_config_invalid_zero_epoch() {
        let mut cfg = S3FifoAdaptiveConfig::default();
        cfg.adaptive_split.epoch_length = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn value_admission_config_invalid_alpha() {
        let mut cfg = S3FifoAdaptiveConfig::default();
        cfg.value_admission.alpha_millionths = 1_000_001;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn simulate_adaptive_empty_trace() {
        let case = ValueAnnotatedTraceCase {
            trace_id: "empty".to_string(),
            workload_class: CacheWorkloadClass::ColdCompile,
            accesses: vec![],
        };
        let cfg = S3FifoAdaptiveConfig::default();
        let result = simulate_s3fifo_adaptive(&case, &cfg);
        assert_eq!(result.base.total_accesses, 0);
        assert_eq!(result.base.hit_count, 0);
        assert_eq!(result.base.miss_count, 0);
        assert_eq!(result.value_denied_count, 0);
        assert_eq!(result.value_admitted_count, 0);
        assert!(result.admission_verdicts.is_empty());
    }

    #[test]
    fn simulate_adaptive_single_access() {
        let case = ValueAnnotatedTraceCase {
            trace_id: "single".to_string(),
            workload_class: CacheWorkloadClass::WarmRun,
            accesses: vec![adaptive_access(
                0,
                "mod:a",
                "s1",
                CacheLocalityClass::Hot,
                900_000,
            )],
        };
        let cfg = S3FifoAdaptiveConfig::default();
        let result = simulate_s3fifo_adaptive(&case, &cfg);
        assert_eq!(result.base.total_accesses, 1);
        assert_eq!(result.base.miss_count, 1);
        assert_eq!(result.base.hit_count, 0);
        assert_eq!(result.value_admitted_count, 1);
        assert_eq!(result.admission_verdicts.len(), 1);
        assert!(result.admission_verdicts[0].admitted);
    }

    #[test]
    fn simulate_adaptive_hit_on_repeat() {
        let case = ValueAnnotatedTraceCase {
            trace_id: "repeat".to_string(),
            workload_class: CacheWorkloadClass::WarmRun,
            accesses: vec![
                adaptive_access(0, "mod:a", "s1", CacheLocalityClass::Hot, 900_000),
                adaptive_access(1, "mod:a", "s1", CacheLocalityClass::Hot, 900_000),
            ],
        };
        let cfg = S3FifoAdaptiveConfig::default();
        let result = simulate_s3fifo_adaptive(&case, &cfg);
        assert_eq!(result.base.hit_count, 1);
        assert_eq!(result.base.miss_count, 1);
        // Only the first access (miss) gets a verdict
        assert_eq!(result.admission_verdicts.len(), 1);
    }

    #[test]
    fn simulate_adaptive_value_denial() {
        // Set floor high enough to deny a low-value entry
        let mut cfg = S3FifoAdaptiveConfig::default();
        cfg.value_admission.floor_value_millionths = 500_000;
        cfg.value_admission.initial_threshold_millionths = 0;

        let case = ValueAnnotatedTraceCase {
            trace_id: "denial".to_string(),
            workload_class: CacheWorkloadClass::ScanHeavy,
            accesses: vec![adaptive_access(
                0,
                "mod:low",
                "s1",
                CacheLocalityClass::Scan,
                100_000,
            )],
        };
        let result = simulate_s3fifo_adaptive(&case, &cfg);
        assert_eq!(result.value_denied_count, 1);
        assert_eq!(result.value_admitted_count, 0);
        assert!(!result.admission_verdicts[0].admitted);
        // Entry was not admitted, so no final residents
        assert!(result.base.final_resident_keys.is_empty());
    }

    #[test]
    fn simulate_adaptive_threshold_denial() {
        // Set initial threshold above the entry value
        let mut cfg = S3FifoAdaptiveConfig::default();
        cfg.value_admission.initial_threshold_millionths = 800_000;
        cfg.value_admission.floor_value_millionths = 0;

        let case = ValueAnnotatedTraceCase {
            trace_id: "thresh-deny".to_string(),
            workload_class: CacheWorkloadClass::WarmRun,
            accesses: vec![adaptive_access(
                0,
                "mod:med",
                "s1",
                CacheLocalityClass::Warm,
                500_000,
            )],
        };
        let result = simulate_s3fifo_adaptive(&case, &cfg);
        assert_eq!(result.value_denied_count, 1);
        assert!(!result.admission_verdicts[0].admitted);
    }

    #[test]
    fn simulate_adaptive_ghost_hit_promotes_to_main() {
        let mut cfg = S3FifoAdaptiveConfig {
            resident_capacity_entries: 4,
            initial_small_queue_entries: 2,
            ghost_queue_entries: 4,
            ..Default::default()
        };
        cfg.value_admission.initial_threshold_millionths = 0;
        cfg.value_admission.floor_value_millionths = 0;
        // Disable adaptation during this test
        cfg.adaptive_split.epoch_length = 10000;

        // Fill small queue (2 entries), then push another to evict first to ghost.
        // Then re-access the evicted entry to get a ghost hit -> main.
        let case = ValueAnnotatedTraceCase {
            trace_id: "ghost-promote".to_string(),
            workload_class: CacheWorkloadClass::WarmRun,
            accesses: vec![
                adaptive_access(0, "mod:a", "sa", CacheLocalityClass::Hot, 500_000),
                adaptive_access(1, "mod:b", "sb", CacheLocalityClass::Hot, 500_000),
                // This evicts mod:a (not hot) to ghost
                adaptive_access(2, "mod:c", "sc", CacheLocalityClass::Hot, 500_000),
                // Ghost hit for mod:a -> goes to main
                adaptive_access(3, "mod:a", "sa", CacheLocalityClass::Hot, 500_000),
            ],
        };
        let result = simulate_s3fifo_adaptive(&case, &cfg);
        assert_eq!(result.base.ghost_hit_count, 1);
        // mod:a should now be in the main queue
        assert!(
            result
                .base
                .final_resident_keys
                .contains(&cache_trace_label(&adaptive_key("mod:a", "sa", 1, 1)))
        );
    }

    #[test]
    fn simulate_adaptive_split_adapts_upward() {
        // Set up a scenario where ghost hits dominate an epoch to trigger expansion.
        let mut cfg = S3FifoAdaptiveConfig {
            resident_capacity_entries: 10,
            initial_small_queue_entries: 2,
            ghost_queue_entries: 10,
            ..Default::default()
        };
        // Use a longer epoch that aligns with our ghost-hit phase
        cfg.adaptive_split.epoch_length = 6;
        cfg.adaptive_split.max_step_per_epoch = 1;
        cfg.adaptive_split.min_small_fraction_millionths = 100_000;
        cfg.adaptive_split.max_small_fraction_millionths = 700_000;
        cfg.value_admission.initial_threshold_millionths = 0;
        cfg.value_admission.floor_value_millionths = 0;

        let mut accesses = Vec::new();
        let mut seq = 0u64;

        // Phase 1: fill + evict to ghost (6 accesses = 1 epoch with no ghost hits)
        for i in 0..6 {
            accesses.push(adaptive_access(
                seq,
                &format!("mod:{i}"),
                &format!("s{i}"),
                CacheLocalityClass::Warm,
                500_000,
            ));
            seq += 1;
        }
        // Phase 2: re-access all 6 (ghost hits dominate this epoch -> adapt up)
        for i in 0..6 {
            accesses.push(adaptive_access(
                seq,
                &format!("mod:{i}"),
                &format!("s{i}"),
                CacheLocalityClass::Warm,
                500_000,
            ));
            seq += 1;
        }

        let case = ValueAnnotatedTraceCase {
            trace_id: "split-adapt".to_string(),
            workload_class: CacheWorkloadClass::PackageGraph,
            accesses,
        };
        let result = simulate_s3fifo_adaptive(&case, &cfg);
        assert!(
            result.adaptation_count > 0,
            "should have adapted at least once"
        );
        // The adaptation mechanism ran; verify it's deterministic
        let r2 = simulate_s3fifo_adaptive(&case, &cfg);
        assert_eq!(result.final_small_capacity, r2.final_small_capacity);
        assert_eq!(result.adaptation_count, r2.adaptation_count);
    }

    #[test]
    fn simulate_adaptive_deterministic_replay() {
        let cfg = S3FifoAdaptiveConfig::default();
        let case = ValueAnnotatedTraceCase {
            trace_id: "replay".to_string(),
            workload_class: CacheWorkloadClass::ReactApp,
            accesses: vec![
                adaptive_access(0, "mod:x", "sx", CacheLocalityClass::Hot, 800_000),
                adaptive_access(1, "mod:y", "sy", CacheLocalityClass::Warm, 400_000),
                adaptive_access(2, "mod:x", "sx", CacheLocalityClass::Hot, 800_000),
                adaptive_access(3, "mod:z", "sz", CacheLocalityClass::Scan, 200_000),
            ],
        };
        let r1 = simulate_s3fifo_adaptive(&case, &cfg);
        let r2 = simulate_s3fifo_adaptive(&case, &cfg);
        assert_eq!(r1.base.hit_count, r2.base.hit_count);
        assert_eq!(r1.base.miss_count, r2.base.miss_count);
        assert_eq!(r1.base.ghost_hit_count, r2.base.ghost_hit_count);
        assert_eq!(r1.final_small_capacity, r2.final_small_capacity);
        assert_eq!(r1.adaptation_count, r2.adaptation_count);
        assert_eq!(r1.value_denied_count, r2.value_denied_count);
        assert_eq!(r1.value_admitted_count, r2.value_admitted_count);
        assert_eq!(r1.final_threshold_millionths, r2.final_threshold_millionths);
        assert_eq!(r1.admission_verdicts.len(), r2.admission_verdicts.len());
        for (v1, v2) in r1
            .admission_verdicts
            .iter()
            .zip(r2.admission_verdicts.iter())
        {
            assert_eq!(v1.admitted, v2.admitted);
            assert_eq!(v1.threshold_millionths, v2.threshold_millionths);
        }
    }

    #[test]
    fn annotate_trace_with_default_values_preserves_structure() {
        let plain_case = CacheTraceCase {
            trace_id: "annotate-test".to_string(),
            workload_class: CacheWorkloadClass::ColdCompile,
            accesses: vec![
                CacheTraceAccess {
                    sequence: 0,
                    key: trace_key("mod:a", "s1", 1, 1),
                    locality: CacheLocalityClass::Hot,
                },
                CacheTraceAccess {
                    sequence: 1,
                    key: trace_key("mod:b", "s2", 1, 1),
                    locality: CacheLocalityClass::Scan,
                },
            ],
        };
        let annotated = annotate_trace_with_default_values(&plain_case);
        assert_eq!(annotated.trace_id, "annotate-test");
        assert_eq!(annotated.workload_class, CacheWorkloadClass::ColdCompile);
        assert_eq!(annotated.accesses.len(), 2);
        assert_eq!(annotated.accesses[0].value_millionths, 900_000); // Hot
        assert_eq!(annotated.accesses[1].value_millionths, 100_000); // Scan
    }

    #[test]
    fn admission_verdict_serde_roundtrip() {
        let verdict = AdmissionVerdict {
            sequence: 42,
            label: "test-label".to_string(),
            value_millionths: 750_000,
            threshold_millionths: 500_000,
            admitted: true,
        };
        let json = serde_json::to_string(&verdict).expect("serde serialization should succeed");
        let decoded: AdmissionVerdict =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded, verdict);
    }

    #[test]
    fn adaptive_metrics_serde_roundtrip() {
        let case = ValueAnnotatedTraceCase {
            trace_id: "serde-rt".to_string(),
            workload_class: CacheWorkloadClass::WarmRun,
            accesses: vec![adaptive_access(
                0,
                "mod:a",
                "s1",
                CacheLocalityClass::Hot,
                800_000,
            )],
        };
        let cfg = S3FifoAdaptiveConfig::default();
        let metrics = simulate_s3fifo_adaptive(&case, &cfg);
        let json = serde_json::to_string(&metrics).expect("serde serialization should succeed");
        let decoded: S3FifoAdaptiveMetrics =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded.base.total_accesses, metrics.base.total_accesses);
        assert_eq!(decoded.final_small_capacity, metrics.final_small_capacity);
        assert_eq!(decoded.value_admitted_count, metrics.value_admitted_count);
    }

    #[test]
    fn adaptive_config_serde_roundtrip() {
        let cfg = S3FifoAdaptiveConfig::default();
        let json = serde_json::to_string(&cfg).expect("serde serialization should succeed");
        let decoded: S3FifoAdaptiveConfig =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded, cfg);
    }

    #[test]
    fn fraction_of_computes_correctly() {
        assert_eq!(fraction_of(10, 500_000), 5); // 50% of 10
        assert_eq!(fraction_of(10, 100_000), 1); // 10% of 10
        assert_eq!(fraction_of(10, 0), 0); // 0% of 10
        assert_eq!(fraction_of(10, 1_000_000), 10); // 100% of 10
        assert_eq!(fraction_of(100, 250_000), 25); // 25% of 100
    }
}
