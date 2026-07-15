# ADR-0008: `franken-core` Public API Freeze

- Status: Accepted
- Date: 2026-06-05
- Owners: FrankenEngine maintainers + Track J maintainers
- Plan references: Track J, franken-core graduation contract, API parity ledger
- Related beads: `bd-cixqu.10.6`, `bd-cixqu.10.7`, `bd-4w7h9.1`, `bd-4w7h9.2`

## Context

Track J prepared `crates/franken-core` for deliberate workspace participation.
The crate is now included in the root workspace under `bd-cixqu.10.7`; its
standalone manifest compiles and the J.1-J.5 boundary-test beads cover class
semantics, async functions, async generators, accessor descriptors, and
heap-backed own-property storage.

Before J.7 removed the root workspace exclusion, the public API surface had to be
named, frozen, and governed. Without this ADR, workspace inclusion could
accidentally treat a broad `pub mod` surface as unreviewed internal detail, or
conversely treat experimental extracted modules as stable third-party contracts
without a semver policy.

Existing graduation artifacts remain authoritative:

- `docs/FRANKEN_CORE_GRADUATION_CONTRACT_V1.md`
- `docs/franken_core_graduation_contract_v1.json`
- `docs/FRANKEN_CORE_API_PARITY_LEDGER_V1.md`
- `docs/franken_core_api_parity_ledger_v1.json`

## Decision

FrankenEngine freezes the current `crates/franken-core/src/lib.rs` public module
surface as the intentional `frankenengine-core` v0.1 workspace-boundary API.

The freeze has two meanings:

1. Every top-level `pub mod` listed in this ADR is an intentional export, not an
   accidental leak.
2. Any new public module, removed public module, renamed public type, renamed
   public function, changed public signature, or changed public enum/struct
   shape requires a Track J follow-up bead and an ADR-0008 update or explicit
   exception note.

This ADR does not approve workspace inclusion. J.7 owns the root `Cargo.toml`
mutation and must still satisfy the graduation contract and parity ledger.

## Public Module Surface

The root public API is exactly the 41 `pub mod` declarations in
`crates/franken-core/src/lib.rs`:

| Module | Stability tier | Graduation state |
| --- | --- | --- |
| `ast` | stable boundary | pending graduation |
| `baseline_interpreter` | stable boundary | pending graduation |
| `bayesian_posterior` | experimental boundary | pending graduation |
| `capability` | stable boundary | pending graduation |
| `checkpoint` | experimental boundary | pending graduation |
| `closure_model` | stable boundary | pending graduation |
| `containment_executor` | experimental boundary | pending graduation |
| `control_plane` | stable boundary | pending graduation |
| `cx_threading` | experimental boundary | pending graduation |
| `deterministic_serde` | stable boundary | pending graduation |
| `engine_object_id` | stable boundary | pending graduation |
| `entropy_evidence_compressor` | experimental boundary | pending graduation |
| `evidence_ledger` | stable boundary | pending graduation |
| `execution_cell` | experimental boundary | pending graduation |
| `execution_orchestrator` | stable boundary | pending graduation |
| `expected_loss_selector` | experimental boundary | pending graduation |
| `fleet_convergence` | experimental boundary | pending graduation |
| `fleet_immune_protocol` | experimental boundary | pending graduation |
| `flow_lattice` | stable boundary | pending graduation |
| `guardplane_adapter` | stable boundary | pending graduation |
| `hash_tiers` | stable boundary | pending graduation |
| `hindsight_boundary_capture` | experimental boundary | pending graduation |
| `ifc_artifacts` | stable boundary | pending graduation |
| `ir_contract` | stable boundary | pending graduation |
| `lowering_pipeline` | stable boundary | pending graduation |
| `object_model` | stable boundary | pending graduation |
| `optimal_stopping` | experimental boundary | pending graduation |
| `parser` | stable boundary | pending graduation |
| `parser_gap_inventory` | experimental boundary | pending graduation |
| `profiling` | experimental boundary | pending graduation |
| `promise_model` | stable boundary | pending graduation |
| `region_lifecycle` | experimental boundary | pending graduation |
| `regret_bounded_router` | experimental boundary | pending graduation |
| `runtime_config` | stable boundary | pending graduation |
| `saga_orchestrator` | experimental boundary | pending graduation |
| `security_epoch` | stable boundary | pending graduation |
| `signature_preimage` | stable boundary | pending graduation |
| `spectral_fleet_convergence` | experimental boundary | pending graduation |
| `tropical_semiring` | experimental boundary | pending graduation |
| `trust_economics` | experimental boundary | pending graduation |
| `ts_normalization` | experimental boundary | pending graduation |

Stable boundary modules are the first-class API for parser/IR/runtime handoff,
object semantics, evidence, control-plane integration, deterministic encoding,
identity, signature, and security epoch use. Experimental boundary modules stay
public for parity and internal workspace integration, but downstream crates must
treat them as subject to 0.x evolution until a later ADR promotes them.

## Top-Level Public Item Catalog

The following catalog records top-level public declarations found by auditing
`crates/franken-core/src/*.rs` with:

```bash
rg -n '^pub (struct|enum|trait|type|fn|const|static) ' crates/franken-core/src/*.rs
```

It intentionally catalogs top-level public types, traits, functions, constants,
and type aliases. Inherent methods and field-level visibility are governed by
the owning type's module tier and Rust visibility rules.

### Stable Boundary Modules

- `ast`: constants `CANONICAL_AST_CONTRACT_VERSION`, `CANONICAL_AST_SCHEMA_VERSION`, `CANONICAL_AST_HASH_ALGORITHM`, `CANONICAL_AST_HASH_PREFIX`; enums `ParseGoal`, `Statement`, `ImportClause`, `ExportKind`, `BindingPattern`, `VariableDeclarationKind`, `MethodKind`, `BinaryOperator`, `UnaryOperator`, `AssignmentOperator`, `ArrowBody`, `Expression`; structs `SourceSpan`, `SyntaxTree`, `ImportSpecifier`, `ImportDeclaration`, `ExportDeclaration`, `ObjectPatternProperty`, `VariableDeclarator`, `VariableDeclaration`, `ExpressionStatement`, `BlockStatement`, `IfStatement`, `ForStatement`, `ForInStatement`, `ForOfStatement`, `WhileStatement`, `DoWhileStatement`, `ReturnStatement`, `ThrowStatement`, `CatchClause`, `TryCatchStatement`, `SwitchCase`, `SwitchStatement`, `BreakStatement`, `ContinueStatement`, `FunctionParam`, `FunctionDeclaration`, `MethodDefinition`, `ClassDeclaration`, `ObjectProperty`.
- `baseline_interpreter`: constants `DETERMINISTIC_PROFILE_LABEL`, `THROUGHPUT_PROFILE_LABEL`, `LEGACY_QUICKJS_PROFILE_LABEL`, `LEGACY_V8_PROFILE_LABEL`; type aliases `ExtensionId`, `ObjectRef`, `PropertyKey`; trait `InterpreterHook`; enums `Value`, `BuiltinFunctionKind`, `AllocKind`, `FunctionRef`, `HookAction`, `InterpreterError`, `ConsoleLevel`, `LaneChoice`, `LaneReason`; structs `ActiveTimer`, `Float64`, `BuiltinFunction`, `ObjectId`, `HeapObject`, `AccessorProperty`, `ChallengeToken`, `HookContext`, `DecisionReceipt`, `EvidenceLog`, `InterpreterConfig`, `InterpreterEvent`, `ConsoleEntry`, `ExecutionResult`, `ExecutionSeed`, `EagerExecutionSeed`, `InterpreterCore`, `QuickJsLane`, `V8Lane`, `RoutedResult`, `LaneRouter`.
- `capability`: enums `RuntimeCapability`, `ProfileKind`; structs `CapabilityProfile`, `CapabilityDenied`; functions `require_capability`, `require_all`.
- `closure_model`: enums `EnvValue`, `EnvironmentKind`, `ScopeError`; structs `ClosureHandle`, `EnvironmentHandle`, `BindingSlot`, `EnvironmentRecord`, `ClosureCapture`, `Closure`, `ScopeChain`, `ClosureStore`.
- `control_plane`: public re-exports from `franken_decision`, `franken_evidence`, and `franken_kernel`; enums `DecisionVerdict`, `ControlPlaneAdapterError`; traits `ContextAdapter`, `DecisionAdapter`, `EvidenceEmitter`; structs `DecisionRequest`, `AdapterEvent`, `KernelContext`, `ContractDecisionAdapter`, `InMemoryEvidenceEmitter`; function `evaluate_contract`.
- `deterministic_serde`: enums `CanonicalValue`, `SerdeError`; structs `CanonicalF64`, `SchemaHash`, `SchemaRegistry`, `SchemaDefinition`; functions `encode_value`, `decode_value`, `serialize_with_schema`, `deserialize_with_schema`, `canonical_hash`.
- `engine_object_id`: constant `OBJECT_ID_LEN`; enums `ObjectDomain`, `IdError`; structs `SchemaId`, `EngineObjectId`; functions `derive_id`, `verify_id`.
- `evidence_ledger`: re-export `SchemaVersion`; constants `EVIDENCE_LEDGER_STITCHING_BEAD_ID`, `EVIDENCE_LEDGER_STITCHING_COMPONENT`, `EVIDENCE_LEDGER_GRAPH_SCHEMA_VERSION`, `DECISION_SEMANTICS_LOG_SCHEMA_VERSION`, `ARTIFACT_LINEAGE_INDEX_SCHEMA_VERSION`, `EVIDENCE_QUERY_SURFACE_SCHEMA_VERSION`, `EVIDENCE_LEDGER_STITCHING_BUNDLE_SCHEMA_VERSION`, `EVIDENCE_LEDGER_STITCHING_TRACE_IDS_SCHEMA_VERSION`, `EVIDENCE_LEDGER_STITCHING_RUN_MANIFEST_SCHEMA_VERSION`; traits `SchemaVersionExt`, `EvidenceEmitter`; enums `DecisionType`, `LedgerError`, `EvidenceGraphNodeKind`, `EvidenceGraphEdgeKind`; structs `CandidateAction`, `Constraint`, `Witness`, `ChosenAction`, `EvidenceEntry`, `EvidenceEntryBuilder`, `InMemoryLedger`, `DecisionSemanticsAnnotations`, `ArtifactRecord`, `EvidenceGraphNode`, `EvidenceGraphEdge`, `EvidenceLedgerGraph`, `DecisionSemanticsRecord`, `ArtifactLineageRecord`, `EvidenceQueryRecord`, `EvidenceQuerySurfaceSnapshot`, `EvidenceLedgerStitchingBundle`, `StitchingTraceIdsArtifact`, `StitchingStructuredLogEvent`, `StitchingArtifactContext`, `StitchingBundleWriteReport`; functions `current_schema_version`, `render_stitching_summary`, `emit_default_stitching_bundle`.
- `execution_orchestrator`: enums `LossMatrixPreset`, `OrchestratorError`; structs `OrchestratorConfig`, `ExtensionPackage`, `OrchestratorResult`, `PreparedRuntimeFlowGuards`, `ExecutionOrchestrator`.
- `flow_lattice`: enums `Clearance`, `LabelClass`, `DataSource`, `SinkKind`, `FlowCheckResult`, `FlowLatticeError`; structs `DeclassificationObligation`, `FlowLatticeEvent`, `Ir2FlowLattice`; functions `assign_label`, `sink_clearance`.
- `guardplane_adapter`: enums `GuardplaneTrustLevel`, `GuardplaneOperation`; structs `GuardplaneExtensionContext`, `GuardplaneDecisionRecord`, `GuardplaneExecutionSummary`, `GuardplaneAdapter`.
- `hash_tiers`: enums `HashTier`, `HashAlgorithm`; structs `IntegrityHash`, `ContentHash`, `AuthenticityHash`, `HashEvent`.
- `ifc_artifacts`: enums `Label`, `ClearanceClass`, `Ir2LabelSource`, `FlowAuthorizationAdvisory`, `FlowCheckResult`, `ProofMethod`, `DeclassificationDecision`, `ClaimStrength`, `IfcValidationError`; structs `IfcSchemaVersion`, `DeclassificationObligation`, `FlowEnvelope`, `FlowAuthorizationAssessment`, `FlowRule`, `DeclassificationRoute`, `FlowPolicy`, `FlowProof`, `DeclassificationReceipt`, `ConfinementClaim`.
- `ir_contract`: constants `IR_ACCESSOR_GET_PREFIX`, `IR_ACCESSOR_SET_PREFIX`, `IR_SUPER_CONSTRUCTOR_PROPERTY`, `IR_SUPER_PROTOTYPE_PROPERTY`; type aliases `BindingId`, `Reg`, `InstrIndex`; enums `IrLevel`, `BindingKind`, `ScopeKind`, `Ir1PropertyKey`, `IteratorCloseReason`, `Ir1Op`, `Ir1Literal`, `EffectBoundary`, `Ir3Instruction`, `WitnessEventKind`, `ExecutionOutcome`, `IrErrorCode`; structs `IrSchemaVersion`, `IrHeader`, `Ir0Module`, `ScopeId`, `ResolvedBinding`, `ScopeNode`, `Ir1Module`, `CapabilityTag`, `FlowAnnotation`, `Ir2Op`, `Ir2Module`, `RegRange`, `Ir3FunctionDesc`, `SpecializationLinkage`, `Ir3Module`, `WitnessEvent`, `HostcallDecisionRecord`, `Ir4Module`, `IrError`, `IrContractEvent`, `IrVerifier`; functions `verify_ir0_hash`, `verify_ir1_source`, `verify_ir3_specialization`, `verify_ir4_linkage`, `error_code`.
- `lowering_pipeline`: enum `LoweringPipelineError`; structs `LoweringContext`, `LoweringEvent`, `InvariantCheck`, `PassWitness`, `IsomorphismLedgerEntry`, `LoweringPassResult`, `LoweringPipelineOutput`, `Ir2FlowProofArtifact`, `FlowProofArtifactEntry`, `DeniedFlowArtifactEntry`, `RequiredDeclassificationArtifactEntry`, `RuntimeCheckpointArtifactEntry`; functions `lower_ir0_to_ir3`, `validate_ir0_static_semantics`, `lower_ir0_to_ir1`, `lower_ir1_to_ir2`, `lower_ir2_to_ir3`.
- `object_model`: enums `PropertyKey`, `WellKnownSymbol`, `JsValue`, `PropertyDescriptor`, `ObjectError`, `ManagedObject`; structs `SymbolId`, `ObjectHandle`, `OrdinaryObject`, `ProxyObject`, `ObjectHeap`, `SymbolRegistry`, `ProxyInvariantChecker`, `Reflect`, `ReflectApplyRequest`, `ReflectConstructRequest`.
- `parser`: public re-export `ParseGoal`; constants `PARSE_EVENT_IR_CONTRACT_VERSION`, `PARSE_EVENT_IR_SCHEMA_VERSION`, `PARSE_EVENT_IR_HASH_ALGORITHM`, `PARSE_EVENT_IR_HASH_PREFIX`, `PARSE_EVENT_IR_POLICY_ID`, `PARSE_EVENT_IR_COMPONENT`, `PARSE_EVENT_IR_TRACE_PREFIX`, `PARSE_EVENT_IR_DECISION_PREFIX`, `PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION`, `PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION`, `PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX`, `PARSER_DIAGNOSTIC_TAXONOMY_VERSION`, `PARSER_DIAGNOSTIC_SCHEMA_VERSION`, `PARSER_DIAGNOSTIC_HASH_ALGORITHM`, `PARSER_DIAGNOSTIC_HASH_PREFIX`, `SEMANTIC_ERROR_TAXONOMY_VERSION`; type aliases `ParseResult`, `ParseEventMaterializationResult`; traits `ParserInput`, `Es2020Parser`; enums `ParseErrorCode`, `ParseDiagnosticCategory`, `ParseDiagnosticSeverity`, `ParserMode`, `ParseBudgetKind`, `GrammarCoverageStatus`, `ParseEventKind`, `ParseEventMaterializationErrorCode`, `SemanticErrorCode`, `SemanticDiagnosticCategory`; structs `ParseDiagnosticRule`, `ParseDiagnosticTaxonomy`, `ParserBudget`, `ParserOptions`, `ParseFailureWitness`, `GrammarFamilyCoverage`, `GrammarCompletenessMatrix`, `GrammarCompletenessSummary`, `ParseError`, `ParseDiagnosticEnvelope`, `ParseEvent`, `ParseEventIr`, `ParseEventMaterializationError`, `MaterializedStatementNode`, `MaterializedSyntaxTree`, `ParserSource`, `StreamInput`, `CanonicalEs2020Parser`, `SemanticError`, `SemanticValidationResult`; function `normalize_parse_error`.
- `promise_model`: enums `PromiseState`, `ReactionKind`, `Microtask`, `MacrotaskSource`, `WitnessEvent`, `PromiseError`, `ExceptionBoundaryKind`; structs `PromiseHandle`, `PromiseReaction`, `PromiseRecord`, `Macrotask`, `VirtualClock`, `PromiseStore`, `MicrotaskQueue`, `MacrotaskQueue`, `EventLoop`, `TurnResult`, `PromiseAllTracker`, `PromiseAllSettledTracker`, `SettledOutcome`, `PromiseRaceTracker`, `PromiseAnyTracker`, `ExceptionRejectionOutcome`, `ExceptionRejectionWitnessEvent`, `ExceptionToRejectionBridge`.
- `runtime_config`: re-export `ExtensionHostConfig`; constant `MILLION`; enum `ConfigError`; structs `ConfigValidationError`, `ExecutionConfig`, `OrchestratorConfig`, `BayesianPriorsConfig`, `DecisionThresholdsConfig`, `ContainmentConfig`, `GuardplaneConfig`, `GovernanceConfig`, `GatesConfig`, `OptimizationConfig`, `RuntimeConfig`.
- `security_epoch`: enums `TransitionReason`, `EpochValidationError`; structs `SecurityEpoch`, `EpochMetadata`, `MonotonicityViolation`, `TransitionRecord`, `EpochTracker`.
- `signature_preimage`: constants `SIGNING_KEY_LEN`, `VERIFICATION_KEY_LEN`, `SIGNATURE_LEN`, `SIGNATURE_SENTINEL`; trait `SignaturePreimage`; enum `SignatureError`; structs `SigningKey`, `VerificationKey`, `Signature`, `SignatureEvent`, `SignatureContext`; functions `sign_preimage`, `sign_object`, `verify_signature`, `verify_object`, `build_preimage`, `preimage_hash`, `check_canonical_for_signing`, `generate_keypair`, `generate_keypair_from_seed`.

### Experimental Boundary Modules

- `bayesian_posterior`: enum `RiskState`; structs `Posterior`, `Evidence`, `LikelihoodModel`, `UpdateResult`, `ChangePointDetector`, `CalibrationResult`, `BayesianPosteriorUpdater`, `UpdaterStore`.
- `checkpoint`: enums `CheckpointReason`, `CheckpointAction`, `LoopSite`; structs `CheckpointEvent`, `DensityConfig`, `CancellationToken`, `CheckpointGuard`, `CheckpointCoverage`.
- `containment_executor`: enums `ContainmentError`, `ContainmentState`; structs `SandboxPolicy`, `ContainmentReceipt`, `ContainmentContext`, `ForensicSnapshot`, `ContainmentExecutor`.
- `cx_threading`: constants `HOSTCALL_BUDGET_COST_MS`, `POLICY_CHECK_BUDGET_COST_MS`, `LIFECYCLE_TRANSITION_BUDGET_COST_MS`, `TELEMETRY_EMIT_BUDGET_COST_MS`; enums `CxThreadingError`, `EffectCategory`, `LifecyclePhase`, `TelemetryLevel`, `PolicyVerdict`; structs `HostcallDescriptor`, `PolicyCheckDescriptor`, `TelemetryDescriptor`, `CxThreadedEvent`, `CxThreadedGateway`, `HostcallRegistration`, `HostcallReceipt`, `PolicyCheckResult`, `LifecycleReceipt`, `TelemetryReceipt`, `EffectAuditLog`; function `run_full_lifecycle`.
- `entropy_evidence_compressor`: constants `ENTROPY_SCHEMA_VERSION`, `COMPRESSION_CERTIFICATE_SCHEMA_VERSION`; enum `EntropyError`; structs `EntropyEstimator`, `SufficientStatistic`, `ArithmeticCoder`, `CompressedEvidence`, `CompressionCertificate`.
- `execution_cell`: enums `CellKind`, `CellError`; structs `CellEvent`, `ExecutionCell`, `CellManager`, `LifecycleEvidenceEntry`, `CellCloseReport`, `ExtensionHostBinding`.
- `expected_loss_selector`: enums `ContainmentAction`, `AlienRiskAlertLevel`, `RuntimeDecisionScoringError`; structs `LossEntry`, `LossMatrix`, `DecisionExplanation`, `ActionDecision`, `RuntimeDecisionScoringInput`, `DecisionConfidenceInterval`, `CandidateActionScore`, `RuntimeDecisionScoreEvent`, `AlienRiskEnvelope`, `RuntimeDecisionScore`, `ExpectedLossSelector`.
- `fleet_convergence`: enums `PartitionMode`, `ConvergenceEventType`, `ConvergenceVerification`, `ConvergenceError`; structs `ContainmentThresholds`, `PartitionInfo`, `HealingInfo`, `ConvergenceConfig`, `ContainmentReceipt`, `ConvergenceDecision`, `ConvergenceEvent`, `ActionRegistry`, `ConvergenceEngine`.
- `fleet_immune_protocol`: enums `ContainmentAction`, `FleetMessage`, `ProtocolError`; structs `ProtocolVersion`, `NodeId`, `MessageSignature`, `EvidencePacket`, `ContainmentIntent`, `QuorumCheckpoint`, `ResolvedContainmentDecision`, `HeartbeatLiveness`, `ReconciliationRequest`, `SequenceRange`, `GossipConfig`, `DeterministicPrecedence`, `NodeSequenceTracker`, `EvidenceAccumulator`, `NodeHealthTracker`, `FleetProtocolState`.
- `hindsight_boundary_capture`: constants `BEAD_ID`, `CONTRACT_SCHEMA_VERSION`, `BOUNDARY_CATALOG_SCHEMA_VERSION`, `MINIMAL_REPLAY_INPUT_SCHEMA_VERSION`, `BOUNDARY_REDACTION_MAP_SCHEMA_VERSION`, `BOUNDARY_CAPTURE_EVENT_SCHEMA_VERSION`; enums `BoundaryClass`, `PrivacyClass`, `RedactionTreatment`, `ReplaySufficiency`, `BoundaryCaptureError`; structs `FieldContract`, `EscalationCase`, `FieldPrivacyMetadata`, `BoundaryRule`, `BoundaryCatalog`, `MinimalReplayInputEntry`, `MinimalReplayInputSchema`, `BoundaryRedactionEntry`, `BoundaryRedactionMap`, `BoundaryCaptureContract`, `BoundaryContext`, `BoundaryCaptureRequest`, `FieldRedactionValue`, `BoundaryCaptureRecord`, `MinimalReplayInputRecord`, `MinimalReplayPlan`, `BoundaryCaptureLog`, `BoundaryCaptureSession`.
- `optimal_stopping`: constant `STOPPING_SCHEMA_VERSION`; enums `StoppingError`, `StoppingDecision`; structs `Observation`, `CusumChart`, `GittinsArm`, `GittinsIndexComputer`, `SnellEnvelope`, `SecretarySelector`, `EscalationPolicy`, `OptimalStoppingCertificate`.
- `parser_gap_inventory`: constants `UNSUPPORTED_SYNTAX_DIAGNOSTIC_SCHEMA_VERSION`, `PARSER_GAP_INVENTORY_SCHEMA_VERSION`, `PARSER_GAP_RUN_MANIFEST_SCHEMA_VERSION`, `PARSER_GAP_EVENT_SCHEMA_VERSION`, `PARSER_GAP_COMPONENT`, `PARSER_GAP_POLICY_ID`; enums `ParserGapStage`, `ParserGapRemediationStatus`, `ParserGapSiteId`, `ParserGapInventoryWriteError`; structs `ParserGapSiteDescriptor`, `ParserGapInventory`, `UnsupportedSyntaxDiagnostic`, `ParserGapInventoryArtifactPaths`, `ParserGapInventoryRunManifest`, `ParserGapInventoryEvent`, `ParserGapInventoryArtifacts`; functions `parser_gap_inventory`, `write_parser_gap_inventory_bundle`.
- `profiling`: structs `ProfilingConfig`, `InstructionStats`, `MemoryStats`, `HotspotInfo`, `ProfilingReport`, `Profiler`; function `instruction_name`.
- `region_lifecycle`: enums `RegionState`, `CancelReason`, `ObligationStatus`; structs `PhaseOrderViolation`, `Obligation`, `DrainDeadline`, `FinalizeResult`, `RegionEvent`, `Region`.
- `regret_bounded_router`: constant `ROUTING_SCHEMA_VERSION`; enums `RegimeKind`, `RouterError`; structs `LaneArm`, `RewardSignal`, `Exp3State`, `FtrlState`, `RegretBoundedRouter`, `RegimeTransition`, `RoutingDecisionReceipt`, `RouterSummary`, `RegretCertificate`.
- `saga_orchestrator`: enums `SagaType`, `SagaState`, `StepOutcome`, `ActionType`, `SagaError`; structs `SagaId`, `SagaStep`, `StepRecord`, `Saga`, `SagaEvent`, `SagaOrchestrator`; functions `quarantine_saga_steps`, `revocation_saga_steps`, `eviction_saga_steps`, `publish_saga_steps`.
- `spectral_fleet_convergence`: constant `SPECTRAL_SCHEMA_VERSION`; enum `SpectralError`; structs `GossipTopology`, `LaplacianMatrix`, `SpectralAnalysis`, `SpectralAnalyzer`, `ConvergenceCertificate`.
- `tropical_semiring`: constants `TROPICAL_INFINITY`, `TROPICAL_ZERO`, `TROPICAL_SCHEMA_VERSION`; enums `TropicalError`, `ScheduleQuality`; structs `TropicalWeight`, `TropicalMatrix`, `InstructionNode`, `InstructionCostGraph`, `CriticalPathResult`, `Schedule`, `OptimalityCertificate`, `ScheduleOptimizer`, `DeadCodeEliminator`, `DeadCodeReport`, `RegisterPressureAnalyzer`, `RegisterPressureReport`, `TropicalPassWitness`.
- `trust_economics`: constant `MILLIONTHS`; enums `TrueState`, `ContainmentAction`, `RoiAlertLevel`, `RoiTrend`, `TrustEconomicsError`; structs `SubLoss`, `DecomposedLossMatrix`, `AttackerCostModel`, `StrategyCostAdjustment`, `AttackerRoiAssessment`, `FleetRoiSummary`, `ActionCost`, `ContainmentCostModel`, `BlastRadiusEstimate`, `TrustEconomicsModelInputs`; functions `classify_roi_alert_level`, `classify_roi_trend`, `summarize_fleet_roi`, `default_conservative_loss_matrix`.
- `ts_normalization`: enums `SourceLanguage`, `TsIngestionErrorCode`, `TsNormalizationError`; structs `TsCompilerOptions`, `TsNormalizationConfig`, `SourceMapEntry`, `CapabilityIntent`, `NormalizationDecision`, `NormalizationEvent`, `TsNormalizationWitness`, `TsNormalizationOutput`, `SourceIngestionSummary`, `PreparedSourceEntry`, `TsIngestionEvent`, `TsIngestionArtifacts`, `TsIngestionProvenance`, `TsIngestionError`; functions `classify_source_language`, `prepare_source_entry_for_public_entrypoints`, `normalize_typescript_to_es2020`, `ingest_typescript_to_pipeline_artifacts`, `ingest_typescript_to_pipeline_artifacts_default`.

## API Surface Audit

Audit result:

- All 41 root exports are explicit `pub mod` declarations in `lib.rs`.
- There is no root-level wildcard `pub use *` facade.
- Module-level public declarations are broad, but this is an intentional
  v0.1 workspace-boundary freeze, not a claim of third-party API maturity.
- The parity ledger records 41 matching module names in `franken-engine`, 0
  missing engine exports, 0 identical source files, 41 different source files,
  and `workspace_inclusion_complete = true`.
- Every parity-ledger row is still `pending_graduation`.

No source visibility changes are required for J.6. Narrowing module exports is a
separate breaking API-design task and must not be mixed into the ADR freeze.

## Stability Guarantees

Stable boundary modules guarantee source-level compatibility within the
`0.1.x` line for:

- module name
- public type/function/trait/constant name
- public function signature
- public trait method signature
- public enum variant name and payload shape
- public struct field name and type where the field is public
- serialized schema/hash constants where documented as schema contracts

Experimental boundary modules guarantee only that they remain named exports
until the next minor version or an ADR-approved migration. Their public items may
change during the `0.x` line, but every change must include a bead, migration
note, and compatibility assessment.

No module in this ADR is considered stable for external third-party ecosystem
use until a later release ADR promotes `frankenengine-core` beyond the workspace
boundary use case.

## Deprecation Policy

Deprecation policy for stable boundary modules:

1. Add `#[deprecated(note = "...")]` before removal when technically possible.
2. Keep deprecated stable items for at least one minor release.
3. Document the replacement API and migration path in the closing bead.
4. Update this ADR or add a superseding ADR when the stable surface changes.
5. Treat removal, rename, signature change, enum variant removal, or public field
   removal as a breaking change.

Deprecation policy for experimental boundary modules:

1. Prefer deprecation before removal when the item is known to have downstream
   users.
2. If fail-closed security or determinism requires immediate removal, the bead
   must state the reason and identify affected modules.
3. Record every experimental breaking change in the release notes for the minor
   version that carries it.

## Semver Policy

`frankenengine-core` is currently versioned `0.1.0`. For `0.x` crates, minor
versions are treated as compatibility boundaries:

| Change class | Required version action | Required process |
| --- | --- | --- |
| Stable boundary additive item | patch or minor | bead + tests + ADR inventory update |
| Stable boundary behavior clarification | patch | bead + validation evidence |
| Stable boundary signature/shape removal or rename | minor while `0.x`, major after `1.0` | ADR update + migration notes |
| Experimental boundary additive item | patch or minor | bead + inventory update |
| Experimental boundary breaking change | minor | bead + release note |
| Workspace inclusion topology change | no automatic version action | separate J.7 bead + graduation-contract evidence |

After `1.0`, stable boundary breaking changes require a major version bump.

## Cross-Crate Compatibility Matrix

| Consumer or peer | Current relation | Compatibility rule |
| --- | --- | --- |
| `crates/franken-engine` | owns the current native runtime and exports matching module names for all 41 `franken-core` modules | J.7 may not replace engine ownership with core ownership unless the parity ledger and graduation contract are updated and verified |
| `crates/franken-extension-host` | dependency of `franken-core` via path dependency | public config and host-boundary types must remain compatible with `frankenengine-extension-host` version used by this repo |
| `/dp/franken_node` | downstream/product repo depends one-way on `franken_engine` | no core-to-node dependency; no forked engine crates inside `franken_node` |
| `/dp/frankensqlite` and `/dp/sqlmodel_rust` | canonical persistence substrates under AGENTS.md sibling reuse policy | `franken-core` must not add local SQLite persistence substitutes for control-plane state |
| `/dp/fastapi_rust` | preferred service/API control-surface substrate | `franken-core` service/API-facing exports must not invent incompatible endpoint conventions |

## J.7 Gate Requirements

J.7 may remove the root `Cargo.toml` exclusion only after this ADR is present and
after it re-validates:

```bash
env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc -Clinker-features=-lld' cargo check --all-targets
```

If the all-target workspace check fails, J.7 must keep the workspace exclusion
and record the first hard blocker. Standalone `franken-core` success is evidence
for this ADR, but it is not workspace-inclusion success.

## Consequences

Positive:

- Track J has a named public API freeze point before workspace mutation.
- Reviewers can distinguish stable boundary APIs from experimental exports.
- Future public API changes have an explicit semver and deprecation process.

Costs:

- The current `pub mod` surface is broad and includes experimental modules.
- Some modules remain parity-visible but not parity-proven.
- J.7 may still uncover workspace integration blockers because 38 parity rows
  differ between `franken-core` and `franken-engine`.

## Validation

Validation for this ADR:

```bash
rg -n '^pub mod ' crates/franken-core/src/lib.rs
rg -n '^pub (struct|enum|trait|type|fn|const|static) ' crates/franken-core/src/*.rs
jq empty docs/franken_core_api_parity_ledger_v1.json docs/franken_core_graduation_contract_v1.json
git diff --check -- docs/adr/ADR-0008-franken-core-public-api.md .beads/issues.jsonl
```
