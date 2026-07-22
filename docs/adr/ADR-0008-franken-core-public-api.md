# ADR-0008: `franken-core` Public API Freeze

- Status: Accepted
- Date: 2026-06-05
- Owners: FrankenEngine maintainers + Track J maintainers
- Plan references: Track J, franken-core graduation contract, API parity ledger
- Related beads: `bd-cixqu.10.6`, `bd-cixqu.10.7`, `bd-4w7h9.1`,
  `bd-4w7h9.2`, `bd-n8eta.4`, `bd-n8eta.4.1`, `bd-n8eta.4.6`,
  `bd-b12xs`, `bd-b12xs.1`, `bd-b12xs.2`, `bd-b12xs.3`,
  `bd-b12xs.4`, `bd-b12xs.5`, `bd-b12xs.6`, `bd-f1ixz`, `bd-g73mg`,
  `bd-t9n3s`

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

The root public API is exactly the 42 `pub mod` declarations in
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
| `js_string` | stable boundary | pending graduation |
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

- `ast`: constants `CANONICAL_AST_CONTRACT_VERSION`, `CANONICAL_AST_SCHEMA_VERSION`, `CANONICAL_AST_HASH_ALGORITHM`, `CANONICAL_AST_HASH_PREFIX`; enums `ParseGoal`, `Statement`, `ImportClause`, `ExportKind`, `BindingPattern`, `VariableDeclarationKind`, `MethodKind`, `BinaryOperator`, `UnaryOperator`, `AssignmentOperator`, `ArrowBody`, `Expression`; structs `SourceSpan`, `SyntaxTree`, `ImportSpecifier`, `ImportDeclaration`, `NamedExportClause`, `ExportDeclaration`, `ObjectPatternProperty`, `VariableDeclarator`, `VariableDeclaration`, `ExpressionStatement`, `BlockStatement`, `IfStatement`, `ForStatement`, `ForInStatement`, `ForOfStatement`, `LabeledStatement`, `WhileStatement`, `DoWhileStatement`, `ReturnStatement`, `ThrowStatement`, `CatchClause`, `TryCatchStatement`, `SwitchCase`, `SwitchStatement`, `BreakStatement`, `ContinueStatement`, `FunctionParam`, `FunctionDeclaration`, `MethodDefinition`, `ClassDeclaration`, `ObjectProperty`.
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
- `ir_contract`: constants `IR_ACCESSOR_GET_PREFIX`, `IR_ACCESSOR_SET_PREFIX`, `IR_SUPER_CONSTRUCTOR_PROPERTY`, `IR_SUPER_PROTOTYPE_PROPERTY`; type aliases `BindingId`, `Reg`, `InstrIndex`; enums `IrLevel`, `BindingKind`, `ScopeKind`, `Ir1PropertyKey`, `IteratorCloseReason`, `Ir1Op`, `Ir1Literal`, `EffectBoundary`, `Ir3Instruction`, `WitnessEventKind`, `ExecutionOutcome`, `IrErrorCode`; structs `IrSchemaVersion`, `IrHeader`, `Ir0Module`, `ScopeId`, `ResolvedBinding`, `ScopeNode`, `Ir1Module`, `CapabilityTag`, `FlowAnnotation`, `Ir2Op`, `Ir2Module`, `RegRange`, `Ir3FunctionDesc`, `SpecializationLinkage`, `Ir3Module`, `WitnessEvent`, `HostcallDecisionRecord`, `Ir4Module`, `IrError`, `IrContractEvent`, `IrVerifier`; functions `verify_schema_version`, `verify_ir0_hash`, `verify_ir1_source`, `verify_ir3_specialization`, `verify_ir4_linkage`, `error_code`.
- `js_string`: structs `JsString`, `CodeUnits`, `ExactPropertyMap`.
- `lowering_pipeline`: enum `LoweringPipelineError`; structs `LoweringContext`, `LoweringEvent`, `InvariantCheck`, `PassWitness`, `IsomorphismLedgerEntry`, `LoweringPassResult`, `LoweringPipelineOutput`, `Ir2FlowProofArtifact`, `FlowProofArtifactEntry`, `DeniedFlowArtifactEntry`, `RequiredDeclassificationArtifactEntry`, `RuntimeCheckpointArtifactEntry`; functions `lower_ir0_to_ir3`, `validate_ir0_static_semantics`, `lower_ir0_to_ir1`, `lower_ir1_to_ir2`, `lower_ir2_to_ir3`.
- `object_model`: enums `PropertyKey`, `WellKnownSymbol`, `JsValue`, `PropertyDescriptor`, `ObjectError`, `ManagedObject`; structs `OrderedStringMap`, `OrderedStringMapIter`, `OrderedStringMapIntoIter`, `ExactOrderedStringMap`, `ExactOrderedStringMapIter`, `ExactOrderedStringMapIntoIter`, `SymbolId`, `OrderedProperties`, `OrderedPropertiesIter`, `ObjectHandle`, `OrdinaryObject`, `ProxyObject`, `ObjectHeap`, `SymbolRegistry`, `ProxyInvariantChecker`, `Reflect`, `ReflectApplyRequest`, `ReflectConstructRequest`.
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

- All 42 root exports are explicit `pub mod` declarations in `lib.rs`.
- There is no root-level wildcard `pub use *` facade.
- Module-level public declarations are broad, but this began as an intentional
  v0.1 workspace-boundary freeze, not a claim of third-party API maturity.
- The parity ledger records 42 matching module names in `franken-engine`, 0
  missing engine exports, 0 identical source files, 42 different source files,
  and `workspace_inclusion_complete = true`.
- Every parity-ledger row is still `pending_graduation`.

No source visibility changes are required for J.6. Narrowing module exports is a
separate breaking API-design task and must not be mixed into the ADR freeze.

## Stability Guarantees

Stable boundary modules guarantee source-level compatibility within each
published `0.x` minor line for:

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

The published GitHub `v0.1.0` release carried `frankenengine-core` and
`frankenengine-engine` source packages versioned at `0.1.0`; current `main`
stages their next source-compatibility boundary at an unreleased `0.2.0`. For
`0.x` crates, minor versions are treated as compatibility boundaries:

| Change class | Required version action | Required process |
| --- | --- | --- |
| Stable boundary additive item | patch or minor | bead + tests + ADR inventory update |
| Stable boundary behavior clarification | patch | bead + validation evidence |
| Stable boundary exhaustive enum variant or public struct field addition | minor while `0.x`, major after `1.0` | ADR update + migration notes + downstream construction/match and serde audit |
| Stable boundary signature/shape removal or rename | minor while `0.x`, major after `1.0` | ADR update + migration notes |
| Experimental boundary additive item | patch or minor | bead + inventory update |
| Experimental boundary breaking change | minor | bead + release note |
| Workspace inclusion topology change | no automatic version action | separate J.7 bead + graduation-contract evidence |

After `1.0`, stable boundary breaking changes require a major version bump.

## Approved Versioned Evolution: Executable Symbol Property Keys

`bd-n8eta.4.1` approves one wire-additive but Rust-source-breaking
stable-boundary evolution for the executable baseline interpreters. Both
public `Value` enums were exhaustive when that decision was approved.
Appending `Value::Symbol` preserves every existing variant's serde encoding,
but it breaks downstream exhaustive matches and old decoders cannot read the
new variant.

The version contract is therefore non-optional:

- `bd-n8eta.4.6` blocks both runtime implementation children.
- The `frankenengine-core` and `frankenengine-engine` source packages carried
  by the `v0.1.0` release must advance to a version newer than `0.1.x` (at
  least `0.2.0`, including a separately approved `1.0.0`) before or atomically
  with the new variant. If either package has already reached `1.0`, this
  change requires its next major version.
- That migration must publish release/migration notes, audit downstream
  exhaustive matches and serde consumers, and add `#[non_exhaustive]` to both
  `Value` enums in the same versioned change.
- The same audit covers any public execution-seed or captured-state shape
  change needed to carry `symbol_state`; no public `0.1.x` shape changes outside
  the coordinated migration.

### `0.2.0` migration checkpoint (`bd-n8eta.4.6`)

The two public runtime crates now stage `0.2.0` on `main`; unrelated workspace
packages remain at `0.1.0`. This checkpoint creates no tag or release and adds
no Symbol runtime behavior. It makes both public baseline `Value` enums
`#[non_exhaustive]`, while leaving every existing variant, payload, serde
discriminant, and execution-seed shape unchanged.

The downstream source audit used AST match enumeration plus direct import and
construction searches. It found 57 cross-crate match expressions in 13 files;
all already carry a wildcard, binding, or equivalent fallback arm. The sibling
`/data/projects/franken_node` tree contains no direct imports, constructions,
or matches of either baseline `Value` type. Existing callers therefore require
no source patch for this checkpoint, but new callers must not exhaustively
match either enum.

Historical-wire regressions decode and re-encode every pre-migration `Value`
variant without changing bytes. Old `0.1.x` decoders will still reject a future
`Symbol` variant, as required for an unknown externally tagged serde variant;
new decoders must continue to accept all historical payloads. Because this
checkpoint adds no IR operation or serialized IR shape,
`IrSchemaVersion::CURRENT` remains `0.1.0`; later IR-shape work must version
that schema independently while the package line is still unreleased.

### Exact quoted-string schema checkpoint (`bd-vltnh`)

The core-first `bd-vltnh` landing is that independently versioned IR-shape
change. `frankenengine-core` advances `IrSchemaVersion::CURRENT` to `0.2.0`
and its canonical AST schema to `franken-engine.parser-ast.schema.v3` while
widening quoted AST literals, IR1 string literals, and the IR3 constant pool
to `JsString`. Well-formed strings retain their historical leaf wire and
canonical representation; strings containing lone UTF-16 surrogates use the
tagged `$wtf16` unit representation. New core readers therefore remain able to
read old plain-string JSON artifacts. Artifact consumers must validate the IR
header and reject unsupported schema versions before decoding; an old
plain-string reader also cannot decode a tagged exact value.

The second landing applies the same carrier to the `frankenengine-engine`
mirror, advancing its canonical AST schema to
`franken-engine.parser-ast.schema.v2` and its `IrSchemaVersion::CURRENT` to
`0.2.0`. The engine parser arena, AST/IR serde and canonical values, IR3
constant pool, and baseline string loads now preserve the same exact code
units. The later exact module-source checkpoint below resolves the separately
tracked `bd-lfq44`; neither schema change creates a tag or release.

### Canonical root EOF coordinate checkpoint (`bd-4tt6s`)

The two parser seams subsequently correct the canonical `SyntaxTree` root
span's `end_column`: it is the one-based UTF-8 byte column immediately after
the original source on its final physical line, not an unconditional `1`.
Because the root span participates in canonical AST bytes and hashes, the
engine AST schema advances independently from v2 to v3 and the core AST schema
from v3 to v4. The AST shape and derived serde remain unchanged, so historical
tree JSON remains readable; consumers must continue to bind cached hashes to
the reported schema version. Parse Event IR, materializer, and executable IR
schemas do not change because their serialized shapes do not change.
Source-backed event materialization preserves old streams through an exact,
hash-authenticated reconstruction of the former root-column value; it does not
relax any other span, statement, envelope, or payload validation.

### `CopyDataProperties` IR schema checkpoint (`bd-f1ixz`)

The core object-rest implementation adds the externally tagged
`Ir1Op::CopyDataProperties { excluded_count }` and
`Ir3Instruction::CopyDataProperties { target, source, excluded, value_dst }`
variants. Because old readers cannot decode either new variant,
`frankenengine-core` advances `IrSchemaVersion::CURRENT` from `0.2.0` to
`0.3.0`. Its Cargo package remains on the unreleased `0.2.0`
compatibility-staging line established by `bd-n8eta.4.6`; no package release,
tag, or `Cargo.lock` version change accompanies this independently versioned
IR wire evolution.

Every pre-existing variant name, payload, serde discriminant, and canonical
representation remains unchanged. A core `0.3.0` reader accepts historical
`0.2.0` IR headers through the documented compatibility window, while a
pre-`0.3.0` reader rejects the unknown new variants. The new variants have
focused serde round-trip and canonical-field regressions and are included in
the existing all-variant tables.

The downstream source audit found one workspace file outside
`frankenengine-core` that directly imports the core IR3 enum:
`crates/franken-engine/src/differential_oracle.rs`. Its two match expressions
already use fallback arms. The sibling `/data/projects/franken_node` tree has
no direct imports, constructions, or matches of core `Ir1Op` or
`Ir3Instruction`. In-core exhaustive matches are updated atomically across
canonical encoding, lowering, effect classification, interpreter dispatch,
and instruction mnemonic reporting. The separate `frankenengine-engine` IR
mirror remains on its own `0.2.0` schema. The later module-source checkpoint
advances that mirror independently without adding `CopyDataProperties` to it.

### Exact module-source schema checkpoint (`bd-lfq44`)

Both public ASTs change the stable `ImportDeclaration::source` field from
`String` to `JsString`, and `ExportKind::NamedClause` now carries the public
`NamedExportClause` value object rather than an undifferentiated `String`.
Both public IR1 enums likewise change `ImportModule::specifier` from `String`
to `JsString`. These are intentional source-shape changes on the unreleased
`0.2.0` Cargo compatibility line; package versions and `Cargo.lock` do not
advance again.

The compatibility engine AST advances from v3 to v4 and its IR schema from
`0.2.0` to `0.3.0`. The native core AST advances from v4 to v5 and its IR
schema from `0.3.0` to `0.4.0`. Same-major current readers retain historical
plain-string inputs. Old readers continue to reject the new exact tagged
values rather than reinterpret them.

Ordinary import and named-export serde/canonical bytes remain unchanged. Exact
imports use the established `$wtf16` `JsString` representation. A named export
with a non-well-formed source uses one namespaced `$module_source` payload that
contains its canonical binding head and exact source; a well-formed source is
invalid in that tagged form so every value has one canonical encoding.

Parser and lowering consumers must use `NamedExportClause::canonical_head()`
and `source()` directly. They must not reconstruct loader identity from a
display string or replacement-character projection. Runtime import dispatch
retains `JsString` through IR execution and converts to `&str` only at the
existing filesystem path boundary, rejecting a non-well-formed value before
path or cache lookup. The independent `module_resolver` and `esm_loader` APIs
do not consume this parser/IR path and remain outside this schema migration.

The descriptor object model already exposes `object_model::SymbolId`,
`object_model::PropertyKey::{String, Symbol}`, and `JsValue::Symbol`; the
executable heaps must reuse those identities instead of inventing a
display-string encoding.

The approved source contract is:

1. After `bd-n8eta.4.6`, append
   `Value::Symbol(object_model::SymbolId)` to each executable baseline `Value`
   enum. Existing variant names, payloads, discriminants, and serialized
   encodings do not move or change; the new JSON value wire is
   `{"Symbol":14}` for `SymbolId(14)`.
2. Use `object_model::PropertyKey` (or a private isomorphic carrier) inside
   executable property operations. The ordinary string `"Symbol(14)"` and
   `PropertyKey::Symbol(SymbolId(14))` are distinct keys in lookup, equality,
   duplicate detection, and replay.
3. Keep every public `HeapObject` field name, type, and visibility unchanged.
   Symbol-keyed data/accessor entries and Symbol creation order may use private
   metadata in the existing ordered property carrier, because replacing the
   public `OrderedStringMap<Value>` field would violate this freeze.
4. Keep `baseline_interpreter::PropertyKey = String` and the current
   `InterpreterHook::pre_property_access` signature unchanged in the ordinary
   ECMAScript implementation children. That callback cannot represent a Symbol
   identity. `bd-n8eta.4.4` owns an explicitly reviewed typed-key hook migration;
   implementations must not stringify a Symbol to cross the old callback, and
   the parent cannot claim hooked-execution completeness before that child
   lands.
5. Store dynamic Symbol allocation, descriptions, the global registry, and
   well-known-symbol schema in interpreter-owned seed-tracked state. That state
   is authoritative; it must never be reconstructed from display strings or
   ordinary user-visible property names.

This evolution does not require an AST or IR schema change: computed property
keys already travel through dynamic value registers. It does require the
following backward-readable heap wire extension:

```json
{
  "properties": {"ordinary": {"Int": 1}},
  "symbol_properties": [
    {"symbol_id": 14, "kind": "data", "value": {"Int": 2}},
    {"symbol_id": 15, "kind": "accessor", "get": null, "set": null}
  ]
}
```

- `properties` retains its historical string-keyed map representation.
- `symbol_properties` is optional, omitted when empty, appended after existing
  fields, and ordered by Symbol-property creation time.
- Every `symbol_properties` record has exactly one nonzero `u32` `symbol_id`
  and one `kind`. A `data` record requires exactly `symbol_id`, `kind`, and one
  existing `Value` wire in `value`; it forbids `get` and `set`. An `accessor`
  record requires exactly `symbol_id`, `kind`, `get`, and `set`; each accessor
  endpoint is JSON `null` or one existing `Value` wire, and `value` is
  forbidden. Unknown fields and kinds are rejected.
- A decoder must continue to accept every payload that omits
  `symbol_properties`. When the field is present it rejects duplicate
  `symbol_id` entries and malformed endpoint values. A whole-interpreter
  decoder also rejects any dynamic ID absent from its `symbol_state`.
- A standalone `HeapObject` decoder has no registry context, so it performs
  only structural validation and preserves typed `SymbolId` keys for exact
  round-trip; it does not invent descriptions or registry entries. Before such
  an object can be attached to an interpreter, seeded, or accessed, the
  interpreter validates every key and nested `Value::Symbol` against its
  `symbol_state`. Missing state or an unresolved dynamic ID rejects attachment.
- Updating a Symbol property retains its array position; delete followed by
  re-creation appends it. Descriptor-kind conversion retains the position.
- Historical engine payloads may contain ordinary strings such as
  `"Symbol(14)"` produced by the old lossy projection. Those strings are
  inherently ambiguous with user-authored strings and must remain ordinary
  string keys; deserialization must not guess and rewrite them into Symbols.
- Existing `Value` and heap payloads with no Symbol values/properties must keep
  their prior bytes. Any explicit schema identifier or golden artifact that a
  child changes must be versioned or regenerated with explicit provenance; a
  Symbol-bearing payload may not be claimed as the old string-only schema.

Every materialized execution seed and serialized whole-interpreter
snapshot/capture carries the same `symbol_state`. In serialized artifacts this
is an optional final field, omitted only for the canonical default state
(`next_symbol_id = 14`, empty `symbols`, and no Symbol values or keys), with
this exact shape:

```json
{
  "symbol_state": {
    "well_known_schema": "es2020-symbol-ids-1-13-v1",
    "next_symbol_id": 16,
    "symbols": [
      {"symbol_id": 14, "kind": "private", "description": null},
      {
        "symbol_id": 15,
        "kind": "global",
        "description": "shared",
        "registry_key": "shared"
      }
    ]
  }
}
```

- Symbol ID `0` is invalid. `WellKnownSymbol` identities are fixed at IDs
  `1..=13` by `es2020-symbol-ids-1-13-v1` and are not listed in `symbols`.
  Dynamic private and global Symbols use monotonically increasing IDs starting
  at `14`; IDs are never reused within an interpreter state. `u32::MAX` is an
  exhausted-state sentinel and is never issued as a `SymbolId`.

The fixed well-known mapping for that schema is:

| ID | Symbol | Property-key name | Description |
| ---: | --- | --- | --- |
| 1 | `Iterator` | `@@iterator` | `Symbol.iterator` |
| 2 | `ToPrimitive` | `@@toPrimitive` | `Symbol.toPrimitive` |
| 3 | `HasInstance` | `@@hasInstance` | `Symbol.hasInstance` |
| 4 | `ToStringTag` | `@@toStringTag` | `Symbol.toStringTag` |
| 5 | `Species` | `@@species` | `Symbol.species` |
| 6 | `IsConcatSpreadable` | `@@isConcatSpreadable` | `Symbol.isConcatSpreadable` |
| 7 | `Unscopables` | `@@unscopables` | `Symbol.unscopables` |
| 8 | `AsyncIterator` | `@@asyncIterator` | `Symbol.asyncIterator` |
| 9 | `Match` | `@@match` | `Symbol.match` |
| 10 | `MatchAll` | `@@matchAll` | `Symbol.matchAll` |
| 11 | `Replace` | `@@replace` | `Symbol.replace` |
| 12 | `Search` | `@@search` | `Symbol.search` |
| 13 | `Split` | `@@split` | `Symbol.split` |

Changing any row requires a new `well_known_schema`; Rust enum declaration
order alone is never allowed to redefine persisted IDs.

- `next_symbol_id` is the first unallocated dynamic ID and must be greater than
  every listed dynamic ID. Overflow is an execution error, not a wrap or reuse.
  `symbols` is serialized in increasing ID order.
- `symbols` contains every live dynamic identity plus every global-registry
  identity. An unreachable private record may be collected, but its ID is not
  reused and `next_symbol_id` does not move backward except when an entire
  earlier execution seed is restored atomically.
- A `private` record requires exactly `symbol_id`, `kind`, and `description`,
  where `description` is JSON `null` or the existing `JsString` wire; it
  forbids `registry_key`. A `global` record additionally requires a non-null
  `registry_key` using the exact `JsString` wire, and its `description` must
  equal that key. Registry keys and Symbol IDs are unique. Unknown fields,
  kinds, reserved IDs, inconsistent `next_symbol_id`, and unresolved
  `Value::Symbol` or Symbol-property IDs are rejected.
- `Symbol.for` consults only the global records and interns by exact `JsString`
  key. `Symbol.keyFor` returns a key only for a global record; private and
  well-known Symbols return `undefined`. Well-known descriptions come from the
  fixed schema, while private/global descriptions come from `symbols`.
- Seed capture/reset copies `symbol_state` atomically with registers and heap.
  Equality, memory estimates, and serialized capture state include it, so a
  restore cannot reuse an existing ID or lose registry identity.

Legacy engine object-backed Symbols need an explicit artifact migration, not a
heuristic applied to arbitrary heap JSON. For a whole interpreter artifact
whose schema/provenance identifies the pre-`0.2.0` engine representation, the
migrator:

1. recognizes only objects whose historical internal marker fields have the
   exact relationships: lowercase `__type: "symbol"` with an integer `__id`
   equal to its heap `ObjectId` and optional string
   `__description`/`__registry_key`, or uppercase `__type: "Symbol"` with
   `__wellKnown: true` and a recognized `__key`; unrelated own properties are
   preserved but do not participate in classification;
2. maps well-known keys to IDs `1..=13`, then assigns dynamic IDs from `14` in
   ascending legacy `ObjectId` order and preserves repeated references;
   legacy global objects with the same exact registry key map to one identity
   when their marker metadata agree, while inconsistent IDs or descriptions
   reject the migration;
3. rewrites legacy Symbol value references to `Value::Symbol`, builds the
   exact `symbol_state`, and leaves every historical string property key,
   including `"Symbol(14)"`, unchanged.

An unversioned standalone legacy `HeapObject` payload without
`symbol_properties` remains readable as its historical ordinary object and is
never guessed to be a Symbol. This avoids silently reinterpreting a
user-authored object that happens to contain the old metadata-like property
names.

The executable ordering contract matches ES2020: canonical integer strings
first numerically, other strings in creation order, then Symbols in creation
order. `Object.keys`/`values`/`entries`, `Object.getOwnPropertyNames`,
`for...in`, querystring, CommonJS named exports, and JSON omit Symbols;
`Object.getOwnPropertySymbols` returns only typed Symbols in creation order,
and `Reflect.ownKeys` returns the complete mixed typed-key order. Enumerable
Symbols participate in `Object.assign` and object spread. Proxy forwarding and
own-key invariant checks must never stringify Symbol identities. Property
storage, execution seeds, equality, memory estimates, and rejected write
rollback must all retain the typed identity and exact order.

Implementation ownership is deliberately split:

| Bead | Contract ownership |
| --- | --- |
| `bd-n8eta.4.6` | version bump, exhaustive-match/serde audit, and migration notes |
| `bd-n8eta.4.2` | engine baseline migration from object-backed/string-projected Symbols |
| `bd-n8eta.4.3` | franken-core executable Symbol value, carrier, and lane parity |
| `bd-n8eta.4.4` | typed property-hook boundary; separate owner-reviewed lane |
| `bd-n8eta.4.5` | Node/Bun donor matrix, cross-lane proof, and DISC-013 closeout |

This is a versioned API approval, not a premature conformance claim. The
baseline interpreter row remains `pending_graduation` until the version,
implementation, and parity children are green.

## Approved Versioned Evolution: Exact UTF-16 Runtime Property Keys

`bd-b12xs.1` and `bd-b12xs.2` established the exact lookup and ordered-storage
primitives without changing a runtime heap. Runtime adoption is a separate
coordinated evolution because, at approval time, the executable baselines projected
`Value::Str` through UTF-8 `String` before property lookup. That projection
aliases distinct lone UTF-16 units to the same replacement-character key.

The approved source contract is:

1. Keep the descriptor-model `object_model::PropertyKey::String(String)` and
   its `JsValue` conversion posture unchanged. That lane deliberately rejects
   a non-well-formed string instead of projecting it. Executable baselines use
   a private isomorphic runtime key whose string arm is `JsString` and whose
   Symbol arm is `SymbolId`; they do not widen the stable descriptor enum.
2. Keep every public executable `HeapObject` field name, type, and visibility
   unchanged. Both lanes retain `properties: OrderedStringMap<Value>`; the core
   lane also retains its public `accessors: BTreeMap<String,
   AccessorProperty>`, while the engine continues to encode accessors as
   `Value::Accessor` property entries and does not acquire a core-style
   accessor field. `OrderedStringMap` may use `ExactOrderedStringMap` and exact
   accessor/order metadata privately and may add exact-key methods.
   Historical `String` key methods plus `len`/`is_empty`, `keys`, `values`,
   `iter`, `retain`, and borrowed or owning `IntoIterator` are explicitly the
   well-formed compatibility view: they never expose or project an exact-only
   key. Consuming iteration yields that view and drops any private exact-only
   entries with the consumed container; `clear` empties both views. Runtime
   property semantics, serde, equality, seed/replay, and memory accounting use
   the new exact APIs whenever exact-only entries can exist.
3. Convert a dynamic computed `Value::Str` directly to the private
   `JsString`-backed key. Get, set, delete, `in`, prototype lookup, and
   data/accessor conversion must compare exact units. They must never call
   `to_string`, `as_utf8_projection`, or replacement-character normalization
   to derive identity.
4. Keep `baseline_interpreter::PropertyKey = String` and
   `InterpreterHook::pre_property_access` unchanged in these ordinary
   compatibility children. With no hook installed, exact property access
   proceeds normally. A well-formed string reaches an installed legacy hook as
   before. With that hook installed, a non-well-formed string, like a Symbol,
   fails closed before the callback and before lookup or mutation because the
   callback cannot represent its identity; tests require zero callback
   invocations and unchanged heap state. Any typed hook migration remains a
   separate owner-reviewed boundary.
5. Land dynamic carrier/storage adoption before consumer and static-source
   parity. The first two runtime children do not change AST or IR schemas.
   `bd-b12xs.6` found no remaining AST projection, so both canonical AST schemas
   stay unchanged. It did find the downstream `Ir1PropertyKey::Static(String)`
   projection, widened that field to `Static(JsString)`, and advanced core IR to
   `0.5.0` and engine IR to `0.4.0`.

The heap wire remains backward-readable and canonical:

- An all-well-formed string-key carrier serializes byte-for-byte as its
  historical JSON object/map. Existing heap, seed, and replay artifacts keep
  their bytes when they contain no exact-only key.
- If any key in a carrier is non-well-formed, that whole carrier uses the
  existing ES-ordered `[[JsString, value], ...]` representation. Core accessor
  and private order metadata use the same exact `JsString` encoding rule while
  retaining the core field names. Engine accessors remain values in the
  property carrier, matching the engine's existing heap shape.
- Readers accept both representations, canonicalize ordinary well-formed
  inputs to the map form, and reject duplicate exact keys plus mixed-form
  aliases. Lone D800, lone D801, and literal U+FFFD are three identities.
- Canonical array indices still enumerate numerically first; other strings
  retain creation order. Replacement and descriptor-kind conversion retain a
  position, while delete followed by re-creation appends.
- Seed capture, equality, full and incremental memory estimates, and rejected
  mutation rollback include every exact key and private ordering copy. A
  failed write cannot leave an exact key, descriptor, or order entry behind.
- Core adoption preserves the already-shipped private Symbol sidecars and
  `symbol_properties` wire. Mixed numeric-string, exact-string, and Symbol
  insertion, replacement, descriptor conversion, deletion, re-creation,
  serde, rollback, and memory tests must retain the ES category order and
  Symbol identity without projecting either key family.

Implementation ownership is deliberately ordered:

| Bead | Contract ownership |
| --- | --- |
| `bd-b12xs.3` | this API/wire decision and dependency split |
| `bd-b12xs.4` | franken-core dynamic computed-key carrier, compatibility/exact views, mixed Symbol storage, serde, seed, memory, and rollback |
| `bd-b12xs.5` | franken-engine mirror after the core call shape is proven |
| `bd-b12xs.6` | landed enumeration/JSON/Reflect/Proxy/assign/spread consumers, static-source audit, donor lockstep, and parent closeout evidence |

The engine Symbol migration `bd-n8eta.4.2` depends on `bd-b12xs.6`. This avoids
first routing its string arms through `PropertyKey::String(String)` and then
remigrating the same property operations to `JsString`. Passing carrier tests
alone does not close the parity gap; both executable baselines and the complete
consumer matrix must be green.

### Exact static-property IR schema checkpoint (`bd-b12xs.6`)

The static-source audit found no lossy AST field: both public ASTs already
carry quoted property names as `Expression::StringLiteral(JsString)`, so
neither canonical AST schema changes. The remaining projection was
`Ir1PropertyKey::Static(String)`, now widened to `Static(JsString)`.

Core advances IR `0.4.0` to `0.5.0`; engine advances IR `0.3.0` to `0.4.0`.
Ordinary static keys retain the historical `{"Static":"name"}` wire and
canonical leaf. Exact-only keys use `{"Static":{"$wtf16":[...]}}`; older
readers must reject the newer header rather than reinterpret that value. This
IR change does not advance either Cargo package beyond the already-unreleased
`0.2.0` line.

Parser and lowering preserve exact units for object literals/patterns,
members, methods, accessors, classes, and destructuring. Class accessor
prefixes concatenate UTF-16 units losslessly, while function display names
remain diagnostic strings. Well-formed-only builtin recognition does not
determine property identity.

### Engine IteratorClose reason schema checkpoint (`bd-g73mg`)

The engine adds the externally tagged `IteratorCloseReason::Continue` variant
to IR1, its IR2 wrapper, and IR3 so a labelled continue that crosses a `for..of` boundary remains
distinct from break, return, and throw. Because an older reader cannot decode
that new enum variant, the engine advances `IrSchemaVersion::CURRENT` from
`0.6.0` to `0.7.0`. Engine `0.7.0` readers retain the supported historical
engine minors, including `0.6.0`; `0.5.0` remains deliberately skipped because
it identifies the incompatible core wire.

The replay-visible engine iterator protocol advances independently from
`franken-engine.iterator-protocol.v1` to `.v2` for the corresponding
`CloseReason::Continue` variant. Neither schema change advances the unreleased
Cargo package version.

The core parity migration `bd-t9n3s` first adds the public
`Statement::Labeled(LabeledStatement)` AST shape required to retain labelled
break and continue targets through lowering. Core advances its canonical AST
schema from v5 directly to v7; v6 is deliberately skipped because that tag
already identifies the incompatible engine assignment-strictness AST shape.
Unlabelled canonical payload bytes remain unchanged, but artifacts must bind
their hashes to the v7 schema tag.

The same migration adds the externally tagged
`IteratorCloseReason::Continue` variant to its IR1, IR2, and IR3 wire. Core
advances from `0.5.0` to `0.8.0`: core minors `0.6.0` and `0.7.0` are
deliberately skipped because those numbers already identify incompatible
engine wires (`0.6.0` adds the engine-only unresolved-name operations and
`0.7.0` adds `Continue` on top of that divergent shape). Core `0.8.0` readers
retain historical core minors `0.1.0` through `0.5.0` and explicitly reject
peer-owned `0.6.x` and `0.7.x` artifacts instead of accepting them through the
minor-version compatibility window. This schema checkpoint does not claim
that the otherwise divergent core and engine IR contracts are interchangeable.

## Cross-Crate Compatibility Matrix

| Consumer or peer | Current relation | Compatibility rule |
| --- | --- | --- |
| `crates/franken-engine` | owns the current native runtime and exports matching module names for all 42 `franken-core` modules | J.7 may not replace engine ownership with core ownership unless the parity ledger and graduation contract are updated and verified |
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
- J.7 may still uncover workspace integration blockers because all 42 parity
  rows have different source files in `franken-core` and `franken-engine`.

## Validation

Validation for this ADR:

```bash
rg -n '^pub mod ' crates/franken-core/src/lib.rs
rg -n '^pub (struct|enum|trait|type|fn|const|static) ' crates/franken-core/src/*.rs
jq empty docs/franken_core_api_parity_ledger_v1.json docs/franken_core_graduation_contract_v1.json
git diff --check -- docs/adr/ADR-0008-franken-core-public-api.md \
  docs/FRANKEN_CORE_API_PARITY_LEDGER_V1.md \
  docs/franken_core_api_parity_ledger_v1.json
```
