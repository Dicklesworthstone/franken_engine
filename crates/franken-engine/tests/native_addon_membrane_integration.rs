#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use frankenengine_engine::capability::{CapabilityProfile, RuntimeCapability};
use frankenengine_engine::module_resolver::ResolutionContext;
use frankenengine_engine::native_addon_membrane::{
    INVENTORY_SCHEMA_VERSION, NativeAddonAbiSurface, NativeAddonArtifactWriteRequest,
    NativeAddonCohort, NativeAddonCrashContainment, NativeAddonFallbackMode,
    NativeAddonHandleDiscipline, NativeAddonInvocationChannel, NativeAddonLoadRequest,
    NativeAddonMembrane, NativeAddonMembraneErrorCode, NativeAddonRoute, NativeAddonSupportStatus,
    NativeAddonSymbol, NativeAddonSymbolClass,
};
use frankenengine_engine::self_replacement::DelegateType;
use frankenengine_engine::slot_registry::SlotCapability;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn context() -> ResolutionContext {
    ResolutionContext::new(
        "trace-native-addon",
        "decision-native-addon",
        "policy-native-addon",
    )
}

fn profile_with(caps: &[RuntimeCapability]) -> CapabilityProfile {
    let mut profile = CapabilityProfile::compute_only();
    profile.capabilities = caps.iter().copied().collect();
    profile
}

fn representative_inventory_requests() -> Vec<NativeAddonLoadRequest> {
    let direct_request = NativeAddonLoadRequest::new(
        "direct-addon",
        "portable-addon",
        "0.1.0",
        "portable-addon",
        "./build/Release/portable.node",
        NativeAddonAbiSurface::NodeApi,
    )
    .with_node_api_version(8)
    .with_symbol(NativeAddonSymbol::new(
        "open",
        NativeAddonSymbolClass::FunctionExport,
    ));

    let delegate_request = NativeAddonLoadRequest::new(
        "delegate-addon",
        "sharp",
        "1.0.0",
        "sharp",
        "./build/Release/sharp.node",
        NativeAddonAbiSurface::NodeApi,
    )
    .with_node_api_version(8)
    .with_handle_discipline(NativeAddonHandleDiscipline::RawPointerEscape)
    .allow_fallback(NativeAddonFallbackMode::DelegateCell)
    .with_symbol(NativeAddonSymbol::new(
        "unsafe_buffer",
        NativeAddonSymbolClass::ExternalBuffer,
    ));

    let mut wasm_request = NativeAddonLoadRequest::new(
        "wasm-addon",
        "bcrypt",
        "5.0.0",
        "bcrypt",
        "./build/Release/bcrypt.node",
        NativeAddonAbiSurface::Nan,
    )
    .allow_fallback(NativeAddonFallbackMode::WasmPort)
    .allow_fallback(NativeAddonFallbackMode::DelegateCell);
    wasm_request.wasm_portable = true;

    let mut unsupported_request = NativeAddonLoadRequest::new(
        "unsupported-addon",
        "native-http",
        "1.2.3",
        "native-http",
        "./build/Release/http.node",
        NativeAddonAbiSurface::NodeApi,
    )
    .with_node_api_version(8)
    .allow_fallback(NativeAddonFallbackMode::DelegateCell)
    .with_symbol(NativeAddonSymbol::new(
        "dispatch",
        NativeAddonSymbolClass::FunctionExport,
    ));
    unsupported_request.requires_network_egress = true;

    vec![
        direct_request,
        delegate_request,
        wasm_request,
        unsupported_request,
    ]
}

fn representative_inventory_profile() -> CapabilityProfile {
    profile_with(&[
        RuntimeCapability::ExtensionLifecycle,
        RuntimeCapability::HeapAllocate,
    ])
}

fn bridge_commands() -> Vec<String> {
    std::env::var("RGC_NATIVE_ADDON_MEMBRANE_COMMANDS_JSON")
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(|| {
            vec![
                "cargo test -p frankenengine-engine --test native_addon_membrane_integration"
                    .to_string(),
            ]
        })
}

#[test]
fn safe_node_api_addon_routes_direct() {
    let membrane = NativeAddonMembrane::standard();
    let request = frankenengine_engine::native_addon_membrane::NativeAddonLoadRequest::new(
        "sqlite-addon",
        "better-sqlite3",
        "9.0.0",
        "better-sqlite3",
        "./build/Release/sqlite.node",
        NativeAddonAbiSurface::NodeApi,
    )
    .with_node_api_version(8)
    .with_symbol(NativeAddonSymbol::new(
        "open",
        NativeAddonSymbolClass::FunctionExport,
    ))
    .with_symbol(NativeAddonSymbol::new(
        "close",
        NativeAddonSymbolClass::Finalizer,
    ));

    let profile = profile_with(&[RuntimeCapability::ExtensionLifecycle]);
    let plan = membrane
        .plan(&request, &context(), &profile)
        .expect("direct-safe addon should route directly");

    assert_eq!(plan.route, NativeAddonRoute::DirectMembrane);
    assert_eq!(
        plan.invocation_channel,
        NativeAddonInvocationChannel::InProcessMembrane
    );
    assert_eq!(
        plan.crash_containment,
        NativeAddonCrashContainment::InProcessMembrane
    );
    assert_eq!(plan.delegate_type, None);
    assert_eq!(plan.event.outcome, "allow");
    assert_eq!(plan.event.error_code, "none");
    assert_eq!(
        plan.support_surface.support_status,
        NativeAddonSupportStatus::Direct
    );
    assert!(plan.support_surface.missing_capabilities.is_empty());
    assert!(plan.support_surface.direct_blockers.is_empty());
}

#[test]
fn unsafe_handle_discipline_falls_back_to_delegate_cell() {
    let membrane = NativeAddonMembrane::standard();
    let request = frankenengine_engine::native_addon_membrane::NativeAddonLoadRequest::new(
        "image-addon",
        "sharp",
        "1.0.0",
        "sharp",
        "./build/Release/sharp.node",
        NativeAddonAbiSurface::NodeApi,
    )
    .with_node_api_version(8)
    .with_handle_discipline(NativeAddonHandleDiscipline::RawPointerEscape)
    .allow_fallback(NativeAddonFallbackMode::DelegateCell)
    .with_symbol(NativeAddonSymbol::new(
        "unsafe_buffer",
        NativeAddonSymbolClass::ExternalBuffer,
    ));

    let profile = profile_with(&[
        RuntimeCapability::ExtensionLifecycle,
        RuntimeCapability::HeapAllocate,
    ]);
    let plan = membrane
        .plan(&request, &context(), &profile)
        .expect("unsafe direct surface should fall back to delegate cell");

    assert_eq!(plan.route, NativeAddonRoute::DelegateCell);
    assert_eq!(
        plan.invocation_channel,
        NativeAddonInvocationChannel::HostcallSession
    );
    assert_eq!(
        plan.crash_containment,
        NativeAddonCrashContainment::DelegateCellBoundary
    );
    assert_eq!(plan.delegate_type, Some(DelegateType::ExternalProcess));
    assert!(plan.capability_envelope.is_some());
    assert!(plan.sandbox.is_some());
    assert_eq!(
        plan.support_surface.support_status,
        NativeAddonSupportStatus::FallbackOnly
    );
    assert!(
        plan.support_surface
            .direct_blockers
            .iter()
            .any(|value| value.contains("raw_pointer_escape"))
    );
    assert!(
        plan.capability_envelope
            .as_ref()
            .expect("delegate authority")
            .required
            .contains(&SlotCapability::HeapAlloc)
    );
}

#[test]
fn wasm_portable_legacy_addon_prefers_wasm_fallback() {
    let membrane = NativeAddonMembrane::standard();
    let mut request = frankenengine_engine::native_addon_membrane::NativeAddonLoadRequest::new(
        "bcrypt-addon",
        "bcrypt",
        "5.0.0",
        "bcrypt",
        "./build/Release/bcrypt.node",
        NativeAddonAbiSurface::Nan,
    )
    .allow_fallback(NativeAddonFallbackMode::WasmPort)
    .allow_fallback(NativeAddonFallbackMode::DelegateCell);
    request.wasm_portable = true;

    let profile = profile_with(&[RuntimeCapability::ExtensionLifecycle]);
    let plan = membrane
        .plan(&request, &context(), &profile)
        .expect("portable legacy addon should prefer wasm fallback");

    assert_eq!(plan.route, NativeAddonRoute::WasmPort);
    assert_eq!(plan.delegate_type, Some(DelegateType::WasmBacked));
    assert_eq!(
        plan.crash_containment,
        NativeAddonCrashContainment::WasmSandbox
    );
    assert!(
        plan.support_surface
            .direct_blockers
            .iter()
            .any(|value| value.contains("requires node_api surface"))
    );
}

#[test]
fn missing_capability_denies_all_routes() {
    let membrane = NativeAddonMembrane::standard();
    let mut request = frankenengine_engine::native_addon_membrane::NativeAddonLoadRequest::new(
        "http-addon",
        "native-http",
        "1.2.3",
        "native-http",
        "./build/Release/http.node",
        NativeAddonAbiSurface::NodeApi,
    )
    .with_node_api_version(8)
    .allow_fallback(NativeAddonFallbackMode::DelegateCell);
    request.requires_network_egress = true;

    let profile = profile_with(&[RuntimeCapability::ExtensionLifecycle]);
    let error = membrane
        .plan(&request, &context(), &profile)
        .expect_err("missing runtime capability must fail closed");

    assert_eq!(error.code, NativeAddonMembraneErrorCode::MissingCapability);
    assert_eq!(error.event.outcome, "deny");
    assert_eq!(
        error.event.error_code,
        NativeAddonMembraneErrorCode::MissingCapability.stable_code()
    );
    assert!(
        error
            .event
            .missing_capabilities
            .contains(&RuntimeCapability::NetworkEgress)
    );

    let surface = membrane.assess_support_surface(&request, &profile);
    assert_eq!(
        surface.support_status,
        NativeAddonSupportStatus::Unsupported
    );
    assert_eq!(surface.selected_route, None);
}

#[test]
fn abi_fingerprint_and_inventory_hash_are_deterministic() {
    let membrane = NativeAddonMembrane::standard();
    let request_a = frankenengine_engine::native_addon_membrane::NativeAddonLoadRequest::new(
        "addon-a",
        "portable-addon",
        "0.1.0",
        "portable-addon",
        "./build/Release/portable.node",
        NativeAddonAbiSurface::NodeApi,
    )
    .with_node_api_version(8)
    .with_symbol(NativeAddonSymbol::new(
        "zeta",
        NativeAddonSymbolClass::FunctionExport,
    ))
    .with_symbol(
        NativeAddonSymbol::new("alpha", NativeAddonSymbolClass::ValueExport)
            .require_capability(RuntimeCapability::FsRead),
    );
    let request_b = frankenengine_engine::native_addon_membrane::NativeAddonLoadRequest::new(
        "addon-a",
        "portable-addon",
        "0.1.0",
        "portable-addon",
        "./build/Release/portable.node",
        NativeAddonAbiSurface::NodeApi,
    )
    .with_node_api_version(8)
    .with_symbol(
        NativeAddonSymbol::new("alpha", NativeAddonSymbolClass::ValueExport)
            .require_capability(RuntimeCapability::FsRead),
    )
    .with_symbol(NativeAddonSymbol::new(
        "zeta",
        NativeAddonSymbolClass::FunctionExport,
    ));

    assert_eq!(request_a.abi_fingerprint(), request_b.abi_fingerprint());

    let profile = profile_with(&[
        RuntimeCapability::ExtensionLifecycle,
        RuntimeCapability::FsRead,
    ]);
    let report_a = membrane.inventory_report(&[request_a.clone(), request_b.clone()], &profile);
    let report_b = membrane.inventory_report(&[request_b, request_a], &profile);

    assert_eq!(report_a.schema_version, INVENTORY_SCHEMA_VERSION);
    assert_eq!(report_a.report_hash, report_a.canonical_hash());
    assert_eq!(report_a.report_hash, report_b.report_hash);
    assert_eq!(report_a.cohort_counts.get("node_api_portable"), Some(&2));
    assert!(
        report_a
            .compatibility_matrix
            .iter()
            .all(|entry| entry.support_status == NativeAddonSupportStatus::Direct)
    );
}

#[test]
fn artifact_bundle_writer_emits_expected_files() {
    let membrane = NativeAddonMembrane::standard();
    let requests = representative_inventory_requests();
    let profile = representative_inventory_profile();
    let artifact_root = std::env::temp_dir().join("franken-engine-native-addon-membrane-tests");
    let artifact_request = NativeAddonArtifactWriteRequest {
        run_id: "native-addon-artifact-bundle".to_string(),
        command_transcript: vec![
            "cargo test -p frankenengine-engine --test native_addon_membrane_integration artifact_bundle_writer_emits_expected_files".to_string(),
        ],
        generated_at_unix_ms: 1_730_000_000_000,
    };
    let bundle = membrane
        .write_artifact_bundle(
            &artifact_root,
            &context(),
            &requests,
            &profile,
            &artifact_request,
        )
        .expect("artifact bundle should write successfully");

    assert!(bundle.step_logs_dir.exists());
    for path in [
        &bundle.step_logs_dir,
        &bundle.run_manifest_path,
        &bundle.events_path,
        &bundle.commands_path,
        &bundle.trace_ids_path,
        &bundle.inventory_path,
        &bundle.support_surface_path,
        &bundle.compatibility_matrix_path,
        &bundle.abi_fingerprint_index_path,
        &bundle.membrane_report_path,
        &bundle.handle_safety_report_path,
        &bundle.execution_disposition_path,
        &bundle.fallback_receipts_path,
    ] {
        assert!(path.exists(), "missing artifact {}", path.display());
    }

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bundle.membrane_report_path).unwrap()).unwrap();
    assert_eq!(report["addon_count"], 4);
    assert_eq!(report["direct_count"], 1);
    assert_eq!(report["fallback_only_count"], 2);
    assert_eq!(report["unsupported_count"], 1);

    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bundle.run_manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["trace_id"], "trace-native-addon");
    assert_eq!(manifest["bead_id"], "bd-1lsy.5.9");
    assert_eq!(manifest["component"], "native_addon_membrane");
    assert!(
        manifest["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry.as_str() == Some("step_logs/"))
    );

    let events = fs::read_to_string(&bundle.events_path).unwrap();
    assert_eq!(events.lines().count(), 4);

    let compatibility_matrix: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bundle.compatibility_matrix_path).unwrap())
            .unwrap();
    let compatibility_matrix = compatibility_matrix.as_array().unwrap();
    let addon_ids = compatibility_matrix
        .iter()
        .map(|entry| entry["addon_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        addon_ids,
        BTreeSet::from([
            "delegate-addon",
            "direct-addon",
            "unsupported-addon",
            "wasm-addon",
        ])
    );
    let unsupported_entry = compatibility_matrix
        .iter()
        .find(|entry| entry["addon_id"].as_str() == Some("unsupported-addon"))
        .expect("unsupported cohort should still have an explicit disposition");
    assert_eq!(unsupported_entry["support_status"], "unsupported");
    assert!(unsupported_entry["selected_route"].is_null());

    let fallback_receipts: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bundle.fallback_receipts_path).unwrap()).unwrap();
    let fallback_receipts = fallback_receipts.as_array().unwrap();
    assert_eq!(fallback_receipts.len(), 2);
    let fallback_routes = fallback_receipts
        .iter()
        .map(|entry| entry["route"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        fallback_routes,
        BTreeSet::from(["delegate_cell", "wasm_port"])
    );
}

#[test]
fn suite_script_is_rch_backed_and_fail_closed() {
    let script =
        fs::read_to_string(repo_root().join("scripts/run_rgc_native_addon_membrane_suite.sh"))
            .expect("suite script should be readable");

    assert!(script.contains("rch exec -- env"));
    assert!(script.contains("rch reported local fallback; refusing local execution"));
    assert!(
        script.contains(
            "cargo check -p frankenengine-engine --test native_addon_membrane_integration"
        )
    );
    assert!(
        script.contains(
            "cargo test -p frankenengine-engine --test native_addon_membrane_integration"
        )
    );
    assert!(
        script.contains(
            "cargo clippy -p frankenengine-engine --test native_addon_membrane_integration --no-deps -- -D warnings"
        )
    );
    assert!(script.contains("RGC_NATIVE_ADDON_MEMBRANE_ARTIFACT_DIR"));
}

#[test]
fn replay_wrapper_delegates_to_suite_script() {
    let script =
        fs::read_to_string(repo_root().join("scripts/e2e/rgc_native_addon_membrane_replay.sh"))
            .expect("replay wrapper should be readable");

    assert!(
        script.contains("scripts/run_rgc_native_addon_membrane_suite.sh"),
        "replay wrapper should invoke the suite script"
    );
}

#[test]
fn native_addon_membrane_artifact_bridge_emits_bundle_when_env_is_set() {
    let Some(artifact_dir) = std::env::var_os("RGC_NATIVE_ADDON_MEMBRANE_ARTIFACT_DIR") else {
        return;
    };
    let artifact_dir = PathBuf::from(artifact_dir);
    let artifact_root = artifact_dir
        .parent()
        .expect("artifact directory should have a parent");
    let run_id = artifact_dir
        .file_name()
        .expect("artifact directory should end in a run id")
        .to_string_lossy()
        .into_owned();
    let membrane = NativeAddonMembrane::standard();
    let profile = representative_inventory_profile();
    let requests = representative_inventory_requests();

    let bundle = membrane
        .write_artifact_bundle(
            artifact_root,
            &context(),
            &requests,
            &profile,
            &NativeAddonArtifactWriteRequest {
                run_id,
                command_transcript: bridge_commands(),
                generated_at_unix_ms: 1_730_000_000_000,
            },
        )
        .expect("artifact bridge should write bundle");

    assert_eq!(bundle.run_dir, artifact_dir);
    assert!(bundle.step_logs_dir.exists());
}

// ---------------------------------------------------------------------------
// Enum as_str / Display round-trips
// ---------------------------------------------------------------------------

#[test]
fn abi_surface_as_str_display_round_trip() {
    let variants = [
        NativeAddonAbiSurface::NodeApi,
        NativeAddonAbiSurface::Nan,
        NativeAddonAbiSurface::V8Direct,
        NativeAddonAbiSurface::ForeignFfi,
        NativeAddonAbiSurface::Unknown,
    ];
    let mut seen = BTreeSet::new();
    for v in variants {
        let s = v.as_str();
        assert!(!s.is_empty());
        assert_eq!(v.to_string(), s);
        assert!(seen.insert(s), "duplicate as_str for AbiSurface");
    }
}

#[test]
fn cohort_as_str_display_round_trip() {
    let variants = [
        NativeAddonCohort::NodeApiPortable,
        NativeAddonCohort::NodeApiIsolateBound,
        NativeAddonCohort::NodeApiPrivileged,
        NativeAddonCohort::LegacyNan,
        NativeAddonCohort::V8Binding,
        NativeAddonCohort::ForeignFfi,
        NativeAddonCohort::Unknown,
    ];
    let mut seen = BTreeSet::new();
    for v in variants {
        let s = v.as_str();
        assert!(!s.is_empty());
        assert_eq!(v.to_string(), s);
        assert!(seen.insert(s), "duplicate as_str for Cohort");
    }
}

#[test]
fn fallback_mode_as_str_display_round_trip() {
    let variants = [
        NativeAddonFallbackMode::WasmPort,
        NativeAddonFallbackMode::DelegateCell,
    ];
    let mut seen = BTreeSet::new();
    for v in variants {
        assert_eq!(v.to_string(), v.as_str());
        assert!(seen.insert(v.as_str()));
    }
}

#[test]
fn route_as_str_display_round_trip() {
    let variants = [
        NativeAddonRoute::DirectMembrane,
        NativeAddonRoute::WasmPort,
        NativeAddonRoute::DelegateCell,
    ];
    let mut seen = BTreeSet::new();
    for v in variants {
        assert_eq!(v.to_string(), v.as_str());
        assert!(seen.insert(v.as_str()));
    }
}

#[test]
fn support_status_as_str_display_round_trip() {
    let variants = [
        NativeAddonSupportStatus::Direct,
        NativeAddonSupportStatus::FallbackOnly,
        NativeAddonSupportStatus::Unsupported,
    ];
    let mut seen = BTreeSet::new();
    for v in variants {
        assert_eq!(v.to_string(), v.as_str());
        assert!(seen.insert(v.as_str()));
    }
}

#[test]
fn handle_discipline_as_str_display_round_trip() {
    let variants = [
        NativeAddonHandleDiscipline::NodeApiOnly,
        NativeAddonHandleDiscipline::ThreadSafeFunctionOnly,
        NativeAddonHandleDiscipline::FinalizerBounded,
        NativeAddonHandleDiscipline::ExternalBuffer,
        NativeAddonHandleDiscipline::RawPointerEscape,
    ];
    let mut seen = BTreeSet::new();
    for v in variants {
        assert_eq!(v.to_string(), v.as_str());
        assert!(seen.insert(v.as_str()));
    }
}

#[test]
fn symbol_class_as_str_display_round_trip() {
    let variants = [
        NativeAddonSymbolClass::ValueExport,
        NativeAddonSymbolClass::FunctionExport,
        NativeAddonSymbolClass::ThreadSafeFunction,
        NativeAddonSymbolClass::Finalizer,
        NativeAddonSymbolClass::PropertyAccessor,
        NativeAddonSymbolClass::ExternalBuffer,
        NativeAddonSymbolClass::ForeignCallback,
        NativeAddonSymbolClass::GlobalStateHook,
        NativeAddonSymbolClass::Unknown,
    ];
    let mut seen = BTreeSet::new();
    for v in variants {
        assert_eq!(v.to_string(), v.as_str());
        assert!(seen.insert(v.as_str()));
    }
}

#[test]
fn invocation_channel_as_str_display_round_trip() {
    let variants = [
        NativeAddonInvocationChannel::InProcessMembrane,
        NativeAddonInvocationChannel::HostcallSession,
    ];
    let mut seen = BTreeSet::new();
    for v in variants {
        assert_eq!(v.to_string(), v.as_str());
        assert!(seen.insert(v.as_str()));
    }
}

#[test]
fn crash_containment_as_str_display_round_trip() {
    let variants = [
        NativeAddonCrashContainment::InProcessMembrane,
        NativeAddonCrashContainment::WasmSandbox,
        NativeAddonCrashContainment::DelegateCellBoundary,
    ];
    let mut seen = BTreeSet::new();
    for v in variants {
        assert_eq!(v.to_string(), v.as_str());
        assert!(seen.insert(v.as_str()));
    }
}

// ---------------------------------------------------------------------------
// HandleDiscipline::is_direct_safe
// ---------------------------------------------------------------------------

#[test]
fn handle_discipline_is_direct_safe_for_each_variant() {
    assert!(NativeAddonHandleDiscipline::NodeApiOnly.is_direct_safe());
    assert!(NativeAddonHandleDiscipline::ThreadSafeFunctionOnly.is_direct_safe());
    assert!(NativeAddonHandleDiscipline::FinalizerBounded.is_direct_safe());
    assert!(!NativeAddonHandleDiscipline::ExternalBuffer.is_direct_safe());
    assert!(!NativeAddonHandleDiscipline::RawPointerEscape.is_direct_safe());
}

// ---------------------------------------------------------------------------
// SymbolClass::is_direct_safe
// ---------------------------------------------------------------------------

#[test]
fn symbol_class_is_direct_safe_for_each_variant() {
    assert!(NativeAddonSymbolClass::ValueExport.is_direct_safe());
    assert!(NativeAddonSymbolClass::FunctionExport.is_direct_safe());
    assert!(NativeAddonSymbolClass::ThreadSafeFunction.is_direct_safe());
    assert!(NativeAddonSymbolClass::Finalizer.is_direct_safe());
    assert!(NativeAddonSymbolClass::PropertyAccessor.is_direct_safe());
    assert!(!NativeAddonSymbolClass::ExternalBuffer.is_direct_safe());
    assert!(!NativeAddonSymbolClass::ForeignCallback.is_direct_safe());
    assert!(!NativeAddonSymbolClass::GlobalStateHook.is_direct_safe());
    assert!(!NativeAddonSymbolClass::Unknown.is_direct_safe());
}

// ---------------------------------------------------------------------------
// Cohort classification
// ---------------------------------------------------------------------------

fn simple_node_api_request(id: &str) -> NativeAddonLoadRequest {
    NativeAddonLoadRequest::new(
        id,
        "pkg",
        "1.0.0",
        "pkg",
        "./build/addon.node",
        NativeAddonAbiSurface::NodeApi,
    )
    .with_node_api_version(8)
}

#[test]
fn cohort_default_node_api_portable() {
    let req = simple_node_api_request("portable-addon");
    assert_eq!(req.cohort(), NativeAddonCohort::NodeApiPortable);
}

#[test]
fn cohort_async_workers_yields_isolate_bound() {
    let mut req = simple_node_api_request("async-addon");
    req.uses_async_workers = true;
    assert_eq!(req.cohort(), NativeAddonCohort::NodeApiIsolateBound);
}

#[test]
fn cohort_thread_safe_function_symbol_yields_isolate_bound() {
    let req = simple_node_api_request("tsf-addon").with_symbol(NativeAddonSymbol::new(
        "worker_fn",
        NativeAddonSymbolClass::ThreadSafeFunction,
    ));
    assert_eq!(req.cohort(), NativeAddonCohort::NodeApiIsolateBound);
}

#[test]
fn cohort_process_global_state_yields_privileged() {
    let mut req = simple_node_api_request("global-addon");
    req.uses_process_global_state = true;
    assert_eq!(req.cohort(), NativeAddonCohort::NodeApiPrivileged);
}

#[test]
fn cohort_foreign_heap_yields_privileged() {
    let mut req = simple_node_api_request("heap-addon");
    req.uses_foreign_heap = true;
    assert_eq!(req.cohort(), NativeAddonCohort::NodeApiPrivileged);
}

#[test]
fn cohort_unsafe_discipline_yields_privileged() {
    let req = simple_node_api_request("unsafe-addon")
        .with_handle_discipline(NativeAddonHandleDiscipline::RawPointerEscape);
    assert_eq!(req.cohort(), NativeAddonCohort::NodeApiPrivileged);
}

#[test]
fn cohort_nan_yields_legacy_nan() {
    let req = NativeAddonLoadRequest::new(
        "nan-addon",
        "pkg",
        "1.0.0",
        "pkg",
        "./build/nan.node",
        NativeAddonAbiSurface::Nan,
    );
    assert_eq!(req.cohort(), NativeAddonCohort::LegacyNan);
}

#[test]
fn cohort_v8_direct_yields_v8_binding() {
    let req = NativeAddonLoadRequest::new(
        "v8-addon",
        "pkg",
        "1.0.0",
        "pkg",
        "./build/v8.node",
        NativeAddonAbiSurface::V8Direct,
    );
    assert_eq!(req.cohort(), NativeAddonCohort::V8Binding);
}

#[test]
fn cohort_foreign_ffi_yields_foreign_ffi() {
    let req = NativeAddonLoadRequest::new(
        "ffi-addon",
        "pkg",
        "1.0.0",
        "pkg",
        "./build/ffi.node",
        NativeAddonAbiSurface::ForeignFfi,
    );
    assert_eq!(req.cohort(), NativeAddonCohort::ForeignFfi);
}

#[test]
fn cohort_unknown_yields_unknown() {
    let req = NativeAddonLoadRequest::new(
        "unk-addon",
        "pkg",
        "1.0.0",
        "pkg",
        "./build/unk.node",
        NativeAddonAbiSurface::Unknown,
    );
    assert_eq!(req.cohort(), NativeAddonCohort::Unknown);
}

// ---------------------------------------------------------------------------
// required_capabilities
// ---------------------------------------------------------------------------

#[test]
fn required_capabilities_always_includes_extension_lifecycle() {
    let req = simple_node_api_request("basic");
    let caps = req.required_capabilities();
    assert!(caps.contains(&RuntimeCapability::ExtensionLifecycle));
}

#[test]
fn required_capabilities_reflects_fs_and_network_flags() {
    let mut req = simple_node_api_request("io-addon");
    req.requires_filesystem_read = true;
    req.requires_filesystem_write = true;
    req.requires_network_egress = true;
    req.requires_process_spawn = true;
    let caps = req.required_capabilities();
    assert!(caps.contains(&RuntimeCapability::FsRead));
    assert!(caps.contains(&RuntimeCapability::FsWrite));
    assert!(caps.contains(&RuntimeCapability::NetworkEgress));
    assert!(caps.contains(&RuntimeCapability::ProcessSpawn));
}

#[test]
fn required_capabilities_foreign_heap_implies_heap_allocate() {
    let mut req = simple_node_api_request("heap");
    req.uses_foreign_heap = true;
    assert!(
        req.required_capabilities()
            .contains(&RuntimeCapability::HeapAllocate)
    );
}

#[test]
fn required_capabilities_external_buffer_discipline_implies_heap() {
    let req = simple_node_api_request("extbuf")
        .with_handle_discipline(NativeAddonHandleDiscipline::ExternalBuffer);
    assert!(
        req.required_capabilities()
            .contains(&RuntimeCapability::HeapAllocate)
    );
}

#[test]
fn required_capabilities_symbol_caps_propagate() {
    let req = simple_node_api_request("sym-caps").with_symbol(
        NativeAddonSymbol::new("read_fn", NativeAddonSymbolClass::FunctionExport)
            .require_capability(RuntimeCapability::FsRead),
    );
    assert!(
        req.required_capabilities()
            .contains(&RuntimeCapability::FsRead)
    );
}

// ---------------------------------------------------------------------------
// required_slot_capabilities
// ---------------------------------------------------------------------------

#[test]
fn required_slot_capabilities_base_contains_emit_and_hostcall() {
    let req = simple_node_api_request("slot-base");
    let slots = req.required_slot_capabilities();
    assert!(slots.contains(&SlotCapability::EmitEvidence));
    assert!(slots.contains(&SlotCapability::InvokeHostcall));
}

#[test]
fn required_slot_capabilities_module_linkage_adds_module_access() {
    let mut req = simple_node_api_request("slot-module");
    req.requires_module_linkage = true;
    let slots = req.required_slot_capabilities();
    assert!(slots.contains(&SlotCapability::ModuleAccess));
}

#[test]
fn required_slot_capabilities_async_workers_adds_schedule_async() {
    let mut req = simple_node_api_request("slot-async");
    req.uses_async_workers = true;
    let slots = req.required_slot_capabilities();
    assert!(slots.contains(&SlotCapability::ScheduleAsync));
}

#[test]
fn required_slot_capabilities_foreign_heap_adds_heap_alloc() {
    let mut req = simple_node_api_request("slot-heap");
    req.uses_foreign_heap = true;
    let slots = req.required_slot_capabilities();
    assert!(slots.contains(&SlotCapability::HeapAlloc));
}

// ---------------------------------------------------------------------------
// NativeAddonMembraneErrorCode::stable_code
// ---------------------------------------------------------------------------

#[test]
fn error_code_stable_codes_non_empty_and_distinct() {
    let codes = [
        NativeAddonMembraneErrorCode::MissingCapability,
        NativeAddonMembraneErrorCode::UnsupportedAbiSurface,
        NativeAddonMembraneErrorCode::UnsafeDirectSurface,
        NativeAddonMembraneErrorCode::NoFallbackRoute,
    ];
    let mut seen = BTreeSet::new();
    for c in codes {
        let s = c.stable_code();
        assert!(!s.is_empty());
        assert!(seen.insert(s), "duplicate stable_code");
    }
}

// ---------------------------------------------------------------------------
// Serde round-trip for NativeAddonLoadRequest
// ---------------------------------------------------------------------------

#[test]
fn load_request_serde_roundtrip() {
    let mut req = simple_node_api_request("serde-addon")
        .with_symbol(NativeAddonSymbol::new(
            "init",
            NativeAddonSymbolClass::FunctionExport,
        ))
        .allow_fallback(NativeAddonFallbackMode::DelegateCell)
        .with_handle_discipline(NativeAddonHandleDiscipline::FinalizerBounded);
    req.requires_filesystem_read = true;
    req.uses_async_workers = true;

    let json = serde_json::to_string(&req).expect("serialize");
    let back: NativeAddonLoadRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(req, back);
}

// ---------------------------------------------------------------------------
// Empty inventory report
// ---------------------------------------------------------------------------

#[test]
fn empty_inventory_report() {
    let membrane = NativeAddonMembrane::standard();
    let profile = profile_with(&[RuntimeCapability::ExtensionLifecycle]);
    let report = membrane.inventory_report(&[], &profile);
    assert_eq!(report.schema_version, INVENTORY_SCHEMA_VERSION);
    assert!(report.support_surface.is_empty());
    assert!(report.compatibility_matrix.is_empty());
    assert!(report.abi_fingerprint_index.is_empty());
    assert!(report.cohort_counts.is_empty());
    assert_eq!(report.report_hash, report.canonical_hash());
}

// ---------------------------------------------------------------------------
// Report with mixed routes
// ---------------------------------------------------------------------------

#[test]
fn inventory_report_mixed_routes() {
    let membrane = NativeAddonMembrane::standard();
    let profile = profile_with(&[
        RuntimeCapability::ExtensionLifecycle,
        RuntimeCapability::HeapAllocate,
    ]);

    let direct_req = simple_node_api_request("direct-mix").with_symbol(NativeAddonSymbol::new(
        "open",
        NativeAddonSymbolClass::FunctionExport,
    ));
    let fallback_req = simple_node_api_request("fallback-mix")
        .with_handle_discipline(NativeAddonHandleDiscipline::RawPointerEscape)
        .allow_fallback(NativeAddonFallbackMode::DelegateCell);

    let report = membrane.inventory_report(&[direct_req, fallback_req], &profile);
    assert_eq!(report.support_surface.len(), 2);
    assert_eq!(report.compatibility_matrix.len(), 2);

    let direct_entry = report
        .compatibility_matrix
        .iter()
        .find(|e| e.addon_id == "direct-mix")
        .expect("direct entry");
    assert_eq!(
        direct_entry.support_status,
        NativeAddonSupportStatus::Direct
    );
    assert_eq!(
        direct_entry.selected_route,
        Some(NativeAddonRoute::DirectMembrane)
    );

    let fallback_entry = report
        .compatibility_matrix
        .iter()
        .find(|e| e.addon_id == "fallback-mix")
        .expect("fallback entry");
    assert_eq!(
        fallback_entry.support_status,
        NativeAddonSupportStatus::FallbackOnly
    );
    assert_eq!(
        fallback_entry.selected_route,
        Some(NativeAddonRoute::DelegateCell)
    );

    // Cohort counts should reflect two node_api variants
    let total: u32 = report.cohort_counts.values().sum();
    assert_eq!(total, 2);
}

// ---------------------------------------------------------------------------
// Unsupported ABI surface error
// ---------------------------------------------------------------------------

#[test]
fn unsupported_abi_surface_without_fallback_errors() {
    let membrane = NativeAddonMembrane::standard();
    let req = NativeAddonLoadRequest::new(
        "v8-no-fallback",
        "v8-pkg",
        "1.0.0",
        "v8-pkg",
        "./build/v8.node",
        NativeAddonAbiSurface::V8Direct,
    );
    let profile = profile_with(&[RuntimeCapability::ExtensionLifecycle]);
    let err = membrane
        .plan(&req, &context(), &profile)
        .expect_err("v8 direct without fallback must fail");
    assert_eq!(
        err.code,
        NativeAddonMembraneErrorCode::UnsupportedAbiSurface
    );
}

// ---------------------------------------------------------------------------
// Unsafe direct surface without approved fallback
// ---------------------------------------------------------------------------

#[test]
fn unsafe_direct_surface_no_fallback_yields_error() {
    let membrane = NativeAddonMembrane::standard();
    let req = simple_node_api_request("unsafe-no-fb")
        .with_handle_discipline(NativeAddonHandleDiscipline::RawPointerEscape);
    let profile = profile_with(&[
        RuntimeCapability::ExtensionLifecycle,
        RuntimeCapability::HeapAllocate,
    ]);
    let err = membrane
        .plan(&req, &context(), &profile)
        .expect_err("unsafe discipline without fallback must fail");
    assert_eq!(err.code, NativeAddonMembraneErrorCode::UnsafeDirectSurface);
}

// ---------------------------------------------------------------------------
// Node API version exceeding ceiling
// ---------------------------------------------------------------------------

#[test]
fn node_api_version_above_ceiling_blocks_direct() {
    let membrane = NativeAddonMembrane::standard();
    let req = NativeAddonLoadRequest::new(
        "future-api",
        "future-pkg",
        "1.0.0",
        "future-pkg",
        "./build/future.node",
        NativeAddonAbiSurface::NodeApi,
    )
    .with_node_api_version(99)
    .allow_fallback(NativeAddonFallbackMode::DelegateCell);
    let profile = profile_with(&[RuntimeCapability::ExtensionLifecycle]);
    let plan = membrane
        .plan(&req, &context(), &profile)
        .expect("should fall back");
    assert_eq!(plan.route, NativeAddonRoute::DelegateCell);
    assert!(
        plan.support_surface
            .direct_blockers
            .iter()
            .any(|b| b.contains("exceeds"))
    );
}

// ---------------------------------------------------------------------------
// Membrane default
// ---------------------------------------------------------------------------

#[test]
fn membrane_default_equals_standard() {
    let std = NativeAddonMembrane::standard();
    let def = NativeAddonMembrane::default();
    assert_eq!(std, def);
}
