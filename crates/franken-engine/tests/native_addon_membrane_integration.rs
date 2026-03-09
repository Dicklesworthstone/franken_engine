#![forbid(unsafe_code)]

use std::fs;

use frankenengine_engine::capability::{CapabilityProfile, RuntimeCapability};
use frankenengine_engine::module_resolver::ResolutionContext;
use frankenengine_engine::native_addon_membrane::{
    INVENTORY_SCHEMA_VERSION, NativeAddonAbiSurface, NativeAddonArtifactWriteRequest,
    NativeAddonCrashContainment, NativeAddonFallbackMode, NativeAddonHandleDiscipline,
    NativeAddonInvocationChannel, NativeAddonMembrane, NativeAddonMembraneErrorCode,
    NativeAddonRoute, NativeAddonSupportStatus, NativeAddonSymbol, NativeAddonSymbolClass,
};
use frankenengine_engine::self_replacement::DelegateType;
use frankenengine_engine::slot_registry::SlotCapability;

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
    let direct_request = frankenengine_engine::native_addon_membrane::NativeAddonLoadRequest::new(
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
    let fallback_request =
        frankenengine_engine::native_addon_membrane::NativeAddonLoadRequest::new(
            "fallback-addon",
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
    let artifact_root = std::env::temp_dir().join("franken-engine-native-addon-membrane-tests");
    let artifact_request = NativeAddonArtifactWriteRequest {
        run_id: "native-addon-artifact-bundle".to_string(),
        command_invocation: "cargo test -p frankenengine-engine --test native_addon_membrane_integration artifact_bundle_writer_emits_expected_files".to_string(),
        generated_at_unix_ms: 1_730_000_000_000,
    };
    let bundle = membrane
        .write_artifact_bundle(
            &artifact_root,
            &context(),
            &[direct_request, fallback_request],
            &profile,
            &artifact_request,
        )
        .expect("artifact bundle should write successfully");

    for path in [
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
    assert_eq!(report["addon_count"], 2);
    assert_eq!(report["direct_count"], 1);
    assert_eq!(report["fallback_only_count"], 1);
    assert_eq!(report["unsupported_count"], 0);

    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bundle.run_manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["trace_id"], "trace-native-addon");
    assert_eq!(manifest["bead_id"], "bd-1lsy.5.9");
    assert_eq!(manifest["component"], "native_addon_membrane");

    let events = fs::read_to_string(&bundle.events_path).unwrap();
    assert_eq!(events.lines().count(), 2);

    let fallback_receipts: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bundle.fallback_receipts_path).unwrap()).unwrap();
    let fallback_receipts = fallback_receipts.as_array().unwrap();
    assert_eq!(fallback_receipts.len(), 1);
    assert_eq!(fallback_receipts[0]["route"], "delegate_cell");
}
