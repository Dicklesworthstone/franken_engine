//! Filesystem provenance for the bounded JavaScript-to-Wasm route.
//!
//! A filesystem module captures raw bytes once, under the ordinary module-root
//! and replay-input boundary. Installing a closed-world resolver never turns
//! this origin into a resolver delivery or permits filesystem fallback.

use super::*;

#[derive(Debug)]
pub(super) enum JsWasmOrigin {
    Installed {
        request: ModuleRequest,
        record_id: String,
        content_hash: ContentHash,
    },
    Filesystem {
        canonical_root: PathBuf,
        content_hash: ContentHash,
    },
}

impl JsWasmOrigin {
    pub(super) fn retained_bytes(&self) -> u64 {
        match self {
            Self::Installed {
                request, record_id, ..
            } => (record_id.len() as u64)
                .saturating_add(request.specifier.len() as u64)
                .saturating_add(request.referrer.as_ref().map_or(0, |value| value.len() as u64)),
            Self::Filesystem { canonical_root, .. } => {
                canonical_root.as_os_str().len() as u64
            }
        }
        .saturating_mul(8)
    }
}

pub(super) enum JsWasmSource<'a> {
    Resolver(&'a str),
    Filesystem(Vec<u8>),
}

impl JsWasmSource<'_> {
    pub(super) fn byte_len(&self) -> u64 {
        match self {
            Self::Resolver(source) => source.len() as u64,
            Self::Filesystem(bytes) => bytes.len() as u64,
        }
    }
}

impl InterpreterCore {
    /// Module capabilities apply before the first binary read and on cached
    /// namespace requests as well as every call into an instantiated module.
    pub(super) fn authorize_wasm_capabilities(&mut self) -> Result<(), InterpreterError> {
        let ip = u32::try_from(self.ip).unwrap_or(u32::MAX);
        check_hostcall_capability_gate(self, "module_load", ip)?;
        check_hostcall_capability_gate(self, "vm_dispatch", ip)?;
        for capability in [RuntimeCapability::ModuleLoad, RuntimeCapability::VmDispatch] {
            if !self.config.granted_capabilities.contains(&capability) {
                return Err(InterpreterError::CapabilityDenied {
                    capability: capability.to_string(),
                });
            }
        }
        Ok(())
    }

    pub(super) fn prepare_wasm_source<'a>(
        &mut self,
        resolved: &str,
        attributes: &ImportAttributes,
        delivered: Option<&'a SharedResolvedModule>,
    ) -> Result<(JsWasmOrigin, JsWasmSource<'a>), InterpreterError> {
        self.authorize_wasm_capabilities()?;
        if let Some(source) = delivered {
            if !crate::module_resolver::wasm_module_required_capabilities()
                .is_subset(&source.record.required_capabilities)
            {
                return Err(Self::wasm_load_error(
                    resolved,
                    "module contract must require module_load and vm_dispatch",
                ));
            }
            let installed = self
                .module_resolver
                .as_ref()
                .ok_or_else(|| Self::wasm_load_error(resolved, "no installed resolver"))?;
            let request = ModuleRequest::new(&source.request_specifier, ImportStyle::Import)
                .with_referrer(
                    self.current_module_specifier
                        .as_deref()
                        .unwrap_or_else(|| installed.resolver.entry_referrer()),
                )
                .with_compatibility_mode(CompatibilityMode::NodeCompat)
                .with_import_attributes(attributes.clone());
            return Ok((
                JsWasmOrigin::Installed {
                    request,
                    record_id: source.record.id.clone(),
                    content_hash: source.content_hash,
                },
                JsWasmSource::Resolver(&source.record.source),
            ));
        }
        if self.module_resolver.is_some() {
            return Err(Self::wasm_load_error(
                resolved,
                "installed resolver cannot fall back to filesystem source",
            ));
        }
        let canonical_root = self.canonical_module_root_path().ok_or_else(|| {
            Self::wasm_load_error(resolved, "filesystem Wasm requires a configured module root")
        })?;
        let canonical = self.canonicalize_module_candidate(resolved, Path::new(resolved))?;
        if canonical != Path::new(resolved) {
            return Err(Self::wasm_load_error(
                resolved,
                "filesystem module identity changed before its binary read",
            ));
        }
        let bytes = self.read_module_bytes(resolved)?;
        let content_hash = ContentHash::compute(&bytes);
        let record = self.module_state.modules.get_mut(resolved).ok_or_else(|| {
            Self::wasm_load_error(resolved, "filesystem Wasm namespace was not admitted")
        })?;
        record.resolved_source_hash = Some(content_hash);
        Ok((
            JsWasmOrigin::Filesystem {
                canonical_root,
                content_hash,
            },
            JsWasmSource::Filesystem(bytes),
        ))
    }

    pub(super) fn authorize_filesystem_wasm(
        &self,
        resolved: &str,
        canonical_root: &Path,
        content_hash: ContentHash,
    ) -> Result<(), InterpreterError> {
        if self.module_resolver.is_some() {
            return Err(Self::wasm_load_error(
                resolved,
                "filesystem Wasm handle cannot run under an installed resolver",
            ));
        }
        if self.canonical_module_root_path().as_deref() != Some(canonical_root)
            || !Path::new(resolved).starts_with(canonical_root)
        {
            return Err(Self::wasm_load_error(
                resolved,
                "filesystem module root changed after its first authorized load",
            ));
        }
        // As with JS modules, later imports and invocations use the captured
        // instance. Replay verifies the original raw bytes at the next run's
        // read boundary, rather than observing a mutable file on every call.
        if self
            .module_state
            .modules
            .get(resolved)
            .and_then(|record| record.resolved_source_hash)
            != Some(content_hash)
        {
            return Err(Self::wasm_load_error(
                resolved,
                "filesystem module source identity changed",
            ));
        }
        Ok(())
    }
}
