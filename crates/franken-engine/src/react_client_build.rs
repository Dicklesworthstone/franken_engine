//! Closed-world ESM client builds using the native React compiler.
//!
//! Source capture is bounded by an explicit project root and resource limits.
//! Modules remain ESM, so the browser owns live bindings, cycles, top-level
//! await, and evaluation order. No guest code or external provider is executed
//! while building. Literal dynamic imports retain lazy ESM execution and share
//! the bounded graph with static imports. Local JSON dependencies with the
//! explicit `type: "json"` attribute become default-only ESM assets. Installed
//! ESM packages use browser/import exports conditions and bounded package
//! metadata; legacy packages may select their explicit ESM module entry.
//! Computed imports, CommonJS, other attributes, and other non-code assets are
//! refused.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ast::{ExportKind, Expression, ImportClause, Statement};
use crate::baseline_interpreter::{
    MAX_PACKAGE_MANIFEST_BYTES, ModuleResolutionFailureReason, PackageManifest,
    resolve_browser_package,
};
use crate::capability::RuntimeCapability;
use crate::hash_tiers::ContentHash;
use crate::import_attributes::ImportAttributes;
use crate::jsx_tsx_parser::import_call_candidates;
use crate::module_resolver::{
    CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
    ModuleDependency, ModuleRequest, ModuleResolver, ModuleSyntax, ResolutionContext,
    validate_import_attributes,
};
use crate::parser::{CanonicalEs2020Parser, Es2020Parser};
use crate::react_compilation_pipeline::{
    ReactCompileConfig, ReactInputLanguage, compile_react_module,
};

pub const REACT_CLIENT_BUILD_SCHEMA_VERSION: &str = "franken-engine.react-client-build.v1";
const EXTENSIONS: &[&str] = &["js", "mjs", "jsx", "ts", "mts", "tsx"];

/// Explicit inputs to an offline client build. `entry` is relative to the
/// caller's working directory; `project_root` bounds every captured source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactClientBuildConfig {
    pub project_root: PathBuf,
    pub entry: PathBuf,
    pub externals: BTreeMap<String, String>,
    pub compile: ReactCompileConfig,
    pub max_modules: usize,
    pub max_source_bytes: usize,
    pub max_output_bytes: usize,
}

impl Default for ReactClientBuildConfig {
    fn default() -> Self {
        Self {
            project_root: PathBuf::from("."),
            entry: PathBuf::from("index.jsx"),
            externals: BTreeMap::new(),
            compile: ReactCompileConfig::default(),
            max_modules: 1_024,
            max_source_bytes: 32 * 1_024 * 1_024,
            max_output_bytes: 64 * 1_024 * 1_024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactClientDependency {
    pub specifier: String,
    /// An emitted asset path for a local module, or an explicitly selected URL.
    pub target: String,
    pub external: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactClientModuleAsset {
    pub source_path: String,
    pub asset_path: String,
    pub code: String,
    pub source_map: Option<String>,
    pub source_hash: ContentHash,
    pub output_hash: ContentHash,
    pub dependencies: Vec<ReactClientDependency>,
}

/// Captured package metadata participates in executable graph selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactClientPackageInput {
    pub source_path: String,
    pub source_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactClientBuild {
    pub schema_version: String,
    pub entry_asset: String,
    /// Commits compiler options and resource limits without retaining host paths.
    pub config_hash: ContentHash,
    pub graph_hash: ContentHash,
    pub modules: Vec<ReactClientModuleAsset>,
    /// Ordered metadata inputs used by package selection, hashed as read.
    /// Empty graphs retain the original v1 identity and serialized shape.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub package_inputs: Vec<ReactClientPackageInput>,
    /// The complete explicit provider configuration; no default CDN is chosen.
    pub import_map: BTreeMap<String, String>,
}

impl ReactClientBuild {
    /// Verify the complete content identity before consuming or publishing a
    /// serialized build. This checks integrity, not producer authenticity.
    pub fn verify_integrity(&self) -> BuildResult<()> {
        let malformed = || {
            ReactClientBuildError::new(
                "FE-REACT-BUILD-INTEGRITY",
                "client graph identity or module linkage is invalid",
            )
        };
        if self.schema_version != REACT_CLIENT_BUILD_SCHEMA_VERSION
            || self.modules.is_empty()
            || self
                .modules
                .windows(2)
                .any(|pair| pair[0].source_path >= pair[1].source_path)
        {
            return Err(malformed());
        }
        if self
            .package_inputs
            .windows(2)
            .any(|pair| pair[0].source_path >= pair[1].source_path)
            || self.package_inputs.iter().any(|input| {
                let path = input.source_path.as_str();
                path.contains('\\')
                    || path.chars().any(char::is_control)
                    || path.split('/').any(|part| matches!(part, "" | "." | ".."))
            })
        {
            return Err(malformed());
        }
        validate_externals(&self.import_map)?;
        let mut paths = BTreeSet::new();
        for module in &self.modules {
            if module.asset_path != asset_path(&module.source_path)
                || !paths.insert(module.asset_path.as_str())
                || module.output_hash != ContentHash::compute(module.code.as_bytes())
            {
                return Err(malformed());
            }
        }
        if !paths.contains(self.entry_asset.as_str()) {
            return Err(malformed());
        }
        for module in &self.modules {
            for dependency in &module.dependencies {
                let linked = if dependency.external {
                    self.import_map.get(&dependency.specifier) == Some(&dependency.target)
                } else {
                    paths.contains(dependency.target.as_str())
                };
                if !linked {
                    return Err(malformed());
                }
            }
        }
        if self.graph_hash
            != graph_identity_hash(
                &self.entry_asset,
                self.config_hash,
                &self.import_map,
                &self.modules,
                &self.package_inputs,
            )?
        {
            return Err(malformed());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactClientBuildError {
    pub code: &'static str,
    pub message: String,
}

impl ReactClientBuildError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ReactClientBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ReactClientBuildError {}

type BuildResult<T> = Result<T, ReactClientBuildError>;

#[derive(Default)]
struct CapturedPackages {
    /// Cache absent manifests too: one build never changes a package scope
    /// after discovering it. Existing files are keyed by canonical paths.
    paths: BTreeMap<PathBuf, Option<PathBuf>>,
    manifests: BTreeMap<PathBuf, PackageManifest>,
    inputs: BTreeMap<String, ReactClientPackageInput>,
}

impl CapturedPackages {
    fn read_manifest(
        &mut self,
        directory: &Path,
        root: &Path,
        source_bytes: &mut usize,
        max_source_bytes: usize,
    ) -> BuildResult<Option<PackageManifest>> {
        let path = directory.join("package.json");
        if let Some(canonical) = self.paths.get(&path) {
            return Ok(canonical
                .as_ref()
                .and_then(|canonical| self.manifests.get(canonical))
                .cloned());
        }
        match path.symlink_metadata() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.paths.insert(path, None);
                return Ok(None);
            }
            Err(error) => {
                return Err(ReactClientBuildError::new(
                    "FE-REACT-BUILD-READ",
                    format!("cannot inspect {}: {error}", path.display()),
                ));
            }
            Ok(_) => {}
        }
        // Never read through an unchecked package.json symlink. Canonical
        // source identity also prevents aliased packages charging it twice.
        let canonical = confined_input_file(&path, root)?;
        if !self.manifests.contains_key(&canonical) {
            let remaining = max_source_bytes.saturating_sub(*source_bytes);
            let source = read_bounded_source(
                &canonical,
                remaining.min(usize::try_from(MAX_PACKAGE_MANIFEST_BYTES).unwrap_or(usize::MAX)),
            )?;
            let manifest = PackageManifest::from_bytes(source.as_bytes()).map_err(|error| {
                ReactClientBuildError::new(
                    "FE-REACT-BUILD-PACKAGE",
                    format!("invalid {}: {error}", canonical.display()),
                )
            })?;
            *source_bytes += source.len();
            let name = source_name(&canonical, root)?;
            self.inputs.insert(
                name.clone(),
                ReactClientPackageInput {
                    source_path: name,
                    source_hash: ContentHash::compute(source.as_bytes()),
                },
            );
            self.manifests.insert(canonical.clone(), manifest);
        }
        let manifest = self.manifests.get(&canonical).cloned();
        self.paths.insert(path, Some(canonical));
        Ok(manifest)
    }
}

fn resolve_client_source(
    referrer: &Path,
    specifier: &str,
    root: &Path,
    packages: &mut CapturedPackages,
    source_bytes: &mut usize,
    max_source_bytes: usize,
) -> BuildResult<PathBuf> {
    if specifier.starts_with("./") || specifier.starts_with("../") {
        return resolve_local_source(referrer, specifier, root);
    }
    if specifier.is_empty()
        || specifier.starts_with(['.', '/'])
        || specifier.contains([':', '\\', '?'])
        || specifier.chars().any(char::is_control)
        || specifier
            .strip_prefix('#')
            .unwrap_or(specifier)
            .contains('#')
    {
        return Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-SPECIFIER",
            format!("unsupported package specifier '{specifier}'"),
        ));
    }
    let target = resolve_browser_package(
        specifier,
        referrer,
        root,
        &mut |directory| packages.read_manifest(directory, root, source_bytes, max_source_bytes),
        &|path| confined_file(path, root),
        &|reason| match reason {
            ModuleResolutionFailureReason::ModuleNotFound => ReactClientBuildError::new(
                "FE-REACT-BUILD-EXTERNAL",
                format!(
                    "cannot resolve installed ESM package '{specifier}'; declare --external {specifier}=<HTTP(S)-module-URL> or install it inside the project root",
                ),
            ),
            reason => ReactClientBuildError::new(
                "FE-REACT-BUILD-PACKAGE",
                format!("{specifier}: {reason}"),
            ),
        },
    )?;
    let path = confined_file(&target, root)?;
    if path
        .to_str()
        .is_some_and(|name| name.ends_with(".d.ts") || name.ends_with(".d.mts"))
    {
        return Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-FORMAT",
            "package entry selects a declaration file instead of runtime code",
        ));
    }
    Ok(path)
}

#[derive(Debug)]
struct SourceImport {
    specifier: String,
    span: std::ops::Range<usize>,
    /// A declaration prefix for static imports. For import(), the span covers
    /// the literal, or the argument list when consuming a JSON attribute.
    declaration: Option<String>,
    attributes: ImportAttributes,
    /// JSON module namespaces expose only `default`. Namespace and star edges
    /// are valid; named imports and reexports must name that one export.
    json_exports_valid: bool,
}

#[derive(Debug)]
struct SourceEdit {
    start: usize,
    end: usize,
    replacement: String,
}

/// Compile the complete reachable local module graph before returning assets.
/// No output paths are written, including on a missing dependency or refusal.
pub fn build_react_client(config: &ReactClientBuildConfig) -> BuildResult<ReactClientBuild> {
    if config.max_modules == 0 || config.max_source_bytes == 0 || config.max_output_bytes == 0 {
        return Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-LIMIT",
            "build budgets must be positive",
        ));
    }
    validate_externals(&config.externals)?;
    let root = config.project_root.canonicalize().map_err(|error| {
        ReactClientBuildError::new(
            "FE-REACT-BUILD-ROOT",
            format!("cannot resolve project root: {error}"),
        )
    })?;
    if !root.is_dir() {
        return Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-ROOT",
            "project root is not a directory",
        ));
    }
    let entry = confined_file(&config.entry, &root)?;
    if source_language(&entry)?.is_none() {
        return Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-FORMAT",
            "the client entry must be JavaScript or TypeScript; import JSON dependencies with type: 'json'",
        ));
    }
    let entry_name = source_name(&entry, &root)?;
    let mut queue = VecDeque::from([entry.clone()]);
    let mut queued = BTreeSet::from([entry]);
    let mut modules = BTreeMap::new();
    let mut source_bytes = 0usize;
    let mut packages = CapturedPackages::default();
    let mut output_bytes = 0usize;
    let mut resolver = DeterministicModuleResolver::new("/");

    while let Some(path) = queue.pop_front() {
        let name = source_name(&path, &root)?;
        let language = source_language(&path)?;
        let source = read_bounded_source(&path, config.max_source_bytes - source_bytes)?;
        source_bytes += source.len();
        let mut compile_config = config.compile.clone();
        compile_config.lowering_config.source_file = Some(name.clone());
        let (generated_code, source_map, syntax) = match language {
            Some(language) => {
                let compiled =
                    compile_react_module(&source, language, &compile_config).map_err(|error| {
                        ReactClientBuildError::new(
                            "FE-REACT-BUILD-COMPILE",
                            format!("{name}: {error}"),
                        )
                    })?;
                (
                    compiled.generated_code,
                    compiled.source_map,
                    ModuleSyntax::EsModule,
                )
            }
            None => {
                let (code, map) = compile_json_module(
                    &source,
                    &name,
                    compile_config.generate_source_maps,
                    config.max_output_bytes - output_bytes,
                )?;
                (code, map, ModuleSyntax::Json)
            }
        };
        let tree = CanonicalEs2020Parser
            .parse(generated_code.as_str(), crate::ast::ParseGoal::Module)
            .map_err(|error| {
                ReactClientBuildError::new("FE-REACT-BUILD-PARSE", format!("{name}: {error}"))
            })?;
        let mut expected_ast = serde_json::to_value(&tree).map_err(serialization_error)?;
        let mut imports = bounded_dynamic_imports(&generated_code, &expected_ast, &name)?;
        let mut edits = Vec::new();
        let mut dynamic_edits = Vec::new();
        let mut dynamic_targets = BTreeMap::new();
        let mut dependencies = Vec::new();
        let mut definition = ModuleDefinition::new(
            syntax,
            if syntax == ModuleSyntax::Json {
                source.clone()
            } else {
                generated_code.clone()
            },
        )
        .require_capability(RuntimeCapability::ModuleLoad)
        .with_provenance(name.clone());

        for statement in &tree.body {
            let (specifier, declaration, attributes, json_exports_valid) = match statement {
                Statement::Import(import) => (
                    import.source.as_str(),
                    Some(import_prefix(&import.clause)?),
                    &import.import_attributes,
                    json_import_exports_valid(&import.clause),
                ),
                Statement::Export(export) => match &export.kind {
                    ExportKind::NamedClause(clause) if clause.source().is_some() => (
                        clause.source().and_then(|source| source.as_str()),
                        Some(format!("export {} from ", clause.canonical_head())),
                        clause.import_attributes(),
                        json_reexport_exports_valid(clause.canonical_head()),
                    ),
                    _ => continue,
                },
                _ => continue,
            };
            let specifier = specifier.ok_or_else(|| {
                ReactClientBuildError::new(
                    "FE-REACT-BUILD-SPECIFIER",
                    format!("{name}: module specifier is not valid UTF-8"),
                )
            })?;
            let span = statement.span();
            imports.push(SourceImport {
                specifier: specifier.to_string(),
                span: usize::try_from(span.start_offset).map_err(|_| invalid_span())?
                    ..usize::try_from(span.end_offset).map_err(|_| invalid_span())?,
                declaration,
                attributes: attributes.clone(),
                json_exports_valid,
            });
        }
        imports.sort_unstable_by_key(|import| import.span.start);
        for import in imports {
            let specifier = import.specifier.as_str();
            let (target, emitted_specifier, external) =
                if let Some(url) = config.externals.get(specifier) {
                    // We do not capture or verify external provider formats.
                    // Never erase an attribute on an unverified external edge.
                    validate_client_import(ModuleSyntax::EsModule, &import, &name)?;
                    (url.clone(), specifier.to_string(), true)
                } else {
                    let dependency = resolve_client_source(
                        &path,
                        specifier,
                        &root,
                        &mut packages,
                        &mut source_bytes,
                        config.max_source_bytes,
                    )?;
                    let dependency_syntax = if source_language(&dependency)?.is_none() {
                        ModuleSyntax::Json
                    } else {
                        ModuleSyntax::EsModule
                    };
                    validate_client_import(dependency_syntax, &import, &name)?;
                    let dependency_name = source_name(&dependency, &root)?;
                    definition.dependencies.push(
                        ModuleDependency::new(format!("/{dependency_name}"), ImportStyle::Import)
                            .with_import_attributes(import.attributes.clone()),
                    );
                    if queued.insert(dependency.clone()) {
                        if queued.len() > config.max_modules {
                            return Err(ReactClientBuildError::new(
                                "FE-REACT-BUILD-LIMIT",
                                "module count exceeds the build budget",
                            ));
                        }
                        queue.push_back(dependency);
                    }
                    let target = asset_path(&dependency_name);
                    let emitted = format!(
                        "./{}",
                        target.strip_prefix("modules/").expect("asset prefix")
                    );
                    (target, emitted, false)
                };
            dependencies.push(ReactClientDependency {
                specifier: specifier.to_string(),
                target,
                external,
            });
            let original = generated_code
                .get(import.span.clone())
                .ok_or_else(invalid_span)?;
            let newlines = line_offsets(original).len() - 1;
            let mut literal = js_string(&emitted_specifier)?;
            let replacement = if let Some(declaration) = import.declaration {
                // Keep physical line counts, then remap columns for unchanged code.
                format!("{declaration}{literal};{}", "\n".repeat(newlines))
            } else {
                // Keep the same line count even when a multi-line JSON options
                // object becomes part of the mapped specifier replacement.
                literal.insert_str(literal.len() - 1, &"\\\n".repeat(newlines));
                dynamic_targets.insert(import.specifier, emitted_specifier);
                dynamic_edits.push(SourceEdit {
                    start: import.span.start,
                    end: import.span.end,
                    replacement: literal.clone(),
                });
                literal
            };
            edits.push(SourceEdit {
                start: import.span.start,
                end: import.span.end,
                replacement,
            });
        }
        if !dynamic_edits.is_empty() {
            verify_dynamic_import_edits(
                &generated_code,
                &mut expected_ast,
                &dynamic_edits,
                &dynamic_targets,
            )?;
        }
        let mut code = apply_edits(&generated_code, &edits)?;
        let asset = asset_path(&name);
        let source_map = source_map
            .as_deref()
            .map(|map| remap_source_map(map, &generated_code, &code, &edits, &asset))
            .transpose()?;
        if source_map.is_some() {
            code.push_str(&format!(
                "\n//# sourceMappingURL={}.map\n",
                asset.strip_prefix("modules/").expect("asset prefix")
            ));
        }
        // Check the complete delivered bytes as well, so declaration-span
        // or ImportCall reconstruction defects cannot emit invalid JavaScript.
        CanonicalEs2020Parser
            .parse(code.as_str(), crate::ast::ParseGoal::Module)
            .map_err(|error| {
                ReactClientBuildError::new("FE-REACT-BUILD-EMIT", format!("{name}: {error}"))
            })?;
        output_bytes = output_bytes
            .checked_add(code.len())
            .and_then(|total| total.checked_add(source_map.as_ref().map_or(0, String::len)))
            .ok_or_else(|| {
                ReactClientBuildError::new("FE-REACT-BUILD-LIMIT", "generated output size overflow")
            })?;
        if output_bytes > config.max_output_bytes {
            return Err(ReactClientBuildError::new(
                "FE-REACT-BUILD-LIMIT",
                "generated output exceeds the build budget",
            ));
        }
        resolver
            .register_workspace_module(format!("/{name}"), definition)
            .map_err(|error| {
                ReactClientBuildError::new("FE-REACT-BUILD-RESOLVE", error.to_string())
            })?;
        modules.insert(
            name.clone(),
            ReactClientModuleAsset {
                source_path: name,
                asset_path: asset,
                output_hash: ContentHash::compute(code.as_bytes()),
                source_hash: ContentHash::compute(source.as_bytes()),
                code,
                source_map,
                dependencies,
            },
        );
    }

    // Exercise the same capability-aware closed-world resolver used by native
    // execution. Every local edge is re-authorized, including repeated edges
    // and cycles; filesystem discovery never stands in for this check.
    resolver
        .resolve_chain(
            &ModuleRequest::new(format!("/{entry_name}"), ImportStyle::Import),
            &ResolutionContext::new(
                "react-client-build",
                "closed-world-graph",
                "react-client-esm-v1",
            ),
            &CapabilityPolicyHook::new(BTreeSet::from([RuntimeCapability::ModuleLoad])),
        )
        .map_err(|error| ReactClientBuildError::new("FE-REACT-BUILD-RESOLVE", error.to_string()))?;

    let package_inputs: Vec<_> = packages.inputs.into_values().collect();
    if !package_inputs.is_empty() {
        // Account the new serialized metadata alongside code and maps. A
        // complete pretty-printed field includes punctuation and indentation
        // conservatively for both compact and pretty graph consumers, without
        // changing the historical limit for builds with no package metadata.
        output_bytes = output_bytes
            .checked_add(
                serde_json::to_vec_pretty(&BTreeMap::from([("package_inputs", &package_inputs)]))
                    .map_err(serialization_error)?
                    .len(),
            )
            .ok_or_else(|| {
                ReactClientBuildError::new("FE-REACT-BUILD-LIMIT", "package metadata size overflow")
            })?;
        if output_bytes > config.max_output_bytes {
            return Err(ReactClientBuildError::new(
                "FE-REACT-BUILD-LIMIT",
                "package metadata and generated output exceed the build budget",
            ));
        }
    }
    let modules: Vec<_> = modules.into_values().collect();
    let entry_asset = asset_path(&entry_name);
    let config_identity = serde_json::to_vec(&(
        "franken-engine.react-client-build-config.v1",
        &config.compile,
        config.max_modules,
        config.max_source_bytes,
        config.max_output_bytes,
    ))
    .map_err(serialization_error)?;
    let config_hash = ContentHash::compute(&config_identity);
    let build = ReactClientBuild {
        schema_version: REACT_CLIENT_BUILD_SCHEMA_VERSION.to_string(),
        graph_hash: graph_identity_hash(
            &entry_asset,
            config_hash,
            &config.externals,
            &modules,
            &package_inputs,
        )?,
        entry_asset,
        config_hash,
        modules,
        package_inputs,
        import_map: config.externals.clone(),
    };
    build.verify_integrity()?;
    Ok(build)
}

fn graph_identity_hash(
    entry: &str,
    config_hash: ContentHash,
    externals: &BTreeMap<String, String>,
    modules: &[ReactClientModuleAsset],
    package_inputs: &[ReactClientPackageInput],
) -> BuildResult<ContentHash> {
    let identity = if package_inputs.is_empty() {
        serde_json::to_vec(&(
            REACT_CLIENT_BUILD_SCHEMA_VERSION,
            entry,
            config_hash,
            externals,
            modules,
        ))
    } else {
        serde_json::to_vec(&(
            REACT_CLIENT_BUILD_SCHEMA_VERSION,
            entry,
            config_hash,
            externals,
            modules,
            package_inputs,
        ))
    };
    identity
        .map(|bytes| ContentHash::compute(&bytes))
        .map_err(serialization_error)
}

fn validate_externals(externals: &BTreeMap<String, String>) -> BuildResult<()> {
    for (specifier, target) in externals {
        if specifier.is_empty()
            || specifier.starts_with('.')
            || specifier.starts_with('/')
            || specifier.ends_with('/')
            || specifier.contains(':')
            || specifier.chars().any(char::is_control)
        {
            return Err(ReactClientBuildError::new(
                "FE-REACT-BUILD-EXTERNAL",
                "external keys must be exact bare module specifiers without URL schemes or a trailing slash",
            ));
        }
        let url = url::Url::parse(target).map_err(|error| {
            ReactClientBuildError::new(
                "FE-REACT-BUILD-EXTERNAL",
                format!("{specifier}: invalid provider URL: {error}"),
            )
        })?;
        let loopback = url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || target.chars().any(char::is_control)
        {
            return Err(ReactClientBuildError::new(
                "FE-REACT-BUILD-EXTERNAL",
                format!(
                    "{specifier}: use an explicit HTTPS module URL (HTTP is restricted to loopback) without credentials",
                ),
            ));
        }
    }
    Ok(())
}

fn source_name(path: &Path, root: &Path) -> BuildResult<String> {
    let relative = path.strip_prefix(root).map_err(|_| outside_root())?;
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(value) => value.to_str().ok_or_else(|| {
                ReactClientBuildError::new("FE-REACT-BUILD-PATH", "source path is not valid UTF-8")
            }),
            _ => Err(outside_root()),
        })
        .collect::<BuildResult<Vec<_>>>()?;
    Ok(components.join("/"))
}

fn confined_file(path: &Path, root: &Path) -> BuildResult<PathBuf> {
    let canonical = confined_input_file(path, root)?;
    let _ = source_language(&canonical)?;
    Ok(canonical)
}

fn confined_input_file(path: &Path, root: &Path) -> BuildResult<PathBuf> {
    let canonical = path.canonicalize().map_err(|error| {
        ReactClientBuildError::new(
            "FE-REACT-BUILD-MISSING",
            format!("cannot read module {}: {error}", path.display()),
        )
    })?;
    if !canonical.starts_with(root) {
        return Err(outside_root());
    }
    if !canonical.is_file() {
        return Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-FORMAT",
            "module source must be a regular file",
        ));
    }
    Ok(canonical)
}

fn outside_root() -> ReactClientBuildError {
    ReactClientBuildError::new(
        "FE-REACT-BUILD-ROOT",
        "module resolution escapes the explicit project root",
    )
}

fn validate_client_import(
    syntax: ModuleSyntax,
    import: &SourceImport,
    referrer: &str,
) -> BuildResult<()> {
    validate_import_attributes(ImportStyle::Import, syntax, &import.attributes).map_err(
        |error| {
            ReactClientBuildError::new(
                "FE-REACT-BUILD-ATTRIBUTES",
                format!("{referrer}: {}: {error}", import.specifier),
            )
        },
    )?;
    if syntax == ModuleSyntax::Json && !import.json_exports_valid {
        return Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-EXPORT",
            format!(
                "{referrer}: JSON module '{}' exports only default",
                import.specifier
            ),
        ));
    }
    Ok(())
}

fn json_import_exports_valid(clause: &ImportClause) -> bool {
    match clause {
        ImportClause::Named { specifiers } | ImportClause::DefaultAndNamed { specifiers, .. } => {
            specifiers
                .iter()
                .all(|specifier| specifier.import_name == "default")
        }
        _ => true,
    }
}

fn json_reexport_exports_valid(head: &str) -> bool {
    if head == "*" || head.starts_with("* as ") {
        return true;
    }
    // This is a parser-validated canonical head. Encoded string export names
    // contain no commas or spaces, as documented by encode_module_export_name.
    head.strip_prefix('{')
        .and_then(|head| head.strip_suffix('}'))
        .is_some_and(|head| {
            head.split(',').all(|specifier| {
                specifier
                    .split_whitespace()
                    .next()
                    .is_none_or(|name| crate::parser::decode_module_export_name(name) == "default")
            })
        })
}

/// Validate data without materializing a serde value tree, then preserve its
/// literal spellings in a default-only ES module. JSON string escapes may
/// contain lone surrogates, numbers may overflow to infinity, and `-0` must
/// retain its sign. Roundtripping through serde_json::Value would lose those
/// distinctions. Computed property keys give every JSON object member ordinary
/// data-property semantics, including duplicate and escaped `__proto__` keys.
/// No mutable guest JSON.parse/Object helper participates in evaluation.
fn compile_json_module(
    source: &str,
    name: &str,
    generate_source_maps: bool,
    output_budget: usize,
) -> BuildResult<(String, Option<String>)> {
    let mut decoder = serde_json::Deserializer::from_str(source);
    serde::de::IgnoredAny::deserialize(&mut decoder)
        .and_then(|_| decoder.end())
        .map_err(|error| {
            ReactClientBuildError::new("FE-REACT-BUILD-JSON", format!("{name}: {error}"))
        })?;

    let append = |output: &mut String, text: &str| -> BuildResult<()> {
        if text.len() > output_budget.saturating_sub(output.len()) {
            return Err(ReactClientBuildError::new(
                "FE-REACT-BUILD-LIMIT",
                "generated JSON module exceeds the build budget",
            ));
        }
        output.push_str(text);
        Ok(())
    };
    let mut code = String::new();
    append(&mut code, "const __franken_json = (\n")?;
    let bytes = source.as_bytes();
    let mut cursor = 0;
    let mut copied = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'"' {
            cursor += 1;
            continue;
        }
        let start = cursor;
        cursor += 1;
        while bytes[cursor] != b'"' {
            cursor += if bytes[cursor] == b'\\' { 2 } else { 1 };
        }
        cursor += 1;
        let mut following = cursor;
        while bytes
            .get(following)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            following += 1;
        }
        if bytes.get(following) == Some(&b':') {
            append(&mut code, &source[copied..start])?;
            append(&mut code, "[")?;
            append(&mut code, &source[start..cursor])?;
            append(&mut code, "]")?;
            copied = cursor;
        }
    }
    append(&mut code, &source[copied..])?;
    append(&mut code, "\n);\nexport default __franken_json;\n")?;

    let map = generate_source_maps
        .then(|| {
            // The wrapper has no source location. Line-start mappings point into
            // the unchanged JSON lines; inserted key brackets map to the same key.
            let mut mappings = String::from(";AAAA");
            for offset in line_offsets(source).into_iter().skip(1) {
                // EOF after a terminator has no source character to map.
                // In particular, a trailing CR combines with the wrapper's
                // leading LF; mapping that empty line would mark `);` as JSON.
                if offset == source.len() {
                    break;
                }
                mappings.push_str(";AACA");
            }
            serde_json::to_string(&serde_json::json!({
                "version": 3,
                "sources": [name],
                "sourcesContent": [source],
                "names": [],
                "mappings": mappings,
            }))
            .map_err(serialization_error)
        })
        .transpose()?;
    if map.as_ref().map_or(0, String::len) > output_budget.saturating_sub(code.len()) {
        return Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-LIMIT",
            "generated JSON source map exceeds the build budget",
        ));
    }
    Ok((code, map))
}

/// `None` is a JSON data module, which bypasses JavaScript/TypeScript parsing
/// until its validated data has been emitted as a default-only ESM asset.
fn source_language(path: &Path) -> BuildResult<Option<ReactInputLanguage>> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("ts" | "tsx" | "mts") => Ok(Some(ReactInputLanguage::Tsx)),
        Some("js" | "jsx" | "mjs") => Ok(Some(ReactInputLanguage::Jsx)),
        Some("json") => Ok(None),
        _ => Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-FORMAT",
            format!(
                "{}: client builds accept local ESM JS/JSX/TS/TSX and explicitly typed JSON dependencies; CommonJS and other non-code assets are unsupported",
                path.display(),
            ),
        )),
    }
}

fn resolve_local_source(referrer: &Path, specifier: &str, root: &Path) -> BuildResult<PathBuf> {
    if !(specifier.starts_with("./") || specifier.starts_with("../")) {
        return Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-EXTERNAL",
            format!(
                "unresolved external '{specifier}'; declare --external {specifier}=<HTTP(S)-module-URL> or use a relative local ESM import",
            ),
        ));
    }
    if specifier.contains(['\\', '?', '#', '%']) || specifier.chars().any(char::is_control) {
        return Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-SPECIFIER",
            format!("unsupported local module URL '{specifier}'"),
        ));
    }
    let candidate = referrer.parent().ok_or_else(outside_root)?.join(specifier);
    if candidate.is_file() {
        return confined_file(&candidate, root);
    }
    let mut matches = BTreeSet::new();
    if let Some(extension) = candidate.extension() {
        // TypeScript ESM sources commonly name the extension that will be
        // emitted. An existing explicit path always wins, including an
        // unusable directory or dangling symlink. Never replace an I/O error.
        match candidate.symlink_metadata() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return confined_file(&candidate, root),
        }
        let alternatives: &[&str] = match (
            referrer.extension().and_then(|value| value.to_str()),
            extension.to_str(),
        ) {
            (Some("ts" | "tsx" | "mts"), Some("js" | "jsx")) => &["ts", "tsx"],
            (Some("ts" | "tsx" | "mts"), Some("mjs")) => &["mts"],
            _ => &[],
        };
        for extension in alternatives {
            let path = candidate.with_extension(extension);
            if path.is_file() {
                let canonical = confined_file(&path, root)?;
                // Declaration modules contain types without runtime values.
                if !canonical
                    .to_str()
                    .is_some_and(|name| name.ends_with(".d.ts") || name.ends_with(".d.mts"))
                {
                    matches.insert(canonical);
                }
            }
        }
    } else {
        for extension in EXTENSIONS {
            for path in [
                candidate.with_extension(extension),
                candidate.join(format!("index.{extension}")),
            ] {
                if path.is_file() {
                    matches.insert(confined_file(&path, root)?);
                }
            }
        }
    }
    match matches.len() {
        1 => Ok(matches.into_iter().next().expect("one match")),
        0 => Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-MISSING",
            format!("cannot resolve '{specifier}' from {}", referrer.display()),
        )),
        _ => Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-AMBIGUOUS",
            format!("'{specifier}' matches multiple modules; specify the file extension"),
        )),
    }
}

fn read_bounded_source(path: &Path, remaining: usize) -> BuildResult<String> {
    let file = File::open(path)
        .map_err(|error| ReactClientBuildError::new("FE-REACT-BUILD-READ", error.to_string()))?;
    if file
        .metadata()
        .map_err(|error| ReactClientBuildError::new("FE-REACT-BUILD-READ", error.to_string()))?
        .len()
        > remaining as u64
    {
        return Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-LIMIT",
            "source bytes exceed the build budget",
        ));
    }
    let mut bytes = Vec::new();
    file.take((remaining as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ReactClientBuildError::new("FE-REACT-BUILD-READ", error.to_string()))?;
    if bytes.len() > remaining {
        return Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-LIMIT",
            "source grew beyond the build budget while reading",
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        ReactClientBuildError::new("FE-REACT-BUILD-READ", "module source must be UTF-8")
    })
}

fn asset_path(name: &str) -> String {
    format!(
        "modules/{}.mjs",
        ContentHash::compute(name.as_bytes()).to_hex()
    )
}

fn import_prefix(clause: &ImportClause) -> BuildResult<String> {
    let named = |specifiers: &[crate::ast::ImportSpecifier]| -> BuildResult<String> {
        Ok(format!(
            "{{ {} }}",
            specifiers
                .iter()
                .map(|specifier| {
                    Ok(format!(
                        "{} as {}",
                        js_string(&specifier.import_name)?,
                        specifier.local_name
                    ))
                })
                .collect::<BuildResult<Vec<_>>>()?
                .join(", ")
        ))
    };
    Ok(match clause {
        ImportClause::SideEffect => "import ".to_string(),
        ImportClause::Default { local } => format!("import {local} from "),
        ImportClause::Namespace { local } => format!("import * as {local} from "),
        ImportClause::Named { specifiers } => format!("import {} from ", named(specifiers)?),
        ImportClause::DefaultAndNamed {
            default,
            specifiers,
        } => format!("import {default}, {} from ", named(specifiers)?),
        ImportClause::DefaultAndNamespace { default, namespace } => {
            format!("import {default}, * as {namespace} from ")
        }
    })
}

/// Validate the whole AST first; lexical candidates are never permission to
/// broaden the closed graph. Calls' parser spans currently name the enclosing
/// expression, so the shared JavaScript scanner supplies exact byte ranges.
fn bounded_dynamic_imports(
    source: &str,
    ast: &serde_json::Value,
    name: &str,
) -> BuildResult<Vec<SourceImport>> {
    let mut expected = BTreeMap::new();
    collect_bounded_imports(ast, name, &mut expected)?;
    if expected.is_empty() {
        return Ok(Vec::new());
    }
    let candidates = import_call_candidates(source)
        .map_err(|error| ReactClientBuildError::new("FE-REACT-BUILD-SPAN", error.to_string()))?;
    let mut observed = BTreeMap::new();
    let mut imports = Vec::new();
    for range in candidates {
        let text = source.get(range.clone()).ok_or_else(invalid_span)?;
        // A method named import can be a lexical candidate, but cannot have
        // a string literal as its parameter. Keep only standalone ImportCalls.
        let Ok(tree) = CanonicalEs2020Parser.parse(text, crate::ast::ParseGoal::Module) else {
            continue;
        };
        let [Statement::Expression(statement)] = tree.body.as_slice() else {
            continue;
        };
        let Expression::Call {
            callee, arguments, ..
        } = &statement.expression
        else {
            continue;
        };
        if !matches!(callee.as_ref(), Expression::Identifier(identifier) if identifier == "import")
            || !matches!(arguments.first(), Some(Expression::StringLiteral(_)))
        {
            continue;
        }
        let request = bounded_import_request(arguments, name)?;
        if !expected.contains_key(&request) {
            continue;
        }
        let (specifier, attributes) = request.clone();
        *observed.entry(request).or_insert(0usize) += 1;
        let span = dynamic_import_argument_span(text, !attributes.is_empty())?;
        imports.push(SourceImport {
            specifier,
            span: range.start + span.start..range.start + span.end,
            declaration: None,
            attributes,
            json_exports_valid: true,
        });
    }
    if observed != expected {
        return Err(invalid_span());
    }
    Ok(imports)
}

/// Only erase options that consist entirely of literal data properties.
/// Computed keys, spread, accessors, and value expressions can run guest code.
fn bounded_import_request(
    arguments: &[Expression],
    name: &str,
) -> BuildResult<(String, ImportAttributes)> {
    fn literal_property<'a>(expression: &'a Expression, key: &str) -> Option<&'a Expression> {
        let Expression::ObjectLiteral(properties) = expression else {
            return None;
        };
        let [property] = properties.as_slice() else {
            return None;
        };
        if property.computed
            || property.shorthand
            || property.kind != crate::ast::ObjectPropertyKind::Data
        {
            return None;
        }
        let property_key = match &property.key {
            Expression::Identifier(name) => name.as_str(),
            Expression::StringLiteral(name) => name.as_str()?,
            _ => return None,
        };
        (property_key == key).then_some(&property.value)
    }

    let invalid = || {
        ReactClientBuildError::new(
            "FE-REACT-BUILD-DYNAMIC",
            format!(
                "{name}: import() requires a string literal with optional literal JSON import attributes"
            ),
        )
    };
    let [Expression::StringLiteral(specifier), options @ ..] = arguments else {
        return Err(invalid());
    };
    let specifier = specifier.as_str().ok_or_else(|| {
        ReactClientBuildError::new(
            "FE-REACT-BUILD-SPECIFIER",
            format!("{name}: module specifier is not valid UTF-8"),
        )
    })?;
    let attributes = match options {
        [] => ImportAttributes::default(),
        [options] => {
            let Some(Expression::StringLiteral(kind)) = literal_property(options, "with")
                .and_then(|attributes| literal_property(attributes, "type"))
            else {
                return Err(invalid());
            };
            let kind = kind.as_str().ok_or_else(invalid)?;
            ImportAttributes::new(BTreeMap::from([("type".to_string(), kind.to_string())]))
                .map_err(|error| {
                    ReactClientBuildError::new(
                        "FE-REACT-BUILD-ATTRIBUTES",
                        format!("{name}: {error}"),
                    )
                })?
        }
        _ => return Err(invalid()),
    };
    Ok((specifier.to_string(), attributes))
}

fn collect_bounded_imports(
    value: &serde_json::Value,
    name: &str,
    imports: &mut BTreeMap<(String, ImportAttributes), usize>,
) -> BuildResult<()> {
    match value {
        serde_json::Value::Object(fields) => {
            if let Some(call) = fields.get("Call")
                && call
                    .pointer("/callee/Identifier")
                    .and_then(serde_json::Value::as_str)
                    == Some("import")
            {
                let arguments = call.get("arguments").ok_or_else(invalid_span)?;
                let arguments =
                    Vec::<Expression>::deserialize(arguments).map_err(serialization_error)?;
                *imports
                    .entry(bounded_import_request(&arguments, name)?)
                    .or_insert(0) += 1;
                return Ok(());
            }
            if let Some(identifier) = fields.get("Identifier").and_then(serde_json::Value::as_str)
                && matches!(identifier, "require" | "module" | "exports" | "import")
            {
                return Err(ReactClientBuildError::new(
                    "FE-REACT-BUILD-DYNAMIC",
                    format!(
                        "{name}: CommonJS bindings and unbounded imports are unsupported in a closed-world ESM client build ({identifier})",
                    ),
                ));
            }
            for (key, child) in fields {
                // Noncomputed property names are not identifier reads.
                if matches!(key.as_str(), "property" | "key")
                    && fields.get("computed") == Some(&serde_json::Value::Bool(false))
                {
                    continue;
                }
                collect_bounded_imports(child, name, imports)?;
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                collect_bounded_imports(child, name, imports)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// For a typed JSON edge, consume the validated options as the output asset
/// is JavaScript. For ordinary imports replace only the specifier literal.
fn dynamic_import_argument_span(
    source: &str,
    consume_options: bool,
) -> BuildResult<std::ops::Range<usize>> {
    fn skip_trivia(source: &str, cursor: &mut usize) -> BuildResult<()> {
        loop {
            let rest = source.get(*cursor..).ok_or_else(invalid_span)?;
            if rest.starts_with("/*") {
                *cursor += rest.find("*/").ok_or_else(invalid_span)? + 2;
            } else if rest.starts_with("//") {
                *cursor += rest
                    .find(['\r', '\n', '\u{2028}', '\u{2029}'])
                    .unwrap_or(rest.len());
            } else if let Some(ch) = rest.chars().next()
                && (ch.is_whitespace() || ch == '\u{feff}')
            {
                *cursor += ch.len_utf8();
            } else {
                return Ok(());
            }
        }
    }

    let mut cursor = "import".len();
    skip_trivia(source, &mut cursor)?;
    if source.as_bytes().get(cursor) != Some(&b'(') {
        return Err(invalid_span());
    }
    if consume_options {
        let call_body = source.strip_suffix(')').ok_or_else(invalid_span)?;
        return Ok(cursor + 1..call_body.len());
    }
    loop {
        cursor += 1;
        skip_trivia(source, &mut cursor)?;
        if source.as_bytes().get(cursor) != Some(&b'(') {
            break;
        }
    }
    let start = cursor;
    let quote = *source.as_bytes().get(cursor).ok_or_else(invalid_span)?;
    if !matches!(quote, b'\'' | b'"') {
        return Err(invalid_span());
    }
    cursor += 1;
    while let Some(&byte) = source.as_bytes().get(cursor) {
        cursor += 1;
        if byte == b'\\' {
            cursor += 1;
        } else if byte == quote {
            return Ok(start..cursor);
        }
    }
    Err(invalid_span())
}

/// Even a lexically plausible range cannot change another expression. Compare
/// the full AST after dynamic edits against the permitted specifier substitutions
/// and consumption of validated JSON attributes, ignoring moved source positions.
fn verify_dynamic_import_edits(
    source: &str,
    expected: &mut serde_json::Value,
    edits: &[SourceEdit],
    targets: &BTreeMap<String, String>,
) -> BuildResult<()> {
    let rewritten = apply_edits(source, edits)?;
    let actual = CanonicalEs2020Parser
        .parse(rewritten.as_str(), crate::ast::ParseGoal::Module)
        .map_err(|_| invalid_span())?;
    let mut actual = serde_json::to_value(actual).map_err(serialization_error)?;
    normalize_dynamic_import_ast(expected, targets);
    normalize_dynamic_import_ast(&mut actual, &BTreeMap::new());
    if *expected != actual {
        return Err(invalid_span());
    }
    Ok(())
}

fn normalize_dynamic_import_ast(value: &mut serde_json::Value, targets: &BTreeMap<String, String>) {
    match value {
        serde_json::Value::Object(fields) => {
            fields.remove("span");
            if let Some(call) = fields.get_mut("Call")
                && call
                    .pointer("/callee/Identifier")
                    .and_then(serde_json::Value::as_str)
                    == Some("import")
                && let Some(target) = call
                    .pointer("/arguments/0/StringLiteral")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|specifier| targets.get(specifier))
            {
                call["arguments"][0]["StringLiteral"] = serde_json::Value::String(target.clone());
                // The resolved JSON asset is a default-only JavaScript module.
                if let Some(arguments) = call["arguments"].as_array_mut() {
                    arguments.truncate(1);
                }
            }
            for child in fields.values_mut() {
                normalize_dynamic_import_ast(child, targets);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                normalize_dynamic_import_ast(child, targets);
            }
        }
        _ => {}
    }
}

fn apply_edits(source: &str, edits: &[SourceEdit]) -> BuildResult<String> {
    let mut output = String::new();
    let mut copied = 0;
    for edit in edits {
        if edit.start < copied || edit.end < edit.start {
            return Err(invalid_span());
        }
        output.push_str(source.get(copied..edit.start).ok_or_else(invalid_span)?);
        output.push_str(&edit.replacement);
        copied = edit.end;
    }
    output.push_str(source.get(copied..).ok_or_else(invalid_span)?);
    Ok(output)
}

fn invalid_span() -> ReactClientBuildError {
    ReactClientBuildError::new(
        "FE-REACT-BUILD-SPAN",
        "native parser and lexical scanner disagree on a module import span",
    )
}

fn serialization_error(error: serde_json::Error) -> ReactClientBuildError {
    ReactClientBuildError::new("FE-REACT-BUILD-ENCODING", error.to_string())
}

fn js_string(value: &str) -> BuildResult<String> {
    serde_json::to_string(value).map_err(serialization_error)
}

/// Rewrite only generated positions in a v3 source map. Source indices,
/// original positions, and optional names remain unchanged. Mappings inside
/// reconstructed import declarations are terminated by unmapped segments
/// rather than inheriting the preceding statement's source position.
fn remap_source_map(
    map: &str,
    original: &str,
    generated: &str,
    edits: &[SourceEdit],
    asset: &str,
) -> BuildResult<String> {
    let mut map: serde_json::Value = serde_json::from_str(map).map_err(serialization_error)?;
    let mappings = map
        .get("mappings")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ReactClientBuildError::new(
                "FE-REACT-BUILD-MAP",
                "compiler source map is missing mappings",
            )
        })?;
    let mut source_index = 0i64;
    let mut source_line = 0i64;
    let mut source_column = 0i64;
    let mut name_index = 0i64;
    let mut segments = BTreeMap::<usize, Vec<Vec<i64>>>::new();
    let original_lines = line_offsets(original);
    let generated_lines = line_offsets(generated);
    let mut edit_prefixes = vec![(0usize, 0usize)];
    for edit in edits {
        let (removed, added) = *edit_prefixes.last().expect("initial prefix");
        edit_prefixes.push((
            removed + edit.end - edit.start,
            added + edit.replacement.len(),
        ));
    }
    for (line, encoded_line) in mappings.split(';').enumerate() {
        let mut column = 0i64;
        for encoded in encoded_line
            .split(',')
            .filter(|segment| !segment.is_empty())
        {
            let values = decode_vlq(encoded)?;
            if !matches!(values.len(), 1 | 4 | 5) {
                return Err(invalid_map());
            }
            column += values[0];
            if values.len() >= 4 {
                source_index += values[1];
                source_line += values[2];
                source_column += values[3];
            }
            if values.len() == 5 {
                name_index += values[4];
            }
            let offset = line_column_offset(original, &original_lines, line, column)?;
            let Some(offset) = remap_offset(offset, edits, &edit_prefixes) else {
                continue;
            };
            let (new_line, new_column) = offset_line_column(generated, &generated_lines, offset)?;
            let mut segment = vec![new_column as i64];
            if values.len() >= 4 {
                segment.extend([source_index, source_line, source_column]);
            }
            if values.len() == 5 {
                segment.push(name_index);
            }
            segments.entry(new_line).or_default().push(segment);
        }
    }
    for (index, edit) in edits.iter().enumerate() {
        let (removed, added) = edit_prefixes[index];
        let offset = edit.start - removed + added;
        let (line, column) = offset_line_column(generated, &generated_lines, offset)?;
        segments.entry(line).or_default().push(vec![column as i64]);
    }
    let mut encoded_lines = Vec::new();
    source_index = 0;
    source_line = 0;
    source_column = 0;
    name_index = 0;
    for line in 0..generated_lines.len() {
        let mut column = 0i64;
        let mut encoded = Vec::new();
        let mut line_segments = segments.remove(&line).unwrap_or_default();
        line_segments.sort_by_key(|segment| segment[0]);
        for segment in line_segments {
            let mut values = vec![segment[0] - column];
            column = segment[0];
            if segment.len() >= 4 {
                values.extend([
                    segment[1] - source_index,
                    segment[2] - source_line,
                    segment[3] - source_column,
                ]);
                source_index = segment[1];
                source_line = segment[2];
                source_column = segment[3];
            }
            if segment.len() == 5 {
                values.push(segment[4] - name_index);
                name_index = segment[4];
            }
            encoded.push(encode_vlq(&values));
        }
        encoded_lines.push(encoded.join(","));
    }
    map["mappings"] = serde_json::Value::String(encoded_lines.join(";"));
    map["file"] =
        serde_json::Value::String(asset.strip_prefix("modules/").unwrap_or(asset).to_string());
    serde_json::to_string(&map).map_err(serialization_error)
}

fn remap_offset(offset: usize, edits: &[SourceEdit], prefixes: &[(usize, usize)]) -> Option<usize> {
    let index = edits.partition_point(|edit| edit.end <= offset);
    if edits.get(index).is_some_and(|edit| edit.start <= offset) {
        return None;
    }
    let (removed, added) = prefixes[index];
    offset.checked_sub(removed)?.checked_add(added)
}

fn line_offsets(source: &str) -> Vec<usize> {
    let mut starts = vec![0];
    let mut characters = source.char_indices().peekable();
    while let Some((offset, character)) = characters.next() {
        if character == '\r' && characters.peek().is_some_and(|(_, next)| *next == '\n') {
            let (offset, _) = characters.next().expect("CRLF lookahead");
            starts.push(offset + 1);
        } else if matches!(character, '\r' | '\n' | '\u{2028}' | '\u{2029}') {
            starts.push(offset + character.len_utf8());
        }
    }
    starts
}

fn line_column_offset(
    source: &str,
    lines: &[usize],
    line: usize,
    column: i64,
) -> BuildResult<usize> {
    let column = usize::try_from(column).map_err(|_| invalid_map())?;
    let offset = *lines.get(line).ok_or_else(invalid_map)?;
    let end = lines.get(line + 1).copied().unwrap_or(source.len());
    let text = source
        .get(offset..end)
        .ok_or_else(invalid_map)?
        .trim_end_matches(['\r', '\n', '\u{2028}', '\u{2029}']);
    let mut units = 0;
    for (byte, ch) in text.char_indices() {
        if units == column {
            return Ok(offset + byte);
        }
        units += ch.len_utf16();
    }
    if units == column {
        Ok(offset + text.len())
    } else {
        Err(invalid_map())
    }
}

fn offset_line_column(source: &str, lines: &[usize], offset: usize) -> BuildResult<(usize, usize)> {
    let line = lines
        .partition_point(|start| *start <= offset)
        .checked_sub(1)
        .ok_or_else(invalid_map)?;
    let prefix = source.get(lines[line]..offset).ok_or_else(invalid_map)?;
    Ok((line, prefix.encode_utf16().count()))
}

fn invalid_map() -> ReactClientBuildError {
    ReactClientBuildError::new(
        "FE-REACT-BUILD-MAP",
        "compiler emitted an invalid source-map segment",
    )
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn decode_vlq(encoded: &str) -> BuildResult<Vec<i64>> {
    let mut values = Vec::new();
    let mut value = 0u64;
    let mut shift = 0u32;
    for byte in encoded.bytes() {
        let digit = BASE64
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or_else(invalid_map)? as u64;
        if shift > 55 {
            return Err(invalid_map());
        }
        value |= (digit & 31) << shift;
        if digit & 32 == 0 {
            let magnitude = i64::try_from(value >> 1).map_err(|_| invalid_map())?;
            values.push(if value & 1 == 0 {
                magnitude
            } else {
                -magnitude
            });
            value = 0;
            shift = 0;
        } else {
            shift += 5;
        }
    }
    if shift != 0 {
        return Err(invalid_map());
    }
    Ok(values)
}

fn encode_vlq(values: &[i64]) -> String {
    let mut output = String::new();
    for value in values {
        let mut value = (value.unsigned_abs() << 1) | u64::from(*value < 0);
        loop {
            let digit = (value & 31) as usize;
            value >>= 5;
            output.push(BASE64[digit | if value == 0 { 0 } else { 32 }] as char);
            if value == 0 {
                break;
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture(files: &[(&str, &str)]) -> (tempfile::TempDir, ReactClientBuildConfig) {
        let directory = tempfile::tempdir().expect("temporary project");
        for (name, source) in files {
            let path = directory.path().join(name);
            fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directory");
            fs::write(path, source).expect("fixture source");
        }
        let config = ReactClientBuildConfig {
            project_root: directory.path().to_path_buf(),
            entry: directory.path().join(files[0].0),
            ..ReactClientBuildConfig::default()
        };
        (directory, config)
    }

    #[test]
    fn client_build_captures_installed_tsx_exports_private_imports_and_lazy_edges() {
        let files = [
            (
                "app.tsx",
                "import { Card } from '@ui/cards'; export { answer } from '@ui/cards/feature/answer'; export const load = () => import('@ui/cards/lazy'); export const app = <Card />;",
            ),
            (
                "node_modules/@ui/cards/package.json",
                r##"{"name":"@ui/cards","type":"module","imports":{"#label":"./src/label.ts"},"exports":{".":{"node":"./node.cjs","browser":"./src/card.tsx","import":"./wrong.mjs"},"./feature/*":"./src/*.ts","./lazy":"./src/lazy.mjs"}}"##,
            ),
            (
                "node_modules/@ui/cards/src/card.tsx",
                "import { label } from '#label'; export function Card() { return <span>{label}</span>; }",
            ),
            (
                "node_modules/@ui/cards/src/label.ts",
                "export const label: string = 'ready';",
            ),
            (
                "node_modules/@ui/cards/src/answer.ts",
                "export const answer: number = 42;",
            ),
            (
                "node_modules/@ui/cards/src/lazy.mjs",
                "export { answer } from '@ui/cards/feature/answer';",
            ),
            ("node_modules/@ui/cards/node.cjs", "module.exports = {};"),
            (
                "node_modules/@ui/cards/wrong.mjs",
                "throw 'wrong condition';",
            ),
        ];
        let (_directory, mut config) = fixture(&files);
        config.compile.generate_source_maps = true;
        config.externals.insert(
            "react/jsx-runtime".into(),
            "https://example.invalid/react-jsx.mjs".into(),
        );
        let build = build_react_client(&config).expect("installed ESM graph");
        assert_eq!(
            build
                .modules
                .iter()
                .map(|module| module.source_path.as_str())
                .collect::<Vec<_>>(),
            [
                "app.tsx",
                "node_modules/@ui/cards/src/answer.ts",
                "node_modules/@ui/cards/src/card.tsx",
                "node_modules/@ui/cards/src/label.ts",
                "node_modules/@ui/cards/src/lazy.mjs",
            ],
        );
        assert_eq!(build.package_inputs.len(), 1);
        assert_eq!(
            build.package_inputs[0].source_hash,
            ContentHash::compute(files[1].1.as_bytes()),
        );
        assert!(
            build
                .modules
                .iter()
                .all(|module| module.source_map.is_some())
        );
        let entry = &build.modules[0];
        assert!(entry.dependencies.iter().any(|dependency| {
            dependency.specifier == "@ui/cards/lazy"
                && dependency.target == asset_path("node_modules/@ui/cards/src/lazy.mjs")
        }));
        assert!(entry.code.contains("import("));
        assert!(!entry.code.contains("<Card"));
        build.verify_integrity().unwrap();
    }

    #[test]
    fn client_build_uses_module_entries_legacy_main_and_exact_package_subpaths() {
        let (_directory, config) = fixture(&[
            (
                "app.js",
                "import { dual } from 'dual'; import { legacy } from 'legacy'; import { implicit } from 'implicit'; import { sub } from '@scope/sub/part.js'; export { dual, legacy, implicit, sub };",
            ),
            (
                "node_modules/dual/package.json",
                r#"{"type":"commonjs","main":"main.cjs","module":"esm/index.js"}"#,
            ),
            (
                "node_modules/dual/esm/index.js",
                "export { dual } from './value.js';",
            ),
            ("node_modules/dual/esm/value.js", "export const dual = 1;"),
            (
                "node_modules/dual/main.cjs",
                "module.exports = { dual: 0 };",
            ),
            (
                "node_modules/legacy/package.json",
                r#"{"type":"module","main":"dist/main"}"#,
            ),
            (
                "node_modules/legacy/dist/main.js",
                "export const legacy = 2;",
            ),
            (
                "node_modules/implicit/index.js",
                "export const implicit = 3;",
            ),
            (
                "node_modules/@scope/sub/package.json",
                r#"{"type":"module"}"#,
            ),
            ("node_modules/@scope/sub/part.js", "export const sub = 4;"),
        ]);
        let build = build_react_client(&config).expect("legacy ESM distributions");
        assert_eq!(build.modules.len(), 6);
        assert_eq!(build.package_inputs.len(), 3);
        assert!(
            build
                .modules
                .iter()
                .any(|module| { module.source_path == "node_modules/dual/esm/value.js" })
        );
        assert!(
            !build
                .modules
                .iter()
                .any(|module| module.source_path.ends_with(".cjs"))
        );
    }

    #[test]
    fn client_package_exports_use_the_canonical_targets_nearest_format_scope() {
        for (outer_type, inner_type, accepted) in
            [("commonjs", "module", true), ("module", "commonjs", false)]
        {
            let outer = format!("{{\"type\":\"{outer_type}\",\"exports\":\"./nested/index.js\"}}");
            let inner = format!("{{\"type\":\"{inner_type}\"}}");
            let (_directory, config) = fixture(&[
                ("app.js", "export { value } from 'pkg';"),
                ("node_modules/pkg/package.json", &outer),
                ("node_modules/pkg/nested/package.json", &inner),
                (
                    "node_modules/pkg/nested/index.js",
                    "export const value = 42;",
                ),
            ]);
            let result = build_react_client(&config);
            if accepted {
                let build = result.expect("nearest scope declares ESM");
                assert_eq!(build.package_inputs.len(), 2);
                assert!(
                    build.package_inputs.iter().any(|input| {
                        input.source_path == "node_modules/pkg/nested/package.json"
                    })
                );
                build.verify_integrity().unwrap();
            } else {
                assert!(result.unwrap_err().message.contains("CommonJS"));
            }
        }
    }

    #[test]
    fn client_build_resolves_nearest_versions_self_references_and_package_aliases() {
        let (_directory, config) = fixture(&[
            (
                "app.js",
                "import { value } from 'wrapper'; import { other } from '#dep'; export { local } from 'app/local'; export { value, other };",
            ),
            (
                "package.json",
                r##"{"name":"app","type":"module","exports":{"./local":"./local.js"},"imports":{"#dep":"dep/other.mjs"}}"##,
            ),
            ("local.js", "export const local = 3;"),
            (
                "node_modules/wrapper/package.json",
                r#"{"name":"wrapper","exports":"./index.mjs"}"#,
            ),
            (
                "node_modules/wrapper/index.mjs",
                "import { nested } from 'dep'; export const value = nested;",
            ),
            (
                "node_modules/wrapper/node_modules/dep/package.json",
                r#"{"exports":"./nested.mjs"}"#,
            ),
            (
                "node_modules/wrapper/node_modules/dep/nested.mjs",
                "export const nested = 1;",
            ),
            (
                "node_modules/dep/package.json",
                r#"{"exports":{".":"./root.mjs","./other.mjs":"./other.mjs"}}"#,
            ),
            ("node_modules/dep/other.mjs", "export const other = 2;"),
            (
                "node_modules/dep/root.mjs",
                "throw 'wrong package version';",
            ),
        ]);
        let build = build_react_client(&config).expect("scoped package graph");
        assert_eq!(build.modules.len(), 5);
        assert_eq!(build.package_inputs.len(), 4);
        assert!(build.modules.iter().any(|module| {
            module.source_path == "node_modules/wrapper/node_modules/dep/nested.mjs"
        }));
        assert!(
            !build
                .modules
                .iter()
                .any(|module| { module.source_path == "node_modules/dep/root.mjs" })
        );
    }

    #[test]
    fn client_package_selection_preserves_condition_order_and_exports_precedence() {
        for (manifest, selected) in [
            (
                r#"{"module":"./module.mjs","exports":{"default":"./default.mjs","browser":"./browser.mjs"}}"#,
                "default.mjs",
            ),
            (
                r#"{"exports":{"browser":"./old.mjs","import":"./import.mjs","browser":"./browser.mjs"}}"#,
                "browser.mjs",
            ),
            (
                r#"{"exports":{"development":"./old.mjs","import":"./import.mjs","browser":"./browser.mjs"}}"#,
                "import.mjs",
            ),
        ] {
            let (_directory, config) = fixture(&[
                ("app.js", "export { value } from 'pkg';"),
                ("node_modules/pkg/package.json", manifest),
                ("node_modules/pkg/default.mjs", "export const value = 1;"),
                ("node_modules/pkg/browser.mjs", "export const value = 2;"),
                ("node_modules/pkg/import.mjs", "export const value = 3;"),
                ("node_modules/pkg/module.mjs", "export const value = 4;"),
                ("node_modules/pkg/old.mjs", "export const value = 5;"),
            ]);
            let build = build_react_client(&config).unwrap();
            assert_eq!(build.modules.len(), 2);
            assert_eq!(
                build.modules[1].source_path,
                format!("node_modules/pkg/{selected}"),
            );
        }
    }

    #[test]
    fn client_package_failures_never_fall_through_to_another_target_or_version() {
        for (request, manifest, message) in [
            (
                "pkg/private",
                r#"{"exports":{"./public":"./good.mjs"}}"#,
                "does not export",
            ),
            (
                "pkg/private",
                r#"{"exports":{"./private":null,"./*":"./good.mjs"}}"#,
                "does not export",
            ),
            (
                "pkg",
                r#"{"exports":{"browser":"./missing.mjs","default":"./good.mjs"}}"#,
                "cannot resolve",
            ),
            (
                "pkg",
                r#"{"exports":["./missing.mjs","./good.mjs"]}"#,
                "cannot resolve",
            ),
            (
                "pkg",
                r#"{"module":"./missing.mjs","main":"./good.mjs"}"#,
                "cannot resolve",
            ),
            (
                "pkg",
                r#"{"exports":{"0":"./good.mjs","browser":"./good.mjs"}}"#,
                "numeric property",
            ),
            (
                "pkg",
                r#"{"type":"commonjs","main":"./plain.js"}"#,
                "CommonJS",
            ),
            ("pkg", r#"{"module":"./main.cjs"}"#, "CommonJS"),
            ("pkg", r#"{"exports":"./types.d.ts"}"#, "declaration file"),
            ("pkg", r#"{"exports":"./%2e%2e/outside.mjs"}"#, "invalid"),
            ("pkg/x", r#"{"exports":{"./*":"./%2f*.mjs"}}"#, "invalid"),
        ] {
            let entry = format!("import '{request}';");
            let (_directory, config) = fixture(&[
                ("app.js", &entry),
                ("node_modules/pkg/package.json", manifest),
                ("node_modules/pkg/good.mjs", "export const good = true;"),
                (
                    "node_modules/pkg/private.js",
                    "export const privateValue = true;",
                ),
                ("node_modules/pkg/plain.js", "this.changed = true;"),
                ("node_modules/pkg/main.cjs", "module.exports = {};"),
                (
                    "node_modules/pkg/types.d.ts",
                    "export declare const value: number;",
                ),
            ]);
            let error = build_react_client(&config).expect_err("invalid selected package");
            assert!(
                error.message.contains(message),
                "{request} {manifest}: {error}"
            );
        }
        let (_directory, config) = fixture(&[
            ("app.js", "import 'wrapper';"),
            (
                "node_modules/wrapper/package.json",
                r#"{"exports":"./index.mjs"}"#,
            ),
            ("node_modules/wrapper/index.mjs", "import 'pkg';"),
            (
                "node_modules/wrapper/node_modules/pkg/package.json",
                r#"{"exports":"./missing.mjs"}"#,
            ),
            (
                "node_modules/pkg/package.json",
                r#"{"exports":"./good.mjs"}"#,
            ),
            ("node_modules/pkg/good.mjs", "export const wrong = true;"),
        ]);
        assert!(
            build_react_client(&config)
                .unwrap_err()
                .message
                .contains("cannot resolve")
        );
    }

    #[test]
    fn client_package_manifests_bind_identity_and_share_all_build_budgets() {
        let files = [
            (
                "app.js",
                "import { value } from 'pkg'; export { value }; export const load = () => import('pkg');",
            ),
            (
                "node_modules/pkg/package.json",
                r#"{"type":"module","exports":"./index.js"}"#,
            ),
            ("node_modules/pkg/index.js", "export const value = 42;"),
        ];
        let (_first, config) = fixture(&files);
        let (_second, mut relocated) = fixture(&files);
        let build = build_react_client(&config).unwrap();
        assert_eq!(build, build_react_client(&relocated).unwrap());
        assert_eq!(build.package_inputs.len(), 1);
        let bytes = files.iter().map(|(_, source)| source.len()).sum::<usize>();
        relocated.max_source_bytes = bytes;
        build_react_client(&relocated).expect("each manifest is charged once");
        relocated.max_source_bytes = bytes - 1;
        assert_eq!(
            build_react_client(&relocated).unwrap_err().code,
            "FE-REACT-BUILD-LIMIT"
        );
        relocated.max_source_bytes = config.max_source_bytes;
        relocated.max_modules = 1;
        assert_eq!(
            build_react_client(&relocated).unwrap_err().code,
            "FE-REACT-BUILD-LIMIT"
        );
        relocated.max_modules = config.max_modules;
        relocated.max_output_bytes = build
            .modules
            .iter()
            .map(|module| module.code.len() + module.source_map.as_ref().map_or(0, String::len))
            .sum();
        assert_eq!(
            build_react_client(&relocated).unwrap_err().code,
            "FE-REACT-BUILD-LIMIT"
        );
        relocated.max_output_bytes = config.max_output_bytes;
        fs::write(
            relocated.project_root.join("node_modules/pkg/package.json"),
            r#"{"type":"module","exports":"./index.js","version":"2.0.0"}"#,
        )
        .unwrap();
        let changed = build_react_client(&relocated).unwrap();
        assert_eq!(build.modules, changed.modules);
        assert_ne!(build.graph_hash, changed.graph_hash);
        let mut tampered = build.clone();
        tampered.package_inputs[0].source_hash = ContentHash::compute(b"changed manifest");
        assert!(tampered.verify_integrity().is_err());
        tampered = build.clone();
        tampered.package_inputs.clear();
        assert!(tampered.verify_integrity().is_err());
        fs::write(
            relocated.project_root.join("node_modules/pkg/package.json"),
            format!(
                "{{\"exports\":\"./index.js\",\"padding\":\"{}\"}}",
                "x".repeat(MAX_PACKAGE_MANIFEST_BYTES as usize),
            ),
        )
        .unwrap();
        assert_eq!(
            build_react_client(&relocated).unwrap_err().code,
            "FE-REACT-BUILD-LIMIT"
        );
    }

    #[test]
    fn client_external_override_and_old_graph_identity_remain_unchanged() {
        let (_directory, mut config) = fixture(&[
            ("app.js", "export { value } from 'pkg';"),
            (
                "node_modules/pkg/package.json",
                "invalid JSON must not be read",
            ),
        ]);
        config
            .externals
            .insert("pkg".into(), "https://example.invalid/pkg.mjs".into());
        let build = build_react_client(&config).expect("explicit provider wins");
        assert_eq!(build.modules.len(), 1);
        assert!(build.package_inputs.is_empty());
        let old_identity = serde_json::to_vec(&(
            REACT_CLIENT_BUILD_SCHEMA_VERSION,
            &build.entry_asset,
            build.config_hash,
            &build.import_map,
            &build.modules,
        ))
        .unwrap();
        assert_eq!(build.graph_hash, ContentHash::compute(&old_identity));
        let encoded = serde_json::to_value(&build).unwrap();
        assert!(encoded.get("package_inputs").is_none());
        let decoded: ReactClientBuild = serde_json::from_value(encoded).unwrap();
        decoded.verify_integrity().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn client_package_manifests_and_targets_cannot_escape_through_symlinks() {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        fs::write(
            outside.path().join("package.json"),
            r#"{"exports":"./index.mjs"}"#,
        )
        .unwrap();
        fs::write(outside.path().join("index.mjs"), "export const value = 99;").unwrap();
        let (_directory, config) = fixture(&[
            ("app.js", "import 'pkg';"),
            ("node_modules/pkg/index.mjs", "export const value = 1;"),
        ]);
        symlink(
            outside.path().join("package.json"),
            config.project_root.join("node_modules/pkg/package.json"),
        )
        .unwrap();
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-ROOT"
        );
        let (_directory, config) = fixture(&[
            ("app.js", "import 'pkg';"),
            (
                "node_modules/pkg/package.json",
                r#"{"exports":"./linked.mjs"}"#,
            ),
        ]);
        symlink(
            outside.path().join("index.mjs"),
            config.project_root.join("node_modules/pkg/linked.mjs"),
        )
        .unwrap();
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-ROOT"
        );
        let (_directory, config) = fixture(&[
            ("app.js", "export { value } from 'pkg';"),
            (
                "metadata/pkg-manifest.json",
                r#"{"type":"commonjs","exports":"./linked.js"}"#,
            ),
            ("node_modules/pkg/runtime.mjs", "export const value = 42;"),
        ]);
        symlink(
            config.project_root.join("metadata/pkg-manifest.json"),
            config.project_root.join("node_modules/pkg/package.json"),
        )
        .unwrap();
        symlink(
            config.project_root.join("node_modules/pkg/runtime.mjs"),
            config.project_root.join("node_modules/pkg/linked.js"),
        )
        .unwrap();
        let build = build_react_client(&config).expect("in-root canonical source and metadata");
        assert_eq!(
            build.package_inputs[0].source_path,
            "metadata/pkg-manifest.json"
        );
        assert_eq!(build.modules[1].source_path, "node_modules/pkg/runtime.mjs");
        build.verify_integrity().unwrap();
    }

    #[test]
    fn client_build_closes_jsx_tsx_graph_and_keeps_explicit_runtime_provider() {
        let (_directory, mut config) = fixture(&[
            (
                "app.jsx",
                "import { Card } from './components/card.tsx'; export const app = <Card value={3}/>;",
            ),
            (
                "components/card.tsx",
                "export function Card(props: { value: number }) { return <span>{props.value}</span>; }",
            ),
        ]);
        config.compile.generate_source_maps = true;
        config.externals.insert(
            "react/jsx-runtime".into(),
            "https://example.invalid/react-jsx.mjs".into(),
        );
        let build = build_react_client(&config).expect("closed client graph");
        assert_eq!(build.modules.len(), 2);
        assert_eq!(build.entry_asset, asset_path("app.jsx"));
        let entry = &build.modules[0];
        assert!(entry.code.contains("react/jsx-runtime"));
        assert!(!entry.code.contains("https://example.invalid"));
        assert!(
            entry
                .code
                .contains(&asset_path("components/card.tsx")["modules/".len()..])
        );
        assert!(!entry.code.contains("<Card"));
        for module in &build.modules {
            assert_eq!(
                module.output_hash,
                ContentHash::compute(module.code.as_bytes())
            );
            assert!(module.source_map.is_some());
            assert!(module.code.contains("//# sourceMappingURL="));
            CanonicalEs2020Parser
                .parse(module.code.as_str(), crate::ast::ParseGoal::Module)
                .expect("emitted module parses natively");
        }
    }

    #[test]
    fn client_build_closes_lazy_tsx_graph_without_eager_imports() {
        let files = [
            (
                "app.tsx",
                "import { lazy } from 'react'; export const View = lazy(() => import('./views/card')); export const load = () => import('./views/card');",
            ),
            (
                "views/card.tsx",
                "import { value } from '../value.js'; export default function Card() { return <span>{value}</span>; } export const parent = () => import('../app.tsx');",
            ),
            ("value.js", "export const value = 7;"),
        ];
        let (_directory, mut config) = fixture(&files);
        config.externals = BTreeMap::from([
            ("react".into(), "https://example.invalid/react.mjs".into()),
            (
                "react/jsx-runtime".into(),
                "https://example.invalid/jsx.mjs".into(),
            ),
        ]);
        config.compile.generate_source_maps = true;
        let build = build_react_client(&config).expect("lazy TSX graph");
        assert_eq!(
            build.modules.len(),
            3,
            "duplicate edges do not duplicate modules"
        );
        let entry = &build.modules[0];
        let lazy_name = asset_path("views/card.tsx");
        let lazy_call = format!(
            "import(\"./{}\")",
            lazy_name.strip_prefix("modules/").unwrap()
        );
        assert_eq!(entry.code.matches(&lazy_call).count(), 2);
        assert!(
            !entry.code.contains("from \"./"),
            "lazy edge stays an ImportCall"
        );
        assert_eq!(
            entry
                .dependencies
                .iter()
                .filter(|dep| dep.target == lazy_name)
                .count(),
            2
        );
        let card = build
            .modules
            .iter()
            .find(|module| module.source_path == "views/card.tsx")
            .unwrap();
        assert!(
            card.dependencies
                .iter()
                .any(|dep| dep.target == build.entry_asset)
        );
        assert!(card.code.contains("react/jsx-runtime"));
        build.verify_integrity().unwrap();
        assert_eq!(build, build_react_client(&config).unwrap());

        let (_other, mut relocated) = fixture(&files);
        relocated.externals = config.externals.clone();
        relocated.compile = config.compile.clone();
        assert_eq!(build, build_react_client(&relocated).unwrap());
        fs::write(
            config.project_root.join("value.js"),
            "export const value = 8;",
        )
        .unwrap();
        assert_ne!(
            build.graph_hash,
            build_react_client(&config).unwrap().graph_hash
        );
    }

    #[test]
    fn client_build_dynamic_imports_preserve_literals_comments_and_templates() {
        let source = r#"const text = "import('./fake.js')"; const regex = /import\('\.\/fake.js'\)/;
const object = { import(path) { return path; } };
object.import('./fake.js');
const escaped = a\u{62}import('./fake.js');
export const meta = import.meta;
export const load = () => import /* keep */ (
    (('./l\u0061zy.js'))
);
export const describe = async () => `loaded:${(await import('./lazy.js')).value}`;
"#;
        let (_directory, mut config) =
            fixture(&[("app.js", source), ("lazy.js", "export const value = 1;")]);
        config.compile.generate_source_maps = true;
        let build = build_react_client(&config).expect("exact lexical import rewriting");
        let entry = &build.modules[0];
        assert_eq!(entry.dependencies.len(), 2);
        assert!(entry.code.contains("import /* keep */ (\n    ((\"./"));
        assert!(entry.code.contains("object.import('./fake.js')"));
        assert!(entry.code.contains(r"a\u{62}import('./fake.js')"));
        assert!(entry.code.contains("import.meta"));
        assert!(entry.code.contains("`loaded:${(await import("));
        let map: serde_json::Value =
            serde_json::from_str(entry.source_map.as_ref().unwrap()).unwrap();
        assert_eq!(map["sourcesContent"][0], source);
    }

    #[test]
    fn client_build_dynamic_imports_enforce_missing_ambiguous_and_root_bounds() {
        let (directory, config) = fixture(&[
            (
                "app.js",
                "export const load = () => import('./missing.js');",
            ),
            ("both.js", "export const value = 1;"),
            ("both.ts", "export const value: number = 2;"),
        ]);
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-MISSING"
        );
        fs::write(&config.entry, "export const load = () => import('./both');").unwrap();
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-AMBIGUOUS"
        );
        fs::write(
            &config.entry,
            "if (false) { import('./missing.js'); } export {};",
        )
        .unwrap();
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-MISSING"
        );

        let nested = directory.path().join("project");
        fs::create_dir(&nested).unwrap();
        let mut confined = config.clone();
        confined.project_root = nested.clone();
        confined.entry = nested.join("app.js");
        fs::write(
            &confined.entry,
            "export const load = () => import('../both.js');",
        )
        .unwrap();
        assert_eq!(
            build_react_client(&confined).unwrap_err().code,
            "FE-REACT-BUILD-ROOT"
        );
    }

    #[test]
    fn emitted_typescript_extensions_keep_exact_files_and_root_bounds() {
        let (directory, _) = fixture(&[
            ("app.ts", ""),
            ("app.js", ""),
            ("exact.js", ""),
            ("exact.ts", ""),
            ("card.ts", ""),
            ("card.tsx", ""),
            ("schema.d.ts", ""),
            ("nested/entry.mts", ""),
            ("logic.mts", ""),
        ]);
        let root = directory.path().canonicalize().unwrap();
        let resolve = |entry: &str, specifier: &str| {
            resolve_local_source(&root.join(entry), specifier, &root)
        };
        assert_eq!(
            resolve("app.ts", "./exact.js").unwrap(),
            root.join("exact.js")
        );
        assert_eq!(
            resolve("app.ts", "./card.js").unwrap_err().code,
            "FE-REACT-BUILD-AMBIGUOUS"
        );
        assert_eq!(
            resolve("app.js", "./logic.mjs").unwrap_err().code,
            "FE-REACT-BUILD-MISSING"
        );
        assert_eq!(
            resolve("app.ts", "./schema.d.js").unwrap_err().code,
            "FE-REACT-BUILD-MISSING"
        );
        assert_eq!(
            resolve("nested/entry.mts", "../logic.mjs").unwrap(),
            root.join("logic.mts")
        );
        let nested = root.join("nested");
        assert_eq!(
            resolve_local_source(&nested.join("entry.mts"), "../logic.mjs", &nested)
                .unwrap_err()
                .code,
            "FE-REACT-BUILD-ROOT"
        );
    }

    #[test]
    fn client_build_dynamic_imports_share_all_graph_budgets_and_external_policy() {
        let app = "export const load = () => import('./lazy.js');";
        let lazy = "export const value = 1;";
        let (_directory, mut config) = fixture(&[("app.js", app), ("lazy.js", lazy)]);
        let baseline = build_react_client(&config).unwrap();
        config.max_modules = 1;
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-LIMIT"
        );
        config.max_modules = 2;
        config.max_source_bytes = app.len() + lazy.len();
        build_react_client(&config).expect("exact source budget");
        config.max_source_bytes -= 1;
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-LIMIT"
        );
        config.max_source_bytes += 1;
        config.max_output_bytes = baseline
            .modules
            .iter()
            .map(|module| module.code.len())
            .sum();
        build_react_client(&config).expect("exact output budget");
        config.max_output_bytes -= 1;
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-LIMIT"
        );
        config.max_output_bytes = 4096;
        config.max_source_bytes = 4096;
        fs::write(
            &config.entry,
            "export const load = () => import('optional-ui');",
        )
        .unwrap();
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-EXTERNAL"
        );
        config.externals.insert(
            "optional-ui".into(),
            "https://example.invalid/ui.mjs".into(),
        );
        let build = build_react_client(&config).unwrap();
        assert_eq!(build.modules.len(), 1);
        assert!(build.modules[0].code.contains("import(\"optional-ui\")"));
        assert!(build.modules[0].dependencies[0].external);
        build.verify_integrity().unwrap();
    }

    #[test]
    fn dynamic_import_literal_edits_preserve_line_continuations_and_utf16_maps() {
        let original =
            "const emoji = '😀'; const load = () => import('./la\\\nzy.js'); const value = 1;";
        let tree = CanonicalEs2020Parser
            .parse(original, crate::ast::ParseGoal::Module)
            .unwrap();
        let mut ast = serde_json::to_value(tree).unwrap();
        let imports = bounded_dynamic_imports(original, &ast, "app.js").unwrap();
        assert_eq!(imports.len(), 1);
        let mut replacement = js_string("./hashed.mjs").unwrap();
        replacement.insert_str(replacement.len() - 1, "\\\n");
        let edits = [SourceEdit {
            start: imports[0].span.start,
            end: imports[0].span.end,
            replacement,
        }];
        let targets = BTreeMap::from([("./lazy.js".into(), "./hashed.mjs".into())]);
        verify_dynamic_import_edits(original, &mut ast, &edits, &targets).unwrap();
        let generated = apply_edits(original, &edits).unwrap();
        assert_eq!(line_offsets(original).len(), line_offsets(&generated).len());
        let value_offset = original.find("const value").unwrap();
        let (_, value_column) =
            offset_line_column(original, &line_offsets(original), value_offset).unwrap();
        let map = serde_json::json!({
            "version": 3, "sources": ["app.js"], "sourcesContent": [original], "names": [],
            "mappings": format!(
                "{};{}",
                encode_vlq(&[0, 0, 0, 0]),
                encode_vlq(&[value_column as i64, 0, 1, value_column as i64]),
            ),
        })
        .to_string();
        let mapped: serde_json::Value = serde_json::from_str(
            &remap_source_map(&map, original, &generated, &edits, "modules/app.mjs").unwrap(),
        )
        .unwrap();
        let segment = decode_vlq(
            mapped["mappings"]
                .as_str()
                .unwrap()
                .split(';')
                .nth(1)
                .unwrap(),
        )
        .unwrap();
        let (_, new_column) = offset_line_column(
            &generated,
            &line_offsets(&generated),
            generated.find("const value").unwrap(),
        )
        .unwrap();
        assert_eq!(segment, vec![new_column as i64, 0, 1, value_column as i64]);
        assert_eq!(mapped["sourcesContent"][0], original);
    }

    #[test]
    fn dynamic_import_edit_verifier_rejects_changes_to_another_expression() {
        let source = "const text = './lazy.js'; export const load = () => import('./lazy.js');";
        let tree = CanonicalEs2020Parser
            .parse(source, crate::ast::ParseGoal::Module)
            .unwrap();
        let mut expected = serde_json::to_value(tree).unwrap();
        let start = source.find("'./lazy.js'").unwrap();
        let edits = [SourceEdit {
            start,
            end: start + "'./lazy.js'".len(),
            replacement: "\"./other.mjs\"".into(),
        }];
        let targets = BTreeMap::from([("./lazy.js".into(), "./other.mjs".into())]);
        assert_eq!(
            verify_dynamic_import_edits(source, &mut expected, &edits, &targets)
                .unwrap_err()
                .code,
            "FE-REACT-BUILD-SPAN"
        );
    }

    #[test]
    fn client_build_preserves_esm_cycles_and_reexports() {
        let (_directory, config) = fixture(&[
            (
                "app.js",
                "import { next } from './cycle.js'; export let value = 1; export function step() { value += 1; return next(); }",
            ),
            (
                "cycle.js",
                "import { value } from './app.js'; export function next() { return value; } export { value as current } from './app.js';",
            ),
        ]);
        let build = build_react_client(&config).expect("cyclic ESM build");
        assert_eq!(build.modules.len(), 2);
        assert_eq!(build.modules[1].dependencies.len(), 2);
        assert!(build.modules[0].code.contains("export let value = 1"));
        assert!(
            build.modules[1]
                .code
                .contains("export { value as current } from")
        );
        assert_eq!(build.modules[1].dependencies[0].target, build.entry_asset);
    }

    #[test]
    fn client_build_emits_shared_default_only_json_modules_and_maps() {
        let source = r#"{"__proto__":{"safe":true},"x":1,"x":2,"neg":-0,"large":1e400,"lone":"\ud800","\udfff":"\u2028\u2029","quote\"key":"a:b"}"#;
        let (directory, mut config) = fixture(&[
            (
                "app.js",
                "import data, { default as same } from './data.json' with { type: 'json' }; import * as ns from './data.json' with { type: 'json' }; export { default as config } from './data.json' with { type: 'json' }; export * as values from './data.json' with { type: 'json' }; export const shared = data === same && data === ns.default;",
            ),
            ("data.json", source),
        ]);
        config.compile.generate_source_maps = true;
        let build = build_react_client(&config).unwrap();
        assert_eq!(build.modules.len(), 2);
        assert_eq!(build.modules[0].dependencies.len(), 4);
        assert!(
            build.modules[0]
                .dependencies
                .iter()
                .all(|edge| { edge.target == build.modules[1].asset_path && !edge.external })
        );
        assert!(!build.modules[0].code.contains("with {"));
        let json = &build.modules[1];
        assert_eq!(json.source_hash, ContentHash::compute(source.as_bytes()));
        assert!(json.code.contains(r#"["__proto__"]"#));
        assert!(json.code.contains(r#"["\udfff"]"#));
        assert!(json.code.contains(r#""\ud800""#));
        assert!(json.code.contains("-0"));
        assert!(json.code.contains("1e400"));
        assert!(!json.code.contains("JSON.parse"));
        assert!(json.dependencies.is_empty());
        let map: serde_json::Value =
            serde_json::from_str(json.source_map.as_ref().unwrap()).unwrap();
        assert_eq!(map["sourcesContent"][0], source);
        assert_eq!(map["sources"][0], "data.json");
        assert_eq!(build, build_react_client(&config).unwrap());
        build.verify_integrity().unwrap();

        fs::write(directory.path().join("data.json"), r#"{"x":3}"#).unwrap();
        let changed = build_react_client(&config).unwrap();
        assert_ne!(build.graph_hash, changed.graph_hash);
        assert_ne!(json.output_hash, changed.modules[1].output_hash);
        assert_eq!(json.asset_path, changed.modules[1].asset_path);
    }

    #[test]
    fn client_build_captures_typed_lazy_json_as_one_shared_esm_asset() {
        let (directory, mut config) = fixture(&[
            (
                "entry.js",
                "import data from './data.json' with { type: 'json' };\nexport const load = () => import /* lazy */ (('./data.json'), {\n'with': { 'type': 'json' }\n});\nexport const same = async () => (await load()).default === data;",
            ),
            ("data.json", r#"{"answer":42}"#),
        ]);
        config.compile.generate_source_maps = true;
        let build = build_react_client(&config).unwrap();
        build.verify_integrity().unwrap();
        assert_eq!(build.modules.len(), 2);
        let entry = build
            .modules
            .iter()
            .find(|module| module.asset_path == build.entry_asset)
            .unwrap();
        assert_eq!(entry.dependencies.len(), 2);
        assert_eq!(entry.dependencies[0].target, entry.dependencies[1].target);
        assert!(!entry.code.contains("'json'"));
        assert!(entry.code.contains("import /* lazy */"));
        let map: serde_json::Value =
            serde_json::from_str(entry.source_map.as_ref().unwrap()).unwrap();
        assert_eq!(
            map["sourcesContent"][0],
            fs::read_to_string(&config.entry).unwrap()
        );
        assert_eq!(build, build_react_client(&config).unwrap());
        fs::write(directory.path().join("data.json"), r#"{"answer":43}"#).unwrap();
        assert_ne!(
            build.graph_hash,
            build_react_client(&config).unwrap().graph_hash
        );
    }

    #[test]
    fn client_build_checks_json_attributes_and_default_only_exports_on_every_edge() {
        let (_directory, mut config) = fixture(&[
            (
                "app.js",
                "import data from './data.json' with { type: 'json' };",
            ),
            ("data.json", "{}"),
            ("code.js", "export default {};"),
        ]);
        for (source, code) in [
            ("import './data.json';", "FE-REACT-BUILD-ATTRIBUTES"),
            (
                "import './data.json' with { type: 'css' };",
                "FE-REACT-BUILD-ATTRIBUTES",
            ),
            (
                "import './data.json' with { type: 'json', integrity: 'unchecked' };",
                "FE-REACT-BUILD-ATTRIBUTES",
            ),
            (
                "import './code.js' with { type: 'json' };",
                "FE-REACT-BUILD-ATTRIBUTES",
            ),
            (
                "import { x } from './data.json' with { type: 'json' };",
                "FE-REACT-BUILD-EXPORT",
            ),
            (
                "import data, { x as other } from './data.json' with { type: 'json' };",
                "FE-REACT-BUILD-EXPORT",
            ),
            (
                "export { x as default } from './data.json' with { type: 'json' };",
                "FE-REACT-BUILD-EXPORT",
            ),
            (
                "export { 'not,default' as x } from './data.json' with { type: 'json' };",
                "FE-REACT-BUILD-EXPORT",
            ),
            (
                "import './data.json' with { type: 'json' }; import './data.json';",
                "FE-REACT-BUILD-ATTRIBUTES",
            ),
            (
                "export const load = () => import('./data.json');",
                "FE-REACT-BUILD-ATTRIBUTES",
            ),
            (
                "export const load = () => import('./code.js', { with: { type: 'json' } });",
                "FE-REACT-BUILD-ATTRIBUTES",
            ),
            (
                "export const load = () => import('./data.json', { with: { type: 'css' } });",
                "FE-REACT-BUILD-ATTRIBUTES",
            ),
            (
                "export const load = () => import('./data.json', { with: { type: 'json', type: 'json' } });",
                "FE-REACT-BUILD-DYNAMIC",
            ),
            (
                "export const load = () => import('./data.json', { with: { type: 'json' }, extra: effect() });",
                "FE-REACT-BUILD-DYNAMIC",
            ),
            (
                "export const load = () => import('./data.json', { get with() { return {}; } });",
                "FE-REACT-BUILD-DYNAMIC",
            ),
            (
                "export const load = () => import('./data.json', { with: { [key()]: 'json' } });",
                "FE-REACT-BUILD-DYNAMIC",
            ),
            (
                "export const load = () => import('./data.json', { with: { type: value } });",
                "FE-REACT-BUILD-DYNAMIC",
            ),
        ] {
            fs::write(&config.entry, source).unwrap();
            assert_eq!(
                build_react_client(&config).unwrap_err().code,
                code,
                "{source}"
            );
        }
        fs::write(
            &config.entry,
            "import './data.json' with { type: 'json', type: 'json' };",
        )
        .unwrap();
        assert!(
            build_react_client(&config).is_err(),
            "duplicate attributes must fail parsing"
        );
        for source in [
            "import './data.json' with { type: 'json' };",
            "import * as data from './data.json' with { type: 'json' };",
            "import { 'default' as data } from './data.json' with { type: 'json' };",
            "export { 'default' as 'a,b' } from './data.json' with { type: 'json' };",
            "export * from './data.json' with { type: 'json' };",
        ] {
            fs::write(&config.entry, source).unwrap();
            build_react_client(&config).unwrap_or_else(|error| panic!("{source}: {error}"));
        }
        config.externals.insert(
            "typed-provider".into(),
            "https://example.invalid/data.json".into(),
        );
        fs::write(
            &config.entry,
            "import data from 'typed-provider' with { type: 'json' };",
        )
        .unwrap();
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-ATTRIBUTES"
        );
    }

    #[test]
    fn client_build_json_validation_rejects_javascript_and_keeps_primitive_spellings() {
        let (directory, config) = fixture(&[
            (
                "app.js",
                "import data from './data.json' with { type: 'json' }; export default data;",
            ),
            ("data.json", "null"),
        ]);
        for source in [
            "",
            "undefined",
            "NaN",
            "[1,]",
            "{\"x\":1,}",
            "{x:1}",
            "01",
            "true false",
            "/* comment */0",
            r#""\x41""#,
            r#""unterminated"#,
        ] {
            fs::write(directory.path().join("data.json"), source).unwrap();
            assert_eq!(
                build_react_client(&config).unwrap_err().code,
                "FE-REACT-BUILD-JSON",
                "{source}"
            );
        }
        for source in [
            "null",
            "false",
            "true",
            "-0",
            "1e400",
            "9007199254740993",
            r#""\ud800""#,
            "\"\u{2028}\u{2029}\"",
            "[]",
            "{}",
        ] {
            fs::write(directory.path().join("data.json"), source).unwrap();
            let build =
                build_react_client(&config).unwrap_or_else(|error| panic!("{source}: {error}"));
            assert!(build.modules[1].code.contains(source), "{source}");
        }

        let mut config = config;
        config.compile.generate_source_maps = true;
        for source in ["0\r", "0\r\n", "0\n"] {
            fs::write(directory.path().join("data.json"), source).unwrap();
            let build = build_react_client(&config).unwrap();
            let map: serde_json::Value =
                serde_json::from_str(build.modules[1].source_map.as_ref().unwrap()).unwrap();
            let mapped_lines: Vec<_> = map["mappings"]
                .as_str()
                .unwrap()
                .split(';')
                .enumerate()
                .filter_map(|(line, mapping)| (!mapping.is_empty()).then_some(line))
                .collect();
            assert_eq!(
                mapped_lines,
                vec![1],
                "generated wrappers must stay unmapped: {source:?}"
            );
            assert_eq!(map["sourcesContent"][0], source);
        }
    }

    #[test]
    fn client_build_json_assets_obey_existing_graph_and_byte_limits() {
        let entry = "import data from './data.json' with { type: 'json' }; export default data;";
        let data = r#"{"nested":[1,2,3],"__proto__":true}"#;
        let (_directory, mut config) = fixture(&[("app.js", entry), ("data.json", data)]);
        config.compile.generate_source_maps = true;
        config.max_modules = 2;
        config.max_source_bytes = entry.len() + data.len();
        let build = build_react_client(&config).unwrap();
        config.max_output_bytes = build
            .modules
            .iter()
            .map(|module| module.code.len() + module.source_map.as_ref().map_or(0, String::len))
            .sum();
        build_react_client(&config).expect("exact delivered byte budget");
        let exact = config.clone();
        config.max_output_bytes -= 1;
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-LIMIT"
        );
        config = exact.clone();
        config.max_source_bytes -= 1;
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-LIMIT"
        );
        config = exact;
        config.max_modules = 1;
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-LIMIT"
        );
    }

    #[test]
    fn client_build_refuses_missing_ambiguous_and_escaping_modules() {
        let (directory, mut config) = fixture(&[
            ("app.js", "import './missing.js';"),
            ("both.js", "export const value = 1;"),
            ("both.ts", "export const value: number = 2;"),
        ]);
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-MISSING"
        );
        fs::write(&config.entry, "import './both';").unwrap();
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-AMBIGUOUS"
        );
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("outside.js"), "export const value = 1;").unwrap();
        config.entry = outside.path().join("outside.js");
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-ROOT"
        );
        assert_eq!(
            directory.path().read_dir().unwrap().count(),
            3,
            "builder must not publish partial assets"
        );
    }

    #[cfg(unix)]
    #[test]
    fn client_build_refuses_symlink_escape() {
        let (directory, config) = fixture(&[("app.js", "import './linked.js';")]);
        let outside = tempfile::tempdir().unwrap();
        let outside_source = outside.path().join("secret.js");
        fs::write(&outside_source, "throw new Error('must not be captured');").unwrap();
        std::os::unix::fs::symlink(outside_source, directory.path().join("linked.js")).unwrap();
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-ROOT"
        );
    }

    #[test]
    fn client_build_refuses_unconfigured_external_and_dynamic_loading() {
        let (_directory, config) = fixture(&[("app.jsx", "export const app = <div/>;")]);
        let error = build_react_client(&config).unwrap_err();
        assert_eq!(error.code, "FE-REACT-BUILD-EXTERNAL");
        assert!(error.message.contains("--external react/jsx-runtime="));
        for source in [
            "const path = './later.js'; const load = () => import(path);",
            "const load = () => import('./' + 'later.js');",
            "const load = () => import('./later.js', {});",
            "const data = require('./data.js');",
            "module.exports = 1;",
        ] {
            fs::write(&config.entry, source).unwrap();
            assert_eq!(
                build_react_client(&config).unwrap_err().code,
                "FE-REACT-BUILD-DYNAMIC",
                "{source}"
            );
        }
    }

    #[test]
    fn client_build_source_module_and_output_budgets_are_enforced() {
        let source = "export const value = 42;";
        let (_directory, mut config) =
            fixture(&[("app.js", source), ("dep.js", "export const dep = 1;")]);
        config.max_source_bytes = source.len();
        let build = build_react_client(&config).expect("exact source budget");
        config.max_source_bytes -= 1;
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-LIMIT"
        );
        config.max_source_bytes = 1_024;
        config.max_output_bytes = build.modules[0].code.len() - 1;
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-LIMIT"
        );
        config.max_output_bytes = 1_024;
        config.max_modules = 1;
        fs::write(&config.entry, "import './dep.js';").unwrap();
        assert_eq!(
            build_react_client(&config).unwrap_err().code,
            "FE-REACT-BUILD-LIMIT"
        );
    }

    #[test]
    fn client_build_is_relocatable_and_hash_binds_all_inputs() {
        let files = [
            (
                "app.js",
                "import { value } from './value'; export { value };",
            ),
            ("value.ts", "export const value: number = 7;"),
        ];
        let (_first, first) = fixture(&files);
        let (_second, mut second) = fixture(&files);
        let original = build_react_client(&first).unwrap();
        assert_eq!(original, build_react_client(&second).unwrap());
        second.externals.insert(
            "unused-provider".into(),
            "https://example.invalid/provider.mjs".into(),
        );
        assert_ne!(
            original.graph_hash,
            build_react_client(&second).unwrap().graph_hash
        );
        second.externals.clear();
        fs::write(
            second.project_root.join("value.ts"),
            "export const value: number = 8;",
        )
        .unwrap();
        assert_ne!(
            original.graph_hash,
            build_react_client(&second).unwrap().graph_hash
        );
    }

    #[test]
    fn client_build_external_providers_are_explicit_and_credential_free() {
        for url in [
            "javascript:alert(1)",
            "file:///tmp/react.mjs",
            "http://example.com/react.mjs",
            "https://user:password@example.com/react.mjs",
        ] {
            let externals = BTreeMap::from([("react".into(), url.into())]);
            assert_eq!(
                validate_externals(&externals).unwrap_err().code,
                "FE-REACT-BUILD-EXTERNAL",
                "{url}"
            );
        }
        for url in [
            "https://example.com/react.mjs",
            "http://localhost:8080/react.mjs",
            "http://127.0.0.1/react.mjs",
            "http://[::1]/react.mjs",
        ] {
            validate_externals(&BTreeMap::from([("react".into(), url.into())]))
                .expect("explicit allowed provider");
        }
    }

    #[test]
    fn client_build_external_keys_are_exact_bare_specifiers() {
        for specifier in [
            "react/",
            "@scope/package/",
            "https://example.com/react.mjs",
            "node:fs",
            "data:text/javascript,export default 1",
        ] {
            let externals =
                BTreeMap::from([(specifier.into(), "https://example.com/provider.mjs".into())]);
            assert_eq!(
                validate_externals(&externals).unwrap_err().code,
                "FE-REACT-BUILD-EXTERNAL",
                "{specifier}",
            );
        }
        for specifier in ["react", "react/jsx-runtime", "@scope/package/subpath"] {
            validate_externals(&BTreeMap::from([(
                specifier.into(),
                "https://example.com/provider.mjs".into(),
            )]))
            .expect("exact bare provider specifier");
        }
    }

    #[test]
    fn client_build_loader_words_in_property_names_are_ordinary_javascript() {
        let source = "const options = { module: 1, exports: 2, require: 3, import: 4 }; export const value = options.module + options.exports + options.require + options.import; export const text = 'ImportMeta require module exports';";
        let (_directory, config) = fixture(&[("app.js", source)]);
        let build = build_react_client(&config).expect("property names are not loader bindings");
        assert!(build.modules[0].code.contains("options.require"));
    }

    #[test]
    fn client_build_source_maps_handle_every_ecmascript_line_terminator() {
        for separator in ["\n", "\r", "\r\n", "\u{2028}", "\u{2029}"] {
            let source =
                format!("import './dep.js';{separator}export const value = '😀';{separator}");
            let (_directory, mut config) =
                fixture(&[("app.js", &source), ("dep.js", "export const dep = 1;")]);
            config.compile.generate_source_maps = true;
            let build = build_react_client(&config)
                .unwrap_or_else(|error| panic!("{separator:?}: {error}"));
            let map: serde_json::Value =
                serde_json::from_str(build.modules[0].source_map.as_ref().unwrap()).unwrap();
            assert_eq!(map["sourcesContent"][0], source);
            assert!(
                map["mappings"]
                    .as_str()
                    .unwrap()
                    .split(';')
                    .nth(1)
                    .is_some_and(|line| !line.is_empty())
            );
        }
    }

    #[test]
    fn client_build_verifier_rejects_code_map_provider_and_link_tampering() {
        let (_directory, mut config) = fixture(&[
            ("app.js", "import './dep.js'; export const value = 1;"),
            ("dep.js", "export const dep = 1;"),
        ]);
        config.compile.generate_source_maps = true;
        let build = build_react_client(&config).unwrap();
        build.verify_integrity().unwrap();
        let mut tampered = build.clone();
        tampered.modules[0]
            .code
            .push_str("\nconsole.log('altered');");
        tampered.modules[0].output_hash = ContentHash::compute(tampered.modules[0].code.as_bytes());
        assert!(
            tampered.verify_integrity().is_err(),
            "even rehashed code changes the graph identity"
        );
        let mut tampered = build.clone();
        tampered.modules[0].source_map.as_mut().unwrap().push(' ');
        assert!(
            tampered.verify_integrity().is_err(),
            "source-map bytes are committed"
        );
        let mut tampered = build.clone();
        tampered
            .import_map
            .insert("react".into(), "https://example.invalid/other.mjs".into());
        assert!(
            tampered.verify_integrity().is_err(),
            "provider selection is committed"
        );
        let mut tampered = build.clone();
        tampered.config_hash = ContentHash::compute(b"different compiler options");
        assert!(
            tampered.verify_integrity().is_err(),
            "compiler settings are committed"
        );
        let mut tampered = build.clone();
        tampered.modules[0].dependencies[0].target = "modules/missing.mjs".into();
        tampered.graph_hash = graph_identity_hash(
            &tampered.entry_asset,
            tampered.config_hash,
            &tampered.import_map,
            &tampered.modules,
            &tampered.package_inputs,
        )
        .unwrap();
        assert!(
            tampered.verify_integrity().is_err(),
            "a correctly hashed dangling edge is still invalid"
        );
    }

    #[test]
    fn import_rewrite_remaps_source_columns_without_changing_original_positions() {
        let original = "import './dep.js'; const \u{03b2} = 1;\nexport { \u{03b2} };\n";
        let declaration_end = original.find(';').unwrap() + 1;
        let binding_column = original.find("const").unwrap() as i64;
        let map = serde_json::json!({
            "version": 3, "sources": ["app.js"], "sourcesContent": [original], "names": [],
            "mappings": format!("{},{};{}", encode_vlq(&[0,0,0,0]), encode_vlq(&[binding_column,0,0,binding_column]), encode_vlq(&[0,0,1,-binding_column])),
        }).to_string();
        let edits = [SourceEdit {
            start: 0,
            end: declaration_end,
            replacement: "import './much-longer-module-name.mjs';".into(),
        }];
        let generated = apply_edits(original, &edits).unwrap();
        let result: serde_json::Value = serde_json::from_str(
            &remap_source_map(&map, original, &generated, &edits, "modules/app.mjs").unwrap(),
        )
        .unwrap();
        let mappings = result["mappings"].as_str().unwrap();
        let first_line = mappings.split(';').next().unwrap();
        let mut segments = first_line
            .split(',')
            .map(|segment| decode_vlq(segment).unwrap());
        assert_eq!(segments.next().unwrap(), vec![0]);
        let first = segments.next().unwrap();
        assert_eq!(
            first,
            vec![
                generated.find("const").unwrap() as i64,
                0,
                0,
                binding_column
            ]
        );
        assert_eq!(result["sourcesContent"][0], original);
        assert_eq!(result["file"], "app.mjs");
    }

    #[test]
    fn import_rewrite_terminates_preceding_same_line_source_mapping() {
        let original = "\"use client\"; import './dep.js'; const value = 1;";
        let start = original.find("import").unwrap();
        let end = original[start..].find(';').unwrap() + start + 1;
        let binding = original.find("const").unwrap() as i64;
        let map = serde_json::json!({
            "version": 3, "sources": ["app.js"], "sourcesContent": [original], "names": [],
            "mappings": ([
                encode_vlq(&[0, 0, 0, 0]),
                encode_vlq(&[start as i64, 0, 0, start as i64]),
                encode_vlq(&[binding - start as i64, 0, 0, binding - start as i64]),
            ].join(",")),
        })
        .to_string();
        let edits = [SourceEdit {
            start,
            end,
            replacement: "import './much-longer-module-name.mjs';".into(),
        }];
        let generated = apply_edits(original, &edits).unwrap();
        let result: serde_json::Value = serde_json::from_str(
            &remap_source_map(&map, original, &generated, &edits, "modules/app.mjs").unwrap(),
        )
        .unwrap();
        let segments: Vec<_> = result["mappings"]
            .as_str()
            .unwrap()
            .split(',')
            .map(|segment| decode_vlq(segment).unwrap())
            .collect();
        assert_eq!(segments[0], vec![0, 0, 0, 0]);
        assert_eq!(
            segments[1],
            vec![start as i64],
            "the rebuilt import must be explicitly unmapped"
        );
        assert_eq!(
            segments[2],
            vec![
                generated.find("const").unwrap() as i64 - start as i64,
                0,
                0,
                binding
            ]
        );
    }
}
