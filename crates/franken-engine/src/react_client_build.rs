//! Closed-world ESM client builds using the native React compiler.
//!
//! Source capture is bounded by an explicit project root and resource limits.
//! Modules remain ESM, so the browser owns live bindings, cycles, top-level
//! await, and evaluation order. No guest code or external provider is executed
//! while building. CommonJS, dynamic imports, and non-code assets are refused.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ast::{ExportKind, ImportClause, Statement};
use crate::capability::RuntimeCapability;
use crate::hash_tiers::ContentHash;
use crate::module_resolver::{
    CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
    ModuleDependency, ModuleRequest, ModuleResolver, ModuleSyntax, ResolutionContext,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactClientBuild {
    pub schema_version: String,
    pub entry_asset: String,
    /// Commits compiler options and resource limits without retaining host paths.
    pub config_hash: ContentHash,
    pub graph_hash: ContentHash,
    pub modules: Vec<ReactClientModuleAsset>,
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
    let entry_name = source_name(&entry, &root)?;
    let mut queue = VecDeque::from([entry.clone()]);
    let mut queued = BTreeSet::from([entry]);
    let mut modules = BTreeMap::new();
    let mut source_bytes = 0usize;
    let mut output_bytes = 0usize;
    let mut resolver = DeterministicModuleResolver::new("/");

    while let Some(path) = queue.pop_front() {
        let name = source_name(&path, &root)?;
        let language = source_language(&path)?;
        let source = read_bounded_source(&path, config.max_source_bytes - source_bytes)?;
        source_bytes += source.len();
        let mut compile_config = config.compile.clone();
        compile_config.lowering_config.source_file = Some(name.clone());
        let compiled =
            compile_react_module(&source, language, &compile_config).map_err(|error| {
                ReactClientBuildError::new("FE-REACT-BUILD-COMPILE", format!("{name}: {error}"))
            })?;
        let tree = CanonicalEs2020Parser
            .parse(
                compiled.generated_code.as_str(),
                crate::ast::ParseGoal::Module,
            )
            .map_err(|error| {
                ReactClientBuildError::new("FE-REACT-BUILD-PARSE", format!("{name}: {error}"))
            })?;
        reject_unbounded_loading(
            &serde_json::to_value(&tree).map_err(serialization_error)?,
            &name,
        )?;
        let mut edits = Vec::new();
        let mut dependencies = Vec::new();
        let mut definition =
            ModuleDefinition::new(ModuleSyntax::EsModule, compiled.generated_code.clone())
                .require_capability(RuntimeCapability::ModuleLoad)
                .with_provenance(name.clone());

        for statement in &tree.body {
            let (specifier, declaration, attributes) = match statement {
                Statement::Import(import) => (
                    import.source.as_str(),
                    Some(import_prefix(&import.clause)?),
                    &import.import_attributes,
                ),
                Statement::Export(export) => match &export.kind {
                    ExportKind::NamedClause(clause) if clause.source().is_some() => (
                        clause.source().and_then(|source| source.as_str()),
                        Some(format!("export {} from ", clause.canonical_head())),
                        clause.import_attributes(),
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
            if !attributes.is_empty() {
                return Err(ReactClientBuildError::new(
                    "FE-REACT-BUILD-FORMAT",
                    format!(
                        "{name}: import attributes require non-code module support ({specifier})",
                    ),
                ));
            }
            let (target, emitted_specifier, external) =
                if let Some(url) = config.externals.get(specifier) {
                    (url.clone(), specifier.to_string(), true)
                } else {
                    let dependency = resolve_local_source(&path, specifier, &root)?;
                    let dependency_name = source_name(&dependency, &root)?;
                    definition.dependencies.push(ModuleDependency::new(
                        format!("/{dependency_name}"),
                        ImportStyle::Import,
                    ));
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
            let span = statement.span();
            let start = usize::try_from(span.start_offset).map_err(|_| invalid_span())?;
            let end = usize::try_from(span.end_offset).map_err(|_| invalid_span())?;
            let original = compiled
                .generated_code
                .get(start..end)
                .ok_or_else(invalid_span)?;
            let mut replacement = format!(
                "{}{};",
                declaration.expect("static declaration"),
                js_string(&emitted_specifier)?
            );
            // Keep physical line counts, then remap columns for unchanged code.
            replacement.push_str(&"\n".repeat(line_offsets(original).len() - 1));
            edits.push(SourceEdit {
                start,
                end,
                replacement,
            });
        }
        let mut code = apply_edits(&compiled.generated_code, &edits)?;
        let asset = asset_path(&name);
        let source_map = compiled
            .source_map
            .as_deref()
            .map(|map| remap_source_map(map, &compiled.generated_code, &code, &edits, &asset))
            .transpose()?;
        if source_map.is_some() {
            code.push_str(&format!(
                "\n//# sourceMappingURL={}.map\n",
                asset.strip_prefix("modules/").expect("asset prefix")
            ));
        }
        // Rewriting uses AST declaration spans, not text substitution. Check
        // the complete delivered bytes as well, so span/reconstruction defects
        // cannot produce a successful build containing invalid JavaScript.
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
        graph_hash: graph_identity_hash(&entry_asset, config_hash, &config.externals, &modules)?,
        entry_asset,
        config_hash,
        modules,
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
) -> BuildResult<ContentHash> {
    serde_json::to_vec(&(
        REACT_CLIENT_BUILD_SCHEMA_VERSION,
        entry,
        config_hash,
        externals,
        modules,
    ))
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
    source_language(&canonical)?;
    Ok(canonical)
}

fn outside_root() -> ReactClientBuildError {
    ReactClientBuildError::new(
        "FE-REACT-BUILD-ROOT",
        "module resolution escapes the explicit project root",
    )
}

fn source_language(path: &Path) -> BuildResult<ReactInputLanguage> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("ts" | "tsx" | "mts") => Ok(ReactInputLanguage::Tsx),
        Some("js" | "jsx" | "mjs") => Ok(ReactInputLanguage::Jsx),
        _ => Err(ReactClientBuildError::new(
            "FE-REACT-BUILD-FORMAT",
            format!(
                "{}: client builds accept local ESM JS/JSX/TS/TSX modules; CommonJS and non-code assets are unsupported",
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
    if candidate.extension().is_some() {
        return confined_file(&candidate, root);
    }
    let mut matches = BTreeSet::new();
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

fn reject_unbounded_loading(value: &serde_json::Value, name: &str) -> BuildResult<()> {
    match value {
        serde_json::Value::Object(fields) => {
            if let Some(identifier) = fields.get("Identifier").and_then(serde_json::Value::as_str)
                && matches!(identifier, "require" | "module" | "exports" | "import")
            {
                return Err(ReactClientBuildError::new(
                    "FE-REACT-BUILD-DYNAMIC",
                    format!(
                        "{name}: CommonJS bindings and dynamic imports are unsupported in a closed-world ESM client build ({identifier})",
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
                reject_unbounded_loading(child, name)?;
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                reject_unbounded_loading(child, name)?;
            }
        }
        _ => {}
    }
    Ok(())
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
        "native parser returned an invalid or overlapping module declaration span",
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
            "const load = () => import('./later.js');",
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
