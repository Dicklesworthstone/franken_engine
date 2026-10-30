//! Node's CommonJS package resolution for bare `require` specifiers
//! (bd-4dme3): the `node_modules` walk-up inside the module root, package.json
//! `exports` (subpaths, `*` patterns, and built-in plus embedder-selected
//! conditions) and `main`, JSON modules, and core-module precedence.
//!
//! Every path this resolves is still canonicalized and bounded by the module
//! root in `canonicalize_module_candidate` before it is read.

use super::*;

/// Node's core module names (`require('module').builtinModules`). A bare
/// `require` of one never resolves from `node_modules`: in Node the core
/// module wins even when a package of the same name is installed.
const NODE_CORE_MODULE_NAMES: &[&str] = &[
    "assert",
    "assert/strict",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "dns/promises",
    "domain",
    "events",
    "fs",
    "fs/promises",
    "http",
    "http2",
    "https",
    "inspector",
    "inspector/promises",
    "module",
    "net",
    "os",
    "path",
    "path/posix",
    "path/win32",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "readline/promises",
    "repl",
    "stream",
    "stream/consumers",
    "stream/promises",
    "stream/web",
    "string_decoder",
    "sys",
    "timers",
    "timers/promises",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "util/types",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

/// A Node core module specifier (`fs`, `node:fs`): no package lookup, no
/// runtime module object; its recognized call forms are lowered instead.
pub(crate) fn is_node_core_module_specifier(specifier: &str) -> bool {
    specifier.starts_with("node:") || NODE_CORE_MODULE_NAMES.contains(&specifier)
}

/// Conditions a CommonJS `require` matches in an `exports` map. `default`
/// always matches as well.
const REQUIRE_EXPORT_CONDITIONS: &[&str] = &["node", "require"];

/// Conditions an ES module `import` matches (bd-mgfhs); `default` as well.
const IMPORT_EXPORT_CONDITIONS: &[&str] = &["node", "import"];

/// PACKAGE_RESOLVE selects one package and exact subpaths. The legacy
/// CommonJS search may probe extensions/directories and keep walking upward.
/// Private imports use PACKAGE_RESOLVE even when their caller is `require`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PackageLookupMode {
    CommonJs,
    PackageUrl,
}

/// Largest package.json the resolver reads.
const MAX_PACKAGE_MANIFEST_BYTES: u64 = 1 << 20;

/// A package.json `exports` value with object keys kept in document order.
/// Condition precedence is the order the package author wrote, which a
/// sorted map would lose.
#[derive(Debug, Clone, PartialEq)]
enum PackageExports {
    Target(String),
    Alternatives(Vec<PackageExports>),
    Map(Vec<(String, PackageExports)>),
    Null,
    Invalid,
}

impl<'de> Deserialize<'de> for PackageExports {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ExportsVisitor;

        impl<'de> serde::de::Visitor<'de> for ExportsVisitor {
            type Value = PackageExports;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a package.json exports value")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(PackageExports::Target(value.to_string()))
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(PackageExports::Null)
            }

            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(PackageExports::Invalid)
            }

            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(PackageExports::Invalid)
            }

            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(PackageExports::Invalid)
            }

            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(PackageExports::Invalid)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut alternatives = Vec::new();
                while let Some(alternative) = seq.next_element()? {
                    alternatives.push(alternative);
                }
                Ok(PackageExports::Alternatives(alternatives))
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut entries: Vec<(String, PackageExports)> = Vec::new();
                let mut positions = BTreeMap::<String, usize>::new();
                while let Some((key, value)) = map.next_entry::<String, PackageExports>()? {
                    // JSON.parse replaces duplicate properties without moving
                    // their original insertion position. Keeping both entries
                    // selected the FIRST value, while sorting keys or moving a
                    // replacement to the end changes conditional precedence.
                    if let Some(&position) = positions.get(&key) {
                        entries[position].1 = value;
                    } else {
                        positions.insert(key.clone(), entries.len());
                        entries.push((key, value));
                    }
                }
                Ok(PackageExports::Map(entries))
            }
        }

        deserializer.deserialize_any(ExportsVisitor)
    }
}

/// The package.json fields CommonJS resolution reads. `exports: null` is
/// absent, as in Node.
#[derive(Debug, Default, Deserialize)]
struct PackageManifest {
    #[serde(default)]
    name: Option<serde_json::Value>,
    #[serde(default)]
    main: Option<serde_json::Value>,
    #[serde(default)]
    exports: Option<PackageExports>,
    #[serde(default)]
    imports: Option<PackageExports>,
    #[serde(default, rename = "type")]
    module_type: Option<serde_json::Value>,
}

impl PackageManifest {
    fn main(&self) -> Option<&str> {
        self.main
            .as_ref()
            .and_then(serde_json::Value::as_str)
            .filter(|main| !main.is_empty())
    }
}

/// How one `exports` target resolved. Node distinguishes an explicit `null`
/// (the subpath is excluded; stop) from no matching condition (try the next).
#[derive(Debug, PartialEq, Eq)]
enum ExportsTargetResolution {
    Found(PathBuf),
    Package(String),
    Excluded,
    NoMatch,
}

/// Only an invalid TARGET is recoverable by an alternatives array. Invalid
/// configuration and invalid requested subpaths must propagate through every
/// enclosing array, rather than selecting an unrelated fallback module.
#[derive(Debug, PartialEq, Eq)]
enum PackageTargetError {
    Target(String),
    Configuration(String),
    Specifier(String),
}

impl fmt::Display for PackageTargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (code, detail) = match self {
            Self::Target(detail) => ("ERR_INVALID_PACKAGE_TARGET", detail),
            Self::Configuration(detail) => ("ERR_INVALID_PACKAGE_CONFIG", detail),
            Self::Specifier(detail) => ("ERR_INVALID_MODULE_SPECIFIER", detail),
        };
        write!(formatter, "{code}: {detail}")
    }
}

fn read_package_manifest(dir: &Path) -> Result<Option<PackageManifest>, String> {
    let path = dir.join("package.json");
    if !path.is_file() {
        return Ok(None);
    }
    read_package_manifest_file(&path).map(Some)
}

/// Read the already-selected manifest, without rebuilding its lexical path.
/// The runtime resolver passes a containment-checked canonical path here.
fn read_package_manifest_file(path: &Path) -> Result<PackageManifest, String> {
    let file = fs::File::open(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_PACKAGE_MANIFEST_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PACKAGE_MANIFEST_BYTES {
        return Err(format!(
            "{} exceeds {MAX_PACKAGE_MANIFEST_BYTES} bytes",
            path.display()
        ));
    }
    // Node accepts one UTF-8 BOM at the start of package.json. Charge it to
    // the existing byte limit before stripping it; do not trim malformed JSON
    // or accept a second/interior BOM as whitespace.
    let json = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
    serde_json::from_slice(json).map_err(|error| format!("invalid {}: {error}", path.display()))
}

/// Split a bare specifier into its package name (`name` or `@scope/name`)
/// and the remaining subpath (empty or starting with `/`). `None` for a name
/// Node rejects.
fn split_package_specifier(specifier: &str) -> Option<(&str, &str)> {
    let name_end = if specifier.starts_with('@') {
        let scope_end = specifier.find('/')?;
        specifier[scope_end + 1..]
            .find('/')
            .map_or(specifier.len(), |offset| scope_end + 1 + offset)
    } else {
        specifier.find('/').unwrap_or(specifier.len())
    };
    let (name, subpath) = specifier.split_at(name_end);
    if name.is_empty()
        || name.starts_with('.')
        || name.ends_with('/')
        || name.contains('\\')
        || name.contains('%')
    {
        return None;
    }
    Some((name, subpath))
}

/// Node's PATTERN_KEY_COMPARE: the key with the longer text before `*` wins,
/// then the longer key.
fn pattern_key_precedes(candidate: &str, incumbent: &str) -> bool {
    let base = |key: &str| key.find('*').map_or(key.len(), |star| star + 1);
    match base(candidate).cmp(&base(incumbent)) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => candidate.len() > incumbent.len(),
    }
}

/// Shared exact/pattern selection for package imports and exports. Lifetimes
/// distinguish a borrowed manifest target from a capture in the request.
fn package_mapping_target<'a, 'b>(
    entries: &'a [(String, PackageExports)],
    subpath: &'b str,
) -> Option<(&'a PackageExports, Option<&'b str>)> {
    let exact = entries
        .iter()
        .find(|(key, _)| key == subpath && !key.contains('*'));
    if let Some((_, target)) = exact {
        return Some((target, None));
    }
    let mut best: Option<(&str, &PackageExports, &str)> = None;
    for (key, target) in entries {
        let Some(star) = key.find('*') else {
            continue;
        };
        let (prefix, suffix) = (&key[..star], &key[star + 1..]);
        if suffix.contains('*')
            || !subpath.starts_with(prefix)
            || subpath == prefix
            || !(suffix.is_empty() || (subpath.ends_with(suffix) && subpath.len() >= key.len()))
        {
            continue;
        }
        if best.is_none_or(|(best_key, ..)| pattern_key_precedes(key, best_key)) {
            best = Some((
                key,
                target,
                &subpath[prefix.len()..subpath.len() - suffix.len()],
            ));
        }
    }
    best.map(|(_, target, capture)| (target, Some(capture)))
}

/// Node's PACKAGE_EXPORTS_RESOLVE for a CommonJS `require`: map `subpath`
/// (`.` or `./x`) through `exports` to a path inside `package_dir`.
fn resolve_package_exports(
    package_dir: &Path,
    subpath: &str,
    exports: &PackageExports,
    conditions: &[&str],
) -> Result<PathBuf, String> {
    let not_exported = || format!("does not export subpath `{subpath}`");
    let subpath_entries = match exports {
        PackageExports::Map(entries) if entries.iter().any(|(key, _)| key.starts_with('.')) => {
            if entries.iter().any(|(key, _)| !key.starts_with('.')) {
                return Err("mixes subpath keys and condition keys in \"exports\"".to_string());
            }
            Some(entries)
        }
        _ => None,
    };
    let (target, pattern_match) = match subpath_entries {
        None if subpath == "." => (exports, None),
        None => return Err(not_exported()),
        Some(entries) => package_mapping_target(entries, subpath).ok_or_else(not_exported)?,
    };
    match resolve_package_target(package_dir, target, pattern_match, false, conditions)
        .map_err(|error| error.to_string())?
    {
        ExportsTargetResolution::Found(path) => Ok(path),
        ExportsTargetResolution::Package(_)
        | ExportsTargetResolution::Excluded
        | ExportsTargetResolution::NoMatch => Err(not_exported()),
    }
}

/// Node's PACKAGE_TARGET_RESOLVE with the given conditions (CommonJS
/// `require` or ES module `import`).
fn resolve_package_target(
    package_dir: &Path,
    target: &PackageExports,
    pattern_match: Option<&str>,
    imports: bool,
    conditions: &[&str],
) -> Result<ExportsTargetResolution, PackageTargetError> {
    match target {
        PackageExports::Target(target) => {
            if let Some(relative) = target.strip_prefix("./") {
                // Validate the target BEFORE replacing '*'. A bad target may
                // select another array entry; a bad capture may not. Check the
                // capture independently even if the target ignores it or only
                // uses it in a query/fragment: appending '.js' must not disguise
                // a forbidden '.' or 'node_modules' capture as a valid name.
                if has_forbidden_package_segment(relative) {
                    return Err(PackageTargetError::Target(format!(
                        "has an invalid or escaping package target `{target}`"
                    )));
                }
                let Some(capture) = pattern_match else {
                    return checked_package_relative_target(package_dir, relative)
                        .map(ExportsTargetResolution::Found);
                };
                if has_forbidden_package_segment(capture) {
                    return Err(PackageTargetError::Specifier(format!(
                        "invalid package pattern subpath `{capture}`"
                    )));
                }
                // Materialize only AFTER substitution. A legal pattern may
                // split a percent escape across its '*' ("./%*", "61.cjs").
                // Traversal assembled across that boundary is still refused
                // by the final package-relative check, without array fallback.
                return checked_package_relative_target(package_dir, &relative.replace('*', capture))
                    .map_err(|error| match error {
                        PackageTargetError::Target(detail) => PackageTargetError::Specifier(detail),
                        other => other,
                    })
                    .map(ExportsTargetResolution::Found);
            }
            let expanded = match pattern_match {
                Some(capture) => target.replace('*', capture),
                None => target.to_string(),
            };
            // Private imports may redirect to another package, but not to an
            // absolute path, a URL, or a relative path outside this package.
            // A missing selected package/file does not select another entry.
            if imports
                && !expanded.starts_with(['/', '.'])
                && !expanded.contains([':', '\\'])
                && split_package_specifier(&expanded).is_some()
            {
                return Ok(ExportsTargetResolution::Package(expanded));
            }
            Err(PackageTargetError::Target(format!(
                "has an invalid package target `{expanded}`"
            )))
        }
        PackageExports::Null => Ok(ExportsTargetResolution::Excluded),
        PackageExports::Invalid => Err(PackageTargetError::Target(
            "has an invalid package target".to_string(),
        )),
        PackageExports::Map(entries) => {
            // Array-index keys have special ECMAScript enumeration order and
            // are not permitted as conditions. Check the whole visited object
            // before selecting any branch, but do not visit unmatched branches.
            if entries
                .iter()
                .any(|(key, _)| canonical_array_index(key).is_some())
            {
                return Err(PackageTargetError::Configuration(
                    "package conditions cannot contain numeric property keys".to_string(),
                ));
            }
            for (condition, value) in entries {
                if condition != "default" && !conditions.contains(&condition.as_str()) {
                    continue;
                }
                match resolve_package_target(
                    package_dir,
                    value,
                    pattern_match,
                    imports,
                    conditions,
                )? {
                    ExportsTargetResolution::NoMatch => continue,
                    resolved => return Ok(resolved),
                }
            }
            Ok(ExportsTargetResolution::NoMatch)
        }
        PackageExports::Alternatives(alternatives) => {
            if alternatives.is_empty() {
                return Ok(ExportsTargetResolution::Excluded);
            }
            // PACKAGE_TARGET_RESOLVE distinguishes undefined (no active
            // condition) from null (an explicit exclusion). Only undefined
            // lets an enclosing condition object try its next branch. Keep
            // the last null/invalid-target result while skipping unmatched
            // alternatives, including nested arrays.
            let mut last_outcome = Ok(ExportsTargetResolution::NoMatch);
            for alternative in alternatives {
                match resolve_package_target(
                    package_dir,
                    alternative,
                    pattern_match,
                    imports,
                    conditions,
                ) {
                    Ok(ExportsTargetResolution::NoMatch) => {}
                    Ok(ExportsTargetResolution::Excluded) => {
                        last_outcome = Ok(ExportsTargetResolution::Excluded);
                    }
                    Ok(resolved) => return Ok(resolved),
                    Err(error @ PackageTargetError::Target(_)) => last_outcome = Err(error),
                    Err(error) => return Err(error),
                }
            }
            last_outcome
        }
    }
}

/// Convert a relative target's URL path to a file path. Decode once, after
/// separating query/fragment. Refuse encoded separators and traversal before
/// joining; the caller still enforces canonical module-root containment.
#[cfg(test)]
fn package_relative_target(package_dir: &Path, relative: &str) -> Result<PathBuf, String> {
    checked_package_relative_target(package_dir, relative).map_err(|error| error.to_string())
}

fn checked_package_relative_target(
    package_dir: &Path,
    relative: &str,
) -> Result<PathBuf, PackageTargetError> {
    let invalid = || format!("has an invalid or escaping package target `./{relative}`");
    // Invalid URL materialization is not an invalid target alternative. Once
    // selected, encoded separators/invalid encodings cannot fall through to
    // another file. The outward interpreter error still carries its request.
    let decoded = decode_package_url_path(relative).map_err(PackageTargetError::Specifier)?;
    if invalid_package_segments(&decoded) {
        return Err(PackageTargetError::Target(invalid()));
    }
    Ok(package_dir.join(decoded))
}

fn invalid_package_segments(decoded: &str) -> bool {
    decoded.split('/').any(|segment| {
        segment.is_empty()
            || matches!(segment, "." | "..")
            || segment.eq_ignore_ascii_case("node_modules")
    })
}

/// Match reserved segments in the ORIGINAL target/capture, decoding ASCII
/// escapes once and treating encoded separators as segment boundaries. A
/// capture is not itself a file URL: a constant target can legitimately
/// ignore its other bytes. Do not reject UTF-8 or percent syntax here; the
/// existing URL decoder validates any bytes actually used by the target.
/// Only twelve bytes per segment are needed, even for a very long request.
fn has_forbidden_package_segment(path: &str) -> bool {
    fn forbidden(segment: &[u8; 12], length: usize) -> bool {
        match length {
            1 => segment[0] == b'.',
            2 => segment[..2] == *b"..",
            12 => segment.eq_ignore_ascii_case(b"node_modules"),
            _ => false,
        }
    }

    let bytes = path.as_bytes();
    let mut cursor = 0;
    let mut segment = [0_u8; 12];
    let mut length = 0_usize;
    while cursor < bytes.len() {
        let mut byte = bytes[cursor];
        cursor += 1;
        if byte == b'%'
            && let Some(high) = bytes.get(cursor).and_then(|b| (*b as char).to_digit(16))
            && let Some(low) = bytes.get(cursor + 1).and_then(|b| (*b as char).to_digit(16))
        {
            byte = ((high << 4) | low) as u8;
            cursor += 2;
        }
        if matches!(byte, b'/' | b'\\') {
            if forbidden(&segment, length) {
                return true;
            }
            length = 0;
        } else {
            if length < segment.len() {
                segment[length] = byte;
            }
            length = length.saturating_add(1);
        }
    }
    forbidden(&segment, length)
}

/// URL decoding shared by export targets and unexported ESM subpaths. The
/// latter are not restricted to an exports map's package-relative segments;
/// final canonical module-root containment is still required by the loader.
fn decode_package_url_path(relative: &str) -> Result<String, String> {
    let pathname = relative.split(['?', '#']).next().unwrap_or(relative);
    decode_package_pathname(pathname)
        .map_err(|_| format!("has an invalid package URL path `{relative}`"))
}

/// Decode the materialized pathname after the URL suffix was separated.
/// Raw pattern captures are checked independently above, before this step.
fn decode_package_pathname(pathname: &str) -> Result<String, String> {
    let invalid = || format!("has an invalid package URL path `{pathname}`");
    let bytes = pathname.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'%' {
            let high = bytes
                .get(cursor + 1)
                .and_then(|byte| (*byte as char).to_digit(16));
            let low = bytes
                .get(cursor + 2)
                .and_then(|byte| (*byte as char).to_digit(16));
            let (Some(high), Some(low)) = (high, low) else {
                return Err(invalid());
            };
            let byte = ((high << 4) | low) as u8;
            if matches!(byte, b'/' | b'\\' | 0) {
                return Err(invalid());
            }
            decoded.push(byte);
            cursor += 3;
        } else {
            decoded.push(bytes[cursor]);
            cursor += 1;
        }
    }
    let decoded = String::from_utf8(decoded).map_err(|_| invalid())?;
    if decoded.contains('\\') || decoded.as_bytes().contains(&0) {
        return Err(invalid());
    }
    Ok(decoded)
}

fn resolve_package_imports_target(
    package_dir: &Path,
    specifier: &str,
    imports: &PackageExports,
    conditions: &[&str],
) -> Result<ExportsTargetResolution, String> {
    let undefined = || format!("package import `{specifier}` is not defined");
    if specifier == "#" || specifier.starts_with("#/") || specifier.ends_with('/') {
        return Err(format!("invalid package import specifier `{specifier}`"));
    }
    let PackageExports::Map(entries) = imports else {
        return Err(undefined());
    };
    let (target, capture) = package_mapping_target(entries, specifier).ok_or_else(undefined)?;
    match resolve_package_target(package_dir, target, capture, true, conditions)
        .map_err(|error| error.to_string())?
    {
        ExportsTargetResolution::Excluded | ExportsTargetResolution::NoMatch => Err(undefined()),
        resolved => Ok(resolved),
    }
}

/// Append `.ext` to a path's full file name (`a.min` becomes `a.min.js`),
/// as Node's file probing does, rather than replacing an extension.
pub(super) fn with_appended_extension(path: &Path, extension: &str) -> PathBuf {
    let mut appended = path.as_os_str().to_owned();
    appended.push(".");
    appended.push(extension);
    PathBuf::from(appended)
}

/// Probe legacy package entry points using metadata already read by the
/// caller. In particular, ESM must not reopen an unchecked package manifest.
fn resolve_manifest_main(directory: &Path, manifest: &PackageManifest) -> Option<PathBuf> {
    let main = directory.join(manifest.main()?);
    if main.is_file() {
        return Some(main);
    }
    ["js", "json", "node"]
        .into_iter()
        .map(|extension| with_appended_extension(&main, extension))
        .chain(["index.js", "index.json", "index.node"].map(|index| main.join(index)))
        .find(|candidate| candidate.is_file())
}

impl InterpreterCore {
    /// Package metadata is executable resolution input, not an exemption from
    /// module-root containment. Check it before reading any JSON bytes, and
    /// open the checked canonical path rather than following the original
    /// manifest symlink again. This does not provide descriptor-relative
    /// protection against concurrent replacement of canonical ancestors.
    fn read_contained_package_manifest(
        &self,
        specifier: &str,
        directory: &Path,
    ) -> Result<Option<PackageManifest>, InterpreterError> {
        let path = directory.join("package.json");
        if !path.is_file() {
            return Ok(None);
        }
        let failed = |reason| InterpreterError::ModuleResolutionFailed {
            specifier: specifier.to_string(),
            reason: ModuleResolutionFailureReason::Other(reason),
        };
        let canonical = path.canonicalize().map_err(|error| {
            failed(format!(
                "failed to canonicalize {}: {error}",
                path.display()
            ))
        })?;
        self.canonicalize_module_candidate(specifier, &canonical)?;
        read_package_manifest_file(&canonical)
            .map(Some)
            .map_err(failed)
    }

    /// The nearest package scope determines a module's declared format.
    /// Reuse the same bounded, containment-checked metadata reader as package
    /// resolution, including its node_modules and configured-root boundaries.
    pub(super) fn package_parse_goal_for_module(
        &self,
        resolved: &str,
    ) -> Result<Option<ParseGoal>, InterpreterError> {
        let Some(root) = self.canonical_module_root_path() else {
            return Ok(None);
        };
        let Some(directory) = Path::new(resolved).parent() else {
            return Ok(None);
        };
        let Some((_, manifest)) = self.require_package_scope(resolved, directory, &root)? else {
            return Ok(None);
        };
        Ok(match manifest.module_type.as_ref().and_then(serde_json::Value::as_str) {
            Some("module") => Some(ParseGoal::Module),
            Some("commonjs") => Some(ParseGoal::Script),
            _ => None,
        })
    }

    /// The module root, canonicalized: the boundary every resolved module and
    /// every `node_modules` lookup must stay inside.
    pub(super) fn canonical_module_root_path(&self) -> Option<PathBuf> {
        self.config.canonical_module_root.clone().or_else(|| {
            self.config
                .module_root
                .as_deref()
                .and_then(|root| Path::new(root).canonicalize().ok())
        })
    }

    /// Resolve a bare `require` specifier the way Node does for CommonJS:
    /// core modules first, then each `node_modules` directory from the
    /// requiring module's directory up to the module root, reading the
    /// package's `exports` when it declares one and otherwise its files,
    /// `main`, and `index`.
    pub(super) fn resolve_bare_require_specifier(
        &self,
        specifier: &str,
    ) -> Result<PathBuf, InterpreterError> {
        let conditions = self.effective_module_conditions(specifier, REQUIRE_EXPORT_CONDITIONS)?;
        self.resolve_bare_package_specifier(specifier, &conditions, PackageLookupMode::CommonJs)
    }

    /// An ES module's bare specifier (bd-mgfhs): match `import` conditions,
    /// select the nearest package, and resolve unexported subpaths exactly.
    pub(super) fn resolve_bare_import_specifier(
        &self,
        specifier: &str,
    ) -> Result<PathBuf, InterpreterError> {
        let conditions = self.effective_module_conditions(specifier, IMPORT_EXPORT_CONDITIONS)?;
        self.resolve_bare_package_specifier(specifier, &conditions, PackageLookupMode::PackageUrl)
    }

    fn effective_module_conditions<'a>(
        &'a self,
        specifier: &str,
        defaults: &'a [&'a str],
    ) -> Result<std::borrow::Cow<'a, [&'a str]>, InterpreterError> {
        // The ordinary no-custom-condition path borrows the static defaults:
        // no allocation, sorting or string copies on a package lookup.
        if self.config.module_conditions.is_empty() {
            return Ok(std::borrow::Cow::Borrowed(defaults));
        }
        // Direct interpreter embedders receive the same bounded contract as
        // orchestrator callers. Validate before consulting any package file.
        InterpreterConfig::validate_module_conditions(&self.config.module_conditions).map_err(
            |detail| InterpreterError::ModuleResolutionFailed {
                specifier: specifier.to_string(),
                reason: ModuleResolutionFailureReason::Other(detail.to_string()),
            },
        )?;
        let mut conditions: Vec<_> = defaults
            .iter()
            .copied()
            .chain(self.config.module_conditions.iter().map(String::as_str))
            .collect();
        conditions.sort_unstable();
        conditions.dedup();
        Ok(std::borrow::Cow::Owned(conditions))
    }

    fn resolve_bare_package_specifier(
        &self,
        specifier: &str,
        conditions: &[&str],
        mode: PackageLookupMode,
    ) -> Result<PathBuf, InterpreterError> {
        let failed = |reason| InterpreterError::ModuleResolutionFailed {
            specifier: specifier.to_string(),
            reason,
        };
        let core_name = specifier.strip_prefix("node:");
        if core_name.is_some() || NODE_CORE_MODULE_NAMES.contains(&specifier) {
            return Err(failed(ModuleResolutionFailureReason::Other(format!(
                "`{}` is a Node core module; its recognized call forms are lowered, but it has no runtime module object",
                core_name.unwrap_or(specifier)
            ))));
        }
        let Some(root) = self.canonical_module_root_path() else {
            return Err(failed(
                ModuleResolutionFailureReason::BareSpecifiersNotSupported,
            ));
        };
        let start = self
            .current_module_specifier
            .as_deref()
            .and_then(|label| Path::new(label).parent())
            .and_then(|dir| dir.canonicalize().ok())
            .filter(|dir| dir.starts_with(&root))
            .unwrap_or_else(|| root.clone());
        if specifier.starts_with('#')
            && let Some((scope, manifest)) = self.require_package_scope(specifier, &start, &root)?
            && let Some(imports) = manifest.imports.as_ref()
        {
            let target = resolve_package_imports_target(&scope, specifier, imports, conditions)
                .map_err(|reason| failed(ModuleResolutionFailureReason::Other(reason)))?;
            return match target {
                ExportsTargetResolution::Found(path) if path.is_file() => Ok(path),
                ExportsTargetResolution::Package(target) => {
                    self.resolve_named_require_from(
                        &target,
                        &scope,
                        &root,
                        conditions,
                        PackageLookupMode::PackageUrl,
                    )
                    .map_err(|error| {
                        // Keep the source-level alias in the outward diagnostic.
                        failed(ModuleResolutionFailureReason::Other(format!(
                            "package import `{specifier}` targeting `{target}`: {error}"
                        )))
                    })
                }
                _ => Err(failed(ModuleResolutionFailureReason::ModuleNotFound)),
            };
        }
        // ESM private imports never fall through to node_modules/#name.
        // CommonJS retains that historical fallback without an imports map.
        if mode == PackageLookupMode::PackageUrl && specifier.starts_with('#') {
            return Err(failed(ModuleResolutionFailureReason::Other(format!(
                "package import `{specifier}` is not defined"
            ))));
        }
        self.resolve_named_require_from(specifier, &start, &root, conditions, mode)
    }

    /// External imports targets resolve from their owning package, not from a
    /// potentially deeper requiring file. This is also the ordinary bare-name
    /// path; aliases do not fork package lookup or mutate the executing module.
    fn resolve_named_require_from(
        &self,
        specifier: &str,
        start: &Path,
        root: &Path,
        conditions: &[&str],
        mode: PackageLookupMode,
    ) -> Result<PathBuf, InterpreterError> {
        let failed = |reason| InterpreterError::ModuleResolutionFailed {
            specifier: specifier.to_string(),
            reason,
        };
        if specifier.starts_with("node:") || NODE_CORE_MODULE_NAMES.contains(&specifier) {
            return Err(failed(ModuleResolutionFailureReason::Other(format!(
                "`{specifier}` is a Node core module without a runtime module object"
            ))));
        }
        let Some((name, subpath)) = split_package_specifier(specifier) else {
            return Err(failed(ModuleResolutionFailureReason::MalformedSpecifier));
        };
        // Self references precede node_modules and are limited to the nearest
        // package scope. An unexported self subpath must not fall through to
        // an installed package of the same name.
        if let Some((scope, manifest)) = self.require_package_scope(specifier, start, root)?
            && manifest.name.as_ref().and_then(serde_json::Value::as_str) == Some(name)
            && let Some(exports) = manifest.exports.as_ref()
        {
            let target =
                resolve_package_exports(&scope, &format!(".{subpath}"), exports, conditions)
                    .map_err(|reason| {
                        failed(ModuleResolutionFailureReason::Other(format!(
                            "package `{name}` {reason}"
                        )))
                    })?;
            return if target.is_file() {
                Ok(target)
            } else {
                Err(failed(ModuleResolutionFailureReason::ModuleNotFound))
            };
        }
        for dir in start.ancestors() {
            if !dir.starts_with(root) {
                break;
            }
            if dir.file_name().is_some_and(|name| name == "node_modules") {
                continue;
            }
            let modules_dir = dir.join("node_modules");
            if !modules_dir.is_dir() {
                continue;
            }
            let package_dir = modules_dir.join(name);
            if mode == PackageLookupMode::PackageUrl && !package_dir.is_dir() {
                continue;
            }
            let manifest = self.read_contained_package_manifest(specifier, &package_dir)?;
            if let Some(exports) = manifest
                .as_ref()
                .and_then(|manifest| manifest.exports.as_ref())
            {
                let target = resolve_package_exports(
                    &package_dir,
                    &format!(".{subpath}"),
                    exports,
                    conditions,
                )
                .map_err(|reason| {
                    failed(ModuleResolutionFailureReason::Other(format!(
                        "package `{name}` {reason}"
                    )))
                })?;
                return if target.is_file() {
                    Ok(target)
                } else {
                    Err(failed(ModuleResolutionFailureReason::ModuleNotFound))
                };
            }
            if mode == PackageLookupMode::PackageUrl {
                let found = if subpath.is_empty() {
                    manifest
                        .as_ref()
                        .and_then(|manifest| resolve_manifest_main(&package_dir, manifest))
                        .or_else(|| {
                            ["index.js", "index.json", "index.node"]
                                .map(|index| package_dir.join(index))
                                .into_iter()
                                .find(|candidate| candidate.is_file())
                        })
                } else {
                    let decoded = decode_package_url_path(&subpath[1..])
                        .map_err(|reason| failed(ModuleResolutionFailureReason::Other(reason)))?;
                    // Prefixing './' also keeps a doubled slash in a package
                    // subpath from becoming an absolute filesystem path.
                    Some(package_dir.join(format!("./{decoded}")))
                };
                // The selected package owns the result even if its requested
                // file is absent. Never substitute another installed version.
                return found
                    .filter(|candidate| candidate.is_file())
                    .ok_or_else(|| failed(ModuleResolutionFailureReason::ModuleNotFound));
            }
            if let Some(found) = self
                .resolve_require_candidate(&modules_dir.join(specifier), specifier.ends_with('/'))
            {
                return Ok(found);
            }
        }
        Err(failed(ModuleResolutionFailureReason::ModuleNotFound))
    }

    /// The nearest package.json owns both self references and private imports.
    /// A dependency without a manifest cannot inherit its consumer's scope
    /// across node_modules. The configured module root is also a hard stop.
    fn require_package_scope(
        &self,
        specifier: &str,
        start: &Path,
        root: &Path,
    ) -> Result<Option<(PathBuf, PackageManifest)>, InterpreterError> {
        for directory in start.ancestors() {
            if !directory.starts_with(root)
                || directory
                    .file_name()
                    .is_some_and(|name| name == "node_modules")
            {
                break;
            }
            let Some(manifest) = self.read_contained_package_manifest(specifier, directory)? else {
                continue;
            };
            // A manifest with no name/exports still closes the scope; never
            // search an outer package just because this one cannot resolve X.
            return Ok(Some((directory.to_path_buf(), manifest)));
        }
        Ok(None)
    }

    /// Node's LOAD_AS_DIRECTORY step for a package.json `main`: the file it
    /// names (as given, or with `.js`/`.json`/`.node` appended), else that path's
    /// `index.js`/`index.json`/`index.node`. A selected native addon is refused
    /// by the loader, not skipped in favor of another candidate. `None` when
    /// the directory declares no usable `main`, so its own index is tried.
    pub(super) fn resolve_package_main(directory: &Path) -> Option<PathBuf> {
        let manifest = read_package_manifest(directory).ok().flatten()?;
        resolve_manifest_main(directory, &manifest)
    }

    /// Node loads a required `.json` file as a module whose `exports` is the
    /// parsed value. It is evaluated as `module.exports = JSON.parse(<text>)`
    /// so the engine's own `JSON.parse` defines that value, and invalid JSON
    /// throws the same `SyntaxError` it would there.
    pub(super) fn json_module_source(text: &str) -> Result<String, InterpreterError> {
        Ok(format!(
            "module.exports = JSON.parse({});\n",
            Self::json_module_text_literal(text)?
        ))
    }

    /// An ES module import of a `.json` file (`import data from './x.json'
    /// with { type: 'json' }`) loads a JSON module (ES2025 16.2.1.7): its
    /// only export is `default`, the value `JSON.parse` gives for the text,
    /// so invalid JSON throws that `SyntaxError`.
    pub(super) fn json_es_module_source(text: &str) -> Result<String, InterpreterError> {
        Ok(format!(
            "export default JSON.parse({});\n",
            Self::json_module_text_literal(text)?
        ))
    }

    fn json_module_text_literal(text: &str) -> Result<String, InterpreterError> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let literal =
            serde_json::to_string(text).map_err(|error| InterpreterError::InternalError {
                details: format!("failed to encode a JSON module as a string literal: {error}"),
            })?;
        // JSON leaves U+2028/U+2029 unescaped; escape them so the literal is
        // valid for any ECMAScript parser.
        Ok(literal
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package_test_core(root: &Path) -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.module_root = Some(root.display().to_string());
        config.canonical_module_root = Some(root.canonicalize().expect("canonical test root"));
        InterpreterCore::new(config, "package-resolution-test")
    }

    fn write_package_fixture(root: &Path, relative: &str, content: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directory");
        fs::write(path, content).expect("fixture file");
    }

    fn assert_package_path(actual: Result<PathBuf, InterpreterError>, expected: &Path) {
        assert_eq!(
            actual
                .expect("resolved package")
                .canonicalize()
                .expect("resolved path"),
            expected.canonicalize().expect("expected path")
        );
    }

    #[test]
    fn conditional_arrays_preserve_unmatched_excluded_and_invalid_states() {
        let directory = Path::new("/conditional-array-package");
        for conditions in [REQUIRE_EXPORT_CONDITIONS, IMPORT_EXPORT_CONDITIONS] {
            for target in [
                r#"[{"browser":"./browser.cjs"}]"#,
                r#"[[{"browser":"./browser.cjs"}],{}]"#,
                r#"[{"browser":null},{"development":[]}]"#,
            ] {
                let target: PackageExports = serde_json::from_str(target).unwrap();
                assert!(matches!(
                    resolve_package_target(directory, &target, None, false, conditions),
                    Ok(ExportsTargetResolution::NoMatch)
                ));
            }
            for target in [
                "[]",
                "[null]",
                r#"[null,{"browser":"./browser.cjs"}]"#,
                r#"[[],{}]"#,
                r#"["../invalid.cjs",null,{"browser":"./browser.cjs"}]"#,
                r#"[["../invalid.cjs"],null,{}]"#,
            ] {
                let target: PackageExports = serde_json::from_str(target).unwrap();
                assert!(matches!(
                    resolve_package_target(directory, &target, None, false, conditions),
                    Ok(ExportsTargetResolution::Excluded)
                ));
            }
            for target in [
                r#"["../invalid.cjs",{"browser":"./browser.cjs"}]"#,
                r#"[null,"../invalid.cjs",{}]"#,
            ] {
                let target: PackageExports = serde_json::from_str(target).unwrap();
                assert!(matches!(
                    resolve_package_target(directory, &target, None, false, conditions),
                    Err(PackageTargetError::Target(_))
                ));
            }
            for target in [
                r#"{"node":[{"browser":"./browser.cjs"}],"default":"./fallback.cjs"}"#,
                r#"{"node":[[{"browser":"./browser.cjs"}],{}],"default":"./fallback.cjs"}"#,
                r#"[null,{"browser":"./browser.cjs"},"./fallback.cjs"]"#,
                r#"["../invalid.cjs",{},"./fallback.cjs"]"#,
            ] {
                let target: PackageExports = serde_json::from_str(target).unwrap();
                for imports in [false, true] {
                    assert!(matches!(
                        resolve_package_target(directory, &target, None, imports, conditions),
                        Ok(ExportsTargetResolution::Found(path))
                            if path == directory.join("fallback.cjs")
                    ));
                }
            }
            // Configuration and selected URL errors are not array fallback
            // signals. They still fail even with a valid later alternative.
            let numeric: PackageExports = serde_json::from_str(
                r#"[{"node":{"0":"./invalid.cjs","default":"./fallback.cjs"}},"./fallback.cjs"]"#,
            )
            .unwrap();
            assert!(matches!(
                resolve_package_target(directory, &numeric, None, false, conditions),
                Err(PackageTargetError::Configuration(_))
            ));
            let separator: PackageExports =
                serde_json::from_str(r#"["./%2fhidden.cjs","./fallback.cjs"]"#).unwrap();
            assert!(matches!(
                resolve_package_target(directory, &separator, None, false, conditions),
                Err(PackageTargetError::Specifier(_))
            ));
        }
    }

    #[test]
    fn commonjs_extension_and_index_probes_follow_node_order() {
        let root = tempfile::tempdir().expect("module root");
        for path in [
            "exact",
            "exact.js",
            "value.cjs",
            "value.js",
            "value.mjs",
            "data.cjs",
            "data.json",
            "data.mjs",
            "dir/index.cjs",
            "dir/index.js",
            "dir/index.json",
            "dir/index.mjs",
            "json-dir/index.cjs",
            "json-dir/index.json",
            "only-cjs.cjs",
            "only-mjs.mjs",
            "only-cjs-dir/index.cjs",
            "only-mjs-dir/index.mjs",
        ] {
            write_package_fixture(root.path(), path, "0");
        }
        let core = package_test_core(root.path());
        for (request, selected) in [
            ("./exact", "exact"),
            ("./value", "value.js"),
            ("./data", "data.json"),
            ("./dir", "dir/index.js"),
            ("./dir/", "dir/index.js"),
            ("./json-dir", "json-dir/index.json"),
            ("./only-cjs.cjs", "only-cjs.cjs"),
            ("./only-mjs.mjs", "only-mjs.mjs"),
        ] {
            assert_package_path(
                core.resolve_require_specifier(request).map(PathBuf::from),
                &root.path().join(selected),
            );
        }
        for request in [
            "./only-cjs",
            "./only-mjs",
            "./only-cjs-dir",
            "./only-mjs-dir",
        ] {
            assert!(
                matches!(
                    core.resolve_require_specifier(request),
                    Err(InterpreterError::ModuleResolutionFailed {
                        reason: ModuleResolutionFailureReason::ModuleNotFound,
                        ..
                    })
                ),
                "{request} must not infer .cjs or .mjs"
            );
        }
    }

    #[test]
    fn commonjs_native_addon_candidates_precede_directory_and_main_fallbacks() {
        let root = tempfile::tempdir().expect("module root");
        for (path, text) in [
            ("addon.node", "not JavaScript"),
            (
                "addon/index.js",
                "module.exports = 'wrong directory fallback';",
            ),
            (
                "node_modules/native-main/package.json",
                r#"{"main":"entry"}"#,
            ),
            ("node_modules/native-main/entry.node", "not JavaScript"),
            (
                "node_modules/native-main/index.js",
                "module.exports = 'wrong main fallback';",
            ),
            ("node_modules/native-index/index.node", "not JavaScript"),
        ] {
            write_package_fixture(root.path(), path, text);
        }
        let core = package_test_core(root.path());
        for (request, selected) in [
            ("./addon", "addon.node"),
            ("./addon.node", "addon.node"),
            ("native-main", "node_modules/native-main/entry.node"),
            ("native-index", "node_modules/native-index/index.node"),
        ] {
            assert_package_path(
                core.resolve_require_specifier(request).map(PathBuf::from),
                &root.path().join(selected),
            );
        }
        // Package-only ESM legacy main resolution chooses the same addon;
        // it will be refused by the loader rather than parsed as source.
        assert_package_path(
            core.resolve_bare_import_specifier("native-main"),
            &root.path().join("node_modules/native-main/entry.node"),
        );
    }

    #[test]
    fn package_conditions_augment_defaults_without_changing_the_lookup_mode() {
        let root = tempfile::tempdir().expect("module root");
        for (path, text) in [
            (
                "package.json",
                r##"{"name":"self","exports":{".":{"development":"./dev.cjs","default":"./prod.cjs"}},"imports":{"#local":{"development":"./dev.cjs","default":"./prod.cjs"},"#external":"conditional"}}"##,
            ),
            ("dev.cjs", "module.exports = 'dev';"),
            ("prod.cjs", "module.exports = 'prod';"),
            (
                "node_modules/conditional/package.json",
                r#"{"exports":{"development":{"import":"./dev.mjs","require":"./dev.cjs"},"import":"./prod.mjs","require":"./prod.cjs"}}"#,
            ),
            (
                "node_modules/conditional/dev.cjs",
                "module.exports = 'dev-require';",
            ),
            (
                "node_modules/conditional/dev.mjs",
                "export default 'dev-import';",
            ),
            (
                "node_modules/conditional/prod.cjs",
                "module.exports = 'prod-require';",
            ),
            (
                "node_modules/conditional/prod.mjs",
                "export default 'prod-import';",
            ),
            ("node_modules/legacy/value.js", "module.exports = 42;"),
            ("node_modules/legacy/dir/index.js", "module.exports = 43;"),
        ] {
            write_package_fixture(root.path(), path, text);
        }
        let mut core = package_test_core(root.path());
        assert!(
            matches!(
                core.effective_module_conditions("conditional", REQUIRE_EXPORT_CONDITIONS)
                    .unwrap(),
                std::borrow::Cow::Borrowed(_)
            ),
            "default package conditions must not allocate"
        );
        assert_package_path(
            core.resolve_bare_require_specifier("conditional"),
            &root.path().join("node_modules/conditional/prod.cjs"),
        );
        assert_package_path(
            core.resolve_bare_import_specifier("conditional"),
            &root.path().join("node_modules/conditional/prod.mjs"),
        );
        core.config.module_conditions = vec!["development".into(), "development".into()];
        for request in ["conditional", "#external"] {
            assert_package_path(
                core.resolve_bare_require_specifier(request),
                &root.path().join("node_modules/conditional/dev.cjs"),
            );
            assert_package_path(
                core.resolve_bare_import_specifier(request),
                &root.path().join("node_modules/conditional/dev.mjs"),
            );
        }
        for request in ["self", "#local"] {
            assert_package_path(
                core.resolve_bare_require_specifier(request),
                &root.path().join("dev.cjs"),
            );
            assert_package_path(
                core.resolve_bare_import_specifier(request),
                &root.path().join("dev.cjs"),
            );
        }
        // Conditions may deliberately include the other style. That changes
        // conditional-map selection, never CommonJS's file/directory probing.
        core.config.module_conditions = vec!["import".into()];
        assert_package_path(
            core.resolve_bare_require_specifier("conditional"),
            &root.path().join("node_modules/conditional/prod.mjs"),
        );
        assert_package_path(
            core.resolve_bare_require_specifier("legacy/value"),
            &root.path().join("node_modules/legacy/value.js"),
        );
        assert_package_path(
            core.resolve_bare_require_specifier("legacy/dir"),
            &root.path().join("node_modules/legacy/dir/index.js"),
        );
        core.config.module_conditions = vec!["require".into()];
        assert!(core.resolve_bare_import_specifier("legacy/value").is_err());
        assert!(core.resolve_bare_import_specifier("legacy/dir").is_err());
    }

    #[test]
    fn additional_conditions_preserve_document_order_and_package_encapsulation() {
        let root = tempfile::tempdir().expect("module root");
        for (path, text) in [
            (
                "node_modules/ordered/package.json",
                r#"{"exports":{"default":"./default.cjs","development":"./dev.cjs"}}"#,
            ),
            ("node_modules/ordered/default.cjs", "module.exports = 1;"),
            ("node_modules/ordered/dev.cjs", "module.exports = 2;"),
            (
                "node_modules/denied/package.json",
                r#"{"exports":{"development":null,"default":"./public.cjs"}}"#,
            ),
            ("node_modules/denied/public.cjs", "module.exports = 3;"),
            (
                "node_modules/escape/package.json",
                r#"{"exports":{"development":"../outside.cjs","default":"./public.cjs"}}"#,
            ),
            ("node_modules/escape/public.cjs", "module.exports = 4;"),
            ("node_modules/outside.cjs", "module.exports = 'escaped';"),
        ] {
            write_package_fixture(root.path(), path, text);
        }
        let mut core = package_test_core(root.path());
        core.config.module_conditions = vec!["development".into()];
        assert_package_path(
            core.resolve_bare_require_specifier("ordered"),
            &root.path().join("node_modules/ordered/default.cjs"),
        );
        for request in ["denied", "escape"] {
            assert!(core.resolve_bare_require_specifier(request).is_err());
            assert!(core.resolve_bare_import_specifier(request).is_err());
        }
        for conditions in [
            vec![String::new()],
            vec!["x".repeat(129)],
            vec!["dev\nprod".into()],
            vec!["dev".into(); 63],
        ] {
            core.config.module_conditions = conditions;
            let error = core
                .resolve_bare_require_specifier("ordered")
                .expect_err("invalid embedder conditions cannot be ignored");
            assert!(error.to_string().contains("module_conditions"), "{error}");
        }
    }

    #[test]
    fn module_format_uses_nearest_scope_and_stops_at_node_modules() {
        let root = tempfile::tempdir().expect("module root");
        for (path, text) in [
            ("package.json", r#"{"type":"module"}"#),
            ("common/package.json", r#"{"type":"commonjs"}"#),
            ("untyped/package.json", "{}"),
            ("node_modules/typed/package.json", r#"{"type":"module"}"#),
        ] {
            write_package_fixture(root.path(), path, text);
        }
        let core = package_test_core(root.path());
        for (path, expected) in [
            ("entry.js", Some(ParseGoal::Module)),
            ("common/nested/value.js", Some(ParseGoal::Script)),
            ("untyped/value.js", None),
            ("node_modules/loose/value.js", None),
            ("node_modules/typed/value.js", Some(ParseGoal::Module)),
        ] {
            assert_eq!(
                core.package_parse_goal_for_module(&root.path().join(path).display().to_string())
                    .expect("contained format"),
                expected,
                "{path}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn module_format_refuses_a_package_manifest_outside_the_module_root() {
        let root = tempfile::tempdir().expect("module root");
        let outside = tempfile::tempdir().expect("outside metadata");
        write_package_fixture(outside.path(), "package.json", r#"{"type":"module"}"#);
        std::os::unix::fs::symlink(
            outside.path().join("package.json"),
            root.path().join("package.json"),
        )
        .expect("manifest link");
        let core = package_test_core(root.path());
        let error = core
            .package_parse_goal_for_module(&root.path().join("entry.js").display().to_string())
            .expect_err("a format probe cannot read outside metadata");
        assert!(error.to_string().contains("escapes module root"), "{error}");
    }

    #[test]
    fn esm_private_imports_do_not_fall_back_to_installed_hash_packages() {
        for manifest in [None, Some("{}"), Some(r#"{"imports":null}"#)] {
            let root = tempfile::tempdir().expect("module root");
            if let Some(manifest) = manifest {
                write_package_fixture(root.path(), "package.json", manifest);
            }
            write_package_fixture(
                root.path(),
                "node_modules/#hidden/index.js",
                "module.exports = 8;",
            );
            let core = package_test_core(root.path());
            assert_package_path(
                core.resolve_bare_require_specifier("#hidden"),
                &root.path().join("node_modules/#hidden/index.js"),
            );
            let error = core
                .resolve_bare_import_specifier("#hidden")
                .expect_err("undefined private import");
            assert!(
                error
                    .to_string()
                    .contains("package import `#hidden` is not defined")
            );
        }
    }

    #[test]
    fn esm_legacy_package_subpaths_require_exact_files() {
        let root = tempfile::tempdir().expect("module root");
        write_package_fixture(root.path(), "node_modules/legacy/package.json", "{}");
        write_package_fixture(
            root.path(),
            "node_modules/legacy/entry.js",
            "module.exports = 2;",
        );
        write_package_fixture(
            root.path(),
            "node_modules/legacy/sub/index.js",
            "module.exports = 3;",
        );
        let core = package_test_core(root.path());
        for (request, relative) in [
            ("legacy/entry", "node_modules/legacy/entry.js"),
            ("legacy/sub", "node_modules/legacy/sub/index.js"),
            ("legacy/sub/", "node_modules/legacy/sub/index.js"),
        ] {
            assert_package_path(
                core.resolve_bare_require_specifier(request),
                &root.path().join(relative),
            );
            assert!(
                core.resolve_bare_import_specifier(request).is_err(),
                "{request}"
            );
        }
        assert_package_path(
            core.resolve_bare_import_specifier("legacy/entry.js"),
            &root.path().join("node_modules/legacy/entry.js"),
        );
    }

    #[test]
    fn esm_nearest_package_does_not_fall_back_to_another_installed_version() {
        let root = tempfile::tempdir().expect("module root");
        write_package_fixture(root.path(), "app/node_modules/legacy/package.json", "{}");
        write_package_fixture(
            root.path(),
            "node_modules/legacy/missing.js",
            "module.exports = 5;",
        );
        let mut core = package_test_core(root.path());
        core.current_module_specifier =
            Some(root.path().join("app/entry.mjs").display().to_string());
        assert_package_path(
            core.resolve_bare_require_specifier("legacy/missing.js"),
            &root.path().join("node_modules/legacy/missing.js"),
        );
        assert!(
            core.resolve_bare_import_specifier("legacy/missing.js")
                .is_err()
        );
    }

    #[test]
    fn esm_legacy_package_roots_keep_main_and_index_fallbacks() {
        for (manifest, relative) in [
            (r#"{"main":"entry"}"#, "entry.js"),
            (r#"{"main":"lib"}"#, "lib/index.js"),
            (r#"{"main":"missing"}"#, "index.js"),
            ("{}", "index.js"),
        ] {
            let root = tempfile::tempdir().expect("module root");
            write_package_fixture(root.path(), "node_modules/legacy/package.json", manifest);
            let entry = format!("node_modules/legacy/{relative}");
            write_package_fixture(root.path(), &entry, "module.exports = 1;");
            let core = package_test_core(root.path());
            assert_package_path(
                core.resolve_bare_import_specifier("legacy"),
                &root.path().join(&entry),
            );
            assert_package_path(
                core.resolve_bare_require_specifier("legacy"),
                &root.path().join(entry),
            );
        }
        let root = tempfile::tempdir().expect("module root");
        write_package_fixture(
            root.path(),
            "node_modules/no-manifest/index.js",
            "module.exports = 7;",
        );
        assert_package_path(
            package_test_core(root.path()).resolve_bare_import_specifier("no-manifest"),
            &root.path().join("node_modules/no-manifest/index.js"),
        );
    }

    #[test]
    fn esm_package_lookup_does_not_probe_standalone_node_modules_files() {
        let root = tempfile::tempdir().expect("module root");
        write_package_fixture(root.path(), "node_modules/flat.js", "module.exports = 6;");
        let core = package_test_core(root.path());
        assert_package_path(
            core.resolve_bare_require_specifier("flat"),
            &root.path().join("node_modules/flat.js"),
        );
        assert!(core.resolve_bare_import_specifier("flat").is_err());
    }

    #[test]
    fn private_external_targets_use_exact_package_subpaths_for_both_callers() {
        let root = tempfile::tempdir().expect("module root");
        write_package_fixture(
            root.path(),
            "package.json",
            r##"{"imports":{"#exact":"legacy/entry.js","#extension":"legacy/entry","#directory":"legacy/sub","#root":"legacy"}}"##,
        );
        write_package_fixture(
            root.path(),
            "node_modules/legacy/package.json",
            r#"{"main":"entry"}"#,
        );
        write_package_fixture(
            root.path(),
            "node_modules/legacy/entry.js",
            "module.exports = 2;",
        );
        write_package_fixture(
            root.path(),
            "node_modules/legacy/sub/index.js",
            "module.exports = 3;",
        );
        let core = package_test_core(root.path());
        for (conditions, mode) in [
            (REQUIRE_EXPORT_CONDITIONS, PackageLookupMode::CommonJs),
            (IMPORT_EXPORT_CONDITIONS, PackageLookupMode::PackageUrl),
        ] {
            for request in ["#exact", "#root"] {
                assert_package_path(
                    core.resolve_bare_package_specifier(request, conditions, mode),
                    &root.path().join("node_modules/legacy/entry.js"),
                );
            }
            for request in ["#extension", "#directory"] {
                let error = core
                    .resolve_bare_package_specifier(request, conditions, mode)
                    .expect_err("no file probing for imports targets");
                assert!(
                    error.to_string().contains(request),
                    "alias must remain in diagnostic"
                );
            }
        }
    }

    #[test]
    fn esm_exact_package_subpaths_decode_urls_once() {
        let root = tempfile::tempdir().expect("module root");
        for name in ["a#b.js", "a%23b.js", "é.js"] {
            write_package_fixture(
                root.path(),
                &format!("node_modules/legacy/{name}"),
                "module.exports = 9;",
            );
        }
        let core = package_test_core(root.path());
        for (request, name) in [
            ("legacy/a%23b.js", "a#b.js"),
            ("legacy/a%2523b.js", "a%23b.js"),
            ("legacy/%C3%A9.js?query#fragment", "é.js"),
            ("legacy//a%23b.js", "a#b.js"),
        ] {
            assert_package_path(
                core.resolve_bare_import_specifier(request),
                &root.path().join("node_modules/legacy").join(name),
            );
        }
        for request in [
            "legacy/a%2fb.js",
            "legacy/a%5cb.js",
            "legacy/%00.js",
            "legacy/%ff.js",
        ] {
            assert!(
                core.resolve_bare_import_specifier(request).is_err(),
                "{request}"
            );
        }
    }

    #[test]
    fn package_conditions_still_select_distinct_import_and_require_entries() {
        let root = tempfile::tempdir().expect("module root");
        write_package_fixture(
            root.path(),
            "node_modules/dual/package.json",
            r#"{"exports":{"import":"./import.mjs","require":"./require.cjs"}}"#,
        );
        write_package_fixture(
            root.path(),
            "node_modules/dual/import.mjs",
            "export default 1;",
        );
        write_package_fixture(
            root.path(),
            "node_modules/dual/require.cjs",
            "module.exports = 2;",
        );
        let core = package_test_core(root.path());
        assert_package_path(
            core.resolve_bare_import_specifier("dual"),
            &root.path().join("node_modules/dual/import.mjs"),
        );
        assert_package_path(
            core.resolve_bare_require_specifier("dual"),
            &root.path().join("node_modules/dual/require.cjs"),
        );
    }

    #[cfg(unix)]
    #[test]
    fn package_manifest_symlink_escape_is_rejected_before_json_parsing() {
        let root = tempfile::tempdir().expect("module root");
        let outside = tempfile::tempdir().expect("outside root");
        write_package_fixture(
            root.path(),
            "node_modules/escape/entry.cjs",
            "module.exports = 1;",
        );
        write_package_fixture(
            outside.path(),
            "manifest.json",
            "not JSON: must not be parsed",
        );
        let outside_manifest = outside.path().join("manifest.json");
        std::os::unix::fs::symlink(
            &outside_manifest,
            root.path().join("node_modules/escape/package.json"),
        )
        .expect("manifest symlink");
        let core = package_test_core(root.path());
        let expected = core
            .canonicalize_module_candidate("escape", &outside_manifest)
            .expect_err("outside manifest must fail containment")
            .to_string();
        for (conditions, mode) in [
            (REQUIRE_EXPORT_CONDITIONS, PackageLookupMode::CommonJs),
            (IMPORT_EXPORT_CONDITIONS, PackageLookupMode::PackageUrl),
        ] {
            let actual = core
                .resolve_bare_package_specifier("escape", conditions, mode)
                .expect_err("must reject the manifest before parsing it");
            assert_eq!(actual.to_string(), expected);
        }
    }

    #[cfg(unix)]
    #[test]
    fn node_modules_directory_symlink_cannot_supply_outside_metadata() {
        let root = tempfile::tempdir().expect("module root");
        let outside = tempfile::tempdir().expect("outside root");
        write_package_fixture(outside.path(), "escape/package.json", "not JSON");
        std::os::unix::fs::symlink(outside.path(), root.path().join("node_modules"))
            .expect("node_modules symlink");
        let core = package_test_core(root.path());
        let expected = core
            .canonicalize_module_candidate("escape", &outside.path().join("escape/package.json"))
            .expect_err("outside metadata must fail containment")
            .to_string();
        assert_eq!(
            core.resolve_bare_require_specifier("escape")
                .expect_err("outside node_modules manifest")
                .to_string(),
            expected
        );
    }

    #[cfg(unix)]
    #[test]
    fn in_root_manifest_symlink_keeps_targets_relative_to_the_package() {
        let root = tempfile::tempdir().expect("module root");
        write_package_fixture(
            root.path(),
            "manifests/shared.json",
            r#"{"exports":"./entry.cjs"}"#,
        );
        write_package_fixture(
            root.path(),
            "node_modules/linked/entry.cjs",
            "module.exports = 42;",
        );
        std::os::unix::fs::symlink(
            root.path().join("manifests/shared.json"),
            root.path().join("node_modules/linked/package.json"),
        )
        .expect("contained manifest symlink");
        let core = package_test_core(root.path());
        for (conditions, mode) in [
            (REQUIRE_EXPORT_CONDITIONS, PackageLookupMode::CommonJs),
            (IMPORT_EXPORT_CONDITIONS, PackageLookupMode::PackageUrl),
        ] {
            assert_eq!(
                core.resolve_bare_package_specifier("linked", conditions, mode)
                    .expect("contained manifest must remain usable")
                    .canonicalize()
                    .expect("resolved module"),
                root.path()
                    .join("node_modules/linked/entry.cjs")
                    .canonicalize()
                    .expect("expected module")
            );
        }
    }

    #[test]
    fn package_manifest_reader_preserves_size_and_parse_errors() {
        let root = tempfile::tempdir().expect("module root");
        write_package_fixture(root.path(), "bad/package.json", "{");
        write_package_fixture(
            root.path(),
            "large/package.json",
            &" ".repeat(MAX_PACKAGE_MANIFEST_BYTES as usize + 1),
        );
        let core = package_test_core(root.path());
        let bad = core
            .read_contained_package_manifest("bad", &root.path().join("bad"))
            .expect_err("malformed JSON must not be treated as a missing manifest");
        assert!(bad.to_string().contains("invalid"));
        let large = core
            .read_contained_package_manifest("large", &root.path().join("large"))
            .expect_err("oversized metadata must not be treated as missing");
        assert!(large.to_string().contains("exceeds"));
        assert!(
            core.read_contained_package_manifest("absent", &root.path().join("absent"))
                .expect("a missing manifest remains optional")
                .is_none()
        );
    }

    fn exports(json: &str) -> PackageExports {
        serde_json::from_str(json).expect("exports JSON")
    }

    #[test]
    fn package_target_fixtures_preserve_selection_and_fatal_errors() {
        #[derive(Deserialize)]
        struct Case {
            id: String,
            target: String,
            capture: Option<String>,
            value: Option<String>,
            error: Option<String>,
        }
        let cases: Vec<Case> = serde_json::from_str(include_str!(
            "../../tests/fixtures/package_target_validation.json"
        ))
        .expect("shared Node target fixtures");
        assert_eq!(cases.len(), 52);
        let package_dir = Path::new("/pkg");
        for case in cases {
            for conditions in [REQUIRE_EXPORT_CONDITIONS, IMPORT_EXPORT_CONDITIONS] {
                for imports in [false, true] {
                    let (key, request) = match (&case.capture, imports) {
                        (None, false) => (".", ".".to_string()),
                        (None, true) => ("#x", "#x".to_string()),
                        (Some(capture), false) => ("./*", format!("./{capture}")),
                        (Some(capture), true) => ("#x/*", format!("#x/{capture}")),
                    };
                    // Keep the original target JSON, including property order.
                    let mapping = PackageExports::Map(vec![(key.into(), exports(&case.target))]);
                    let actual = if imports {
                        resolve_package_imports_target(package_dir, &request, &mapping, conditions)
                    } else {
                        resolve_package_exports(package_dir, &request, &mapping, conditions)
                            .map(ExportsTargetResolution::Found)
                    };
                    let context = format!("{} {conditions:?} imports={imports}", case.id);
                    match (&case.value, &case.error) {
                        (Some(file), None) => assert_eq!(
                            actual,
                            Ok(ExportsTargetResolution::Found(package_dir.join(file))),
                            "{context}"
                        ),
                        (None, Some(expected)) => {
                            let error = actual.expect_err(&context);
                            let expected = if expected == "excluded" {
                                if imports {
                                    "is not defined"
                                } else {
                                    "does not export"
                                }
                            } else {
                                expected.as_str()
                            };
                            assert!(error.contains(expected), "{context}: {error}");
                        }
                        _ => panic!("fixture must specify exactly one outcome: {context}"),
                    }
                }
            }
        }
    }

    #[test]
    fn pattern_segment_scan_is_bounded_and_decodes_only_once() {
        for value in [
            ".",
            "..",
            "node_modules",
            "NODE_MODULES",
            "%2E",
            "%2e%2E",
            "%6Eode_modules",
            "a%2f..%5cb",
            "a/./b",
            "a\\node_modules\\b",
            "a?ignored/../b",
            "a#ignored/node_modules/b",
            "node_modules\\other_text_too_long",
        ] {
            assert!(has_forbidden_package_segment(value), "{value}");
        }
        for value in [
            "",
            "...",
            "..cjs",
            "a..",
            "node_modules_extra",
            "not_node_modules",
            "%252e%252e",
            "%256eode_modules",
            "%",
            "%ff",
            "%zz",
            "a%2fb",
            "a?x=node_modules",
            "a#node_modules",
        ] {
            assert!(!has_forbidden_package_segment(value), "{value}");
        }
        let long = "x".repeat(16_384);
        assert!(!has_forbidden_package_segment(&long));
        assert!(!has_forbidden_package_segment(&format!("node_modules{long}")));
        assert!(has_forbidden_package_segment(&format!(
            "{long}/node_modules"
        )));
        assert!(!has_forbidden_package_segment(&format!("{long}/..cjs")));
    }

    #[test]
    fn substituted_escape_cannot_escape_the_package_or_select_a_fallback() {
        // Node's literal-target validation does not catch traversal assembled
        // across a percent escape and '*'. Keep this engine's existing strict
        // decoded containment, now fatal rather than selecting another module.
        // This is a containment regression, not a Node-equivalence fixture.
        for target in ["./%*", "./%2*", "./%6*", "./node_*", "./pre/*"] {
            let capture = match target {
                "./%*" => "2e%2e/outside.cjs",
                "./%2*" => "e/outside.cjs",
                "./%6*" => "eode_modules/outside.cjs",
                "./node_*" => "modules/outside.cjs",
                _ => "../outside.cjs",
            };
            let alternatives = PackageExports::Alternatives(vec![
                PackageExports::Target(target.into()),
                PackageExports::Target("./fallback.cjs".into()),
            ]);
            for conditions in [REQUIRE_EXPORT_CONDITIONS, IMPORT_EXPORT_CONDITIONS] {
                for imports in [false, true] {
                    let error = resolve_package_target(
                        Path::new("/pkg"),
                        &alternatives,
                        Some(capture),
                        imports,
                        conditions,
                    )
                    .expect_err("cannot hide an invalid subpath behind fallback");
                    assert!(
                        matches!(error, PackageTargetError::Specifier(_)),
                        "{target}: {error}"
                    );
                }
            }
        }
    }

    #[test]
    fn manifest_json_fixtures_select_the_node_reference_files() {
        #[derive(Deserialize)]
        struct Case {
            id: String,
            manifest: String,
            specifier: String,
            require: String,
            import: String,
        }
        let cases: Vec<Case> = serde_json::from_str(include_str!(
            "../../tests/fixtures/package_manifest_json.json"
        ))
        .expect("shared Node reference fixtures");
        assert_eq!(cases.len(), 12);
        for case in cases {
            let root = tempfile::tempdir().expect("module root");
            let directory = root.path().join("node_modules/pkg");
            write_package_fixture(root.path(), "node_modules/pkg/package.json", &case.manifest);
            for name in ["first.cjs", "last.cjs", "require.cjs", "import.cjs", "index.js"] {
                write_package_fixture(&directory, name, "module.exports = 1;");
            }
            let mut core = package_test_core(root.path());
            core.current_module_specifier = Some(directory.join("probe.cjs").display().to_string());
            for (conditions, mode, expected) in [
                (REQUIRE_EXPORT_CONDITIONS, PackageLookupMode::CommonJs, &case.require),
                (IMPORT_EXPORT_CONDITIONS, PackageLookupMode::PackageUrl, &case.import),
            ] {
                let actual = core
                    .resolve_bare_package_specifier(&case.specifier, conditions, mode)
                    .unwrap_or_else(|error| panic!("{} {conditions:?}: {error}", case.id));
                assert_eq!(
                    actual.canonicalize().expect("resolved file"),
                    directory.join(expected).canonicalize().expect("expected file"),
                    "{} {conditions:?}",
                    case.id
                );
            }
        }
    }

    #[test]
    fn duplicate_mapping_keys_can_revoke_or_invalidate_an_earlier_target() {
        for last in ["null", "false", "5", "{}", "[]"] {
            let json = format!(r#"{{"node":"./first.cjs","node":{last}}}"#);
            assert!(resolve(&json, ".").is_err(), "{json}");
            let json = format!(r##"{{"#x":"./first.cjs","#x":{last}}}"##);
            assert!(import_target(&json, "#x").is_err(), "{json}");
        }
        let PackageExports::Map(entries) = exports(
            r#"{"node":"./old.cjs","default":"./fallback.cjs","node":"./new.cjs"}"#,
        ) else {
            panic!("ordered mapping");
        };
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], ("node".to_string(), PackageExports::Target("./new.cjs".into())));
        assert_eq!(entries[1].0, "default");
    }

    #[test]
    fn package_manifest_bom_does_not_relax_size_or_json_validation() {
        let root = tempfile::tempdir().expect("module root");
        let mut bounded = "\u{feff}{}".to_string();
        bounded.push_str(&" ".repeat(MAX_PACKAGE_MANIFEST_BYTES as usize - bounded.len()));
        write_package_fixture(root.path(), "bounded/package.json", &bounded);
        read_package_manifest(&root.path().join("bounded")).expect("one BOM within byte cap");
        bounded.push(' ');
        write_package_fixture(root.path(), "oversize/package.json", &bounded);
        assert!(
            read_package_manifest(&root.path().join("oversize"))
                .expect_err("BOM bytes count against the original cap")
                .contains("exceeds")
        );
        for (index, source) in ["\u{feff}\u{feff}{}", " \u{feff}{}", "\u{feff}{", "\u{feff}{}x"]
            .iter()
            .enumerate()
        {
            let name = format!("invalid-{index}");
            write_package_fixture(root.path(), &format!("{name}/package.json"), source);
            assert!(read_package_manifest(&root.path().join(name)).is_err(), "{source:?}");
        }
    }

    fn resolve(json: &str, subpath: &str) -> Result<PathBuf, String> {
        resolve_package_exports(
            Path::new("/pkg"),
            subpath,
            &exports(json),
            REQUIRE_EXPORT_CONDITIONS,
        )
    }

    #[test]
    fn exports_conditions_follow_document_order_not_key_order() {
        // Sorted, "default" would precede "require"; Node honours the author's order.
        assert_eq!(
            resolve(r#"{"require": "./r.js", "default": "./d.js"}"#, "."),
            Ok(PathBuf::from("/pkg/r.js"))
        );
        assert_eq!(
            resolve(r#"{"default": "./d.js", "require": "./r.js"}"#, "."),
            Ok(PathBuf::from("/pkg/d.js"))
        );
        assert_eq!(
            resolve(
                r#"{"import": "./i.mjs", "node": {"require": "./n.js"}}"#,
                "."
            ),
            Ok(PathBuf::from("/pkg/n.js"))
        );
    }

    #[test]
    fn exports_subpaths_patterns_and_exclusions() {
        let map = r#"{
            ".": "./main.js",
            "./feature": {"require": "./feature.cjs"},
            "./utils/*": "./src/utils/*.js",
            "./utils/private/*": null
        }"#;
        assert_eq!(resolve(map, "."), Ok(PathBuf::from("/pkg/main.js")));
        assert_eq!(
            resolve(map, "./feature"),
            Ok(PathBuf::from("/pkg/feature.cjs"))
        );
        assert_eq!(
            resolve(map, "./utils/strings"),
            Ok(PathBuf::from("/pkg/src/utils/strings.js"))
        );
        // The longer pattern base wins, and its null excludes the subpath.
        assert!(resolve(map, "./utils/private/key").is_err());
        // A file that exists but is not exported stays unreachable.
        assert!(resolve(map, "./main.js").is_err());
        // A string or conditions object exports only ".".
        assert!(resolve(r#""./main.js""#, "./other").is_err());
    }

    #[test]
    fn exports_targets_cannot_leave_the_package() {
        assert!(resolve(r#"{".": "../escape.js"}"#, ".").is_err());
        assert!(resolve(r#"{"./*": "./*.js"}"#, "./../escape").is_err());
        assert!(resolve(r#"{"./*": "./*.js"}"#, "./node_modules/x").is_err());
        assert!(resolve(r#"{".": "./lib/", "./x": 5}"#, "./x").is_err());
    }

    #[test]
    fn exports_alternatives_take_the_first_valid_target() {
        assert_eq!(
            resolve(r#"{".": ["bad-no-dot-slash", "./ok.js"]}"#, "."),
            Ok(PathBuf::from("/pkg/ok.js"))
        );
        assert!(resolve(r#"{".": ["bad"]}"#, ".").is_err());
    }

    #[test]
    fn mixed_subpath_and_condition_keys_are_refused() {
        assert!(resolve(r#"{".": "./a.js", "require": "./b.js"}"#, ".").is_err());
    }

    #[test]
    fn package_specifiers_split_into_name_and_subpath() {
        assert_eq!(split_package_specifier("lodash"), Some(("lodash", "")));
        assert_eq!(
            split_package_specifier("lodash/fp"),
            Some(("lodash", "/fp"))
        );
        assert_eq!(
            split_package_specifier("@scope/pkg"),
            Some(("@scope/pkg", ""))
        );
        assert_eq!(
            split_package_specifier("@scope/pkg/deep/file"),
            Some(("@scope/pkg", "/deep/file"))
        );
        assert_eq!(split_package_specifier("@scope"), None);
        assert_eq!(split_package_specifier("@scope/"), None);
        assert_eq!(split_package_specifier(".hidden"), None);
        assert_eq!(split_package_specifier("bad%name"), None);
    }

    #[test]
    fn json_module_source_escapes_line_separators() {
        let source =
            InterpreterCore::json_module_source("\u{feff}{\"a\":\"x\u{2028}y\"}").expect("source");
        assert_eq!(
            source,
            "module.exports = JSON.parse(\"{\\\"a\\\":\\\"x\\u2028y\\\"}\");\n"
        );
    }

    fn import_target(json: &str, specifier: &str) -> Result<ExportsTargetResolution, String> {
        resolve_package_imports_target(
            Path::new("/pkg"),
            specifier,
            &exports(json),
            REQUIRE_EXPORT_CONDITIONS,
        )
    }

    #[test]
    fn imports_select_exact_keys_and_most_specific_patterns() {
        let map = r##"{
            "#x/*": "./general/*.cjs",
            "#x/*.json": "./data/*.json",
            "#x/special/*": "./special/*.cjs",
            "#x/exact": "./exact.cjs",
            "#x/private/*": null
        }"##;
        for (request, target) in [
            ("#x/exact", "/pkg/exact.cjs"),
            ("#x/a.json", "/pkg/data/a.json"),
            ("#x/special/a", "/pkg/special/a.cjs"),
            ("#x/a", "/pkg/general/a.cjs"),
        ] {
            assert_eq!(
                import_target(map, request),
                Ok(ExportsTargetResolution::Found(target.into()))
            );
        }
        assert!(import_target(map, "#x/private/secret").is_err());
        assert!(import_target(map, "#missing").is_err());
    }

    #[test]
    fn imports_conditions_and_array_alternatives_share_exports_semantics() {
        assert_eq!(
            import_target(
                r##"{"#x":{"default":"./first.cjs","require":"./second.cjs"}}"##,
                "#x"
            ),
            Ok(ExportsTargetResolution::Found("/pkg/first.cjs".into()))
        );
        assert_eq!(
            import_target(
                r##"{"#x":[null,"../invalid",{"browser":"./wrong.cjs"},{"node":{"require":"./right.cjs"}}]}"##,
                "#x"
            ),
            Ok(ExportsTargetResolution::Found("/pkg/right.cjs".into()))
        );
        assert_eq!(
            resolve(r#"[null,"./right.cjs"]"#, "."),
            Ok("/pkg/right.cjs".into())
        );
        assert!(import_target(r##"{"#x":[]}"##, "#x").is_err());
        assert!(import_target(r##"{"#x":{"browser":"./wrong.cjs"}}"##, "#x").is_err());
    }

    #[test]
    fn only_imports_can_select_external_package_targets() {
        assert_eq!(
            import_target(r##"{"#dep/*":"@scope/dependency/*"}"##, "#dep/feature"),
            Ok(ExportsTargetResolution::Package(
                "@scope/dependency/feature".to_string()
            ))
        );
        // Target selection does not examine the filesystem or try fallbacks
        // after selecting a syntactically valid but possibly absent package.
        assert_eq!(
            import_target(r##"{"#dep":["missing-package","./fallback.cjs"]}"##, "#dep"),
            Ok(ExportsTargetResolution::Package(
                "missing-package".to_string()
            ))
        );
        assert!(resolve(r#""@scope/dependency/feature""#, ".").is_err());
        assert!(import_target(r##"{"#x":"node:path"}"##, "#x").is_err());
    }

    #[test]
    fn package_url_paths_decode_once_and_drop_query_and_fragment() {
        for (url_path, file) in [
            ("lib/%76alue.cjs?query#fragment", "/pkg/lib/value.cjs"),
            ("lib/%C3%A9.cjs", "/pkg/lib/é.cjs"),
            ("lib/%252e.cjs", "/pkg/lib/%2e.cjs"),
            ("lib/a%23b.cjs", "/pkg/lib/a#b.cjs"),
        ] {
            assert_eq!(
                package_relative_target(Path::new("/pkg"), url_path),
                Ok(file.into())
            );
        }
    }

    #[test]
    fn package_url_targets_refuse_encoded_traversal_separators_and_invalid_utf8() {
        for target in [
            "../escape.cjs",
            "%2e%2e/escape.cjs",
            ".%2e/escape.cjs",
            "%2e./escape.cjs",
            "node_modules/x.cjs",
            "%6eode_modules/x.cjs",
            "x%2fy.cjs",
            "x%5cy.cjs",
            "x\\y.cjs",
            "%ff.cjs",
            "%00.cjs",
            "%zz.cjs",
            "%",
            "",
        ] {
            assert!(
                package_relative_target(Path::new("/pkg"), target).is_err(),
                "{target}"
            );
        }
        assert!(import_target(r##"{"#x":"../escape.cjs"}"##, "#x").is_err());
        assert!(import_target(r##"{"#x":"file:///tmp/escape.cjs"}"##, "#x").is_err());
    }

    #[test]
    fn invalid_private_names_and_non_object_maps_cannot_select_targets() {
        for request in ["#", "#/x", "#x/"] {
            assert!(import_target(r##"{"#*":"./*.cjs"}"##, request).is_err());
        }
        for map in ["null", "5", r#""./value.cjs""#, "[]"] {
            assert!(import_target(map, "#x").is_err());
        }
    }
}
