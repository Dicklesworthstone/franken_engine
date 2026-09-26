//! Node's CommonJS package resolution for bare `require` specifiers
//! (bd-4dme3): the `node_modules` walk-up inside the module root, package.json
//! `exports` (subpaths, `*` patterns, and the `node`/`require`/`default`
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

/// Conditions a CommonJS `require` matches in an `exports` map. `default`
/// always matches as well.
const REQUIRE_EXPORT_CONDITIONS: &[&str] = &["node", "require"];

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
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    entries.push(entry);
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
    main: Option<serde_json::Value>,
    #[serde(default)]
    exports: Option<PackageExports>,
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
enum ExportsTargetResolution {
    Found(PathBuf),
    Excluded,
    NoMatch,
}

fn read_package_manifest(dir: &Path) -> Result<Option<PackageManifest>, String> {
    let path = dir.join("package.json");
    if !path.is_file() {
        return Ok(None);
    }
    let file = fs::File::open(&path)
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
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("invalid {}: {error}", path.display()))
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

/// Node's PACKAGE_EXPORTS_RESOLVE for a CommonJS `require`: map `subpath`
/// (`.` or `./x`) through `exports` to a path inside `package_dir`.
fn resolve_package_exports(
    package_dir: &Path,
    subpath: &str,
    exports: &PackageExports,
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
        Some(entries) => {
            let exact = entries
                .iter()
                .find(|(key, _)| key == subpath && !key.contains('*'));
            if let Some((_, target)) = exact {
                (target, None)
            } else {
                let mut best: Option<(&str, &PackageExports, &str)> = None;
                for (key, target) in entries {
                    let Some(star) = key.find('*') else {
                        continue;
                    };
                    let (prefix, suffix) = (&key[..star], &key[star + 1..]);
                    if suffix.contains('*')
                        || !subpath.starts_with(prefix)
                        || subpath == prefix
                        || !(suffix.is_empty()
                            || (subpath.ends_with(suffix) && subpath.len() >= key.len()))
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
                let Some((_, target, pattern_match)) = best else {
                    return Err(not_exported());
                };
                (target, Some(pattern_match))
            }
        }
    };
    match resolve_package_target(package_dir, target, pattern_match)? {
        ExportsTargetResolution::Found(path) => Ok(path),
        ExportsTargetResolution::Excluded | ExportsTargetResolution::NoMatch => Err(not_exported()),
    }
}

/// Node's PACKAGE_TARGET_RESOLVE with the CommonJS conditions.
fn resolve_package_target(
    package_dir: &Path,
    target: &PackageExports,
    pattern_match: Option<&str>,
) -> Result<ExportsTargetResolution, String> {
    match target {
        PackageExports::Target(target) => {
            let Some(relative) = target.strip_prefix("./") else {
                return Err(format!(
                    "has an \"exports\" target `{target}` that does not start with \"./\""
                ));
            };
            let expanded = match pattern_match {
                Some(pattern_match) => relative.replace('*', pattern_match),
                None => relative.to_string(),
            };
            if expanded.split(['/', '\\']).any(|segment| {
                segment.is_empty()
                    || segment == "."
                    || segment == ".."
                    || segment.eq_ignore_ascii_case("node_modules")
            }) {
                return Err(format!(
                    "has an \"exports\" target `./{expanded}` that leaves the package"
                ));
            }
            Ok(ExportsTargetResolution::Found(package_dir.join(expanded)))
        }
        PackageExports::Null => Ok(ExportsTargetResolution::Excluded),
        PackageExports::Invalid => Err("has an invalid \"exports\" target".to_string()),
        PackageExports::Map(conditions) => {
            for (condition, value) in conditions {
                if condition != "default"
                    && !REQUIRE_EXPORT_CONDITIONS.contains(&condition.as_str())
                {
                    continue;
                }
                match resolve_package_target(package_dir, value, pattern_match)? {
                    ExportsTargetResolution::NoMatch => continue,
                    resolved => return Ok(resolved),
                }
            }
            Ok(ExportsTargetResolution::NoMatch)
        }
        PackageExports::Alternatives(alternatives) => {
            let mut last_error = None;
            for alternative in alternatives {
                match resolve_package_target(package_dir, alternative, pattern_match) {
                    Ok(ExportsTargetResolution::NoMatch) => {}
                    Ok(resolved) => return Ok(resolved),
                    Err(error) => last_error = Some(error),
                }
            }
            last_error.map_or(Ok(ExportsTargetResolution::Excluded), Err)
        }
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

impl InterpreterCore {
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
        let Some((name, subpath)) = split_package_specifier(specifier) else {
            return Err(failed(ModuleResolutionFailureReason::MalformedSpecifier));
        };
        let start = self
            .current_module_specifier
            .as_deref()
            .and_then(|label| Path::new(label).parent())
            .and_then(|dir| dir.canonicalize().ok())
            .filter(|dir| dir.starts_with(&root))
            .unwrap_or_else(|| root.clone());
        for dir in start.ancestors() {
            if !dir.starts_with(&root) {
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
            let manifest = read_package_manifest(&package_dir)
                .map_err(|reason| failed(ModuleResolutionFailureReason::Other(reason)))?;
            if let Some(exports) = manifest
                .as_ref()
                .and_then(|manifest| manifest.exports.as_ref())
            {
                let target = resolve_package_exports(&package_dir, &format!(".{subpath}"), exports)
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
            if let Some(found) = self
                .resolve_require_candidate(&modules_dir.join(specifier), specifier.ends_with('/'))
            {
                return Ok(found);
            }
        }
        Err(failed(ModuleResolutionFailureReason::ModuleNotFound))
    }

    /// Node's LOAD_AS_DIRECTORY step for a package.json `main`: the file it
    /// names (as given, or with `.js`/`.json` appended), else that path's
    /// `index.js`/`index.json`. `None` when the directory declares no usable
    /// `main`, so the caller falls back to the directory's own index.
    pub(super) fn resolve_package_main(directory: &Path) -> Option<PathBuf> {
        let manifest = read_package_manifest(directory).ok().flatten()?;
        let main = directory.join(manifest.main()?);
        if main.is_file() {
            return Some(main);
        }
        ["js", "json"]
            .into_iter()
            .map(|extension| with_appended_extension(&main, extension))
            .chain(["index.js", "index.json"].map(|index| main.join(index)))
            .find(|candidate| candidate.is_file())
    }

    /// Node loads a required `.json` file as a module whose `exports` is the
    /// parsed value. It is evaluated as `module.exports = JSON.parse(<text>)`
    /// so the engine's own `JSON.parse` defines that value, and invalid JSON
    /// throws the same `SyntaxError` it would there.
    pub(super) fn json_module_source(text: &str) -> Result<String, InterpreterError> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let literal =
            serde_json::to_string(text).map_err(|error| InterpreterError::InternalError {
                details: format!("failed to encode a JSON module as a string literal: {error}"),
            })?;
        // JSON leaves U+2028/U+2029 unescaped; escape them so the literal is
        // valid for any ECMAScript parser.
        let literal = literal
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029");
        Ok(format!("module.exports = JSON.parse({literal});\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exports(json: &str) -> PackageExports {
        serde_json::from_str(json).expect("exports JSON")
    }

    fn resolve(json: &str, subpath: &str) -> Result<PathBuf, String> {
        resolve_package_exports(Path::new("/pkg"), subpath, &exports(json))
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
}
