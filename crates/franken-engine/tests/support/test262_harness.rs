use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use frankenengine_engine::{
    HybridRouter, JsEngine, QuickJsInspiredNativeEngine, V8InspiredNativeEngine,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Test262HarnessLane {
    QuickJs,
    V8,
    Hybrid,
}

#[derive(Debug, Clone)]
pub struct Test262HarnessConfig {
    pub archive_path: PathBuf,
    pub extraction_root: PathBuf,
    pub selection_prefixes: Vec<String>,
    pub max_cases: Option<usize>,
    pub lane: Test262HarnessLane,
    pub skipped_flags: BTreeSet<String>,
}

impl Test262HarnessConfig {
    pub fn new(archive_path: impl Into<PathBuf>, extraction_root: impl Into<PathBuf>) -> Self {
        let mut skipped_flags = BTreeSet::new();
        skipped_flags.insert("async".to_string());
        skipped_flags.insert("module".to_string());
        Self {
            archive_path: archive_path.into(),
            extraction_root: extraction_root.into(),
            selection_prefixes: Vec::new(),
            max_cases: None,
            lane: Test262HarnessLane::QuickJs,
            skipped_flags,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Test262NegativeMetadata {
    pub phase: Option<String>,
    pub error_type: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Test262Metadata {
    pub description: Option<String>,
    pub esid: Option<String>,
    pub includes: Vec<String>,
    pub flags: Vec<String>,
    pub features: Vec<String>,
    pub negative: Option<Test262NegativeMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Test262Case {
    pub test_id: String,
    pub relative_path: PathBuf,
    pub metadata: Test262Metadata,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Test262Verdict {
    Pass,
    ExpectedFailure,
    UnexpectedPass,
    EngineError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Test262ExecutionResult {
    pub test_id: String,
    pub verdict: Test262Verdict,
    pub observed_value: Option<String>,
    pub error_class: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug)]
pub enum Test262HarnessError {
    Io(io::Error),
    UnsupportedArchive(PathBuf),
    ArchiveCommandFailed {
        archive_path: PathBuf,
        stderr: String,
    },
    MissingSuiteRoot(PathBuf),
    InvalidFrontmatter {
        test_path: PathBuf,
        message: String,
    },
}

impl fmt::Display for Test262HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::UnsupportedArchive(path) => {
                write!(f, "unsupported test262 archive format: {}", path.display())
            }
            Self::ArchiveCommandFailed {
                archive_path,
                stderr,
            } => write!(
                f,
                "failed to unpack {} with tar: {}",
                archive_path.display(),
                stderr.trim()
            ),
            Self::MissingSuiteRoot(path) => write!(
                f,
                "unable to locate extracted test262 suite root under {}",
                path.display()
            ),
            Self::InvalidFrontmatter { test_path, message } => {
                write!(
                    f,
                    "{}: invalid test262 frontmatter: {message}",
                    test_path.display()
                )
            }
        }
    }
}

impl std::error::Error for Test262HarnessError {}

impl From<io::Error> for Test262HarnessError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub struct Test262Harness {
    config: Test262HarnessConfig,
}

impl Test262Harness {
    pub fn new(config: Test262HarnessConfig) -> Self {
        Self { config }
    }

    pub fn discover_cases(&self) -> Result<Vec<Test262Case>, Test262HarnessError> {
        let suite_root = self.extract_suite_root()?;
        let tests_root = suite_root.join("test");
        let mut relative_paths = Vec::new();
        collect_js_paths(&tests_root, &tests_root, &mut relative_paths)?;
        relative_paths.sort();

        let mut cases = Vec::new();
        for relative_path in relative_paths {
            if !self.matches_selection_prefix(&relative_path) {
                continue;
            }
            let case = self.load_case(&suite_root, &relative_path)?;
            if case
                .metadata
                .flags
                .iter()
                .any(|flag| self.config.skipped_flags.contains(flag))
            {
                continue;
            }
            cases.push(case);
            if let Some(max_cases) = self.config.max_cases
                && cases.len() >= max_cases
            {
                break;
            }
        }
        Ok(cases)
    }

    pub fn execute_case(&self, case: &Test262Case) -> Test262ExecutionResult {
        let evaluation = match self.config.lane {
            Test262HarnessLane::QuickJs => {
                let mut engine = QuickJsInspiredNativeEngine;
                engine.eval(case.source.as_str())
            }
            Test262HarnessLane::V8 => {
                let mut engine = V8InspiredNativeEngine;
                engine.eval(case.source.as_str())
            }
            Test262HarnessLane::Hybrid => {
                let mut router = HybridRouter::default();
                router.eval(case.source.as_str())
            }
        };

        match evaluation {
            Ok(outcome) if case.metadata.negative.is_some() => Test262ExecutionResult {
                test_id: case.test_id.clone(),
                verdict: Test262Verdict::UnexpectedPass,
                observed_value: Some(outcome.value),
                error_class: None,
                error_code: None,
                error_message: None,
            },
            Ok(outcome) => Test262ExecutionResult {
                test_id: case.test_id.clone(),
                verdict: Test262Verdict::Pass,
                observed_value: Some(outcome.value),
                error_class: None,
                error_code: None,
                error_message: None,
            },
            Err(err) if case.metadata.negative.is_some() => Test262ExecutionResult {
                test_id: case.test_id.clone(),
                verdict: Test262Verdict::ExpectedFailure,
                observed_value: None,
                error_class: Some(err.class().stable_label().to_string()),
                error_code: Some(err.stable_namespace().to_string()),
                error_message: Some(err.message),
            },
            Err(err) => Test262ExecutionResult {
                test_id: case.test_id.clone(),
                verdict: Test262Verdict::EngineError,
                observed_value: None,
                error_class: Some(err.class().stable_label().to_string()),
                error_code: Some(err.stable_namespace().to_string()),
                error_message: Some(err.message),
            },
        }
    }

    fn matches_selection_prefix(&self, relative_path: &Path) -> bool {
        if self.config.selection_prefixes.is_empty() {
            return true;
        }
        let normalized = normalize_path(relative_path);
        self.config
            .selection_prefixes
            .iter()
            .any(|prefix| normalized.starts_with(prefix))
    }

    fn load_case(
        &self,
        suite_root: &Path,
        relative_path: &Path,
    ) -> Result<Test262Case, Test262HarnessError> {
        let absolute_path = suite_root.join("test").join(relative_path);
        let raw = fs::read_to_string(&absolute_path)?;
        let (metadata, body) = parse_test262_file(&raw).map_err(|message| {
            Test262HarnessError::InvalidFrontmatter {
                test_path: absolute_path.clone(),
                message,
            }
        })?;
        let source = compose_case_source(suite_root, &metadata, body.as_str())?;
        Ok(Test262Case {
            test_id: normalize_path(relative_path),
            relative_path: relative_path.to_path_buf(),
            metadata,
            source,
        })
    }

    fn extract_suite_root(&self) -> Result<PathBuf, Test262HarnessError> {
        let extraction_dir = self.extraction_cache_dir();
        if directory_is_empty(&extraction_dir)? {
            fs::create_dir_all(&extraction_dir)?;
            self.unpack_archive(&extraction_dir)?;
        }
        find_suite_root(&extraction_dir)
            .ok_or_else(|| Test262HarnessError::MissingSuiteRoot(extraction_dir.clone()))
    }

    fn extraction_cache_dir(&self) -> PathBuf {
        let file_name = self
            .config
            .archive_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("test262");
        self.config
            .extraction_root
            .join(format!("{}.extracted", sanitize_component(file_name)))
    }

    fn unpack_archive(&self, destination: &Path) -> Result<(), Test262HarnessError> {
        let mut command = Command::new("tar");
        if is_tar_gz(&self.config.archive_path) {
            command.arg("-xzf");
        } else if self
            .config
            .archive_path
            .extension()
            .and_then(|ext| ext.to_str())
            == Some("tar")
        {
            command.arg("-xf");
        } else {
            return Err(Test262HarnessError::UnsupportedArchive(
                self.config.archive_path.clone(),
            ));
        }
        let output = command
            .arg(&self.config.archive_path)
            .arg("-C")
            .arg(destination)
            .output()?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        Err(Test262HarnessError::ArchiveCommandFailed {
            archive_path: self.config.archive_path.clone(),
            stderr,
        })
    }
}

fn collect_js_paths(
    root: &Path,
    current: &Path,
    relative_paths: &mut Vec<PathBuf>,
) -> Result<(), Test262HarnessError> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_js_paths(root, &path, relative_paths)?;
        } else if file_type.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("js")
        {
            let relative = path
                .strip_prefix(root)
                .map(Path::to_path_buf)
                .map_err(|err| Test262HarnessError::Io(io::Error::other(err.to_string())))?;
            relative_paths.push(relative);
        }
    }
    Ok(())
}

fn directory_is_empty(path: &Path) -> io::Result<bool> {
    if !path.exists() {
        return Ok(true);
    }
    Ok(fs::read_dir(path)?.next().is_none())
}

fn find_suite_root(root: &Path) -> Option<PathBuf> {
    if root.join("test").is_dir() && root.join("harness").is_dir() {
        return Some(root.to_path_buf());
    }
    for entry in fs::read_dir(root).ok()? {
        let entry = entry.ok()?;
        let path = entry.path();
        if entry.file_type().ok()?.is_dir()
            && let Some(found) = find_suite_root(&path)
        {
            return Some(found);
        }
    }
    None
}

fn compose_case_source(
    suite_root: &Path,
    metadata: &Test262Metadata,
    body: &str,
) -> Result<String, Test262HarnessError> {
    let mut source = String::new();
    let harness_root = suite_root.join("harness");
    for include in &metadata.includes {
        let include_path = harness_root.join(include);
        let include_source = fs::read_to_string(&include_path)?;
        source.push_str(include_source.trim_end());
        source.push('\n');
    }
    if metadata.flags.iter().any(|flag| flag == "onlyStrict")
        && !metadata.flags.iter().any(|flag| flag == "raw")
        && !body.contains("\"use strict\"")
        && !body.contains("'use strict'")
    {
        source.push_str("\"use strict\";\n");
    }
    source.push_str(body.trim());
    source.push('\n');
    Ok(source)
}

fn parse_test262_file(content: &str) -> Result<(Test262Metadata, String), String> {
    let trimmed = content.trim_start_matches('\u{feff}');
    let Some(frontmatter) = trimmed.strip_prefix("/*---") else {
        return Ok((Test262Metadata::default(), trimmed.to_string()));
    };
    let Some(frontmatter_end) = frontmatter.find("---*/") else {
        return Err("missing terminating ---*/ marker".to_string());
    };
    let metadata_block = &frontmatter[..frontmatter_end];
    let body = &frontmatter[frontmatter_end + 5..];
    Ok((parse_frontmatter(metadata_block)?, body.trim().to_string()))
}

fn parse_frontmatter(block: &str) -> Result<Test262Metadata, String> {
    let mut metadata = Test262Metadata::default();
    let lines: Vec<&str> = block.lines().collect();
    let mut idx = 0usize;
    while idx < lines.len() {
        let trimmed = lines[idx].trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            idx += 1;
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("description:") {
            metadata.description = Some(strip_yaml_scalar(value));
            idx += 1;
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("esid:") {
            metadata.esid = Some(strip_yaml_scalar(value));
            idx += 1;
            continue;
        }
        if trimmed.starts_with("includes:") {
            let (values, next_idx) = parse_yaml_list(&lines, idx, "includes:")?;
            metadata.includes = values;
            idx = next_idx;
            continue;
        }
        if trimmed.starts_with("flags:") {
            let (values, next_idx) = parse_yaml_list(&lines, idx, "flags:")?;
            metadata.flags = values;
            idx = next_idx;
            continue;
        }
        if trimmed.starts_with("features:") {
            let (values, next_idx) = parse_yaml_list(&lines, idx, "features:")?;
            metadata.features = values;
            idx = next_idx;
            continue;
        }
        if trimmed == "negative:" {
            let (negative, next_idx) = parse_negative_block(&lines, idx)?;
            metadata.negative = Some(negative);
            idx = next_idx;
            continue;
        }
        idx += 1;
    }
    Ok(metadata)
}

fn parse_yaml_list(
    lines: &[&str],
    start_idx: usize,
    key: &str,
) -> Result<(Vec<String>, usize), String> {
    let raw = lines[start_idx].trim();
    let inline = raw
        .strip_prefix(key)
        .ok_or_else(|| format!("expected {key} list"))?
        .trim();
    if !inline.is_empty() {
        return Ok((parse_inline_list(inline), start_idx + 1));
    }

    let parent_indent = leading_whitespace(lines[start_idx]);
    let mut values = Vec::new();
    let mut idx = start_idx + 1;
    while idx < lines.len() {
        let raw_line = lines[idx];
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            idx += 1;
            continue;
        }
        if leading_whitespace(raw_line) <= parent_indent {
            break;
        }
        if let Some(item) = trimmed.strip_prefix("- ") {
            values.push(strip_yaml_scalar(item));
            idx += 1;
            continue;
        }
        return Err(format!("unsupported list item syntax: {trimmed}"));
    }
    Ok((values, idx))
}

fn parse_negative_block(
    lines: &[&str],
    start_idx: usize,
) -> Result<(Test262NegativeMetadata, usize), String> {
    let parent_indent = leading_whitespace(lines[start_idx]);
    let mut negative = Test262NegativeMetadata::default();
    let mut idx = start_idx + 1;
    while idx < lines.len() {
        let raw_line = lines[idx];
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            idx += 1;
            continue;
        }
        if leading_whitespace(raw_line) <= parent_indent {
            break;
        }
        if let Some(value) = trimmed.strip_prefix("phase:") {
            negative.phase = Some(strip_yaml_scalar(value));
            idx += 1;
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("type:") {
            negative.error_type = Some(strip_yaml_scalar(value));
            idx += 1;
            continue;
        }
        return Err(format!("unsupported negative metadata entry: {trimmed}"));
    }
    Ok((negative, idx))
}

fn parse_inline_list(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    let Some(list) = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    else {
        return vec![strip_yaml_scalar(trimmed)];
    };
    list.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(strip_yaml_scalar)
        .collect()
}

fn strip_yaml_scalar(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        return trimmed[1..trimmed.len() - 1].to_string();
    }
    trimmed.to_string()
}

fn leading_whitespace(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn sanitize_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn is_tar_gz(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    name.ends_with(".tar.gz") || name.ends_with(".tgz")
}

#[cfg(test)]
mod tests {
    use super::{parse_frontmatter, parse_test262_file, parse_yaml_list};

    #[test]
    fn parse_test262_file_reads_block_list_metadata() {
        let content = r#"/*---
description: synthetic helper-backed addition test
includes:
  - helper.js
flags: [onlyStrict]
negative:
  phase: runtime
  type: Test262Error
---*/
helperAdd(1, 2);
"#;

        let (metadata, body) = parse_test262_file(content).expect("parse synthetic frontmatter");

        assert_eq!(
            metadata.description.as_deref(),
            Some("synthetic helper-backed addition test")
        );
        assert_eq!(metadata.includes, vec!["helper.js"]);
        assert_eq!(metadata.flags, vec!["onlyStrict"]);
        let negative = metadata.negative.expect("negative metadata");
        assert_eq!(negative.phase.as_deref(), Some("runtime"));
        assert_eq!(negative.error_type.as_deref(), Some("Test262Error"));
        assert_eq!(body, "helperAdd(1, 2);");
    }

    #[test]
    fn parse_frontmatter_reads_block_list_metadata() {
        let block = r#"
description: synthetic helper-backed addition test
includes:
  - helper.js
flags: [onlyStrict]
"#;
        let lines: Vec<&str> = block.lines().collect();

        let (includes, next_idx) = parse_yaml_list(&lines, 2, "includes:").expect("parse includes");
        assert_eq!(includes, vec!["helper.js"]);
        assert_eq!(next_idx, 4);

        let metadata = parse_frontmatter(block).expect("parse frontmatter");
        assert_eq!(metadata.includes, vec!["helper.js"]);
        assert_eq!(metadata.flags, vec!["onlyStrict"]);
    }
}
