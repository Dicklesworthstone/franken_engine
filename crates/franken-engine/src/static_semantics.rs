//! ES2020 static-semantics enforcement (early errors, scope resolution, binding validation).
//!
//! This module validates an AST (IR0 `SyntaxTree`) before lowering to IR1.
//! It catches early errors per the ES2020 spec and builds the scope/binding
//! resolution map that feeds into IR1 `SpecIR`.
//!
//! # Covered checks
//!
//! - Duplicate `let`/`const` bindings in the same scope
//! - `const` declarations without initializer
//! - `import`/`export` only in module goal
//! - `import`/`export` not nested inside non-top-level contexts
//! - Duplicate `export` names
//! - `await` outside async context
//! - TDZ violations for `let`/`const` (use-before-declare detection)
//! - Name collision between `let`/`const` and `var` in same scope
//! - Empty declarator list
//! - Strict-mode reserved words used as bindings

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::ast::{
    ExportKind, Expression, ParseGoal, SourceSpan, Statement, SyntaxTree, VariableDeclaration,
    VariableDeclarationKind,
};
use crate::deterministic_serde::CanonicalValue;
use crate::ir_contract::{BindingId, BindingKind, ResolvedBinding, ScopeId, ScopeKind, ScopeNode};

// ---------------------------------------------------------------------------
// Contract constants
// ---------------------------------------------------------------------------

/// Schema version for static-semantics analysis artifacts.
pub const STATIC_SEMANTICS_CONTRACT_VERSION: &str = "franken-engine.static-semantics.contract.v1";

/// Bead reference for this module.
pub const STATIC_SEMANTICS_BEAD_ID: &str = "bd-1lsy.2.2";

/// Component identifier for structured logging.
pub const STATIC_SEMANTICS_COMPONENT: &str = "static_semantics";

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Classification of static-semantic errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StaticErrorKind {
    /// Duplicate `let`/`const` binding in same scope.
    DuplicateBinding,
    /// `const` declaration with no initializer.
    ConstWithoutInitializer,
    /// `import` statement in Script goal.
    ImportInScript,
    /// `export` statement in Script goal.
    ExportInScript,
    /// Duplicate export name.
    DuplicateExport,
    /// `await` expression outside async context.
    AwaitOutsideAsync,
    /// Reference to a `let`/`const` binding before its declaration (TDZ).
    TemporalDeadZone,
    /// Collision between `let`/`const` and `var` binding with same name.
    LexicalVarCollision,
    /// Empty declarator list in variable declaration.
    EmptyDeclaratorList,
    /// Reserved word used as binding name in strict mode.
    ReservedWordBinding,
    /// Redeclaration of an import binding.
    ImportRedeclaration,
    /// Assignment to a `const` binding.
    AssignmentToConst,
    /// `return` statement outside a function body.
    ReturnOutsideFunction,
    /// `break` statement outside a loop or switch.
    BreakOutsideLoop,
    /// `continue` statement outside a loop.
    ContinueOutsideLoop,
    /// Duplicate parameter name in strict-mode function.
    DuplicateParameter,
    /// `delete` applied to an identifier in strict mode.
    DeleteOfIdentifier,
    /// `eval` or `arguments` used as binding name in strict mode.
    EvalArgumentsBinding,
    /// `for-in` initializer in strict mode (`for (var x = 1 in ...)` is invalid).
    ForInInitializer,
    /// Duplicate binding name in destructuring pattern.
    DuplicateDestructuringBinding,
}

impl StaticErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateBinding => "duplicate_binding",
            Self::ConstWithoutInitializer => "const_without_initializer",
            Self::ImportInScript => "import_in_script",
            Self::ExportInScript => "export_in_script",
            Self::DuplicateExport => "duplicate_export",
            Self::AwaitOutsideAsync => "await_outside_async",
            Self::TemporalDeadZone => "temporal_dead_zone",
            Self::LexicalVarCollision => "lexical_var_collision",
            Self::EmptyDeclaratorList => "empty_declarator_list",
            Self::ReservedWordBinding => "reserved_word_binding",
            Self::ImportRedeclaration => "import_redeclaration",
            Self::AssignmentToConst => "assignment_to_const",
            Self::ReturnOutsideFunction => "return_outside_function",
            Self::BreakOutsideLoop => "break_outside_loop",
            Self::ContinueOutsideLoop => "continue_outside_loop",
            Self::DuplicateParameter => "duplicate_parameter",
            Self::DeleteOfIdentifier => "delete_of_identifier",
            Self::EvalArgumentsBinding => "eval_arguments_binding",
            Self::ForInInitializer => "for_in_initializer",
            Self::DuplicateDestructuringBinding => "duplicate_destructuring_binding",
        }
    }

    /// Stable diagnostic code for structured logging.
    pub fn diagnostic_code(self) -> &'static str {
        match self {
            Self::DuplicateBinding => "FE-STATIC-DIAG-DUP-BINDING-0001",
            Self::ConstWithoutInitializer => "FE-STATIC-DIAG-CONST-INIT-0002",
            Self::ImportInScript => "FE-STATIC-DIAG-IMPORT-SCRIPT-0003",
            Self::ExportInScript => "FE-STATIC-DIAG-EXPORT-SCRIPT-0004",
            Self::DuplicateExport => "FE-STATIC-DIAG-DUP-EXPORT-0005",
            Self::AwaitOutsideAsync => "FE-STATIC-DIAG-AWAIT-ASYNC-0006",
            Self::TemporalDeadZone => "FE-STATIC-DIAG-TDZ-0007",
            Self::LexicalVarCollision => "FE-STATIC-DIAG-LEX-VAR-0008",
            Self::EmptyDeclaratorList => "FE-STATIC-DIAG-EMPTY-DECL-0009",
            Self::ReservedWordBinding => "FE-STATIC-DIAG-RESERVED-0010",
            Self::ImportRedeclaration => "FE-STATIC-DIAG-IMPORT-REDECL-0011",
            Self::AssignmentToConst => "FE-STATIC-DIAG-ASSIGN-CONST-0012",
            Self::ReturnOutsideFunction => "FE-STATIC-DIAG-RETURN-OUTSIDE-0013",
            Self::BreakOutsideLoop => "FE-STATIC-DIAG-BREAK-OUTSIDE-0014",
            Self::ContinueOutsideLoop => "FE-STATIC-DIAG-CONTINUE-OUTSIDE-0015",
            Self::DuplicateParameter => "FE-STATIC-DIAG-DUP-PARAM-0016",
            Self::DeleteOfIdentifier => "FE-STATIC-DIAG-DELETE-IDENT-0017",
            Self::EvalArgumentsBinding => "FE-STATIC-DIAG-EVAL-ARGS-0018",
            Self::ForInInitializer => "FE-STATIC-DIAG-FOR-IN-INIT-0019",
            Self::DuplicateDestructuringBinding => "FE-STATIC-DIAG-DUP-DESTR-0020",
        }
    }
}

impl std::fmt::Display for StaticErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single static-semantic error with location and descriptive message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticError {
    pub kind: StaticErrorKind,
    pub message: String,
    pub span: SourceSpan,
}

impl StaticError {
    pub fn new(kind: StaticErrorKind, message: impl Into<String>, span: SourceSpan) -> Self {
        Self {
            kind,
            message: message.into(),
            span,
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "diagnostic_code".to_string(),
            CanonicalValue::String(self.kind.diagnostic_code().to_string()),
        );
        map.insert(
            "kind".to_string(),
            CanonicalValue::String(self.kind.as_str().to_string()),
        );
        map.insert(
            "message".to_string(),
            CanonicalValue::String(self.message.clone()),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

impl std::fmt::Display for StaticError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} (line {}:{})",
            self.kind.diagnostic_code(),
            self.message,
            self.span.start_line,
            self.span.start_column,
        )
    }
}

// ---------------------------------------------------------------------------
// Analysis output
// ---------------------------------------------------------------------------

/// Result of static-semantic analysis: scope tree + binding map + errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticAnalysisResult {
    /// Resolved scope tree (ready for IR1 consumption).
    pub scopes: Vec<ScopeNode>,
    /// All resolved bindings indexed by `BindingId`.
    pub bindings: Vec<ResolvedBinding>,
    /// Collected errors (empty means analysis passed).
    pub errors: Vec<StaticError>,
    /// Whether the tree was analyzed in module goal.
    pub is_module: bool,
}

impl StaticAnalysisResult {
    pub fn passed(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "bindings".to_string(),
            CanonicalValue::Array(
                self.bindings
                    .iter()
                    .map(ResolvedBinding::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "errors".to_string(),
            CanonicalValue::Array(
                self.errors
                    .iter()
                    .map(StaticError::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "is_module".to_string(),
            CanonicalValue::Bool(self.is_module),
        );
        map.insert(
            "scopes".to_string(),
            CanonicalValue::Array(self.scopes.iter().map(ScopeNode::canonical_value).collect()),
        );
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// Strict-mode reserved words
// ---------------------------------------------------------------------------

/// ES2020 strict-mode reserved words that cannot be used as binding names.
const STRICT_RESERVED_WORDS: &[&str] = &[
    "implements",
    "interface",
    "let",
    "package",
    "private",
    "protected",
    "public",
    "static",
    "yield",
];

/// ES2020 keywords that cannot appear as binding identifiers.
const KEYWORD_BINDINGS: &[&str] = &[
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "new",
    "null",
    "return",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
];

/// Extract individual exported names from a named export clause string.
///
/// The parser produces canonicalized clause strings like `{ a, b as c }`.
/// This function extracts the exported names (the "as" alias if present,
/// otherwise the local name). Returns an empty vec if the clause cannot
/// be parsed (falls back to whole-clause comparison).
fn extract_export_specifier_names(clause: &str) -> Vec<String> {
    let trimmed = clause.trim();
    let inner = match trimmed.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        Some(s) => s.trim(),
        None => return Vec::new(),
    };
    if inner.is_empty() {
        return Vec::new();
    }
    let mut names = Vec::new();
    for specifier in inner.split(',') {
        let specifier = specifier.trim();
        if specifier.is_empty() {
            continue;
        }
        // Handle `local as exported` form: the exported name is the alias.
        let parts: Vec<&str> = specifier.split_whitespace().collect();
        let exported_name = match parts.as_slice() {
            [local] => *local,
            [_local, "as", alias] => *alias,
            _ => specifier,
        };
        names.push(exported_name.to_string());
    }
    names
}

fn is_reserved_binding(name: &str, is_module: bool) -> bool {
    // Module code is always strict
    if is_module && STRICT_RESERVED_WORDS.contains(&name) {
        return true;
    }
    KEYWORD_BINDINGS.contains(&name)
}

// ---------------------------------------------------------------------------
// Analyzer state
// ---------------------------------------------------------------------------

struct AnalyzerState {
    scopes: Vec<ScopeNode>,
    bindings: Vec<ResolvedBinding>,
    errors: Vec<StaticError>,
    is_module: bool,
    next_binding_id: BindingId,
    next_scope_index: u32,
    /// Export names seen so far (for duplicate detection).
    export_names: BTreeSet<String>,
    /// Import bindings (name -> span) for redeclaration detection.
    import_bindings: BTreeMap<String, SourceSpan>,
    /// Names of `const` bindings in scope (for assignment-to-const detection).
    const_bindings: BTreeSet<String>,
    /// Whether we are currently inside a function body.
    in_function: bool,
    /// Whether we are currently inside a loop body.
    in_loop: bool,
    /// Whether we are currently inside a switch statement.
    in_switch: bool,
}

impl AnalyzerState {
    fn new(is_module: bool) -> Self {
        Self {
            scopes: Vec::new(),
            bindings: Vec::new(),
            errors: Vec::new(),
            is_module,
            next_binding_id: 0,
            next_scope_index: 0,
            export_names: BTreeSet::new(),
            import_bindings: BTreeMap::new(),
            const_bindings: BTreeSet::new(),
            in_function: false,
            in_loop: false,
            in_switch: false,
        }
    }

    fn alloc_binding_id(&mut self) -> BindingId {
        let id = self.next_binding_id;
        self.next_binding_id += 1;
        id
    }

    fn alloc_scope_id(&mut self, depth: u32) -> ScopeId {
        let id = ScopeId {
            depth,
            index: self.next_scope_index,
        };
        self.next_scope_index += 1;
        id
    }

    fn push_error(&mut self, kind: StaticErrorKind, message: impl Into<String>, span: SourceSpan) {
        self.errors.push(StaticError::new(kind, message, span));
    }
}

// ---------------------------------------------------------------------------
// Core analysis
// ---------------------------------------------------------------------------

/// Run static-semantic analysis on an IR0 syntax tree.
///
/// Returns a `StaticAnalysisResult` with scope tree, bindings, and any errors.
/// The caller should check `result.passed()` before proceeding to lowering.
pub fn analyze(tree: &SyntaxTree) -> StaticAnalysisResult {
    let is_module = tree.goal == ParseGoal::Module;
    let mut state = AnalyzerState::new(is_module);

    // Create top-level scope
    let top_scope_kind = if is_module {
        ScopeKind::Module
    } else {
        ScopeKind::Global
    };
    let top_scope_id = state.alloc_scope_id(0);

    // First pass: collect declarations in top scope
    let mut top_bindings: Vec<ResolvedBinding> = Vec::new();
    // Track names to detect duplicates
    let mut lexical_names: BTreeMap<String, SourceSpan> = BTreeMap::new();
    let mut var_names: BTreeMap<String, SourceSpan> = BTreeMap::new();

    for stmt in &tree.body {
        analyze_statement(
            &mut state,
            stmt,
            top_scope_id,
            &mut top_bindings,
            &mut lexical_names,
            &mut var_names,
        );
    }

    // Second pass: detect TDZ violations in expression statements
    let declared_before: BTreeSet<String> = BTreeSet::new();
    detect_tdz_violations(&mut state, &tree.body, &declared_before);

    let top_scope = ScopeNode {
        scope_id: top_scope_id,
        parent: None,
        kind: top_scope_kind,
        bindings: top_bindings.clone(),
    };
    state.scopes.push(top_scope);
    state.bindings.extend(top_bindings);

    StaticAnalysisResult {
        scopes: state.scopes,
        bindings: state.bindings,
        errors: state.errors,
        is_module,
    }
}

fn analyze_statement(
    state: &mut AnalyzerState,
    stmt: &Statement,
    scope_id: ScopeId,
    bindings: &mut Vec<ResolvedBinding>,
    lexical_names: &mut BTreeMap<String, SourceSpan>,
    var_names: &mut BTreeMap<String, SourceSpan>,
) {
    match stmt {
        Statement::Import(import) => {
            // Import only valid in Module goal
            if !state.is_module {
                state.push_error(
                    StaticErrorKind::ImportInScript,
                    "import declarations are only allowed in module code",
                    import.span.clone(),
                );
            }

            // Register import binding if present
            if let Some(ref binding_name) = import.binding {
                check_reserved(state, binding_name, &import.span);

                // Check for duplicate import binding
                if let Some(prev_span) = state.import_bindings.get(binding_name) {
                    state.push_error(
                        StaticErrorKind::ImportRedeclaration,
                        format!(
                            "import binding '{}' already declared at line {}",
                            binding_name, prev_span.start_line
                        ),
                        import.span.clone(),
                    );
                } else {
                    state
                        .import_bindings
                        .insert(binding_name.clone(), import.span.clone());
                }

                // Check for collision with lexical bindings
                if let Some(prev_span) = lexical_names.get(binding_name) {
                    state.push_error(
                        StaticErrorKind::DuplicateBinding,
                        format!(
                            "identifier '{}' already declared as lexical binding at line {}",
                            binding_name, prev_span.start_line
                        ),
                        import.span.clone(),
                    );
                } else {
                    lexical_names.insert(binding_name.clone(), import.span.clone());
                }

                let bid = state.alloc_binding_id();
                bindings.push(ResolvedBinding {
                    name: binding_name.clone(),
                    binding_id: bid,
                    scope: scope_id,
                    kind: BindingKind::Import,
                });
            }
        }

        Statement::Export(export) => {
            // Export only valid in Module goal
            if !state.is_module {
                state.push_error(
                    StaticErrorKind::ExportInScript,
                    "export declarations are only allowed in module code",
                    export.span.clone(),
                );
            }

            // Duplicate export name detection
            match &export.kind {
                ExportKind::Default(_) => {
                    let name = "default".to_string();
                    if !state.export_names.insert(name) {
                        state.push_error(
                            StaticErrorKind::DuplicateExport,
                            "duplicate default export",
                            export.span.clone(),
                        );
                    }
                }
                ExportKind::NamedClause(clause) => {
                    // Extract individual specifier names from the clause string.
                    // The clause is canonicalized from the parser as `{ a, b as c }`.
                    let specifier_names = extract_export_specifier_names(clause);
                    if specifier_names.is_empty() {
                        // Entire clause as single name (legacy or single-specifier).
                        if !state.export_names.insert(clause.clone()) {
                            state.push_error(
                                StaticErrorKind::DuplicateExport,
                                format!("duplicate export name '{}'", clause),
                                export.span.clone(),
                            );
                        }
                    } else {
                        for exported_name in &specifier_names {
                            if !state.export_names.insert(exported_name.clone()) {
                                state.push_error(
                                    StaticErrorKind::DuplicateExport,
                                    format!("duplicate export name '{}'", exported_name),
                                    export.span.clone(),
                                );
                            }
                        }
                    }
                }
            }

            // Check for await in export default expression
            if let ExportKind::Default(ref expr) = export.kind {
                check_await_in_expression(state, expr, &export.span);
            }
        }

        Statement::VariableDeclaration(decl) => {
            analyze_variable_declaration(state, decl, scope_id, bindings, lexical_names, var_names);
        }

        Statement::Expression(expr_stmt) => {
            check_await_in_expression(state, &expr_stmt.expression, &expr_stmt.span);
        }

        Statement::Block(block) => {
            let block_scope_id = state.alloc_scope_id(scope_id.depth + 1);
            let mut block_bindings: Vec<ResolvedBinding> = Vec::new();
            let mut block_lex: BTreeMap<String, SourceSpan> = BTreeMap::new();
            let mut block_var: BTreeMap<String, SourceSpan> = var_names.clone();
            for child in &block.body {
                analyze_statement(
                    state,
                    child,
                    block_scope_id,
                    &mut block_bindings,
                    &mut block_lex,
                    &mut block_var,
                );
            }
            let block_scope = ScopeNode {
                scope_id: block_scope_id,
                parent: Some(scope_id),
                kind: ScopeKind::Block,
                bindings: block_bindings.clone(),
            };
            state.scopes.push(block_scope);
            state.bindings.extend(block_bindings);
        }

        Statement::If(if_stmt) => {
            check_await_in_expression(state, &if_stmt.condition, &if_stmt.span);
            analyze_statement(
                state,
                &if_stmt.consequent,
                scope_id,
                bindings,
                lexical_names,
                var_names,
            );
            if let Some(ref alt) = if_stmt.alternate {
                analyze_statement(state, alt, scope_id, bindings, lexical_names, var_names);
            }
        }

        Statement::For(for_stmt) => {
            let for_scope_id = state.alloc_scope_id(scope_id.depth + 1);
            let mut for_bindings: Vec<ResolvedBinding> = Vec::new();
            let mut for_lex: BTreeMap<String, SourceSpan> = BTreeMap::new();
            let mut for_var: BTreeMap<String, SourceSpan> = var_names.clone();
            if let Some(ref init) = for_stmt.init {
                analyze_statement(
                    state,
                    init,
                    for_scope_id,
                    &mut for_bindings,
                    &mut for_lex,
                    &mut for_var,
                );
            }
            if let Some(ref cond) = for_stmt.condition {
                check_await_in_expression(state, cond, &for_stmt.span);
            }
            if let Some(ref update) = for_stmt.update {
                check_await_in_expression(state, update, &for_stmt.span);
            }
            let prev_in_loop = state.in_loop;
            state.in_loop = true;
            analyze_statement(
                state,
                &for_stmt.body,
                for_scope_id,
                &mut for_bindings,
                &mut for_lex,
                &mut for_var,
            );
            state.in_loop = prev_in_loop;
            let for_scope = ScopeNode {
                scope_id: for_scope_id,
                parent: Some(scope_id),
                kind: ScopeKind::Block,
                bindings: for_bindings.clone(),
            };
            state.scopes.push(for_scope);
            state.bindings.extend(for_bindings);
        }

        Statement::While(while_stmt) => {
            check_await_in_expression(state, &while_stmt.condition, &while_stmt.span);
            let prev_in_loop = state.in_loop;
            state.in_loop = true;
            analyze_statement(
                state,
                &while_stmt.body,
                scope_id,
                bindings,
                lexical_names,
                var_names,
            );
            state.in_loop = prev_in_loop;
        }

        Statement::DoWhile(do_while) => {
            let prev_in_loop = state.in_loop;
            state.in_loop = true;
            analyze_statement(
                state,
                &do_while.body,
                scope_id,
                bindings,
                lexical_names,
                var_names,
            );
            state.in_loop = prev_in_loop;
            check_await_in_expression(state, &do_while.condition, &do_while.span);
        }

        Statement::Return(ret) => {
            if !state.in_function {
                state.push_error(
                    StaticErrorKind::ReturnOutsideFunction,
                    "return statement is not allowed outside a function",
                    ret.span.clone(),
                );
            }
            if let Some(ref arg) = ret.argument {
                check_await_in_expression(state, arg, &ret.span);
            }
        }

        Statement::Throw(throw) => {
            check_await_in_expression(state, &throw.argument, &throw.span);
        }

        Statement::TryCatch(tc) => {
            for child in &tc.block.body {
                analyze_statement(state, child, scope_id, bindings, lexical_names, var_names);
            }
            if let Some(ref handler) = tc.handler {
                let catch_scope_id = state.alloc_scope_id(scope_id.depth + 1);
                let mut catch_bindings: Vec<ResolvedBinding> = Vec::new();
                let mut catch_lex: BTreeMap<String, SourceSpan> = BTreeMap::new();
                let mut catch_var: BTreeMap<String, SourceSpan> = var_names.clone();
                if let Some(ref param) = handler.parameter {
                    let bid = state.alloc_binding_id();
                    catch_bindings.push(ResolvedBinding {
                        name: param.clone(),
                        binding_id: bid,
                        scope: catch_scope_id,
                        kind: BindingKind::Let,
                    });
                    catch_lex.insert(param.clone(), handler.span.clone());
                }
                for child in &handler.body.body {
                    analyze_statement(
                        state,
                        child,
                        catch_scope_id,
                        &mut catch_bindings,
                        &mut catch_lex,
                        &mut catch_var,
                    );
                }
                let catch_scope = ScopeNode {
                    scope_id: catch_scope_id,
                    parent: Some(scope_id),
                    kind: ScopeKind::Block,
                    bindings: catch_bindings.clone(),
                };
                state.scopes.push(catch_scope);
                state.bindings.extend(catch_bindings);
            }
            if let Some(ref finalizer) = tc.finalizer {
                for child in &finalizer.body {
                    analyze_statement(state, child, scope_id, bindings, lexical_names, var_names);
                }
            }
        }

        Statement::Switch(sw) => {
            check_await_in_expression(state, &sw.discriminant, &sw.span);
            let prev_in_switch = state.in_switch;
            state.in_switch = true;
            for case in &sw.cases {
                if let Some(ref test) = case.test {
                    check_await_in_expression(state, test, &sw.span);
                }
                for child in &case.consequent {
                    analyze_statement(state, child, scope_id, bindings, lexical_names, var_names);
                }
            }
            state.in_switch = prev_in_switch;
        }

        Statement::Break(brk) => {
            if !state.in_loop && !state.in_switch {
                state.push_error(
                    StaticErrorKind::BreakOutsideLoop,
                    "break statement must be inside a loop or switch",
                    brk.span.clone(),
                );
            }
        }

        Statement::Continue(cont) => {
            if !state.in_loop {
                state.push_error(
                    StaticErrorKind::ContinueOutsideLoop,
                    "continue statement must be inside a loop",
                    cont.span.clone(),
                );
            }
        }

        Statement::FunctionDeclaration(func) => {
            if let Some(ref name) = func.name {
                check_reserved(state, name, &func.span);
                let bid = state.alloc_binding_id();
                bindings.push(ResolvedBinding {
                    name: name.clone(),
                    binding_id: bid,
                    scope: scope_id,
                    kind: BindingKind::Var,
                });
                if let Some(prev_span) = var_names.get(name) {
                    let _ = prev_span;
                }
                var_names.insert(name.clone(), func.span.clone());
            }
            let func_scope_id = state.alloc_scope_id(scope_id.depth + 1);
            let mut func_bindings: Vec<ResolvedBinding> = Vec::new();
            let mut func_lex: BTreeMap<String, SourceSpan> = BTreeMap::new();
            let mut func_var: BTreeMap<String, SourceSpan> = BTreeMap::new();
            let mut seen_params: BTreeSet<String> = BTreeSet::new();
            for param in &func.params {
                for bound_name in param.pattern.binding_names() {
                    check_reserved(state, bound_name, &param.span);
                    if !seen_params.insert(bound_name.to_string()) && state.is_module {
                        state.push_error(
                            StaticErrorKind::DuplicateParameter,
                            format!("duplicate parameter name '{}'", bound_name),
                            param.span.clone(),
                        );
                    }
                    let bid = state.alloc_binding_id();
                    func_bindings.push(ResolvedBinding {
                        name: bound_name.to_string(),
                        binding_id: bid,
                        scope: func_scope_id,
                        kind: BindingKind::Parameter,
                    });
                }
            }
            let prev_in_function = state.in_function;
            let prev_in_loop = state.in_loop;
            let prev_in_switch = state.in_switch;
            let prev_const_bindings = state.const_bindings.clone();
            state.in_function = true;
            state.in_loop = false;
            state.in_switch = false;
            state.const_bindings = BTreeSet::new();
            for child in &func.body.body {
                analyze_statement(
                    state,
                    child,
                    func_scope_id,
                    &mut func_bindings,
                    &mut func_lex,
                    &mut func_var,
                );
            }
            state.in_function = prev_in_function;
            state.in_loop = prev_in_loop;
            state.in_switch = prev_in_switch;
            state.const_bindings = prev_const_bindings;
            let func_scope = ScopeNode {
                scope_id: func_scope_id,
                parent: Some(scope_id),
                kind: ScopeKind::Function,
                bindings: func_bindings.clone(),
            };
            state.scopes.push(func_scope);
            state.bindings.extend(func_bindings);
        }

        Statement::ForIn(for_in_stmt) => {
            check_await_in_expression(state, &for_in_stmt.object, &for_in_stmt.span);
            // Check binding names for reserved words
            for bound_name in for_in_stmt.binding.binding_names() {
                check_reserved(state, bound_name, &for_in_stmt.span);
            }
            // Check for duplicate names within destructuring
            check_destructuring_duplicates(state, &for_in_stmt.binding, &for_in_stmt.span);
            // Create scope for for-in binding if let/const
            let for_in_scope_id = state.alloc_scope_id(scope_id.depth + 1);
            let mut for_in_bindings: Vec<ResolvedBinding> = Vec::new();
            let mut for_in_lex: BTreeMap<String, SourceSpan> = BTreeMap::new();
            let mut for_in_var: BTreeMap<String, SourceSpan> = var_names.clone();
            if let Some(ref kind) = for_in_stmt.binding_kind {
                let bk = match kind {
                    VariableDeclarationKind::Var => BindingKind::Var,
                    VariableDeclarationKind::Let => BindingKind::Let,
                    VariableDeclarationKind::Const => BindingKind::Const,
                };
                for bound_name in for_in_stmt.binding.binding_names() {
                    let bid = state.alloc_binding_id();
                    for_in_bindings.push(ResolvedBinding {
                        name: bound_name.to_string(),
                        binding_id: bid,
                        scope: for_in_scope_id,
                        kind: bk,
                    });
                }
            }
            let prev_in_loop = state.in_loop;
            state.in_loop = true;
            analyze_statement(
                state,
                &for_in_stmt.body,
                for_in_scope_id,
                &mut for_in_bindings,
                &mut for_in_lex,
                &mut for_in_var,
            );
            state.in_loop = prev_in_loop;
            let for_in_scope = ScopeNode {
                scope_id: for_in_scope_id,
                parent: Some(scope_id),
                kind: ScopeKind::Block,
                bindings: for_in_bindings.clone(),
            };
            state.scopes.push(for_in_scope);
            state.bindings.extend(for_in_bindings);
        }

        Statement::ForOf(for_of_stmt) => {
            check_await_in_expression(state, &for_of_stmt.iterable, &for_of_stmt.span);
            // Check binding names for reserved words
            for bound_name in for_of_stmt.binding.binding_names() {
                check_reserved(state, bound_name, &for_of_stmt.span);
            }
            // Check for duplicate names within destructuring
            check_destructuring_duplicates(state, &for_of_stmt.binding, &for_of_stmt.span);
            // Create scope for for-of binding if let/const
            let for_of_scope_id = state.alloc_scope_id(scope_id.depth + 1);
            let mut for_of_bindings: Vec<ResolvedBinding> = Vec::new();
            let mut for_of_lex: BTreeMap<String, SourceSpan> = BTreeMap::new();
            let mut for_of_var: BTreeMap<String, SourceSpan> = var_names.clone();
            if let Some(ref kind) = for_of_stmt.binding_kind {
                let bk = match kind {
                    VariableDeclarationKind::Var => BindingKind::Var,
                    VariableDeclarationKind::Let => BindingKind::Let,
                    VariableDeclarationKind::Const => BindingKind::Const,
                };
                for bound_name in for_of_stmt.binding.binding_names() {
                    let bid = state.alloc_binding_id();
                    for_of_bindings.push(ResolvedBinding {
                        name: bound_name.to_string(),
                        binding_id: bid,
                        scope: for_of_scope_id,
                        kind: bk,
                    });
                }
            }
            let prev_in_loop = state.in_loop;
            state.in_loop = true;
            analyze_statement(
                state,
                &for_of_stmt.body,
                for_of_scope_id,
                &mut for_of_bindings,
                &mut for_of_lex,
                &mut for_of_var,
            );
            state.in_loop = prev_in_loop;
            let for_of_scope = ScopeNode {
                scope_id: for_of_scope_id,
                parent: Some(scope_id),
                kind: ScopeKind::Block,
                bindings: for_of_bindings.clone(),
            };
            state.scopes.push(for_of_scope);
            state.bindings.extend(for_of_bindings);
        }
    }
}

fn analyze_variable_declaration(
    state: &mut AnalyzerState,
    decl: &VariableDeclaration,
    scope_id: ScopeId,
    bindings: &mut Vec<ResolvedBinding>,
    lexical_names: &mut BTreeMap<String, SourceSpan>,
    var_names: &mut BTreeMap<String, SourceSpan>,
) {
    // Empty declarator list check
    if decl.declarations.is_empty() {
        state.push_error(
            StaticErrorKind::EmptyDeclaratorList,
            format!("{} declaration has no declarators", decl.kind.as_str()),
            decl.span.clone(),
        );
        return;
    }

    let binding_kind = match decl.kind {
        VariableDeclarationKind::Var => BindingKind::Var,
        VariableDeclarationKind::Let => BindingKind::Let,
        VariableDeclarationKind::Const => BindingKind::Const,
    };

    let is_lexical = matches!(
        decl.kind,
        VariableDeclarationKind::Let | VariableDeclarationKind::Const
    );

    for declarator in &decl.declarations {
        let names = declarator.pattern.binding_names();
        let primary_name = names.first().copied().unwrap_or("_").to_string();

        // Reserved word check for all bound names
        for bound_name in &names {
            check_reserved(state, bound_name, &declarator.span);
        }

        // Check for duplicate names within a single destructuring pattern
        check_destructuring_duplicates(state, &declarator.pattern, &declarator.span);

        // const without initializer
        if decl.kind == VariableDeclarationKind::Const && declarator.initializer.is_none() {
            state.push_error(
                StaticErrorKind::ConstWithoutInitializer,
                format!(
                    "const declaration '{}' must have an initializer",
                    primary_name
                ),
                declarator.span.clone(),
            );
        }

        for name in &names {
            if is_lexical {
                // Check duplicate lexical binding
                if let Some(prev_span) = lexical_names.get(*name) {
                    state.push_error(
                        StaticErrorKind::DuplicateBinding,
                        format!(
                            "identifier '{}' has already been declared at line {}",
                            name, prev_span.start_line
                        ),
                        declarator.span.clone(),
                    );
                } else {
                    lexical_names.insert((*name).to_string(), declarator.span.clone());
                }

                // Check collision with var
                if let Some(prev_span) = var_names.get(*name) {
                    state.push_error(
                        StaticErrorKind::LexicalVarCollision,
                        format!(
                            "lexical binding '{}' collides with var declaration at line {}",
                            name, prev_span.start_line
                        ),
                        declarator.span.clone(),
                    );
                }

                // Check collision with import
                if let Some(prev_span) = state.import_bindings.get(*name) {
                    state.push_error(
                        StaticErrorKind::DuplicateBinding,
                        format!(
                            "identifier '{}' already declared as import binding at line {}",
                            name, prev_span.start_line
                        ),
                        declarator.span.clone(),
                    );
                }
            } else {
                // var declaration
                if let Some(prev_span) = lexical_names.get(*name) {
                    state.push_error(
                        StaticErrorKind::LexicalVarCollision,
                        format!(
                            "var '{}' collides with lexical declaration at line {}",
                            name, prev_span.start_line
                        ),
                        declarator.span.clone(),
                    );
                }
                var_names.insert((*name).to_string(), declarator.span.clone());
            }

            // Track const bindings for assignment-to-const detection
            if decl.kind == VariableDeclarationKind::Const {
                state.const_bindings.insert((*name).to_string());
            }

            let bid = state.alloc_binding_id();
            bindings.push(ResolvedBinding {
                name: (*name).to_string(),
                binding_id: bid,
                scope: scope_id,
                kind: binding_kind,
            });
        } // end for name in &names

        // Check await in initializer
        if let Some(ref init_expr) = declarator.initializer {
            check_await_in_expression(state, init_expr, &declarator.span);
        }
    }
}

fn check_reserved(state: &mut AnalyzerState, name: &str, span: &SourceSpan) {
    if is_reserved_binding(name, state.is_module) {
        state.push_error(
            StaticErrorKind::ReservedWordBinding,
            format!(
                "'{}' is a reserved word and cannot be used as a binding name",
                name
            ),
            span.clone(),
        );
    }
    // ES2020 §12.1.1: 'eval' and 'arguments' cannot be binding names in strict mode
    if state.is_module && (name == "eval" || name == "arguments") {
        state.push_error(
            StaticErrorKind::EvalArgumentsBinding,
            format!("'{}' cannot be used as a binding name in strict mode", name),
            span.clone(),
        );
    }
}

/// Check for duplicate binding names within a single destructuring pattern.
///
/// Unlike the top-level duplicate check (which compares across declarations),
/// this catches things like `let { a, a } = obj` or `([x, x]) => ...`.
fn check_destructuring_duplicates(
    state: &mut AnalyzerState,
    pattern: &crate::ast::BindingPattern,
    span: &SourceSpan,
) {
    let names = pattern.binding_names();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for name in &names {
        if !seen.insert(name) {
            state.push_error(
                StaticErrorKind::DuplicateDestructuringBinding,
                format!("duplicate binding name '{}' in destructuring pattern", name),
                span.clone(),
            );
        }
    }
}

/// Recursively walk an expression tree, checking for:
/// - `await` outside module context
/// - `delete` of a bare identifier in module (strict) mode
/// - Assignment to const-declared bindings
fn walk_expression(state: &mut AnalyzerState, expr: &Expression, span: &SourceSpan) {
    match expr {
        Expression::Await(inner) => {
            if !state.is_module {
                state.push_error(
                    StaticErrorKind::AwaitOutsideAsync,
                    "await is only valid in async functions or module top-level",
                    span.clone(),
                );
            }
            walk_expression(state, inner, span);
        }
        Expression::Binary { left, right, .. } => {
            walk_expression(state, left, span);
            walk_expression(state, right, span);
        }
        Expression::Unary {
            operator, argument, ..
        } => {
            if *operator == crate::ast::UnaryOperator::Delete
                && state.is_module
                && matches!(argument.as_ref(), Expression::Identifier(_))
            {
                state.push_error(
                    StaticErrorKind::DeleteOfIdentifier,
                    "delete of a bare identifier is not allowed in strict mode",
                    span.clone(),
                );
            }
            walk_expression(state, argument, span);
        }
        Expression::Assignment { left, right, .. } => {
            if let Expression::Identifier(name) = left.as_ref()
                && state.const_bindings.contains(name.as_str())
            {
                state.push_error(
                    StaticErrorKind::AssignmentToConst,
                    format!("assignment to constant variable '{}'", name),
                    span.clone(),
                );
            }
            walk_expression(state, left, span);
            walk_expression(state, right, span);
        }
        Expression::Conditional {
            test,
            consequent,
            alternate,
        } => {
            walk_expression(state, test, span);
            walk_expression(state, consequent, span);
            walk_expression(state, alternate, span);
        }
        Expression::Call {
            callee, arguments, ..
        } => {
            walk_expression(state, callee, span);
            for arg in arguments {
                walk_expression(state, arg, span);
            }
        }
        Expression::Member {
            object, property, ..
        } => {
            walk_expression(state, object, span);
            walk_expression(state, property, span);
        }
        Expression::OptionalCall { callee, arguments } => {
            walk_expression(state, callee, span);
            for arg in arguments {
                walk_expression(state, arg, span);
            }
        }
        Expression::OptionalMember {
            object, property, ..
        } => {
            walk_expression(state, object, span);
            walk_expression(state, property, span);
        }
        Expression::ArrayLiteral(elements) => {
            for elem in elements.iter().flatten() {
                walk_expression(state, elem, span);
            }
        }
        Expression::ObjectLiteral(props) => {
            for prop in props {
                walk_expression(state, &prop.key, span);
                walk_expression(state, &prop.value, span);
            }
        }
        Expression::ArrowFunction {
            params,
            body,
            is_async: _,
        } => {
            // Check for duplicate parameter names in strict mode (module code)
            if state.is_module {
                let mut seen_params: BTreeSet<String> = BTreeSet::new();
                for param in params {
                    for bound_name in param.pattern.binding_names() {
                        check_reserved(state, bound_name, &param.span);
                        if !seen_params.insert(bound_name.to_string()) {
                            state.push_error(
                                StaticErrorKind::DuplicateParameter,
                                format!("duplicate parameter name '{}'", bound_name),
                                param.span.clone(),
                            );
                        }
                    }
                }
            }
            // Check for duplicate binding names within destructuring patterns
            for param in params {
                check_destructuring_duplicates(state, &param.pattern, &param.span);
            }
            match body {
                crate::ast::ArrowBody::Expression(inner) => {
                    walk_expression(state, inner, span);
                }
                crate::ast::ArrowBody::Block(block) => {
                    // Arrow block body creates a function scope context
                    let prev_in_function = state.in_function;
                    let prev_in_loop = state.in_loop;
                    let prev_in_switch = state.in_switch;
                    let prev_const = state.const_bindings.clone();
                    state.in_function = true;
                    state.in_loop = false;
                    state.in_switch = false;
                    state.const_bindings = BTreeSet::new();
                    let arrow_scope_id = state.alloc_scope_id(0);
                    let mut arrow_bindings: Vec<ResolvedBinding> = Vec::new();
                    let mut arrow_lex: BTreeMap<String, SourceSpan> = BTreeMap::new();
                    let mut arrow_var: BTreeMap<String, SourceSpan> = BTreeMap::new();
                    for child in &block.body {
                        analyze_statement(
                            state,
                            child,
                            arrow_scope_id,
                            &mut arrow_bindings,
                            &mut arrow_lex,
                            &mut arrow_var,
                        );
                    }
                    state.in_function = prev_in_function;
                    state.in_loop = prev_in_loop;
                    state.in_switch = prev_in_switch;
                    state.const_bindings = prev_const;
                    let arrow_scope = ScopeNode {
                        scope_id: arrow_scope_id,
                        parent: None,
                        kind: ScopeKind::Function,
                        bindings: arrow_bindings.clone(),
                    };
                    state.scopes.push(arrow_scope);
                    state.bindings.extend(arrow_bindings);
                }
            }
        }
        Expression::New { callee, arguments } => {
            walk_expression(state, callee, span);
            for arg in arguments {
                walk_expression(state, arg, span);
            }
        }
        Expression::TemplateLiteral { expressions, .. } => {
            for expr in expressions {
                walk_expression(state, expr, span);
            }
        }
        Expression::Identifier(_)
        | Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral
        | Expression::UndefinedLiteral
        | Expression::This
        | Expression::Raw(_) => {}
    }
}

/// Backward-compat alias used by existing call sites.
fn check_await_in_expression(state: &mut AnalyzerState, expr: &Expression, span: &SourceSpan) {
    walk_expression(state, expr, span);
}

/// Detect TDZ violations: identifier references that appear before `let`/`const`
/// declarations in textual order.
/// Collect all identifier names referenced in an expression tree.
fn collect_identifier_refs(expr: &Expression, out: &mut Vec<String>) {
    match expr {
        Expression::Identifier(name) => out.push(name.clone()),
        Expression::Binary { left, right, .. } => {
            collect_identifier_refs(left, out);
            collect_identifier_refs(right, out);
        }
        Expression::Unary { argument, .. } => {
            collect_identifier_refs(argument, out);
        }
        Expression::Assignment { left, right, .. } => {
            collect_identifier_refs(left, out);
            collect_identifier_refs(right, out);
        }
        Expression::Conditional {
            test,
            consequent,
            alternate,
        } => {
            collect_identifier_refs(test, out);
            collect_identifier_refs(consequent, out);
            collect_identifier_refs(alternate, out);
        }
        Expression::Call {
            callee, arguments, ..
        } => {
            collect_identifier_refs(callee, out);
            for arg in arguments {
                collect_identifier_refs(arg, out);
            }
        }
        Expression::Member {
            object, property, ..
        } => {
            collect_identifier_refs(object, out);
            collect_identifier_refs(property, out);
        }
        Expression::OptionalCall { callee, arguments } => {
            collect_identifier_refs(callee, out);
            for arg in arguments {
                collect_identifier_refs(arg, out);
            }
        }
        Expression::OptionalMember {
            object, property, ..
        } => {
            collect_identifier_refs(object, out);
            collect_identifier_refs(property, out);
        }
        Expression::Await(inner) => {
            collect_identifier_refs(inner, out);
        }
        Expression::ArrayLiteral(elements) => {
            for elem in elements.iter().flatten() {
                collect_identifier_refs(elem, out);
            }
        }
        Expression::ObjectLiteral(props) => {
            for prop in props {
                collect_identifier_refs(&prop.key, out);
                collect_identifier_refs(&prop.value, out);
            }
        }
        Expression::ArrowFunction { body, .. } => {
            if let crate::ast::ArrowBody::Expression(inner) = body {
                collect_identifier_refs(inner, out);
            }
        }
        Expression::New { callee, arguments } => {
            collect_identifier_refs(callee, out);
            for arg in arguments {
                collect_identifier_refs(arg, out);
            }
        }
        Expression::TemplateLiteral { expressions, .. } => {
            for expr in expressions {
                collect_identifier_refs(expr, out);
            }
        }
        Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral
        | Expression::UndefinedLiteral
        | Expression::This
        | Expression::Raw(_) => {}
    }
}

fn detect_tdz_violations(
    state: &mut AnalyzerState,
    body: &[Statement],
    _declared_before: &BTreeSet<String>,
) {
    // Build the set of let/const names with their declaration positions (statement index)
    let mut decl_positions: BTreeMap<String, usize> = BTreeMap::new();
    for (idx, stmt) in body.iter().enumerate() {
        if let Statement::VariableDeclaration(decl) = stmt
            && matches!(
                decl.kind,
                VariableDeclarationKind::Let | VariableDeclarationKind::Const
            )
        {
            for declarator in &decl.declarations {
                for bound_name in declarator.pattern.binding_names() {
                    decl_positions.entry(bound_name.to_string()).or_insert(idx);
                }
            }
        }
    }

    // Now scan expression statements for references that precede declarations.
    // Walk into all expression types to find identifier references.
    for (idx, stmt) in body.iter().enumerate() {
        if let Statement::Expression(expr_stmt) = stmt {
            let mut refs = Vec::new();
            collect_identifier_refs(&expr_stmt.expression, &mut refs);
            for name in &refs {
                if let Some(&decl_idx) = decl_positions.get(name.as_str())
                    && idx < decl_idx
                {
                    state.push_error(
                        StaticErrorKind::TemporalDeadZone,
                        format!("cannot access '{}' before initialization", name),
                        expr_stmt.span.clone(),
                    );
                }
            }
        }

        // Also check initializers of variable declarations
        if let Statement::VariableDeclaration(decl) = stmt {
            for declarator in &decl.declarations {
                if let Some(ref init_expr) = declarator.initializer {
                    let mut refs = Vec::new();
                    collect_identifier_refs(init_expr, &mut refs);
                    for name in &refs {
                        if let Some(&decl_idx) = decl_positions.get(name.as_str())
                            && idx < decl_idx
                        {
                            state.push_error(
                                StaticErrorKind::TemporalDeadZone,
                                format!("cannot access '{}' before initialization", name),
                                declarator.span.clone(),
                            );
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Structured logging event
// ---------------------------------------------------------------------------

/// Structured log event for static-semantic analysis runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticSemanticsEvent {
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_count: u64,
    pub binding_count: u64,
    pub scope_count: u64,
    pub is_module: bool,
}

impl StaticSemanticsEvent {
    pub fn from_result(result: &StaticAnalysisResult) -> Self {
        Self {
            component: STATIC_SEMANTICS_COMPONENT.to_string(),
            event: "analysis_complete".to_string(),
            outcome: if result.passed() {
                "pass".to_string()
            } else {
                "fail".to_string()
            },
            error_count: result.errors.len() as u64,
            binding_count: result.bindings.len() as u64,
            scope_count: result.scopes.len() as u64,
            is_module: result.is_module,
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "binding_count".to_string(),
            CanonicalValue::U64(self.binding_count),
        );
        map.insert(
            "component".to_string(),
            CanonicalValue::String(self.component.clone()),
        );
        map.insert(
            "error_count".to_string(),
            CanonicalValue::U64(self.error_count),
        );
        map.insert(
            "event".to_string(),
            CanonicalValue::String(self.event.clone()),
        );
        map.insert(
            "is_module".to_string(),
            CanonicalValue::Bool(self.is_module),
        );
        map.insert(
            "outcome".to_string(),
            CanonicalValue::String(self.outcome.clone()),
        );
        map.insert(
            "scope_count".to_string(),
            CanonicalValue::U64(self.scope_count),
        );
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{
        BindingPattern, ExportDeclaration, ExportKind, ExpressionStatement, ImportDeclaration,
        ParseGoal, SourceSpan, Statement, SyntaxTree, VariableDeclaration, VariableDeclarationKind,
        VariableDeclarator,
    };

    fn span(line: u64) -> SourceSpan {
        SourceSpan::new(0, 10, line, 1, line, 10)
    }

    fn make_tree(goal: ParseGoal, body: Vec<Statement>) -> SyntaxTree {
        SyntaxTree {
            goal,
            body,
            span: SourceSpan::new(0, 100, 1, 1, 10, 1),
        }
    }

    fn var_decl(
        kind: VariableDeclarationKind,
        name: &str,
        init: Option<Expression>,
        line: u64,
    ) -> Statement {
        Statement::VariableDeclaration(VariableDeclaration {
            kind,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::Identifier(name.to_string()),
                initializer: init,
                span: span(line),
            }],
            span: span(line),
        })
    }

    fn import_stmt(binding: Option<&str>, source: &str, line: u64) -> Statement {
        Statement::Import(ImportDeclaration {
            binding: binding.map(ToString::to_string),
            source: source.to_string(),
            span: span(line),
        })
    }

    fn export_default(expr: Expression, line: u64) -> Statement {
        Statement::Export(ExportDeclaration {
            kind: ExportKind::Default(expr),
            span: span(line),
        })
    }

    fn export_named(name: &str, line: u64) -> Statement {
        Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause(name.to_string()),
            span: span(line),
        })
    }

    fn expr_stmt(expr: Expression, line: u64) -> Statement {
        Statement::Expression(ExpressionStatement {
            expression: expr,
            span: span(line),
        })
    }

    // -----------------------------------------------------------------------
    // Happy path
    // -----------------------------------------------------------------------

    #[test]
    fn empty_script_passes() {
        let tree = make_tree(ParseGoal::Script, vec![]);
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.scopes.len(), 1);
        assert_eq!(result.scopes[0].kind, ScopeKind::Global);
        assert!(!result.is_module);
    }

    #[test]
    fn empty_module_passes() {
        let tree = make_tree(ParseGoal::Module, vec![]);
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.scopes.len(), 1);
        assert_eq!(result.scopes[0].kind, ScopeKind::Module);
        assert!(result.is_module);
    }

    #[test]
    fn single_var_declaration() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(42)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.bindings.len(), 1);
        assert_eq!(result.bindings[0].name, "x");
        assert_eq!(result.bindings[0].kind, BindingKind::Var);
    }

    #[test]
    fn single_let_declaration() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Let,
                "y",
                Some(Expression::StringLiteral("hello".to_string())),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.bindings.len(), 1);
        assert_eq!(result.bindings[0].name, "y");
        assert_eq!(result.bindings[0].kind, BindingKind::Let);
    }

    #[test]
    fn single_const_with_initializer() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Const,
                "z",
                Some(Expression::BooleanLiteral(true)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.bindings.len(), 1);
        assert_eq!(result.bindings[0].kind, BindingKind::Const);
    }

    #[test]
    fn module_import_and_export() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                import_stmt(Some("foo"), "./foo.js", 1),
                export_named("bar", 2),
            ],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.bindings.len(), 1);
        assert_eq!(result.bindings[0].name, "foo");
        assert_eq!(result.bindings[0].kind, BindingKind::Import);
    }

    #[test]
    fn multiple_var_same_name_allowed() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Var,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Var,
                    "x",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.bindings.len(), 2);
    }

    #[test]
    fn distinct_let_bindings() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Let,
                    "a",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "b",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.bindings.len(), 2);
    }

    #[test]
    fn module_with_multiple_named_exports() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                export_named("a", 1),
                export_named("b", 2),
                export_named("c", 3),
            ],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn module_default_and_named_exports() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                export_default(Expression::NumericLiteral(42), 1),
                export_named("foo", 2),
            ],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn top_level_await_in_module() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![expr_stmt(
                Expression::Await(Box::new(Expression::Identifier("promise".to_string()))),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn expression_statement_in_script() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(Expression::NumericLiteral(42), 1)],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn import_without_binding() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![import_stmt(None, "./side-effect.js", 1)],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.bindings.len(), 0);
    }

    // -----------------------------------------------------------------------
    // Error: const without initializer
    // -----------------------------------------------------------------------

    #[test]
    fn const_without_initializer() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(VariableDeclarationKind::Const, "x", None, 1)],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(
            result.errors[0].kind,
            StaticErrorKind::ConstWithoutInitializer
        );
    }

    #[test]
    fn const_without_initializer_multiple() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(VariableDeclarationKind::Const, "a", None, 1),
                var_decl(VariableDeclarationKind::Const, "b", None, 2),
            ],
        );
        let result = analyze(&tree);
        assert_eq!(result.errors.len(), 2);
        assert!(
            result
                .errors
                .iter()
                .all(|e| e.kind == StaticErrorKind::ConstWithoutInitializer)
        );
    }

    // -----------------------------------------------------------------------
    // Error: duplicate let/const bindings
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_let_binding() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].kind, StaticErrorKind::DuplicateBinding);
    }

    #[test]
    fn duplicate_const_binding() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Const,
                    "y",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Const,
                    "y",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateBinding)
        );
    }

    #[test]
    fn let_const_collision() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Let,
                    "z",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Const,
                    "z",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateBinding)
        );
    }

    // -----------------------------------------------------------------------
    // Error: import/export in script
    // -----------------------------------------------------------------------

    #[test]
    fn import_in_script() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![import_stmt(Some("foo"), "./foo.js", 1)],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].kind, StaticErrorKind::ImportInScript);
    }

    #[test]
    fn export_in_script() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![export_default(Expression::NumericLiteral(42), 1)],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].kind, StaticErrorKind::ExportInScript);
    }

    #[test]
    fn export_named_in_script() {
        let tree = make_tree(ParseGoal::Script, vec![export_named("foo", 1)]);
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors[0].kind, StaticErrorKind::ExportInScript);
    }

    // -----------------------------------------------------------------------
    // Error: duplicate exports
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_named_export() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![export_named("foo", 1), export_named("foo", 2)],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].kind, StaticErrorKind::DuplicateExport);
    }

    #[test]
    fn duplicate_default_export() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                export_default(Expression::NumericLiteral(1), 1),
                export_default(Expression::NumericLiteral(2), 2),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].kind, StaticErrorKind::DuplicateExport);
    }

    // -----------------------------------------------------------------------
    // Error: await outside async (in Script)
    // -----------------------------------------------------------------------

    #[test]
    fn await_in_script() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::Await(Box::new(Expression::Identifier("p".to_string()))),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].kind, StaticErrorKind::AwaitOutsideAsync);
    }

    // -----------------------------------------------------------------------
    // Error: lexical/var collision
    // -----------------------------------------------------------------------

    #[test]
    fn let_var_collision() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Var,
                    "x",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::LexicalVarCollision)
        );
    }

    #[test]
    fn var_let_collision() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Var,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::LexicalVarCollision)
        );
    }

    // -----------------------------------------------------------------------
    // Error: TDZ violation
    // -----------------------------------------------------------------------

    #[test]
    fn tdz_use_before_let() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                expr_stmt(Expression::Identifier("x".to_string()), 1),
                var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::TemporalDeadZone)
        );
    }

    #[test]
    fn tdz_use_before_const() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                expr_stmt(Expression::Identifier("y".to_string()), 1),
                var_decl(
                    VariableDeclarationKind::Const,
                    "y",
                    Some(Expression::NumericLiteral(1)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::TemporalDeadZone)
        );
    }

    #[test]
    fn no_tdz_for_var() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                expr_stmt(Expression::Identifier("x".to_string()), 1),
                var_decl(
                    VariableDeclarationKind::Var,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        // var declarations are hoisted, no TDZ
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::TemporalDeadZone)
        );
    }

    #[test]
    fn tdz_in_initializer() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Let,
                    "a",
                    Some(Expression::Identifier("b".to_string())),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "b",
                    Some(Expression::NumericLiteral(1)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::TemporalDeadZone)
        );
    }

    // -----------------------------------------------------------------------
    // Error: empty declarator list
    // -----------------------------------------------------------------------

    #[test]
    fn empty_declarator_list() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Let,
                declarations: vec![],
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors[0].kind, StaticErrorKind::EmptyDeclaratorList);
    }

    // -----------------------------------------------------------------------
    // Error: reserved words as bindings
    // -----------------------------------------------------------------------

    #[test]
    fn keyword_as_binding() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Let,
                "class",
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors[0].kind, StaticErrorKind::ReservedWordBinding);
    }

    #[test]
    fn strict_reserved_in_module() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![var_decl(
                VariableDeclarationKind::Let,
                "interface",
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors[0].kind, StaticErrorKind::ReservedWordBinding);
    }

    #[test]
    fn strict_reserved_allowed_in_script() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Let,
                "interface",
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    // -----------------------------------------------------------------------
    // Error: import redeclaration
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_import_binding() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                import_stmt(Some("foo"), "./a.js", 1),
                import_stmt(Some("foo"), "./b.js", 2),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ImportRedeclaration)
        );
    }

    #[test]
    fn import_then_let_collision() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                import_stmt(Some("x"), "./x.js", 1),
                var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateBinding)
        );
    }

    // -----------------------------------------------------------------------
    // Multiple errors in one tree
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_errors_combined() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                import_stmt(Some("a"), "./a.js", 1), // import in script
                var_decl(VariableDeclarationKind::Const, "b", None, 2), // const no init
                var_decl(
                    VariableDeclarationKind::Let,
                    "c",
                    Some(Expression::NumericLiteral(1)),
                    3,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "c",
                    Some(Expression::NumericLiteral(2)),
                    4,
                ), // duplicate let
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(result.errors.len() >= 3);
    }

    // -----------------------------------------------------------------------
    // Scope structure
    // -----------------------------------------------------------------------

    #[test]
    fn scope_has_correct_kind_for_script() {
        let tree = make_tree(ParseGoal::Script, vec![]);
        let result = analyze(&tree);
        assert_eq!(result.scopes[0].kind, ScopeKind::Global);
    }

    #[test]
    fn scope_has_correct_kind_for_module() {
        let tree = make_tree(ParseGoal::Module, vec![]);
        let result = analyze(&tree);
        assert_eq!(result.scopes[0].kind, ScopeKind::Module);
    }

    #[test]
    fn top_scope_has_no_parent() {
        let tree = make_tree(ParseGoal::Script, vec![]);
        let result = analyze(&tree);
        assert!(result.scopes[0].parent.is_none());
    }

    #[test]
    fn bindings_have_incremental_ids() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Let,
                    "a",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "b",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "c",
                    Some(Expression::NumericLiteral(3)),
                    3,
                ),
            ],
        );
        let result = analyze(&tree);
        assert_eq!(result.bindings[0].binding_id, 0);
        assert_eq!(result.bindings[1].binding_id, 1);
        assert_eq!(result.bindings[2].binding_id, 2);
    }

    // -----------------------------------------------------------------------
    // Serde round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn static_error_kind_serde() {
        let kinds = [
            StaticErrorKind::DuplicateBinding,
            StaticErrorKind::ConstWithoutInitializer,
            StaticErrorKind::ImportInScript,
            StaticErrorKind::ExportInScript,
            StaticErrorKind::DuplicateExport,
            StaticErrorKind::AwaitOutsideAsync,
            StaticErrorKind::TemporalDeadZone,
            StaticErrorKind::LexicalVarCollision,
            StaticErrorKind::EmptyDeclaratorList,
            StaticErrorKind::ReservedWordBinding,
            StaticErrorKind::ImportRedeclaration,
            StaticErrorKind::AssignmentToConst,
            StaticErrorKind::ReturnOutsideFunction,
            StaticErrorKind::BreakOutsideLoop,
            StaticErrorKind::ContinueOutsideLoop,
            StaticErrorKind::DuplicateParameter,
            StaticErrorKind::DeleteOfIdentifier,
            StaticErrorKind::EvalArgumentsBinding,
            StaticErrorKind::ForInInitializer,
            StaticErrorKind::DuplicateDestructuringBinding,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let back: StaticErrorKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn static_error_serde() {
        let err = StaticError::new(StaticErrorKind::DuplicateBinding, "test error", span(5));
        let json = serde_json::to_string(&err).unwrap();
        let back: StaticError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn analysis_result_serde() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        );
        let result = analyze(&tree);
        let json = serde_json::to_string(&result).unwrap();
        let back: StaticAnalysisResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // -----------------------------------------------------------------------
    // Display / canonical_value
    // -----------------------------------------------------------------------

    #[test]
    fn static_error_display() {
        let err = StaticError::new(
            StaticErrorKind::ConstWithoutInitializer,
            "const must have init",
            span(3),
        );
        let s = err.to_string();
        assert!(s.contains("FE-STATIC-DIAG-CONST-INIT-0002"));
        assert!(s.contains("const must have init"));
        assert!(s.contains("line 3"));
    }

    #[test]
    fn static_error_kind_display() {
        assert_eq!(
            StaticErrorKind::DuplicateBinding.to_string(),
            "duplicate_binding"
        );
    }

    #[test]
    fn canonical_value_not_empty() {
        let err = StaticError::new(StaticErrorKind::DuplicateBinding, "dup", span(1));
        let cv = err.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert!(map.contains_key("kind"));
            assert!(map.contains_key("message"));
            assert!(map.contains_key("span"));
            assert!(map.contains_key("diagnostic_code"));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn analysis_result_canonical_value_keys() {
        let tree = make_tree(ParseGoal::Script, vec![]);
        let result = analyze(&tree);
        let cv = result.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert!(map.contains_key("bindings"));
            assert!(map.contains_key("errors"));
            assert!(map.contains_key("is_module"));
            assert!(map.contains_key("scopes"));
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // Structured logging event
    // -----------------------------------------------------------------------

    #[test]
    fn event_from_passing_result() {
        let tree = make_tree(ParseGoal::Script, vec![]);
        let result = analyze(&tree);
        let event = StaticSemanticsEvent::from_result(&result);
        assert_eq!(event.component, "static_semantics");
        assert_eq!(event.event, "analysis_complete");
        assert_eq!(event.outcome, "pass");
        assert_eq!(event.error_count, 0);
    }

    #[test]
    fn event_from_failing_result() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(VariableDeclarationKind::Const, "x", None, 1)],
        );
        let result = analyze(&tree);
        let event = StaticSemanticsEvent::from_result(&result);
        assert_eq!(event.outcome, "fail");
        assert_eq!(event.error_count, 1);
    }

    #[test]
    fn event_canonical_value_keys() {
        let tree = make_tree(ParseGoal::Script, vec![]);
        let result = analyze(&tree);
        let event = StaticSemanticsEvent::from_result(&result);
        let cv = event.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert!(map.contains_key("component"));
            assert!(map.contains_key("event"));
            assert!(map.contains_key("outcome"));
            assert!(map.contains_key("error_count"));
            assert!(map.contains_key("binding_count"));
            assert!(map.contains_key("scope_count"));
            assert!(map.contains_key("is_module"));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn event_serde_round_trip() {
        let event = StaticSemanticsEvent {
            component: "static_semantics".to_string(),
            event: "analysis_complete".to_string(),
            outcome: "pass".to_string(),
            error_count: 0,
            binding_count: 3,
            scope_count: 1,
            is_module: false,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: StaticSemanticsEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    // -----------------------------------------------------------------------
    // Contract constants
    // -----------------------------------------------------------------------

    #[test]
    fn contract_constants_non_empty() {
        assert!(!STATIC_SEMANTICS_CONTRACT_VERSION.is_empty());
        assert!(!STATIC_SEMANTICS_BEAD_ID.is_empty());
        assert!(!STATIC_SEMANTICS_COMPONENT.is_empty());
    }

    // -----------------------------------------------------------------------
    // Diagnostic codes are unique
    // -----------------------------------------------------------------------

    #[test]
    fn diagnostic_codes_are_unique() {
        let kinds = [
            StaticErrorKind::DuplicateBinding,
            StaticErrorKind::ConstWithoutInitializer,
            StaticErrorKind::ImportInScript,
            StaticErrorKind::ExportInScript,
            StaticErrorKind::DuplicateExport,
            StaticErrorKind::AwaitOutsideAsync,
            StaticErrorKind::TemporalDeadZone,
            StaticErrorKind::LexicalVarCollision,
            StaticErrorKind::EmptyDeclaratorList,
            StaticErrorKind::ReservedWordBinding,
            StaticErrorKind::ImportRedeclaration,
            StaticErrorKind::AssignmentToConst,
            StaticErrorKind::ReturnOutsideFunction,
            StaticErrorKind::BreakOutsideLoop,
            StaticErrorKind::ContinueOutsideLoop,
            StaticErrorKind::DuplicateParameter,
            StaticErrorKind::DeleteOfIdentifier,
            StaticErrorKind::EvalArgumentsBinding,
            StaticErrorKind::ForInInitializer,
            StaticErrorKind::DuplicateDestructuringBinding,
        ];
        let codes: BTreeSet<&str> = kinds.iter().map(|k| k.diagnostic_code()).collect();
        assert_eq!(codes.len(), kinds.len(), "diagnostic codes must be unique");
    }

    // -----------------------------------------------------------------------
    // Passed / error_count helpers
    // -----------------------------------------------------------------------

    #[test]
    fn passed_and_error_count() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(VariableDeclarationKind::Const, "a", None, 1),
                var_decl(VariableDeclarationKind::Const, "b", None, 2),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.error_count(), 2);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn let_without_initializer_is_allowed() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(VariableDeclarationKind::Let, "x", None, 1)],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn var_without_initializer_is_allowed() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(VariableDeclarationKind::Var, "x", None, 1)],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn raw_expression_passes() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(Expression::Raw("some code".to_string()), 1)],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn null_literal_expression_passes() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(Expression::NullLiteral, 1)],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn undefined_literal_expression_passes() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(Expression::UndefinedLiteral, 1)],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn await_in_export_default_script() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![export_default(
                Expression::Await(Box::new(Expression::Identifier("p".to_string()))),
                1,
            )],
        );
        let result = analyze(&tree);
        // Both export-in-script and await-outside-async
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ExportInScript)
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AwaitOutsideAsync)
        );
    }

    #[test]
    fn is_reserved_binding_covers_keywords() {
        assert!(is_reserved_binding("class", false));
        assert!(is_reserved_binding("function", false));
        assert!(is_reserved_binding("return", false));
        assert!(is_reserved_binding("var", false));
        assert!(is_reserved_binding("const", false));
    }

    #[test]
    fn is_reserved_binding_strict_in_module() {
        assert!(is_reserved_binding("interface", true));
        assert!(is_reserved_binding("implements", true));
        assert!(is_reserved_binding("yield", true));
        assert!(!is_reserved_binding("interface", false));
    }

    #[test]
    fn is_reserved_binding_normal_names() {
        assert!(!is_reserved_binding("foo", false));
        assert!(!is_reserved_binding("bar", true));
        assert!(!is_reserved_binding("myVar", false));
    }

    #[test]
    fn mixed_valid_and_invalid_bindings() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Let,
                    "validName",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "class",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].kind, StaticErrorKind::ReservedWordBinding);
        // Valid binding still registered
        assert_eq!(result.bindings.len(), 2);
    }

    #[test]
    fn scope_bindings_match_top_level() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                import_stmt(Some("a"), "./a.js", 1),
                var_decl(
                    VariableDeclarationKind::Const,
                    "b",
                    Some(Expression::NumericLiteral(1)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.scopes[0].bindings.len(), 2);
        assert_eq!(result.scopes[0].bindings[0].name, "a");
        assert_eq!(result.scopes[0].bindings[1].name, "b");
    }

    // -----------------------------------------------------------------------
    // New error kinds: AssignmentToConst
    // -----------------------------------------------------------------------

    #[test]
    fn assignment_to_const_detected() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Const,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                expr_stmt(
                    Expression::Assignment {
                        operator: crate::ast::AssignmentOperator::Assign,
                        left: Box::new(Expression::Identifier("x".to_string())),
                        right: Box::new(Expression::NumericLiteral(2)),
                    },
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AssignmentToConst)
        );
    }

    #[test]
    fn assignment_to_let_allowed() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                expr_stmt(
                    Expression::Assignment {
                        operator: crate::ast::AssignmentOperator::Assign,
                        left: Box::new(Expression::Identifier("x".to_string())),
                        right: Box::new(Expression::NumericLiteral(2)),
                    },
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AssignmentToConst)
        );
    }

    #[test]
    fn compound_assignment_to_const() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Const,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                expr_stmt(
                    Expression::Assignment {
                        operator: crate::ast::AssignmentOperator::AddAssign,
                        left: Box::new(Expression::Identifier("x".to_string())),
                        right: Box::new(Expression::NumericLiteral(5)),
                    },
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AssignmentToConst)
        );
    }

    // -----------------------------------------------------------------------
    // New error kinds: ReturnOutsideFunction
    // -----------------------------------------------------------------------

    #[test]
    fn return_outside_function() {
        use crate::ast::ReturnStatement;
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::Return(ReturnStatement {
                argument: None,
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ReturnOutsideFunction)
        );
    }

    #[test]
    fn return_inside_function_ok() {
        use crate::ast::{BlockStatement, FunctionDeclaration, ReturnStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::FunctionDeclaration(FunctionDeclaration {
                name: Some("foo".to_string()),
                params: vec![],
                body: BlockStatement {
                    body: vec![Statement::Return(ReturnStatement {
                        argument: Some(Expression::NumericLiteral(42)),
                        span: span(2),
                    })],
                    span: span(1),
                },
                is_async: false,
                is_generator: false,
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ReturnOutsideFunction)
        );
    }

    // -----------------------------------------------------------------------
    // New error kinds: BreakOutsideLoop, ContinueOutsideLoop
    // -----------------------------------------------------------------------

    #[test]
    fn break_outside_loop() {
        use crate::ast::BreakStatement;
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::Break(BreakStatement {
                label: None,
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::BreakOutsideLoop)
        );
    }

    #[test]
    fn continue_outside_loop() {
        use crate::ast::ContinueStatement;
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::Continue(ContinueStatement {
                label: None,
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ContinueOutsideLoop)
        );
    }

    #[test]
    fn break_inside_for_ok() {
        use crate::ast::{BreakStatement, ForStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::For(ForStatement {
                init: None,
                condition: Some(Expression::BooleanLiteral(true)),
                update: None,
                body: Box::new(Statement::Break(BreakStatement {
                    label: None,
                    span: span(2),
                })),
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::BreakOutsideLoop)
        );
    }

    #[test]
    fn continue_inside_while_ok() {
        use crate::ast::{ContinueStatement, WhileStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::While(WhileStatement {
                condition: Expression::BooleanLiteral(true),
                body: Box::new(Statement::Continue(ContinueStatement {
                    label: None,
                    span: span(2),
                })),
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ContinueOutsideLoop)
        );
    }

    #[test]
    fn break_inside_switch_ok() {
        use crate::ast::{BreakStatement, SwitchCase, SwitchStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::Switch(SwitchStatement {
                discriminant: Expression::Identifier("x".to_string()),
                cases: vec![SwitchCase {
                    test: Some(Expression::NumericLiteral(1)),
                    consequent: vec![Statement::Break(BreakStatement {
                        label: None,
                        span: span(3),
                    })],
                    span: span(2),
                }],
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::BreakOutsideLoop)
        );
    }

    #[test]
    fn continue_inside_do_while_ok() {
        use crate::ast::{ContinueStatement, DoWhileStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::DoWhile(DoWhileStatement {
                body: Box::new(Statement::Continue(ContinueStatement {
                    label: None,
                    span: span(2),
                })),
                condition: Expression::BooleanLiteral(true),
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ContinueOutsideLoop)
        );
    }

    // -----------------------------------------------------------------------
    // New error kinds: DuplicateParameter (module strict mode)
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_parameter_in_module() {
        use crate::ast::{BindingPattern, BlockStatement, FunctionDeclaration, FunctionParam};
        let tree = make_tree(
            ParseGoal::Module,
            vec![Statement::FunctionDeclaration(FunctionDeclaration {
                name: Some("foo".to_string()),
                params: vec![
                    FunctionParam {
                        pattern: BindingPattern::Identifier("a".to_string()),
                        span: span(1),
                    },
                    FunctionParam {
                        pattern: BindingPattern::Identifier("a".to_string()),
                        span: span(1),
                    },
                ],
                body: BlockStatement {
                    body: vec![],
                    span: span(2),
                },
                is_async: false,
                is_generator: false,
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateParameter)
        );
    }

    #[test]
    fn distinct_parameters_ok() {
        use crate::ast::{BindingPattern, BlockStatement, FunctionDeclaration, FunctionParam};
        let tree = make_tree(
            ParseGoal::Module,
            vec![Statement::FunctionDeclaration(FunctionDeclaration {
                name: Some("bar".to_string()),
                params: vec![
                    FunctionParam {
                        pattern: BindingPattern::Identifier("a".to_string()),
                        span: span(1),
                    },
                    FunctionParam {
                        pattern: BindingPattern::Identifier("b".to_string()),
                        span: span(1),
                    },
                ],
                body: BlockStatement {
                    body: vec![],
                    span: span(2),
                },
                is_async: false,
                is_generator: false,
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateParameter)
        );
    }

    // -----------------------------------------------------------------------
    // New error kinds: DeleteOfIdentifier
    // -----------------------------------------------------------------------

    #[test]
    fn delete_identifier_in_module() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![expr_stmt(
                Expression::Unary {
                    operator: crate::ast::UnaryOperator::Delete,
                    argument: Box::new(Expression::Identifier("x".to_string())),
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DeleteOfIdentifier)
        );
    }

    #[test]
    fn delete_member_in_module_ok() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![expr_stmt(
                Expression::Unary {
                    operator: crate::ast::UnaryOperator::Delete,
                    argument: Box::new(Expression::Member {
                        object: Box::new(Expression::Identifier("obj".to_string())),
                        property: Box::new(Expression::Identifier("prop".to_string())),
                        computed: false,
                    }),
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DeleteOfIdentifier)
        );
    }

    #[test]
    fn delete_identifier_in_script_ok() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::Unary {
                    operator: crate::ast::UnaryOperator::Delete,
                    argument: Box::new(Expression::Identifier("x".to_string())),
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DeleteOfIdentifier)
        );
    }

    // -----------------------------------------------------------------------
    // Block scoping
    // -----------------------------------------------------------------------

    #[test]
    fn block_creates_child_scope() {
        use crate::ast::BlockStatement;
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::Block(BlockStatement {
                body: vec![var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    2,
                )],
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        // Top scope + block scope
        assert_eq!(result.scopes.len(), 2);
        assert_eq!(result.scopes[0].kind, ScopeKind::Block);
        assert_eq!(result.scopes[0].parent, Some(result.scopes[1].scope_id));
    }

    #[test]
    fn for_loop_creates_child_scope() {
        use crate::ast::ForStatement;
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::For(ForStatement {
                init: Some(Box::new(var_decl(
                    VariableDeclarationKind::Let,
                    "i",
                    Some(Expression::NumericLiteral(0)),
                    1,
                ))),
                condition: Some(Expression::BooleanLiteral(true)),
                update: None,
                body: Box::new(expr_stmt(Expression::Identifier("i".to_string()), 2)),
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        // Top scope + for scope
        assert_eq!(result.scopes.len(), 2);
    }

    #[test]
    fn function_creates_child_scope() {
        use crate::ast::{BindingPattern, BlockStatement, FunctionDeclaration, FunctionParam};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::FunctionDeclaration(FunctionDeclaration {
                name: Some("foo".to_string()),
                params: vec![FunctionParam {
                    pattern: BindingPattern::Identifier("a".to_string()),
                    span: span(1),
                }],
                body: BlockStatement {
                    body: vec![var_decl(
                        VariableDeclarationKind::Let,
                        "b",
                        Some(Expression::NumericLiteral(1)),
                        2,
                    )],
                    span: span(1),
                },
                is_async: false,
                is_generator: false,
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        // Top scope + function scope
        assert_eq!(result.scopes.len(), 2);
        // Function scope has param + local binding
        let func_scope = &result.scopes[0];
        assert_eq!(func_scope.kind, ScopeKind::Function);
        assert_eq!(func_scope.bindings.len(), 2); // param "a" + let "b"
        assert_eq!(func_scope.bindings[0].name, "a");
        assert_eq!(func_scope.bindings[0].kind, BindingKind::Parameter);
        assert_eq!(func_scope.bindings[1].name, "b");
        assert_eq!(func_scope.bindings[1].kind, BindingKind::Let);
    }

    // -----------------------------------------------------------------------
    // Recursive expression walking
    // -----------------------------------------------------------------------

    #[test]
    fn await_nested_in_binary_detected() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::Binary {
                    operator: crate::ast::BinaryOperator::Add,
                    left: Box::new(Expression::NumericLiteral(1)),
                    right: Box::new(Expression::Await(Box::new(Expression::Identifier(
                        "p".to_string(),
                    )))),
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AwaitOutsideAsync)
        );
    }

    #[test]
    fn await_nested_in_call_detected() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::Call {
                    callee: Box::new(Expression::Identifier("foo".to_string())),
                    arguments: vec![Expression::Await(Box::new(Expression::Identifier(
                        "p".to_string(),
                    )))],
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AwaitOutsideAsync)
        );
    }

    #[test]
    fn await_nested_in_conditional_detected() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::Conditional {
                    test: Box::new(Expression::BooleanLiteral(true)),
                    consequent: Box::new(Expression::Await(Box::new(Expression::Identifier(
                        "p".to_string(),
                    )))),
                    alternate: Box::new(Expression::NumericLiteral(0)),
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AwaitOutsideAsync)
        );
    }

    #[test]
    fn await_in_array_literal_detected() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::ArrayLiteral(vec![Some(Expression::Await(Box::new(
                    Expression::Identifier("p".to_string()),
                )))]),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AwaitOutsideAsync)
        );
    }

    #[test]
    fn await_in_object_literal_detected() {
        use crate::ast::ObjectProperty;
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::ObjectLiteral(vec![ObjectProperty {
                    key: Expression::StringLiteral("k".to_string()),
                    value: Expression::Await(Box::new(Expression::Identifier("p".to_string()))),
                    computed: false,
                    shorthand: false,
                }]),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AwaitOutsideAsync)
        );
    }

    // -----------------------------------------------------------------------
    // TDZ in complex expressions
    // -----------------------------------------------------------------------

    #[test]
    fn tdz_in_binary_expression() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                expr_stmt(
                    Expression::Binary {
                        operator: crate::ast::BinaryOperator::Add,
                        left: Box::new(Expression::Identifier("x".to_string())),
                        right: Box::new(Expression::NumericLiteral(1)),
                    },
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(10)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::TemporalDeadZone)
        );
    }

    #[test]
    fn tdz_in_call_argument() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                expr_stmt(
                    Expression::Call {
                        callee: Box::new(Expression::Identifier("foo".to_string())),
                        arguments: vec![Expression::Identifier("x".to_string())],
                    },
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Const,
                    "x",
                    Some(Expression::NumericLiteral(10)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::TemporalDeadZone)
        );
    }

    // -----------------------------------------------------------------------
    // Catch clause scoping
    // -----------------------------------------------------------------------

    #[test]
    fn catch_parameter_creates_scope() {
        use crate::ast::{BlockStatement, CatchClause, TryCatchStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::TryCatch(TryCatchStatement {
                block: BlockStatement {
                    body: vec![],
                    span: span(1),
                },
                handler: Some(CatchClause {
                    parameter: Some("err".to_string()),
                    body: BlockStatement {
                        body: vec![],
                        span: span(3),
                    },
                    span: span(2),
                }),
                finalizer: None,
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        // Top scope + catch scope
        assert_eq!(result.scopes.len(), 2);
        let catch_scope = &result.scopes[0];
        assert_eq!(catch_scope.bindings.len(), 1);
        assert_eq!(catch_scope.bindings[0].name, "err");
    }

    // -----------------------------------------------------------------------
    // Context flags reset correctly
    // -----------------------------------------------------------------------

    #[test]
    fn return_inside_nested_function_ok_but_outside_not() {
        use crate::ast::{BlockStatement, FunctionDeclaration, ReturnStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                Statement::FunctionDeclaration(FunctionDeclaration {
                    name: Some("outer".to_string()),
                    params: vec![],
                    body: BlockStatement {
                        body: vec![Statement::Return(ReturnStatement {
                            argument: None,
                            span: span(2),
                        })],
                        span: span(1),
                    },
                    is_async: false,
                    is_generator: false,
                    span: span(1),
                }),
                // This return is at top-level (outside function)
                Statement::Return(ReturnStatement {
                    argument: None,
                    span: span(5),
                }),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(
            result
                .errors
                .iter()
                .filter(|e| e.kind == StaticErrorKind::ReturnOutsideFunction)
                .count(),
            1
        );
    }

    #[test]
    fn break_after_loop_not_in_loop() {
        use crate::ast::{BreakStatement, WhileStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                Statement::While(WhileStatement {
                    condition: Expression::BooleanLiteral(true),
                    body: Box::new(Statement::Break(BreakStatement {
                        label: None,
                        span: span(2),
                    })),
                    span: span(1),
                }),
                Statement::Break(BreakStatement {
                    label: None,
                    span: span(4),
                }),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(
            result
                .errors
                .iter()
                .filter(|e| e.kind == StaticErrorKind::BreakOutsideLoop)
                .count(),
            1
        );
    }

    // -----------------------------------------------------------------------
    // New error kind serde round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn new_error_kinds_as_str() {
        assert_eq!(
            StaticErrorKind::AssignmentToConst.as_str(),
            "assignment_to_const"
        );
        assert_eq!(
            StaticErrorKind::ReturnOutsideFunction.as_str(),
            "return_outside_function"
        );
        assert_eq!(
            StaticErrorKind::BreakOutsideLoop.as_str(),
            "break_outside_loop"
        );
        assert_eq!(
            StaticErrorKind::ContinueOutsideLoop.as_str(),
            "continue_outside_loop"
        );
        assert_eq!(
            StaticErrorKind::DuplicateParameter.as_str(),
            "duplicate_parameter"
        );
        assert_eq!(
            StaticErrorKind::DeleteOfIdentifier.as_str(),
            "delete_of_identifier"
        );
    }

    #[test]
    fn new_error_kinds_diagnostic_codes_non_empty() {
        let new_kinds = [
            StaticErrorKind::AssignmentToConst,
            StaticErrorKind::ReturnOutsideFunction,
            StaticErrorKind::BreakOutsideLoop,
            StaticErrorKind::ContinueOutsideLoop,
            StaticErrorKind::DuplicateParameter,
            StaticErrorKind::DeleteOfIdentifier,
            StaticErrorKind::EvalArgumentsBinding,
            StaticErrorKind::ForInInitializer,
            StaticErrorKind::DuplicateDestructuringBinding,
        ];
        for kind in new_kinds {
            assert!(!kind.diagnostic_code().is_empty());
            assert!(kind.diagnostic_code().starts_with("FE-STATIC-DIAG-"));
        }
    }

    // -----------------------------------------------------------------------
    // collect_identifier_refs
    // -----------------------------------------------------------------------

    #[test]
    fn collect_refs_from_binary() {
        let expr = Expression::Binary {
            operator: crate::ast::BinaryOperator::Add,
            left: Box::new(Expression::Identifier("a".to_string())),
            right: Box::new(Expression::Identifier("b".to_string())),
        };
        let mut refs = Vec::new();
        collect_identifier_refs(&expr, &mut refs);
        assert_eq!(refs, vec!["a", "b"]);
    }

    #[test]
    fn collect_refs_from_call() {
        let expr = Expression::Call {
            callee: Box::new(Expression::Identifier("fn".to_string())),
            arguments: vec![
                Expression::Identifier("x".to_string()),
                Expression::NumericLiteral(1),
            ],
        };
        let mut refs = Vec::new();
        collect_identifier_refs(&expr, &mut refs);
        assert_eq!(refs, vec!["fn", "x"]);
    }

    #[test]
    fn collect_refs_from_nested() {
        let expr = Expression::Conditional {
            test: Box::new(Expression::Identifier("cond".to_string())),
            consequent: Box::new(Expression::Identifier("a".to_string())),
            alternate: Box::new(Expression::Binary {
                operator: crate::ast::BinaryOperator::Multiply,
                left: Box::new(Expression::Identifier("b".to_string())),
                right: Box::new(Expression::Identifier("c".to_string())),
            }),
        };
        let mut refs = Vec::new();
        collect_identifier_refs(&expr, &mut refs);
        assert_eq!(refs, vec!["cond", "a", "b", "c"]);
    }

    #[test]
    fn collect_refs_from_terminals() {
        let expr = Expression::NumericLiteral(42);
        let mut refs = Vec::new();
        collect_identifier_refs(&expr, &mut refs);
        assert!(refs.is_empty());
    }

    #[test]
    fn collect_refs_from_array_literal() {
        let expr = Expression::ArrayLiteral(vec![
            Some(Expression::Identifier("a".to_string())),
            None,
            Some(Expression::Identifier("b".to_string())),
        ]);
        let mut refs = Vec::new();
        collect_identifier_refs(&expr, &mut refs);
        assert_eq!(refs, vec!["a", "b"]);
    }

    #[test]
    fn collect_refs_from_object_literal() {
        use crate::ast::ObjectProperty;
        let expr = Expression::ObjectLiteral(vec![ObjectProperty {
            key: Expression::StringLiteral("k".to_string()),
            value: Expression::Identifier("v".to_string()),
            computed: false,
            shorthand: false,
        }]);
        let mut refs = Vec::new();
        collect_identifier_refs(&expr, &mut refs);
        assert_eq!(refs, vec!["v"]);
    }

    // -----------------------------------------------------------------------
    // Assignment to const inside function scope is independent
    // -----------------------------------------------------------------------

    #[test]
    fn const_in_outer_scope_not_visible_in_function() {
        use crate::ast::{BlockStatement, FunctionDeclaration};
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Const,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                Statement::FunctionDeclaration(FunctionDeclaration {
                    name: Some("foo".to_string()),
                    params: vec![],
                    body: BlockStatement {
                        body: vec![
                            // x = 2 inside function — const_bindings was reset,
                            // so no AssignmentToConst here (function has its own scope)
                            expr_stmt(
                                Expression::Assignment {
                                    operator: crate::ast::AssignmentOperator::Assign,
                                    left: Box::new(Expression::Identifier("x".to_string())),
                                    right: Box::new(Expression::NumericLiteral(2)),
                                },
                                3,
                            ),
                        ],
                        span: span(2),
                    },
                    is_async: false,
                    is_generator: false,
                    span: span(2),
                }),
            ],
        );
        let result = analyze(&tree);
        // The function creates a new scope, const tracking is reset
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AssignmentToConst)
        );
    }

    // -----------------------------------------------------------------------
    // Unary expression walking
    // -----------------------------------------------------------------------

    #[test]
    fn typeof_expression_passes() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::Unary {
                    operator: crate::ast::UnaryOperator::Typeof,
                    argument: Box::new(Expression::Identifier("x".to_string())),
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn void_expression_passes() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::Unary {
                    operator: crate::ast::UnaryOperator::Void,
                    argument: Box::new(Expression::NumericLiteral(0)),
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    // -----------------------------------------------------------------------
    // Member expression walking
    // -----------------------------------------------------------------------

    #[test]
    fn member_expression_passes() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::Member {
                    object: Box::new(Expression::Identifier("obj".to_string())),
                    property: Box::new(Expression::Identifier("prop".to_string())),
                    computed: false,
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    // -----------------------------------------------------------------------
    // This expression
    // -----------------------------------------------------------------------

    #[test]
    fn this_expression_passes() {
        let tree = make_tree(ParseGoal::Script, vec![expr_stmt(Expression::This, 1)]);
        let result = analyze(&tree);
        assert!(result.passed());
    }

    // -----------------------------------------------------------------------
    // For-in / For-of
    // -----------------------------------------------------------------------

    #[test]
    fn break_inside_for_in_ok() {
        use crate::ast::{BindingPattern, BreakStatement, ForInStatement, VariableDeclarationKind};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::ForIn(ForInStatement {
                binding: BindingPattern::Identifier("k".to_string()),
                binding_kind: Some(VariableDeclarationKind::Let),
                object: Expression::Identifier("obj".to_string()),
                body: Box::new(Statement::Break(BreakStatement {
                    label: None,
                    span: span(2),
                })),
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::BreakOutsideLoop)
        );
    }

    #[test]
    fn continue_inside_for_of_ok() {
        use crate::ast::{
            BindingPattern, ContinueStatement, ForOfStatement, VariableDeclarationKind,
        };
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::ForOf(ForOfStatement {
                binding: BindingPattern::Identifier("v".to_string()),
                binding_kind: Some(VariableDeclarationKind::Const),
                iterable: Expression::Identifier("arr".to_string()),
                body: Box::new(Statement::Continue(ContinueStatement {
                    label: None,
                    span: span(2),
                })),
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ContinueOutsideLoop)
        );
    }

    #[test]
    fn for_in_bare_binding_passes() {
        use crate::ast::{BindingPattern, ForInStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::ForIn(ForInStatement {
                binding: BindingPattern::Identifier("k".to_string()),
                binding_kind: None,
                object: Expression::Identifier("obj".to_string()),
                body: Box::new(expr_stmt(Expression::Identifier("k".to_string()), 2)),
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    // -----------------------------------------------------------------------
    // New expression
    // -----------------------------------------------------------------------

    #[test]
    fn new_expression_passes() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::New {
                    callee: Box::new(Expression::Identifier("Foo".to_string())),
                    arguments: vec![Expression::NumericLiteral(1)],
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn new_expression_no_args_passes() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::New {
                    callee: Box::new(Expression::Identifier("Foo".to_string())),
                    arguments: Vec::new(),
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    // -----------------------------------------------------------------------
    // Template literal
    // -----------------------------------------------------------------------

    #[test]
    fn template_literal_no_expressions_passes() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::TemplateLiteral {
                    quasis: vec!["hello world".to_string()],
                    expressions: Vec::new(),
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn template_literal_with_expressions_passes() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::TemplateLiteral {
                    quasis: vec!["hello ".to_string(), "!".to_string()],
                    expressions: vec![Expression::Identifier("name".to_string())],
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn template_literal_await_outside_async_flagged() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::TemplateLiteral {
                    quasis: vec!["result: ".to_string(), "".to_string()],
                    expressions: vec![Expression::Await(Box::new(Expression::Identifier(
                        "p".to_string(),
                    )))],
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AwaitOutsideAsync)
        );
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    // -----------------------------------------------------------------------
    // StaticErrorKind Display / as_str completeness
    // -----------------------------------------------------------------------

    #[test]
    fn static_error_kind_display_all_distinct() {
        let kinds = [
            StaticErrorKind::DuplicateBinding,
            StaticErrorKind::ConstWithoutInitializer,
            StaticErrorKind::ImportInScript,
            StaticErrorKind::ExportInScript,
            StaticErrorKind::DuplicateExport,
            StaticErrorKind::AwaitOutsideAsync,
            StaticErrorKind::TemporalDeadZone,
            StaticErrorKind::LexicalVarCollision,
            StaticErrorKind::EmptyDeclaratorList,
            StaticErrorKind::ReservedWordBinding,
            StaticErrorKind::ImportRedeclaration,
            StaticErrorKind::AssignmentToConst,
            StaticErrorKind::ReturnOutsideFunction,
            StaticErrorKind::BreakOutsideLoop,
            StaticErrorKind::ContinueOutsideLoop,
            StaticErrorKind::DuplicateParameter,
            StaticErrorKind::DeleteOfIdentifier,
            StaticErrorKind::EvalArgumentsBinding,
            StaticErrorKind::ForInInitializer,
            StaticErrorKind::DuplicateDestructuringBinding,
        ];
        let strs: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
        assert_eq!(strs.len(), 20, "all 20 Display outputs must be distinct");
    }

    #[test]
    fn static_error_kind_display_matches_as_str() {
        let kinds = [
            StaticErrorKind::DuplicateBinding,
            StaticErrorKind::ConstWithoutInitializer,
            StaticErrorKind::ImportInScript,
            StaticErrorKind::ExportInScript,
            StaticErrorKind::DuplicateExport,
            StaticErrorKind::AwaitOutsideAsync,
            StaticErrorKind::TemporalDeadZone,
            StaticErrorKind::LexicalVarCollision,
            StaticErrorKind::EmptyDeclaratorList,
            StaticErrorKind::ReservedWordBinding,
            StaticErrorKind::ImportRedeclaration,
            StaticErrorKind::AssignmentToConst,
            StaticErrorKind::ReturnOutsideFunction,
            StaticErrorKind::BreakOutsideLoop,
            StaticErrorKind::ContinueOutsideLoop,
            StaticErrorKind::DuplicateParameter,
            StaticErrorKind::DeleteOfIdentifier,
            StaticErrorKind::EvalArgumentsBinding,
            StaticErrorKind::ForInInitializer,
            StaticErrorKind::DuplicateDestructuringBinding,
        ];
        for kind in kinds {
            assert_eq!(kind.to_string(), kind.as_str());
        }
    }

    #[test]
    fn static_error_kind_as_str_original_11() {
        assert_eq!(
            StaticErrorKind::DuplicateBinding.as_str(),
            "duplicate_binding"
        );
        assert_eq!(
            StaticErrorKind::ConstWithoutInitializer.as_str(),
            "const_without_initializer"
        );
        assert_eq!(StaticErrorKind::ImportInScript.as_str(), "import_in_script");
        assert_eq!(StaticErrorKind::ExportInScript.as_str(), "export_in_script");
        assert_eq!(
            StaticErrorKind::DuplicateExport.as_str(),
            "duplicate_export"
        );
        assert_eq!(
            StaticErrorKind::AwaitOutsideAsync.as_str(),
            "await_outside_async"
        );
        assert_eq!(
            StaticErrorKind::TemporalDeadZone.as_str(),
            "temporal_dead_zone"
        );
        assert_eq!(
            StaticErrorKind::LexicalVarCollision.as_str(),
            "lexical_var_collision"
        );
        assert_eq!(
            StaticErrorKind::EmptyDeclaratorList.as_str(),
            "empty_declarator_list"
        );
        assert_eq!(
            StaticErrorKind::ReservedWordBinding.as_str(),
            "reserved_word_binding"
        );
        assert_eq!(
            StaticErrorKind::ImportRedeclaration.as_str(),
            "import_redeclaration"
        );
    }

    #[test]
    fn all_diagnostic_codes_have_prefix() {
        let kinds = [
            StaticErrorKind::DuplicateBinding,
            StaticErrorKind::ConstWithoutInitializer,
            StaticErrorKind::ImportInScript,
            StaticErrorKind::ExportInScript,
            StaticErrorKind::DuplicateExport,
            StaticErrorKind::AwaitOutsideAsync,
            StaticErrorKind::TemporalDeadZone,
            StaticErrorKind::LexicalVarCollision,
            StaticErrorKind::EmptyDeclaratorList,
            StaticErrorKind::ReservedWordBinding,
            StaticErrorKind::ImportRedeclaration,
            StaticErrorKind::AssignmentToConst,
            StaticErrorKind::ReturnOutsideFunction,
            StaticErrorKind::BreakOutsideLoop,
            StaticErrorKind::ContinueOutsideLoop,
            StaticErrorKind::DuplicateParameter,
            StaticErrorKind::DeleteOfIdentifier,
            StaticErrorKind::EvalArgumentsBinding,
            StaticErrorKind::ForInInitializer,
            StaticErrorKind::DuplicateDestructuringBinding,
        ];
        for kind in kinds {
            assert!(
                kind.diagnostic_code().starts_with("FE-STATIC-DIAG-"),
                "{:?} code {} missing prefix",
                kind,
                kind.diagnostic_code()
            );
        }
    }

    #[test]
    fn static_error_kind_ord_consistent() {
        assert!(StaticErrorKind::DuplicateBinding < StaticErrorKind::ConstWithoutInitializer);
        assert!(StaticErrorKind::ConstWithoutInitializer < StaticErrorKind::ImportInScript);
        assert!(StaticErrorKind::DeleteOfIdentifier > StaticErrorKind::DuplicateParameter);
    }

    // -----------------------------------------------------------------------
    // StaticError Display for additional kinds
    // -----------------------------------------------------------------------

    #[test]
    fn static_error_display_import_in_script() {
        let err = StaticError::new(
            StaticErrorKind::ImportInScript,
            "import not allowed in script",
            span(7),
        );
        let s = err.to_string();
        assert!(s.contains("FE-STATIC-DIAG-IMPORT-SCRIPT-0003"));
        assert!(s.contains("import not allowed in script"));
        assert!(s.contains("line 7"));
    }

    #[test]
    fn static_error_display_tdz() {
        let err = StaticError::new(
            StaticErrorKind::TemporalDeadZone,
            "cannot access 'x' before initialization",
            span(12),
        );
        let s = err.to_string();
        assert!(s.contains("FE-STATIC-DIAG-TDZ-0007"));
        assert!(s.contains("cannot access 'x'"));
        assert!(s.contains("line 12"));
    }

    #[test]
    fn static_error_display_delete_of_identifier() {
        let err = StaticError::new(
            StaticErrorKind::DeleteOfIdentifier,
            "delete of bare identifier in strict mode",
            span(99),
        );
        let s = err.to_string();
        assert!(s.contains("FE-STATIC-DIAG-DELETE-IDENT-0017"));
        assert!(s.contains("line 99"));
    }

    // -----------------------------------------------------------------------
    // StaticError canonical_value content verification
    // -----------------------------------------------------------------------

    #[test]
    fn static_error_canonical_value_content() {
        let err = StaticError::new(
            StaticErrorKind::DuplicateExport,
            "duplicate export 'foo'",
            span(5),
        );
        let cv = err.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert_eq!(
                map["kind"],
                CanonicalValue::String("duplicate_export".to_string())
            );
            assert_eq!(
                map["diagnostic_code"],
                CanonicalValue::String("FE-STATIC-DIAG-DUP-EXPORT-0005".to_string())
            );
            assert_eq!(
                map["message"],
                CanonicalValue::String("duplicate export 'foo'".to_string())
            );
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // StaticAnalysisResult edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn analysis_result_passed_zero_errors() {
        let tree = make_tree(ParseGoal::Script, vec![]);
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.error_count(), 0);
    }

    #[test]
    fn analysis_result_serde_module_flag() {
        let tree = make_tree(ParseGoal::Module, vec![import_stmt(Some("x"), "./x.js", 1)]);
        let result = analyze(&tree);
        assert!(result.is_module);
        let json = serde_json::to_string(&result).unwrap();
        let back: StaticAnalysisResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
        assert!(back.is_module);
    }

    // -----------------------------------------------------------------------
    // StaticSemanticsEvent coverage
    // -----------------------------------------------------------------------

    #[test]
    fn event_from_result_with_module_counts() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                import_stmt(Some("a"), "./a.js", 1),
                var_decl(
                    VariableDeclarationKind::Const,
                    "b",
                    Some(Expression::NumericLiteral(1)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        let event = StaticSemanticsEvent::from_result(&result);
        assert!(event.is_module);
        assert_eq!(event.binding_count, 2); // "a" (import) + "b" (const)
        assert_eq!(event.scope_count, 1); // top-level module scope
        assert_eq!(event.error_count, 0);
        assert_eq!(event.outcome, "pass");
    }

    #[test]
    fn event_canonical_value_content() {
        let event = StaticSemanticsEvent {
            component: "static_semantics".to_string(),
            event: "analysis_complete".to_string(),
            outcome: "fail".to_string(),
            error_count: 3,
            binding_count: 5,
            scope_count: 2,
            is_module: true,
        };
        let cv = event.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert_eq!(
                map["component"],
                CanonicalValue::String("static_semantics".to_string())
            );
            assert_eq!(map["outcome"], CanonicalValue::String("fail".to_string()));
            assert_eq!(map["error_count"], CanonicalValue::U64(3));
            assert_eq!(map["binding_count"], CanonicalValue::U64(5));
            assert_eq!(map["scope_count"], CanonicalValue::U64(2));
            assert_eq!(map["is_module"], CanonicalValue::Bool(true));
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // is_reserved_binding completeness
    // -----------------------------------------------------------------------

    #[test]
    fn is_reserved_binding_all_strict_reserved_words() {
        let words = [
            "implements",
            "interface",
            "let",
            "package",
            "private",
            "protected",
            "public",
            "static",
            "yield",
        ];
        for word in words {
            assert!(
                is_reserved_binding(word, true),
                "'{}' should be reserved in module mode",
                word
            );
            assert!(
                !is_reserved_binding(word, false),
                "'{}' should NOT be reserved in script mode",
                word
            );
        }
    }

    #[test]
    fn is_reserved_binding_all_keyword_bindings() {
        let keywords = [
            "break",
            "case",
            "catch",
            "class",
            "const",
            "continue",
            "debugger",
            "default",
            "delete",
            "do",
            "else",
            "enum",
            "export",
            "extends",
            "false",
            "finally",
            "for",
            "function",
            "if",
            "import",
            "in",
            "instanceof",
            "new",
            "null",
            "return",
            "super",
            "switch",
            "this",
            "throw",
            "true",
            "try",
            "typeof",
            "var",
            "void",
            "while",
            "with",
        ];
        for kw in keywords {
            assert!(
                is_reserved_binding(kw, false),
                "'{}' should be a keyword binding",
                kw
            );
            assert!(
                is_reserved_binding(kw, true),
                "'{}' should be a keyword binding in module mode too",
                kw
            );
        }
    }

    // -----------------------------------------------------------------------
    // collect_identifier_refs for untested expression types
    // -----------------------------------------------------------------------

    #[test]
    fn collect_refs_from_unary() {
        let expr = Expression::Unary {
            operator: crate::ast::UnaryOperator::Typeof,
            argument: Box::new(Expression::Identifier("x".to_string())),
        };
        let mut refs = Vec::new();
        collect_identifier_refs(&expr, &mut refs);
        assert_eq!(refs, vec!["x"]);
    }

    #[test]
    fn collect_refs_from_assignment() {
        let expr = Expression::Assignment {
            operator: crate::ast::AssignmentOperator::Assign,
            left: Box::new(Expression::Identifier("a".to_string())),
            right: Box::new(Expression::Identifier("b".to_string())),
        };
        let mut refs = Vec::new();
        collect_identifier_refs(&expr, &mut refs);
        assert_eq!(refs, vec!["a", "b"]);
    }

    #[test]
    fn collect_refs_from_await() {
        let expr = Expression::Await(Box::new(Expression::Identifier("p".to_string())));
        let mut refs = Vec::new();
        collect_identifier_refs(&expr, &mut refs);
        assert_eq!(refs, vec!["p"]);
    }

    #[test]
    fn collect_refs_from_arrow_function_body() {
        let expr = Expression::ArrowFunction {
            params: vec![],
            body: crate::ast::ArrowBody::Expression(Box::new(Expression::Identifier(
                "x".to_string(),
            ))),
            is_async: false,
        };
        let mut refs = Vec::new();
        collect_identifier_refs(&expr, &mut refs);
        assert_eq!(refs, vec!["x"]);
    }

    #[test]
    fn collect_refs_from_new_expression() {
        let expr = Expression::New {
            callee: Box::new(Expression::Identifier("Cls".to_string())),
            arguments: vec![Expression::Identifier("arg".to_string())],
        };
        let mut refs = Vec::new();
        collect_identifier_refs(&expr, &mut refs);
        assert_eq!(refs, vec!["Cls", "arg"]);
    }

    #[test]
    fn collect_refs_from_template_literal() {
        let expr = Expression::TemplateLiteral {
            quasis: vec!["pre ".to_string(), " post".to_string()],
            expressions: vec![Expression::Identifier("val".to_string())],
        };
        let mut refs = Vec::new();
        collect_identifier_refs(&expr, &mut refs);
        assert_eq!(refs, vec!["val"]);
    }

    #[test]
    fn collect_refs_from_member_expression() {
        let expr = Expression::Member {
            object: Box::new(Expression::Identifier("obj".to_string())),
            property: Box::new(Expression::Identifier("prop".to_string())),
            computed: false,
        };
        let mut refs = Vec::new();
        collect_identifier_refs(&expr, &mut refs);
        assert_eq!(refs, vec!["obj", "prop"]);
    }

    // -----------------------------------------------------------------------
    // walk_expression: await detection in additional expression types
    // -----------------------------------------------------------------------

    #[test]
    fn await_nested_in_new_detected() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::New {
                    callee: Box::new(Expression::Identifier("Foo".to_string())),
                    arguments: vec![Expression::Await(Box::new(Expression::Identifier(
                        "p".to_string(),
                    )))],
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AwaitOutsideAsync)
        );
    }

    #[test]
    fn await_nested_in_unary_detected() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::Unary {
                    operator: crate::ast::UnaryOperator::Typeof,
                    argument: Box::new(Expression::Await(Box::new(Expression::Identifier(
                        "p".to_string(),
                    )))),
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AwaitOutsideAsync)
        );
    }

    #[test]
    fn await_nested_in_member_detected() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::Member {
                    object: Box::new(Expression::Await(Box::new(Expression::Identifier(
                        "p".to_string(),
                    )))),
                    property: Box::new(Expression::Identifier("then".to_string())),
                    computed: false,
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AwaitOutsideAsync)
        );
    }

    #[test]
    fn await_nested_in_assignment_detected() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::Assignment {
                    operator: crate::ast::AssignmentOperator::Assign,
                    left: Box::new(Expression::Identifier("x".to_string())),
                    right: Box::new(Expression::Await(Box::new(Expression::Identifier(
                        "p".to_string(),
                    )))),
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AwaitOutsideAsync)
        );
    }

    #[test]
    fn await_nested_in_arrow_body_detected() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::ArrowFunction {
                    params: vec![],
                    body: crate::ast::ArrowBody::Expression(Box::new(Expression::Await(Box::new(
                        Expression::Identifier("p".to_string()),
                    )))),
                    is_async: false,
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AwaitOutsideAsync)
        );
    }

    // -----------------------------------------------------------------------
    // Context flag edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn continue_in_switch_without_loop_errors() {
        use crate::ast::{ContinueStatement, SwitchCase, SwitchStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::Switch(SwitchStatement {
                discriminant: Expression::Identifier("x".to_string()),
                cases: vec![SwitchCase {
                    test: Some(Expression::NumericLiteral(1)),
                    consequent: vec![Statement::Continue(ContinueStatement {
                        label: None,
                        span: span(3),
                    })],
                    span: span(2),
                }],
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ContinueOutsideLoop),
            "continue in switch (no enclosing loop) should error"
        );
    }

    #[test]
    fn duplicate_param_in_script_allowed() {
        use crate::ast::{BindingPattern, BlockStatement, FunctionDeclaration, FunctionParam};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::FunctionDeclaration(FunctionDeclaration {
                name: Some("foo".to_string()),
                params: vec![
                    FunctionParam {
                        pattern: BindingPattern::Identifier("a".to_string()),
                        span: span(1),
                    },
                    FunctionParam {
                        pattern: BindingPattern::Identifier("a".to_string()),
                        span: span(1),
                    },
                ],
                body: BlockStatement {
                    body: vec![],
                    span: span(2),
                },
                is_async: false,
                is_generator: false,
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        // Duplicate params only flagged in module (strict) mode
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateParameter)
        );
    }

    // -----------------------------------------------------------------------
    // TDZ detection in additional contexts
    // -----------------------------------------------------------------------

    #[test]
    fn tdz_in_member_expression() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                expr_stmt(
                    Expression::Member {
                        object: Box::new(Expression::Identifier("x".to_string())),
                        property: Box::new(Expression::Identifier("prop".to_string())),
                        computed: false,
                    },
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::TemporalDeadZone)
        );
    }

    #[test]
    fn tdz_in_template_literal() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                expr_stmt(
                    Expression::TemplateLiteral {
                        quasis: vec!["val: ".to_string(), "".to_string()],
                        expressions: vec![Expression::Identifier("x".to_string())],
                    },
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Const,
                    "x",
                    Some(Expression::NumericLiteral(42)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::TemporalDeadZone)
        );
    }

    // -----------------------------------------------------------------------
    // Throw and if statement analysis
    // -----------------------------------------------------------------------

    #[test]
    fn throw_with_await_in_script_detected() {
        use crate::ast::ThrowStatement;
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::Throw(ThrowStatement {
                argument: Expression::Await(Box::new(Expression::Identifier("err".to_string()))),
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AwaitOutsideAsync)
        );
    }

    #[test]
    fn if_condition_await_detected() {
        use crate::ast::IfStatement;
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::If(IfStatement {
                condition: Expression::Await(Box::new(Expression::Identifier("p".to_string()))),
                consequent: Box::new(expr_stmt(Expression::NumericLiteral(1), 2)),
                alternate: None,
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AwaitOutsideAsync)
        );
    }

    // -----------------------------------------------------------------------
    // eval/arguments binding in strict mode (ES2020 §12.1.1)
    // -----------------------------------------------------------------------

    #[test]
    fn eval_as_binding_in_module_detected() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![var_decl(
                VariableDeclarationKind::Let,
                "eval",
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::EvalArgumentsBinding),
            "eval as let binding in module should be flagged"
        );
    }

    #[test]
    fn arguments_as_binding_in_module_detected() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![var_decl(
                VariableDeclarationKind::Const,
                "arguments",
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::EvalArgumentsBinding),
            "arguments as const binding in module should be flagged"
        );
    }

    #[test]
    fn eval_as_binding_in_script_allowed() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Var,
                "eval",
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::EvalArgumentsBinding),
            "eval as var binding in sloppy mode should be allowed"
        );
    }

    #[test]
    fn arguments_as_binding_in_script_allowed() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(VariableDeclarationKind::Var, "arguments", None, 1)],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::EvalArgumentsBinding),
            "arguments as var binding in sloppy mode should be allowed"
        );
    }

    #[test]
    fn eval_as_import_binding_in_module_detected() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![import_stmt(Some("eval"), "some-module", 1)],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::EvalArgumentsBinding),
            "eval as import binding in module should be flagged"
        );
    }

    // -----------------------------------------------------------------------
    // Arrow function parameter validation
    // -----------------------------------------------------------------------

    #[test]
    fn arrow_duplicate_params_in_module_detected() {
        use crate::ast::{ArrowBody, BindingPattern, FunctionParam};
        let tree = make_tree(
            ParseGoal::Module,
            vec![expr_stmt(
                Expression::ArrowFunction {
                    params: vec![
                        FunctionParam {
                            pattern: BindingPattern::Identifier("a".to_string()),
                            span: span(1),
                        },
                        FunctionParam {
                            pattern: BindingPattern::Identifier("a".to_string()),
                            span: span(1),
                        },
                    ],
                    body: ArrowBody::Expression(Box::new(Expression::Identifier("a".to_string()))),
                    is_async: false,
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateParameter),
            "duplicate arrow params in module should be flagged"
        );
    }

    #[test]
    fn arrow_block_body_return_allowed() {
        use crate::ast::{
            ArrowBody, BindingPattern, BlockStatement, FunctionParam, ReturnStatement,
        };
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::ArrowFunction {
                    params: vec![FunctionParam {
                        pattern: BindingPattern::Identifier("x".to_string()),
                        span: span(1),
                    }],
                    body: ArrowBody::Block(BlockStatement {
                        body: vec![Statement::Return(ReturnStatement {
                            argument: Some(Expression::Identifier("x".to_string())),
                            span: span(2),
                        })],
                        span: span(1),
                    }),
                    is_async: false,
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ReturnOutsideFunction),
            "return inside arrow function block body should be allowed"
        );
    }

    #[test]
    fn arrow_block_body_const_tracked() {
        use crate::ast::{ArrowBody, BlockStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::ArrowFunction {
                    params: vec![],
                    body: ArrowBody::Block(BlockStatement {
                        body: vec![
                            var_decl(
                                VariableDeclarationKind::Const,
                                "x",
                                Some(Expression::NumericLiteral(1)),
                                2,
                            ),
                            expr_stmt(
                                Expression::Assignment {
                                    operator: crate::ast::AssignmentOperator::Assign,
                                    left: Box::new(Expression::Identifier("x".to_string())),
                                    right: Box::new(Expression::NumericLiteral(2)),
                                },
                                3,
                            ),
                        ],
                        span: span(1),
                    }),
                    is_async: false,
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AssignmentToConst),
            "assignment to const inside arrow body should be detected"
        );
    }

    // -----------------------------------------------------------------------
    // Destructuring duplicate binding
    // -----------------------------------------------------------------------

    #[test]
    fn destructuring_duplicate_in_object_pattern() {
        use crate::ast::{BindingPattern, ObjectPatternProperty};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Let,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::ObjectPattern(vec![
                        ObjectPatternProperty {
                            key: Expression::Identifier("a".to_string()),
                            value: BindingPattern::Identifier("x".to_string()),
                            computed: false,
                            shorthand: false,
                        },
                        ObjectPatternProperty {
                            key: Expression::Identifier("b".to_string()),
                            value: BindingPattern::Identifier("x".to_string()),
                            computed: false,
                            shorthand: false,
                        },
                    ]),
                    initializer: Some(Expression::Identifier("obj".to_string())),
                    span: span(1),
                }],
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateDestructuringBinding),
            "duplicate x in destructuring should be flagged"
        );
    }

    #[test]
    fn destructuring_no_duplicate_ok() {
        use crate::ast::{BindingPattern, ObjectPatternProperty};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Let,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::ObjectPattern(vec![
                        ObjectPatternProperty {
                            key: Expression::Identifier("a".to_string()),
                            value: BindingPattern::Identifier("x".to_string()),
                            computed: false,
                            shorthand: false,
                        },
                        ObjectPatternProperty {
                            key: Expression::Identifier("b".to_string()),
                            value: BindingPattern::Identifier("y".to_string()),
                            computed: false,
                            shorthand: false,
                        },
                    ]),
                    initializer: Some(Expression::Identifier("obj".to_string())),
                    span: span(1),
                }],
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateDestructuringBinding),
            "distinct names in destructuring should not error"
        );
    }

    #[test]
    fn destructuring_duplicate_in_array_pattern() {
        use crate::ast::BindingPattern;
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Const,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::ArrayPattern(vec![
                        Some(BindingPattern::Identifier("a".to_string())),
                        Some(BindingPattern::Identifier("a".to_string())),
                    ]),
                    initializer: Some(Expression::ArrayLiteral(vec![
                        Some(Expression::NumericLiteral(1)),
                        Some(Expression::NumericLiteral(2)),
                    ])),
                    span: span(1),
                }],
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateDestructuringBinding),
            "duplicate a in array destructuring should be flagged"
        );
    }

    // -----------------------------------------------------------------------
    // For-in/for-of scope creation and binding validation
    // -----------------------------------------------------------------------

    #[test]
    fn for_in_creates_scope_with_let_binding() {
        use crate::ast::{BindingPattern, ForInStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::ForIn(ForInStatement {
                binding: BindingPattern::Identifier("key".to_string()),
                binding_kind: Some(VariableDeclarationKind::Let),
                object: Expression::Identifier("obj".to_string()),
                body: Box::new(expr_stmt(Expression::Identifier("key".to_string()), 2)),
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(result.passed(), "for-in with let binding should pass");
        assert!(
            result.scopes.len() >= 2,
            "for-in should create a child scope (got {} scopes)",
            result.scopes.len()
        );
        assert!(
            result.bindings.iter().any(|b| b.name == "key"),
            "for-in binding 'key' should be registered"
        );
    }

    #[test]
    fn for_of_creates_scope_with_const_binding() {
        use crate::ast::{BindingPattern, ForOfStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::ForOf(ForOfStatement {
                binding: BindingPattern::Identifier("item".to_string()),
                binding_kind: Some(VariableDeclarationKind::Const),
                iterable: Expression::Identifier("arr".to_string()),
                body: Box::new(expr_stmt(Expression::Identifier("item".to_string()), 2)),
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(result.passed(), "for-of with const binding should pass");
        assert!(
            result.bindings.iter().any(|b| b.name == "item"),
            "for-of binding 'item' should be registered"
        );
    }

    #[test]
    fn for_in_reserved_binding_detected_in_module() {
        use crate::ast::{BindingPattern, ForInStatement};
        let tree = make_tree(
            ParseGoal::Module,
            vec![Statement::ForIn(ForInStatement {
                binding: BindingPattern::Identifier("eval".to_string()),
                binding_kind: Some(VariableDeclarationKind::Let),
                object: Expression::Identifier("obj".to_string()),
                body: Box::new(expr_stmt(Expression::NumericLiteral(1), 2)),
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::EvalArgumentsBinding),
            "for-in binding 'eval' in module should be flagged"
        );
    }

    #[test]
    fn for_of_destructuring_duplicate_detected() {
        use crate::ast::{BindingPattern, ForOfStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::ForOf(ForOfStatement {
                binding: BindingPattern::ArrayPattern(vec![
                    Some(BindingPattern::Identifier("x".to_string())),
                    Some(BindingPattern::Identifier("x".to_string())),
                ]),
                binding_kind: Some(VariableDeclarationKind::Let),
                iterable: Expression::Identifier("pairs".to_string()),
                body: Box::new(expr_stmt(Expression::NumericLiteral(1), 2)),
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateDestructuringBinding),
            "duplicate x in for-of destructuring should be flagged"
        );
    }

    // -----------------------------------------------------------------------
    // New error kinds as_str and diagnostic_code coverage
    // -----------------------------------------------------------------------

    #[test]
    fn new_error_kinds_v2_as_str() {
        assert_eq!(
            StaticErrorKind::EvalArgumentsBinding.as_str(),
            "eval_arguments_binding"
        );
        assert_eq!(
            StaticErrorKind::ForInInitializer.as_str(),
            "for_in_initializer"
        );
        assert_eq!(
            StaticErrorKind::DuplicateDestructuringBinding.as_str(),
            "duplicate_destructuring_binding"
        );
    }

    #[test]
    fn new_error_kinds_v2_diagnostic_codes() {
        assert_eq!(
            StaticErrorKind::EvalArgumentsBinding.diagnostic_code(),
            "FE-STATIC-DIAG-EVAL-ARGS-0018"
        );
        assert_eq!(
            StaticErrorKind::ForInInitializer.diagnostic_code(),
            "FE-STATIC-DIAG-FOR-IN-INIT-0019"
        );
        assert_eq!(
            StaticErrorKind::DuplicateDestructuringBinding.diagnostic_code(),
            "FE-STATIC-DIAG-DUP-DESTR-0020"
        );
    }

    #[test]
    fn new_error_kinds_v2_serde_roundtrip() {
        let kinds = [
            StaticErrorKind::EvalArgumentsBinding,
            StaticErrorKind::ForInInitializer,
            StaticErrorKind::DuplicateDestructuringBinding,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let back: StaticErrorKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn arrow_destructuring_params_dup_detected() {
        use crate::ast::{ArrowBody, BindingPattern, FunctionParam, ObjectPatternProperty};
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::ArrowFunction {
                    params: vec![FunctionParam {
                        pattern: BindingPattern::ObjectPattern(vec![
                            ObjectPatternProperty {
                                key: Expression::Identifier("a".to_string()),
                                value: BindingPattern::Identifier("x".to_string()),
                                computed: false,
                                shorthand: false,
                            },
                            ObjectPatternProperty {
                                key: Expression::Identifier("b".to_string()),
                                value: BindingPattern::Identifier("x".to_string()),
                                computed: false,
                                shorthand: false,
                            },
                        ]),
                        span: span(1),
                    }],
                    body: ArrowBody::Expression(Box::new(Expression::Identifier("x".to_string()))),
                    is_async: false,
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateDestructuringBinding),
            "duplicate binding in arrow destructuring param should be flagged"
        );
    }

    #[test]
    fn arrow_block_body_break_outside_loop_detected() {
        use crate::ast::{ArrowBody, BlockStatement, BreakStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::ArrowFunction {
                    params: vec![],
                    body: ArrowBody::Block(BlockStatement {
                        body: vec![Statement::Break(BreakStatement {
                            label: None,
                            span: span(2),
                        })],
                        span: span(1),
                    }),
                    is_async: false,
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::BreakOutsideLoop),
            "break inside arrow block body (no loop) should be detected"
        );
    }

    #[test]
    fn arrow_block_body_continue_in_for_ok() {
        use crate::ast::{ArrowBody, BlockStatement, ContinueStatement, ForInStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::ArrowFunction {
                    params: vec![],
                    body: ArrowBody::Block(BlockStatement {
                        body: vec![Statement::ForIn(ForInStatement {
                            binding: BindingPattern::Identifier("k".to_string()),
                            binding_kind: Some(VariableDeclarationKind::Const),
                            object: Expression::Identifier("obj".to_string()),
                            body: Box::new(Statement::Continue(ContinueStatement {
                                label: None,
                                span: span(3),
                            })),
                            span: span(2),
                        })],
                        span: span(1),
                    }),
                    is_async: false,
                },
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ContinueOutsideLoop),
            "continue inside for-in inside arrow block body should be OK"
        );
    }

    // -----------------------------------------------------------------------
    // Export named clause specifier extraction
    // -----------------------------------------------------------------------

    #[test]
    fn extract_export_specifier_names_single() {
        let names = super::extract_export_specifier_names("{ a }");
        assert_eq!(names, vec!["a"]);
    }

    #[test]
    fn extract_export_specifier_names_multiple() {
        let names = super::extract_export_specifier_names("{ a, b, c }");
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn extract_export_specifier_names_with_alias() {
        let names = super::extract_export_specifier_names("{ a as x, b }");
        assert_eq!(names, vec!["x", "b"]);
    }

    #[test]
    fn extract_export_specifier_names_empty_clause() {
        let names = super::extract_export_specifier_names("{ }");
        assert!(names.is_empty());
    }

    #[test]
    fn extract_export_specifier_names_not_brace() {
        let names = super::extract_export_specifier_names("foo");
        assert!(names.is_empty());
    }

    #[test]
    fn duplicate_export_via_named_specifiers() {
        // export { a } followed by export { a } should detect duplicate "a"
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                Statement::Export(ExportDeclaration {
                    kind: ExportKind::NamedClause("{ a }".to_string()),
                    span: span(1),
                }),
                Statement::Export(ExportDeclaration {
                    kind: ExportKind::NamedClause("{ a }".to_string()),
                    span: span(2),
                }),
            ],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateExport),
            "duplicate 'a' in separate named export clauses should be detected"
        );
    }

    #[test]
    fn duplicate_export_across_default_and_named() {
        // export default 42; export { x as default } — duplicate "default"
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                export_default(Expression::NumericLiteral(42), 1),
                Statement::Export(ExportDeclaration {
                    kind: ExportKind::NamedClause("{ x as default }".to_string()),
                    span: span(2),
                }),
            ],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateExport),
            "export default + export {{x as default}} should detect duplicate 'default'"
        );
    }

    #[test]
    fn distinct_named_exports_ok() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                Statement::Export(ExportDeclaration {
                    kind: ExportKind::NamedClause("{ a, b }".to_string()),
                    span: span(1),
                }),
                Statement::Export(ExportDeclaration {
                    kind: ExportKind::NamedClause("{ c }".to_string()),
                    span: span(2),
                }),
            ],
        );
        let result = analyze(&tree);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateExport),
            "distinct specifier names across export clauses should pass"
        );
    }

    // -----------------------------------------------------------------------
    // Static error kind coverage
    // -----------------------------------------------------------------------

    #[test]
    fn static_error_kind_as_str_covers_all_variants() {
        // Ensure every variant returns a non-empty stable string.
        let all_kinds = vec![
            StaticErrorKind::DuplicateBinding,
            StaticErrorKind::ConstWithoutInitializer,
            StaticErrorKind::ImportInScript,
            StaticErrorKind::ExportInScript,
            StaticErrorKind::DuplicateExport,
            StaticErrorKind::AwaitOutsideAsync,
            StaticErrorKind::TemporalDeadZone,
            StaticErrorKind::LexicalVarCollision,
            StaticErrorKind::EmptyDeclaratorList,
            StaticErrorKind::ReservedWordBinding,
            StaticErrorKind::ImportRedeclaration,
            StaticErrorKind::AssignmentToConst,
            StaticErrorKind::ReturnOutsideFunction,
            StaticErrorKind::BreakOutsideLoop,
            StaticErrorKind::ContinueOutsideLoop,
            StaticErrorKind::DuplicateParameter,
            StaticErrorKind::DeleteOfIdentifier,
            StaticErrorKind::EvalArgumentsBinding,
            StaticErrorKind::ForInInitializer,
            StaticErrorKind::DuplicateDestructuringBinding,
        ];
        for kind in &all_kinds {
            let s = kind.as_str();
            assert!(!s.is_empty(), "as_str() must not be empty for {:?}", kind);
            let code = kind.diagnostic_code();
            assert!(
                code.starts_with("FE-STATIC-DIAG-"),
                "diagnostic code must start with FE-STATIC-DIAG- for {:?}",
                kind
            );
        }
        // Verify unique as_str values
        let strs: BTreeSet<_> = all_kinds.iter().map(|k| k.as_str()).collect();
        assert_eq!(
            strs.len(),
            all_kinds.len(),
            "all error kinds should have unique as_str"
        );
        // Verify unique diagnostic codes
        let codes: BTreeSet<_> = all_kinds.iter().map(|k| k.diagnostic_code()).collect();
        assert_eq!(
            codes.len(),
            all_kinds.len(),
            "all error kinds should have unique diagnostic codes"
        );
    }

    #[test]
    fn static_error_display_includes_diagnostic_code() {
        let err = StaticError::new(StaticErrorKind::DuplicateBinding, "test message", span(5));
        let display = format!("{}", err);
        assert!(
            display.contains("FE-STATIC-DIAG-DUP-BINDING-0001"),
            "Display should include diagnostic code: {}",
            display
        );
        assert!(
            display.contains("test message"),
            "Display should include message: {}",
            display
        );
    }

    #[test]
    fn static_analysis_result_canonical_value_has_required_keys() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        );
        let result = analyze(&tree);
        let cv = result.canonical_value();
        if let CanonicalValue::Map(map) = &cv {
            assert!(map.contains_key("bindings"));
            assert!(map.contains_key("errors"));
            assert!(map.contains_key("is_module"));
            assert!(map.contains_key("scopes"));
        } else {
            panic!("canonical_value should be a Map");
        }
    }

    #[test]
    fn static_semantics_event_canonical_value_keys() {
        let tree = make_tree(ParseGoal::Module, vec![]);
        let result = analyze(&tree);
        let event = StaticSemanticsEvent::from_result(&result);
        assert_eq!(event.component, "static_semantics");
        assert_eq!(event.event, "analysis_complete");
        assert_eq!(event.outcome, "pass");
        assert!(event.is_module);
        let cv = event.canonical_value();
        if let CanonicalValue::Map(map) = &cv {
            assert!(map.contains_key("component"));
            assert!(map.contains_key("event"));
            assert!(map.contains_key("outcome"));
            assert!(map.contains_key("is_module"));
            assert!(map.contains_key("binding_count"));
            assert!(map.contains_key("error_count"));
            assert!(map.contains_key("scope_count"));
        } else {
            panic!("event canonical_value should be a Map");
        }
    }

    #[test]
    fn for_of_loop_binding_scope_created() {
        use crate::ast::{BlockStatement, ForOfStatement};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::ForOf(ForOfStatement {
                binding: BindingPattern::Identifier("item".to_string()),
                binding_kind: Some(VariableDeclarationKind::Const),
                iterable: Expression::Identifier("items".to_string()),
                body: Box::new(Statement::Block(BlockStatement {
                    body: vec![],
                    span: span(2),
                })),
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        // Should have top scope + for-of scope + block scope
        assert!(
            result.scopes.len() >= 2,
            "for-of should create its own scope"
        );
    }

    #[test]
    fn for_in_reserved_binding_detected() {
        use crate::ast::{BlockStatement, ForInStatement};
        let tree = make_tree(
            ParseGoal::Module,
            vec![Statement::ForIn(ForInStatement {
                binding: BindingPattern::Identifier("package".to_string()),
                binding_kind: Some(VariableDeclarationKind::Let),
                object: Expression::Identifier("obj".to_string()),
                body: Box::new(Statement::Block(BlockStatement {
                    body: vec![],
                    span: span(2),
                })),
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ReservedWordBinding),
            "'package' is strict-mode reserved and should be flagged in module code"
        );
    }

    #[test]
    fn destructuring_in_for_of_duplicate_detected() {
        use crate::ast::{BlockStatement, ForOfStatement, ObjectPatternProperty};
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::ForOf(ForOfStatement {
                binding: BindingPattern::ObjectPattern(vec![
                    ObjectPatternProperty {
                        key: Expression::Identifier("a".to_string()),
                        value: BindingPattern::Identifier("x".to_string()),
                        computed: false,
                        shorthand: false,
                    },
                    ObjectPatternProperty {
                        key: Expression::Identifier("b".to_string()),
                        value: BindingPattern::Identifier("x".to_string()),
                        computed: false,
                        shorthand: false,
                    },
                ]),
                binding_kind: Some(VariableDeclarationKind::Const),
                iterable: Expression::Identifier("arr".to_string()),
                body: Box::new(Statement::Block(BlockStatement {
                    body: vec![],
                    span: span(2),
                })),
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateDestructuringBinding),
            "duplicate 'x' in for-of destructuring pattern should be detected"
        );
    }
}
