use super::*;

/// recognized fs host method (`<name>.readFileSync/writeFileSync(...)`) somewhere
/// in a top-level expression or variable initializer of `body` (bd-1xl17.a
/// usage-lookahead).
///
/// Only such names are aliased, so that the fs *binding* form lowers to fs:
/// HostCalls; a `const fs = require('fs')` that is never used as an fs method is
/// deliberately left to the existing ambient-authority denial (preserving the
/// `require(...)` rejection contract for bare/unused requires without any test
/// changes). The usage scan covers top-level positions and fails closed for
/// deeper nesting is covered by the timers-family deep statement walker.
pub(super) fn confirmed_fs_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            for d in &vd.declarations {
                if let (BindingPattern::Identifier(name), Some(init)) = (&d.pattern, &d.initializer)
                    && is_require_fs_module_initializer(init, binding_lookup)
                {
                    candidates.insert(name.clone());
                }
            }
        }
    }
    if candidates.is_empty() {
        return candidates;
    }

    let mut used = BTreeSet::new();
    for name in &candidates {
        let single: BTreeSet<String> = std::iter::once(name.clone()).collect();
        if body.iter().any(|stmt| {
            timers_scan_statement_deep(stmt, &|candidate| {
                is_fs_alias_constant_member(candidate, &single)
                    || matches!(candidate,
                        Expression::Call { callee, .. } | Expression::OptionalCall { callee, .. }
                            if is_fs_alias_method_callee(callee, &single))
            })
        }) {
            used.insert(name.clone());
        }
    }
    used
}

/// Recognize an idiomatic synchronous fs read/write call and return its `fs:`
/// hostcall capability so it lowers to a real, capability-gated host effect
/// instead of a `CallMethod` that would fault on the (non-existent) fs module
/// object (bd-1xl17 + bd-1xl17.a). Two receiver shapes are matched, both purely
/// syntactic (there is no real `fs` heap object; `require('fs')` resolves to
/// `ModuleNotFound` at runtime):
///   * inline:  `require('fs').readFileSync(path)` / `.writeFileSync(path, data)`
///   * binding: `fs.readFileSync(path)` where `fs` was aliased via
///     `const fs = require('fs')` — recorded as a NUL-sentinel in
///     `binding_lookup` by the program pre-scan, gated on actual usage so the
///     ambient-authority denial of bare/unused requires is preserved.
///
/// Only the `fs`/`node:fs` specifier and the synchronous `readFileSync` /
/// `writeFileSync` methods are matched (async / ESM / return-shape variants are
/// tracked separately as bd-1xl17.b–.d).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FsBuiltinCall {
    pub(super) capability: &'static str,
    pub(super) operation: FsOperation,
    pub(super) min_args: usize,
    pub(super) max_args: usize,
}

impl FsBuiltinCall {
    pub(super) fn accepts_arity(self, arg_count: usize) -> bool {
        (self.min_args..=self.max_args).contains(&arg_count)
    }

    pub(super) fn carries_operation_discriminator(self) -> bool {
        !matches!(self.operation, FsOperation::Read | FsOperation::Write)
    }

    pub(super) fn discriminator(self) -> String {
        format!("\0fsop:{}", self.operation.as_str())
    }
}

pub(super) fn is_fs_module_object(
    expression: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    match expression {
        Expression::Call { .. } => is_require_fs_module_initializer(expression, binding_lookup),
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&fs_module_alias_sentinel(alias))
        }
        _ => false,
    }
}

pub(super) fn fs_constants_member_value(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<i64> {
    if computed {
        return None;
    }
    let constant = well_formed_static_name(property)?;
    let Expression::Member {
        object: fs_object,
        property: constants_property,
        computed: false,
        ..
    } = object
    else {
        return None;
    };
    if !is_fs_module_object(fs_object, binding_lookup)
        || !well_formed_static_name(constants_property).is_some_and(|name| name == "constants")
    {
        return None;
    }
    match constant {
        "F_OK" => Some(0),
        "X_OK" => Some(1),
        "W_OK" => Some(2),
        "R_OK" => Some(4),
        _ => None,
    }
}

pub(super) fn fs_sync_builtin_spec(method: &str) -> Option<FsBuiltinCall> {
    let (capability, operation, min_args, max_args) = match method {
        "readFileSync" => ("fs:read", FsOperation::Read, 1, 2),
        "writeFileSync" => ("fs:write", FsOperation::Write, 2, 3),
        "appendFileSync" => ("fs:write", FsOperation::Append, 2, 3),
        "existsSync" => ("fs:read", FsOperation::Exists, 1, 1),
        "mkdirSync" => ("fs:write", FsOperation::Mkdir, 1, 2),
        "readdirSync" => ("fs:read", FsOperation::ReadDir, 1, 2),
        "statSync" => ("fs:read", FsOperation::Stat, 1, 2),
        "lstatSync" => ("fs:read", FsOperation::Lstat, 1, 2),
        "symlinkSync" => ("fs:write", FsOperation::Symlink, 2, 3),
        "readlinkSync" => ("fs:read", FsOperation::ReadLink, 1, 2),
        "renameSync" => ("fs:write", FsOperation::Rename, 2, 2),
        "copyFileSync" => ("fs:write", FsOperation::CopyFile, 2, 3),
        "unlinkSync" => ("fs:write", FsOperation::Unlink, 1, 1),
        "rmSync" => ("fs:write", FsOperation::Remove, 1, 2),
        "rmdirSync" => ("fs:write", FsOperation::RemoveDir, 1, 2),
        "truncateSync" => ("fs:write", FsOperation::Truncate, 1, 2),
        "accessSync" => ("fs:read", FsOperation::Access, 1, 2),
        "chmodSync" => ("fs:write", FsOperation::Chmod, 2, 2),
        "utimesSync" => ("fs:write", FsOperation::Utimes, 3, 3),
        "realpathSync" => ("fs:read", FsOperation::Realpath, 1, 2),
        "mkdtempSync" => ("fs:write", FsOperation::Mkdtemp, 1, 2),
        // Numeric fd lifecycle (bd-zco6t). openSync keeps the existing
        // `fs:write` capability tag rather than growing an `fs:open` alias
        // (this table deliberately never adds capability aliases): an open
        // may create or truncate depending on its flags, so write authority
        // is the conservative gate. writeSync/readSync carry a NUMERIC fd as
        // their first argument — the interpreter's fd-shaped dispatch reads
        // it from the argument list, never as a path.
        "openSync" => ("fs:write", FsOperation::Open, 1, 3),
        "writeSync" => ("fs:write", FsOperation::WriteFd, 2, 5),
        "readSync" => ("fs:read", FsOperation::ReadFd, 2, 5),
        "fsyncSync" => ("fs:write", FsOperation::Fsync, 1, 1),
        "closeSync" => ("fs:write", FsOperation::CloseFd, 1, 1),
        _ => return None,
    };
    Some(FsBuiltinCall {
        capability,
        operation,
        min_args,
        max_args,
    })
}

pub(super) fn fs_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<FsBuiltinCall> {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return None;
    };
    if !is_fs_module_object(object, binding_lookup) {
        return None;
    }
    let method = well_formed_static_name(property)?;
    fs_sync_builtin_spec(method)
}

/// bd-tu0c3: true when `specifier` names the Node path module — `path` or
/// `node:path`. Shared by the path require-initializer recognizer and the
/// inline-receiver recognizer so the accepted specifier set stays identical
/// across both idiomatic shapes.
pub(super) fn is_path_module_specifier(specifier: &str) -> bool {
    specifier == "path" || specifier == "node:path"
}

/// bd-tu0c3: sentinel key recording that `name` is bound to the `path`/
/// `node:path` module via `const <name> = require('path')` AND used as a
/// recognized `path` builtin. Mirror of [`fs_module_alias_sentinel`]: stored in
/// the lowering `binding_lookup`; the leading NUL cannot occur in a JS
/// identifier so the sentinel never collides with or shadows a real binding.
pub(super) fn path_module_alias_sentinel(name: &str) -> String {
    format!("\0pathmod\0{name}")
}

/// bd-tu0c3: true when `expr` is exactly `require('path')` /
/// `require('node:path')` with an unshadowed `require` — the initializer shape
/// that aliases the path module in `const path = require('path')`. Mirror of
/// [`is_require_fs_module_initializer`].
pub(super) fn is_require_path_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    if !matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
    {
        return false;
    }
    matches!(arguments.as_slice(), [spec]
        if well_formed_string_literal(spec).is_some_and(is_path_module_specifier))
}

/// Which Node `path` namespace a recognized receiver selects (bd-tu0c3). The
/// default `path` object on linux IS the posix implementation, so both the bare
/// module receiver and `.posix` map to [`PathModuleNamespace::Posix`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PathModuleNamespace {
    Posix,
    Win32,
}

/// bd-tu0c3: capability tag for a recognized `path` method in `namespace`.
/// Single source of truth shared by the usage-lookahead scan and the call-site
/// recognizer, so the confirmed-alias gate can never diverge from what the
/// lowering actually rewrites (an alias is confirmed only by a usage the call
/// arm will really intercept). The win32 surface is deliberately the small
/// separator-sensitive subset (join/basename/isAbsolute); everything else on
/// `path.win32` is unrecognized and falls through fail-closed.
pub(super) fn path_method_capability(
    namespace: PathModuleNamespace,
    method: &str,
) -> Option<&'static str> {
    match namespace {
        PathModuleNamespace::Posix => match method {
            "join" => Some("builtin:PathJoin"),
            "basename" => Some("builtin:PathBasename"),
            "dirname" => Some("builtin:PathDirname"),
            "extname" => Some("builtin:PathExtname"),
            "normalize" => Some("builtin:PathNormalize"),
            "resolve" => Some("builtin:PathResolve"),
            "relative" => Some("builtin:PathRelative"),
            "isAbsolute" => Some("builtin:PathIsAbsolute"),
            "parse" => Some("builtin:PathParse"),
            "format" => Some("builtin:PathFormat"),
            _ => None,
        },
        PathModuleNamespace::Win32 => match method {
            "join" => Some("builtin:PathWin32Join"),
            "basename" => Some("builtin:PathWin32Basename"),
            "isAbsolute" => Some("builtin:PathWin32IsAbsolute"),
            _ => None,
        },
    }
}

/// bd-tu0c3: the constant value of a recognized `path` namespace property read
/// (`sep` / `delimiter`), per Node.
pub(super) fn path_namespace_property_constant(
    namespace: PathModuleNamespace,
    property: &str,
) -> Option<&'static str> {
    match (namespace, property) {
        (PathModuleNamespace::Posix, "sep") => Some("/"),
        (PathModuleNamespace::Posix, "delimiter") => Some(":"),
        (PathModuleNamespace::Win32, "sep") => Some("\\"),
        (PathModuleNamespace::Win32, "delimiter") => Some(";"),
        _ => None,
    }
}

/// bd-tu0c3: resolve a member-expression receiver to a path-module namespace,
/// parameterized over the module-object predicate so the pre-scan (candidate
/// alias names) and the lowering (recorded sentinels) share one shape:
///   * `<module>`         -> Posix (linux default `path` IS posix)
///   * `<module>.posix`   -> Posix
///   * `<module>.win32`   -> Win32
pub(super) fn path_receiver_namespace_with<F: Fn(&Expression) -> bool>(
    object: &Expression,
    is_module_object: &F,
) -> Option<PathModuleNamespace> {
    if is_module_object(object) {
        return Some(PathModuleNamespace::Posix);
    }
    if let Expression::Member {
        object: inner,
        property,
        computed: false,
        ..
    } = object
        && is_module_object(inner)
        && let Some(ns) = well_formed_static_name(property)
    {
        return match ns {
            "posix" => Some(PathModuleNamespace::Posix),
            "win32" => Some(PathModuleNamespace::Win32),
            _ => None,
        };
    }
    None
}

/// bd-tu0c3: true when `expr` IS the path module object at lowering time — a
/// sentinel-recorded require-binding alias or the inline `require('path')`
/// call. Mirror of the receiver check in [`fs_builtin_call_capability`].
pub(super) fn is_path_module_object(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    match expr {
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&path_module_alias_sentinel(alias))
        }
        Expression::Call {
            callee, arguments, ..
        } => {
            matches!(callee.as_ref(), Expression::Identifier(name)
                if is_builtin_require_callee(binding_lookup, name))
                && matches!(arguments.as_slice(), [spec]
                    if well_formed_string_literal(spec).is_some_and(is_path_module_specifier))
        }
        _ => false,
    }
}

/// bd-tu0c3: recognize a `path` builtin member call and return its
/// `builtin:Path*` capability. Purely syntactic (there is no real path module
/// heap object): the receiver must be a recognized path-module object or one of
/// its `.posix`/`.win32` namespaces, and the method must be in the recognized
/// pure-compute set for that namespace.
pub(super) fn path_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return None;
    };
    let namespace =
        path_receiver_namespace_with(object, &|expr| is_path_module_object(expr, binding_lookup))?;
    let method = well_formed_static_name(property)?;
    path_method_capability(namespace, method)
}

/// bd-tu0c3: recognize a `path` constant property READ (`path.sep`,
/// `path.delimiter`, `path.posix.sep`, `path.win32.delimiter`, …) and return
/// the string constant it lowers to. Accepts both static and quoted property
/// shapes.
pub(super) fn path_member_constant(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let namespace =
        path_receiver_namespace_with(object, &|expr| is_path_module_object(expr, binding_lookup))?;
    let prop = match computed {
        false => well_formed_static_name(property)?,
        true => well_formed_string_literal(property)?,
    };
    path_namespace_property_constant(namespace, prop)
}

/// bd-tu0c3: scan-time twin of [`path_builtin_call_capability`]'s receiver
/// check — during the pre-scan the sentinels are not recorded yet, so the
/// module-object predicate is membership in the candidate alias-name set.
pub(super) fn is_path_alias_method_callee(
    callee: &Expression,
    alias_names: &BTreeSet<String>,
) -> bool {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return false;
    };
    let Some(namespace) = path_receiver_namespace_with(
        object,
        &|expr| matches!(expr, Expression::Identifier(name) if alias_names.contains(name)),
    ) else {
        return false;
    };
    well_formed_static_name(property)
        .is_some_and(|method| path_method_capability(namespace, method).is_some())
}

/// bd-tu0c3: scan-time twin of [`path_member_constant`]: true when `expr` is a
/// recognized constant property read (`<alias>.sep`, `<alias>.posix.delimiter`,
/// …) on one of the candidate alias names.
pub(super) fn is_path_alias_property_read(
    expr: &Expression,
    alias_names: &BTreeSet<String>,
) -> bool {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = expr
    else {
        return false;
    };
    let Some(namespace) = path_receiver_namespace_with(
        object,
        &|inner| matches!(inner, Expression::Identifier(name) if alias_names.contains(name)),
    ) else {
        return false;
    };
    well_formed_static_name(property)
        .is_some_and(|property| path_namespace_property_constant(namespace, property).is_some())
}

/// bd-tu0c3: recursively scan `expr` for a member READ satisfying `is_target` —
/// the property-read sibling of [`expr_contains_matching_call`], with the same
/// traversal and the same fail-closed opacity: function/arrow/class bodies and
/// object literals are NOT entered, so a usage buried inside one is
/// conservatively not detected (the alias then keeps the ambient-authority
/// denial — recognition is never widened, only declined).
pub(super) fn expr_contains_matching_member<F: Fn(&Expression) -> bool>(
    expr: &Expression,
    is_target: &F,
) -> bool {
    match expr {
        Expression::Member {
            object, property, ..
        }
        | Expression::OptionalMember {
            object, property, ..
        } => {
            is_target(expr)
                || expr_contains_matching_member(object, is_target)
                || expr_contains_matching_member(property, is_target)
        }
        Expression::Call {
            callee, arguments, ..
        }
        | Expression::OptionalCall {
            callee, arguments, ..
        } => {
            expr_contains_matching_member(callee, is_target)
                || arguments
                    .iter()
                    .any(|a| expr_contains_matching_member(a, is_target))
        }
        Expression::New { callee, arguments } => {
            expr_contains_matching_member(callee, is_target)
                || arguments
                    .iter()
                    .any(|a| expr_contains_matching_member(a, is_target))
        }
        Expression::Binary { left, right, .. } | Expression::Assignment { left, right, .. } => {
            expr_contains_matching_member(left, is_target)
                || expr_contains_matching_member(right, is_target)
        }
        Expression::Unary { argument, .. }
        | Expression::Await(argument)
        | Expression::SpreadElement(argument) => expr_contains_matching_member(argument, is_target),
        Expression::Conditional {
            test,
            consequent,
            alternate,
        } => {
            expr_contains_matching_member(test, is_target)
                || expr_contains_matching_member(consequent, is_target)
                || expr_contains_matching_member(alternate, is_target)
        }
        Expression::Yield {
            argument: Some(argument),
            ..
        } => expr_contains_matching_member(argument, is_target),
        Expression::ArrayLiteral(elements) => elements
            .iter()
            .flatten()
            .any(|e| expr_contains_matching_member(e, is_target)),
        Expression::TemplateLiteral { expressions, .. } => expressions
            .iter()
            .any(|e| expr_contains_matching_member(e, is_target)),
        _ => false,
    }
}

/// bd-tu0c3: true when `expr` contains a recognized path usage on one of
/// `alias_names` — either a recognized method CALL (`<alias>.join(...)`) or a
/// recognized constant property READ (`<alias>.sep`).
pub(super) fn expr_contains_path_alias_usage(
    expr: &Expression,
    alias_names: &BTreeSet<String>,
) -> bool {
    expr_contains_matching_call(expr, &|callee| {
        is_path_alias_method_callee(callee, alias_names)
    }) || expr_contains_matching_member(expr, &|member| {
        is_path_alias_property_read(member, alias_names)
    })
}

/// bd-tu0c3: statement-level usage scan for the path alias gate. Unlike the fs
/// scan (`body_top_level_expr_matches`, expression statements + variable
/// initializers only), this recurses through CONTROL-FLOW statements (blocks,
/// if/else, loops, switch, try/catch/finally, return/throw) so idiomatic shapes
/// like `try { path.join('a', 1) } catch (e) {}` confirm the alias. Function
/// and class bodies remain opaque — a usage only inside one is conservatively
/// not detected, preserving the fail-closed ambient-denial default.
pub(super) fn path_statement_contains_usage<F: Fn(&Expression) -> bool>(
    stmt: &Statement,
    uses: &F,
) -> bool {
    match stmt {
        Statement::Expression(es) => uses(&es.expression),
        Statement::VariableDeclaration(vd) => vd
            .declarations
            .iter()
            .any(|d| d.initializer.as_ref().is_some_and(uses)),
        Statement::Block(block) => block
            .body
            .iter()
            .any(|inner| path_statement_contains_usage(inner, uses)),
        Statement::If(if_stmt) => {
            uses(&if_stmt.condition)
                || path_statement_contains_usage(&if_stmt.consequent, uses)
                || if_stmt
                    .alternate
                    .as_deref()
                    .is_some_and(|alt| path_statement_contains_usage(alt, uses))
        }
        Statement::For(for_stmt) => {
            for_stmt
                .init
                .as_deref()
                .is_some_and(|init| path_statement_contains_usage(init, uses))
                || for_stmt.condition.as_ref().is_some_and(uses)
                || for_stmt.update.as_ref().is_some_and(uses)
                || path_statement_contains_usage(&for_stmt.body, uses)
        }
        Statement::ForIn(for_in) => {
            uses(&for_in.object) || path_statement_contains_usage(&for_in.body, uses)
        }
        Statement::ForOf(for_of) => {
            uses(&for_of.iterable) || path_statement_contains_usage(&for_of.body, uses)
        }
        Statement::While(while_stmt) => {
            uses(&while_stmt.condition) || path_statement_contains_usage(&while_stmt.body, uses)
        }
        Statement::DoWhile(do_while) => {
            uses(&do_while.condition) || path_statement_contains_usage(&do_while.body, uses)
        }
        Statement::Return(ret) => ret.argument.as_ref().is_some_and(uses),
        Statement::Throw(throw_stmt) => uses(&throw_stmt.argument),
        Statement::TryCatch(try_stmt) => {
            try_stmt
                .block
                .body
                .iter()
                .any(|inner| path_statement_contains_usage(inner, uses))
                || try_stmt.handler.as_ref().is_some_and(|handler| {
                    handler
                        .body
                        .body
                        .iter()
                        .any(|inner| path_statement_contains_usage(inner, uses))
                })
                || try_stmt.finalizer.as_ref().is_some_and(|finalizer| {
                    finalizer
                        .body
                        .iter()
                        .any(|inner| path_statement_contains_usage(inner, uses))
                })
        }
        Statement::Switch(switch_stmt) => {
            uses(&switch_stmt.discriminant)
                || switch_stmt.cases.iter().any(|case| {
                    case.test.as_ref().is_some_and(uses)
                        || case
                            .consequent
                            .iter()
                            .any(|inner| path_statement_contains_usage(inner, uses))
                })
        }
        // Function/class declarations stay opaque (fail-closed); imports,
        // exports, break and continue carry no scannable expression.
        _ => false,
    }
}

/// bd-tu0c3: compute the set of identifier names that are BOTH bound via
/// `const/let/var <name> = require('path')` / `require('node:path')` at the
/// unit root AND used as a recognized `path` builtin (method call or constant
/// property read) somewhere reachable by the fail-closed statement scan.
/// Mirror of [`confirmed_fs_module_aliases`]: only such names are aliased, so
/// a bare/unused `const path = require('path')` deliberately keeps the
/// existing ambient-authority denial.
pub(super) fn confirmed_path_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            for d in &vd.declarations {
                if let (BindingPattern::Identifier(name), Some(init)) = (&d.pattern, &d.initializer)
                    && is_require_path_module_initializer(init, binding_lookup)
                {
                    candidates.insert(name.clone());
                }
            }
        }
    }
    if candidates.is_empty() {
        return candidates;
    }

    let mut used = BTreeSet::new();
    for name in &candidates {
        let single: BTreeSet<String> = std::iter::once(name.clone()).collect();
        if body.iter().any(|stmt| {
            path_statement_contains_usage(stmt, &|e| expr_contains_path_alias_usage(e, &single))
        }) {
            used.insert(name.clone());
        }
    }
    used
}

// ---------------------------------------------------------------------------
// Legacy Node `url` builtin recognition (bd-4awsz)
//
// This is a finite lowering-only facade over the interpreter's existing
// WHATWG URL implementation. No ambient module object or filesystem authority
// is manufactured: only `fileURLToPath`, `format`, and `parse` calls on a
// closed-use `require('url')` / `require('node:url')` alias are rewritten.
// The idiomatic destructured `fileURLToPath` binding shares the same rule.

pub(super) fn is_url_module_specifier(specifier: &str) -> bool {
    specifier == "url" || specifier == "node:url"
}

pub(super) fn url_module_alias_sentinel(name: &str) -> String {
    format!("\0urlmod\0{name}")
}

pub(super) fn url_named_binding_sentinel(name: &str) -> String {
    format!("\0urlnamed\0{name}")
}

pub(super) fn is_require_url_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
        && matches!(arguments.as_slice(), [specifier]
            if well_formed_string_literal(specifier).is_some_and(is_url_module_specifier))
}

pub(super) fn url_method_capability(method: &str) -> Option<&'static str> {
    match method {
        "fileURLToPath" => Some("builtin:UrlFileUrlToPath"),
        "format" => Some("builtin:UrlFormat"),
        "parse" => Some("builtin:UrlParse"),
        _ => None,
    }
}

pub(super) fn is_url_module_object(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    match expr {
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&url_module_alias_sentinel(alias))
        }
        Expression::Call { .. } => is_require_url_module_initializer(expr, binding_lookup),
        _ => false,
    }
}

pub(super) fn url_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    match callee {
        Expression::Identifier(local)
            if binding_lookup.contains_key(&url_named_binding_sentinel(local)) =>
        {
            Some("builtin:UrlFileUrlToPath")
        }
        Expression::Member {
            object,
            property,
            computed: false,
            ..
        } if is_url_module_object(object, binding_lookup) => {
            well_formed_static_name(property).and_then(url_method_capability)
        }
        _ => None,
    }
}

pub(super) fn is_url_module_alias_usage(expr: &Expression, alias: &str) -> bool {
    matches!(expr,
        Expression::Call { callee, .. }
            if module_alias_member_name(callee, alias)
                .is_some_and(|method| url_method_capability(method).is_some()))
}

pub(super) fn is_url_named_binding_usage(expr: &Expression, local: &str) -> bool {
    matches!(expr,
        Expression::Call { callee, .. }
            if matches!(callee.as_ref(), Expression::Identifier(name) if name == local))
}

pub(super) fn confirmed_url_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeMap::new();
    for (statement_index, statement) in body.iter().enumerate() {
        if let Statement::VariableDeclaration(declaration) = statement {
            if declaration.kind != VariableDeclarationKind::Const {
                continue;
            }
            for (declarator_index, declarator) in declaration.declarations.iter().enumerate() {
                if let (BindingPattern::Identifier(alias), Some(initializer)) =
                    (&declarator.pattern, &declarator.initializer)
                    && is_require_url_module_initializer(initializer, binding_lookup)
                {
                    candidates.insert(alias.clone(), (statement_index, declarator_index));
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|(alias, (statement_index, declarator_index))| {
            !module_alias_has_predeclaration_hazard(
                body,
                *statement_index,
                *declarator_index,
                alias,
                LoweringOnlyModuleAliasSurface::UrlModule,
                binding_lookup,
            ) && body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(
                    statement,
                    alias,
                    LoweringOnlyModuleAliasSurface::UrlModule,
                )
            }) && !body.iter().any(|statement| {
                module_alias_statement_has_rejected_use(
                    statement,
                    alias,
                    LoweringOnlyModuleAliasSurface::UrlModule,
                )
            })
        })
        .map(|(alias, _)| alias)
        .collect()
}

pub(super) fn confirmed_url_file_url_to_path_destructured_requires(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeMap::new();
    for (statement_index, statement) in body.iter().enumerate() {
        let Statement::VariableDeclaration(declaration) = statement else {
            continue;
        };
        if declaration.kind != VariableDeclarationKind::Const {
            continue;
        }
        for (declarator_index, declarator) in declaration.declarations.iter().enumerate() {
            let (BindingPattern::ObjectPattern(properties), Some(initializer)) =
                (&declarator.pattern, &declarator.initializer)
            else {
                continue;
            };
            if !is_require_url_module_initializer(initializer, binding_lookup) {
                continue;
            }
            for property in properties {
                if property.computed
                    || !well_formed_static_name(&property.key)
                        .is_some_and(|name| name == "fileURLToPath")
                {
                    continue;
                }
                if let BindingPattern::Identifier(local) = &property.value {
                    candidates.insert(local.clone(), (statement_index, declarator_index));
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|(local, (statement_index, declarator_index))| {
            !module_alias_has_predeclaration_hazard(
                body,
                *statement_index,
                *declarator_index,
                local,
                LoweringOnlyModuleAliasSurface::UrlNamed,
                binding_lookup,
            ) && body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(
                    statement,
                    local,
                    LoweringOnlyModuleAliasSurface::UrlNamed,
                )
            }) && !body.iter().any(|statement| {
                module_alias_statement_has_rejected_use(
                    statement,
                    local,
                    LoweringOnlyModuleAliasSurface::UrlNamed,
                )
            })
        })
        .map(|(local, _)| local)
        .collect()
}

pub(super) fn confirmed_url_destructure_locals(
    pattern: &BindingPattern,
    init: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<Vec<String>> {
    let BindingPattern::ObjectPattern(properties) = pattern else {
        return None;
    };
    if !is_require_url_module_initializer(init, binding_lookup) {
        return None;
    }
    let mut locals = Vec::new();
    for property in properties {
        if property.computed
            || !well_formed_static_name(&property.key).is_some_and(|name| name == "fileURLToPath")
        {
            return None;
        }
        let BindingPattern::Identifier(local) = &property.value else {
            return None;
        };
        if !binding_lookup.contains_key(&url_named_binding_sentinel(local)) {
            return None;
        }
        locals.push(local.clone());
    }
    (!locals.is_empty()).then_some(locals)
}

pub(super) fn seed_url_module_sentinels(
    body_lookup: &mut BTreeMap<String, BindingId>,
    outer_lookup: &BTreeMap<String, BindingId>,
) {
    seed_prefixed_sentinels(body_lookup, outer_lookup, &["\0urlmod\0", "\0urlnamed\0"]);
}

pub(super) fn suppress_url_module_sentinel(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    name: &str,
) {
    binding_lookup.remove(&url_module_alias_sentinel(name));
    binding_lookup.remove(&url_named_binding_sentinel(name));
}

pub(super) fn suppress_url_module_sentinels(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    names: &BTreeSet<String>,
) {
    for name in names {
        suppress_url_module_sentinel(binding_lookup, name);
    }
}

// ---------------------------------------------------------------------------
// Node `querystring` + `os` builtin recognition (bd-qmy52)
//
// Two further pure-compute module families following the `path` template
// (bd-tu0c3) exactly: a usage-lookahead pre-scan confirms `const qs =
// require('querystring')` / `const os = require('os')` aliases that are
// actually USED as a recognized builtin, records a NUL-sentinel, and the
// recognized require declaration is elided. Member calls lower to
// `builtin:Querystring*` / `builtin:Os*` HostCalls; the deterministic `os`
// property constants (`EOL`, `devNull`) lower to string literals and
// `os.constants` lowers to a 0-arg `builtin:OsConstants` HostCall. Bare/unused
// aliases keep the ambient-authority denial (fail-closed, test-pinned).
// ---------------------------------------------------------------------------

/// bd-qmy52: true when `specifier` names the Node querystring module —
/// `querystring` or `node:querystring`.
pub(super) fn is_querystring_module_specifier(specifier: &str) -> bool {
    specifier == "querystring" || specifier == "node:querystring"
}

/// bd-qmy52: sentinel key recording that `name` is bound to the querystring
/// module via `const <name> = require('querystring')` AND used as a recognized
/// querystring builtin. Mirror of [`path_module_alias_sentinel`].
pub(super) fn querystring_module_alias_sentinel(name: &str) -> String {
    format!("\0qsmod\0{name}")
}

/// bd-qmy52: true when `expr` is exactly `require('querystring')` /
/// `require('node:querystring')` with an unshadowed `require`.
pub(super) fn is_require_querystring_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    if matches!(callee.as_ref(), Expression::Identifier(name) if name == "__franken_querystring_module")
        && arguments.is_empty()
    {
        return true;
    }
    if !matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
    {
        return false;
    }
    matches!(arguments.as_slice(), [spec]
        if well_formed_string_literal(spec).is_some_and(is_querystring_module_specifier))
}

/// bd-qmy52: capability tag for a recognized `querystring` method. Single
/// source of truth shared by the usage-lookahead scan and the call-site
/// recognizer (an alias is confirmed only by a usage the call arm will really
/// intercept). `decode`/`encode` are Node's documented aliases of
/// `parse`/`stringify`.
pub(crate) fn querystring_method_capability(method: &str) -> Option<&'static str> {
    match method {
        "parse" | "decode" => Some("builtin:QuerystringParse"),
        "stringify" | "encode" => Some("builtin:QuerystringStringify"),
        "escape" => Some("builtin:QuerystringEscape"),
        "unescape" => Some("builtin:QuerystringUnescape"),
        _ => None,
    }
}

/// Supported querystring exports, in Node's enumeration order. The aliases
/// share their canonical native function values in the realm module (bd-305gi).
pub(crate) const QUERYSTRING_METHOD_NAMES: [&str; 6] = [
    "unescape",
    "escape",
    "stringify",
    "encode",
    "parse",
    "decode",
];

/// bd-qmy52: true when `expr` IS the querystring module object at lowering
/// time — a sentinel-recorded require-binding alias or the inline
/// `require('querystring')` call.
pub(super) fn is_querystring_module_object(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    match expr {
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&querystring_module_alias_sentinel(alias))
        }
        Expression::Call {
            callee, arguments, ..
        } => {
            (matches!(callee.as_ref(), Expression::Identifier(name) if name == "__franken_querystring_module")
                && arguments.is_empty())
                || (matches!(callee.as_ref(), Expression::Identifier(name)
                    if is_builtin_require_callee(binding_lookup, name))
                    && matches!(arguments.as_slice(), [spec]
                        if well_formed_string_literal(spec)
                            .is_some_and(is_querystring_module_specifier)))
        }
        _ => false,
    }
}

/// bd-qmy52: recognize a `querystring` builtin member call and return its
/// `builtin:Querystring*` capability. Purely syntactic (there is no real
/// querystring module heap object); no sub-namespaces (unlike path).
pub(super) fn querystring_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return None;
    };
    if !is_querystring_module_object(object, binding_lookup) {
        return None;
    }
    let method = well_formed_static_name(property)?;
    querystring_method_capability(method)
}

/// bd-qmy52: scan-time twin of [`querystring_builtin_call_capability`]'s
/// receiver check — during the pre-scan the sentinels are not recorded yet, so
/// the module-object predicate is membership in the candidate alias-name set.
pub(super) fn is_querystring_alias_method_callee(
    callee: &Expression,
    alias_names: &BTreeSet<String>,
) -> bool {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return false;
    };
    if !matches!(object.as_ref(), Expression::Identifier(name) if alias_names.contains(name)) {
        return false;
    }
    well_formed_static_name(property)
        .is_some_and(|method| querystring_method_capability(method).is_some())
}

/// bd-qmy52: compute the set of identifier names that are BOTH bound via
/// `const/let/var <name> = require('querystring')` at the unit root AND used
/// as a recognized querystring builtin somewhere reachable by the fail-closed
/// statement scan (shared with path: control-flow recursion, opaque
/// function/class bodies).
pub(super) fn confirmed_querystring_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            for d in &vd.declarations {
                if let (BindingPattern::Identifier(name), Some(init)) = (&d.pattern, &d.initializer)
                    && is_require_querystring_module_initializer(init, binding_lookup)
                {
                    candidates.insert(name.clone());
                }
            }
        }
    }
    if candidates.is_empty() {
        return candidates;
    }

    let mut used = BTreeSet::new();
    for name in &candidates {
        let single: BTreeSet<String> = std::iter::once(name.clone()).collect();
        if body.iter().any(|stmt| {
            path_statement_contains_usage(stmt, &|e| {
                expr_contains_matching_call(e, &|callee| {
                    is_querystring_alias_method_callee(callee, &single)
                })
            })
        }) {
            used.insert(name.clone());
        }
    }
    used
}

// ---------------------------------------------------------------------------
// Node `zlib` pure-compute builtin recognition (bd-fdqd4)
// ---------------------------------------------------------------------------

pub(super) fn is_zlib_module_specifier(specifier: &str) -> bool {
    specifier == "zlib" || specifier == "node:zlib"
}

pub(super) fn zlib_module_alias_sentinel(name: &str) -> String {
    format!("\0zlibmod\0{name}")
}

pub(super) fn is_require_zlib_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
        && matches!(arguments.as_slice(), [specifier]
            if well_formed_string_literal(specifier).is_some_and(is_zlib_module_specifier))
}

/// The methods backed by the engine's bounded codec implementation. Both the
/// legacy direct-call lowering and ordinary runtime module objects use this
/// inventory; exporting a function never grants its invocation authority.
pub(crate) const ZLIB_METHOD_NAMES: [&str; 13] = [
    "gzipSync",
    "gunzipSync",
    "deflateSync",
    "inflateSync",
    "deflateRawSync",
    "inflateRawSync",
    "unzipSync",
    "gzip",
    "gunzip",
    "deflate",
    "inflate",
    "brotliCompressSync",
    "brotliDecompressSync",
];

pub(crate) fn zlib_method_capability(method: &str) -> Option<&'static str> {
    match method {
        "gzipSync" => Some("builtin:ZlibGzipSync"),
        "gunzipSync" => Some("builtin:ZlibGunzipSync"),
        "deflateSync" => Some("builtin:ZlibDeflateSync"),
        "inflateSync" => Some("builtin:ZlibInflateSync"),
        "deflateRawSync" => Some("builtin:ZlibDeflateRawSync"),
        "inflateRawSync" => Some("builtin:ZlibInflateRawSync"),
        "unzipSync" => Some("builtin:ZlibUnzipSync"),
        "gzip" => Some("builtin:ZlibGzip"),
        "gunzip" => Some("builtin:ZlibGunzip"),
        "deflate" => Some("builtin:ZlibDeflate"),
        "inflate" => Some("builtin:ZlibInflate"),
        "brotliCompressSync" => Some("builtin:ZlibBrotliCompressSync"),
        "brotliDecompressSync" => Some("builtin:ZlibBrotliDecompressSync"),
        _ => None,
    }
}

pub(super) fn is_zlib_module_object(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    // A CommonJS wrapper has a real, mutable realm module. Preserve ordinary
    // property reads/calls (including aliases and later mutations) rather than
    // replacing its exports with compile-time hostcall sentinels.
    if require_is_commonjs_wrapper(binding_lookup) {
        return false;
    }
    match expr {
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&zlib_module_alias_sentinel(alias))
        }
        Expression::Call { .. } => is_require_zlib_module_initializer(expr, binding_lookup),
        _ => false,
    }
}

pub(super) fn zlib_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return None;
    };
    if !is_zlib_module_object(object, binding_lookup) {
        return None;
    }
    zlib_method_capability(well_formed_static_name(property)?)
}

pub(super) fn zlib_constants_member_read(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    if !is_zlib_module_object(object, binding_lookup) {
        return false;
    }
    let property = match computed {
        false => well_formed_static_name(property),
        true => well_formed_string_literal(property),
    };
    property == Some("constants")
}

pub(super) fn is_zlib_alias_usage(expr: &Expression, alias: &str) -> bool {
    match expr {
        Expression::Call { callee, .. } => module_alias_member_name(callee, alias)
            .is_some_and(|method| zlib_method_capability(method).is_some()),
        Expression::Member { .. } => module_alias_member_name(expr, alias) == Some("constants"),
        _ => false,
    }
}

pub(super) fn confirmed_zlib_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    if require_is_commonjs_wrapper(binding_lookup) {
        return BTreeSet::new();
    }
    let mut candidates = BTreeMap::new();
    for (statement_index, statement) in body.iter().enumerate() {
        if let Statement::VariableDeclaration(declaration) = statement {
            if declaration.kind != VariableDeclarationKind::Const {
                continue;
            }
            for (declarator_index, declarator) in declaration.declarations.iter().enumerate() {
                if let (BindingPattern::Identifier(name), Some(initializer)) =
                    (&declarator.pattern, &declarator.initializer)
                    && is_require_zlib_module_initializer(initializer, binding_lookup)
                {
                    candidates.insert(name.clone(), (statement_index, declarator_index));
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|(alias, (statement_index, declarator_index))| {
            !module_alias_has_predeclaration_hazard(
                body,
                *statement_index,
                *declarator_index,
                alias,
                LoweringOnlyModuleAliasSurface::Zlib,
                binding_lookup,
            ) && body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(
                    statement,
                    alias,
                    LoweringOnlyModuleAliasSurface::Zlib,
                )
            }) && !body.iter().any(|statement| {
                module_alias_statement_has_rejected_use(
                    statement,
                    alias,
                    LoweringOnlyModuleAliasSurface::Zlib,
                )
            })
        })
        .map(|(alias, _)| alias)
        .collect()
}

// ---------------------------------------------------------------------------
// Node `crypto` deterministic builtin recognition (bd-2z157)
// ---------------------------------------------------------------------------

pub(super) fn is_crypto_module_specifier(specifier: &str) -> bool {
    specifier == "crypto" || specifier == "node:crypto"
}

pub(super) fn crypto_module_alias_sentinel(name: &str) -> String {
    format!("\0cryptomod\0{name}")
}

pub(super) fn crypto_hash_object_alias_sentinel(name: &str) -> String {
    format!("\0cryptoobj\0hash\0{name}")
}

pub(super) fn crypto_hmac_object_alias_sentinel(name: &str) -> String {
    format!("\0cryptoobj\0hmac\0{name}")
}

pub(super) fn crypto_cipher_object_alias_sentinel(name: &str) -> String {
    format!("\0cryptoobj\0cipher\0{name}")
}

pub(super) fn crypto_object_alias_surface(
    name: &str,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<LoweringOnlyModuleAliasSurface> {
    if binding_lookup.contains_key(&crypto_hash_object_alias_sentinel(name)) {
        Some(LoweringOnlyModuleAliasSurface::CryptoHashObject)
    } else if binding_lookup.contains_key(&crypto_hmac_object_alias_sentinel(name)) {
        Some(LoweringOnlyModuleAliasSurface::CryptoHmacObject)
    } else if binding_lookup.contains_key(&crypto_cipher_object_alias_sentinel(name)) {
        Some(LoweringOnlyModuleAliasSurface::CryptoCipherObject)
    } else {
        None
    }
}

pub(super) fn insert_crypto_object_alias_sentinel(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    name: &str,
    surface: LoweringOnlyModuleAliasSurface,
) {
    let sentinel = match surface {
        LoweringOnlyModuleAliasSurface::CryptoHashObject => crypto_hash_object_alias_sentinel(name),
        LoweringOnlyModuleAliasSurface::CryptoHmacObject => crypto_hmac_object_alias_sentinel(name),
        LoweringOnlyModuleAliasSurface::CryptoCipherObject => {
            crypto_cipher_object_alias_sentinel(name)
        }
        _ => unreachable!("only crypto-object surfaces have object sentinels"),
    };
    binding_lookup.insert(sentinel, 0);
}

pub(super) fn is_require_crypto_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
        && matches!(arguments.as_slice(), [specifier]
            if well_formed_string_literal(specifier).is_some_and(is_crypto_module_specifier))
}

/// Supported native crypto exports, shared by lowering and runtime providers.
/// Randomness still requires RandomRead at the invocation boundary; loading
/// the crypto module supplies no entropy or additional authority.
pub(crate) const CRYPTO_METHOD_NAMES: [&str; 17] = [
    "createHash",
    "createHmac",
    "timingSafeEqual",
    "pbkdf2Sync",
    "pbkdf2",
    "scryptSync",
    "createCipheriv",
    "createDecipheriv",
    "getHashes",
    "getCiphers",
    "generateKeyPairSync",
    "sign",
    "verify",
    "randomBytes",
    "randomUUID",
    "randomInt",
    "randomFillSync",
];

pub(crate) fn crypto_method_capability(method: &str) -> Option<&'static str> {
    match method {
        "createHash" => Some("builtin:CryptoCreateHash"),
        "createHmac" => Some("builtin:CryptoCreateHmac"),
        "timingSafeEqual" => Some("builtin:CryptoTimingSafeEqual"),
        "pbkdf2Sync" => Some("builtin:CryptoPbkdf2Sync"),
        "pbkdf2" => Some("builtin:CryptoPbkdf2"),
        "scryptSync" => Some("builtin:CryptoScryptSync"),
        "createCipheriv" => Some("builtin:CryptoCreateCipheriv"),
        "createDecipheriv" => Some("builtin:CryptoCreateDecipheriv"),
        "getHashes" => Some("builtin:CryptoGetHashes"),
        "getCiphers" => Some("builtin:CryptoGetCiphers"),
        // bd-53l89 slice 1: ed25519 generation lowers to the typed
        // RandomRead-authority hostcall; P-256 arrives with the ECDSA slice.
        "generateKeyPairSync" => Some("builtin:CryptoGenerateKeyPairSync"),
        // bd-53l89 slice 2: module-level sign/verify over KeyPairActive
        // handles; Ed25519-only in this slice.
        "sign" => Some("builtin:CryptoSign"),
        "verify" => Some("builtin:CryptoVerify"),
        "randomBytes" => Some("builtin:CryptoRandomBytes"),
        "randomUUID" => Some("builtin:CryptoRandomUUID"),
        "randomInt" => Some("builtin:CryptoRandomInt"),
        "randomFillSync" => Some("builtin:CryptoRandomFillSync"),
        _ => None,
    }
}

/// A literal `randomInt` range that is already invalid must throw before drawing
/// entropy. Those calls receive a separate deterministic validation hostcall,
/// which intentionally retains generic Builtin authority rather than RandomRead.
pub(super) fn crypto_random_int_args_are_statically_invalid(arguments: &[Expression]) -> bool {
    match arguments {
        [Expression::NumericLiteral(max)] => *max <= 0,
        [
            Expression::NumericLiteral(min),
            Expression::NumericLiteral(max),
        ] => min >= max,
        _ => false,
    }
}

pub(super) fn crypto_method_call_capability(
    method: &str,
    arguments: &[Expression],
) -> Option<&'static str> {
    if arguments
        .iter()
        .any(|argument| matches!(argument, Expression::SpreadElement(_)))
    {
        return None;
    }
    if method == "randomInt" && crypto_random_int_args_are_statically_invalid(arguments) {
        return Some("builtin:CryptoInvalidRandomInt");
    }
    if method == "randomUUID" && !arguments.is_empty() {
        return None;
    }
    crypto_method_capability(method)
}

pub(super) fn is_crypto_module_object(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    if require_is_commonjs_wrapper(binding_lookup) {
        return false;
    }
    match expr {
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&crypto_module_alias_sentinel(alias))
        }
        Expression::Call { .. } => is_require_crypto_module_initializer(expr, binding_lookup),
        _ => false,
    }
}

pub(super) fn crypto_builtin_call_capability(
    callee: &Expression,
    arguments: &[Expression],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return None;
    };
    if !is_crypto_module_object(object, binding_lookup) {
        return None;
    }
    let capability = crypto_method_call_capability(well_formed_static_name(property)?, arguments)?;
    if matches!(
        capability,
        "builtin:CryptoRandomBytes"
            | "builtin:CryptoRandomUUID"
            | "builtin:CryptoRandomInt"
            | "builtin:CryptoRandomFillSync"
    ) && matches!(object.as_ref(), Expression::Call { .. })
    {
        return None;
    }
    Some(capability)
}

pub(super) fn crypto_object_method_capability(method: &str) -> Option<&'static str> {
    match method {
        "update" => Some("builtin:CryptoObjectUpdate"),
        "digest" => Some("builtin:CryptoObjectDigest"),
        "copy" => Some("builtin:CryptoObjectCopy"),
        "final" => Some("builtin:CryptoObjectFinal"),
        "getAuthTag" => Some("builtin:CryptoObjectGetAuthTag"),
        "setAuthTag" => Some("builtin:CryptoObjectSetAuthTag"),
        _ => None,
    }
}

pub(super) fn crypto_object_factory_surface(
    expression: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<LoweringOnlyModuleAliasSurface> {
    let Expression::Call {
        callee, arguments, ..
    } = expression
    else {
        return None;
    };
    match crypto_builtin_call_capability(callee, arguments, binding_lookup) {
        Some("builtin:CryptoCreateHash") => Some(LoweringOnlyModuleAliasSurface::CryptoHashObject),
        Some("builtin:CryptoCreateHmac") => Some(LoweringOnlyModuleAliasSurface::CryptoHmacObject),
        Some("builtin:CryptoCreateCipheriv" | "builtin:CryptoCreateDecipheriv") => {
            Some(LoweringOnlyModuleAliasSurface::CryptoCipherObject)
        }
        _ => None,
    }
}

/// Recover the authenticated crypto-object surface produced by an expression
/// without consulting guest-visible heap tags. Besides a direct factory call,
/// hash/HMAC methods whose Node contract returns an authenticated object may
/// participate in a finite static chain. Cipher `setAuthTag` is deliberately
/// absent: its fluent return remains outside the accepted surface until that
/// contract is implemented explicitly (bd-2z157).
pub(super) fn crypto_object_expression_surface(
    expression: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<LoweringOnlyModuleAliasSurface> {
    if let Some(surface) = crypto_object_factory_surface(expression, binding_lookup) {
        return Some(surface);
    }
    if let Expression::Identifier(alias) = expression {
        return crypto_object_alias_surface(alias, binding_lookup);
    }
    let Expression::Call {
        callee, arguments, ..
    } = expression
    else {
        return None;
    };
    if arguments
        .iter()
        .any(|argument| matches!(argument, Expression::SpreadElement(_)))
    {
        return None;
    }
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee.as_ref()
    else {
        return None;
    };
    let surface = crypto_object_expression_surface(object, binding_lookup)?;
    let method = well_formed_static_name(property)?;
    match (surface, method) {
        (LoweringOnlyModuleAliasSurface::CryptoHashObject, "update" | "copy") => Some(surface),
        (LoweringOnlyModuleAliasSurface::CryptoHmacObject, "update") => Some(surface),
        _ => None,
    }
}

pub(super) fn crypto_object_builtin_call_capability(
    callee: &Expression,
    arguments: &[Expression],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return None;
    };
    let surface = crypto_object_expression_surface(object, binding_lookup)?;
    if arguments
        .iter()
        .any(|argument| matches!(argument, Expression::SpreadElement(_)))
    {
        return None;
    }
    let method = well_formed_static_name(property)?;
    let capability = crypto_object_method_capability(method)?;
    match surface {
        LoweringOnlyModuleAliasSurface::CryptoHashObject
            if matches!(method, "update" | "digest" | "copy") =>
        {
            Some(capability)
        }
        LoweringOnlyModuleAliasSurface::CryptoHmacObject
            if matches!(method, "update" | "digest") =>
        {
            Some(capability)
        }
        LoweringOnlyModuleAliasSurface::CryptoCipherObject
            if matches!(method, "update" | "final" | "getAuthTag" | "setAuthTag") =>
        {
            Some(capability)
        }
        _ => None,
    }
}

pub(super) fn crypto_constants_member_read(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    if computed || !is_crypto_module_object(object, binding_lookup) {
        return false;
    }
    well_formed_static_name(property) == Some("constants")
}

pub(super) fn is_crypto_alias_usage(expr: &Expression, alias: &str) -> bool {
    match expr {
        Expression::Call {
            callee, arguments, ..
        } => module_alias_member_name(callee, alias)
            .is_some_and(|method| crypto_method_call_capability(method, arguments).is_some()),
        Expression::Member { .. } => module_alias_member_name(expr, alias) == Some("constants"),
        _ => false,
    }
}

pub(super) fn is_crypto_object_alias_usage(
    expr: &Expression,
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> bool {
    matches!(
        expr,
        Expression::Call {
            callee,
            arguments,
            ..
        } if module_alias_member_name(callee, alias).is_some_and(|method| match surface {
            LoweringOnlyModuleAliasSurface::CryptoHashObject => {
                matches!(method, "update" | "digest" | "copy")
            }
            LoweringOnlyModuleAliasSurface::CryptoHmacObject => {
                matches!(method, "update" | "digest")
            }
            LoweringOnlyModuleAliasSurface::CryptoCipherObject => {
                matches!(method, "update" | "final" | "getAuthTag" | "setAuthTag")
            }
            _ => false,
        })
            && arguments
                .iter()
                .all(|argument| !matches!(argument, Expression::SpreadElement(_)))
    )
}

pub(super) fn is_discarded_crypto_identity_call(
    expr: &Expression,
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> bool {
    matches!(
        expr,
        Expression::Call {
            callee,
            arguments,
            ..
        } if module_alias_member_name(callee, alias).is_some_and(|method| match surface {
            LoweringOnlyModuleAliasSurface::CryptoHashObject => {
                matches!(method, "update" | "copy")
            }
            LoweringOnlyModuleAliasSurface::CryptoHmacObject => method == "update",
            LoweringOnlyModuleAliasSurface::CryptoCipherObject => method == "setAuthTag",
            _ => false,
        })
            && arguments
                .iter()
                .all(|argument| !matches!(argument, Expression::SpreadElement(_)))
    )
}

pub(super) fn crypto_object_alias_identity_chain_rejected_use(
    expr: &Expression,
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> Option<bool> {
    if matches!(expr, Expression::Identifier(name) if name == alias) {
        return Some(false);
    }
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return None;
    };
    if arguments
        .iter()
        .any(|argument| matches!(argument, Expression::SpreadElement(_)))
    {
        return None;
    }
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee.as_ref()
    else {
        return None;
    };
    let receiver_rejected =
        crypto_object_alias_identity_chain_rejected_use(object, alias, surface)?;
    let method = well_formed_static_name(property)?;
    let returns_authenticated_identity = match surface {
        LoweringOnlyModuleAliasSurface::CryptoHashObject => {
            matches!(method, "update" | "copy")
        }
        LoweringOnlyModuleAliasSurface::CryptoHmacObject => method == "update",
        _ => false,
    };
    returns_authenticated_identity.then(|| {
        receiver_rejected
            || arguments
                .iter()
                .any(|argument| module_alias_expr_has_rejected_use(argument, alias, surface))
    })
}

pub(super) fn crypto_object_alias_closed_result_call_rejected_use(
    expr: &Expression,
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> Option<bool> {
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return None;
    };
    if arguments
        .iter()
        .any(|argument| matches!(argument, Expression::SpreadElement(_)))
    {
        return None;
    }
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee.as_ref()
    else {
        return None;
    };
    let receiver_rejected =
        crypto_object_alias_identity_chain_rejected_use(object, alias, surface)?;
    let method = well_formed_static_name(property)?;
    let returns_closed_result = matches!(
        (surface, method),
        (
            LoweringOnlyModuleAliasSurface::CryptoHashObject
                | LoweringOnlyModuleAliasSurface::CryptoHmacObject,
            "digest"
        )
    );
    returns_closed_result.then(|| {
        receiver_rejected
            || arguments
                .iter()
                .any(|argument| module_alias_expr_has_rejected_use(argument, alias, surface))
    })
}

/// Recognize the one crypto-object identity transfer that is safe to bind to a
/// second name: `Hash::copy`, optionally followed by finite `update` calls.
/// `update` by itself deliberately stays excluded because it aliases the same
/// mutable lifecycle object; `copy` creates an independently tracked hash.
pub(super) fn is_crypto_hash_copy_transfer_initializer(
    expr: &Expression,
    source_alias: &str,
) -> bool {
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    if arguments
        .iter()
        .any(|argument| matches!(argument, Expression::SpreadElement(_)))
        || arguments.iter().any(|argument| {
            module_alias_expr_has_rejected_use(
                argument,
                source_alias,
                LoweringOnlyModuleAliasSurface::CryptoHashObject,
            )
        })
    {
        return false;
    }
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee.as_ref()
    else {
        return false;
    };
    match well_formed_static_name(property) {
        Some("copy") => {
            matches!(object.as_ref(), Expression::Identifier(name) if name == source_alias)
        }
        Some("update") => is_crypto_hash_copy_transfer_initializer(object, source_alias),
        _ => false,
    }
}

pub(super) fn crypto_object_control_flow_statement_has_rejected_use(
    statement: &Statement,
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
    binding_lookup: &BTreeMap<String, BindingId>,
    active: &mut BTreeSet<String>,
) -> bool {
    // The caller holds `alias` in `active` as its recursion cycle guard, but
    // recursing into a NESTED lexical scope for the SAME alias is not a cycle --
    // it is the same alias's uses in a child scope. Lift the guard for the
    // duration of this nested validation and restore it after; without this the
    // guard trips on re-entry and every nested Hash.copy chain is spuriously
    // rejected (bd-5l5ye).
    let was_active = active.remove(alias);
    let result = match statement {
        Statement::Block(block) => crypto_object_alias_has_rejected_use(
            &block.body,
            alias,
            surface,
            binding_lookup,
            active,
        ),
        Statement::If(if_statement) => {
            module_alias_expr_has_rejected_use(&if_statement.condition, alias, surface)
                || crypto_object_control_flow_statement_has_rejected_use(
                    &if_statement.consequent,
                    alias,
                    surface,
                    binding_lookup,
                    active,
                )
                || if_statement.alternate.as_deref().is_some_and(|alternate| {
                    crypto_object_control_flow_statement_has_rejected_use(
                        alternate,
                        alias,
                        surface,
                        binding_lookup,
                        active,
                    )
                })
        }
        Statement::TryCatch(try_statement) => {
            crypto_object_alias_has_rejected_use(
                &try_statement.block.body,
                alias,
                surface,
                binding_lookup,
                active,
            ) || try_statement.handler.as_ref().is_some_and(|handler| {
                handler.parameter.as_deref() != Some(alias)
                    && crypto_object_alias_has_rejected_use(
                        &handler.body.body,
                        alias,
                        surface,
                        binding_lookup,
                        active,
                    )
            }) || try_statement.finalizer.as_ref().is_some_and(|finalizer| {
                crypto_object_alias_has_rejected_use(
                    &finalizer.body,
                    alias,
                    surface,
                    binding_lookup,
                    active,
                )
            })
        }
        _ => module_alias_statement_has_rejected_use(statement, alias, surface),
    };
    if was_active {
        active.insert(alias.to_string());
    }
    result
}

pub(super) fn crypto_object_alias_has_rejected_use(
    body: &[Statement],
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
    binding_lookup: &BTreeMap<String, BindingId>,
    active: &mut BTreeSet<String>,
) -> bool {
    if !active.insert(alias.to_string()) {
        return true;
    }

    let rejected = body.iter().enumerate().any(|(statement_index, statement)| {
        let Statement::VariableDeclaration(declaration) = statement else {
            if surface.is_authenticated_object() {
                return crypto_object_control_flow_statement_has_rejected_use(
                    statement,
                    alias,
                    surface,
                    binding_lookup,
                    active,
                );
            }
            return module_alias_statement_has_rejected_use(statement, alias, surface);
        };
        declaration
            .declarations
            .iter()
            .enumerate()
            .any(|(declarator_index, declarator)| {
                if net_pattern_binds_alias(&declarator.pattern, alias) {
                    return declarator.initializer.as_ref().is_some_and(|initializer| {
                        module_alias_expr_has_rejected_use(initializer, alias, surface)
                    });
                }
                if module_alias_binding_pattern_has_rejected_use(
                    &declarator.pattern,
                    alias,
                    surface,
                ) {
                    return true;
                }
                let Some(initializer) = declarator.initializer.as_ref() else {
                    return false;
                };
                if declaration.kind == VariableDeclarationKind::Const
                    && surface == LoweringOnlyModuleAliasSurface::CryptoHashObject
                    && let BindingPattern::Identifier(target_alias) = &declarator.pattern
                    && is_crypto_hash_copy_transfer_initializer(initializer, alias)
                {
                    let target_surface = LoweringOnlyModuleAliasSurface::CryptoHashObject;
                    return module_alias_has_predeclaration_hazard(
                        body,
                        statement_index,
                        declarator_index,
                        target_alias,
                        target_surface,
                        binding_lookup,
                    ) || !body.iter().any(|statement| {
                        module_alias_statement_contains_unshadowed_usage(
                            statement,
                            target_alias,
                            target_surface,
                        )
                    }) || crypto_object_alias_has_rejected_use(
                        body,
                        target_alias,
                        target_surface,
                        binding_lookup,
                        active,
                    );
                }
                module_alias_expr_has_rejected_use(initializer, alias, surface)
            })
    });
    active.remove(alias);
    rejected
}

pub(super) fn confirmed_crypto_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    if require_is_commonjs_wrapper(binding_lookup) {
        return BTreeSet::new();
    }
    let mut candidates = BTreeMap::new();
    for (statement_index, statement) in body.iter().enumerate() {
        if let Statement::VariableDeclaration(declaration) = statement {
            if declaration.kind != VariableDeclarationKind::Const {
                continue;
            }
            for (declarator_index, declarator) in declaration.declarations.iter().enumerate() {
                if let (BindingPattern::Identifier(name), Some(initializer)) =
                    (&declarator.pattern, &declarator.initializer)
                    && is_require_crypto_module_initializer(initializer, binding_lookup)
                {
                    candidates.insert(name.clone(), (statement_index, declarator_index));
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|(alias, (statement_index, declarator_index))| {
            !module_alias_has_predeclaration_hazard(
                body,
                *statement_index,
                *declarator_index,
                alias,
                LoweringOnlyModuleAliasSurface::Crypto,
                binding_lookup,
            ) && body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(
                    statement,
                    alias,
                    LoweringOnlyModuleAliasSurface::Crypto,
                )
            }) && !body.iter().any(|statement| {
                module_alias_statement_has_rejected_use(
                    statement,
                    alias,
                    LoweringOnlyModuleAliasSurface::Crypto,
                )
            })
        })
        .map(|(alias, _)| alias)
        .collect()
}

pub(super) fn confirmed_crypto_object_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeMap<String, LoweringOnlyModuleAliasSurface> {
    let mut confirmed: BTreeMap<String, LoweringOnlyModuleAliasSurface> = BTreeMap::new();
    loop {
        let mut augmented_lookup = binding_lookup.clone();
        for (alias, surface) in &confirmed {
            insert_crypto_object_alias_sentinel(&mut augmented_lookup, alias, *surface);
        }

        let mut discovered = Vec::new();
        for (statement_index, statement) in body.iter().enumerate() {
            if let Statement::VariableDeclaration(declaration) = statement {
                if declaration.kind != VariableDeclarationKind::Const {
                    continue;
                }
                for (declarator_index, declarator) in declaration.declarations.iter().enumerate() {
                    let (BindingPattern::Identifier(name), Some(initializer)) =
                        (&declarator.pattern, &declarator.initializer)
                    else {
                        continue;
                    };
                    if confirmed.contains_key(name) {
                        continue;
                    }
                    let Some(surface) =
                        crypto_object_expression_surface(initializer, &augmented_lookup)
                    else {
                        continue;
                    };
                    if !module_alias_has_predeclaration_hazard(
                        body,
                        statement_index,
                        declarator_index,
                        name,
                        surface,
                        &augmented_lookup,
                    ) && body.iter().any(|statement| {
                        module_alias_statement_contains_unshadowed_usage(statement, name, surface)
                    }) && !crypto_object_alias_has_rejected_use(
                        body,
                        name,
                        surface,
                        &augmented_lookup,
                        &mut BTreeSet::new(),
                    ) {
                        discovered.push((name.clone(), surface));
                    }
                }
            }
        }

        if discovered.is_empty() {
            return confirmed;
        }
        confirmed.extend(discovered);
    }
}

// ---------------------------------------------------------------------------
// Node `cluster` primary-process facade recognition (bd-9p2v3)
// ---------------------------------------------------------------------------

pub(super) fn is_cluster_module_specifier(specifier: &str) -> bool {
    specifier == "cluster" || specifier == "node:cluster"
}

pub(super) fn cluster_module_alias_sentinel(name: &str) -> String {
    format!("\0clustermod\0{name}")
}

pub(super) fn cluster_singleton_binding_sentinel() -> &'static str {
    "\0cluster-singleton-binding"
}

pub(super) fn is_require_cluster_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
        && matches!(arguments.as_slice(), [specifier]
            if well_formed_string_literal(specifier).is_some_and(is_cluster_module_specifier))
}

/// Closed facade surface. Reads are materialized on one engine-owned object;
/// calls resolve to first-class builtins or the shared EventEmitter table.
/// Keeping a single list for the provenance scan prevents an accepted alias
/// from exposing any property the runtime did not intentionally model.
pub(super) fn cluster_property_is_supported(property: &str) -> bool {
    matches!(
        property,
        "isPrimary"
            | "isMaster"
            | "isWorker"
            | "worker"
            | "workers"
            | "settings"
            | "schedulingPolicy"
            | "SCHED_RR"
            | "SCHED_NONE"
            | "Worker"
            | "fork"
            | "setupPrimary"
            | "setupMaster"
            | "disconnect"
            | "on"
            | "once"
            | "emit"
    )
}

pub(super) fn cluster_method_is_supported(method: &str) -> bool {
    matches!(
        method,
        "setupPrimary" | "setupMaster" | "disconnect" | "fork" | "Worker" | "on" | "once" | "emit"
    )
}

/// `EventEmitter.on`/`once` return their receiver. Keep that fluent receiver
/// inside the lowering-only cluster surface by admitting it only when the
/// entire expression statement discards the returned facade. Every consumed
/// occurrence is handled by the ordinary rejected-use scanner below.
pub(super) fn is_discarded_cluster_listener_registration(expr: &Expression, alias: &str) -> bool {
    matches!(
        expr,
        Expression::Call { callee, .. }
            if matches!(module_alias_member_name(callee, alias), Some("on" | "once"))
    )
}

pub(super) fn is_cluster_alias_usage(expr: &Expression, alias: &str) -> bool {
    match expr {
        Expression::Call { callee, .. } => {
            module_alias_member_name(callee, alias).is_some_and(cluster_method_is_supported)
        }
        Expression::Member { .. } => {
            module_alias_member_name(expr, alias).is_some_and(cluster_property_is_supported)
        }
        Expression::Binary {
            operator: BinaryOperator::Instanceof,
            left,
            ..
        } => matches!(left.as_ref(), Expression::Identifier(name) if name == alias),
        _ => false,
    }
}

pub(super) fn confirmed_cluster_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeMap::new();
    for (statement_index, statement) in body.iter().enumerate() {
        if let Statement::VariableDeclaration(declaration) = statement {
            if declaration.kind != VariableDeclarationKind::Const {
                continue;
            }
            for (declarator_index, declarator) in declaration.declarations.iter().enumerate() {
                if let (BindingPattern::Identifier(name), Some(initializer)) =
                    (&declarator.pattern, &declarator.initializer)
                    && is_require_cluster_module_initializer(initializer, binding_lookup)
                {
                    candidates.insert(name.clone(), (statement_index, declarator_index));
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|(alias, (statement_index, declarator_index))| {
            !module_alias_has_predeclaration_hazard(
                body,
                *statement_index,
                *declarator_index,
                alias,
                LoweringOnlyModuleAliasSurface::Cluster,
                binding_lookup,
            ) && body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(
                    statement,
                    alias,
                    LoweringOnlyModuleAliasSurface::Cluster,
                )
            }) && !body.iter().any(|statement| {
                module_alias_statement_has_rejected_use(
                    statement,
                    alias,
                    LoweringOnlyModuleAliasSurface::Cluster,
                )
            })
        })
        .map(|(alias, _)| alias)
        .collect()
}

// ---------------------------------------------------------------------------
// Node `child_process` authenticated effect facade (bd-x85a7 / bd-at11s)
// ---------------------------------------------------------------------------

pub(super) fn is_child_process_module_specifier(specifier: &str) -> bool {
    specifier == "child_process" || specifier == "node:child_process"
}

pub(super) fn child_process_module_alias_sentinel(name: &str) -> String {
    format!("\0child-process-mod\0{name}")
}

pub(super) fn is_require_child_process_module_initializer(
    expression: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    // The authenticated CommonJS loader returns a real, mutable module.
    // Preserve its identity, property reads and call sites; only an actual
    // native function invocation may cross the process_spawn authority gate.
    if require_is_commonjs_wrapper(binding_lookup) {
        return false;
    }
    let Expression::Call {
        callee, arguments, ..
    } = expression
    else {
        return false;
    };
    matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
        && matches!(arguments.as_slice(), [specifier]
            if well_formed_string_literal(specifier)
                .is_some_and(is_child_process_module_specifier))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChildProcessOperation {
    SpawnSync,
    ExecSync,
    ExecFileSync,
    Spawn,
    Exec,
    ExecFile,
}

impl ChildProcessOperation {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::SpawnSync => "spawn_sync",
            Self::ExecSync => "exec_sync",
            Self::ExecFileSync => "exec_file_sync",
            Self::Spawn => "spawn",
            Self::Exec => "exec",
            Self::ExecFile => "exec_file",
        }
    }

    pub(super) fn from_discriminator(discriminator: &str) -> Option<Self> {
        Some(match discriminator {
            "\0processop:spawn_sync" => Self::SpawnSync,
            "\0processop:exec_sync" => Self::ExecSync,
            "\0processop:exec_file_sync" => Self::ExecFileSync,
            "\0processop:spawn" => Self::Spawn,
            "\0processop:exec" => Self::Exec,
            "\0processop:exec_file" => Self::ExecFile,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ChildProcessBuiltinCall {
    pub(super) operation: ChildProcessOperation,
}

impl ChildProcessBuiltinCall {
    pub(super) fn discriminator(self) -> String {
        format!("\0processop:{}", self.operation.as_str())
    }
}

pub(super) fn child_process_method_spec(method: &str) -> Option<(ChildProcessOperation, usize)> {
    Some(match method {
        "spawnSync" => (ChildProcessOperation::SpawnSync, 1),
        "execSync" => (ChildProcessOperation::ExecSync, 1),
        "execFileSync" => (ChildProcessOperation::ExecFileSync, 1),
        "spawn" => (ChildProcessOperation::Spawn, 1),
        "exec" => (ChildProcessOperation::Exec, 1),
        "execFile" => (ChildProcessOperation::ExecFile, 1),
        _ => return None,
    })
}

pub(super) fn is_child_process_alias_usage(expression: &Expression, alias: &str) -> bool {
    matches!(expression,
    Expression::Call { callee, arguments, .. }
        if module_alias_member_name(callee, alias)
            .and_then(child_process_method_spec)
            .is_some_and(|(_, minimum)| {
                arguments.len() >= minimum
                    && arguments
                        .iter()
                        .all(|argument| !matches!(argument, Expression::SpreadElement(_)))
            }))
}

pub(super) fn confirmed_child_process_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeMap::new();
    for (statement_index, statement) in body.iter().enumerate() {
        let Statement::VariableDeclaration(declaration) = statement else {
            continue;
        };
        if declaration.kind != VariableDeclarationKind::Const {
            continue;
        }
        for (declarator_index, declarator) in declaration.declarations.iter().enumerate() {
            if let (BindingPattern::Identifier(name), Some(initializer)) =
                (&declarator.pattern, &declarator.initializer)
                && is_require_child_process_module_initializer(initializer, binding_lookup)
            {
                candidates.insert(name.clone(), (statement_index, declarator_index));
            }
        }
    }

    candidates
        .into_iter()
        .filter(|(alias, (statement_index, declarator_index))| {
            !module_alias_has_predeclaration_hazard(
                body,
                *statement_index,
                *declarator_index,
                alias,
                LoweringOnlyModuleAliasSurface::ChildProcess,
                binding_lookup,
            ) && body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(
                    statement,
                    alias,
                    LoweringOnlyModuleAliasSurface::ChildProcess,
                )
            }) && !body.iter().any(|statement| {
                module_alias_statement_has_rejected_use(
                    statement,
                    alias,
                    LoweringOnlyModuleAliasSurface::ChildProcess,
                )
            })
        })
        .map(|(alias, _)| alias)
        .collect()
}

pub(super) fn is_child_process_module_object(
    expression: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    match expression {
        Expression::Call { .. } => {
            is_require_child_process_module_initializer(expression, binding_lookup)
        }
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&child_process_module_alias_sentinel(alias))
        }
        _ => false,
    }
}

pub(super) fn child_process_builtin_call(
    callee: &Expression,
    arguments: &[Expression],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<ChildProcessBuiltinCall> {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return None;
    };
    if !is_child_process_module_object(object, binding_lookup) {
        return None;
    }
    let (operation, minimum) = child_process_method_spec(well_formed_static_name(property)?)?;
    (arguments.len() >= minimum
        && arguments
            .iter()
            .all(|argument| !matches!(argument, Expression::SpreadElement(_))))
    .then_some(ChildProcessBuiltinCall { operation })
}

/// bd-suwvw: true when `specifier` names the Node timers module — `timers`
/// or `node:timers`.
pub(super) fn is_timers_module_specifier(specifier: &str) -> bool {
    specifier == "timers" || specifier == "node:timers"
}

/// bd-suwvw: true when `specifier` names the Node timers/promises module.
pub(super) fn is_timers_promises_module_specifier(specifier: &str) -> bool {
    specifier == "timers/promises" || specifier == "node:timers/promises"
}

/// bd-suwvw: sentinel key recording that `name` is bound to the timers module
/// via `const <name> = require('timers')` AND used as a recognized timers
/// export. Mirror of [`querystring_module_alias_sentinel`].
pub(super) fn timers_module_alias_sentinel(name: &str) -> String {
    format!("\0timersmod\0{name}")
}

/// bd-suwvw: sentinel key for a confirmed `require('timers/promises')` alias.
pub(super) fn timers_promises_module_alias_sentinel(name: &str) -> String {
    format!("\0timerspmod\0{name}")
}

/// bd-suwvw: true when `expr` is exactly `require('timers')` /
/// `require('node:timers')` with an unshadowed `require`.
pub(super) fn is_require_timers_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    if require_is_commonjs_wrapper(binding_lookup) {
        return false;
    }
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    if !matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
    {
        return false;
    }
    matches!(arguments.as_slice(), [spec]
        if well_formed_string_literal(spec).is_some_and(is_timers_module_specifier))
}

/// bd-suwvw: true when `expr` is exactly `require('timers/promises')` /
/// `require('node:timers/promises')` with an unshadowed `require`.
pub(super) fn is_require_timers_promises_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    if require_is_commonjs_wrapper(binding_lookup) {
        return false;
    }
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    if !matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
    {
        return false;
    }
    matches!(arguments.as_slice(), [spec]
        if well_formed_string_literal(spec).is_some_and(is_timers_promises_module_specifier))
}

/// bd-suwvw: true when `expr` IS the timers module object at lowering time —
/// a sentinel-recorded require-binding alias or the inline
/// `require('timers')` call.
pub(super) fn is_timers_module_object(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    match expr {
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&timers_module_alias_sentinel(alias))
        }
        Expression::Call { .. } => is_require_timers_module_initializer(expr, binding_lookup),
        _ => false,
    }
}

/// bd-suwvw: true when `expr` IS the timers/promises module object at
/// lowering time.
pub(super) fn is_timers_promises_module_object(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    match expr {
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&timers_promises_module_alias_sentinel(alias))
        }
        Expression::Call { .. } => {
            is_require_timers_promises_module_initializer(expr, binding_lookup)
        }
        _ => false,
    }
}

/// bd-suwvw: capability for a recognized `timers/promises` method call.
pub(super) fn timers_promises_method_capability(method: &str) -> Option<&'static str> {
    match method {
        "setTimeout" => Some("builtin:TimersPromisesSetTimeout"),
        "setInterval" => Some("builtin:TimersPromisesSetInterval"),
        "setImmediate" => Some("builtin:TimersPromisesSetImmediate"),
        _ => None,
    }
}

/// bd-suwvw: recognize a `timers/promises` builtin member call
/// (`tp.setTimeout(ms, value)`) and return its capability. Slot-0 argument
/// convention (no receiver placeholder), like the querystring builtins.
pub(super) fn timers_promises_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return None;
    };
    if !is_timers_promises_module_object(object, binding_lookup) {
        return None;
    }
    let method = well_formed_static_name(property)?;
    timers_promises_method_capability(method)
}

/// bd-suwvw: member READ of a recognized timers-module export on a confirmed
/// alias / inline require receiver (`timers.setTimeout` in value position —
/// e.g. `timers.setTimeout === setTimeout`). Returns the like-named GLOBAL to
/// lower the read as, so the module export and the injected runtime global
/// are the same first-class `BuiltinFunction` value and identity holds.
pub(super) fn timers_member_global_read(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    if computed {
        return None;
    }
    if !is_timers_module_object(object, binding_lookup) {
        return None;
    }
    let name = well_formed_static_name(property)?;
    timers_module_export_global(name)
}

/// bd-suwvw: scan-time twin of the timers member recognizers — during the
/// pre-scan the sentinels are not recorded yet, so the module-object
/// predicate is membership in the candidate alias-name set. A member READ
/// counts as usage (identity comparisons never call), so this matches the
/// Member node itself rather than only call callees.
pub(super) fn is_timers_alias_member(expr: &Expression, alias_names: &BTreeSet<String>) -> bool {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = expr
    else {
        return false;
    };
    if !matches!(object.as_ref(), Expression::Identifier(name) if alias_names.contains(name)) {
        return false;
    }
    well_formed_static_name(property)
        .is_some_and(|name| timers_module_export_global(name).is_some())
}

/// bd-suwvw: scan-time twin for timers/promises (member CALLS only — the
/// promises API is consumed by calling).
pub(super) fn is_timers_promises_alias_method_callee(
    callee: &Expression,
    alias_names: &BTreeSet<String>,
) -> bool {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return false;
    };
    if !matches!(object.as_ref(), Expression::Identifier(name) if alias_names.contains(name)) {
        return false;
    }
    well_formed_static_name(property)
        .is_some_and(|method| timers_promises_method_capability(method).is_some())
}

/// bd-suwvw: deep usage-scan walker for the timers module families. Unlike
/// the path/querystring/os scans (which keep function bodies opaque), the
/// timers scans recurse INTO arrow/function bodies: timer APIs are routinely
/// consumed inside callbacks and async IIFEs (`(async () => { for await (…
/// of tp.setInterval(10)) … })()`), and the member-call recognizers DO
/// intercept those sites at lowering (the sentinels are seeded into function
/// body lookups — see `seed_timers_module_alias_sentinels`), so confirming an
/// alias from an in-function usage is sound. Applies `base` at every visited
/// expression node.
pub(super) fn timers_scan_expr_deep<F: Fn(&Expression) -> bool>(
    expr: &Expression,
    base: &F,
) -> bool {
    if base(expr) {
        return true;
    }
    match expr {
        Expression::ArrowFunction { body, .. } => match body {
            ArrowBody::Expression(inner) => timers_scan_expr_deep(inner, base),
            ArrowBody::Block(block) => block
                .body
                .iter()
                .any(|stmt| timers_scan_statement_deep(stmt, base)),
        },
        Expression::Function { body, .. } => body
            .body
            .iter()
            .any(|stmt| timers_scan_statement_deep(stmt, base)),
        Expression::Call {
            callee, arguments, ..
        }
        | Expression::OptionalCall {
            callee, arguments, ..
        }
        | Expression::New { callee, arguments } => {
            timers_scan_expr_deep(callee, base)
                || arguments.iter().any(|a| timers_scan_expr_deep(a, base))
        }
        Expression::Member {
            object, property, ..
        }
        | Expression::OptionalMember {
            object, property, ..
        } => timers_scan_expr_deep(object, base) || timers_scan_expr_deep(property, base),
        Expression::Binary { left, right, .. } | Expression::Assignment { left, right, .. } => {
            timers_scan_expr_deep(left, base) || timers_scan_expr_deep(right, base)
        }
        Expression::Unary { argument, .. }
        | Expression::Await(argument)
        | Expression::SpreadElement(argument) => timers_scan_expr_deep(argument, base),
        Expression::Conditional {
            test,
            consequent,
            alternate,
        } => {
            timers_scan_expr_deep(test, base)
                || timers_scan_expr_deep(consequent, base)
                || timers_scan_expr_deep(alternate, base)
        }
        Expression::Yield {
            argument: Some(argument),
            ..
        } => timers_scan_expr_deep(argument, base),
        Expression::ArrayLiteral(elements) => elements
            .iter()
            .flatten()
            .any(|e| timers_scan_expr_deep(e, base)),
        Expression::TemplateLiteral { expressions, .. } => {
            expressions.iter().any(|e| timers_scan_expr_deep(e, base))
        }
        _ => false,
    }
}

/// bd-suwvw: statement-level twin of [`timers_scan_expr_deep`] — reuses the
/// shared control-flow statement recursion with the deep expression walker
/// as the predicate, and additionally enters function/class DECLARATION
/// bodies (the shared walker keeps those opaque; the timers scan must see
/// `function go() { tp.setTimeout(...) }`).
pub(super) fn timers_scan_statement_deep<F: Fn(&Expression) -> bool>(
    stmt: &Statement,
    base: &F,
) -> bool {
    match stmt {
        Statement::FunctionDeclaration(func) => func
            .body
            .body
            .iter()
            .any(|inner| timers_scan_statement_deep(inner, base)),
        Statement::ClassDeclaration(cls) => cls.body.iter().any(|method| {
            method
                .body
                .body
                .iter()
                .any(|inner| timers_scan_statement_deep(inner, base))
        }),
        Statement::Labeled(labeled) => timers_scan_statement_deep(&labeled.body, base),
        _ => path_statement_contains_usage(stmt, &|e| timers_scan_expr_deep(e, base)),
    }
}

/// bd-suwvw: copy the timers-family NUL-sentinels from the enclosing lookup
/// into a fresh function-body lookup, so the member call/read recognizers
/// keep working INSIDE function and arrow bodies (`(async () => {
/// tp.setTimeout(10) })()`). Scoped to the timers sentinels only — the other
/// module families keep their existing top-level-only recognition surface.
pub(super) fn seed_timers_module_alias_sentinels(
    body_lookup: &mut BTreeMap<String, BindingId>,
    outer_lookup: &BTreeMap<String, BindingId>,
) {
    seed_prefixed_sentinels(
        body_lookup,
        outer_lookup,
        &["\0timersmod\0", "\0timerspmod\0"],
    );
}

/// bd-fdqd4: retain authenticated zlib provenance in nested callbacks while
/// keeping the module object entirely lowering-only.
pub(super) fn seed_zlib_module_alias_sentinels(
    body_lookup: &mut BTreeMap<String, BindingId>,
    outer_lookup: &BTreeMap<String, BindingId>,
) {
    seed_prefixed_sentinels(body_lookup, outer_lookup, &["\0zlibmod\0"]);
    // Crypto shares the same immutable lowering-only alias lifetime: every
    // function-like scope that carries zlib provenance must also carry crypto
    // provenance, with the same lexical-shadow suppression below.
    seed_crypto_module_alias_sentinels(body_lookup, outer_lookup);
}

pub(super) fn suppress_zlib_module_sentinel(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    name: &str,
) {
    binding_lookup.remove(&zlib_module_alias_sentinel(name));
    suppress_crypto_module_sentinel(binding_lookup, name);
}

pub(super) fn suppress_zlib_module_sentinels(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    names: &BTreeSet<String>,
) {
    for name in names {
        binding_lookup.remove(&zlib_module_alias_sentinel(name));
    }
    suppress_crypto_module_sentinels(binding_lookup, names);
}

/// Retain authenticated crypto-module provenance in nested callbacks. The
/// runtime values returned by `createHash`/`createCipheriv` are ordinary heap
/// objects, but the module alias itself remains lowering-only.
pub(super) fn seed_crypto_module_alias_sentinels(
    body_lookup: &mut BTreeMap<String, BindingId>,
    outer_lookup: &BTreeMap<String, BindingId>,
) {
    seed_prefixed_sentinels(
        body_lookup,
        outer_lookup,
        &["\0cryptomod\0", "\0cryptoobj\0"],
    );
}

pub(super) fn suppress_crypto_module_sentinel(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    name: &str,
) {
    binding_lookup.remove(&crypto_module_alias_sentinel(name));
    binding_lookup.remove(&crypto_hash_object_alias_sentinel(name));
    binding_lookup.remove(&crypto_hmac_object_alias_sentinel(name));
    binding_lookup.remove(&crypto_cipher_object_alias_sentinel(name));
    // Buffer object authentication is intentionally not seeded into nested
    // function bodies, but every lexical-shadow path still removes a
    // scope-local sentinel before lowering the shadowed name.
    binding_lookup.remove(&buffer_object_alias_sentinel(name));
}

pub(super) fn suppress_crypto_module_sentinels(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    names: &BTreeSet<String>,
) {
    for name in names {
        suppress_crypto_module_sentinel(binding_lookup, name);
    }
}

/// Carry authenticated cluster provenance into nested functions. The facade
/// itself is a captured runtime binding, but the sentinel is still required so
/// lexical shadows suppress rather than spoof the pre-scan's finite surface.
pub(super) fn seed_cluster_module_alias_sentinels(
    body_lookup: &mut BTreeMap<String, BindingId>,
    outer_lookup: &BTreeMap<String, BindingId>,
) {
    seed_prefixed_sentinels(body_lookup, outer_lookup, &["\0clustermod\0"]);
}

pub(super) fn suppress_cluster_module_sentinel(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    name: &str,
) {
    binding_lookup.remove(&cluster_module_alias_sentinel(name));
}

pub(super) fn suppress_cluster_module_sentinels(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    names: &BTreeSet<String>,
) {
    for name in names {
        suppress_cluster_module_sentinel(binding_lookup, name);
    }
}

/// Carry authenticated child-process facade provenance into nested functions.
/// The sentinel only authenticates the syntactic module receiver; every actual
/// call still emits and is gated by `RuntimeCapability::ProcessSpawn`.
pub(super) fn seed_child_process_module_alias_sentinels(
    body_lookup: &mut BTreeMap<String, BindingId>,
    outer_lookup: &BTreeMap<String, BindingId>,
) {
    seed_prefixed_sentinels(body_lookup, outer_lookup, &["\0child-process-mod\0"]);
}

pub(super) fn suppress_child_process_module_sentinel(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    name: &str,
) {
    binding_lookup.remove(&child_process_module_alias_sentinel(name));
}

pub(super) fn suppress_child_process_module_sentinels(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    names: &BTreeSet<String>,
) {
    for name in names {
        suppress_child_process_module_sentinel(binding_lookup, name);
    }
}

/// bd-8u1t5: carry confirmed fs and fs/promises provenance into every fresh
/// function/method lookup. This makes the deep pre-scan actionable inside
/// callbacks, try/catch bodies, and promise arrows without creating a runtime
/// module object or widening the two existing fs capability classes.
pub(super) fn seed_fs_module_alias_sentinels(
    body_lookup: &mut BTreeMap<String, BindingId>,
    outer_lookup: &BTreeMap<String, BindingId>,
) {
    seed_prefixed_sentinels(
        body_lookup,
        outer_lookup,
        &[
            "\0fsmod\0",
            "\0fsnamed\0",
            "\0fsprommod\0",
            "\0fspromnamed\0",
        ],
    );
}

// ---------------------------------------------------------------------------
// Node `net` builtin recognition (bd-7qwej)
//
// The supported net slice is a finite lowering-only surface: exact static
// member calls on an unshadowed `require('net')` / `require('node:net')`
// receiver, or on a usage-confirmed alias of that receiver, lower directly to
// `builtin:Net*`. No module object is materialized. Computed/optional access,
// dynamic specifiers, unsupported exports, and bare possession therefore keep
// the ordinary fail-closed require behavior.

pub(super) fn is_net_module_specifier(specifier: &str) -> bool {
    specifier == "net" || specifier == "node:net"
}

pub(super) fn net_module_alias_sentinel(name: &str) -> String {
    format!("\0netmod\0{name}")
}

pub(super) fn suppress_net_module_sentinel(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    name: &str,
) {
    binding_lookup.remove(&net_module_alias_sentinel(name));
    // The same lexical declaration shadows a same-named TLS alias sentinel.
    binding_lookup.remove(&tls_module_alias_sentinel(name));
    binding_lookup.remove(&http_module_alias_sentinel(name));
    binding_lookup.remove(&https_module_alias_sentinel(name));
    for capability in [
        "builtin:HttpCreateServer",
        "builtin:HttpGet",
        "builtin:HttpRequest",
        "net:request",
        "net:client_request",
    ] {
        binding_lookup.remove(&http_named_import_sentinel(name, capability));
    }
}

pub(super) fn suppress_net_module_sentinels(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    names: &BTreeSet<String>,
) {
    for name in names {
        suppress_net_module_sentinel(binding_lookup, name);
    }
}

pub(super) fn seed_net_module_alias_sentinels(
    body_lookup: &mut BTreeMap<String, BindingId>,
    outer_lookup: &BTreeMap<String, BindingId>,
) {
    seed_prefixed_sentinels(
        body_lookup,
        outer_lookup,
        &["\0netmod\0", "\0httpmod\0", "\0httpsmod\0", "\0httpnamed\0"],
    );
}

pub(super) fn is_require_net_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    if !matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
    {
        return false;
    }
    matches!(arguments.as_slice(), [specifier]
        if well_formed_string_literal(specifier).is_some_and(is_net_module_specifier))
}

pub(super) fn net_method_capability(method: &str) -> Option<&'static str> {
    match method {
        "isIP" => Some("builtin:NetIsIP"),
        "isIPv4" => Some("builtin:NetIsIPv4"),
        "isIPv6" => Some("builtin:NetIsIPv6"),
        "createServer" => Some("builtin:NetCreateServer"),
        "connect" => Some("builtin:NetConnect"),
        "createConnection" => Some("builtin:NetCreateConnection"),
        _ => None,
    }
}

pub(super) fn is_net_module_object(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    match expr {
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&net_module_alias_sentinel(alias))
        }
        Expression::Call { .. } => is_require_net_module_initializer(expr, binding_lookup),
        _ => false,
    }
}

pub(super) fn net_member_name<'a>(
    callee: &'a Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'a str> {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return None;
    };
    if !is_net_module_object(object, binding_lookup) {
        return None;
    }
    well_formed_static_name(property)
}

pub(super) fn net_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    net_member_name(callee, binding_lookup).and_then(net_method_capability)
}

pub(super) fn net_socket_constructor_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    (net_member_name(callee, binding_lookup) == Some("Socket")).then_some("builtin:NetSocket")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LoweringOnlyModuleAliasSurface {
    Net,
    Http,
    HttpsExternal,
    HttpNamedCreateServer,
    HttpNamedRequest,
    Tls,
    Zlib,
    Crypto,
    CryptoHashObject,
    CryptoHmacObject,
    CryptoCipherObject,
    BufferObject,
    Cluster,
    ChildProcess,
    StreamConstructor,
    StreamPipeline,
    StreamPromises,
    EventEmitter,
    EventsOnce,
    EventsModule,
    UrlModule,
    UrlNamed,
}

impl LoweringOnlyModuleAliasSurface {
    pub(super) fn is_crypto_object(self) -> bool {
        matches!(
            self,
            Self::CryptoHashObject | Self::CryptoHmacObject | Self::CryptoCipherObject
        )
    }

    pub(super) fn is_authenticated_object(self) -> bool {
        self.is_crypto_object() || self == Self::BufferObject
    }
}

pub(super) fn module_alias_member_name<'a>(callee: &'a Expression, alias: &str) -> Option<&'a str> {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return None;
    };
    if !matches!(object.as_ref(), Expression::Identifier(name) if name == alias) {
        return None;
    }
    well_formed_static_name(property)
}

pub(super) fn net_alias_member_name<'a>(callee: &'a Expression, alias: &str) -> Option<&'a str> {
    module_alias_member_name(callee, alias)
}

pub(super) fn tls_alias_member_name<'a>(
    expression: &'a Expression,
    alias: &str,
) -> Option<&'a str> {
    module_alias_member_name(expression, alias)
}

pub(super) fn is_tls_alias_call(expr: &Expression, alias: &str) -> bool {
    matches!(expr,
        Expression::Call { callee, .. }
            if tls_alias_member_name(callee, alias)
                .is_some_and(|method| tls_method_capability(method).is_some()))
}

pub(super) fn is_tls_alias_constant_read(expr: &Expression, alias: &str) -> bool {
    tls_alias_member_name(expr, alias)
        .is_some_and(|property| tls_property_read_lowering(property).is_some())
}

pub(super) fn is_net_alias_usage(expr: &Expression, alias: &str) -> bool {
    match expr {
        Expression::Call { callee, .. } => net_alias_member_name(callee, alias)
            .is_some_and(|method| net_method_capability(method).is_some()),
        Expression::New { callee, .. } => net_alias_member_name(callee, alias) == Some("Socket"),
        Expression::Binary {
            operator: BinaryOperator::Instanceof,
            right,
            ..
        } => net_alias_member_name(right, alias) == Some("Socket"),
        _ => false,
    }
}

pub(super) fn is_http_alias_usage(expr: &Expression, alias: &str) -> bool {
    match expr {
        Expression::Call {
            callee, arguments, ..
        } => module_alias_member_name(callee, alias).is_some_and(|method| {
            http_method_capability(method).is_some()
                && (method == "createServer" || !arguments.is_empty())
        }),
        Expression::New { callee, .. } => module_alias_member_name(callee, alias) == Some("Agent"),
        Expression::Member { .. } => module_alias_member_name(expr, alias)
            .is_some_and(|property| http_property_capability(property).is_some()),
        _ => false,
    }
}

pub(super) fn is_https_external_alias_usage(expr: &Expression, alias: &str) -> bool {
    matches!(expr,
        Expression::Call { callee, arguments, .. }
            if module_alias_member_name(callee, alias)
                .is_some_and(|method| https_external_method_capability(method).is_some())
                && !arguments.is_empty())
}

pub(super) fn is_http_named_alias_usage(
    expr: &Expression,
    alias: &str,
    allow_zero_arguments: bool,
) -> bool {
    matches!(expr,
        Expression::Call { callee, arguments, .. }
            if matches!(callee.as_ref(), Expression::Identifier(name) if name == alias)
                && (allow_zero_arguments || !arguments.is_empty()))
}

pub(super) fn is_module_alias_usage(
    expr: &Expression,
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> bool {
    match surface {
        LoweringOnlyModuleAliasSurface::Net => is_net_alias_usage(expr, alias),
        LoweringOnlyModuleAliasSurface::Http => is_http_alias_usage(expr, alias),
        LoweringOnlyModuleAliasSurface::HttpsExternal => is_https_external_alias_usage(expr, alias),
        LoweringOnlyModuleAliasSurface::HttpNamedCreateServer => {
            is_http_named_alias_usage(expr, alias, true)
        }
        LoweringOnlyModuleAliasSurface::HttpNamedRequest => {
            is_http_named_alias_usage(expr, alias, false)
        }
        LoweringOnlyModuleAliasSurface::Tls => {
            is_tls_alias_call(expr, alias) || is_tls_alias_constant_read(expr, alias)
        }
        LoweringOnlyModuleAliasSurface::Zlib => is_zlib_alias_usage(expr, alias),
        LoweringOnlyModuleAliasSurface::Crypto => is_crypto_alias_usage(expr, alias),
        LoweringOnlyModuleAliasSurface::CryptoHashObject
        | LoweringOnlyModuleAliasSurface::CryptoHmacObject
        | LoweringOnlyModuleAliasSurface::CryptoCipherObject => {
            is_crypto_object_alias_usage(expr, alias, surface)
        }
        LoweringOnlyModuleAliasSurface::BufferObject => is_buffer_object_alias_usage(expr, alias),
        LoweringOnlyModuleAliasSurface::Cluster => is_cluster_alias_usage(expr, alias),
        LoweringOnlyModuleAliasSurface::ChildProcess => is_child_process_alias_usage(expr, alias),
        LoweringOnlyModuleAliasSurface::StreamConstructor => is_stream_constructor_use(expr, alias),
        LoweringOnlyModuleAliasSurface::StreamPipeline => {
            is_stream_pipeline_direct_call(expr, alias)
        }
        LoweringOnlyModuleAliasSurface::StreamPromises => {
            is_stream_promises_pipeline_call(expr, alias)
        }
        LoweringOnlyModuleAliasSurface::EventEmitter => is_event_emitter_usage(expr, alias),
        LoweringOnlyModuleAliasSurface::EventsOnce => is_events_once_direct_call(expr, alias),
        LoweringOnlyModuleAliasSurface::EventsModule => {
            is_events_alias_capture_rejections_read(expr, alias)
                || is_events_alias_once_call(expr, alias)
        }
        LoweringOnlyModuleAliasSurface::UrlModule => is_url_module_alias_usage(expr, alias),
        LoweringOnlyModuleAliasSurface::UrlNamed => is_url_named_binding_usage(expr, alias),
    }
}

pub(super) fn net_pattern_binds_alias(pattern: &BindingPattern, alias: &str) -> bool {
    pattern.binding_names().contains(&alias)
}

pub(super) fn module_alias_binding_pattern_contains_unshadowed_usage(
    pattern: &BindingPattern,
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> bool {
    match pattern {
        BindingPattern::Identifier(_) => false,
        BindingPattern::ObjectPattern(properties) => properties.iter().any(|property| {
            (property.computed
                && module_alias_expr_contains_unshadowed_usage(&property.key, alias, surface))
                || module_alias_binding_pattern_contains_unshadowed_usage(
                    &property.value,
                    alias,
                    surface,
                )
        }),
        BindingPattern::ArrayPattern(elements) => elements.iter().flatten().any(|element| {
            module_alias_binding_pattern_contains_unshadowed_usage(element, alias, surface)
        }),
        BindingPattern::Rest(inner) => {
            module_alias_binding_pattern_contains_unshadowed_usage(inner, alias, surface)
        }
        BindingPattern::AssignmentPattern { left, right } => {
            module_alias_binding_pattern_contains_unshadowed_usage(left, alias, surface)
                || module_alias_expr_contains_unshadowed_usage(right, alias, surface)
        }
    }
}

pub(super) fn module_alias_binding_pattern_has_rejected_use(
    pattern: &BindingPattern,
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> bool {
    match pattern {
        BindingPattern::Identifier(_) => false,
        BindingPattern::ObjectPattern(properties) => properties.iter().any(|property| {
            (property.computed && module_alias_expr_has_rejected_use(&property.key, alias, surface))
                || module_alias_binding_pattern_has_rejected_use(&property.value, alias, surface)
        }),
        BindingPattern::ArrayPattern(elements) => elements
            .iter()
            .flatten()
            .any(|element| module_alias_binding_pattern_has_rejected_use(element, alias, surface)),
        BindingPattern::Rest(inner) => {
            module_alias_binding_pattern_has_rejected_use(inner, alias, surface)
        }
        BindingPattern::AssignmentPattern { left, right } => {
            module_alias_binding_pattern_has_rejected_use(left, alias, surface)
                || module_alias_expr_has_rejected_use(right, alias, surface)
        }
    }
}

pub(super) fn net_statement_hoists_var_alias(statement: &Statement, alias: &str) -> bool {
    match statement {
        Statement::VariableDeclaration(declaration)
            if declaration.kind == VariableDeclarationKind::Var =>
        {
            declaration
                .declarations
                .iter()
                .any(|declarator| net_pattern_binds_alias(&declarator.pattern, alias))
        }
        Statement::Block(block) => block
            .body
            .iter()
            .any(|inner| net_statement_hoists_var_alias(inner, alias)),
        Statement::If(if_statement) => {
            net_statement_hoists_var_alias(&if_statement.consequent, alias)
                || if_statement
                    .alternate
                    .as_deref()
                    .is_some_and(|alternate| net_statement_hoists_var_alias(alternate, alias))
        }
        Statement::For(for_statement) => {
            for_statement
                .init
                .as_deref()
                .is_some_and(|init| net_statement_hoists_var_alias(init, alias))
                || net_statement_hoists_var_alias(&for_statement.body, alias)
        }
        Statement::ForIn(for_statement) => {
            (for_statement.binding_kind == Some(VariableDeclarationKind::Var)
                && net_pattern_binds_alias(&for_statement.binding, alias))
                || net_statement_hoists_var_alias(&for_statement.body, alias)
        }
        Statement::ForOf(for_statement) => {
            (for_statement.binding_kind == Some(VariableDeclarationKind::Var)
                && net_pattern_binds_alias(&for_statement.binding, alias))
                || net_statement_hoists_var_alias(&for_statement.body, alias)
        }
        Statement::While(while_statement) => {
            net_statement_hoists_var_alias(&while_statement.body, alias)
        }
        Statement::DoWhile(do_while_statement) => {
            net_statement_hoists_var_alias(&do_while_statement.body, alias)
        }
        Statement::TryCatch(try_statement) => {
            try_statement
                .block
                .body
                .iter()
                .any(|inner| net_statement_hoists_var_alias(inner, alias))
                || try_statement.handler.as_ref().is_some_and(|handler| {
                    handler
                        .body
                        .body
                        .iter()
                        .any(|inner| net_statement_hoists_var_alias(inner, alias))
                })
                || try_statement.finalizer.as_ref().is_some_and(|finalizer| {
                    finalizer
                        .body
                        .iter()
                        .any(|inner| net_statement_hoists_var_alias(inner, alias))
                })
        }
        Statement::Switch(switch_statement) => switch_statement.cases.iter().any(|case| {
            case.consequent
                .iter()
                .any(|inner| net_statement_hoists_var_alias(inner, alias))
        }),
        Statement::Labeled(labeled) => net_statement_hoists_var_alias(&labeled.body, alias),
        // Nested function/class declarations introduce distinct function
        // scopes, so their `var` declarations do not hoist into this one.
        Statement::FunctionDeclaration(_) | Statement::ClassDeclaration(_) => false,
        _ => false,
    }
}

pub(super) fn net_function_scope_shadows_alias(
    name: Option<&str>,
    params: &[FunctionParam],
    body: &[Statement],
    alias: &str,
) -> bool {
    name == Some(alias)
        || params
            .iter()
            .any(|param| net_pattern_binds_alias(&param.pattern, alias))
        || direct_lexical_binding_names(body).contains(alias)
        || body
            .iter()
            .any(|statement| net_statement_hoists_var_alias(statement, alias))
}

pub(super) fn crypto_object_params_have_outer_alias_use(
    name: Option<&str>,
    params: &[FunctionParam],
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> bool {
    if name == Some(alias)
        || params
            .iter()
            .any(|param| net_pattern_binds_alias(&param.pattern, alias))
    {
        return false;
    }
    params.iter().any(|param| {
        module_alias_binding_pattern_contains_unshadowed_usage(&param.pattern, alias, surface)
            || module_alias_binding_pattern_has_rejected_use(&param.pattern, alias, surface)
    })
}

pub(super) fn crypto_object_body_has_outer_alias_use(
    name: Option<&str>,
    params: &[FunctionParam],
    body: &[Statement],
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> bool {
    !net_function_scope_shadows_alias(name, params, body, alias)
        && body.iter().any(|statement| {
            module_alias_statement_contains_unshadowed_usage(statement, alias, surface)
                || module_alias_statement_has_rejected_use(statement, alias, surface)
        })
}

pub(super) fn module_alias_expr_contains_unshadowed_usage(
    expr: &Expression,
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> bool {
    if is_module_alias_usage(expr, alias, surface) {
        return true;
    }
    match expr {
        Expression::ArrowFunction { params, body, .. } => {
            if params
                .iter()
                .any(|param| net_pattern_binds_alias(&param.pattern, alias))
            {
                return false;
            }
            if surface.is_authenticated_object() {
                return params.iter().any(|param| {
                    module_alias_binding_pattern_contains_unshadowed_usage(
                        &param.pattern,
                        alias,
                        surface,
                    ) || module_alias_binding_pattern_has_rejected_use(
                        &param.pattern,
                        alias,
                        surface,
                    )
                }) || match body {
                    ArrowBody::Expression(inner) => {
                        module_alias_expr_contains_unshadowed_usage(inner, alias, surface)
                            || module_alias_expr_has_rejected_use(inner, alias, surface)
                    }
                    ArrowBody::Block(block) => block.body.iter().any(|statement| {
                        module_alias_statement_contains_unshadowed_usage(statement, alias, surface)
                            || module_alias_statement_has_rejected_use(statement, alias, surface)
                    }),
                };
            }
            params.iter().any(|param| {
                module_alias_binding_pattern_contains_unshadowed_usage(
                    &param.pattern,
                    alias,
                    surface,
                )
            }) || match body {
                ArrowBody::Expression(inner) => {
                    module_alias_expr_contains_unshadowed_usage(inner, alias, surface)
                }
                ArrowBody::Block(block) => {
                    if net_function_scope_shadows_alias(None, params, &block.body, alias) {
                        return false;
                    }
                    block.body.iter().any(|statement| {
                        module_alias_statement_contains_unshadowed_usage(statement, alias, surface)
                    })
                }
            }
        }
        Expression::Function {
            name, params, body, ..
        } => {
            !net_function_scope_shadows_alias(name.as_deref(), params, &body.body, alias)
                && (params.iter().any(|param| {
                    module_alias_binding_pattern_contains_unshadowed_usage(
                        &param.pattern,
                        alias,
                        surface,
                    )
                }) || body.body.iter().any(|statement| {
                    module_alias_statement_contains_unshadowed_usage(statement, alias, surface)
                }))
        }
        Expression::Call {
            callee, arguments, ..
        }
        | Expression::OptionalCall {
            callee, arguments, ..
        }
        | Expression::New { callee, arguments } => {
            module_alias_expr_contains_unshadowed_usage(callee, alias, surface)
                || arguments.iter().any(|argument| {
                    module_alias_expr_contains_unshadowed_usage(argument, alias, surface)
                })
        }
        Expression::Member {
            object, property, ..
        }
        | Expression::OptionalMember {
            object, property, ..
        } => {
            module_alias_expr_contains_unshadowed_usage(object, alias, surface)
                || module_alias_expr_contains_unshadowed_usage(property, alias, surface)
        }
        Expression::Binary { left, right, .. } | Expression::Assignment { left, right, .. } => {
            module_alias_expr_contains_unshadowed_usage(left, alias, surface)
                || module_alias_expr_contains_unshadowed_usage(right, alias, surface)
        }
        Expression::Unary { argument, .. }
        | Expression::Await(argument)
        | Expression::SpreadElement(argument) => {
            module_alias_expr_contains_unshadowed_usage(argument, alias, surface)
        }
        Expression::Conditional {
            test,
            consequent,
            alternate,
        } => {
            module_alias_expr_contains_unshadowed_usage(test, alias, surface)
                || module_alias_expr_contains_unshadowed_usage(consequent, alias, surface)
                || module_alias_expr_contains_unshadowed_usage(alternate, alias, surface)
        }
        Expression::Yield {
            argument: Some(argument),
            ..
        } => module_alias_expr_contains_unshadowed_usage(argument, alias, surface),
        Expression::ArrayLiteral(elements) => elements
            .iter()
            .flatten()
            .any(|element| module_alias_expr_contains_unshadowed_usage(element, alias, surface)),
        Expression::ObjectLiteral(properties) => properties.iter().any(|property| {
            (property.computed
                && module_alias_expr_contains_unshadowed_usage(&property.key, alias, surface))
                || module_alias_expr_contains_unshadowed_usage(&property.value, alias, surface)
        }),
        Expression::TemplateLiteral { expressions, .. } => expressions.iter().any(|expression| {
            module_alias_expr_contains_unshadowed_usage(expression, alias, surface)
        }),
        Expression::ClassExpression {
            name,
            super_class,
            body,
            ..
        } => {
            if surface.is_authenticated_object()
                && name.as_deref() != Some(alias)
                && body.iter().any(|method| {
                    !net_function_scope_shadows_alias(
                        None,
                        &method.params,
                        &method.body.body,
                        alias,
                    ) && (method.params.iter().any(|param| {
                        module_alias_binding_pattern_contains_unshadowed_usage(
                            &param.pattern,
                            alias,
                            surface,
                        ) || module_alias_binding_pattern_has_rejected_use(
                            &param.pattern,
                            alias,
                            surface,
                        )
                    }) || method.body.body.iter().any(|statement| {
                        module_alias_statement_contains_unshadowed_usage(statement, alias, surface)
                            || module_alias_statement_has_rejected_use(statement, alias, surface)
                    }))
                })
            {
                return true;
            }
            super_class.as_deref().is_some_and(|super_class| {
                is_event_emitter_heritage(super_class, alias, surface)
                    || module_alias_expr_contains_unshadowed_usage(super_class, alias, surface)
            }) || (name.as_deref() != Some(alias)
                && body.iter().any(|method| {
                    (method.computed
                        && module_alias_expr_contains_unshadowed_usage(&method.key, alias, surface))
                        || (!net_function_scope_shadows_alias(
                            None,
                            &method.params,
                            &method.body.body,
                            alias,
                        ) && (method.params.iter().any(|param| {
                            module_alias_binding_pattern_contains_unshadowed_usage(
                                &param.pattern,
                                alias,
                                surface,
                            )
                        }) || method.body.body.iter().any(|statement| {
                            module_alias_statement_contains_unshadowed_usage(
                                statement, alias, surface,
                            )
                        })))
                }))
        }
        _ => false,
    }
}

/// True when an assignment/delete/update target mutates the lowering-only
/// module alias itself. Reads from real values returned by an accepted builtin
/// remain ordinary JavaScript (`tls.rootCertificates[0] = value` is not a
/// module-object mutation), but writing `tls.rootCertificates` or `tls.connect`
/// must keep the ambient `require` denial intact.
pub(super) fn module_alias_write_target_has_rejected_use(
    target: &Expression,
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> bool {
    match target {
        Expression::Identifier(name) => name == alias,
        Expression::Member {
            object,
            property,
            computed,
            ..
        }
        | Expression::OptionalMember {
            object,
            property,
            computed,
            ..
        } => {
            module_alias_member_name(target, alias).is_some()
                || (surface == LoweringOnlyModuleAliasSurface::Zlib
                    && module_alias_expr_contains_unshadowed_usage(target, alias, surface))
                || (surface == LoweringOnlyModuleAliasSurface::Crypto
                    && module_alias_expr_contains_unshadowed_usage(target, alias, surface))
                || (surface.is_authenticated_object()
                    && module_alias_expr_contains_unshadowed_usage(target, alias, surface))
                || (surface == LoweringOnlyModuleAliasSurface::Cluster
                    && module_alias_expr_contains_unshadowed_usage(target, alias, surface))
                || module_alias_expr_has_rejected_use(object, alias, surface)
                || (*computed && module_alias_expr_has_rejected_use(property, alias, surface))
        }
        _ => module_alias_expr_has_rejected_use(target, alias, surface),
    }
}

/// True when an unshadowed alias occurrence is used outside the finite static
/// surface selected by `surface`. An accepted call/read consumes its receiver
/// here (so the module identifier is not mistaken for a bare escape), but call
/// arguments and write targets are still scanned.
pub(super) fn module_alias_expr_has_rejected_use(
    expr: &Expression,
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> bool {
    if surface.is_crypto_object()
        && let Some(rejected) =
            crypto_object_alias_closed_result_call_rejected_use(expr, alias, surface)
    {
        return rejected;
    }
    match expr {
        Expression::Identifier(name) => name == alias,
        Expression::Call { .. }
            if surface == LoweringOnlyModuleAliasSurface::Cluster
                && is_discarded_cluster_listener_registration(expr, alias) =>
        {
            true
        }
        // bd-zco6t: passing the confirmed Buffer alias into the numeric fd
        // read/write (`fs.readSync(fd, buf, ...)` / `fs.writeSync(fd, buf)`)
        // is an engine-consumed use, not an escape: the fd dispatch mutates
        // or reads the bytes in place and never observes or re-exposes the
        // object. This acceptance is syntactic only — the flow layer remains
        // the enforcement point. BufferObject is preserved through the
        // generic GetProperty/CallMethod invalidation (so intervening
        // `fs.*` / `console.log` keep the engine receiver for
        // `buf.toString`); StoreBinding of a new value still overwrites.
        // A rewritten `builtin:BufferObjectToString` whose receiver is not
        // BufferObject takes the fail-closed TopSecret arm.
        Expression::Call {
            callee, arguments, ..
        } if surface == LoweringOnlyModuleAliasSurface::BufferObject
            && matches!(
                callee.as_ref(),
                Expression::Member {
                    object,
                    property,
                    computed: false,
                    ..
                } if matches!(
                    object.as_ref(),
                    Expression::Identifier(receiver) if receiver != alias
                ) && matches!(
                    well_formed_static_name(property),
                    Some("readSync" | "writeSync")
                )
            ) =>
        {
            arguments.iter().any(|argument| {
                !matches!(argument, Expression::Identifier(name) if name == alias)
                    && module_alias_expr_has_rejected_use(argument, alias, surface)
            })
        }
        Expression::Call {
            callee, arguments, ..
        } if surface == LoweringOnlyModuleAliasSurface::EventEmitter
            && matches!(callee.as_ref(), Expression::Identifier(name) if name == alias) =>
        {
            arguments
                .iter()
                .any(|argument| module_alias_expr_has_rejected_use(argument, alias, surface))
        }
        Expression::Call {
            callee, arguments, ..
        } if match surface {
            LoweringOnlyModuleAliasSurface::Net => net_alias_member_name(callee, alias)
                .is_some_and(|method| net_method_capability(method).is_some()),
            LoweringOnlyModuleAliasSurface::Http => module_alias_member_name(callee, alias)
                .is_some_and(|method| {
                    http_method_capability(method).is_some()
                        && (method == "createServer" || !arguments.is_empty())
                }),
            LoweringOnlyModuleAliasSurface::HttpsExternal => {
                module_alias_member_name(callee, alias)
                    .is_some_and(|method| https_external_method_capability(method).is_some())
                    && !arguments.is_empty()
            }
            LoweringOnlyModuleAliasSurface::HttpNamedCreateServer => {
                is_http_named_alias_usage(expr, alias, true)
            }
            LoweringOnlyModuleAliasSurface::HttpNamedRequest => {
                is_http_named_alias_usage(expr, alias, false)
            }
            LoweringOnlyModuleAliasSurface::Tls => is_tls_alias_call(expr, alias),
            LoweringOnlyModuleAliasSurface::Zlib => module_alias_member_name(callee, alias)
                .is_some_and(|method| zlib_method_capability(method).is_some()),
            LoweringOnlyModuleAliasSurface::Crypto => module_alias_member_name(callee, alias)
                .is_some_and(|method| crypto_method_call_capability(method, arguments).is_some()),
            LoweringOnlyModuleAliasSurface::CryptoHashObject
            | LoweringOnlyModuleAliasSurface::CryptoHmacObject
            | LoweringOnlyModuleAliasSurface::CryptoCipherObject => {
                is_crypto_object_alias_usage(expr, alias, surface)
            }
            LoweringOnlyModuleAliasSurface::BufferObject => {
                is_buffer_object_alias_usage(expr, alias)
            }
            LoweringOnlyModuleAliasSurface::Cluster => module_alias_member_name(callee, alias)
                .is_some_and(|method| {
                    cluster_method_is_supported(method) && !matches!(method, "on" | "once")
                }),
            LoweringOnlyModuleAliasSurface::ChildProcess => {
                is_child_process_alias_usage(expr, alias)
            }
            LoweringOnlyModuleAliasSurface::StreamConstructor => false,
            LoweringOnlyModuleAliasSurface::StreamPipeline => {
                is_stream_pipeline_direct_call(expr, alias)
            }
            LoweringOnlyModuleAliasSurface::StreamPromises => {
                is_stream_promises_pipeline_call(expr, alias)
            }
            LoweringOnlyModuleAliasSurface::EventEmitter => false,
            LoweringOnlyModuleAliasSurface::EventsOnce => is_events_once_direct_call(expr, alias),
            LoweringOnlyModuleAliasSurface::EventsModule => is_events_alias_once_call(expr, alias),
            LoweringOnlyModuleAliasSurface::UrlModule => is_url_module_alias_usage(expr, alias),
            LoweringOnlyModuleAliasSurface::UrlNamed => is_url_named_binding_usage(expr, alias),
        } =>
        {
            is_discarded_crypto_identity_call(expr, alias, surface)
                || arguments
                    .iter()
                    .any(|argument| module_alias_expr_has_rejected_use(argument, alias, surface))
        }
        Expression::New { callee, arguments }
            if surface == LoweringOnlyModuleAliasSurface::Net
                && net_alias_member_name(callee, alias) == Some("Socket") =>
        {
            arguments
                .iter()
                .any(|argument| module_alias_expr_has_rejected_use(argument, alias, surface))
        }
        Expression::New { callee, arguments }
            if surface == LoweringOnlyModuleAliasSurface::Http
                && module_alias_member_name(callee, alias) == Some("Agent") =>
        {
            arguments
                .iter()
                .any(|argument| module_alias_expr_has_rejected_use(argument, alias, surface))
        }
        Expression::New { callee, arguments }
            if surface == LoweringOnlyModuleAliasSurface::StreamConstructor
                && matches!(callee.as_ref(), Expression::Identifier(name) if name == alias) =>
        {
            arguments
                .iter()
                .any(|argument| module_alias_expr_has_rejected_use(argument, alias, surface))
        }
        Expression::New { arguments, .. }
            if surface == LoweringOnlyModuleAliasSurface::EventEmitter
                && is_event_emitter_usage(expr, alias) =>
        {
            arguments
                .iter()
                .any(|argument| module_alias_expr_has_rejected_use(argument, alias, surface))
        }
        Expression::Binary {
            operator: BinaryOperator::Instanceof,
            left,
            right,
        } if surface == LoweringOnlyModuleAliasSurface::Cluster
            && matches!(left.as_ref(), Expression::Identifier(name) if name == alias) =>
        {
            module_alias_expr_has_rejected_use(right, alias, surface)
        }
        Expression::Binary {
            operator: BinaryOperator::Instanceof,
            left,
            right,
        } if surface == LoweringOnlyModuleAliasSurface::EventEmitter
            && matches!(right.as_ref(), Expression::Identifier(name) if name == alias) =>
        {
            module_alias_expr_has_rejected_use(left, alias, surface)
        }
        Expression::Binary {
            operator: BinaryOperator::StrictEqual | BinaryOperator::StrictNotEqual,
            left,
            right,
        } if surface == LoweringOnlyModuleAliasSurface::EventEmitter
            && matches!(left.as_ref(), Expression::Identifier(name) if name == alias) =>
        {
            !matches!(right.as_ref(), Expression::Identifier(name) if name == alias)
                && module_alias_expr_has_rejected_use(right, alias, surface)
        }
        Expression::Binary {
            operator: BinaryOperator::StrictEqual | BinaryOperator::StrictNotEqual,
            left,
            right,
        } if surface == LoweringOnlyModuleAliasSurface::EventEmitter
            && matches!(right.as_ref(), Expression::Identifier(name) if name == alias) =>
        {
            module_alias_expr_has_rejected_use(left, alias, surface)
        }
        Expression::Binary {
            operator: BinaryOperator::Instanceof,
            left,
            right,
        } if surface == LoweringOnlyModuleAliasSurface::Net
            && net_alias_member_name(right, alias) == Some("Socket") =>
        {
            module_alias_expr_has_rejected_use(left, alias, surface)
        }
        Expression::Member { .. }
            if surface == LoweringOnlyModuleAliasSurface::Tls
                && is_tls_alias_constant_read(expr, alias) =>
        {
            false
        }
        Expression::Member { .. }
            if surface == LoweringOnlyModuleAliasSurface::Zlib
                && module_alias_member_name(expr, alias) == Some("constants") =>
        {
            false
        }
        Expression::Member { .. }
            if surface == LoweringOnlyModuleAliasSurface::Crypto
                && module_alias_member_name(expr, alias) == Some("constants") =>
        {
            false
        }
        Expression::Member { .. }
            if surface == LoweringOnlyModuleAliasSurface::Http
                && module_alias_member_name(expr, alias)
                    .is_some_and(|property| http_property_capability(property).is_some()) =>
        {
            false
        }
        Expression::Member { .. }
            if surface == LoweringOnlyModuleAliasSurface::Cluster
                && module_alias_member_name(expr, alias)
                    .is_some_and(cluster_property_is_supported) =>
        {
            false
        }
        Expression::Member { .. }
            if matches!(
                surface,
                LoweringOnlyModuleAliasSurface::EventEmitter
                    | LoweringOnlyModuleAliasSurface::EventsModule
            ) && is_module_alias_usage(expr, alias, surface) =>
        {
            false
        }
        Expression::Unary {
            operator: UnaryOperator::Typeof,
            argument,
        } if surface == LoweringOnlyModuleAliasSurface::EventEmitter
            && matches!(argument.as_ref(), Expression::Identifier(name) if name == alias) =>
        {
            false
        }
        Expression::ArrowFunction { params, body, .. } => {
            if params
                .iter()
                .any(|param| net_pattern_binds_alias(&param.pattern, alias))
            {
                return false;
            }
            if surface.is_authenticated_object() {
                return params.iter().any(|param| {
                    module_alias_binding_pattern_contains_unshadowed_usage(
                        &param.pattern,
                        alias,
                        surface,
                    ) || module_alias_binding_pattern_has_rejected_use(
                        &param.pattern,
                        alias,
                        surface,
                    )
                }) || match body {
                    ArrowBody::Expression(inner) => {
                        module_alias_expr_contains_unshadowed_usage(inner, alias, surface)
                            || module_alias_expr_has_rejected_use(inner, alias, surface)
                    }
                    ArrowBody::Block(block) => {
                        if net_function_scope_shadows_alias(None, params, &block.body, alias) {
                            false
                        } else {
                            block.body.iter().any(|statement| {
                                module_alias_statement_contains_unshadowed_usage(
                                    statement, alias, surface,
                                ) || module_alias_statement_has_rejected_use(
                                    statement, alias, surface,
                                )
                            })
                        }
                    }
                };
            }
            params.iter().any(|param| {
                module_alias_binding_pattern_has_rejected_use(&param.pattern, alias, surface)
            }) || match body {
                ArrowBody::Expression(inner) => {
                    module_alias_expr_has_rejected_use(inner, alias, surface)
                }
                ArrowBody::Block(block) => {
                    if net_function_scope_shadows_alias(None, params, &block.body, alias) {
                        false
                    } else {
                        block.body.iter().any(|statement| {
                            module_alias_statement_has_rejected_use(statement, alias, surface)
                        })
                    }
                }
            }
        }
        Expression::Function {
            name, params, body, ..
        } => {
            let unshadowed =
                !net_function_scope_shadows_alias(name.as_deref(), params, &body.body, alias);
            if surface.is_authenticated_object() {
                return crypto_object_params_have_outer_alias_use(
                    name.as_deref(),
                    params,
                    alias,
                    surface,
                ) || crypto_object_body_has_outer_alias_use(
                    name.as_deref(),
                    params,
                    &body.body,
                    alias,
                    surface,
                );
            }
            unshadowed
                && (params.iter().any(|param| {
                    module_alias_binding_pattern_has_rejected_use(&param.pattern, alias, surface)
                }) || body.body.iter().any(|statement| {
                    module_alias_statement_has_rejected_use(statement, alias, surface)
                }))
        }
        Expression::Call {
            callee, arguments, ..
        }
        | Expression::OptionalCall {
            callee, arguments, ..
        }
        | Expression::New { callee, arguments } => {
            module_alias_expr_has_rejected_use(callee, alias, surface)
                || arguments
                    .iter()
                    .any(|argument| module_alias_expr_has_rejected_use(argument, alias, surface))
        }
        Expression::Member {
            object,
            property,
            computed,
            ..
        }
        | Expression::OptionalMember {
            object,
            property,
            computed,
            ..
        } => {
            module_alias_expr_has_rejected_use(object, alias, surface)
                || (*computed && module_alias_expr_has_rejected_use(property, alias, surface))
        }
        Expression::Binary { left, right, .. } => {
            module_alias_expr_has_rejected_use(left, alias, surface)
                || module_alias_expr_has_rejected_use(right, alias, surface)
        }
        Expression::Assignment { left, right, .. } => {
            module_alias_write_target_has_rejected_use(left, alias, surface)
                || module_alias_expr_has_rejected_use(right, alias, surface)
        }
        Expression::Unary {
            operator: UnaryOperator::Delete | UnaryOperator::StrictDelete,
            argument,
        } => module_alias_write_target_has_rejected_use(argument, alias, surface),
        Expression::Unary { argument, .. }
        | Expression::Await(argument)
        | Expression::SpreadElement(argument) => {
            module_alias_expr_has_rejected_use(argument, alias, surface)
        }
        Expression::Conditional {
            test,
            consequent,
            alternate,
        } => {
            module_alias_expr_has_rejected_use(test, alias, surface)
                || module_alias_expr_has_rejected_use(consequent, alias, surface)
                || module_alias_expr_has_rejected_use(alternate, alias, surface)
        }
        Expression::Yield {
            argument: Some(argument),
            ..
        } => module_alias_expr_has_rejected_use(argument, alias, surface),
        Expression::ArrayLiteral(elements) => elements
            .iter()
            .flatten()
            .any(|element| module_alias_expr_has_rejected_use(element, alias, surface)),
        Expression::ObjectLiteral(properties) => properties.iter().any(|property| {
            (property.computed && module_alias_expr_has_rejected_use(&property.key, alias, surface))
                || module_alias_expr_has_rejected_use(&property.value, alias, surface)
        }),
        Expression::TemplateLiteral { expressions, .. } => expressions
            .iter()
            .any(|expression| module_alias_expr_has_rejected_use(expression, alias, surface)),
        Expression::ClassExpression {
            name,
            super_class,
            body,
            ..
        } => {
            if surface.is_authenticated_object()
                && name.as_deref() != Some(alias)
                && body.iter().any(|method| {
                    crypto_object_params_have_outer_alias_use(None, &method.params, alias, surface)
                        || crypto_object_body_has_outer_alias_use(
                            None,
                            &method.params,
                            &method.body.body,
                            alias,
                            surface,
                        )
                })
            {
                return true;
            }
            super_class.as_deref().is_some_and(|super_class| {
                !is_event_emitter_heritage(super_class, alias, surface)
                    && module_alias_expr_has_rejected_use(super_class, alias, surface)
            }) || (name.as_deref() != Some(alias)
                && body.iter().any(|method| {
                    (method.computed
                        && module_alias_expr_has_rejected_use(&method.key, alias, surface))
                        || (!net_function_scope_shadows_alias(
                            None,
                            &method.params,
                            &method.body.body,
                            alias,
                        ) && (method.params.iter().any(|param| {
                            module_alias_binding_pattern_has_rejected_use(
                                &param.pattern,
                                alias,
                                surface,
                            )
                        }) || method.body.body.iter().any(|statement| {
                            module_alias_statement_has_rejected_use(statement, alias, surface)
                        })))
                }))
        }
        _ => false,
    }
}

pub(super) fn module_alias_statement_contains_unshadowed_usage(
    statement: &Statement,
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> bool {
    match statement {
        Statement::Expression(expression) => {
            module_alias_expr_contains_unshadowed_usage(&expression.expression, alias, surface)
        }
        Statement::VariableDeclaration(declaration) => {
            declaration.declarations.iter().any(|declarator| {
                !net_pattern_binds_alias(&declarator.pattern, alias)
                    && (module_alias_binding_pattern_contains_unshadowed_usage(
                        &declarator.pattern,
                        alias,
                        surface,
                    ) || declarator.initializer.as_ref().is_some_and(|initializer| {
                        module_alias_expr_contains_unshadowed_usage(initializer, alias, surface)
                    }))
            })
        }
        Statement::Block(block) => {
            if direct_lexical_binding_names(&block.body).contains(alias) {
                return false;
            }
            block.body.iter().any(|inner| {
                module_alias_statement_contains_unshadowed_usage(inner, alias, surface)
            })
        }
        Statement::FunctionDeclaration(function) => {
            !net_function_scope_shadows_alias(
                function.name.as_deref(),
                &function.params,
                &function.body.body,
                alias,
            ) && (function.params.iter().any(|param| {
                module_alias_binding_pattern_contains_unshadowed_usage(
                    &param.pattern,
                    alias,
                    surface,
                )
            }) || function.body.body.iter().any(|inner| {
                module_alias_statement_contains_unshadowed_usage(inner, alias, surface)
            }))
        }
        Statement::ClassDeclaration(class) => {
            class.super_class.as_deref().is_some_and(|super_class| {
                is_event_emitter_heritage(super_class, alias, surface)
                    || module_alias_expr_contains_unshadowed_usage(super_class, alias, surface)
            }) || (class.name.as_deref() != Some(alias)
                && class.body.iter().any(|method| {
                    (method.computed
                        && module_alias_expr_contains_unshadowed_usage(&method.key, alias, surface))
                        || (!net_function_scope_shadows_alias(
                            None,
                            &method.params,
                            &method.body.body,
                            alias,
                        ) && (method.params.iter().any(|param| {
                            module_alias_binding_pattern_contains_unshadowed_usage(
                                &param.pattern,
                                alias,
                                surface,
                            )
                        }) || method.body.body.iter().any(|inner| {
                            module_alias_statement_contains_unshadowed_usage(inner, alias, surface)
                        })))
                }))
        }
        Statement::If(if_statement) => {
            module_alias_expr_contains_unshadowed_usage(&if_statement.condition, alias, surface)
                || module_alias_statement_contains_unshadowed_usage(
                    &if_statement.consequent,
                    alias,
                    surface,
                )
                || if_statement.alternate.as_deref().is_some_and(|alternate| {
                    module_alias_statement_contains_unshadowed_usage(alternate, alias, surface)
                })
        }
        Statement::For(for_statement) => {
            let init_shadows = for_statement.init.as_deref().is_some_and(|initializer| {
                direct_lexical_binding_names(std::slice::from_ref(initializer)).contains(alias)
                    || net_statement_hoists_var_alias(initializer, alias)
            });
            if init_shadows {
                return false;
            }
            for_statement.init.as_deref().is_some_and(|initializer| {
                module_alias_statement_contains_unshadowed_usage(initializer, alias, surface)
            }) || for_statement.condition.as_ref().is_some_and(|condition| {
                module_alias_expr_contains_unshadowed_usage(condition, alias, surface)
            }) || for_statement.update.as_ref().is_some_and(|update| {
                module_alias_expr_contains_unshadowed_usage(update, alias, surface)
            }) || module_alias_statement_contains_unshadowed_usage(
                &for_statement.body,
                alias,
                surface,
            )
        }
        Statement::ForIn(for_statement) => {
            if net_pattern_binds_alias(&for_statement.binding, alias) {
                return for_statement.binding_kind.is_none();
            }
            module_alias_binding_pattern_contains_unshadowed_usage(
                &for_statement.binding,
                alias,
                surface,
            ) || module_alias_expr_contains_unshadowed_usage(&for_statement.object, alias, surface)
                || module_alias_statement_contains_unshadowed_usage(
                    &for_statement.body,
                    alias,
                    surface,
                )
        }
        Statement::ForOf(for_statement) => {
            if net_pattern_binds_alias(&for_statement.binding, alias) {
                return for_statement.binding_kind.is_none();
            }
            module_alias_binding_pattern_contains_unshadowed_usage(
                &for_statement.binding,
                alias,
                surface,
            ) || module_alias_expr_contains_unshadowed_usage(
                &for_statement.iterable,
                alias,
                surface,
            ) || module_alias_statement_contains_unshadowed_usage(
                &for_statement.body,
                alias,
                surface,
            )
        }
        Statement::While(while_statement) => {
            module_alias_expr_contains_unshadowed_usage(&while_statement.condition, alias, surface)
                || module_alias_statement_contains_unshadowed_usage(
                    &while_statement.body,
                    alias,
                    surface,
                )
        }
        Statement::DoWhile(do_while_statement) => {
            module_alias_expr_contains_unshadowed_usage(
                &do_while_statement.condition,
                alias,
                surface,
            ) || module_alias_statement_contains_unshadowed_usage(
                &do_while_statement.body,
                alias,
                surface,
            )
        }
        Statement::Return(return_statement) => {
            return_statement.argument.as_ref().is_some_and(|argument| {
                module_alias_expr_contains_unshadowed_usage(argument, alias, surface)
            })
        }
        Statement::Throw(throw_statement) => {
            module_alias_expr_contains_unshadowed_usage(&throw_statement.argument, alias, surface)
        }
        Statement::TryCatch(try_statement) => {
            let try_uses = module_alias_statement_contains_unshadowed_usage(
                &Statement::Block(try_statement.block.clone()),
                alias,
                surface,
            );
            let catch_uses = try_statement.handler.as_ref().is_some_and(|handler| {
                handler.parameter.as_deref() != Some(alias)
                    && module_alias_statement_contains_unshadowed_usage(
                        &Statement::Block(handler.body.clone()),
                        alias,
                        surface,
                    )
            });
            let finally_uses = try_statement.finalizer.as_ref().is_some_and(|finalizer| {
                module_alias_statement_contains_unshadowed_usage(
                    &Statement::Block(finalizer.clone()),
                    alias,
                    surface,
                )
            });
            try_uses || catch_uses || finally_uses
        }
        Statement::Switch(switch_statement) => {
            let discriminant_uses = module_alias_expr_contains_unshadowed_usage(
                &switch_statement.discriminant,
                alias,
                surface,
            );
            let switch_shadows = switch_statement
                .cases
                .iter()
                .any(|case| direct_lexical_binding_names(&case.consequent).contains(alias));
            discriminant_uses
                || (!switch_shadows
                    && switch_statement.cases.iter().any(|case| {
                        case.test.as_ref().is_some_and(|test| {
                            module_alias_expr_contains_unshadowed_usage(test, alias, surface)
                        }) || case.consequent.iter().any(|inner| {
                            module_alias_statement_contains_unshadowed_usage(inner, alias, surface)
                        })
                    }))
        }
        Statement::Labeled(labeled) => {
            module_alias_statement_contains_unshadowed_usage(&labeled.body, alias, surface)
        }
        Statement::Export(export) => match &export.kind {
            ExportKind::Default(expression) => {
                module_alias_expr_contains_unshadowed_usage(expression, alias, surface)
            }
            ExportKind::NamedClause(clause) => {
                clause.source().is_none()
                    && parse_named_export_clause_bindings(clause.canonical_head())
                        .iter()
                        .any(|(local_name, _)| local_name == alias)
            }
        },
        // `with` is rejected by lowering; imports and control-only statements
        // carry no module-alias use.
        _ => false,
    }
}

pub(super) fn module_alias_block_has_rejected_use(
    body: &[Statement],
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> bool {
    if direct_lexical_binding_names(body).contains(alias) {
        false
    } else {
        body.iter()
            .any(|statement| module_alias_statement_has_rejected_use(statement, alias, surface))
    }
}

pub(super) fn module_alias_statement_has_rejected_use(
    statement: &Statement,
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> bool {
    match statement {
        Statement::Expression(expression)
            if surface == LoweringOnlyModuleAliasSurface::Cluster
                && is_discarded_cluster_listener_registration(&expression.expression, alias) =>
        {
            let Expression::Call { arguments, .. } = &expression.expression else {
                unreachable!("discarded cluster listener registration is a call")
            };
            arguments
                .iter()
                .any(|argument| module_alias_expr_has_rejected_use(argument, alias, surface))
        }
        Statement::Expression(expression)
            if is_discarded_crypto_identity_call(&expression.expression, alias, surface) =>
        {
            let Expression::Call { arguments, .. } = &expression.expression else {
                unreachable!("discarded crypto identity use is a call")
            };
            arguments
                .iter()
                .any(|argument| module_alias_expr_has_rejected_use(argument, alias, surface))
        }
        Statement::Expression(expression) => {
            module_alias_expr_has_rejected_use(&expression.expression, alias, surface)
        }
        Statement::VariableDeclaration(declaration) => {
            declaration.declarations.iter().any(|declarator| {
                !net_pattern_binds_alias(&declarator.pattern, alias)
                    && (module_alias_binding_pattern_has_rejected_use(
                        &declarator.pattern,
                        alias,
                        surface,
                    ) || declarator.initializer.as_ref().is_some_and(|initializer| {
                        module_alias_expr_has_rejected_use(initializer, alias, surface)
                    }))
            })
        }
        Statement::Block(block) => module_alias_block_has_rejected_use(&block.body, alias, surface),
        Statement::FunctionDeclaration(function) => {
            let unshadowed = !net_function_scope_shadows_alias(
                function.name.as_deref(),
                &function.params,
                &function.body.body,
                alias,
            );
            if surface.is_authenticated_object() {
                return crypto_object_params_have_outer_alias_use(
                    function.name.as_deref(),
                    &function.params,
                    alias,
                    surface,
                ) || crypto_object_body_has_outer_alias_use(
                    function.name.as_deref(),
                    &function.params,
                    &function.body.body,
                    alias,
                    surface,
                );
            }
            unshadowed
                && (function.params.iter().any(|param| {
                    module_alias_binding_pattern_has_rejected_use(&param.pattern, alias, surface)
                }) || function
                    .body
                    .body
                    .iter()
                    .any(|inner| module_alias_statement_has_rejected_use(inner, alias, surface)))
        }
        Statement::ClassDeclaration(class) => {
            if surface.is_authenticated_object()
                && class.name.as_deref() != Some(alias)
                && class.body.iter().any(|method| {
                    crypto_object_params_have_outer_alias_use(None, &method.params, alias, surface)
                        || crypto_object_body_has_outer_alias_use(
                            None,
                            &method.params,
                            &method.body.body,
                            alias,
                            surface,
                        )
                })
            {
                return true;
            }
            class.super_class.as_deref().is_some_and(|super_class| {
                !is_event_emitter_heritage(super_class, alias, surface)
                    && module_alias_expr_has_rejected_use(super_class, alias, surface)
            }) || (class.name.as_deref() != Some(alias)
                && class.body.iter().any(|method| {
                    (method.computed
                        && module_alias_expr_has_rejected_use(&method.key, alias, surface))
                        || (!net_function_scope_shadows_alias(
                            None,
                            &method.params,
                            &method.body.body,
                            alias,
                        ) && (method.params.iter().any(|param| {
                            module_alias_binding_pattern_has_rejected_use(
                                &param.pattern,
                                alias,
                                surface,
                            )
                        }) || method.body.body.iter().any(|inner| {
                            module_alias_statement_has_rejected_use(inner, alias, surface)
                        })))
                }))
        }
        Statement::If(if_statement) => {
            module_alias_expr_has_rejected_use(&if_statement.condition, alias, surface)
                || module_alias_statement_has_rejected_use(&if_statement.consequent, alias, surface)
                || if_statement.alternate.as_deref().is_some_and(|alternate| {
                    module_alias_statement_has_rejected_use(alternate, alias, surface)
                })
        }
        Statement::For(for_statement) => {
            let init_shadows = for_statement.init.as_deref().is_some_and(|initializer| {
                direct_lexical_binding_names(std::slice::from_ref(initializer)).contains(alias)
                    || net_statement_hoists_var_alias(initializer, alias)
            });
            if init_shadows {
                return false;
            }
            for_statement.init.as_deref().is_some_and(|initializer| {
                module_alias_statement_has_rejected_use(initializer, alias, surface)
            }) || for_statement.condition.as_ref().is_some_and(|condition| {
                module_alias_expr_has_rejected_use(condition, alias, surface)
            }) || for_statement
                .update
                .as_ref()
                .is_some_and(|update| module_alias_expr_has_rejected_use(update, alias, surface))
                || module_alias_statement_has_rejected_use(&for_statement.body, alias, surface)
        }
        Statement::ForIn(for_statement) => {
            if net_pattern_binds_alias(&for_statement.binding, alias) {
                return for_statement.binding_kind.is_none();
            }
            module_alias_binding_pattern_has_rejected_use(&for_statement.binding, alias, surface)
                || module_alias_expr_has_rejected_use(&for_statement.object, alias, surface)
                || module_alias_statement_has_rejected_use(&for_statement.body, alias, surface)
        }
        Statement::ForOf(for_statement) => {
            if net_pattern_binds_alias(&for_statement.binding, alias) {
                return for_statement.binding_kind.is_none();
            }
            module_alias_binding_pattern_has_rejected_use(&for_statement.binding, alias, surface)
                || module_alias_expr_has_rejected_use(&for_statement.iterable, alias, surface)
                || module_alias_statement_has_rejected_use(&for_statement.body, alias, surface)
        }
        Statement::While(while_statement) => {
            module_alias_expr_has_rejected_use(&while_statement.condition, alias, surface)
                || module_alias_statement_has_rejected_use(&while_statement.body, alias, surface)
        }
        Statement::DoWhile(do_while_statement) => {
            module_alias_expr_has_rejected_use(&do_while_statement.condition, alias, surface)
                || module_alias_statement_has_rejected_use(&do_while_statement.body, alias, surface)
        }
        Statement::Return(return_statement) => return_statement
            .argument
            .as_ref()
            .is_some_and(|argument| module_alias_expr_has_rejected_use(argument, alias, surface)),
        Statement::Throw(throw_statement) => {
            module_alias_expr_has_rejected_use(&throw_statement.argument, alias, surface)
        }
        Statement::TryCatch(try_statement) => {
            module_alias_block_has_rejected_use(&try_statement.block.body, alias, surface)
                || try_statement.handler.as_ref().is_some_and(|handler| {
                    handler.parameter.as_deref() != Some(alias)
                        && module_alias_block_has_rejected_use(&handler.body.body, alias, surface)
                })
                || try_statement.finalizer.as_ref().is_some_and(|finalizer| {
                    module_alias_block_has_rejected_use(&finalizer.body, alias, surface)
                })
        }
        Statement::Switch(switch_statement) => {
            if module_alias_expr_has_rejected_use(&switch_statement.discriminant, alias, surface) {
                return true;
            }
            let switch_shadows = switch_statement
                .cases
                .iter()
                .any(|case| direct_lexical_binding_names(&case.consequent).contains(alias));
            !switch_shadows
                && switch_statement.cases.iter().any(|case| {
                    case.test.as_ref().is_some_and(|test| {
                        module_alias_expr_has_rejected_use(test, alias, surface)
                    }) || case
                        .consequent
                        .iter()
                        .any(|inner| module_alias_statement_has_rejected_use(inner, alias, surface))
                })
        }
        Statement::Labeled(labeled) => {
            module_alias_statement_has_rejected_use(&labeled.body, alias, surface)
        }
        Statement::Export(export) => match &export.kind {
            ExportKind::Default(expression) => {
                module_alias_expr_has_rejected_use(expression, alias, surface)
            }
            ExportKind::NamedClause(clause) => {
                clause.source().is_none()
                    && parse_named_export_clause_bindings(clause.canonical_head())
                        .iter()
                        .any(|(local_name, _)| local_name == alias)
            }
        },
        _ => false,
    }
}

/// A lowering-only module alias must not gain provenance before its lexical
/// initializer executes. The sentinels are seeded for the whole unit before
/// statement lowering, so reject candidates whose pre-declaration prefix can
/// observe the alias directly or execute arbitrary call/new code that could
/// reach a hoisted closure capturing the alias. This is intentionally
/// conservative: ambient denial is safer than manufacturing a value through
/// the JavaScript temporal dead zone.
pub(super) fn module_alias_expression_is_predeclaration_call_hazard(
    expression: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    // A builtin module's require runs no guest code, so it cannot reach a
    // hoisted closure that observes a later alias: `const path =
    // require('path'); const cp = require('child_process');` keeps `cp`.
    matches!(
        expression,
        Expression::OptionalCall { .. } | Expression::New { .. }
    ) || matches!(expression, Expression::Call { .. })
        && !is_require_fs_module_initializer(expression, binding_lookup)
        && !is_require_fs_promises_module_initializer(expression, binding_lookup)
        && !is_require_path_module_initializer(expression, binding_lookup)
        && !is_require_querystring_module_initializer(expression, binding_lookup)
        && !is_require_os_module_initializer(expression, binding_lookup)
        && !is_require_timers_module_initializer(expression, binding_lookup)
        && !is_require_timers_promises_module_initializer(expression, binding_lookup)
        && !is_require_net_module_initializer(expression, binding_lookup)
        && !is_require_http_module_initializer(expression, binding_lookup)
        && !is_require_https_module_initializer(expression, binding_lookup)
        && !is_require_tls_module_initializer(expression, binding_lookup)
        && !is_require_zlib_module_initializer(expression, binding_lookup)
        && !is_require_crypto_module_initializer(expression, binding_lookup)
        && !is_require_cluster_module_initializer(expression, binding_lookup)
        && !is_require_child_process_module_initializer(expression, binding_lookup)
        && !is_require_url_module_initializer(expression, binding_lookup)
        && !is_require_events_module_initializer(expression, binding_lookup)
        && !matches!(
            expression,
            Expression::Call {
                callee,
                arguments,
                ..
            } if arguments.is_empty()
                && matches!(
                    callee.as_ref(),
                    Expression::Identifier(name) if util_module::is_module_binding(name)
                )
        )
}

pub(super) fn module_alias_expression_has_predeclaration_call_hazard(
    expression: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    timers_scan_expr_deep(expression, &|nested| {
        module_alias_expression_is_predeclaration_call_hazard(nested, binding_lookup)
    })
}

pub(super) fn module_alias_binding_pattern_has_predeclaration_call_hazard(
    pattern: &BindingPattern,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    match pattern {
        BindingPattern::Identifier(_) => false,
        BindingPattern::ObjectPattern(properties) => properties.iter().any(|property| {
            (property.computed
                && module_alias_expression_has_predeclaration_call_hazard(
                    &property.key,
                    binding_lookup,
                ))
                || module_alias_binding_pattern_has_predeclaration_call_hazard(
                    &property.value,
                    binding_lookup,
                )
        }),
        BindingPattern::ArrayPattern(elements) => elements.iter().flatten().any(|element| {
            module_alias_binding_pattern_has_predeclaration_call_hazard(element, binding_lookup)
        }),
        BindingPattern::Rest(inner) => {
            module_alias_binding_pattern_has_predeclaration_call_hazard(inner, binding_lookup)
        }
        BindingPattern::AssignmentPattern { left, right } => {
            module_alias_binding_pattern_has_predeclaration_call_hazard(left, binding_lookup)
                || module_alias_expression_has_predeclaration_call_hazard(right, binding_lookup)
        }
    }
}

pub(super) fn module_alias_has_predeclaration_hazard(
    body: &[Statement],
    statement_index: usize,
    declarator_index: usize,
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    // Crypto lifecycle objects have a stricter, whole-body provenance scan:
    // every unshadowed function/arrow/class capture of the object alias is a
    // rejected use. An unrelated call before the lexical initializer therefore
    // cannot reach a hoisted closure that observes the alias. Applying the
    // generic call/new hazard here would reject ordinary setup expressions such
    // as `const bytes = Buffer.from(...); const hash = crypto.createHash(...)`.
    // Direct prefix uses and all rejected/escaped uses remain fail-closed below.
    let arbitrary_call_can_observe_hoisted_alias = !surface.is_authenticated_object();
    // The util and path modules (`util_module.rs`, `path_module.rs`) are
    // engine-owned code that names no program binding, so building them
    // cannot observe the alias.
    let statement_prefix_has_hazard = body[..statement_index].iter().any(|statement| {
        !util_module::is_module_declaration(statement)
            && !path_module::is_module_declaration(statement)
            && (module_alias_statement_contains_unshadowed_usage(statement, alias, surface)
                || module_alias_statement_has_rejected_use(statement, alias, surface)
                || (arbitrary_call_can_observe_hoisted_alias
                    && timers_scan_statement_deep(statement, &|expression| {
                        module_alias_expression_is_predeclaration_call_hazard(
                            expression,
                            binding_lookup,
                        )
                    })))
    });
    let declarator_prefix_has_hazard = match &body[statement_index] {
        Statement::VariableDeclaration(declaration) => declaration.declarations[..declarator_index]
            .iter()
            .any(|declarator| {
                net_pattern_binds_alias(&declarator.pattern, alias)
                    || module_alias_binding_pattern_contains_unshadowed_usage(
                        &declarator.pattern,
                        alias,
                        surface,
                    )
                    || module_alias_binding_pattern_has_rejected_use(
                        &declarator.pattern,
                        alias,
                        surface,
                    )
                    || (arbitrary_call_can_observe_hoisted_alias
                        && module_alias_binding_pattern_has_predeclaration_call_hazard(
                            &declarator.pattern,
                            binding_lookup,
                        ))
                    || declarator.initializer.as_ref().is_some_and(|initializer| {
                        module_alias_expr_contains_unshadowed_usage(initializer, alias, surface)
                            || module_alias_expr_has_rejected_use(initializer, alias, surface)
                            || (arbitrary_call_can_observe_hoisted_alias
                                && module_alias_expression_has_predeclaration_call_hazard(
                                    initializer,
                                    binding_lookup,
                                ))
                    })
            }),
        _ => true,
    };
    statement_prefix_has_hazard || declarator_prefix_has_hazard
}

pub(super) fn confirmed_net_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeMap::new();
    for (statement_index, statement) in body.iter().enumerate() {
        if let Statement::VariableDeclaration(declaration) = statement {
            if declaration.kind != VariableDeclarationKind::Const {
                continue;
            }
            for (declarator_index, declarator) in declaration.declarations.iter().enumerate() {
                if let (BindingPattern::Identifier(alias), Some(initializer)) =
                    (&declarator.pattern, &declarator.initializer)
                    && is_require_net_module_initializer(initializer, binding_lookup)
                {
                    candidates.insert(alias.clone(), (statement_index, declarator_index));
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|(alias, (statement_index, declarator_index))| {
            !module_alias_has_predeclaration_hazard(
                body,
                *statement_index,
                *declarator_index,
                alias,
                LoweringOnlyModuleAliasSurface::Net,
                binding_lookup,
            ) && body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(
                    statement,
                    alias,
                    LoweringOnlyModuleAliasSurface::Net,
                )
            }) && !body.iter().any(|statement| {
                module_alias_statement_has_rejected_use(
                    statement,
                    alias,
                    LoweringOnlyModuleAliasSurface::Net,
                )
            })
        })
        .map(|(alias, _)| alias)
        .collect()
}

// ---------------------------------------------------------------------------
// Node `tls` builtin recognition (bd-70cv1)
//
// This is a lowering-only semantic layer over the hermetic net loopback
// kernel. It never routes through extension-host rustls/OS networking.

pub(super) fn is_tls_module_specifier(specifier: &str) -> bool {
    specifier == "tls" || specifier == "node:tls"
}

pub(super) fn tls_module_alias_sentinel(name: &str) -> String {
    format!("\0tlsmod\0{name}")
}

pub(super) fn seed_tls_module_alias_sentinels(
    body_lookup: &mut BTreeMap<String, BindingId>,
    outer_lookup: &BTreeMap<String, BindingId>,
) {
    seed_prefixed_sentinels(body_lookup, outer_lookup, &["\0tlsmod\0"]);
}

pub(super) fn is_require_tls_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
        && matches!(arguments.as_slice(), [specifier]
            if well_formed_string_literal(specifier).is_some_and(is_tls_module_specifier))
}

pub(super) fn tls_method_capability(method: &str) -> Option<&'static str> {
    match method {
        "getCiphers" => Some("builtin:TlsGetCiphers"),
        "createSecureContext" => Some("builtin:TlsCreateSecureContext"),
        "checkServerIdentity" => Some("builtin:TlsCheckServerIdentity"),
        "createServer" => Some("builtin:TlsCreateServer"),
        "connect" => Some("builtin:TlsConnect"),
        _ => None,
    }
}

pub(super) enum TlsMemberReadLowering {
    RootCertificates,
    StringConstant(&'static str),
}

pub(super) fn tls_property_read_lowering(property: &str) -> Option<TlsMemberReadLowering> {
    match property {
        "rootCertificates" => Some(TlsMemberReadLowering::RootCertificates),
        "DEFAULT_MIN_VERSION" => Some(TlsMemberReadLowering::StringConstant("TLSv1.2")),
        _ => None,
    }
}

pub(super) fn is_tls_module_object(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    match expr {
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&tls_module_alias_sentinel(alias))
        }
        Expression::Call { .. } => is_require_tls_module_initializer(expr, binding_lookup),
        _ => false,
    }
}

pub(super) fn tls_member_name<'a>(
    expression: &'a Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'a str> {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = expression
    else {
        return None;
    };
    if !is_tls_module_object(object, binding_lookup) {
        return None;
    }
    well_formed_static_name(property)
}

pub(super) fn tls_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    tls_member_name(callee, binding_lookup).and_then(tls_method_capability)
}

pub(super) fn tls_member_read_lowering(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<TlsMemberReadLowering> {
    if !is_tls_module_object(object, binding_lookup) {
        return None;
    }
    if computed {
        return None;
    }
    let property = well_formed_static_name(property)?;
    tls_property_read_lowering(property)
}

pub(super) fn confirmed_tls_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeMap::new();
    for (statement_index, statement) in body.iter().enumerate() {
        if let Statement::VariableDeclaration(declaration) = statement {
            if declaration.kind != VariableDeclarationKind::Const {
                continue;
            }
            for (declarator_index, declarator) in declaration.declarations.iter().enumerate() {
                if let (BindingPattern::Identifier(alias), Some(initializer)) =
                    (&declarator.pattern, &declarator.initializer)
                    && is_require_tls_module_initializer(initializer, binding_lookup)
                {
                    candidates.insert(alias.clone(), (statement_index, declarator_index));
                }
            }
        }
    }
    candidates
        .into_iter()
        .filter(|(alias, (statement_index, declarator_index))| {
            !module_alias_has_predeclaration_hazard(
                body,
                *statement_index,
                *declarator_index,
                alias,
                LoweringOnlyModuleAliasSurface::Tls,
                binding_lookup,
            ) && body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(
                    statement,
                    alias,
                    LoweringOnlyModuleAliasSurface::Tls,
                )
            }) && !body.iter().any(|statement| {
                module_alias_statement_has_rejected_use(
                    statement,
                    alias,
                    LoweringOnlyModuleAliasSurface::Tls,
                )
            })
        })
        .map(|(alias, _)| alias)
        .collect()
}

/// bd-suwvw: compute the identifier names BOTH bound via `const/let/var
/// <name> = require('timers')` at the unit root AND used as a recognized
/// timers export (member call OR member read) somewhere reachable by the
/// deep statement scan (control flow + function/arrow bodies). Mirror of
/// [`confirmed_querystring_module_aliases`] apart from the deep recursion —
/// see [`timers_scan_expr_deep`].
pub(super) fn confirmed_timers_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            for d in &vd.declarations {
                if let (BindingPattern::Identifier(name), Some(init)) = (&d.pattern, &d.initializer)
                    && is_require_timers_module_initializer(init, binding_lookup)
                {
                    candidates.insert(name.clone());
                }
            }
        }
    }
    if candidates.is_empty() {
        return candidates;
    }

    let mut used = BTreeSet::new();
    for name in &candidates {
        let single: BTreeSet<String> = std::iter::once(name.clone()).collect();
        if body.iter().any(|stmt| {
            timers_scan_statement_deep(stmt, &|member| is_timers_alias_member(member, &single))
        }) {
            used.insert(name.clone());
        }
    }
    used
}

/// bd-suwvw: like [`confirmed_timers_module_aliases`] for
/// `require('timers/promises')` (member CALLS count as usage).
pub(super) fn confirmed_timers_promises_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            for d in &vd.declarations {
                if let (BindingPattern::Identifier(name), Some(init)) = (&d.pattern, &d.initializer)
                    && is_require_timers_promises_module_initializer(init, binding_lookup)
                {
                    candidates.insert(name.clone());
                }
            }
        }
    }
    if candidates.is_empty() {
        return candidates;
    }

    let mut used = BTreeSet::new();
    for name in &candidates {
        let single: BTreeSet<String> = std::iter::once(name.clone()).collect();
        if body.iter().any(|stmt| {
            timers_scan_statement_deep(stmt, &|e| {
                matches!(e, Expression::Call { callee, .. } | Expression::OptionalCall { callee, .. }
                    if is_timers_promises_alias_method_callee(callee, &single))
            })
        }) {
            used.insert(name.clone());
        }
    }
    used
}

// ---------------------------------------------------------------------------
// Node `stream` builtin recognition (bd-fw7zd)
//
// The stream kernel is exposed only through statically proven exports. This
// supported slices recognize `Readable.from(...)`, `new Readable(...)`,
// `new Writable(...)`, and `new PassThrough(...)` through either a const CJS
// destructure or an ESM named import. They do not materialize the stream
// module or constructor values;
// namespace imports, computed properties, and dynamic module names remain
// unsupported.

pub(super) fn is_stream_module_specifier(specifier: &str) -> bool {
    specifier == "stream" || specifier == "node:stream"
}

pub(super) fn is_stream_promises_module_specifier(specifier: &str) -> bool {
    specifier == "stream/promises" || specifier == "node:stream/promises"
}

pub(super) fn stream_readable_binding_sentinel(name: &str) -> String {
    format!("\0stream-readable\0{name}")
}

pub(super) fn stream_writable_binding_sentinel(name: &str) -> String {
    format!("\0stream-writable\0{name}")
}

pub(super) fn stream_passthrough_binding_sentinel(name: &str) -> String {
    format!("\0stream-passthrough\0{name}")
}

pub(super) fn stream_transform_binding_sentinel(name: &str) -> String {
    format!("\0stream-transform\0{name}")
}

pub(super) fn stream_pipeline_binding_sentinel(name: &str) -> String {
    format!("\0stream-pipeline\0{name}")
}

pub(super) fn stream_promises_binding_sentinel(name: &str) -> String {
    format!("\0stream-promises\0{name}")
}

pub(super) fn stream_promises_pipeline_binding_sentinel(name: &str) -> String {
    format!("\0stream-promises-pipeline\0{name}")
}

pub(super) fn pending_stream_readable_binding_sentinel(name: &str) -> String {
    format!("\0stream-readable-pending\0{name}")
}

pub(super) fn pending_stream_writable_binding_sentinel(name: &str) -> String {
    format!("\0stream-writable-pending\0{name}")
}

pub(super) fn pending_stream_passthrough_binding_sentinel(name: &str) -> String {
    format!("\0stream-passthrough-pending\0{name}")
}

pub(super) fn pending_stream_transform_binding_sentinel(name: &str) -> String {
    format!("\0stream-transform-pending\0{name}")
}

pub(super) fn pending_stream_pipeline_binding_sentinel(name: &str) -> String {
    format!("\0stream-pipeline-pending\0{name}")
}

pub(super) fn pending_stream_promises_binding_sentinel(name: &str) -> String {
    format!("\0stream-promises-pending\0{name}")
}

pub(super) fn suppress_stream_module_sentinel(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    name: &str,
) {
    binding_lookup.remove(&stream_readable_binding_sentinel(name));
    binding_lookup.remove(&stream_writable_binding_sentinel(name));
    binding_lookup.remove(&stream_passthrough_binding_sentinel(name));
    binding_lookup.remove(&stream_transform_binding_sentinel(name));
    binding_lookup.remove(&stream_pipeline_binding_sentinel(name));
    binding_lookup.remove(&stream_promises_binding_sentinel(name));
    binding_lookup.remove(&stream_promises_pipeline_binding_sentinel(name));
    binding_lookup.remove(&pending_stream_readable_binding_sentinel(name));
    binding_lookup.remove(&pending_stream_writable_binding_sentinel(name));
    binding_lookup.remove(&pending_stream_passthrough_binding_sentinel(name));
    binding_lookup.remove(&pending_stream_transform_binding_sentinel(name));
    binding_lookup.remove(&pending_stream_pipeline_binding_sentinel(name));
    binding_lookup.remove(&pending_stream_promises_binding_sentinel(name));
}

pub(super) fn suppress_stream_module_sentinels(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    names: &BTreeSet<String>,
) {
    for name in names {
        suppress_stream_module_sentinel(binding_lookup, name);
    }
}

pub(super) fn is_require_stream_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    if require_is_commonjs_wrapper(binding_lookup) {
        return false;
    }
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    if !matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
    {
        return false;
    }
    matches!(arguments.as_slice(), [specifier]
        if well_formed_string_literal(specifier).is_some_and(is_stream_module_specifier))
}

pub(super) fn is_stream_readable_from_direct_call(expr: &Expression, local: &str) -> bool {
    matches!(expr,
        Expression::Call { callee, .. }
            if matches!(callee.as_ref(), Expression::Member {
                object,
                property,
                computed: false,
                ..
            } if matches!(object.as_ref(), Expression::Identifier(name) if name == local)
                && well_formed_static_name(property).is_some_and(|name| name == "from")))
}

pub(super) fn is_stream_constructor_use(expr: &Expression, local: &str) -> bool {
    matches!(expr,
        Expression::New { callee, .. }
            if matches!(callee.as_ref(), Expression::Identifier(name) if name == local))
}

pub(super) fn is_stream_pipeline_direct_call(expr: &Expression, local: &str) -> bool {
    matches!(expr,
        Expression::Call { callee, .. }
            if matches!(callee.as_ref(), Expression::Identifier(name) if name == local))
}

pub(super) fn is_stream_promises_pipeline_call(expr: &Expression, local: &str) -> bool {
    matches!(expr,
        Expression::Call { callee, .. }
            if matches!(callee.as_ref(), Expression::Member {
                object,
                property,
                computed: false,
                ..
            } if matches!(object.as_ref(), Expression::Identifier(name) if name == local)
                && well_formed_static_name(property).is_some_and(|name| name == "pipeline")))
}

pub(super) fn is_stream_readable_usage(expr: &Expression, local: &str) -> bool {
    is_stream_readable_from_direct_call(expr, local) || is_stream_constructor_use(expr, local)
}

/// A lowering-only constructor binding is safe to elide only when it has at
/// least one supported unshadowed `new` site and every other unshadowed use is
/// consumed by that finite surface. This prevents one valid site from
/// authorizing an unrelated alias/escape, while nested same-named bindings do
/// not count as either confirmation or rejection.
pub(super) fn stream_constructor_binding_is_exhaustively_supported(
    body: &[Statement],
    local: &str,
) -> bool {
    stream_binding_is_exhaustively_supported(
        body,
        local,
        LoweringOnlyModuleAliasSurface::StreamConstructor,
    )
}

pub(super) fn stream_binding_is_exhaustively_supported(
    body: &[Statement],
    local: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> bool {
    body.iter().any(|statement| {
        module_alias_statement_contains_unshadowed_usage(statement, local, surface)
    }) && !body
        .iter()
        .any(|statement| module_alias_statement_has_rejected_use(statement, local, surface))
}

pub(super) fn confirmed_stream_readable_destructured_requires(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            if vd.kind != VariableDeclarationKind::Const {
                continue;
            }
            for declaration in &vd.declarations {
                let (Some(init), BindingPattern::ObjectPattern(properties)) =
                    (&declaration.initializer, &declaration.pattern)
                else {
                    continue;
                };
                if !is_require_stream_module_initializer(init, binding_lookup) {
                    continue;
                }
                for property in properties {
                    if property.computed
                        || !well_formed_static_name(&property.key)
                            .is_some_and(|name| name == "Readable")
                    {
                        continue;
                    }
                    if let BindingPattern::Identifier(local) = &property.value {
                        candidates.insert(local.clone());
                    }
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|local| {
            body.iter().any(|stmt| {
                timers_scan_statement_deep(stmt, &|expr| is_stream_readable_usage(expr, local))
            })
        })
        .collect()
}

pub(super) fn confirmed_stream_writable_destructured_requires(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            if vd.kind != VariableDeclarationKind::Const {
                continue;
            }
            for declaration in &vd.declarations {
                let (Some(init), BindingPattern::ObjectPattern(properties)) =
                    (&declaration.initializer, &declaration.pattern)
                else {
                    continue;
                };
                if !is_require_stream_module_initializer(init, binding_lookup) {
                    continue;
                }
                for property in properties {
                    if property.computed
                        || !well_formed_static_name(&property.key)
                            .is_some_and(|name| name == "Writable")
                    {
                        continue;
                    }
                    if let BindingPattern::Identifier(local) = &property.value {
                        candidates.insert(local.clone());
                    }
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|local| stream_constructor_binding_is_exhaustively_supported(body, local))
        .collect()
}

pub(super) fn confirmed_stream_passthrough_destructured_requires(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeMap::new();
    for (statement_index, stmt) in body.iter().enumerate() {
        if let Statement::VariableDeclaration(vd) = stmt {
            if vd.kind != VariableDeclarationKind::Const {
                continue;
            }
            for (declarator_index, declaration) in vd.declarations.iter().enumerate() {
                let (Some(init), BindingPattern::ObjectPattern(properties)) =
                    (&declaration.initializer, &declaration.pattern)
                else {
                    continue;
                };
                if !is_require_stream_module_initializer(init, binding_lookup) {
                    continue;
                }
                for property in properties {
                    if property.computed
                        || !well_formed_static_name(&property.key)
                            .is_some_and(|name| name == "PassThrough")
                    {
                        continue;
                    }
                    if let BindingPattern::Identifier(local) = &property.value {
                        candidates.insert(local.clone(), (statement_index, declarator_index));
                    }
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|(local, (statement_index, declarator_index))| {
            stream_constructor_binding_is_exhaustively_supported(body, local)
                && !module_alias_has_predeclaration_hazard(
                    body,
                    *statement_index,
                    *declarator_index,
                    local,
                    LoweringOnlyModuleAliasSurface::StreamConstructor,
                    binding_lookup,
                )
        })
        .map(|(local, _)| local)
        .collect()
}

pub(super) fn confirmed_stream_destructured_export(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
    export: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> BTreeSet<String> {
    let mut candidates = BTreeMap::new();
    for (statement_index, stmt) in body.iter().enumerate() {
        let Statement::VariableDeclaration(vd) = stmt else {
            continue;
        };
        if vd.kind != VariableDeclarationKind::Const {
            continue;
        }
        for (declarator_index, declaration) in vd.declarations.iter().enumerate() {
            let (Some(init), BindingPattern::ObjectPattern(properties)) =
                (&declaration.initializer, &declaration.pattern)
            else {
                continue;
            };
            if !is_require_stream_module_initializer(init, binding_lookup) {
                continue;
            }
            for property in properties {
                if !property.computed
                    && well_formed_static_name(&property.key).is_some_and(|name| name == export)
                    && let BindingPattern::Identifier(local) = &property.value
                {
                    candidates.insert(local.clone(), (statement_index, declarator_index));
                }
            }
        }
    }
    candidates
        .into_iter()
        .filter(|(local, (statement_index, declarator_index))| {
            stream_binding_is_exhaustively_supported(body, local, surface)
                && !module_alias_has_predeclaration_hazard(
                    body,
                    *statement_index,
                    *declarator_index,
                    local,
                    surface,
                    binding_lookup,
                )
        })
        .map(|(local, _)| local)
        .collect()
}

pub(super) fn confirmed_stream_transform_destructured_requires(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    confirmed_stream_destructured_export(
        body,
        binding_lookup,
        "Transform",
        LoweringOnlyModuleAliasSurface::StreamConstructor,
    )
}

pub(super) fn confirmed_stream_pipeline_destructured_requires(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    confirmed_stream_destructured_export(
        body,
        binding_lookup,
        "pipeline",
        LoweringOnlyModuleAliasSurface::StreamPipeline,
    )
}

pub(super) fn confirmed_stream_promises_destructured_requires(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    confirmed_stream_destructured_export(
        body,
        binding_lookup,
        "promises",
        LoweringOnlyModuleAliasSurface::StreamPromises,
    )
}

pub(super) fn confirmed_stream_readable_named_imports(body: &[Statement]) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::Import(import) = stmt
            && import.import_attributes.is_empty()
            && module_source_matches(&import.source, is_stream_module_specifier)
            && let ImportClause::Named { specifiers } = &import.clause
        {
            for specifier in specifiers {
                if specifier.import_name == "Readable" {
                    candidates.insert(specifier.local_name.clone());
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|local| {
            body.iter().any(|stmt| {
                timers_scan_statement_deep(stmt, &|expr| is_stream_readable_usage(expr, local))
            })
        })
        .collect()
}

pub(super) fn confirmed_stream_writable_named_imports(body: &[Statement]) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::Import(import) = stmt
            && import.import_attributes.is_empty()
            && module_source_matches(&import.source, is_stream_module_specifier)
            && let ImportClause::Named { specifiers } = &import.clause
        {
            for specifier in specifiers {
                if specifier.import_name == "Writable" {
                    candidates.insert(specifier.local_name.clone());
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|local| stream_constructor_binding_is_exhaustively_supported(body, local))
        .collect()
}

pub(super) fn confirmed_stream_passthrough_named_imports(body: &[Statement]) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::Import(import) = stmt
            && import.import_attributes.is_empty()
            && module_source_matches(&import.source, is_stream_module_specifier)
            && let ImportClause::Named { specifiers } = &import.clause
        {
            for specifier in specifiers {
                if specifier.import_name == "PassThrough" {
                    candidates.insert(specifier.local_name.clone());
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|local| stream_constructor_binding_is_exhaustively_supported(body, local))
        .collect()
}

pub(super) fn confirmed_stream_named_export(
    body: &[Statement],
    promises_module: bool,
    export: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::Import(import) = stmt
            && import.import_attributes.is_empty()
            && (if promises_module {
                module_source_matches(&import.source, is_stream_promises_module_specifier)
            } else {
                module_source_matches(&import.source, is_stream_module_specifier)
            })
            && let ImportClause::Named { specifiers } = &import.clause
        {
            for specifier in specifiers {
                if specifier.import_name == export {
                    candidates.insert(specifier.local_name.clone());
                }
            }
        }
    }
    candidates
        .into_iter()
        .filter(|local| stream_binding_is_exhaustively_supported(body, local, surface))
        .collect()
}

pub(super) fn confirmed_stream_transform_named_imports(body: &[Statement]) -> BTreeSet<String> {
    confirmed_stream_named_export(
        body,
        false,
        "Transform",
        LoweringOnlyModuleAliasSurface::StreamConstructor,
    )
}

pub(super) fn confirmed_stream_pipeline_named_imports(body: &[Statement]) -> BTreeSet<String> {
    confirmed_stream_named_export(
        body,
        false,
        "pipeline",
        LoweringOnlyModuleAliasSurface::StreamPipeline,
    )
}

pub(super) fn confirmed_stream_promises_pipeline_named_imports(
    body: &[Statement],
) -> BTreeSet<String> {
    confirmed_stream_named_export(
        body,
        true,
        "pipeline",
        LoweringOnlyModuleAliasSurface::StreamPipeline,
    )
}

pub(super) fn confirmed_stream_destructure_locals(
    pattern: &BindingPattern,
    init: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<Vec<String>> {
    let BindingPattern::ObjectPattern(properties) = pattern else {
        return None;
    };
    if !is_require_stream_module_initializer(init, binding_lookup) {
        return None;
    }

    let mut locals = Vec::new();
    for property in properties {
        if property.computed {
            return None;
        }
        let constructor = well_formed_static_name(&property.key)?;
        let BindingPattern::Identifier(local) = &property.value else {
            return None;
        };
        let confirmed = match constructor {
            "Readable" => {
                binding_lookup.contains_key(&pending_stream_readable_binding_sentinel(local))
            }
            "Writable" => {
                binding_lookup.contains_key(&pending_stream_writable_binding_sentinel(local))
            }
            "PassThrough" => {
                binding_lookup.contains_key(&pending_stream_passthrough_binding_sentinel(local))
            }
            "Transform" => {
                binding_lookup.contains_key(&pending_stream_transform_binding_sentinel(local))
            }
            "pipeline" => {
                binding_lookup.contains_key(&pending_stream_pipeline_binding_sentinel(local))
            }
            "promises" => {
                binding_lookup.contains_key(&pending_stream_promises_binding_sentinel(local))
            }
            _ => false,
        };
        if !confirmed {
            return None;
        }
        locals.push(local.clone());
    }
    (!locals.is_empty()).then_some(locals)
}

pub(super) fn seed_stream_module_sentinels(
    body_lookup: &mut BTreeMap<String, BindingId>,
    outer_lookup: &BTreeMap<String, BindingId>,
) {
    seed_prefixed_sentinels(
        body_lookup,
        outer_lookup,
        &[
            "\0stream-readable\0",
            "\0stream-writable\0",
            "\0stream-passthrough\0",
            "\0stream-transform\0",
            "\0stream-pipeline\0",
            "\0stream-promises\0",
            "\0stream-promises-pipeline\0",
        ],
    );
}

pub(super) fn stream_constructor_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Identifier(name) = callee else {
        return None;
    };
    if binding_lookup.contains_key(&stream_readable_binding_sentinel(name)) {
        Some("builtin:StreamReadable")
    } else if binding_lookup.contains_key(&stream_writable_binding_sentinel(name)) {
        Some("builtin:StreamWritable")
    } else if binding_lookup.contains_key(&stream_passthrough_binding_sentinel(name)) {
        Some("builtin:StreamPassThrough")
    } else if binding_lookup.contains_key(&stream_transform_binding_sentinel(name)) {
        Some("builtin:StreamTransform")
    } else {
        None
    }
}

pub(super) fn stream_pipeline_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    match callee {
        Expression::Identifier(name)
            if binding_lookup.contains_key(&stream_pipeline_binding_sentinel(name)) =>
        {
            Some("builtin:StreamPipeline")
        }
        Expression::Identifier(name)
            if binding_lookup.contains_key(&stream_promises_pipeline_binding_sentinel(name)) =>
        {
            Some("builtin:StreamPromisesPipeline")
        }
        Expression::Member {
            object,
            property,
            computed: false,
            ..
        } if matches!(object.as_ref(), Expression::Identifier(name)
            if binding_lookup.contains_key(&stream_promises_binding_sentinel(name)))
            && well_formed_static_name(property).is_some_and(|name| name == "pipeline") =>
        {
            Some("builtin:StreamPromisesPipeline")
        }
        _ => None,
    }
}

pub(super) fn stream_readable_from_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return None;
    };
    matches!(object.as_ref(), Expression::Identifier(name)
        if binding_lookup.contains_key(&stream_readable_binding_sentinel(name)))
    .then_some(())?;
    well_formed_static_name(property)
        .is_some_and(|name| name == "from")
        .then_some("builtin:StreamReadableFrom")
}

// ---------------------------------------------------------------------------
// Node `events` builtin recognition (bd-2dmnn)
//
// The engine does not materialize a Node `events` module object. Instead, a
// pre-scan confirms only supported static export shapes and records provenance
// sentinels in the lowering lookup:
//   * `const { EventEmitter } = require('events')`, when the local is used by
//     `new EventEmitter(...)` or `EventEmitter.defaultMaxListeners`;
//   * `const { once } = require('events')` or `import { once } from
//     'node:events'`, when the local is called;
//   * `const events = require('events')`, when the alias is read as
//     `events.captureRejections` or called as `events.once(...)`.
// Bare/unused requires/imports and unsupported exports do not get a sentinel,
// so they preserve the ambient-authority denial/module-load failure.

pub(super) fn is_events_module_specifier(specifier: &str) -> bool {
    specifier == "events" || specifier == "node:events"
}

pub(super) fn event_emitter_binding_sentinel(name: &str) -> String {
    format!("\0eventemitter\0{name}")
}

pub(super) fn events_once_binding_sentinel(name: &str) -> String {
    format!("\0eventsonce\0{name}")
}

pub(super) fn events_module_alias_sentinel(name: &str) -> String {
    format!("\0eventsmod\0{name}")
}

pub(super) fn is_require_events_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    // Runtime CommonJS exports are shared and mutable. A finite script facade
    // must not replace events.once or fold constructor/module settings after
    // a package or another source module changes the retained provider.
    if require_is_commonjs_wrapper(binding_lookup) {
        return false;
    }
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    if !matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
    {
        return false;
    }
    matches!(arguments.as_slice(), [specifier]
        if well_formed_string_literal(specifier).is_some_and(is_events_module_specifier))
}

pub(super) fn is_require_event_emitter_member_initializer(
    expression: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = expression
    else {
        return false;
    };
    is_require_events_module_initializer(object, binding_lookup)
        && well_formed_static_name(property).is_some_and(|name| name == "EventEmitter")
}

pub(super) fn event_emitter_default_max_listeners_member(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    if computed {
        return false;
    }
    matches!(object, Expression::Identifier(name)
        if binding_lookup.contains_key(&event_emitter_binding_sentinel(name)))
        && well_formed_static_name(property).is_some_and(|name| name == "defaultMaxListeners")
}

pub(super) fn event_emitter_prototype_member(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    if computed {
        return false;
    }
    matches!(object, Expression::Identifier(name)
        if binding_lookup.contains_key(&event_emitter_binding_sentinel(name)))
        && well_formed_static_name(property).is_some_and(|name| name == "prototype")
}

pub(super) fn events_capture_rejections_member(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    if computed {
        return false;
    }
    matches!(object, Expression::Identifier(name)
        if binding_lookup.contains_key(&events_module_alias_sentinel(name)))
        && well_formed_static_name(property).is_some_and(|name| name == "captureRejections")
}

/// `class X extends <EventEmitter binding>` (bd-9vouw.165): the binding is a
/// real constructor value (builtin:EventEmitterConstructorRef, bd-dspwz), and
/// a class heritage reads it as one. Only the bare binding counts; any other
/// heritage expression is judged as an ordinary use.
pub(super) fn is_event_emitter_heritage(
    super_class: &Expression,
    alias: &str,
    surface: LoweringOnlyModuleAliasSurface,
) -> bool {
    surface == LoweringOnlyModuleAliasSurface::EventEmitter
        && matches!(super_class, Expression::Identifier(name) if name == alias)
}

pub(super) fn is_event_emitter_usage(expr: &Expression, local: &str) -> bool {
    match expr {
        Expression::Call { callee, .. } | Expression::New { callee, .. } => {
            matches!(callee.as_ref(), Expression::Identifier(name) if name == local)
        }
        Expression::Unary {
            operator: UnaryOperator::Typeof,
            argument,
        } => matches!(argument.as_ref(), Expression::Identifier(name) if name == local),
        Expression::Binary {
            operator: BinaryOperator::Instanceof,
            right,
            ..
        } => matches!(right.as_ref(), Expression::Identifier(name) if name == local),
        Expression::Binary {
            operator: BinaryOperator::StrictEqual | BinaryOperator::StrictNotEqual,
            left,
            right,
        } => {
            matches!(left.as_ref(), Expression::Identifier(name) if name == local)
                || matches!(right.as_ref(), Expression::Identifier(name) if name == local)
        }
        Expression::Member {
            object,
            property,
            computed: false,
            ..
        } => {
            matches!(object.as_ref(), Expression::Identifier(name) if name == local)
                && well_formed_static_name(property)
                    .is_some_and(|name| matches!(name, "defaultMaxListeners" | "prototype"))
        }
        _ => false,
    }
}

pub(super) fn is_events_alias_capture_rejections_read(expr: &Expression, alias: &str) -> bool {
    matches!(expr,
        Expression::Member {
            object,
            property,
            computed: false,
            ..
        } if matches!(object.as_ref(), Expression::Identifier(name) if name == alias)
            && well_formed_static_name(property)
                .is_some_and(|name| name == "captureRejections"))
}

pub(super) fn is_events_once_direct_call(expr: &Expression, local: &str) -> bool {
    matches!(expr,
        Expression::Call { callee, .. }
            if matches!(callee.as_ref(), Expression::Identifier(name) if name == local))
}

pub(super) fn is_events_alias_once_call(expr: &Expression, alias: &str) -> bool {
    matches!(expr,
        Expression::Call { callee, .. }
            if matches!(callee.as_ref(), Expression::Member {
                object,
                property,
                computed: false,
                ..
            } if matches!(object.as_ref(), Expression::Identifier(name) if name == alias)
                && well_formed_static_name(property).is_some_and(|name| name == "once")))
}

pub(super) fn confirmed_event_emitter_bindings(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeMap::new();
    for (statement_index, statement) in body.iter().enumerate() {
        if let Statement::VariableDeclaration(declaration) = statement {
            if declaration.kind != VariableDeclarationKind::Const {
                continue;
            }
            for (declarator_index, declarator) in declaration.declarations.iter().enumerate() {
                let Some(initializer) = &declarator.initializer else {
                    continue;
                };
                match &declarator.pattern {
                    BindingPattern::Identifier(local)
                        if is_require_event_emitter_member_initializer(
                            initializer,
                            binding_lookup,
                        ) || is_require_events_module_initializer(
                            initializer,
                            binding_lookup,
                        ) =>
                    {
                        candidates.insert(local.clone(), (statement_index, declarator_index));
                    }
                    BindingPattern::ObjectPattern(properties)
                        if is_require_events_module_initializer(initializer, binding_lookup) =>
                    {
                        for property in properties {
                            if !property.computed
                                && well_formed_static_name(&property.key)
                                    .is_some_and(|name| name == "EventEmitter")
                                && let BindingPattern::Identifier(local) = &property.value
                            {
                                candidates
                                    .insert(local.clone(), (statement_index, declarator_index));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|(local, (statement_index, declarator_index))| {
            !module_alias_has_predeclaration_hazard(
                body,
                *statement_index,
                *declarator_index,
                local,
                LoweringOnlyModuleAliasSurface::EventEmitter,
                binding_lookup,
            ) && body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(
                    statement,
                    local,
                    LoweringOnlyModuleAliasSurface::EventEmitter,
                )
            }) && !body.iter().any(|statement| {
                module_alias_statement_has_rejected_use(
                    statement,
                    local,
                    LoweringOnlyModuleAliasSurface::EventEmitter,
                )
            })
        })
        .map(|(local, _)| local)
        .collect()
}

pub(super) fn confirmed_events_once_destructured_requires(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            for declaration in &vd.declarations {
                let (Some(init), BindingPattern::ObjectPattern(properties)) =
                    (&declaration.initializer, &declaration.pattern)
                else {
                    continue;
                };
                if !is_require_events_module_initializer(init, binding_lookup) {
                    continue;
                }
                for property in properties {
                    if property.computed
                        || !well_formed_static_name(&property.key)
                            .is_some_and(|name| name == "once")
                    {
                        continue;
                    }
                    if let BindingPattern::Identifier(local) = &property.value {
                        candidates.insert(local.clone());
                    }
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|local| {
            body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(
                    statement,
                    local,
                    LoweringOnlyModuleAliasSurface::EventsOnce,
                )
            })
        })
        .collect()
}

pub(super) fn confirmed_events_once_named_imports(body: &[Statement]) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::Import(import) = stmt
            && import.import_attributes.is_empty()
            && module_source_matches(&import.source, is_events_module_specifier)
            && let ImportClause::Named { specifiers } = &import.clause
        {
            for specifier in specifiers {
                if specifier.import_name == "once" {
                    candidates.insert(specifier.local_name.clone());
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|local| {
            body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(
                    statement,
                    local,
                    LoweringOnlyModuleAliasSurface::EventsOnce,
                )
            })
        })
        .collect()
}

pub(super) fn confirmed_events_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            for declaration in &vd.declarations {
                if let (BindingPattern::Identifier(alias), Some(init)) =
                    (&declaration.pattern, &declaration.initializer)
                    && is_require_events_module_initializer(init, binding_lookup)
                {
                    candidates.insert(alias.clone());
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|alias| {
            body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(
                    statement,
                    alias,
                    LoweringOnlyModuleAliasSurface::EventsModule,
                )
            })
        })
        .collect()
}

pub(super) fn confirmed_events_destructure_locals(
    pattern: &BindingPattern,
    init: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<Vec<String>> {
    let BindingPattern::ObjectPattern(properties) = pattern else {
        return None;
    };
    if !is_require_events_module_initializer(init, binding_lookup) {
        return None;
    }

    let mut locals = Vec::new();
    for property in properties {
        if property.computed {
            return None;
        }
        let BindingPattern::Identifier(local) = &property.value else {
            return None;
        };
        let confirmed = match well_formed_static_name(&property.key) {
            Some("EventEmitter") => {
                binding_lookup.contains_key(&event_emitter_binding_sentinel(local))
            }
            Some("once") => binding_lookup.contains_key(&events_once_binding_sentinel(local)),
            _ => false,
        };
        if !confirmed {
            return None;
        }
        locals.push(local.clone());
    }
    (!locals.is_empty()).then_some(locals)
}

pub(super) fn seed_events_module_sentinels(
    body_lookup: &mut BTreeMap<String, BindingId>,
    outer_lookup: &BTreeMap<String, BindingId>,
) {
    seed_url_module_sentinels(body_lookup, outer_lookup);
    seed_prefixed_sentinels(
        body_lookup,
        outer_lookup,
        &["\0eventemitter\0", "\0eventsonce\0", "\0eventsmod\0"],
    );
}

pub(super) fn suppress_events_module_sentinel(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    name: &str,
) {
    binding_lookup.remove(&event_emitter_binding_sentinel(name));
    binding_lookup.remove(&events_once_binding_sentinel(name));
    binding_lookup.remove(&events_module_alias_sentinel(name));
    suppress_url_module_sentinel(binding_lookup, name);
}

pub(super) fn suppress_events_module_sentinels(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    names: &BTreeSet<String>,
) {
    for name in names {
        suppress_events_module_sentinel(binding_lookup, name);
    }
    suppress_url_module_sentinels(binding_lookup, names);
}

pub(super) fn events_once_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    match callee {
        Expression::Identifier(name)
            if binding_lookup.contains_key(&events_once_binding_sentinel(name)) =>
        {
            Some("builtin:EventsOnce")
        }
        Expression::Member {
            object,
            property,
            computed: false,
            ..
        } if matches!(object.as_ref(), Expression::Identifier(name)
            if binding_lookup.contains_key(&events_module_alias_sentinel(name)))
            && well_formed_static_name(property).is_some_and(|name| name == "once") =>
        {
            Some("builtin:EventsOnce")
        }
        _ => None,
    }
}

/// bd-qmy52: true when `specifier` names the Node os module — `os` or
/// `node:os`.
pub(super) fn is_os_module_specifier(specifier: &str) -> bool {
    specifier == "os" || specifier == "node:os"
}

/// bd-qmy52: sentinel key recording that `name` is bound to the os module via
/// `const <name> = require('os')` AND used as a recognized os builtin. Mirror
/// of [`path_module_alias_sentinel`].
pub(super) fn os_module_alias_sentinel(name: &str) -> String {
    format!("\0osmod\0{name}")
}

/// bd-qmy52: true when `expr` is exactly `require('os')` / `require('node:os')`
/// with an unshadowed `require`.
pub(super) fn is_require_os_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    if !matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
    {
        return false;
    }
    matches!(arguments.as_slice(), [spec]
        if well_formed_string_literal(spec).is_some_and(is_os_module_specifier))
}

/// bd-qmy52: capability tag for a recognized `os` method. Single source of
/// truth shared by the usage-lookahead scan and the call-site recognizer. All
/// of these are pure-compute in this engine: the interpreter dispatch returns
/// FIXED engine-contained values (documented at the dispatch arms) — the
/// engine has no ambient authority, so nothing here reads the real host.
pub(crate) fn os_method_capability(method: &str) -> Option<&'static str> {
    match method {
        "platform" => Some("builtin:OsPlatform"),
        "arch" => Some("builtin:OsArch"),
        "type" => Some("builtin:OsType"),
        "release" => Some("builtin:OsRelease"),
        "version" => Some("builtin:OsVersion"),
        "homedir" => Some("builtin:OsHomedir"),
        "tmpdir" => Some("builtin:OsTmpdir"),
        "hostname" => Some("builtin:OsHostname"),
        "uptime" => Some("builtin:OsUptime"),
        "totalmem" => Some("builtin:OsTotalmem"),
        "freemem" => Some("builtin:OsFreemem"),
        "loadavg" => Some("builtin:OsLoadavg"),
        "cpus" => Some("builtin:OsCpus"),
        "networkInterfaces" => Some("builtin:OsNetworkInterfaces"),
        "userInfo" => Some("builtin:OsUserInfo"),
        "endianness" => Some("builtin:OsEndianness"),
        "availableParallelism" => Some("builtin:OsAvailableParallelism"),
        "machine" => Some("builtin:OsMachine"),
        "getPriority" => Some("builtin:OsGetPriority"),
        "setPriority" => Some("builtin:OsSetPriority"),
        _ => None,
    }
}

/// The `os` methods in Node v22's key order, each with an
/// [`os_method_capability`]: the members of the runtime `require('os')`
/// module object (bd-9vouw.204) and the names of their builtins.
pub(crate) const OS_METHOD_NAMES: [&str; 20] = [
    "arch",
    "availableParallelism",
    "cpus",
    "endianness",
    "freemem",
    "getPriority",
    "homedir",
    "hostname",
    "loadavg",
    "networkInterfaces",
    "platform",
    "release",
    "setPriority",
    "tmpdir",
    "totalmem",
    "type",
    "userInfo",
    "uptime",
    "version",
    "machine",
];

/// bd-qmy52: what a recognized `os` property READ lowers to.
pub(super) enum OsMemberReadLowering {
    /// Deterministic constant (`os.EOL`, `os.devNull`) — a string literal.
    StringConstant(&'static str),
    /// `os.constants` — a 0-arg `builtin:OsConstants` HostCall allocating the
    /// nested `{ signals, errno, priority }` object.
    ConstantsHostcall,
}

/// bd-qmy52: the lowering of a recognized `os` property name, per Node
/// (linux). Shared by the scan and the member arm so the confirmed-alias gate
/// can never diverge from what the lowering rewrites.
pub(super) fn os_property_read_lowering(property: &str) -> Option<OsMemberReadLowering> {
    match property {
        "EOL" => Some(OsMemberReadLowering::StringConstant("\n")),
        "devNull" => Some(OsMemberReadLowering::StringConstant("/dev/null")),
        "constants" => Some(OsMemberReadLowering::ConstantsHostcall),
        _ => None,
    }
}

/// bd-qmy52: true when `expr` IS the os module object at lowering time — a
/// sentinel-recorded require-binding alias or the inline `require('os')` call.
pub(super) fn is_os_module_object(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    match expr {
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&os_module_alias_sentinel(alias))
        }
        Expression::Call {
            callee, arguments, ..
        } => {
            matches!(callee.as_ref(), Expression::Identifier(name)
                if is_builtin_require_callee(binding_lookup, name))
                && matches!(arguments.as_slice(), [spec]
                    if well_formed_string_literal(spec).is_some_and(is_os_module_specifier))
        }
        _ => false,
    }
}

/// bd-qmy52: recognize an `os` builtin member call and return its
/// `builtin:Os*` capability. Purely syntactic; no sub-namespaces.
pub(super) fn os_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return None;
    };
    if !is_os_module_object(object, binding_lookup) {
        return None;
    }
    let method = well_formed_static_name(property)?;
    os_method_capability(method)
}

/// bd-qmy52: recognize an `os` property READ (`os.EOL`, `os.devNull`,
/// `os.constants`) on a recognized os-module object and return its lowering.
/// Accepts the same static/quoted property shapes as [`path_member_constant`].
pub(super) fn os_member_read_lowering(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<OsMemberReadLowering> {
    if !is_os_module_object(object, binding_lookup) {
        return None;
    }
    let prop = match computed {
        false => well_formed_static_name(property)?,
        true => well_formed_string_literal(property)?,
    };
    os_property_read_lowering(prop)
}

/// bd-qmy52: scan-time twin of [`os_builtin_call_capability`]'s receiver check.
pub(super) fn is_os_alias_method_callee(
    callee: &Expression,
    alias_names: &BTreeSet<String>,
) -> bool {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return false;
    };
    if !matches!(object.as_ref(), Expression::Identifier(name) if alias_names.contains(name)) {
        return false;
    }
    well_formed_static_name(property).is_some_and(|method| os_method_capability(method).is_some())
}

/// bd-qmy52: scan-time twin of [`os_member_read_lowering`]: true when `expr`
/// is a recognized os property read (`<alias>.EOL`, `<alias>.constants`, …) on
/// one of the candidate alias names.
pub(super) fn is_os_alias_property_read(expr: &Expression, alias_names: &BTreeSet<String>) -> bool {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = expr
    else {
        return false;
    };
    if !matches!(object.as_ref(), Expression::Identifier(name) if alias_names.contains(name)) {
        return false;
    }
    well_formed_static_name(property)
        .is_some_and(|property| os_property_read_lowering(property).is_some())
}

/// bd-qmy52: true when `expr` contains a recognized os usage on one of
/// `alias_names` — either a recognized method CALL (`<alias>.platform()`) or a
/// recognized property READ (`<alias>.EOL`, `<alias>.constants`).
pub(super) fn expr_contains_os_alias_usage(
    expr: &Expression,
    alias_names: &BTreeSet<String>,
) -> bool {
    expr_contains_matching_call(expr, &|callee| {
        is_os_alias_method_callee(callee, alias_names)
    }) || expr_contains_matching_member(expr, &|member| {
        is_os_alias_property_read(member, alias_names)
    })
}

/// bd-qmy52: compute the set of identifier names that are BOTH bound via
/// `const/let/var <name> = require('os')` at the unit root AND used as a
/// recognized os builtin (method call or property read) somewhere reachable by
/// the fail-closed statement scan. Mirror of
/// [`confirmed_path_module_aliases`].
pub(super) fn confirmed_os_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            for d in &vd.declarations {
                if let (BindingPattern::Identifier(name), Some(init)) = (&d.pattern, &d.initializer)
                    && is_require_os_module_initializer(init, binding_lookup)
                {
                    candidates.insert(name.clone());
                }
            }
        }
    }
    if candidates.is_empty() {
        return candidates;
    }

    let mut used = BTreeSet::new();
    for name in &candidates {
        let single: BTreeSet<String> = std::iter::once(name.clone()).collect();
        if body.iter().any(|stmt| {
            path_statement_contains_usage(stmt, &|e| expr_contains_os_alias_usage(e, &single))
        }) {
            used.insert(name.clone());
        }
    }
    used
}

/// bd-d0n7u: only plaintext `http` enters the hermetic loopback facade.
pub(super) fn is_http_module_specifier(specifier: &str) -> bool {
    matches!(specifier, "http" | "node:http")
}

/// HTTPS retains its existing external `net:*` path. Keeping a distinct
/// recognizer prevents the hermetic HTTP facade from silently treating TLS as
/// plaintext.
pub(super) fn is_https_module_specifier(specifier: &str) -> bool {
    matches!(specifier, "https" | "node:https")
}

pub(super) fn http_module_alias_sentinel(name: &str) -> String {
    format!("\0httpmod\0{name}")
}

pub(super) fn https_module_alias_sentinel(name: &str) -> String {
    format!("\0httpsmod\0{name}")
}

pub(super) fn is_require_http_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    if !matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
    {
        return false;
    }
    matches!(arguments.as_slice(), [spec]
        if well_formed_string_literal(spec).is_some_and(is_http_module_specifier))
}

pub(super) fn is_require_https_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    if !matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
    {
        return false;
    }
    matches!(arguments.as_slice(), [spec]
        if well_formed_string_literal(spec).is_some_and(is_https_module_specifier))
}

pub(super) fn http_method_capability(method: &str) -> Option<&'static str> {
    match method {
        "createServer" => Some("builtin:HttpCreateServer"),
        "get" => Some("builtin:HttpGet"),
        "request" => Some("builtin:HttpRequest"),
        _ => None,
    }
}

pub(super) fn https_external_method_capability(method: &str) -> Option<&'static str> {
    match method {
        "get" => Some("net:request"),
        "request" => Some("net:client_request"),
        _ => None,
    }
}

pub(super) fn http_property_capability(property: &str) -> Option<&'static str> {
    match property {
        "STATUS_CODES" => Some("builtin:HttpStatusCodes"),
        "METHODS" => Some("builtin:HttpMethods"),
        _ => None,
    }
}

pub(super) fn is_http_module_object(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    if require_is_commonjs_wrapper(binding_lookup) {
        return false;
    }
    match expr {
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&http_module_alias_sentinel(alias))
        }
        Expression::Call { .. } => is_require_http_module_initializer(expr, binding_lookup),
        _ => false,
    }
}

pub(super) fn is_https_module_object(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    if require_is_commonjs_wrapper(binding_lookup) {
        return false;
    }
    match expr {
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&https_module_alias_sentinel(alias))
        }
        Expression::Call { .. } => is_require_https_module_initializer(expr, binding_lookup),
        _ => false,
    }
}

pub(super) fn http_member_name<'a>(
    expression: &'a Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'a str> {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = expression
    else {
        return None;
    };
    if !is_http_module_object(object, binding_lookup) {
        return None;
    }
    well_formed_static_name(property)
}

pub(super) fn https_member_name<'a>(
    expression: &'a Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'a str> {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = expression
    else {
        return None;
    };
    if !is_https_module_object(object, binding_lookup) {
        return None;
    }
    well_formed_static_name(property)
}

pub(super) fn http_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    http_member_name(callee, binding_lookup).and_then(http_method_capability)
}

pub(super) fn https_external_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    https_member_name(callee, binding_lookup).and_then(https_external_method_capability)
}

pub(super) fn http_agent_constructor_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    (http_member_name(callee, binding_lookup) == Some("Agent")).then_some("builtin:HttpAgent")
}

pub(super) fn http_member_read_capability(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    if computed || !is_http_module_object(object, binding_lookup) {
        return None;
    }
    well_formed_static_name(property).and_then(http_property_capability)
}

pub(super) fn confirmed_http_like_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
    initializer_matches: fn(&Expression, &BTreeMap<String, BindingId>) -> bool,
    surface: LoweringOnlyModuleAliasSurface,
) -> BTreeSet<String> {
    // Authenticated CommonJS owns mutable, first-class module objects. A
    // const binding does not make its exported methods immutable.
    if require_is_commonjs_wrapper(binding_lookup) {
        return BTreeSet::new();
    }
    let mut candidates = BTreeMap::new();
    for (statement_index, statement) in body.iter().enumerate() {
        if let Statement::VariableDeclaration(declaration) = statement {
            if declaration.kind != VariableDeclarationKind::Const {
                continue;
            }
            for (declarator_index, declarator) in declaration.declarations.iter().enumerate() {
                if let (BindingPattern::Identifier(alias), Some(initializer)) =
                    (&declarator.pattern, &declarator.initializer)
                    && initializer_matches(initializer, binding_lookup)
                {
                    candidates.insert(alias.clone(), (statement_index, declarator_index));
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|(alias, (statement_index, declarator_index))| {
            !module_alias_has_predeclaration_hazard(
                body,
                *statement_index,
                *declarator_index,
                alias,
                surface,
                binding_lookup,
            ) && body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(statement, alias, surface)
            }) && !body
                .iter()
                .any(|statement| module_alias_statement_has_rejected_use(statement, alias, surface))
        })
        .map(|(alias, _)| alias)
        .collect()
}

pub(super) fn confirmed_http_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    confirmed_http_like_module_aliases(
        body,
        binding_lookup,
        is_require_http_module_initializer,
        LoweringOnlyModuleAliasSurface::Http,
    )
}

pub(super) fn confirmed_https_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    confirmed_http_like_module_aliases(
        body,
        binding_lookup,
        is_require_https_module_initializer,
        LoweringOnlyModuleAliasSurface::HttpsExternal,
    )
}

pub(super) fn http_named_import_sentinel(local_name: &str, capability: &str) -> String {
    format!("\0httpnamed\0{capability}\0{local_name}")
}

pub(super) fn confirmed_http_like_namespace_import_aliases(
    body: &[Statement],
    source_matches: fn(&str) -> bool,
    surface: LoweringOnlyModuleAliasSurface,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::Import(import) = stmt
            && import.import_attributes.is_empty()
            && module_source_matches(&import.source, source_matches)
        {
            match &import.clause {
                ImportClause::Namespace { local } | ImportClause::Default { local } => {
                    candidates.insert(local.clone());
                }
                _ => {}
            }
        }
    }
    candidates
        .into_iter()
        .filter(|alias| {
            body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(statement, alias, surface)
            }) && !body
                .iter()
                .any(|statement| module_alias_statement_has_rejected_use(statement, alias, surface))
        })
        .collect()
}

pub(super) fn confirmed_http_namespace_import_aliases(body: &[Statement]) -> BTreeSet<String> {
    confirmed_http_like_namespace_import_aliases(
        body,
        is_http_module_specifier,
        LoweringOnlyModuleAliasSurface::Http,
    )
}

pub(super) fn confirmed_https_namespace_import_aliases(body: &[Statement]) -> BTreeSet<String> {
    confirmed_http_like_namespace_import_aliases(
        body,
        is_https_module_specifier,
        LoweringOnlyModuleAliasSurface::HttpsExternal,
    )
}

pub(super) fn confirmed_http_like_named_imports(
    body: &[Statement],
    source_matches: fn(&str) -> bool,
    capability_for_name: fn(&str) -> Option<&'static str>,
) -> BTreeMap<String, &'static str> {
    let mut candidates: BTreeMap<String, &'static str> = BTreeMap::new();
    for stmt in body {
        if let Statement::Import(import) = stmt
            && import.import_attributes.is_empty()
            && module_source_matches(&import.source, source_matches)
            && let ImportClause::Named { specifiers } = &import.clause
        {
            for spec in specifiers {
                let Some(capability) = capability_for_name(&spec.import_name) else {
                    continue;
                };
                candidates.insert(spec.local_name.clone(), capability);
            }
        }
    }
    candidates
        .into_iter()
        .filter(|(local, capability)| {
            let surface = if *capability == "builtin:HttpCreateServer" {
                LoweringOnlyModuleAliasSurface::HttpNamedCreateServer
            } else {
                LoweringOnlyModuleAliasSurface::HttpNamedRequest
            };
            body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(statement, local, surface)
            }) && !body
                .iter()
                .any(|statement| module_alias_statement_has_rejected_use(statement, local, surface))
        })
        .collect()
}

pub(super) fn confirmed_http_named_imports(body: &[Statement]) -> BTreeMap<String, &'static str> {
    confirmed_http_like_named_imports(body, is_http_module_specifier, http_method_capability)
}

pub(super) fn confirmed_https_named_imports(body: &[Statement]) -> BTreeMap<String, &'static str> {
    confirmed_http_like_named_imports(
        body,
        is_https_module_specifier,
        https_external_method_capability,
    )
}

pub(super) fn http_named_import_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Identifier(name) = callee else {
        return None;
    };
    [
        "builtin:HttpCreateServer",
        "builtin:HttpGet",
        "builtin:HttpRequest",
        "net:request",
        "net:client_request",
    ]
    .into_iter()
    .find(|&capability| binding_lookup.contains_key(&http_named_import_sentinel(name, capability)))
}

/// bd-3894s (http leg, fetch global): capability for a bare `fetch(url)` call —
/// the WHATWG/Node global HTTP entry point. Like the timer/global-function
/// builtins it is invoked as a bare identifier (not a member access), so it is
/// recognized here rather than by the http member-call recognizer
/// [`http_builtin_call_capability`]. Fetch remains an external
/// `net:request` egress surface; it is intentionally separate from the
/// hermetic plain-HTTP facade. Returns `None` when `fetch` is
/// shadowed by a user binding in scope (e.g. `const fetch = ...`), so a local
/// `fetch` is never reinterpreted as the host egress — the fail-closed shadowing
/// gate shared with [`timer_builtin_call_capability`].
pub(super) fn fetch_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Identifier(name) = callee else {
        return None;
    };
    if is_lexically_shadowed(binding_lookup, name) {
        return None;
    }
    match name.as_str() {
        "fetch" => Some("net:request"),
        _ => None,
    }
}

/// bd-201vt: the *async callback* analogue of [`fs_builtin_call_capability`].
/// Recognizes the idiomatic Node callback forms
///   * inline:  `require('fs').readFile(path, cb)` / `.writeFile(path, data, cb)`
///   * binding: `fs.readFile(path, cb)` where `fs` was aliased via
///     `const fs = require('fs')` (recorded as a NUL-sentinel, gated on usage by
///     the same pre-scan as the sync form — see [`is_fs_alias_method_callee`]).
///
/// Returns the SAME `fs:read`/`fs:write` capability as the sync form: the host
/// effect is identical, and the trailing callback closure is carried as a normal
/// trailing HostCall argument that `dispatch_host_io_hostcall` detects (a
/// `Value::Closure` in the last slot) to switch to the async path — schedule the
/// callback as an `IoCompletion` macrotask and return `undefined`. Only the
/// `fs`/`node:fs` specifier and the async `readFile`/`writeFile` methods match
/// (the `*Sync` methods stay with the sync recognizer; fs/promises is separate).
pub(super) fn fs_callback_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    if binding_lookup.contains_key(PRESERVE_RUNTIME_MODULE_LOADS_SENTINEL) {
        return None;
    }
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return None;
    };
    let receiver_is_fs_module = match object.as_ref() {
        // inline `require('fs')` / `require('node:fs')` receiver.
        Expression::Call {
            callee: require_callee,
            arguments: require_args,
            ..
        } => {
            matches!(require_callee.as_ref(), Expression::Identifier(name) if name == "require")
                && matches!(require_args.as_slice(), [spec]
                    if well_formed_string_literal(spec).is_some_and(is_fs_module_specifier))
        }
        // binding form: identifier aliased to the fs module.
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&fs_module_alias_sentinel(alias))
        }
        _ => false,
    };
    if !receiver_is_fs_module {
        return None;
    }
    let method = well_formed_static_name(property)?;
    match method {
        "readFile" => Some("fs:read"),
        "writeFile" => Some("fs:write"),
        _ => None,
    }
}

/// True when `callee` is exactly the bare identifier `name` — the direct-call
/// shape `readFileSync(path)` of an fs function brought in by a named ESM import
/// `import { readFileSync } from 'node:fs'` (bd-1xl17.b). Used as the
/// usage-lookahead target for [`expr_contains_matching_call`].
pub(super) fn is_fs_named_callee(callee: &Expression, name: &str) -> bool {
    matches!(callee, Expression::Identifier(n) if n == name)
}

pub(super) fn body_deep_contains_fs_named_call(body: &[Statement], local: &str) -> bool {
    body.iter().any(|stmt| {
        timers_scan_statement_deep(stmt, &|candidate| {
            matches!(candidate,
                Expression::Call { callee, .. } | Expression::OptionalCall { callee, .. }
                    if is_fs_named_callee(callee, local))
        })
    })
}

/// Sentinel key recording that the local binding `local_name` is an fs *named
/// import* (`import { readFileSync } from 'node:fs'`, incl. `as` renames) bound to
/// `capability` ("fs:read"/"fs:write") AND used as a direct call (bd-1xl17.b).
/// Like [`fs_module_alias_sentinel`] it lives in the lowering `binding_lookup`;
/// the leading NUL and the `:` inside the capability cannot occur in a JS
/// identifier, so the composite key never collides with a real binding. This lets
/// the direct-call recognizer map `readFileSync(...)` to its `fs:` hostcall
/// without threading an import-provenance map through the IR1 recursion.
pub(super) fn fs_named_import_sentinel(local_name: &str, capability: &str) -> String {
    format!("\0fsnamed\0{capability}\0{local_name}")
}

/// Confirmed fs *namespace/default* ESM import aliases (bd-1xl17.b): a local
/// bound via `import * as <local> from 'node:fs'` or `import <local> from
/// 'node:fs'` that is actually used as `<local>.readFileSync/writeFileSync(...)`
/// at a top-level program position. These reuse the SAME member-call recognizer
/// and [`fs_module_alias_sentinel`] as the require-binding form (bd-1xl17.a), so
/// the call sites need no additional handling. Gated on usage so a bare/unused fs
/// import keeps its current (runtime module-load) behavior — the fail-closed
/// analogue of the `require`-binding ambient-denial contract.
pub(super) fn confirmed_fs_namespace_import_aliases(body: &[Statement]) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::Import(import) = stmt
            && import.import_attributes.is_empty()
            && module_source_matches(&import.source, is_fs_module_specifier)
        {
            match &import.clause {
                ImportClause::Namespace { local } | ImportClause::Default { local } => {
                    candidates.insert(local.clone());
                }
                _ => {}
            }
        }
    }
    let mut used = BTreeSet::new();
    for name in &candidates {
        let single: BTreeSet<String> = std::iter::once(name.clone()).collect();
        if body.iter().any(|stmt| {
            timers_scan_statement_deep(stmt, &|candidate| {
                is_fs_alias_constant_member(candidate, &single)
                    || matches!(candidate,
                        Expression::Call { callee, .. } | Expression::OptionalCall { callee, .. }
                            if is_fs_alias_method_callee(callee, &single))
            })
        }) {
            used.insert(name.clone());
        }
    }
    used
}

/// Confirmed fs *named* ESM imports (bd-1xl17.b): `import { readFileSync[,
/// writeFileSync] } from 'node:fs'` (incl. `as` renames) whose local binding is
/// used as a direct call `<local>(...)` at a top-level program position. Returns
/// a map local-name -> fs capability ("fs:read"/"fs:write"). Recorded as
/// NUL-sentinels (see [`fs_named_import_sentinel`]) and gated on usage, exactly
/// like the binding/namespace forms.
pub(super) fn confirmed_fs_named_imports(body: &[Statement]) -> BTreeMap<String, &'static str> {
    let mut candidates: BTreeMap<String, &'static str> = BTreeMap::new();
    for stmt in body {
        if let Statement::Import(import) = stmt
            && import.import_attributes.is_empty()
            && module_source_matches(&import.source, is_fs_module_specifier)
            && let ImportClause::Named { specifiers } = &import.clause
        {
            for spec in specifiers {
                let capability = match spec.import_name.as_str() {
                    // sync forms (bd-1xl17.b)
                    "readFileSync" => "fs:read",
                    "writeFileSync" => "fs:write",
                    // async callback forms (bd-201vt) — same fs: capability; the
                    // trailing callback closure is detected at dispatch.
                    "readFile" => "fs:read",
                    "writeFile" => "fs:write",
                    _ => continue,
                };
                candidates.insert(spec.local_name.clone(), capability);
            }
        }
    }
    candidates
        .into_iter()
        .filter(|(local, _)| body_deep_contains_fs_named_call(body, local))
        .collect()
}

/// bd-rmaze: confirmed *destructured CJS* sync-fs requires — `const {
/// readFileSync[, writeFileSync, readFile, writeFile] } = require('fs')` (incl.
/// `{ readFileSync: rd }` renames) whose destructured local is used as a direct
/// call `<local>(...)` at a top-level program position. Returns a map local-name
/// -> fs capability ("fs:read"/"fs:write"). The CJS-destructure analogue of
/// [`confirmed_fs_named_imports`] (the ESM named import) — both record the same
/// [`fs_named_import_sentinel`], so the shared direct-call recognizer
/// [`fs_named_import_call_capability`] + the named-import dispatch (which already
/// disambiguates the sync `readFileSync` from the async-callback `readFile` on
/// the trailing closure) handle the call sites unchanged. Mirrors
/// [`confirmed_fs_promises_destructured_requires`] for the synchronous module.
/// Usage-gated: a bare/unused destructured require is not recorded and keeps the
/// ambient-authority denial of `require('fs')`.
pub(super) fn confirmed_fs_destructured_requires(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeMap<String, &'static str> {
    let mut candidates: BTreeMap<String, &'static str> = BTreeMap::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            for d in &vd.declarations {
                let (Some(init), BindingPattern::ObjectPattern(props)) =
                    (&d.initializer, &d.pattern)
                else {
                    continue;
                };
                if !is_require_fs_module_initializer(init, binding_lookup) {
                    continue;
                }
                for prop in props {
                    if prop.computed {
                        continue;
                    }
                    let capability = match well_formed_static_name(&prop.key) {
                        // sync forms
                        Some("readFileSync") => "fs:read",
                        Some("writeFileSync") => "fs:write",
                        // async callback forms — same fs: capability; the
                        // trailing callback closure is detected at dispatch.
                        Some("readFile") => "fs:read",
                        Some("writeFile") => "fs:write",
                        _ => continue,
                    };
                    if let BindingPattern::Identifier(local) = &prop.value {
                        candidates.insert(local.clone(), capability);
                    }
                }
            }
        }
    }
    candidates
        .into_iter()
        .filter(|(local, _)| body_deep_contains_fs_named_call(body, local))
        .collect()
}

/// bd-rmaze: if `pattern`/`init` form a confirmed *destructured* sync-fs require
/// (`const { readFileSync } = require('fs')`), return the simple-identifier local
/// names to bind to `undefined` (eliding the faulting `require('fs')` load and
/// the property extraction; there is no real fs module object). Gated on at least
/// one local having been confirmed at the program pre-scan (recorded as an
/// [`fs_named_import_sentinel`]). Returns `None` for any non-plain pattern
/// (rest/nested/computed targets) or when no local is confirmed, leaving the
/// existing ambient-denial path intact. Unconfirmed sibling locals in a confirmed
/// declaration are still bound to `undefined` (fail-closed: invoking one faults,
/// exactly as the elided require would have). The synchronous analogue of
/// [`confirmed_fs_promises_destructure_locals`] (whose `const { promises } =
/// require('fs')` shape this defers to — a `promises` local is not an
/// `fs_named_import_sentinel`, so this returns `None` for it).
pub(super) fn confirmed_fs_destructure_locals(
    pattern: &BindingPattern,
    init: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<Vec<String>> {
    let BindingPattern::ObjectPattern(props) = pattern else {
        return None;
    };
    if !is_require_fs_module_initializer(init, binding_lookup) {
        return None;
    }
    let mut locals = Vec::new();
    let mut any_confirmed = false;
    for prop in props {
        if prop.computed {
            return None;
        }
        let BindingPattern::Identifier(local) = &prop.value else {
            return None;
        };
        let confirmed = binding_lookup.contains_key(&fs_named_import_sentinel(local, "fs:read"))
            || binding_lookup.contains_key(&fs_named_import_sentinel(local, "fs:write"));
        any_confirmed |= confirmed;
        locals.push(local.clone());
    }
    any_confirmed.then_some(locals)
}

/// Recognize a direct call to an fs *named import* — `readFileSync(path)` /
/// `writeFileSync(path, data)` brought in by `import { ... } from 'node:fs'`
/// (bd-1xl17.b) — and return its `fs:` hostcall capability. The local name
/// (respecting `as` renames) was recorded as a NUL-sentinel in `binding_lookup`
/// by the program pre-scan, gated on actual direct-call usage so a bare/unused fs
/// import keeps its current behavior. This is the ESM-named-import analogue of
/// [`fs_builtin_call_capability`]'s inline/binding member-call recognition.
pub(super) fn fs_named_import_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Identifier(name) = callee else {
        return None;
    };
    if binding_lookup.contains_key(&fs_named_import_sentinel(name, "fs:read")) {
        Some("fs:read")
    } else if binding_lookup.contains_key(&fs_named_import_sentinel(name, "fs:write")) {
        Some("fs:write")
    } else {
        None
    }
}

/// True when `specifier` names the Node promises filesystem module —
/// `fs/promises` or `node:fs/promises` (bd-1xl17.c). The async analogue of
/// [`is_fs_module_specifier`]; kept separate so the synchronous recognizers never
/// accept the promises module (its functions return Promises, not raw values).
pub(super) fn is_fs_promises_module_specifier(specifier: &str) -> bool {
    specifier == "fs/promises" || specifier == "node:fs/promises"
}

/// Sentinel key recording that the local binding `local_name` is an fs/promises
/// *named import* (`import { readFile } from 'node:fs/promises'`, incl. `as`
/// renames) bound to the underlying `capability` ("fs:read"/"fs:write") AND used
/// as a direct call (bd-1xl17.c). Mirrors [`fs_named_import_sentinel`] with a
/// distinct prefix so the async (Promise-returning) and synchronous forms never
/// collide in `binding_lookup`.
pub(super) fn fs_promises_named_import_sentinel(local_name: &str, capability: &str) -> String {
    format!("\0fspromnamed\0{capability}\0{local_name}")
}

/// Confirmed fs/promises *named* ESM imports (bd-1xl17.c): `import { readFile[,
/// writeFile] } from 'node:fs/promises'` (incl. `as` renames) whose local binding
/// is used as a direct call `<local>(...)` at a top-level program position.
/// Returns a map local-name -> underlying fs capability ("fs:read"/"fs:write").
/// The promises module exposes the un-suffixed names (`readFile`/`writeFile`),
/// each returning a Promise. Recorded as NUL-sentinels (see
/// [`fs_promises_named_import_sentinel`]) and gated on usage, exactly like the
/// synchronous named-import form ([`confirmed_fs_named_imports`]).
pub(super) fn confirmed_fs_promises_named_imports(
    body: &[Statement],
) -> BTreeMap<String, &'static str> {
    let mut candidates: BTreeMap<String, &'static str> = BTreeMap::new();
    for stmt in body {
        if let Statement::Import(import) = stmt
            && import.import_attributes.is_empty()
            && module_source_matches(&import.source, is_fs_promises_module_specifier)
            && let ImportClause::Named { specifiers } = &import.clause
        {
            for spec in specifiers {
                let capability = match spec.import_name.as_str() {
                    "readFile" => "fs:read",
                    "writeFile" => "fs:write",
                    _ => continue,
                };
                candidates.insert(spec.local_name.clone(), capability);
            }
        }
    }
    candidates
        .into_iter()
        .filter(|(local, _)| body_deep_contains_fs_named_call(body, local))
        .collect()
}

/// Recognize a direct call to an fs/promises *named import* —
/// `readFile(path[, encoding])` / `writeFile(path, data)` brought in by
/// `import { ... } from 'node:fs/promises'` (bd-1xl17.c) — and return its
/// underlying `fs:` hostcall capability. The call site lowers this to the same
/// `fs:` HostCall as the synchronous form and then wraps the result in a
/// `promise:resolve` HostCall, so the call evaluates to a (resolved) Promise that
/// matches the Promise-returning contract of `fs/promises`. The async analogue of
/// [`fs_named_import_call_capability`].
pub(super) fn fs_promises_named_import_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Identifier(name) = callee else {
        return None;
    };
    if binding_lookup.contains_key(&fs_promises_named_import_sentinel(name, "fs:read")) {
        Some("fs:read")
    } else if binding_lookup.contains_key(&fs_promises_named_import_sentinel(name, "fs:write")) {
        Some("fs:write")
    } else {
        None
    }
}

/// True when `expr` is exactly `require('fs/promises')` / `require('node:fs/promises')`
/// with an unshadowed `require` — the initializer that aliases the promises fs
/// module in `const fsp = require('fs/promises')` (bd-1xl17.c). Mirrors
/// [`is_require_fs_module_initializer`].
pub(super) fn is_require_fs_promises_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    if require_is_commonjs_wrapper(binding_lookup) {
        return false;
    }
    let Expression::Call {
        callee, arguments, ..
    } = expr
    else {
        return false;
    };
    if !matches!(callee.as_ref(), Expression::Identifier(name)
        if is_builtin_require_callee(binding_lookup, name))
    {
        return false;
    }
    matches!(arguments.as_slice(), [spec]
        if well_formed_string_literal(spec).is_some_and(is_fs_promises_module_specifier))
}

/// Sentinel recording that `name` is bound to the fs/promises module via
/// `const <name> = require('fs/promises')` (bd-1xl17.c). Distinct prefix from
/// [`fs_module_alias_sentinel`] so the member-call recognizer knows the call is
/// async (Promise-returning) and wraps the result in `promise:resolve`.
pub(super) fn fs_promises_module_alias_sentinel(name: &str) -> String {
    format!("\0fsprommod\0{name}")
}

pub(super) fn fs_promises_method_spec(method: &str) -> Option<FsBuiltinCall> {
    let (capability, operation, min_args, max_args) = match method {
        "readFile" => ("fs:read", FsOperation::Read, 1, 2),
        "writeFile" => ("fs:write", FsOperation::Write, 2, 3),
        "mkdir" => ("fs:write", FsOperation::Mkdir, 1, 2),
        "readdir" => ("fs:read", FsOperation::ReadDir, 1, 2),
        _ => return None,
    };
    Some(FsBuiltinCall {
        capability,
        operation,
        min_args,
        max_args,
    })
}

/// True when `callee` is `<obj>.readFile` / `.writeFile` whose object identifier
/// is in `alias_names` — an fs/promises host method call on a
/// `const fsp = require('fs/promises')` alias (bd-1xl17.c). Mirrors
/// [`is_fs_alias_method_callee`] with the promises (un-suffixed) method names.
pub(super) fn is_fs_promises_alias_method_callee(
    callee: &Expression,
    alias_names: &BTreeSet<String>,
) -> bool {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return false;
    };
    let Expression::Identifier(obj) = object.as_ref() else {
        return false;
    };
    if !alias_names.contains(obj) {
        return false;
    }
    well_formed_static_name(property)
        .is_some_and(|method| fs_promises_method_spec(method).is_some())
}

/// Confirmed fs/promises module aliases (bd-1xl17.c): names bound via
/// `const <name> = require('fs/promises')` AND used as
/// `<name>.readFile/writeFile(...)` at a top-level position. Usage-gated exactly
/// like the synchronous [`confirmed_fs_module_aliases`], so a bare/unused
/// `const fsp = require('fs/promises')` keeps its current behavior.
pub(super) fn confirmed_fs_promises_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            for d in &vd.declarations {
                // `const fsp = require('fs/promises')` (the promises module) OR
                // `const fsp = require('fs').promises` (the promises sub-object
                // hung off the synchronous fs module). Both alias the same
                // Promise-returning API, so both record the same module-alias
                // sentinel and share `fs_promises_builtin_call_capability`.
                if let (BindingPattern::Identifier(name), Some(init)) = (&d.pattern, &d.initializer)
                    && (is_require_fs_promises_module_initializer(init, binding_lookup)
                        || is_fs_promises_subobject(init, binding_lookup))
                {
                    candidates.insert(name.clone());
                }
            }
        }
    }
    if candidates.is_empty() {
        return candidates;
    }
    let mut used = BTreeSet::new();
    for name in &candidates {
        let single: BTreeSet<String> = std::iter::once(name.clone()).collect();
        if body.iter().any(|stmt| {
            timers_scan_statement_deep(stmt, &|candidate| {
                matches!(candidate,
                    Expression::Call { callee, .. } | Expression::OptionalCall { callee, .. }
                        if is_fs_promises_alias_method_callee(callee, &single))
            })
        }) {
            used.insert(name.clone());
        }
    }
    used
}

/// Confirmed fs/promises *namespace/default* ESM import aliases (bd-1xl17.c): a
/// local bound via `import * as fsp from 'node:fs/promises'` or `import fsp from
/// 'node:fs/promises'` that is actually used as `fsp.readFile/writeFile(...)` at a
/// top-level program position. The ESM analogue of the require-binding form
/// ([`confirmed_fs_promises_module_aliases`]); both record the same
/// [`fs_promises_module_alias_sentinel`] and reuse
/// [`fs_promises_builtin_call_capability`], so the call sites need no extra
/// handling. Usage-gated so a bare/unused fs/promises namespace/default import
/// keeps its current (runtime module-load) behavior.
pub(super) fn confirmed_fs_promises_namespace_import_aliases(
    body: &[Statement],
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::Import(import) = stmt
            && import.import_attributes.is_empty()
            && module_source_matches(&import.source, is_fs_promises_module_specifier)
        {
            match &import.clause {
                ImportClause::Namespace { local } | ImportClause::Default { local } => {
                    candidates.insert(local.clone());
                }
                _ => {}
            }
        }
    }
    let mut used = BTreeSet::new();
    for name in &candidates {
        let single: BTreeSet<String> = std::iter::once(name.clone()).collect();
        if body.iter().any(|stmt| {
            timers_scan_statement_deep(stmt, &|candidate| {
                matches!(candidate,
                    Expression::Call { callee, .. } | Expression::OptionalCall { callee, .. }
                        if is_fs_promises_alias_method_callee(callee, &single))
            })
        }) {
            used.insert(name.clone());
        }
    }
    used
}

/// Recognize an fs/promises read/write member call — inline
/// `require('fs/promises').readFile(path)` or binding `fsp.readFile(path)` where
/// `fsp` was aliased via `const fsp = require('fs/promises')` (bd-1xl17.c) — and
/// return its underlying `fs:` capability. The call site lowers this to the same
/// `fs:` HostCall as the synchronous form plus a `promise:resolve` wrap. The async
/// analogue of [`fs_builtin_call_capability`].
pub(super) fn fs_promises_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<FsBuiltinCall> {
    if binding_lookup.contains_key(PRESERVE_RUNTIME_MODULE_LOADS_SENTINEL) {
        return None;
    }
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return None;
    };
    let receiver_is_fs_promises = match object.as_ref() {
        // inline `require('fs/promises')` / `require('node:fs/promises')` receiver.
        Expression::Call {
            callee: require_callee,
            arguments: require_args,
            ..
        } => {
            matches!(require_callee.as_ref(), Expression::Identifier(name) if name == "require")
                && matches!(require_args.as_slice(), [spec]
                    if well_formed_string_literal(spec)
                        .is_some_and(is_fs_promises_module_specifier))
        }
        // binding form: identifier aliased to the fs/promises module.
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&fs_promises_module_alias_sentinel(alias))
        }
        // sub-object form: `require('fs').promises.readFile(...)` — the promises
        // API hung off the synchronous fs module (bd-1xl17.c).
        member @ Expression::Member { .. } => is_fs_promises_subobject(member, binding_lookup),
        _ => false,
    };
    if !receiver_is_fs_promises {
        return None;
    }
    let method = well_formed_static_name(property)?;
    fs_promises_method_spec(method)
}

/// True when `expr` is the `require('fs').promises` sub-object — the promises API
/// hung off the synchronous fs module (`const fsp = require('fs').promises` /
/// `require('fs').promises.readFile(...)`, bd-1xl17.c). Purely syntactic like the
/// other fs recognizers: there is no real `fs` heap object, so `.promises` is
/// recognized at lowering time and is never read at runtime. Both `fs` and
/// `node:fs` specifiers are accepted (via [`is_fs_module_specifier`]).
pub(super) fn is_fs_promises_subobject(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = expr
    else {
        return false;
    };
    let property_is_promises =
        well_formed_static_name(property).is_some_and(|name| name == "promises");
    if !property_is_promises {
        return false;
    }
    is_fs_module_object(object, binding_lookup)
}

/// Confirmed fs/promises *destructured* CJS requires (bd-1xl17.c):
/// `const { readFile[, writeFile] } = require('fs/promises')` (incl. `{ readFile:
/// rf }` renames) whose destructured local is used as a direct call
/// `<local>(...)` at a top-level program position. Returns a map local-name ->
/// underlying fs capability ("fs:read"/"fs:write"). The destructured locals are
/// the CJS analogue of the ESM named import and reuse the SAME direct-call
/// recognizer ([`fs_promises_named_import_call_capability`] via
/// [`fs_promises_named_import_sentinel`]); usage-gated exactly like every other
/// fs form so a bare/unused destructure keeps the ambient-authority denial.
pub(super) fn confirmed_fs_promises_destructured_requires(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeMap<String, &'static str> {
    let mut candidates: BTreeMap<String, &'static str> = BTreeMap::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            for d in &vd.declarations {
                let (Some(init), BindingPattern::ObjectPattern(props)) =
                    (&d.initializer, &d.pattern)
                else {
                    continue;
                };
                if !is_require_fs_promises_module_initializer(init, binding_lookup) {
                    continue;
                }
                for prop in props {
                    if prop.computed {
                        continue;
                    }
                    let capability = match well_formed_static_name(&prop.key) {
                        Some("readFile") => "fs:read",
                        Some("writeFile") => "fs:write",
                        _ => continue,
                    };
                    if let BindingPattern::Identifier(local) = &prop.value {
                        candidates.insert(local.clone(), capability);
                    }
                }
            }
        }
    }
    candidates
        .into_iter()
        .filter(|(local, _)| body_deep_contains_fs_named_call(body, local))
        .collect()
}

/// Confirmed fs/promises *sub-object* destructures (bd-1xl17.c):
/// `const { promises } = require('fs')` (incl. `{ promises: fsp }` renames) whose
/// destructured local is used as `<local>.readFile/writeFile(...)` at a top-level
/// program position. Returns the set of local names, each recorded as an
/// fs/promises *module-alias* sentinel so the existing member-call recognizer
/// ([`fs_promises_builtin_call_capability`]) handles the call sites unchanged.
/// Only the `promises` property is matched — sibling sync names destructured off
/// `require('fs')` are outside bd-1xl17.c and keep their current behavior. Usage-
/// gated like the simple-id require-binding form.
pub(super) fn confirmed_fs_promises_subobject_destructures(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            for d in &vd.declarations {
                let (Some(init), BindingPattern::ObjectPattern(props)) =
                    (&d.initializer, &d.pattern)
                else {
                    continue;
                };
                if !is_require_fs_module_initializer(init, binding_lookup) {
                    continue;
                }
                for prop in props {
                    if prop.computed {
                        continue;
                    }
                    let key_is_promises =
                        well_formed_static_name(&prop.key).is_some_and(|name| name == "promises");
                    if !key_is_promises {
                        continue;
                    }
                    if let BindingPattern::Identifier(local) = &prop.value {
                        candidates.insert(local.clone());
                    }
                }
            }
        }
    }
    if candidates.is_empty() {
        return candidates;
    }
    let mut used = BTreeSet::new();
    for name in &candidates {
        let single: BTreeSet<String> = std::iter::once(name.clone()).collect();
        if body.iter().any(|stmt| {
            timers_scan_statement_deep(stmt, &|candidate| {
                matches!(candidate,
                    Expression::Call { callee, .. } | Expression::OptionalCall { callee, .. }
                        if is_fs_promises_alias_method_callee(callee, &single))
            })
        }) {
            used.insert(name.clone());
        }
    }
    used
}

/// If `pattern`/`init` form a confirmed *destructured* fs/promises require
/// declaration, return the simple-identifier local names that should be bound to
/// `undefined` (eliding the faulting `require(...)` load and the property
/// extraction; there is no real fs module object to destructure). Two shapes
/// (bd-1xl17.c), gated on at least one local having been confirmed at the program
/// pre-scan:
///   * `const { readFile } = require('fs/promises')` — locals recorded as
///     fs/promises named-import sentinels (direct-call recognizer).
///   * `const { promises } = require('fs')` — the `promises` local recorded as an
///     fs/promises module-alias sentinel (member-call recognizer).
///
/// Returns `None` for any non-plain pattern (rest/nested/computed targets) or
/// when no local is confirmed, leaving the existing ambient-denial path intact —
/// the destructure analogue of the simple-id elision's usage gating. Unconfirmed
/// sibling locals in a confirmed declaration are still bound to `undefined`
/// (fail-closed: invoking one faults, exactly as the elided `require` would have),
/// mirroring the ESM named-import elision.
pub(super) fn confirmed_fs_promises_destructure_locals(
    pattern: &BindingPattern,
    init: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<Vec<String>> {
    let BindingPattern::ObjectPattern(props) = pattern else {
        return None;
    };
    let from_fs_promises = is_require_fs_promises_module_initializer(init, binding_lookup);
    let from_fs = !from_fs_promises && is_require_fs_module_initializer(init, binding_lookup);
    if !from_fs_promises && !from_fs {
        return None;
    }
    let mut locals = Vec::new();
    let mut any_confirmed = false;
    for prop in props {
        // Only plain `{ name }` / `{ key: local }` props participate; bail on
        // rest/nested/computed targets so unusual shapes keep their current path.
        if prop.computed {
            return None;
        }
        let BindingPattern::Identifier(local) = &prop.value else {
            return None;
        };
        let confirmed = if from_fs_promises {
            binding_lookup.contains_key(&fs_promises_named_import_sentinel(local, "fs:read"))
                || binding_lookup
                    .contains_key(&fs_promises_named_import_sentinel(local, "fs:write"))
        } else {
            binding_lookup.contains_key(&fs_promises_module_alias_sentinel(local))
        };
        any_confirmed |= confirmed;
        locals.push(local.clone());
    }
    any_confirmed.then_some(locals)
}

/// Capability for a `new Proxy(target, handler)` constructor (bd-v93ds). Like the
/// collection/error constructors, the bare `Proxy` global has no binding on
/// the eval scope, so route the bare-identifier callee to the `builtin:Proxy`
/// constructor hostcall (which allocates the proxy object; member access then
/// flows through the already-wired `proxy_aware_*` runtime seam). Returns `None`
/// when shadowed by a user binding in scope.
pub(super) fn proxy_constructor_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Identifier(name) = callee else {
        return None;
    };
    if is_lexically_shadowed(binding_lookup, name) {
        return None;
    }
    match name.as_str() {
        "Proxy" => Some("builtin:Proxy"),
        _ => None,
    }
}

/// Capability for a `Reflect.<method>(...)` static member call (bd-v93ds).
/// The `Reflect` global has no eval-scope binding, so recognize the member
/// callee and route to the matching `builtin:Reflect*` hostcall (whose
/// implementations already exist in `dispatch_builtin_hostcall_inner`). Returns
/// `None` when `Reflect` is shadowed by a user binding in scope.
pub(super) fn reflect_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed,
        ..
    } = callee
    else {
        return None;
    };
    if !matches!(object.as_ref(), Expression::Identifier(name) if name == "Reflect")
        || is_lexically_shadowed(binding_lookup, "Reflect")
    {
        return None;
    }
    let method = match *computed {
        false => well_formed_static_name(property)?,
        true => well_formed_string_literal(property)?,
    };
    reflect_member_capability(method)
}

/// The native hostcall behind `Reflect.<member>`, shared by the direct-call
/// interception above and the first-class `Reflect` object.
pub(crate) fn reflect_member_capability(member: &str) -> Option<&'static str> {
    match member {
        "has" => Some("builtin:ReflectHas"),
        "get" => Some("builtin:ReflectGet"),
        "set" => Some("builtin:ReflectSet"),
        "deleteProperty" => Some("builtin:ReflectDeleteProperty"),
        "apply" => Some("builtin:ReflectApply"),
        "construct" => Some("builtin:ReflectConstruct"),
        "ownKeys" => Some("builtin:ReflectOwnKeys"),
        "getPrototypeOf" => Some("builtin:ReflectGetPrototypeOf"),
        "setPrototypeOf" => Some("builtin:ReflectSetPrototypeOf"),
        "isExtensible" => Some("builtin:ReflectIsExtensible"),
        "preventExtensions" => Some("builtin:ReflectPreventExtensions"),
        "defineProperty" => Some("builtin:ReflectDefineProperty"),
        "getOwnPropertyDescriptor" => Some("builtin:ReflectGetOwnPropertyDescriptor"),
        _ => None,
    }
}

/// The member name of an unshadowed `process.<name>` / `process["<name>"]`
/// reference. A source binding named `process` in scope or a computed
/// non-literal key yields `None`, so the recognizers below only ever match the
/// global. Like the process-shape read path (bd-y30zw), only a *source*
/// binding shadows: the plain name entry that path installs for the injected
/// receiver must not hide `process.exit` after a `process.argv` read.
pub(super) fn unshadowed_process_member<'a>(
    expression: &'a Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'a str> {
    let Expression::Member {
        object,
        property,
        computed,
        ..
    } = expression
    else {
        return None;
    };
    if !matches!(object.as_ref(), Expression::Identifier(name) if name == "process")
        || has_source_lexical_binding(binding_lookup, "process")
    {
        return None;
    }
    if *computed {
        return None;
    }
    well_formed_static_name(property)
}

/// Capability for a statically recognized `process` method call: the exact
/// unshadowed `process.nextTick(...)` (bd-8nrud) and `process.exit(...)`
/// (bd-my9hk) shapes route to dedicated hostcalls. Any other `process` member
/// falls through to the ordinary lowering and its ambient-authority denial, so
/// raw process authority is never exposed: the recognizer grants next-tick
/// scheduling and ending the program itself, nothing else.
pub(super) fn process_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    match unshadowed_process_member(callee, binding_lookup)? {
        "nextTick" => Some("builtin:ProcessNextTick"),
        "exit" => Some("builtin:ProcessExit"),
        _ => None,
    }
}

/// `process.nextTick` read as a value (bd-9vouw.186): the engine's next-tick
/// scheduler as a first-class function, the same hostcall the call shape
/// lowers to. Libraries probe and keep it (`typeof process.nextTick ===
/// 'function'`, `defer = process.nextTick`); a module holding such a read was
/// refused whole as an `env.read`. It grants scheduling only.
pub(crate) const PROCESS_NEXT_TICK_VALUE_CAPABILITY: &str =
    "builtin:static-value:builtin:ProcessNextTick";

pub(super) fn is_process_next_tick_read(
    expression: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    unshadowed_process_member(expression, binding_lookup) == Some("nextTick")
}

/// `eval` read as a value (bd-9vouw.191): an inert function named `eval`
/// whose every call throws EvalError, so a module that only keeps the
/// intrinsic (get-intrinsic's `'%eval%': eval`, under qs, call-bind and
/// side-channel) lowers instead of being refused whole as `runtime.eval`. A
/// direct `eval(src)` keeps its ambient check; no source text is compiled
/// through either form.
pub(crate) const EVAL_VALUE_CAPABILITY: &str = "builtin:static-value:builtin:Eval";

/// A tagged template's `%TemplateObject(site, [cooked...], [raw...])`
/// (crate::parser::TEMPLATE_OBJECT_INTRINSIC): the call site's one frozen
/// template object (ES2020 12.2.9.3, bd-9vouw.343). Pure: it builds or
/// returns an array of the literal strings.
pub(crate) const TEMPLATE_OBJECT_CAPABILITY: &str = "builtin:TemplateObject";

pub(super) fn is_eval_value_read(
    expression: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    matches!(expression, Expression::Identifier(name)
        if name == "eval" && !has_source_lexical_binding(binding_lookup, name))
}

/// Whether an assignment target is the unshadowed `process.exitCode`
/// (bd-my9hk), which lowers to `builtin:ProcessSetExitCode` instead of a
/// property store on the (never lowered) raw `process` object.
pub(super) fn is_process_exit_code_target(
    target: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    unshadowed_process_member(target, binding_lookup) == Some("exitCode")
}

/// Capability tag for a recognized timer-global name (bd-1lw7r.13, extended
/// for the Node-compat timers breadth under bd-suwvw). Single source of truth
/// shared by the bare-call recognizer, the `require('timers')` member-call
/// recognizer, and the usage-lookahead alias scan.
pub(super) fn timer_global_capability(name: &str) -> Option<&'static str> {
    match name {
        "setTimeout" => Some("builtin:SetTimeout"),
        "setInterval" => Some("builtin:SetInterval"),
        "clearTimeout" => Some("builtin:ClearTimeout"),
        "clearInterval" => Some("builtin:ClearInterval"),
        "setImmediate" => Some("builtin:SetImmediate"),
        "clearImmediate" => Some("builtin:ClearImmediate"),
        "queueMicrotask" => Some("builtin:QueueMicrotask"),
        _ => None,
    }
}

/// bd-suwvw: the exports of `require('timers')` (`node:timers`), each mapped
/// to the like-named global. Note the Node timers module does NOT export
/// `queueMicrotask` (that is only a global), so it is absent here.
pub(super) fn timers_module_export_global(name: &str) -> Option<&'static str> {
    match name {
        "setTimeout" => Some("setTimeout"),
        "setInterval" => Some("setInterval"),
        "clearTimeout" => Some("clearTimeout"),
        "clearInterval" => Some("clearInterval"),
        "setImmediate" => Some("setImmediate"),
        "clearImmediate" => Some("clearImmediate"),
        _ => None,
    }
}

/// Capability for a bare global timer-builtin call (`setTimeout(fn, ms)` etc.)
/// or a member call on the timers module (`require('timers').setTimeout(...)`
/// / a confirmed `const timers = require('timers')` alias — bd-suwvw).
///
/// Unlike member-call string/array builtins, the globals are invoked as bare
/// identifiers rather than member access, so they are not recognized by the
/// member-callee capability helpers. Returns `None` when the identifier is
/// shadowed by a user binding in scope (e.g. `let setTimeout = …`), so a
/// local `setTimeout` is never reinterpreted as the host builtin (bd-1lw7r.13).
/// (A shadowed-but-injected global still works through the first-class
/// `BuiltinFunction` value path at runtime.)
pub(super) fn timer_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    match callee {
        Expression::Identifier(name) => {
            if is_lexically_shadowed(binding_lookup, name) {
                return None;
            }
            timer_global_capability(name)
        }
        Expression::Member {
            object,
            property,
            computed: false,
            ..
        } => {
            // bd-suwvw: `timers.setTimeout(...)` on a confirmed timers-module
            // alias (or an inline `require('timers')` receiver) lowers to the
            // SAME builtin hostcall as the bare global, so the module and
            // global forms share one timer machinery.
            if !is_timers_module_object(object, binding_lookup) {
                return None;
            }
            let method = well_formed_static_name(property)?;
            timers_module_export_global(method).and_then(timer_global_capability)
        }
        _ => None,
    }
}

/// Capability for a bare global function-builtin call (`parseInt("42")`,
/// `parseFloat("3.5")`, `isNaN(x)`, `isFinite(x)`, `String(value)`). These
/// standard globals have no binding on the eval scope, so — like the
/// timer/error interceptions — recognize the bare identifier callee and
/// route to the canonical `builtin:<name>` hostcall. Returns `None` when the
/// name is shadowed by a user binding in scope, so a local declaration is never
/// reinterpreted as the host builtin (bd-n5lhl, bd-wgezf).
pub(super) fn global_function_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Identifier(name) = callee else {
        return None;
    };
    if is_lexically_shadowed(binding_lookup, name) {
        return None;
    }
    global_function_capability(name.as_str())
}

/// bd-9vouw.17: prefix of the pure factory hostcall that materializes a static
/// builtin read as a value (`const keys = Object.keys`, `arr.map(parseInt)`).
/// Lowering emits it instead of a bare member/name read, so the module's
/// declared authority footprint names the Builtin-class authority the value
/// will exercise exactly as a direct call would; the runtime call of the value
/// then passes the ordinary hostcall capability gate.
pub(crate) const STATIC_VALUE_CAPABILITY_PREFIX: &str = "builtin:static-value:";

/// These standard constructors and namespace objects have real runtime
/// bindings and mutable static properties. Source member operations must
/// resolve their live properties; internal native HostCalls stay explicit.
pub(super) fn has_mutable_static_builtins(name: &str) -> bool {
    matches!(
        name,
        "Object"
            | "Array"
            | "String"
            | "Number"
            | "JSON"
            | "Reflect"
            | "Symbol"
            | "Proxy"
            | "Map"
            | "ArrayBuffer"
    )
}

pub(super) fn is_mutable_static_builtin_receiver(
    object: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    matches!(object, Expression::Identifier(name)
        if has_mutable_static_builtins(name) && !is_lexically_shadowed(binding_lookup, name))
}

/// Bare global functions that read as first-class values.
pub(crate) const GLOBAL_FUNCTION_VALUE_NAMES: [&str; 13] = [
    "parseInt",
    "parseFloat",
    "isNaN",
    "isFinite",
    "btoa",
    "atob",
    "escape",
    "unescape",
    "encodeURIComponent",
    "decodeURIComponent",
    "encodeURI",
    "decodeURI",
    "structuredClone",
];

pub(super) fn static_member_value_capability(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<String> {
    let Expression::Identifier(global) = object else {
        return None;
    };
    if is_lexically_shadowed(binding_lookup, global) {
        return None;
    }
    let property_name = match computed {
        false => well_formed_static_name(property)?,
        true => well_formed_string_literal(property)?,
    };
    slot0_static_member_capability(global, property_name)
        .map(|tag| format!("{STATIC_VALUE_CAPABILITY_PREFIX}{tag}"))
}

/// `JSON` read as a value (`const J = JSON; J.stringify(v)`): the factory
/// yields the realm's `JSON` binding and declares the Builtin authority its
/// methods exercise.
pub(crate) const JSON_VALUE_CAPABILITY: &str = "builtin:static-value:JSON";

pub(super) fn global_function_value_capability(name: &str) -> Option<String> {
    if name == "JSON" {
        return Some(JSON_VALUE_CAPABILITY.to_string());
    }
    if !GLOBAL_FUNCTION_VALUE_NAMES.contains(&name) {
        return None;
    }
    global_function_capability(name).map(|tag| format!("{STATIC_VALUE_CAPABILITY_PREFIX}{tag}"))
}

/// Bare global functions dispatched as slot-0 `builtin:*` hostcalls. Shared by
/// call-site interception above and by the runtime's first-class global
/// function values (bd-9vouw.17).
pub(crate) fn global_function_capability(name: &str) -> Option<&'static str> {
    match name {
        "parseInt" => Some("builtin:parseInt"),
        "parseFloat" => Some("builtin:parseFloat"),
        "isNaN" => Some("builtin:isNaN"),
        "isFinite" => Some("builtin:isFinite"),
        // `String([value])` is the standard callable conversion intrinsic. It
        // is distinct from `new String` (boxed strings, still deferred) and
        // from the static `String.*` member surface (bd-wgezf).
        "String" => Some("builtin:String"),
        // `Symbol([description])` — the bare `Symbol` global has no eval-scope
        // binding, so route the call to the existing `builtin:Symbol` hostcall
        // (which allocates a fresh, unique `__type:"symbol"` value; `typeof` of it
        // already yields "symbol"). Member forms `Symbol.iterator`
        // (`well_known_symbol_member`) and `Symbol.for` (a registry, bd-bn1z7
        // follow-up) are handled elsewhere; this is the bare constructor call.
        // Slot-0 description argument, no receiver — same convention as the other
        // global function builtins above (bd-bn1z7).
        "Symbol" => Some("builtin:Symbol"),
        // `Number(value)` coercion function — the bare `Number` global has no
        // eval-scope binding (only the `Number.is*`/`Number.parse*` static
        // members were wired). Route the bare call to the existing `builtin:Number`
        // coercion hostcall (`Number("42")`===42, `Number(true)`===1). Slot-0
        // value argument, no receiver (bd-1trl5).
        "Number" => Some("builtin:Number"),
        "Boolean" => Some("builtin:Boolean"),
        // bd-9vouw.96: the HTML Standard's base64 pair (Node globals) and
        // ES2020 B.2.1's escape/unescape.
        "btoa" => Some("builtin:Btoa"),
        "atob" => Some("builtin:Atob"),
        "escape" => Some("builtin:Escape"),
        "unescape" => Some("builtin:Unescape"),
        // The URI codecs: direct calls and first-class values
        // (`options.decode || decodeURIComponent`, path-to-regexp).
        "encodeURIComponent" => Some("builtin:EncodeURIComponent"),
        "decodeURIComponent" => Some("builtin:DecodeURIComponent"),
        "encodeURI" => Some("builtin:EncodeURI"),
        "decodeURI" => Some("builtin:DecodeURI"),
        // bd-9vouw.96: HTML structuredClone (a Node global).
        "structuredClone" => Some("builtin:StructuredClone"),
        _ => None,
    }
}

/// Recognize the one supported first-class static builtin member read.
///
/// The engine intentionally has no materialized `Array` global object, so an
/// unshadowed `Array.isArray` value read needs a dedicated pure factory
/// hostcall. Keep this allowlist separate from direct-call interception:
/// widening arbitrary capability-backed functions into guest-callable values
/// would bypass the normal hostcall authority boundary.
pub(super) fn static_builtin_member_factory_capability(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Identifier(global) = object else {
        return None;
    };
    if is_lexically_shadowed(binding_lookup, global) {
        return None;
    }
    let property_name = match computed {
        false => well_formed_static_name(property)?,
        true => well_formed_string_literal(property)?,
    };
    match (global.as_str(), property_name) {
        ("Array", "isArray") => Some("builtin:ArrayIsArrayFunction"),
        _ => None,
    }
}

/// Recognize calls to the standard `Object.*` / `JSON.*` / `Array.*` / `String.*`
/// STATIC methods whose receiver is the bare (unbound) global identifier. These
/// globals have no binding on the eval scope, so — like the timer/Number/
/// global-function interceptions — route the recognized member call to the
/// canonical `builtin:*` hostcall whose impl already exists in
/// `dispatch_builtin_hostcall_inner` (bd-9a8cz.2 seeded Object/JSON; bd-tvpjk
/// added the remaining Object statics + Array/String statics whose handlers were
/// present but unwired). Returns `None` when the global is shadowed by a user
/// binding (so `let JSON = …` is honored) or the property is not a supported
/// static method. Instance/prototype methods (e.g. `obj.hasOwnProperty`) are NOT
/// handled here — those go through the receiver-aware member-access seam.
pub(super) fn object_json_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed,
        ..
    } = callee
    else {
        return None;
    };
    let Expression::Identifier(global) = object.as_ref() else {
        return None;
    };
    if is_lexically_shadowed(binding_lookup, global) {
        return None;
    }
    let property_name = match *computed {
        false => well_formed_static_name(property)?,
        true => well_formed_string_literal(property)?,
    };
    slot0_static_member_capability(global.as_str(), property_name)
}

/// The slot-0 static builtin table: `(global, member)` -> the `builtin:*`
/// hostcall whose handler reads its arguments from slot 0 with no receiver
/// placeholder. Shared by call-site interception above and by the runtime's
/// first-class standard-constructor values (bd-9vouw.17), so a static read as
/// a value (`const keys = Object.keys`) dispatches exactly the hostcall a
/// direct call would.
pub(crate) fn slot0_static_member_capability(global: &str, member: &str) -> Option<&'static str> {
    match (global, member) {
        ("Object", "keys") => Some("builtin:ObjectKeys"),
        ("Object", "values") => Some("builtin:ObjectValues"),
        ("Object", "entries") => Some("builtin:ObjectEntries"),
        // Additional `Object.*` statics whose execution handlers + id-registry
        // entries already exist in `dispatch_builtin_hostcall_inner` but were
        // never wired into this lowering interception (bd-tvpjk). All read their
        // arguments from slot 0 with no receiver placeholder, the same
        // convention as `Object.keys`.
        ("Object", "assign") => Some("builtin:ObjectAssign"),
        ("Object", "freeze") => Some("builtin:ObjectFreeze"),
        ("Object", "isFrozen") => Some("builtin:ObjectIsFrozen"),
        ("Object", "create") => Some("builtin:ObjectCreate"),
        ("Object", "getPrototypeOf") => Some("builtin:ObjectGetPrototypeOf"),
        ("Object", "setPrototypeOf") => Some("builtin:ObjectSetPrototypeOf"),
        ("Object", "defineProperty") => Some("builtin:ObjectDefineProperty"),
        ("Object", "defineProperties") => Some("builtin:ObjectDefineProperties"),
        ("Object", "getOwnPropertyNames") => Some("builtin:ObjectGetOwnPropertyNames"),
        ("Object", "getOwnPropertySymbols") => Some("builtin:ObjectGetOwnPropertySymbols"),
        ("Object", "getOwnPropertyDescriptor") => Some("builtin:ObjectGetOwnPropertyDescriptor"),
        ("Object", "getOwnPropertyDescriptors") => Some("builtin:ObjectGetOwnPropertyDescriptors"),
        ("Object", "fromEntries") => Some("builtin:ObjectFromEntries"),
        // ES2024 grouping (bd-9vouw.95): items, callback in slots 0 and 1.
        ("Object", "groupBy") => Some("builtin:ObjectGroupBy"),
        // ES2022 Object.hasOwn(object, key): slots 0 and 1.
        ("Object", "hasOwn") => Some("builtin:ObjectHasOwn"),
        ("Map", "groupBy") => Some("builtin:MapGroupBy"),
        ("ArrayBuffer", "isView") => Some("builtin:ArrayBufferIsView"),
        // Node's Buffer statics read as values off the global constructor
        // (bd-9vouw.104); direct calls keep buffer_static_builtin_call_capability,
        // which maps to the same builtins.
        ("Buffer", "from") => Some("builtin:BufferFrom"),
        ("Buffer", "alloc") => Some("builtin:BufferAlloc"),
        ("Buffer", "allocUnsafe") => Some("builtin:BufferAllocUnsafe"),
        ("Buffer", "byteLength") => Some("builtin:BufferByteLength"),
        ("Buffer", "concat") => Some("builtin:BufferConcat"),
        ("Buffer", "compare") => Some("builtin:BufferCompare"),
        ("Buffer", "isBuffer") => Some("builtin:BufferIsBuffer"),
        ("Buffer", "isEncoding") => Some("builtin:BufferIsEncoding"),
        // NOTE: Object.is / Object.isExtensible use the RECEIVER-PLACEHOLDER
        // calling convention (handler reads args.start+1.., guards count<N
        // counting a slot-0 receiver) — they are wired via
        // `object_receiver_static_call_capability` below, NOT here.
        ("JSON", "parse") => Some("builtin:JsonParse"),
        ("JSON", "stringify") => Some("builtin:JsonStringify"),
        // JSON.parse source text access (Node v22, bd-9vouw.380).
        ("JSON", "rawJSON") => Some("builtin:JsonRawJson"),
        ("JSON", "isRawJSON") => Some("builtin:JsonIsRawJson"),
        // `Array.*` and `String.*` statics — same family, same slot-0 convention
        // (bd-tvpjk). `Array`/`String` globals have no eval-scope binding either.
        ("Array", "isArray") => Some("builtin:ArrayIsArray"),
        ("Array", "from") => Some("builtin:ArrayFrom"),
        // ES2024 Array.fromAsync (bd-9vouw.172): a promise of the array.
        ("Array", "fromAsync") => Some("builtin:ArrayFromAsync"),
        ("Array", "of") => Some("builtin:ArrayOf"),
        ("String", "fromCharCode") => Some("builtin:StringFromCharCode"),
        ("String", "fromCodePoint") => Some("builtin:StringFromCodePoint"),
        // `String.raw` (bd-bl591): used almost exclusively as a template tag
        // (`String.raw`x${y}z``). The tagged-template desugar (parser.rs) rewrites
        // that into `String.raw(<strings-with-.raw>, ...substitutions)`, a normal
        // `Expression::Call` whose callee is `String.raw` — so this slot-0
        // interception fires for both the tag form and direct calls. The `String`
        // global has no eval-scope binding, same as `fromCharCode`. Shadowing-safe.
        ("String", "raw") => Some("builtin:StringRaw"),
        // Symbol global registry (bd-hitj1): Symbol.for(key)/Symbol.keyFor(sym).
        ("Symbol", "for") => Some("builtin:SymbolFor"),
        ("Symbol", "keyFor") => Some("builtin:SymbolKeyFor"),
        // Like the Reflect statics, Proxy.revocable is a slot-zero native
        // factory, not an ambient global binding. The lexical-shadowing check
        // above keeps a user-defined Proxy object's method entirely ordinary.
        ("Proxy", "revocable") => Some("builtin:ProxyRevocable"),
        // Number statics read as values (`[x].filter(Number.isNaN)`, `const
        // { isInteger } = Number`); direct calls keep
        // number_static_builtin_call_capability, which is checked first.
        // Number.parseInt and Number.parseFloat are the global functions
        // (ES2020 20.1.2.12-13), so they share those tags and identities.
        ("Number", "isInteger") => Some("builtin:NumberIsInteger"),
        ("Number", "isSafeInteger") => Some("builtin:NumberIsSafeInteger"),
        ("Number", "isFinite") => Some("builtin:NumberIsFinite"),
        ("Number", "isNaN") => Some("builtin:NumberIsNaN"),
        ("Number", "parseInt") => Some("builtin:parseInt"),
        ("Number", "parseFloat") => Some("builtin:parseFloat"),
        _ => None,
    }
}

/// `Object.*` statics whose execution handlers use the RECEIVER-PLACEHOLDER
/// calling convention — they read their first meaningful argument from
/// `args.start + 1` (slot 0 is the call receiver) and guard on a count that
/// includes that receiver. Routed through the timer-style call-site that pushes
/// an `undefined` receiver placeholder, NOT the slot-0 static call-site
/// (bd-tvpjk). Kept separate from `object_json_builtin_call_capability` because
/// mixing the two conventions at one call-site silently mis-feeds arguments
/// (e.g. `Object.is(1, 1)` returned `false` when fed slot-0). Shadowing-safe.
pub(super) fn object_receiver_static_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed,
        ..
    } = callee
    else {
        return None;
    };
    let Expression::Identifier(global) = object.as_ref() else {
        return None;
    };
    if global.as_str() != "Object" || is_lexically_shadowed(binding_lookup, global) {
        return None;
    }
    let property_name = match *computed {
        false => well_formed_static_name(property)?,
        true => well_formed_string_literal(property)?,
    };
    object_receiver_static_member_capability(property_name)
}

/// The `Object.*` statics whose handlers use the receiver-placeholder
/// convention (see `object_receiver_static_call_capability`).
pub(crate) const OBJECT_RECEIVER_STATIC_MEMBERS: [&str; 5] = [
    "is",
    "isExtensible",
    "preventExtensions",
    "seal",
    "isSealed",
];

/// The hostcall of the receiver-placeholder `Object.*` static `member`.
pub(crate) fn object_receiver_static_member_capability(member: &str) -> Option<&'static str> {
    match member {
        "is" => Some("builtin:ObjectIs"),
        "isExtensible" => Some("builtin:ObjectIsExtensible"),
        "preventExtensions" => Some("builtin:ObjectPreventExtensions"),
        "seal" => Some("builtin:ObjectSeal"),
        "isSealed" => Some("builtin:ObjectIsSealed"),
        _ => None,
    }
}

/// Recognize calls to the standard `Number.*` STATIC methods whose receiver is
/// the bare (unbound) global identifier `Number` — `Number.isInteger(x)`,
/// `Number.isFinite(x)`, `Number.isNaN(x)`, `Number.parseInt(s)`,
/// `Number.parseFloat(s)`. Like `Object`/`JSON`, the `Number` global has
/// no binding on the eval scope, so the member-call must be recognized here and
/// routed to the canonical `builtin:Number*` hostcall whose impl already exists
/// in `dispatch_builtin_hostcall_inner` (bd-6kkg6 — execution + id-registry were
/// already present; only this lowering interception was missing). Returns `None`
/// when `Number` is shadowed by a user binding (so `let Number = …` is honored),
/// when the receiver is computed in a way we can't statically resolve, or when
/// the property is not a supported static method (instance/prototype methods like
/// `n.toFixed` are handled by the receiver-aware member-access seam, not here).
pub(super) fn number_static_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed,
        ..
    } = callee
    else {
        return None;
    };
    let Expression::Identifier(global) = object.as_ref() else {
        return None;
    };
    if global.as_str() != "Number" || is_lexically_shadowed(binding_lookup, global) {
        return None;
    }
    let property_name = match *computed {
        false => well_formed_static_name(property)?,
        true => well_formed_string_literal(property)?,
    };
    match property_name {
        "isInteger" => Some("builtin:NumberIsInteger"),
        "isSafeInteger" => Some("builtin:NumberIsSafeInteger"),
        "isFinite" => Some("builtin:NumberIsFinite"),
        "isNaN" => Some("builtin:NumberIsNaN"),
        "parseInt" => Some("builtin:NumberParseInt"),
        "parseFloat" => Some("builtin:NumberParseFloat"),
        _ => None,
    }
}

/// Recognize the core Node-compatible `Buffer.*` static calls used by the
/// compatibility corpus. Buffer values reuse the interpreter's Uint8Array
/// substrate, but the global itself is intentionally not materialized: an
/// unshadowed, statically named member call lowers directly to a pure-compute
/// builtin. A lexical `Buffer` binding always wins, and dynamic property names
/// remain ordinary JavaScript member calls (bd-ys3f4).
pub(super) fn buffer_static_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed,
        ..
    } = callee
    else {
        return None;
    };
    let Expression::Identifier(global) = object.as_ref() else {
        return None;
    };
    if global.as_str() != "Buffer" || is_lexically_shadowed(binding_lookup, global) {
        return None;
    }
    let property_name = match *computed {
        false => well_formed_static_name(property)?,
        true => well_formed_string_literal(property)?,
    };
    match property_name {
        "from" => Some("builtin:BufferFrom"),
        "alloc" => Some("builtin:BufferAlloc"),
        "allocUnsafe" => Some("builtin:BufferAllocUnsafe"),
        "byteLength" => Some("builtin:BufferByteLength"),
        "concat" => Some("builtin:BufferConcat"),
        "compare" => Some("builtin:BufferCompare"),
        "isBuffer" => Some("builtin:BufferIsBuffer"),
        "isEncoding" => Some("builtin:BufferIsEncoding"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Authenticated Node Buffer instance observations (bd-nx5cb)
// ---------------------------------------------------------------------------

pub(super) fn buffer_object_alias_sentinel(name: &str) -> String {
    format!("\0bufferobj\0{name}")
}

pub(super) fn buffer_object_method_capability(method: &str) -> Option<&'static str> {
    match method {
        "toString" => Some("builtin:BufferObjectToString"),
        "readUInt32LE" => Some("builtin:BufferObjectReadUInt32LE"),
        "equals" => Some("builtin:BufferObjectEquals"),
        _ => None,
    }
}

pub(super) fn buffer_object_argument_is_static_primitive(expression: &Expression) -> bool {
    matches!(
        expression,
        Expression::StringLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::FloatLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral
            | Expression::UndefinedLiteral
    )
}

pub(super) fn buffer_factory_expression_is_authenticated(
    expression: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Call {
        callee, arguments, ..
    } = expression
    else {
        return false;
    };
    if !arguments
        .iter()
        .all(buffer_object_argument_is_static_primitive)
    {
        return false;
    }
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee.as_ref()
    else {
        return false;
    };
    matches!(object.as_ref(), Expression::Identifier(global)
        if global == "Buffer" && !is_lexically_shadowed(binding_lookup, global))
        && matches!(well_formed_static_name(property), Some("from" | "alloc"))
}

pub(super) fn buffer_object_expression_is_authenticated(
    expression: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    buffer_factory_expression_is_authenticated(expression, binding_lookup)
        || matches!(expression, Expression::Identifier(alias)
            if binding_lookup.contains_key(&buffer_object_alias_sentinel(alias)))
}

pub(super) fn buffer_object_builtin_call_capability(
    callee: &Expression,
    arguments: &[Expression],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    if !arguments
        .iter()
        .all(buffer_object_argument_is_static_primitive)
    {
        return None;
    }
    let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = callee
    else {
        return None;
    };
    if !buffer_object_expression_is_authenticated(object, binding_lookup) {
        return None;
    }
    buffer_object_method_capability(well_formed_static_name(property)?)
}

pub(super) fn is_buffer_object_alias_usage(expr: &Expression, alias: &str) -> bool {
    matches!(
        expr,
        Expression::Call {
            callee,
            arguments,
            ..
        } if module_alias_member_name(callee, alias)
            .and_then(buffer_object_method_capability)
            .is_some()
            && arguments
                .iter()
                .all(buffer_object_argument_is_static_primitive)
    )
}

pub(super) fn confirmed_buffer_object_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeMap::new();
    for (statement_index, statement) in body.iter().enumerate() {
        let Statement::VariableDeclaration(declaration) = statement else {
            continue;
        };
        if declaration.kind != VariableDeclarationKind::Const {
            continue;
        }
        for (declarator_index, declarator) in declaration.declarations.iter().enumerate() {
            let (BindingPattern::Identifier(alias), Some(initializer)) =
                (&declarator.pattern, &declarator.initializer)
            else {
                continue;
            };
            if buffer_factory_expression_is_authenticated(initializer, binding_lookup)
                && !module_alias_expr_has_rejected_use(
                    initializer,
                    alias,
                    LoweringOnlyModuleAliasSurface::BufferObject,
                )
            {
                candidates.insert(alias.clone(), (statement_index, declarator_index));
            }
        }
    }

    candidates
        .into_iter()
        .filter(|(alias, (statement_index, declarator_index))| {
            let surface = LoweringOnlyModuleAliasSurface::BufferObject;
            !module_alias_has_predeclaration_hazard(
                body,
                *statement_index,
                *declarator_index,
                alias,
                surface,
                binding_lookup,
            ) && body.iter().any(|statement| {
                module_alias_statement_contains_unshadowed_usage(statement, alias, surface)
            }) && !crypto_object_alias_has_rejected_use(
                body,
                alias,
                surface,
                binding_lookup,
                &mut BTreeSet::new(),
            )
        })
        .map(|(alias, _)| alias)
        .collect()
}

pub(super) fn array_literal_builtin_call_capability(callee: &Expression) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed,
        ..
    } = callee
    else {
        return None;
    };
    if *computed || !matches!(object.as_ref(), Expression::ArrayLiteral(_)) {
        return None;
    }
    well_formed_static_name(property)
        .is_some_and(|name| name == "some")
        .then_some("builtin:ArrayPrototypeSome")
}

pub(super) fn string_literal_builtin_call_capability(callee: &Expression) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed,
        ..
    } = callee
    else {
        return None;
    };
    if *computed || !matches!(object.as_ref(), Expression::StringLiteral(_)) {
        return None;
    }
    well_formed_static_name(property)
        .is_some_and(|name| name == "charAt")
        .then_some("builtin:StringPrototypeCharAt")
}

#[allow(clippy::too_many_arguments)]
pub(super) fn lower_member_property_key_to_ir1(
    property: &Expression,
    computed: bool,
    ops: &mut Vec<Ir1Op>,
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    root_scope_id: ScopeId,
    label_counter: &mut u32,
    span_table: &mut Vec<Ir1OpSpanEntry>,
) -> Result<Ir1PropertyKey, LoweringPipelineError> {
    if computed {
        lower_expression_to_ir1(
            property,
            ops,
            bindings,
            binding_lookup,
            binding_index,
            root_scope_id,
            label_counter,
            span_table,
        )?;
        return Ok(Ir1PropertyKey::Dynamic);
    }

    let key = match property {
        Expression::Identifier(name) => name.clone().into(),
        Expression::StringLiteral(value) => value.clone(),
        Expression::NumericLiteral(value) => value.to_string().into(),
        Expression::BigIntLiteral(value) => value.clone().into(),
        _ => "unknown".into(),
    };
    Ok(Ir1PropertyKey::Static(key))
}

/// Include authority exercised by a directly invoked, zero-argument function
/// expression. The adjacent stack operations prove the callee's identity;
/// aliases, property lookups and other indirect calls need separate summaries.
/// Calling a generator only creates an iterator and does not execute its body.
/// Use an explicit work list so deeply nested factories do not recurse here.
pub(super) fn collect_immediately_invoked_capabilities(
    ops: &[Ir1Op],
    required: &mut BTreeSet<String>,
) {
    let mut pending = vec![ops];
    while let Some(ops) = pending.pop() {
        for pair in ops.windows(2) {
            let [
                Ir1Op::CreateFunction {
                    body_ops,
                    is_generator: false,
                    ..
                },
                Ir1Op::Call { arg_count: 0 },
            ] = pair
            else {
                continue;
            };
            for op in body_ops {
                if let (_, Some(capability), _) = classify_ir1_op(op) {
                    required.insert(capability.0);
                }
            }
            pending.push(body_ops);
        }
    }
}

/// The native module rewriter binds only reserved, engine-owned names to
/// `(function (initialize) { ... return cachedLoader; })(initializerThunk)`.
/// Read the actual thunk rather than hard-coding a module's capability list.
/// Creating the cache does not initialize a module; only a call to its private
/// binding exercises these capabilities. Ordinary guest functions/aliases are
/// not claimed by this bounded summary.
pub(super) fn collect_native_module_initializer_capabilities(
    ir1: &Ir1Module,
    required: &mut BTreeSet<String>,
) {
    let native_bindings: BTreeSet<BindingId> = ir1
        .scopes
        .iter()
        .flat_map(|scope| &scope.bindings)
        .filter(|binding| util_module::is_module_binding(&binding.name))
        .map(|binding| binding.binding_id)
        .collect();
    let mut initializers = BTreeMap::new();
    for window in ir1.ops.windows(4) {
        let [
            Ir1Op::CreateFunction { .. },
            Ir1Op::CreateFunction {
                body_ops,
                is_generator: false,
                ..
            },
            Ir1Op::Call { arg_count: 1 },
            Ir1Op::StoreBinding { binding_id } | Ir1Op::InitializeBinding { binding_id },
        ] = window
        else {
            continue;
        };
        if native_bindings.contains(binding_id) {
            initializers.insert(*binding_id, body_ops.as_slice());
        }
    }
    for window in ir1.ops.windows(2) {
        let [
            Ir1Op::LoadBinding { binding_id },
            Ir1Op::Call { arg_count: 0 },
        ] = window
        else {
            continue;
        };
        if let Some(body) = initializers.remove(binding_id) {
            for op in body {
                if let (_, Some(capability), _) = classify_ir1_op(op) {
                    required.insert(capability.0);
                }
            }
            collect_immediately_invoked_capabilities(body, required);
        }
    }
}

pub(super) fn classify_ir1_op(
    op: &Ir1Op,
) -> (
    EffectBoundary,
    Option<CapabilityTag>,
    Option<FlowAnnotation>,
) {
    match op {
        Ir1Op::LoadName { name, .. } => {
            // Match the IR3/runtime authority for first-class realm values.
            // Lexically shadowed names use LoadBinding and cannot acquire this
            // authority merely by being spelled Object or a timer.
            let capability = timer_global_capability(name)
                .map(|_| CapabilityTag("timer".to_string()))
                .or_else(|| {
                    has_mutable_static_builtins(name).then(|| CapabilityTag("builtin".to_string()))
                });
            (EffectBoundary::ReadEffect, capability, None)
        }
        Ir1Op::ResolveNameStatus { .. } => (EffectBoundary::ReadEffect, None, None),
        Ir1Op::PutName { .. } | Ir1Op::PutNameWithStatus { .. } => {
            (EffectBoundary::WriteEffect, None, None)
        }
        Ir1Op::ImportModule { .. } => (
            EffectBoundary::ReadEffect,
            Some(CapabilityTag("module.import".to_string())),
            Some(FlowAnnotation {
                data_label: Label::Internal,
                sink_clearance: Label::Internal,
                declassification_required: false,
            }),
        ),
        Ir1Op::HostCall { capability, .. } => (
            EffectBoundary::HostcallEffect,
            Some(CapabilityTag(capability.clone())),
            Some(FlowAnnotation {
                data_label: Label::Confidential,
                sink_clearance: Label::Confidential,
                declassification_required: false,
            }),
        ),
        Ir1Op::Call { .. } | Ir1Op::CallMethod { .. } => (
            // User-defined function calls are pure; they must reach the
            // regular Ir1Op::Call → Ir3Instruction::Call lowering path
            // so the interpreter can set up a call frame and execute the
            // function body.  Hostcall-grade IFC gating, when required,
            // should be emitted as a separate guard instruction rather
            // than hijacking the call itself.
            EffectBoundary::Pure,
            None,
            None,
        ),
        Ir1Op::Await => (
            EffectBoundary::ReadEffect,
            None,
            Some(FlowAnnotation {
                data_label: Label::Internal,
                sink_clearance: Label::Internal,
                declassification_required: false,
            }),
        ),
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String(raw),
        } => {
            if let Some(capability) = extract_hostcall_capability(raw) {
                return (
                    EffectBoundary::HostcallEffect,
                    Some(CapabilityTag(capability)),
                    Some(FlowAnnotation {
                        data_label: Label::Confidential,
                        sink_clearance: Label::Confidential,
                        declassification_required: false,
                    }),
                );
            }
            (EffectBoundary::Pure, None, None)
        }
        Ir1Op::Throw
        | Ir1Op::BeginTry { .. }
        | Ir1Op::EndTry
        | Ir1Op::EnterFinally
        | Ir1Op::EndFinally
        | Ir1Op::DiscardAbruptCompletion => (
            EffectBoundary::ReadEffect,
            None,
            Some(FlowAnnotation {
                data_label: Label::Internal,
                sink_clearance: Label::Internal,
                declassification_required: false,
            }),
        ),
        // A property READ observes a value; it is not an information sink. Its
        // result already carries the receiver's label (join, in
        // simulate_ir2_flow_labels) so any real egress downstream still checks
        // it -- exactly like an ordinary Call (also Pure) whose getter body is
        // checked separately. Classifying it as a ReadEffect gave it an Internal
        // sink clearance, which wrongly DENIED the single most common error
        // idiom `catch (e) { e.message }`: the caught exception carries the
        // fail-high TopSecret user-Call exception label, and reading a property
        // off it tripped a TopSecret -> Internal egress denial even though
        // nothing leaves the program (bd-az056).
        Ir1Op::GetProperty { .. } => (EffectBoundary::Pure, None, None),
        // Synchronous iterator operations transfer labeled values inside the
        // interpreter. Like CallMethod, the protocol operation itself is not
        // egress. Acquisition/stepping/closing callbacks and generator resume
        // retain their receiver, lookup and completion provenance; any actual
        // callback effects still gate at their own sinks. Await remains on its
        // separately modeled asynchronous settlement boundary above.
        Ir1Op::IteratorClose { .. }
        | Ir1Op::ForOfInit
        | Ir1Op::ForOfNext { .. }
        | Ir1Op::Yield { .. } => (EffectBoundary::Pure, None, None),
        // SetProperty and DeleteProperty stay checked: they MUTATE the heap,
        // whose per-property IFC labels are not yet persisted (bd-ojvo1), so
        // their Internal sink is a fail-closed guard against laundering a high
        // value through an untracked property slot.
        Ir1Op::SetProperty { .. } | Ir1Op::DeleteProperty { .. } => {
            (EffectBoundary::ReadEffect, None, None)
        }
        Ir1Op::ForInInit
        | Ir1Op::ForInNext { .. }
        | Ir1Op::Construct { .. }
        | Ir1Op::ConstructSuper { .. }
        | Ir1Op::RegisterDerivedConstructor { .. }
        | Ir1Op::TemplateLiteral { .. } => (EffectBoundary::ReadEffect, None, None),
        _ => (EffectBoundary::Pure, None, None),
    }
}

#[derive(Clone, Debug)]
pub(super) struct FlowValue {
    pub(super) identity: usize,
    pub(super) label: Label,
    pub(super) crypto_origin: Option<usize>,
    pub(super) shape: FlowValueShape,
    pub(super) process_operation: Option<ChildProcessOperation>,
    /// bd-pafik: stream-protocol provenance (callback summaries on function
    /// and options-object literals, authenticated stream states, and
    /// pipeline-promise rejection origins).
    pub(super) stream: Option<StreamFlowInfo>,
    /// bd-zco6t: the fs-operation discriminator carried by a NUL-sentinel
    /// `fsop:` string literal, so the flow simulation can distinguish finite
    /// fd-lifecycle results from generic fs reads.
    pub(super) fs_operation: Option<FsOperation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FlowValueShape {
    Unknown,
    Primitive,
    Callable,
    CallableContainer,
    /// The exact callable-only native returned by
    /// `builtin:ArrayIsArrayFunction`. Calls are finite and primitive-valued;
    /// construction deterministically rejects before dispatching arguments.
    ArrayIsArrayFunction,
    /// The runtime-injected global `Function` constructor. Construction from
    /// primitive source fragments produces a summarized callable.
    FunctionConstructor,
    /// Authenticated constructor reference returned by the finite
    /// `builtin:EventEmitterConstructorRef` hostcall.
    EventEmitterConstructor,
    /// Fresh engine-owned EventEmitter instance produced by constructing the
    /// authenticated constructor reference.
    EventEmitterObject,
    /// Receiver-preserving `EventEmitter.on` / `once` method reference.
    EventEmitterFluentMethod,
    /// Boolean-returning `EventEmitter.emit` method reference.
    EventEmitterEmitMethod,
    /// A fresh engine-owned array returned by `Object.keys`. Its elements are
    /// primitive strings and its prototype is the native Array prototype, so
    /// an immediate static `.join` lookup is finite and cannot invoke guest
    /// accessors. Any mutation, escape, or control-flow merge clears this
    /// proof through the ordinary shape invalidation paths.
    OwnKeyArray,
    /// The exact native `Array.prototype.join` method read from an
    /// authenticated `OwnKeyArray`. Keeping this distinct from a generic
    /// callable lets CallMethod retain the primitive-string result contract.
    OwnKeyJoinMethod,
    FreshAggregate,
    ClosedResult,
    BufferObject,
    ConstantsObject,
}

impl FlowValueShape {
    /// Whether a value of this shape, passed as an argument, can make the
    /// callee run guest code: a callback, or coercion / accessor hooks on a
    /// guest-reachable object. Only primitives and engine-owned closed
    /// results are known to be inert.
    pub(super) fn argument_cannot_run_guest_code(self) -> bool {
        matches!(
            self,
            Self::Primitive
                | Self::OwnKeyArray
                | Self::ClosedResult
                | Self::BufferObject
                | Self::ConstantsObject
        )
    }

    pub(super) fn is_closed(self) -> bool {
        matches!(
            self,
            Self::Primitive
                | Self::OwnKeyArray
                | Self::ClosedResult
                | Self::BufferObject
                | Self::FreshAggregate
                | Self::ConstantsObject
                | Self::EventEmitterObject
        )
    }
}

pub(super) fn invalidate_nonprimitive_flow_shapes(values: &mut [FlowValue]) {
    for value in values {
        if !matches!(
            value.shape,
            FlowValueShape::Primitive
                | FlowValueShape::Callable
                | FlowValueShape::ArrayIsArrayFunction
                | FlowValueShape::FunctionConstructor
                | FlowValueShape::EventEmitterObject
                // bd-zco6t: BufferObject must survive GetProperty/CallMethod
                // on unrelated `fs.*` members and `console.log` so
                // `buf.toString` still sees the engine receiver. StoreBinding
                // of a new value still overwrites the binding shape.
                | FlowValueShape::BufferObject
                // bd-dign3: ClosedResult is engine-vouched closed data
                // (catalog arrays, typed-array views, cipher results). It
                // must survive unrelated GetProperty/CallMethod invalidation
                // exactly as BufferObject does: the synthetic receiver path
                // (`StoreBinding` -> `GetProperty` -> `LoadBinding`) reads
                // the stack copy immediately, and wiping it here turns every
                // finite method call on such a value into an unknown-callee
                // fail-high. Mutation and escape paths still clear it via
                // their own explicit invalidations.
                | FlowValueShape::ClosedResult
                | FlowValueShape::ConstantsObject
        ) {
            value.shape = FlowValueShape::Unknown;
        }
    }
}

/// Whether the nonprimitive sweep resets a binding holding `shape` to
/// `Unknown` (an `Unknown` shape stays as it is).
pub(super) fn nonprimitive_binding_sweep_resets(shape: FlowValueShape) -> bool {
    !matches!(
        shape,
        FlowValueShape::Unknown
            | FlowValueShape::Primitive
            | FlowValueShape::Callable
            | FlowValueShape::ArrayIsArrayFunction
            | FlowValueShape::FunctionConstructor
            | FlowValueShape::EventEmitterObject
            // Named `buf` must still be BufferObject after `fs.readSync`
            // / `fs.closeSync` so the later `buf.toString` hostcall
            // authenticates (bd-zco6t).
            | FlowValueShape::BufferObject
            // bd-dign3: named bindings holding engine-vouched closed
            // data keep their proof across unrelated invalidation for
            // the synthetic-receiver and later-read paths, exactly as
            // BufferObject does.
            | FlowValueShape::ClosedResult
            | FlowValueShape::ConstantsObject
    )
}

/// Heap-backed retained proofs (see [`invalidate_heap_backed_flow_shapes`]).
pub(super) fn is_heap_backed_flow_shape(shape: FlowValueShape) -> bool {
    matches!(
        shape,
        FlowValueShape::BufferObject
            | FlowValueShape::ClosedResult
            | FlowValueShape::FreshAggregate
            | FlowValueShape::ConstantsObject
    )
}

/// The flow shapes of a unit's bindings (bd-9vouw.227). The two sweeps below
/// run at every call, property write, coercion and merge; each visits only
/// the bindings whose shape it changes, kept apart as shapes are stored,
/// instead of every binding of the unit (simulation was quadratic: bindings
/// x calls). Every write goes through `insert`, so the sets stay exact.
#[derive(Default)]
pub(super) struct BindingFlowShapes {
    pub(super) shapes: BTreeMap<BindingId, FlowValueShape>,
    /// Bindings whose shape the nonprimitive sweep resets.
    pub(super) nonprimitive: BTreeSet<BindingId>,
    /// Bindings whose shape is heap-backed.
    pub(super) heap_backed: BTreeSet<BindingId>,
}

impl BindingFlowShapes {
    pub(super) fn get(&self, binding_id: &BindingId) -> Option<&FlowValueShape> {
        self.shapes.get(binding_id)
    }

    pub(super) fn insert(&mut self, binding_id: BindingId, shape: FlowValueShape) {
        self.shapes.insert(binding_id, shape);
        if nonprimitive_binding_sweep_resets(shape) {
            self.nonprimitive.insert(binding_id);
        } else {
            self.nonprimitive.remove(&binding_id);
        }
        if is_heap_backed_flow_shape(shape) {
            self.heap_backed.insert(binding_id);
        } else {
            self.heap_backed.remove(&binding_id);
        }
    }

    pub(super) fn reset_to_unknown(&mut self, bindings: BTreeSet<BindingId>) {
        for binding_id in bindings {
            self.insert(binding_id, FlowValueShape::Unknown);
        }
    }
}

pub(super) fn invalidate_nonprimitive_binding_flow_shapes(binding_shapes: &mut BindingFlowShapes) {
    let reset = std::mem::take(&mut binding_shapes.nonprimitive);
    binding_shapes.reset_to_unknown(reset);
}

/// Heap-backed retained proofs (`BufferObject`, `ClosedResult`,
/// `FreshAggregate`, `ConstantsObject`) summarize engine-vouched structure
/// whose backing store lives on the shared heap (bd-b1etn). Guest call
/// boundaries, property mutations, and control-flow merges can observe or
/// mutate that store through aliases, so the soundness-critical sites must
/// clear heap-backed proofs outright instead of keeping them alive for later
/// finite-method reads. Unrelated-call sweeps keep using the weaker
/// nonprimitive invalidation so synthetic-receiver reads survive (bd-zco6t,
/// bd-dign3).
pub(super) fn invalidate_heap_backed_flow_shapes(values: &mut [FlowValue]) {
    for value in values {
        if matches!(
            value.shape,
            FlowValueShape::BufferObject
                | FlowValueShape::ClosedResult
                | FlowValueShape::FreshAggregate
                | FlowValueShape::ConstantsObject
        ) {
            value.shape = FlowValueShape::Unknown;
        }
    }
}

pub(super) fn invalidate_heap_backed_binding_flow_shapes(binding_shapes: &mut BindingFlowShapes) {
    let reset = std::mem::take(&mut binding_shapes.heap_backed);
    binding_shapes.reset_to_unknown(reset);
}

// ---------------------------------------------------------------------------
// bd-pafik: stream pipeline callback and Promise rejection provenance
// ---------------------------------------------------------------------------

/// Conservative symbolic exception summary for a user callback handed to a
/// stream constructor (bd-pafik). `Supported(label)` bounds the provenance of
/// every value the callback can throw, pass to its engine continuation
/// (`callback(error)`), or reject with — EXCEPT contributions derived from the
/// callback's parameters, which the pipeline site covers separately by joining
/// its operand labels. `Unsupported` means no sound bound was established and
/// every consumer must fail high (TopSecret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum StreamCallbackSummary {
    Supported(Label),
    Unsupported,
}

impl StreamCallbackSummary {
    pub(super) fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Supported(a), Self::Supported(b)) => Self::Supported(a.join(b)),
            _ => Self::Unsupported,
        }
    }
}

/// bd-pafik: stream-protocol provenance carried by a [`FlowValue`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum StreamFlowInfo {
    /// A function literal (or options-object literal aggregating function
    /// literals) whose callback exception sources were symbolically
    /// summarized at creation.
    CallbackCarrier(StreamCallbackSummary),
    /// A stream constructed by an audited stream hostcall; `origin` keys its
    /// authenticated callback-error state.
    Stream { origin: usize },
    /// The Promise produced by `stream/promises` `pipeline`; `origin` keys
    /// its static rejection summary.
    PipelinePromise { origin: usize },
}

/// Per-slot abstract tag for the callback-body dataflow walk. The three
/// non-`Data` tags are MUST properties (definitely that thing on every path);
/// the merge of unequal tags is therefore `Data`, which admits nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StreamCallbackTag {
    /// Definitely the engine-provided continuation parameter (the last
    /// declared parameter, per the Node stream callback convention this
    /// engine implements for `write`/`transform`/`flush`/`final`).
    Continuation,
    /// Definitely a plain fresh aggregate: either a body-local array/object
    /// literal of closed values, or a capture of an outer binding that
    /// provably held such an aggregate when the callback was created. Its
    /// methods are the engine's own Array/Object prototype natives, whose
    /// exceptions are engine-internal and operand-derived.
    PlainAggregate,
    /// Definitely a primitive value.
    Primitive,
    /// Anything else.
    Data,
}

impl StreamCallbackTag {
    pub(super) fn merge(self, other: Self) -> Self {
        if self == other { self } else { Self::Data }
    }
}

/// bd-pafik: resolve a stream constructor's authenticated callback-error
/// state from its popped inputs (`pop_flow_values` order: inputs[0] is the
/// LAST argument). Zero arguments means no user callbacks; a single options
/// argument must carry a supported callback summary; anything else is
/// unsupported.
pub(super) fn stream_constructor_summary(
    inputs: &[FlowValue],
    operation_data_label: &Label,
) -> StreamCallbackSummary {
    match inputs {
        [] => StreamCallbackSummary::Supported(Label::Internal.join(operation_data_label)),
        [options] => match &options.stream {
            Some(StreamFlowInfo::CallbackCarrier(StreamCallbackSummary::Supported(
                callback_label,
            ))) => {
                // Deliberately do NOT join the options object's own value
                // label: it is the JoinInputs of the callback FUNCTION value,
                // whose bd-qjh7y return summary fails high on the engine
                // continuation call (`callback(...)` has no Callable-shaped
                // callee) and would poison every authenticated stream with
                // TopSecret. The symbolic callback summary is the exact
                // audited bound for what the constructor consumes.
                StreamCallbackSummary::Supported(Label::Internal.join(callback_label))
            }
            _ => StreamCallbackSummary::Unsupported,
        },
        _ => StreamCallbackSummary::Unsupported,
    }
}

/// bd-pafik: compute the static rejection summary for a `stream/promises`
/// pipeline whose every stage must be an authenticated stream with a
/// supported callback summary. `None` = at least one unknown stage: fail
/// high.
pub(super) fn stream_pipeline_rejection(
    inputs: &[FlowValue],
    stream_states: &BTreeMap<usize, StreamCallbackSummary>,
) -> Option<Label> {
    if inputs.is_empty() {
        return None;
    }
    // Start at the Internal engine-failure floor and join ONLY the
    // authenticated per-stage summaries. Each summary already covers its
    // stage's data (`Readable.from` joins the iterable; constructors carry
    // the audited callback bound), while the raw operand join would re-import
    // the bd-qjh7y JoinInputs poison from the stream VALUES' labels.
    let mut rejection = Label::Internal;
    for input in inputs {
        let Some(StreamFlowInfo::Stream { origin }) = &input.stream else {
            return None;
        };
        let Some(StreamCallbackSummary::Supported(summary)) = stream_states.get(origin) else {
            return None;
        };
        rejection = rejection.join(summary);
    }
    Some(rejection)
}

/// Build the [`StreamFlowInfo::CallbackCarrier`] for a function literal:
/// resolve which captures provably held a fresh plain aggregate at creation
/// time (their body-side ids admit `PlainAggregate` method calls in the
/// summary walk), then summarize the body's exception sources.
pub(super) fn stream_callback_carrier_for_function(
    param_names: &[String],
    rest_param_index: Option<u32>,
    body_ops: &[Ir1Op],
    free_vars: &[String],
    free_var_ids: &[BindingId],
    binding_labels: &BTreeMap<BindingId, Label>,
    binding_flow_shapes: &BindingFlowShapes,
) -> StreamFlowInfo {
    let aggregate_captures = free_vars
        .iter()
        .zip(free_var_ids.iter())
        .filter_map(|(name, body_id)| {
            let (origin_id, _) = parse_capture_cell_name(name)?;
            (binding_flow_shapes.get(&origin_id).copied() == Some(FlowValueShape::FreshAggregate))
                .then_some(*body_id)
        })
        .collect::<BTreeSet<_>>();
    StreamFlowInfo::CallbackCarrier(summarize_stream_callback_exceptions(
        param_names.len(),
        rest_param_index,
        body_ops,
        free_var_ids,
        free_vars,
        &aggregate_captures,
        binding_labels,
    ))
}

/// Symbolically bound the exception sources of a stream callback body
/// (bd-pafik). Returns `Supported(label)` only when every operation in the
/// body is on the audited allowlist below; ANY other construct — mutation
/// (`SetProperty`/`DeleteProperty`), alias escape into an unknown call,
/// nested function creation (recursion), `try` regions, dynamic name access,
/// un-audited hostcalls, iterators, `await`/`yield` — bails to `Unsupported`,
/// as does dataflow nonconvergence (step cap) or any stack-height merge
/// mismatch.
///
/// Soundness shape: the returned label joins the callback's capture labels
/// (via [`infer_function_capture_label`], Internal-floored) — every
/// NON-parameter value the body can reach flows from a literal (Public), a
/// capture (≤ that join), or an admitted engine-finite operation over those.
/// Parameter-derived values are excluded here by construction and covered at
/// the pipeline site by the operand join. Admissions that lean on the same
/// bd-ojvo1-era heap approximations as the main pass (`GetProperty` joins the
/// receiver label; `PlainAggregate` method calls trust the aggregate's
/// creation-time shape) are the documented heap-property provenance
/// prerequisites of this summary.
pub(super) fn summarize_stream_callback_exceptions(
    param_count: usize,
    rest_param_index: Option<u32>,
    body_ops: &[Ir1Op],
    free_var_ids: &[BindingId],
    free_vars: &[String],
    aggregate_captures: &BTreeSet<BindingId>,
    binding_labels: &BTreeMap<BindingId, Label>,
) -> StreamCallbackSummary {
    const STEP_CAP: usize = 20_000;

    // Non-parameter provenance floor: Internal (engine-owned failures) joined
    // with every capture's enclosing label. An unparseable capture identity
    // has no sound bound.
    let mut concrete = Label::Internal;
    for name in free_vars {
        let origin = parse_capture_cell_name(name)
            .or_else(|| parse_class_expression_self_capture_name(name))
            .map(|(origin_id, _)| origin_id);
        let Some(origin_id) = origin else {
            return StreamCallbackSummary::Unsupported;
        };
        concrete = concrete.join(binding_labels.get(&origin_id).unwrap_or(&Label::Internal));
    }
    let capture_ids = free_var_ids.iter().copied().collect::<BTreeSet<_>>();
    // Body binding ids allocate parameters first (0..param_count); a capture
    // cell colliding with a parameter slot would make tagging ambiguous.
    if capture_ids.iter().any(|id| (*id as usize) < param_count) {
        return StreamCallbackSummary::Unsupported;
    }
    // The engine invokes the LAST declared parameter as the continuation. A
    // rest parameter makes the final slot a fresh array instead, so no
    // parameter is provably the continuation.
    let continuation_id = match rest_param_index {
        Some(_) => None,
        None => param_count
            .checked_sub(1)
            .and_then(|index| u32::try_from(index).ok()),
    };

    let mut label_targets = BTreeMap::<u32, usize>::new();
    for (index, body_op) in body_ops.iter().enumerate() {
        if let Ir1Op::Label { id } = body_op
            && label_targets.insert(*id, index).is_some()
        {
            return StreamCallbackSummary::Unsupported;
        }
    }

    type TagState = (
        Vec<StreamCallbackTag>,
        BTreeMap<BindingId, StreamCallbackTag>,
    );
    let merge_states = |a: &TagState, b: &TagState| -> Option<TagState> {
        if a.0.len() != b.0.len() {
            return None;
        }
        let stack =
            a.0.iter()
                .zip(b.0.iter())
                .map(|(x, y)| x.merge(*y))
                .collect::<Vec<_>>();
        let mut locals = BTreeMap::new();
        for key in a.1.keys().chain(b.1.keys()) {
            let merged = match (a.1.get(key), b.1.get(key)) {
                (Some(x), Some(y)) => x.merge(*y),
                _ => StreamCallbackTag::Data,
            };
            locals.insert(*key, merged);
        }
        Some((stack, locals))
    };

    let mut states = BTreeMap::<usize, TagState>::new();
    let mut worklist = vec![(0usize, (Vec::new(), BTreeMap::new()))];
    let mut steps = 0usize;

    let load_tag = |binding_id: u32, locals: &BTreeMap<BindingId, StreamCallbackTag>| {
        if capture_ids.contains(&binding_id) {
            if aggregate_captures.contains(&binding_id) {
                StreamCallbackTag::PlainAggregate
            } else {
                StreamCallbackTag::Data
            }
        } else if let Some(tag) = locals.get(&binding_id) {
            *tag
        } else if continuation_id == Some(binding_id) {
            StreamCallbackTag::Continuation
        } else {
            StreamCallbackTag::Data
        }
    };

    while let Some((entry_index, entry_state)) = worklist.pop() {
        let merged_entry = match states.get(&entry_index) {
            Some(existing) => {
                let Some(merged) = merge_states(existing, &entry_state) else {
                    return StreamCallbackSummary::Unsupported;
                };
                if merged == *existing {
                    continue;
                }
                merged
            }
            None => entry_state,
        };
        states.insert(entry_index, merged_entry.clone());
        let (mut stack, mut locals) = merged_entry;

        let mut index = entry_index;
        loop {
            steps += 1;
            if steps > STEP_CAP {
                return StreamCallbackSummary::Unsupported;
            }
            let Some(body_op) = body_ops.get(index) else {
                break;
            };
            match body_op {
                Ir1Op::LoadLiteral { .. } => stack.push(StreamCallbackTag::Primitive),
                Ir1Op::LoadBinding { binding_id } => stack.push(load_tag(*binding_id, &locals)),
                Ir1Op::StoreBinding { binding_id } | Ir1Op::InitializeBinding { binding_id } => {
                    let Some(tag) = stack.pop() else {
                        return StreamCallbackSummary::Unsupported;
                    };
                    locals.insert(*binding_id, tag);
                    stack.push(tag);
                }
                Ir1Op::BinaryOp { .. } => {
                    if stack.len() < 2 {
                        return StreamCallbackSummary::Unsupported;
                    }
                    stack.pop();
                    stack.pop();
                    stack.push(StreamCallbackTag::Primitive);
                }
                Ir1Op::UnaryOp { .. } => {
                    if stack.pop().is_none() {
                        return StreamCallbackSummary::Unsupported;
                    }
                    stack.push(StreamCallbackTag::Primitive);
                }
                Ir1Op::GetProperty { key } => {
                    let pops = if matches!(key, Ir1PropertyKey::Dynamic) {
                        2
                    } else {
                        1
                    };
                    if stack.len() < pops {
                        return StreamCallbackSummary::Unsupported;
                    }
                    for _ in 0..pops {
                        stack.pop();
                    }
                    stack.push(StreamCallbackTag::Data);
                }
                Ir1Op::NewArray { count } => {
                    let count = *count as usize;
                    if stack.len() < count {
                        return StreamCallbackSummary::Unsupported;
                    }
                    let closed = stack[stack.len() - count..]
                        .iter()
                        .all(|tag| matches!(tag, StreamCallbackTag::Primitive));
                    for _ in 0..count {
                        stack.pop();
                    }
                    stack.push(if closed {
                        StreamCallbackTag::PlainAggregate
                    } else {
                        StreamCallbackTag::Data
                    });
                }
                Ir1Op::NewObject { count } => {
                    let Some(needed) = (*count as usize).checked_mul(2) else {
                        return StreamCallbackSummary::Unsupported;
                    };
                    if stack.len() < needed {
                        return StreamCallbackSummary::Unsupported;
                    }
                    let closed = stack[stack.len() - needed..]
                        .iter()
                        .all(|tag| matches!(tag, StreamCallbackTag::Primitive));
                    for _ in 0..needed {
                        stack.pop();
                    }
                    stack.push(if closed {
                        StreamCallbackTag::PlainAggregate
                    } else {
                        StreamCallbackTag::Data
                    });
                }
                Ir1Op::Call { arg_count } => {
                    let args = *arg_count as usize;
                    if stack.len() < args + 1 {
                        return StreamCallbackSummary::Unsupported;
                    }
                    for _ in 0..args {
                        stack.pop();
                    }
                    let callee = stack.pop().expect("callee presence checked above");
                    // Only the engine continuation is a known-finite callee;
                    // its error argument's non-parameter provenance is covered
                    // by `concrete` and the pipeline operand join.
                    if callee != StreamCallbackTag::Continuation {
                        return StreamCallbackSummary::Unsupported;
                    }
                    stack.push(StreamCallbackTag::Data);
                }
                Ir1Op::CallMethod { arg_count } => {
                    let args = *arg_count as usize;
                    // Stack order: args, then method-name value, then receiver.
                    if stack.len() < args + 2 {
                        return StreamCallbackSummary::Unsupported;
                    }
                    for _ in 0..args + 1 {
                        stack.pop();
                    }
                    let receiver = stack.pop().expect("receiver presence checked above");
                    // Plain-aggregate receivers dispatch the engine's own
                    // Array/Object prototype natives (heap-property
                    // provenance prerequisite: creation-time shape).
                    if receiver != StreamCallbackTag::PlainAggregate {
                        return StreamCallbackSummary::Unsupported;
                    }
                    stack.push(StreamCallbackTag::Data);
                }
                Ir1Op::HostCall {
                    capability,
                    arg_count,
                } => {
                    let args = *arg_count as usize;
                    if stack.len() < args {
                        return StreamCallbackSummary::Unsupported;
                    }
                    let arg_tags = stack.split_off(stack.len() - args);
                    match capability.as_str() {
                        // `String(value)` is a finite engine formatter
                        // (`value_to_string` takes `&self`: it can never
                        // re-enter guest code), so its exceptions are
                        // engine-internal for every operand.
                        "builtin:String" => stack.push(StreamCallbackTag::Primitive),
                        // The unshadowed native Error family is finite for
                        // primitive messages (bd-8y64t); object arguments can
                        // re-enter guest coercion, so they bail.
                        "builtin:Error"
                        | "builtin:TypeError"
                        | "builtin:RangeError"
                        | "builtin:ReferenceError"
                        | "builtin:SyntaxError"
                        | "builtin:EvalError"
                        | "builtin:URIError" => {
                            if !arg_tags
                                .iter()
                                .all(|tag| matches!(tag, StreamCallbackTag::Primitive))
                            {
                                return StreamCallbackSummary::Unsupported;
                            }
                            stack.push(StreamCallbackTag::Data);
                        }
                        _ => return StreamCallbackSummary::Unsupported,
                    }
                }
                Ir1Op::Throw => {
                    // The thrown value's non-parameter provenance is bounded
                    // by `concrete`; parameter-derived provenance is covered
                    // by the pipeline operand join.
                    if stack.pop().is_none() {
                        return StreamCallbackSummary::Unsupported;
                    }
                    break;
                }
                Ir1Op::Return => {
                    stack.pop();
                    break;
                }
                Ir1Op::Pop | Ir1Op::Discard => {
                    if stack.pop().is_none() {
                        return StreamCallbackSummary::Unsupported;
                    }
                }
                Ir1Op::Nop => {}
                Ir1Op::Label { .. } => {}
                Ir1Op::Jump { label_id } => {
                    let Some(&target_index) = label_targets.get(label_id) else {
                        return StreamCallbackSummary::Unsupported;
                    };
                    worklist.push((target_index, (stack, locals)));
                    break;
                }
                Ir1Op::JumpIfFalsy { label_id } => {
                    if stack.last().is_none() {
                        return StreamCallbackSummary::Unsupported;
                    }
                    let Some(&target_index) = label_targets.get(label_id) else {
                        return StreamCallbackSummary::Unsupported;
                    };
                    worklist.push((target_index, (stack.clone(), locals.clone())));
                }
                Ir1Op::JumpIfFalsyConsume { label_id }
                | Ir1Op::JumpIfTruthy { label_id }
                | Ir1Op::JumpIfNullish { label_id } => {
                    if stack.pop().is_none() {
                        return StreamCallbackSummary::Unsupported;
                    }
                    let Some(&target_index) = label_targets.get(label_id) else {
                        return StreamCallbackSummary::Unsupported;
                    };
                    worklist.push((target_index, (stack.clone(), locals.clone())));
                }
                _ => return StreamCallbackSummary::Unsupported,
            }
            index += 1;
            // Straight-line successor states merge through the same map when
            // the successor is a join point (a Label op).
            if matches!(body_ops.get(index), Some(Ir1Op::Label { .. })) {
                worklist.push((index, (stack.clone(), locals.clone())));
                break;
            }
        }
    }

    StreamCallbackSummary::Supported(concrete)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CryptoFlowObjectKind {
    Hash,
    Hmac,
    Cipher,
}

pub(super) fn crypto_flow_kind_supports_capability(
    kind: CryptoFlowObjectKind,
    capability: &str,
) -> bool {
    match kind {
        CryptoFlowObjectKind::Hash => matches!(
            capability,
            "builtin:CryptoObjectUpdate"
                | "builtin:CryptoObjectDigest"
                | "builtin:CryptoObjectCopy"
        ),
        CryptoFlowObjectKind::Hmac => matches!(
            capability,
            "builtin:CryptoObjectUpdate" | "builtin:CryptoObjectDigest"
        ),
        CryptoFlowObjectKind::Cipher => matches!(
            capability,
            "builtin:CryptoObjectUpdate"
                | "builtin:CryptoObjectFinal"
                | "builtin:CryptoObjectGetAuthTag"
                | "builtin:CryptoObjectSetAuthTag"
        ),
    }
}

#[derive(Clone, Debug)]
pub(super) struct CryptoFlowObjectState {
    pub(super) kind: CryptoFlowObjectKind,
    pub(super) lifecycle_label: Label,
}

pub(super) fn pop_flow_value(
    value_stack: &mut Vec<FlowValue>,
) -> Result<FlowValue, LoweringPipelineError> {
    value_stack
        .pop()
        .ok_or(LoweringPipelineError::ValueStackUnderflow)
}

pub(super) fn pop_flow_values(
    value_stack: &mut Vec<FlowValue>,
    count: usize,
) -> Result<Vec<FlowValue>, LoweringPipelineError> {
    if count > value_stack.len() {
        return Err(LoweringPipelineError::ValueStackUnderflow);
    }
    let mut values = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        values.push(pop_flow_value(value_stack)?);
    }
    Ok(values)
}

pub(super) fn join_flow_values(values: &[FlowValue]) -> Label {
    Label::join_all(values.iter().map(|value| value.label.clone())).unwrap_or(Label::Public)
}

pub(super) fn process_spawn_request_label(inputs: &[FlowValue]) -> Label {
    let Some(discriminator) = inputs.last() else {
        return Label::TopSecret;
    };
    let Some(operation) = discriminator.process_operation else {
        return Label::TopSecret;
    };
    let logical_reversed = &inputs[..inputs.len() - 1];
    let source_argument = |index: usize| {
        logical_reversed
            .len()
            .checked_sub(index + 1)
            .and_then(|reversed_index| logical_reversed.get(reversed_index))
    };
    let request_argument_count = match operation {
        ChildProcessOperation::SpawnSync
        | ChildProcessOperation::ExecFileSync
        | ChildProcessOperation::Spawn => 3,
        ChildProcessOperation::ExecSync => 2,
        ChildProcessOperation::Exec => {
            if source_argument(1).is_some_and(|value| value.shape == FlowValueShape::Callable) {
                1
            } else {
                2
            }
        }
        ChildProcessOperation::ExecFile => {
            if source_argument(1).is_some_and(|value| value.shape == FlowValueShape::Callable) {
                1
            } else if source_argument(2)
                .is_some_and(|value| value.shape == FlowValueShape::Callable)
            {
                2
            } else {
                // `execFile(file[, args][, options][, callback])` has at most
                // three request-bearing arguments. A callback at index 3 and
                // an omitted callback therefore both join the first three.
                3
            }
        }
    };
    Label::join_all(
        logical_reversed
            .iter()
            .rev()
            .take(request_argument_count)
            .map(|value| value.label.clone()),
    )
    .unwrap_or(Label::Public)
}

pub(super) fn fresh_flow_value(label: Label, next_identity: &mut usize) -> FlowValue {
    let identity = *next_identity;
    *next_identity = (*next_identity).saturating_add(1);
    FlowValue {
        identity,
        label,
        crypto_origin: None,
        shape: FlowValueShape::Unknown,
        process_operation: None,
        stream: None,
        fs_operation: None,
    }
}

pub(super) fn fresh_shaped_flow_value(
    label: Label,
    shape: FlowValueShape,
    next_identity: &mut usize,
) -> FlowValue {
    let mut value = fresh_flow_value(label, next_identity);
    value.shape = shape;
    value
}

pub(super) fn fresh_crypto_flow_value(
    label: Label,
    crypto_origin: Option<usize>,
    next_identity: &mut usize,
) -> FlowValue {
    let mut value = fresh_flow_value(label, next_identity);
    value.crypto_origin = crypto_origin;
    value
}

pub(super) fn join_binding_label(
    binding_labels: &mut BTreeMap<BindingId, Label>,
    binding_id: BindingId,
    label: &Label,
) -> bool {
    match binding_labels.get_mut(&binding_id) {
        Some(existing) => {
            let joined = existing.join(label);
            if *existing == joined {
                false
            } else {
                *existing = joined;
                true
            }
        }
        None => {
            binding_labels.insert(binding_id, label.clone());
            true
        }
    }
}

pub(super) fn infer_function_capture_label(
    free_vars: &[String],
    free_var_ids: &[BindingId],
    body_ops: &[Ir1Op],
    binding_labels: &BTreeMap<BindingId, Label>,
    host_io_exception_provenance: HostIoExceptionProvenance,
    summary_depth: usize,
) -> Label {
    summarize_function_body(
        free_vars,
        free_var_ids,
        body_ops,
        binding_labels,
        host_io_exception_provenance,
        summary_depth,
    )
}

/// FRANKEN_CAPTURE_DEBUG, read once: the flow analysis checked it for every
/// function summary and capture (bd-9vouw.153).
pub(super) fn capture_debug_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("FRANKEN_CAPTURE_DEBUG").is_some())
}

/// FRANKEN_IFC_DEBUG, read once: the flow analysis checked it for every
/// method call it simulated (bd-9vouw.153).
pub(super) fn ifc_debug_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("FRANKEN_IFC_DEBUG").is_some())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FunctionCaptureOrigin {
    pub(super) enclosing_id: BindingId,
    pub(super) body_id: BindingId,
}

/// Decode the same capture-cell identity pair used when the runtime installs a
/// closure call frame: the encoded id selects the retained enclosing cell,
/// while `free_var_ids` selects the body-local slot that receives that cell.
/// Any ambiguity is unsound for a static summary and therefore has no mapping.
// bd-h7p1a: gated diagnostic — emit the free_var / return-value pair on
// None so the next agent can see the exact closure shape the capture
// resolver is failing on, without building the full closure-cell
// reconstruction. Activated by FRANKEN_CAPTURE_DEBUG=1.
pub(super) fn canonical_function_capture_origins(
    free_vars: &[String],
    free_var_ids: &[BindingId],
) -> Option<Vec<FunctionCaptureOrigin>> {
    if capture_debug_enabled() {
        eprintln!(
            "[capture-debug] canonical_function_capture_origins free_vars={:?} body_ids={:?}",
            free_vars, free_var_ids
        );
    }
    if free_vars.len() != free_var_ids.len() {
        return None;
    }

    let mut enclosing_ids = BTreeSet::<BindingId>::new();
    let mut body_ids = BTreeSet::<BindingId>::new();
    free_vars
        .iter()
        .zip(free_var_ids)
        .map(|(runtime_name, body_id)| {
            let parse_cell = parse_capture_cell_name(runtime_name);
            let parse_self = parse_class_expression_self_capture_name(runtime_name);
            if capture_debug_enabled() && parse_cell.is_none() && parse_self.is_none() {
                eprintln!(
                    "[capture-debug] unparseable free_var name={:?}",
                    runtime_name
                );
            }
            let enclosing_id = parse_cell.or(parse_self).map(|(origin_id, _)| origin_id)?;
            if !enclosing_ids.insert(enclosing_id) || !body_ids.insert(*body_id) {
                return None;
            }
            Some(FunctionCaptureOrigin {
                enclosing_id,
                body_id: *body_id,
            })
        })
        .collect()
}

/// Compute the hidden IFC sources of a function value. `free_var_ids` live in
/// the detached body namespace; the canonical capture-cell name carries the
/// enclosing binding origin. Keeping the two aligned here mirrors runtime
/// closure setup, which binds each body-local scoped load to that exact outer
/// cell rather than treating the body ID as a module binding ID.
pub(super) fn summarize_function_body(
    free_vars: &[String],
    free_var_ids: &[BindingId],
    body_ops: &[Ir1Op],
    enclosing_labels: &BTreeMap<BindingId, Label>,
    host_io_exception_provenance: HostIoExceptionProvenance,
    summary_depth: usize,
) -> Label {
    // bd-9vouw.153: each pass of an enclosing body's fixed point summarized
    // every nested function again, and each summary ran its own fixed point
    // over its nested functions, so work grew with the pass count raised to
    // the nesting depth. A summary is a function of the body, its captures'
    // enclosing labels, the provenance and the depth; within one analysis
    // (FunctionSummaryMemoScope) the body's address identifies it.
    let origin_labels =
        canonical_function_capture_origins(free_vars, free_var_ids).map(|origins| {
            origins
                .iter()
                .map(|origin| {
                    enclosing_labels
                        .get(&origin.enclosing_id)
                        .cloned()
                        .unwrap_or(Label::Internal)
                })
                .collect::<Vec<_>>()
        });
    let key = origin_labels.map(|origin_labels| FunctionSummaryKey {
        body: (body_ops.as_ptr() as usize, body_ops.len()),
        free_var_ids: (free_var_ids.as_ptr() as usize, free_var_ids.len()),
        summary_depth,
        origin_labels,
    });
    if let Some(key) = &key
        && let Some(label) = FUNCTION_SUMMARY_MEMO.with(|memo| {
            memo.borrow().as_ref().and_then(|memo| {
                (memo.provenance == host_io_exception_provenance)
                    .then(|| memo.entries.get(key).cloned())
                    .flatten()
            })
        })
    {
        return label;
    }
    let label = summarize_function_body_uncached(
        free_vars,
        free_var_ids,
        body_ops,
        enclosing_labels,
        host_io_exception_provenance,
        summary_depth,
    );
    if let Some(key) = key {
        FUNCTION_SUMMARY_MEMO.with(|memo| {
            if let Some(memo) = memo.borrow_mut().as_mut()
                && memo.provenance == host_io_exception_provenance
            {
                memo.entries.insert(key, label.clone());
            }
        });
    }
    label
}

/// bd-9vouw.153: what a function summary depends on. `body` and
/// `free_var_ids` are addresses of the analysed module's ops, which do not
/// move or change while a [`FunctionSummaryMemoScope`] is open.
#[derive(PartialEq, Eq, Hash)]
pub(super) struct FunctionSummaryKey {
    pub(super) body: (usize, usize),
    pub(super) free_var_ids: (usize, usize),
    pub(super) summary_depth: usize,
    pub(super) origin_labels: Vec<Label>,
}

pub(super) struct FunctionSummaryMemo {
    pub(super) provenance: HostIoExceptionProvenance,
    pub(super) entries: std::collections::HashMap<FunctionSummaryKey, Label>,
}

thread_local! {
    static FUNCTION_SUMMARY_MEMO: std::cell::RefCell<Option<FunctionSummaryMemo>> =
        const { std::cell::RefCell::new(None) };
}

/// Function summaries are memoized while this scope is open: one flow
/// analysis of one module. A nested analysis gets a fresh memo and the
/// enclosing one is restored when it ends, so no entry outlives the ops
/// whose addresses key it.
pub(super) struct FunctionSummaryMemoScope {
    pub(super) saved: Option<FunctionSummaryMemo>,
}

impl FunctionSummaryMemoScope {
    pub(super) fn enter(provenance: HostIoExceptionProvenance) -> Self {
        let saved = FUNCTION_SUMMARY_MEMO.with(|memo| {
            memo.replace(Some(FunctionSummaryMemo {
                provenance,
                entries: std::collections::HashMap::new(),
            }))
        });
        Self { saved }
    }
}

impl Drop for FunctionSummaryMemoScope {
    fn drop(&mut self) {
        let saved = self.saved.take();
        FUNCTION_SUMMARY_MEMO.with(|memo| {
            memo.replace(saved);
        });
    }
}

pub(super) fn summarize_function_body_uncached(
    free_vars: &[String],
    free_var_ids: &[BindingId],
    body_ops: &[Ir1Op],
    enclosing_labels: &BTreeMap<BindingId, Label>,
    host_io_exception_provenance: HostIoExceptionProvenance,
    summary_depth: usize,
) -> Label {
    const MAX_FUNCTION_SUMMARY_DEPTH: usize = 64;
    const MAX_FUNCTION_SUMMARY_PASSES: usize = 16;

    if summary_depth > MAX_FUNCTION_SUMMARY_DEPTH || body_ops.is_empty() {
        return Label::TopSecret;
    }

    let Some(capture_origins) = canonical_function_capture_origins(free_vars, free_var_ids) else {
        return Label::TopSecret;
    };
    let mut body_binding_labels = BTreeMap::<BindingId, Label>::new();
    let mut capture_label = Label::Public;
    for origin in capture_origins {
        // A closure can be created before the captured binding's first store.
        // Match runtime's retained cell with the ordinary unresolved-binding
        // floor until the enclosing fixed point supplies a stronger label.
        let origin_label = enclosing_labels
            .get(&origin.enclosing_id)
            .cloned()
            .unwrap_or(Label::Internal);
        capture_label = capture_label.join(&origin_label);
        body_binding_labels.insert(origin.body_id, origin_label);
    }

    let Ok(catch_region_events) = ir2_catch_region_events(body_ops) else {
        return Label::TopSecret;
    };

    // The pass that changes no binding label read the fixed point
    // throughout, so its labels are the converged ones: a further pass
    // recomputed exactly them (debug builds still check that).
    let mut fixed_point = None;
    for _ in 0..MAX_FUNCTION_SUMMARY_PASSES {
        let Ok((labels, changed, _, _)) = simulate_ir2_flow_labels(
            body_ops,
            &mut body_binding_labels,
            &catch_region_events,
            host_io_exception_provenance,
            summary_depth,
        ) else {
            return Label::TopSecret;
        };
        if !changed {
            fixed_point = Some(labels);
            break;
        }
    }
    let Some(labels) = fixed_point else {
        return Label::TopSecret;
    };
    #[cfg(debug_assertions)]
    {
        let again = simulate_ir2_flow_labels(
            body_ops,
            &mut body_binding_labels,
            &catch_region_events,
            host_io_exception_provenance,
            summary_depth,
        );
        debug_assert!(
            matches!(&again, Ok((again_labels, false, _, _)) if *again_labels == labels),
            "a function's flow summary changed after its fixed point"
        );
    }

    let return_label = Label::join_all(body_ops.iter().zip(labels).filter_map(|(op, label)| {
        matches!(op, Ir1Op::Return | Ir1Op::Yield { .. }).then_some(label)
    }))
    .unwrap_or(Label::Public);
    capture_label.join(&return_label)
}

/// bd-9vouw.153: the IR1 operation a flow-simulation step reads. The
/// simulation and the catch-region scan read nothing else, so a function
/// summary runs them over the nested body's IR1 ops in place; it cloned the
/// whole nested body into IR2 ops on every call.
pub(super) trait FlowOp {
    fn inner(&self) -> &Ir1Op;
}

impl FlowOp for Ir2Op {
    fn inner(&self) -> &Ir1Op {
        &self.inner
    }
}

impl FlowOp for Ir1Op {
    fn inner(&self) -> &Ir1Op {
        self
    }
}

pub(super) type CatchRegionEvents = (
    BTreeMap<usize, Vec<u32>>,
    BTreeMap<usize, Vec<u32>>,
    BTreeMap<u32, Label>,
);

pub(super) fn ir2_catch_region_events<O: FlowOp>(
    ops: &[O],
) -> Result<CatchRegionEvents, LoweringPipelineError> {
    let mut label_positions = BTreeMap::new();
    for (index, op) in ops.iter().enumerate() {
        let Ir1Op::Label { id } = op.inner() else {
            continue;
        };
        if label_positions.insert(*id, index).is_some() {
            return Err(LoweringPipelineError::InvariantViolation {
                detail: "lowered exception flow contains a duplicate label",
            });
        }
    }
    let explicit_finally_entry_labels = ops
        .windows(2)
        .filter_map(|pair| match (pair[0].inner(), pair[1].inner()) {
            (Ir1Op::Label { id }, Ir1Op::EnterFinally) => Some(*id),
            _ => None,
        })
        .collect::<BTreeSet<_>>();

    struct ProtectedRegion {
        start_index: usize,
        target_index: usize,
        catch_label: Option<u32>,
        end_index: Option<usize>,
    }

    let mut regions = Vec::<ProtectedRegion>::new();
    let mut region_by_begin = BTreeMap::<usize, usize>::new();
    for (index, op) in ops.iter().enumerate() {
        let Ir1Op::BeginTry {
            catch_label,
            finally_label,
        } = op.inner()
        else {
            continue;
        };
        let Some(&target_index) = label_positions.get(catch_label) else {
            return Err(LoweringPipelineError::InvariantViolation {
                detail: "lowered try references missing catch label",
            });
        };
        let Some(start_index) = index.checked_add(1) else {
            return Err(LoweringPipelineError::InvariantViolation {
                detail: "lowered try region index overflow",
            });
        };
        if target_index < start_index {
            return Err(LoweringPipelineError::InvariantViolation {
                detail: "lowered catch label precedes its protected region",
            });
        }
        let region_id = regions.len();
        regions.push(ProtectedRegion {
            start_index,
            target_index,
            catch_label: (finally_label.as_ref() != Some(catch_label)
                && !explicit_finally_entry_labels.contains(catch_label))
            .then_some(*catch_label),
            end_index: None,
        });
        region_by_begin.insert(index, region_id);
    }

    // Abrupt-exit lowering can emit several mutually exclusive `EndTry`
    // forwarders for one protected region. Attribute every marker to the
    // innermost lexical region whose target still lies ahead, and use only its
    // first marker as the end of exception provenance. This excludes the
    // forwarders' finalizer bodies without letting duplicate inner markers
    // accidentally terminate an enclosing region.
    let mut active_regions = Vec::<usize>::new();
    for (op_index, op) in ops.iter().enumerate() {
        while active_regions
            .last()
            .is_some_and(|region_id| regions[*region_id].target_index <= op_index)
        {
            active_regions.pop();
        }

        if let Some(&region_id) = region_by_begin.get(&op_index) {
            if active_regions.last().is_some_and(|parent_id| {
                regions[region_id].target_index > regions[*parent_id].target_index
            }) {
                return Err(LoweringPipelineError::InvariantViolation {
                    detail: "lowered protected regions cross instead of nesting",
                });
            }
            active_regions.push(region_id);
        }

        if !matches!(op.inner(), Ir1Op::EndTry) {
            continue;
        }
        let Some(&region_id) = active_regions.last() else {
            return Err(LoweringPipelineError::InvariantViolation {
                detail: "lowered EndTry is outside a protected region",
            });
        };
        regions[region_id].end_index.get_or_insert(op_index);
    }

    let mut starts = BTreeMap::<usize, Vec<u32>>::new();
    let mut ends = BTreeMap::<usize, Vec<u32>>::new();
    let mut labels = BTreeMap::<u32, Label>::new();

    for region in regions {
        let Some(end_index) = region.end_index else {
            return Err(LoweringPipelineError::InvariantViolation {
                detail: "lowered protected region has no EndTry marker",
            });
        };
        let Some(catch_label) = region.catch_label else {
            continue;
        };
        // Even a data-independent engine failure can disclose internal error
        // details. Direct operands may raise this floor, but never lower it.
        labels.entry(catch_label).or_insert(Label::Internal);
        // An empty `try {}` protects no operation: its EndTry is the op its
        // region would start at, so the region would end before it began
        // (and flow simulation refused `try {} catch {}` as improperly
        // nested). Nothing in it can throw, so it has no region events.
        if end_index == region.start_index {
            continue;
        }
        starts
            .entry(region.start_index)
            .or_default()
            .push(catch_label);
        if ends.insert(end_index, vec![catch_label]).is_some() {
            return Err(LoweringPipelineError::InvariantViolation {
                detail: "multiple catch regions share one EndTry marker",
            });
        }
    }

    Ok((starts, ends, labels))
}

pub(super) fn hostcall_exception_is_operand_derived(
    capability: &str,
    inputs: &[FlowValue],
    host_io_exception_provenance: HostIoExceptionProvenance,
) -> bool {
    let all_inputs_are_closed = || inputs.iter().all(|value| value.shape.is_closed());

    // bd-dign3: entropy completion callbacks stay inside the interpreter's
    // deterministic bd-opsnv macrotask lane; the typed random-read request
    // carries only size/count operands. A deferred-callback argument is an
    // engine-consumed reference, not disclosed data, so it must not defeat
    // the operand-derived exception contract (its own body summary governs
    // the later macrotask invocation instead).
    if matches!(
        capability,
        "builtin:CryptoRandomBytes"
            | "builtin:CryptoRandomInt"
            | "builtin:CryptoRandomFillSync"
            | "builtin:CryptoRandomUUID"
    ) {
        return inputs
            .iter()
            .all(|value| value.shape == FlowValueShape::Callable || value.shape.is_closed());
    }

    if matches!(capability, "fs:read" | "fs:write") {
        return host_io_exception_provenance == HostIoExceptionProvenance::ProviderInternal
            && all_inputs_are_closed();
    }

    if matches!(
        capability,
        "builtin:CryptoCreateHash"
            | "builtin:CryptoCreateHmac"
            | "builtin:CryptoTimingSafeEqual"
            | "builtin:CryptoPbkdf2Sync"
            | "builtin:CryptoPbkdf2"
            | "builtin:CryptoScryptSync"
            | "builtin:CryptoCreateCipheriv"
            | "builtin:CryptoCreateDecipheriv"
            | "builtin:CryptoGetHashes"
            | "builtin:CryptoGetCiphers"
            | "builtin:CryptoConstants"
            | "builtin:ZlibConstants"
            | "builtin:OsConstants"
            | "builtin:CryptoInvalidRandomInt"
            | "builtin:CryptoObjectUpdate"
            | "builtin:CryptoObjectCopy"
            | "builtin:CryptoObjectFinal"
            | "builtin:CryptoObjectGetAuthTag"
            | "builtin:CryptoObjectSetAuthTag"
            // bd-53l89 slice 2: pure-compute Ed25519 sign/verify over
            // KeyPairActive handles and closed inputs.
            | "builtin:CryptoSign"
            | "builtin:CryptoVerify"
    ) {
        return inputs
            .iter()
            .all(|value| value.shape.is_closed() || value.crypto_origin.is_some());
    }

    match capability {
        // These product-path builtins are finite engine implementations: they
        // neither invoke guest code nor perform accessor/coercion callbacks.
        // Keep the closed-shape requirement because zlib also has distinct
        // callback entry points, while zlib/console can receive objects whose
        // transitive provenance is not summarized after escape yet. The
        // Internal exception floor below accounts for engine failures without
        // discarding stronger operand labels.
        "builtin:ConsoleLog"
        | "builtin:ConsoleError"
        | "builtin:ConsoleWarn"
        | "builtin:ConsoleInfo"
        | "console:log"
        | "console:error"
        | "console:warn"
        | "console:info"
        | "console:debug"
        | "console:trace"
        | "console:dir"
        | "console:dirxml"
        | "console:time"
        | "console:timeEnd"
        | "console:timeLog"
        | "console:count"
        | "console:countReset"
        | "console:group"
        | "console:groupCollapsed"
        | "console:groupEnd"
        | "console:assert"
        | "console:clear"
        | "console:table"
        // bd-dign3 follow-up: the whole zlib sync family shares this arm -
        // pure-compute engine implementations over closed inputs whose only
        // exceptional outcomes are engine-owned validation errors.
        | "builtin:ZlibGunzipSync"
        | "builtin:ZlibGzipSync"
        | "builtin:ZlibDeflateSync"
        | "builtin:ZlibInflateSync"
        | "builtin:ZlibDeflateRawSync"
        | "builtin:ZlibInflateRawSync"
        | "builtin:ZlibUnzipSync"
        // bd-zlib-residual-l6ev2: brotli sync codecs share the zlib family's
        // pure-compute contract — engine-owned compression over closed
        // inputs, exceptional outcomes are engine validation errors only.
        | "builtin:ZlibBrotliCompressSync"
        | "builtin:ZlibBrotliDecompressSync" => all_inputs_are_closed(),
        // These exact pure-compute entry points validate only primitive
        // arguments. Object inputs remain fail-high because their coercion or
        // transitive state does not yet have a complete static summary.
        "builtin:PathJoin"
        | "builtin:OsGetPriority"
        | "builtin:OsSetPriority"
        | "builtin:Url"
        | "builtin:UrlFileUrlToPath"
        | "builtin:UrlParse" => inputs
            .iter()
            .all(|value| value.shape == FlowValueShape::Primitive),
        "builtin:UrlFormat" => inputs.iter().all(|value| value.shape.is_closed()),
        // Object.keys is finite for primitives and for aggregates whose own
        // properties are still statically authenticated. Aggregates holding
        // summarized callables qualify too: keys() reads structural key
        // names only — never property values — so callable contents cannot
        // disclose unsummarized labels through the produced key array,
        // exactly as for plain fresh aggregates. Querystring.parse is
        // finite for primitive arguments and returns a fresh null-prototype
        // data object. Arbitrary objects remain fail-high: proxy traps,
        // accessors, or coercions can otherwise disclose unsummarized labels.
        "builtin:ObjectKeys" => matches!(inputs, [value]
            if matches!(value.shape, FlowValueShape::Primitive
                | FlowValueShape::FreshAggregate
                | FlowValueShape::CallableContainer
                | FlowValueShape::OwnKeyArray)),
        "builtin:ArrayIsArrayFunction" | "builtin:QuerystringModule" => inputs.is_empty(),
        // bd-9vouw.17: materializes an engine-owned builtin function value.
        _ if capability.starts_with(STATIC_VALUE_CAPABILITY_PREFIX) => inputs.is_empty(),
        _ if capability.starts_with("builtin:instanceof:") => true,
        "builtin:QuerystringParse" => !inputs.is_empty()
            && inputs
                .iter()
                .all(|value| value.shape == FlowValueShape::Primitive),
        // bd-dmnqx: net loopback constructors build engine-owned server and
        // socket aggregates from finite inputs — option bags and callbacks
        // the runtime stores as summarized listeners. Their results are
        // engine state mirrors, so closed data or summarized callables keep
        // the whole construction operand-derived; unknown shapes stay
        // fail-high.
        "builtin:NetCreateServer"
        | "builtin:NetConnect"
        | "builtin:NetCreateConnection"
        | "builtin:NetServerAddress"
        | "builtin:HttpCreateServer"
        | "builtin:HttpGet"
        | "builtin:HttpRequest"
        | "builtin:TlsCreateServer"
        | "builtin:TlsConnect"
        | "builtin:TlsCreateSecureContext"
        | "builtin:TlsCheckServerIdentity"
        | "builtin:TlsGetCiphers"
        | "builtin:TlsRootCertificates" => inputs.iter().all(|value| {
            value.shape.is_closed()
                || matches!(
                    value.shape,
                    FlowValueShape::Callable | FlowValueShape::CallableContainer
                )
        }),
        // qs.stringify walks own enumerable string keys of a closed data
        // object and formats primitive values. Fresh object literals and
        // parse results stay finite; unknown objects remain fail-high.
        "builtin:QuerystringStringify" => !inputs.is_empty()
            && inputs.iter().all(|value| value.shape.is_closed()),
        // The authenticated EventEmitter constructor reference is a finite
        // engine-owned value with no guest operands or callbacks.
        "builtin:EventEmitterConstructorRef" => inputs.is_empty(),
        // Private abort registration checks native slots and callable identity,
        // then allocates a listener record. It never invokes the listener or
        // guest getters/coercions; argument labels still join the result and
        // the Internal exception floor, while fatal budget refusals stay fatal.
        "builtin:EventsAddAbortListener" => inputs.len() == 2,
        // These constructors are intercepted only for the unshadowed native
        // globals. Closed direct inputs cover primitive lengths/offsets,
        // engine-owned ArrayBuffers/views, and fresh array literals without
        // admitting arbitrary array-like objects whose properties could carry
        // unsummarized provenance.
        "builtin:ArrayBuffer"
        | "builtin:Uint8Array"
        | "builtin:Int32Array"
        | "builtin:Uint32Array"
        | "builtin:Int8Array"
        | "builtin:Uint8ClampedArray"
        | "builtin:Int16Array"
        | "builtin:Uint16Array"
        | "builtin:Float32Array"
        | "builtin:Float64Array"
        | "builtin:BigInt64Array"
        | "builtin:BigUint64Array"
        | "builtin:DataView" => inputs.iter().all(|value| value.shape.is_closed()),
        // Unshadowed native Error-family constructors are finite engine
        // implementations for primitive arguments: stringifying a primitive
        // message never invokes guest coercion, so the only exceptional
        // outcomes are engine-owned (allocation) and operand-derived. Object
        // arguments — including an options/cause bag — keep the fail-high
        // default because ToString / property reads on them can run guest
        // code whose thrown values are not summarized here (bd-8y64t: this
        // is what lets `try { throw new Error("m") } catch (e) { e.message }`
        // work).
        "builtin:Error"
        | "builtin:TypeError"
        | "builtin:RangeError"
        | "builtin:ReferenceError"
        | "builtin:SyntaxError"
        | "builtin:EvalError"
        | "builtin:URIError" => inputs
            .iter()
            .all(|value| value.shape == FlowValueShape::Primitive),
        // These two receiver-aware Buffer observations are finite only when
        // slot zero came from the dedicated authenticated Buffer shape and
        // every method argument is statically primitive. `pop_flow_values`
        // reverses stack order, so the source receiver is the final input.
        "builtin:BufferObjectToString" | "builtin:BufferObjectReadUInt32LE" => {
            inputs.split_last().is_some_and(|(receiver, arguments)| {
                receiver.shape == FlowValueShape::BufferObject
                    && arguments
                        .iter()
                        .all(|value| value.shape == FlowValueShape::Primitive)
            })
        }
        // bd-dign3 follow-up: `buf.equals(other)` never throws for Buffer
        // operands and rejects non-buffer operands with an engine-owned
        // TypeError before any byte comparison, so a closed receiver plus
        // closed arguments bounds every exceptional outcome.
        "builtin:BufferObjectEquals" => {
            inputs.split_last().is_some_and(|(receiver, arguments)| {
                receiver.shape == FlowValueShape::BufferObject
                    && !arguments.is_empty()
                    && arguments.iter().all(|value| value.shape.is_closed())
            })
        }
        // Buffer.from and Buffer.alloc/allocUnsafe have a closed exception
        // contract for direct primitive arguments (bd-znj5l): Buffer.from
        // also admits a single fresh aggregate — an array literal is
        // engine-fresh, invalidated by any mutation or opaque escape, and
        // Buffer.from copies its enumerable elements through engine-owned
        // byte coercion without invoking guest code, the same trust the
        // Buffer.concat arm already places in its list argument. Generic
        // object arguments stay fail-high: array-likes, TypedArrays, and
        // iterables can carry accessors or unsummarized backing stores.
        // Buffer.alloc/allocUnsafe keep primitive-only arguments; their
        // allocation-size coercion is a different contract.
        "builtin:BufferFrom" | "builtin:BufferAlloc" | "builtin:BufferAllocUnsafe" => {
            !inputs.is_empty()
                && inputs.iter().all(|value| match value.shape {
                    FlowValueShape::Primitive => true,
                    FlowValueShape::FreshAggregate | FlowValueShape::ClosedResult => {
                        capability == "builtin:BufferFrom"
                    }
                    _ => false,
                })
        }
        "builtin:ArrayFrom" => {
            !inputs.is_empty()
                && inputs.iter().all(|value| {
                    value.shape.is_closed()
                        || matches!(
                            value.shape,
                            FlowValueShape::Callable | FlowValueShape::CallableContainer
                        )
                })
        }
        // Buffer.concat is finite only when its list is a fresh aggregate of
        // closed elements. Passive binding storage may retain that proof, but
        // every mutation, opaque escape, or control-flow merge invalidates it.
        "builtin:BufferConcat" => inputs.last().is_some_and(|list| {
            list.shape == FlowValueShape::FreshAggregate
                && inputs[..inputs.len() - 1]
                    .iter()
                    .all(|value| value.shape == FlowValueShape::Primitive)
        }),
        _ => false,
    }
}

pub(super) fn ir1_exception_flow_label(
    op: &Ir1Op,
    inferred_label: &Label,
    operation_exception_is_operand_derived: bool,
    is_event_emitter_error_throw: bool,
) -> Option<Label> {
    match op {
        // An explicit throw carries precisely the thrown value's provenance.
        Ir1Op::Throw => Some(inferred_label.clone()),
        // Finite engine-owned hostcalls derive both results and validation
        // errors from their direct operands. Dynamic hostcalls have no such
        // closed contract and therefore remain fail-high.
        Ir1Op::HostCall { .. } if operation_exception_is_operand_derived => {
            Some(Label::Internal.join(inferred_label))
        }
        // Unary operations over a statically primitive operand cannot invoke
        // guest coercion. `typeof`, `void`, and logical-not are non-coercing for
        // every operand shape. Their only exceptional outcomes are therefore
        // engine-owned and direct-operand-derived; object/unknown operands to
        // numeric/bitwise unary operators still fail high below.
        Ir1Op::UnaryOp { .. } if operation_exception_is_operand_derived => {
            Some(Label::Internal.join(inferred_label))
        }
        // bd-pafik: an Await whose operand carries an authenticated pipeline
        // rejection summary throws at most that summary (routed here through
        // the exception-label override); every other Await stays fail-high
        // below.
        Ir1Op::Await if operation_exception_is_operand_derived => {
            Some(Label::Internal.join(inferred_label))
        }
        // Node EventEmitter error-channel parity (runtime
        // emit_event_listener_snapshot): with no listener registered,
        // emit("error", payload) throws the payload value itself carrying
        // the joined emit-argument labels; a payload-less emit throws an
        // engine-constructed Error and stays fail-high below.
        //
        // Finite engine methods (summarized callee, primitive receiver, or
        // closed aggregate) share the HostCall operand-derived exception
        // contract. Without this, `'x'.repeat(n)` inside `try` around
        // `tls.connect({ servername })` poisoned catch as TopSecret and
        // denied `console.log(error.name)` (bd-jux2l).
        Ir1Op::CallMethod { .. }
            if is_event_emitter_error_throw || operation_exception_is_operand_derived =>
        {
            Some(Label::Internal.join(inferred_label))
        }
        // Named builtins are fail-high unless their exception contract is
        // explicitly audited above. Some finite hostcalls synchronously run
        // guest callbacks, whose thrown values are not summarized by their
        // direct IR2 operands (for example Array.from and Array#some).
        Ir1Op::HostCall { .. } => Some(Label::TopSecret),
        // User code, accessors, coercions, iterators, and resumed computations
        // can throw values that direct IR2 operands do not summarize yet.
        Ir1Op::Construct { .. } if operation_exception_is_operand_derived => {
            Some(Label::Internal.join(inferred_label))
        }
        // bd-kx70h engine residual: a static property read on a closed
        // receiver touches only data descriptors the engine itself
        // materialized, so it cannot invoke guest accessors or throw guest
        // values; its exceptional outcomes are engine-owned. Dynamic keys
        // and open receivers stay fail-high in the default arm below.
        Ir1Op::GetProperty { .. } if operation_exception_is_operand_derived => {
            Some(Label::Internal.join(inferred_label))
        }
        Ir1Op::Call { .. }
        | Ir1Op::CallMethod { .. }
        | Ir1Op::ConstructSuper { .. }
        | Ir1Op::RegisterDerivedConstructor { .. }
        | Ir1Op::Await
        | Ir1Op::Yield { .. }
        | Ir1Op::GetProperty { .. }
        | Ir1Op::SetProperty { .. }
        | Ir1Op::DefineAccessor { .. }
        | Ir1Op::DefineMethod { .. }
        | Ir1Op::DeleteProperty { .. }
        | Ir1Op::BinaryOp { .. }
        | Ir1Op::UnaryOp { .. }
        | Ir1Op::ForInInit
        | Ir1Op::ForInNext { .. }
        | Ir1Op::ForOfInit
        | Ir1Op::ForOfNext { .. }
        | Ir1Op::IteratorClose { .. }
        | Ir1Op::SpreadIntoArray
        | Ir1Op::SpreadIntoObject
        | Ir1Op::ImportModule { .. } => Some(Label::TopSecret),
        // Allocation and deterministic primitive operations can still fail for
        // engine-internal reasons, while any disclosed operand data retains its
        // inferred label.
        Ir1Op::NewArray { .. } | Ir1Op::NewObject { .. } | Ir1Op::ArraySlice => {
            Some(Label::Internal.join(inferred_label))
        }
        Ir1Op::TemplateLiteral { .. }
        | Ir1Op::AssignOp { .. }
        | Ir1Op::LoadName { .. }
        | Ir1Op::ResolveNameStatus { .. }
        | Ir1Op::PutName { .. }
        | Ir1Op::PutNameWithStatus { .. } => Some(Label::Internal.join(inferred_label)),
        _ => None,
    }
}

type SimulatedIr2FlowLabels = (Vec<Label>, bool, BTreeSet<usize>, BTreeSet<usize>);

pub(super) fn simulate_ir2_flow_labels<O: FlowOp>(
    ops: &[O],
    binding_labels: &mut BTreeMap<BindingId, Label>,
    catch_region_events: &CatchRegionEvents,
    host_io_exception_provenance: HostIoExceptionProvenance,
    summary_depth: usize,
) -> Result<SimulatedIr2FlowLabels, LoweringPipelineError> {
    let mut value_stack = Vec::<FlowValue>::new();
    let mut next_identity = 0usize;
    let (catch_region_starts, catch_region_ends, initial_catch_entry_labels) = catch_region_events;
    let mut catch_entry_labels = initial_catch_entry_labels.clone();
    // bd-pafik: identities of live catch-entry values and the op indexes of
    // the binding stores that consume one. A catch-parameter store is where
    // exception provenance becomes observable to source code, so the
    // annotation pass materializes a flow annotation there even though
    // ordinary binding stores stay unannotated.
    let mut catch_entry_identities = BTreeSet::<usize>::new();
    let mut catch_entry_store_indexes = BTreeSet::<usize>::new();
    let mut hmac_update_indexes = BTreeSet::<usize>::new();
    let mut active_catch_regions = Vec::<u32>::new();
    let mut iterator_cleanup_labels = BTreeMap::<u32, usize>::new();
    let mut binding_crypto_origins = BTreeMap::<BindingId, Option<usize>>::new();
    let mut binding_flow_shapes = BindingFlowShapes::default();
    let mut crypto_flow_states = BTreeMap::<usize, CryptoFlowObjectState>::new();
    // bd-pafik: authenticated stream callback-error states (keyed by the
    // constructing hostcall's op index), static pipeline rejection summaries
    // (keyed by the pipeline hostcall's op index), and the binding round-trip
    // map that lets `const sink = new Writable({...})` keep its provenance.
    let mut stream_states = BTreeMap::<usize, StreamCallbackSummary>::new();
    let mut pipeline_rejections = BTreeMap::<usize, Label>::new();
    let mut binding_stream_infos = BTreeMap::<BindingId, StreamFlowInfo>::new();
    let mut inferred_labels = Vec::with_capacity(ops.len());
    let mut bindings_changed = false;

    for (op_index, op) in ops.iter().enumerate() {
        if let Some(ending) = catch_region_ends.get(&op_index) {
            for catch_label in ending {
                if active_catch_regions.pop().as_ref() != Some(catch_label) {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "catch region termination is not properly nested",
                    });
                }
            }
        }
        if let Some(starting) = catch_region_starts.get(&op_index) {
            active_catch_regions.extend(starting.iter().copied());
        }
        let mut operation_exception_is_operand_derived = false;
        let mut operation_exception_is_event_emitter_error = false;
        let mut operation_exception_label_override = None;
        let inferred = match op.inner() {
            Ir1Op::LoadLiteral { value } => {
                let label = infer_data_label_for_op(op.inner(), binding_labels, Label::Public);
                let mut flow_value = fresh_shaped_flow_value(
                    label.clone(),
                    FlowValueShape::Primitive,
                    &mut next_identity,
                );
                if let Ir1Literal::String(raw) = value {
                    flow_value.process_operation = raw
                        .as_str()
                        .and_then(ChildProcessOperation::from_discriminator);
                    // bd-zco6t: an engine-emitted fs NUL-sentinel discriminator
                    // identifies the concrete fs operation for the HostCall
                    // result-shape rules below. Guest strings cannot begin
                    // with NUL through the parser, so this is lowering-owned.
                    flow_value.fs_operation = raw
                        .as_str()
                        .and_then(|text| text.strip_prefix("\0fsop:"))
                        .and_then(FsOperation::parse_name);
                }
                value_stack.push(flow_value);
                label
            }
            Ir1Op::LoadBinding { binding_id } => {
                let crypto_origin = binding_crypto_origins
                    .get(binding_id)
                    .copied()
                    .flatten()
                    .filter(|origin| crypto_flow_states.contains_key(origin));
                let label = crypto_origin
                    .and_then(|origin| crypto_flow_states.get(&origin))
                    .map(|state| state.lifecycle_label.clone())
                    .or_else(|| binding_labels.get(binding_id).cloned())
                    .unwrap_or(Label::Internal);
                let mut value =
                    fresh_crypto_flow_value(label.clone(), crypto_origin, &mut next_identity);
                value.shape = binding_flow_shapes
                    .get(binding_id)
                    .copied()
                    .unwrap_or(FlowValueShape::Unknown);
                // bd-pafik: restore stream provenance across the binding
                // round-trip, but only while its origin state still exists.
                value.stream = binding_stream_infos
                    .get(binding_id)
                    .filter(|info| match info {
                        StreamFlowInfo::Stream { origin } => stream_states.contains_key(origin),
                        StreamFlowInfo::PipelinePromise { origin } => {
                            pipeline_rejections.contains_key(origin)
                        }
                        StreamFlowInfo::CallbackCarrier(_) => false,
                    })
                    .cloned();
                value_stack.push(value);
                label
            }
            Ir1Op::LoadName { name, .. } => {
                let label = Label::Internal;
                let shape = if name == "Function" {
                    FlowValueShape::FunctionConstructor
                } else if matches!(name.as_str(), "undefined" | "NaN" | "Infinity") {
                    FlowValueShape::Primitive
                } else if matches!(
                    name.as_str(),
                    "Error"
                        | "TypeError"
                        | "RangeError"
                        | "SyntaxError"
                        | "ReferenceError"
                        | "URIError"
                        | "EvalError"
                        | "Array"
                        | "Object"
                        | "String"
                        | "Number"
                        | "Boolean"
                        | "Symbol"
                        | "BigInt"
                ) {
                    FlowValueShape::Callable
                } else {
                    FlowValueShape::Unknown
                };
                value_stack.push(fresh_shaped_flow_value(
                    label.clone(),
                    shape,
                    &mut next_identity,
                ));
                label
            }
            Ir1Op::ResolveNameStatus { .. } => Label::Internal,
            Ir1Op::DeleteName { .. } => {
                // The boolean delete result observes whether a dynamic name
                // was resident; treat it as an Internal primitive, mirroring
                // the dynamic-name load lane.
                let label = Label::Internal;
                value_stack.push(fresh_shaped_flow_value(
                    label.clone(),
                    FlowValueShape::Primitive,
                    &mut next_identity,
                ));
                label
            }
            Ir1Op::StoreBinding { binding_id } | Ir1Op::InitializeBinding { binding_id } => {
                let mut value = pop_flow_value(&mut value_stack)?;
                if catch_entry_identities.contains(&value.identity) {
                    catch_entry_store_indexes.insert(op_index);
                }
                bindings_changed |= join_binding_label(binding_labels, *binding_id, &value.label);
                binding_crypto_origins.insert(*binding_id, value.crypto_origin);
                binding_flow_shapes.insert(*binding_id, value.shape);
                // bd-pafik: stream and pipeline-promise provenance survives
                // binding storage; callback carriers deliberately do not
                // (options objects must flow literally into the stream
                // constructor to stay authenticated).
                match &value.stream {
                    Some(
                        info @ (StreamFlowInfo::Stream { .. }
                        | StreamFlowInfo::PipelinePromise { .. }),
                    ) => {
                        binding_stream_infos.insert(*binding_id, info.clone());
                    }
                    _ => {
                        binding_stream_infos.remove(binding_id);
                    }
                }
                let label = value.label.clone();
                // The binding retains a straight-line closed-shape proof until
                // an operation below can mutate or escape it. The assignment
                // expression's stack copy is no longer a fresh value. Preserve
                // only dedicated finite-method receivers long enough for the
                // generic method-call lowering's synthetic receiver binding:
                // it emits StoreBinding, GetProperty, then LoadBinding.
                // GetProperty immediately invalidates the stored alias, so the
                // proof cannot survive a mutation or opaque escape.
                if !matches!(
                    value.shape,
                    FlowValueShape::OwnKeyArray
                        | FlowValueShape::EventEmitterObject
                        | FlowValueShape::BufferObject
                        | FlowValueShape::ClosedResult
                        | FlowValueShape::FreshAggregate
                        | FlowValueShape::ConstantsObject
                ) {
                    invalidate_nonprimitive_flow_shapes(std::slice::from_mut(&mut value));
                }
                value_stack.push(value);
                label
            }
            Ir1Op::PutName { .. } | Ir1Op::PutNameWithStatus { .. } => {
                let mut value = pop_flow_value(&mut value_stack)?;
                let label = value.label.clone();
                invalidate_nonprimitive_flow_shapes(std::slice::from_mut(&mut value));
                value_stack.push(value);
                label
            }
            Ir1Op::CreatePerIterationBinding { binding_id, .. } => binding_labels
                .get(binding_id)
                .cloned()
                .unwrap_or(Label::Internal),
            Ir1Op::Call { arg_count } => {
                let mut inputs = pop_flow_values(&mut value_stack, *arg_count as usize)?;
                let callee = pop_flow_value(&mut value_stack)?;
                let callee_shape = callee.shape;
                let callee_is_summarized = matches!(
                    callee_shape,
                    FlowValueShape::Callable | FlowValueShape::ArrayIsArrayFunction
                );
                inputs.push(callee);
                let label = if callee_is_summarized {
                    join_flow_values(&inputs)
                } else {
                    Label::TopSecret
                };
                invalidate_heap_backed_flow_shapes(&mut value_stack);
                invalidate_heap_backed_binding_flow_shapes(&mut binding_flow_shapes);
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                let result_shape = if callee_shape == FlowValueShape::ArrayIsArrayFunction {
                    FlowValueShape::Primitive
                } else {
                    FlowValueShape::Unknown
                };
                value_stack.push(fresh_shaped_flow_value(
                    label.clone(),
                    result_shape,
                    &mut next_identity,
                ));
                label
            }
            Ir1Op::CallMethod { arg_count } => {
                let mut inputs = pop_flow_values(&mut value_stack, *arg_count as usize)?;
                // Stack layout is `[..., callee, receiver, arg0, ...]`,
                // matching both IR1 -> IR3 lowering paths above. Pop the
                // receiver before the callee so finite receiver-aware method
                // shapes (notably EventEmitter.on/once/emit) are attributed
                // to the callable rather than mistaken for the receiver.
                let receiver = pop_flow_value(&mut value_stack)?;
                let receiver_shape = receiver.shape;
                let callee = pop_flow_value(&mut value_stack)?;
                let callee_shape = callee.shape;
                if ifc_debug_enabled() {
                    eprintln!(
                        "[ifc-debug] CallMethod arg_count={arg_count} callee_shape={callee_shape:?} receiver_shape={:?}",
                        receiver_shape
                    );
                }
                // bd-l0d6z Node parity: emit("error", payload) with no
                // listener throws the payload VALUE itself, labeled with the
                // joined emit-argument labels (runtime
                // emit_event_listener_snapshot pairs arguments.first() with
                // emission_label). With no payload argument the engine
                // constructs its own Error, which stays fail-high below.
                if callee_shape == FlowValueShape::EventEmitterEmitMethod && *arg_count >= 2 {
                    operation_exception_is_event_emitter_error = true;
                    operation_exception_label_override = Some(join_flow_values(&inputs));
                }
                let callee_is_summarized = matches!(
                    callee_shape,
                    FlowValueShape::Callable
                        | FlowValueShape::OwnKeyJoinMethod
                        | FlowValueShape::EventEmitterFluentMethod
                        | FlowValueShape::EventEmitterEmitMethod
                );
                // bd-zk58q: an argument that can run guest code (a callback,
                // or coercion hooks) can throw or return a value that no
                // operand label covers. `Buffer.from('x').map(() => { throw
                // secret })` reached its catch as Internal and printed.
                let arguments_are_inert = inputs
                    .iter()
                    .all(|argument| argument.shape.argument_cannot_run_guest_code());
                inputs.push(callee);
                inputs.push(receiver);
                // Primitive receivers (`str.startsWith`, `str.endsWith`) and
                // engine-owned closed aggregates (hermetic net/tls sockets
                // and `tls.rootCertificates` entries) are finite operations
                // over the receiver's own label. Failing them high made
                // nested TLS callbacks a TopSecret -> Internal console
                // denial after nested-body IFC walking (bd-jux2l / bd-wyazf).
                // That shortcut holds only while no argument can run guest
                // code; otherwise the call fails high, bounded by the lowering
                // unit's label ceiling (bd-9vouw.1), so programs without a
                // sensitive source are unaffected.
                let finite_engine_method = callee_is_summarized
                    || ((receiver_shape == FlowValueShape::Primitive
                        || receiver_shape.is_closed())
                        && arguments_are_inert);
                // Payload-less EventEmitter.emit stays fail-high (engine Error).
                // The payload-throw path is handled via
                // `operation_exception_is_event_emitter_error` above.
                operation_exception_is_operand_derived =
                    finite_engine_method && callee_shape != FlowValueShape::EventEmitterEmitMethod;
                let label = if finite_engine_method {
                    join_flow_values(&inputs)
                } else {
                    Label::TopSecret
                };
                // Array.prototype.join on an authenticated Object.keys array
                // cannot mutate or escape unrelated closed bindings still
                // live for a later stringify or own-property read.
                if callee_shape != FlowValueShape::OwnKeyJoinMethod {
                    invalidate_nonprimitive_flow_shapes(&mut value_stack);
                    invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                }
                let result_shape = match callee_shape {
                    FlowValueShape::OwnKeyJoinMethod => FlowValueShape::Primitive,
                    FlowValueShape::EventEmitterFluentMethod => FlowValueShape::EventEmitterObject,
                    FlowValueShape::EventEmitterEmitMethod => FlowValueShape::Primitive,
                    _ if receiver_shape == FlowValueShape::Primitive => FlowValueShape::Primitive,
                    _ => FlowValueShape::Unknown,
                };
                value_stack.push(fresh_shaped_flow_value(
                    label.clone(),
                    result_shape,
                    &mut next_identity,
                ));
                label
            }
            Ir1Op::Return => {
                if op_index + 1 == ops.len() {
                    value_stack
                        .last()
                        .map_or(Label::Public, |value| value.label.clone())
                } else {
                    pop_flow_value(&mut value_stack)?.label
                }
            }
            Ir1Op::ImportModule { .. } => {
                let label = Label::Internal;
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                value_stack.push(fresh_flow_value(label.clone(), &mut next_identity));
                label
            }
            Ir1Op::ExportBinding { .. } => {
                let mut value = pop_flow_value(&mut value_stack)?;
                let label = value.label.clone();
                invalidate_nonprimitive_flow_shapes(std::slice::from_mut(&mut value));
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                value_stack.push(value);
                label
            }
            Ir1Op::Await | Ir1Op::Yield { .. } => {
                let value = pop_flow_value(&mut value_stack)?;
                // bd-pafik: Await transfers static settlement provenance. A
                // pipeline promise with an authenticated rejection summary
                // bounds what this Await can throw into the enclosing catch;
                // every other awaited value keeps the fail-high default.
                if matches!(op.inner(), Ir1Op::Await)
                    && let Some(StreamFlowInfo::PipelinePromise { origin }) = &value.stream
                    && let Some(rejection) = pipeline_rejections.get(origin)
                {
                    operation_exception_is_operand_derived = true;
                    // The rejection summary alone is the bound; the operand's
                    // own value label is the pipeline result label, which the
                    // authenticated path already set to this same summary.
                    operation_exception_label_override = Some(rejection.clone());
                }
                // Await resumes with a Promise settlement and Yield resumes
                // with a caller-supplied value. Neither output is an identity
                // transform of the suspended operand, so retain the historic
                // unknown-runtime floor while also preserving any stronger
                // direct-input label.
                let label = Label::Internal.join(&value.label);
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                value_stack.push(fresh_flow_value(label.clone(), &mut next_identity));
                label
            }
            Ir1Op::Nop => {
                let value = pop_flow_value(&mut value_stack)?;
                let label = value.label.clone();
                value_stack.push(value);
                label
            }
            Ir1Op::Pop | Ir1Op::Discard | Ir1Op::Throw => pop_flow_value(&mut value_stack)?.label,
            Ir1Op::BeginTry {
                catch_label: _,
                finally_label: _,
            } => Label::Public,
            Ir1Op::EndTry
            | Ir1Op::EnterFinally
            | Ir1Op::EndFinally
            | Ir1Op::DiscardAbruptCompletion => Label::Public,
            Ir1Op::BinaryOp { operator } => {
                if matches!(
                    operator,
                    BinaryOperator::LogicalAnd
                        | BinaryOperator::LogicalOr
                        | BinaryOperator::NullishCoalescing
                ) {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "logical operators must be short-circuit lowered before IR3",
                    });
                }
                let inputs = pop_flow_values(&mut value_stack, 2)?;
                let label = join_flow_values(&inputs);
                operation_exception_is_operand_derived = inputs
                    .iter()
                    .all(|value| value.shape == FlowValueShape::Primitive);
                if !operation_exception_is_operand_derived {
                    invalidate_nonprimitive_flow_shapes(&mut value_stack);
                    invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                }
                // Every successful ECMAScript binary operation produces a
                // primitive. Object operands can still run guest coercions,
                // so only all-primitive inputs receive the bounded exception
                // contract above; the result value-kind remains primitive in
                // either case, matching the UnaryOp rule below.
                value_stack.push(fresh_shaped_flow_value(
                    label.clone(),
                    FlowValueShape::Primitive,
                    &mut next_identity,
                ));
                label
            }
            Ir1Op::UnaryOp { operator } => {
                if matches!(
                    operator,
                    UnaryOperator::Delete | UnaryOperator::StrictDelete
                ) {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "delete must lower through delete_property or literal-true path before IR3",
                    });
                }
                let value = pop_flow_value(&mut value_stack)?;
                let operand_is_primitive = value.shape == FlowValueShape::Primitive;
                let operator_is_noncoercing = matches!(
                    operator,
                    UnaryOperator::LogicalNot | UnaryOperator::Typeof | UnaryOperator::Void
                );
                operation_exception_is_operand_derived =
                    operand_is_primitive || operator_is_noncoercing;
                let label = value.label;
                if !operation_exception_is_operand_derived {
                    invalidate_nonprimitive_flow_shapes(&mut value_stack);
                    invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                }
                // Every successful ECMAScript unary operation produces a
                // primitive, even when a numeric/bitwise operator first runs
                // an object coercion whose exception path must remain fail-high.
                value_stack.push(fresh_shaped_flow_value(
                    label.clone(),
                    FlowValueShape::Primitive,
                    &mut next_identity,
                ));
                label
            }
            Ir1Op::AssignOp {
                binding_id,
                operator,
                ..
            } => {
                if matches!(
                    operator,
                    AssignmentOperator::LogicalAndAssign
                        | AssignmentOperator::LogicalOrAssign
                        | AssignmentOperator::NullishCoalescingAssign
                ) {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "logical compound assignments must be short-circuit lowered before IR3",
                    });
                }
                let may_coerce = !matches!(operator, AssignmentOperator::Assign);
                let rhs = pop_flow_value(&mut value_stack)?;
                let label = if matches!(operator, AssignmentOperator::Assign) {
                    rhs.label
                } else {
                    binding_labels
                        .get(binding_id)
                        .cloned()
                        .unwrap_or(Label::Internal)
                        .join(&rhs.label)
                };
                bindings_changed |= join_binding_label(binding_labels, *binding_id, &label);
                binding_crypto_origins.insert(*binding_id, None);
                binding_flow_shapes.insert(
                    *binding_id,
                    match rhs.shape {
                        FlowValueShape::Primitive => FlowValueShape::Primitive,
                        FlowValueShape::Callable => FlowValueShape::Callable,
                        _ => FlowValueShape::Unknown,
                    },
                );
                if may_coerce {
                    invalidate_nonprimitive_flow_shapes(&mut value_stack);
                    invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                }
                value_stack.push(fresh_flow_value(label.clone(), &mut next_identity));
                label
            }
            Ir1Op::Label { id } => {
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                if let Some(catch_label) = catch_entry_labels.get(id) {
                    let value = fresh_flow_value(catch_label.clone(), &mut next_identity);
                    catch_entry_identities.insert(value.identity);
                    value_stack.push(value);
                }
                if iterator_cleanup_labels.get(id).is_some_and(|expected| {
                    value_stack
                        .last()
                        .is_some_and(|value| value.identity == *expected)
                }) {
                    value_stack.pop();
                }
                Label::Public
            }
            Ir1Op::Jump { .. } => {
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                Label::Public
            }
            Ir1Op::JumpIfFalsy { .. } => {
                let value = pop_flow_value(&mut value_stack)?;
                let label = value.label.clone();
                value_stack.push(value);
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                invalidate_heap_backed_flow_shapes(&mut value_stack);
                invalidate_heap_backed_binding_flow_shapes(&mut binding_flow_shapes);
                label
            }
            Ir1Op::JumpIfFalsyConsume { .. }
            | Ir1Op::JumpIfTruthy { .. }
            | Ir1Op::JumpIfNullish { .. } => {
                let label = pop_flow_value(&mut value_stack)?.label;
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                invalidate_heap_backed_flow_shapes(&mut value_stack);
                invalidate_heap_backed_binding_flow_shapes(&mut binding_flow_shapes);
                label
            }
            Ir1Op::GetProperty { key } => {
                let mut inputs = Vec::with_capacity(2);
                if matches!(key, Ir1PropertyKey::Dynamic) {
                    inputs.push(pop_flow_value(&mut value_stack)?);
                }
                let object = pop_flow_value(&mut value_stack)?;
                // bd-kx70h: a static read on an UNFORGEABLE engine-branded
                // receiver is finite (the runtime owns the layout; guest
                // Object.defineProperty cannot retrofit accessors onto
                // branded objects), so the read's exceptional outcomes are
                // engine-owned. FreshAggregate is guest-mutable through
                // defineProperty and stays excluded; dynamic keys and open
                // receivers leave the flag false and stay fail-high.
                operation_exception_is_operand_derived =
                    matches!(
                        object.shape,
                        FlowValueShape::EventEmitterObject
                            | FlowValueShape::ConstantsObject
                            | FlowValueShape::OwnKeyArray
                            | FlowValueShape::BufferObject
                            | FlowValueShape::ClosedResult
                            | FlowValueShape::Primitive
                    ) && matches!(key, Ir1PropertyKey::Static(_));
                let shape = match (&object.shape, key) {
                    (FlowValueShape::ConstantsObject, _) => FlowValueShape::Primitive,
                    (FlowValueShape::CallableContainer, _) => FlowValueShape::Callable,
                    (FlowValueShape::EventEmitterObject, Ir1PropertyKey::Static(key))
                        if matches!(key.as_str(), Some("on" | "once")) =>
                    {
                        FlowValueShape::EventEmitterFluentMethod
                    }
                    (FlowValueShape::EventEmitterObject, Ir1PropertyKey::Static(key))
                        if key.as_str() == Some("emit") =>
                    {
                        FlowValueShape::EventEmitterEmitMethod
                    }
                    (FlowValueShape::OwnKeyArray, Ir1PropertyKey::Static(key))
                        if key.as_str() == Some("join") =>
                    {
                        FlowValueShape::OwnKeyJoinMethod
                    }
                    // bd-h7p1a: finite engine-owned array methods on an
                    // authenticated Object.keys result produce another finite
                    // own-key array; `.length` is a primitive numeric property.
                    (FlowValueShape::OwnKeyArray, Ir1PropertyKey::Static(key))
                        if matches!(key.as_str(), Some("sort" | "map" | "slice" | "filter")) =>
                    {
                        FlowValueShape::OwnKeyArray
                    }
                    (FlowValueShape::OwnKeyArray, Ir1PropertyKey::Static(key))
                        if matches!(key.as_str(), Some("length" | "size")) =>
                    {
                        FlowValueShape::Primitive
                    }
                    // receivers, mirroring the OwnKeyArray `.join` proof.
                    // `String.prototype.includes` on a primitive receiver and
                    // the authenticated Buffer's `toString`/`readUInt32LE`
                    // are engine-owned implementations, so the method value
                    // is a summarized callable and the subsequent CallMethod
                    // stays JoinInputs instead of the fail-high TopSecret.
                    (
                        FlowValueShape::Primitive | FlowValueShape::ClosedResult,
                        Ir1PropertyKey::Static(key),
                    ) if matches!(
                        key.as_str(),
                        Some(
                            "includes"
                                | "repeat"
                                | "slice"
                                | "substring"
                                | "trim"
                                | "toLowerCase"
                                | "toUpperCase"
                                | "concat"
                                | "indexOf"
                                | "charAt"
                                | "charCodeAt"
                                | "startsWith"
                                | "endsWith"
                                | "split"
                        )
                    ) =>
                    {
                        FlowValueShape::Callable
                    }
                    (
                        FlowValueShape::ClosedResult | FlowValueShape::FreshAggregate,
                        Ir1PropertyKey::Static(key),
                    ) if matches!(key.as_str(), Some("toString" | "valueOf")) => {
                        // bd-dign3: engine-owned closed data and fresh
                        // aggregates coerce through the engine's own
                        // ToString, never guest code, so the method value is
                        // summarized exactly like the Buffer lane above.
                        FlowValueShape::Callable
                    }
                    (FlowValueShape::BufferObject, Ir1PropertyKey::Static(key))
                        if matches!(key.as_str(), Some("toString" | "readUInt32LE" | "equals")) =>
                    {
                        FlowValueShape::Callable
                    }
                    // bd-jux2l: engine-owned arrays (`tls.rootCertificates`,
                    // `tls.getCiphers()`) expose finite `length` and index
                    // reads. Without this, `roots[0].startsWith` saw an
                    // Unknown receiver and fail-high CallMethod poisoned
                    // the console sink.
                    (
                        FlowValueShape::ClosedResult | FlowValueShape::FreshAggregate,
                        Ir1PropertyKey::Static(key),
                    ) if key.as_str() == Some("length") => FlowValueShape::Primitive,
                    // Engine-owned fresh aggregates (array literals, os.loadavg,
                    // etc.) expose the standard non-mutating Array.prototype
                    // methods. Treating the method value as a summarized
                    // callable keeps the CallMethod on the JoinInputs lane
                    // instead of fail-high TopSecret.
                    (FlowValueShape::FreshAggregate, Ir1PropertyKey::Static(key))
                        if matches!(
                            key.as_str(),
                            Some(
                                "join"
                                    | "slice"
                                    | "every"
                                    | "some"
                                    | "map"
                                    | "filter"
                                    | "sort"
                                    | "forEach"
                                    | "reduce"
                                    | "reduceRight"
                                    | "find"
                                    | "findIndex"
                                    | "indexOf"
                                    | "lastIndexOf"
                                    | "includes"
                                    | "flat"
                                    | "flatMap"
                            )
                        ) =>
                    {
                        FlowValueShape::Callable
                    }
                    (
                        FlowValueShape::ClosedResult | FlowValueShape::FreshAggregate,
                        Ir1PropertyKey::Dynamic,
                    ) => FlowValueShape::ClosedResult,
                    // bd-jux2l: TLSSocket observation methods are engine-owned
                    // even when the receiver is an isolated nested-body
                    // LoadBinding (Unknown shape). Without this, nested
                    // `c.getPeerCertificate()` / `getProtocol()` CallMethods
                    // fail-high TopSecret into console.log.
                    (
                        FlowValueShape::Unknown
                        | FlowValueShape::FreshAggregate
                        | FlowValueShape::ClosedResult,
                        Ir1PropertyKey::Static(key),
                    ) if matches!(
                        key.as_str(),
                        Some(
                            "getPeerCertificate"
                                | "getProtocol"
                                | "getCipher"
                                | "isSessionReused"
                                | "getSession"
                        )
                    ) =>
                    {
                        FlowValueShape::Callable
                    }
                    _ => FlowValueShape::Unknown,
                };
                inputs.push(object);
                let label = join_flow_values(&inputs);
                // Finite Object.keys `.join` lookup and engine-owned array
                // `length` / index / string-method lookups cannot alias-mutate
                // other closed values; keep FreshAggregate bindings intact
                // for later stringify or own-property reads on the same object.
                if !matches!(
                    shape,
                    FlowValueShape::OwnKeyJoinMethod
                        | FlowValueShape::Primitive
                        | FlowValueShape::ClosedResult
                        | FlowValueShape::Callable
                        | FlowValueShape::EventEmitterFluentMethod
                        | FlowValueShape::EventEmitterEmitMethod
                ) && inputs.last().map(|obj| obj.shape) != Some(FlowValueShape::ConstantsObject)
                {
                    invalidate_nonprimitive_flow_shapes(&mut value_stack);
                    invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                }
                value_stack.push(fresh_shaped_flow_value(
                    label.clone(),
                    shape,
                    &mut next_identity,
                ));
                label
            }
            Ir1Op::SetProperty { key, .. } => {
                let mut value = pop_flow_value(&mut value_stack)?;
                let value_is_callable = value.shape == FlowValueShape::Callable;
                let mut inputs = vec![value.clone()];
                if matches!(key, Ir1PropertyKey::Dynamic) {
                    inputs.push(pop_flow_value(&mut value_stack)?);
                }
                let mut object = pop_flow_value(&mut value_stack)?;
                if value_is_callable {
                    object.shape = FlowValueShape::CallableContainer;
                }
                inputs.push(object);
                let label = join_flow_values(&inputs);
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_flow_shapes(std::slice::from_mut(&mut value));
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                invalidate_heap_backed_flow_shapes(&mut value_stack);
                invalidate_heap_backed_binding_flow_shapes(&mut binding_flow_shapes);
                value_stack.push(value);
                label
            }
            Ir1Op::DefineAccessor { key, .. } | Ir1Op::DefineMethod { key } => {
                let function = pop_flow_value(&mut value_stack)?;
                let function_is_summarized = function.shape == FlowValueShape::Callable;
                let mut inputs = vec![function];
                if matches!(key, Ir1PropertyKey::Dynamic) {
                    inputs.push(pop_flow_value(&mut value_stack)?);
                }
                let mut object = pop_flow_value(&mut value_stack)?;
                if function_is_summarized {
                    object.shape = FlowValueShape::CallableContainer;
                }
                inputs.push(object.clone());
                let label = join_flow_values(&inputs);
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                value_stack.push(FlowValue {
                    identity: object.identity,
                    label: label.clone(),
                    crypto_origin: None,
                    shape: object.shape,
                    process_operation: None,
                    // bd-pafik: DefineMethod/DefineAccessor mutate the object
                    // after literal construction, so any callback-carrier
                    // proof it held no longer covers its contents.
                    stream: None,
                    fs_operation: None,
                });
                label
            }
            Ir1Op::DeleteProperty { key } => {
                let mut inputs = Vec::with_capacity(2);
                if matches!(key, Ir1PropertyKey::Dynamic) {
                    inputs.push(pop_flow_value(&mut value_stack)?);
                }
                inputs.push(pop_flow_value(&mut value_stack)?);
                let label = join_flow_values(&inputs);
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                invalidate_heap_backed_flow_shapes(&mut value_stack);
                invalidate_heap_backed_binding_flow_shapes(&mut binding_flow_shapes);
                value_stack.push(fresh_flow_value(label.clone(), &mut next_identity));
                label
            }
            Ir1Op::NewArray { count } => {
                let inputs = pop_flow_values(&mut value_stack, *count as usize)?;
                let label = join_flow_values(&inputs);
                let shape = if inputs.iter().all(|value| value.shape.is_closed()) {
                    FlowValueShape::FreshAggregate
                } else {
                    FlowValueShape::Unknown
                };
                value_stack.push(fresh_shaped_flow_value(
                    label.clone(),
                    shape,
                    &mut next_identity,
                ));
                label
            }
            Ir1Op::NewObject { count } => {
                let needed = (*count as usize)
                    .checked_mul(2)
                    .ok_or(LoweringPipelineError::ValueStackUnderflow)?;
                let inputs = pop_flow_values(&mut value_stack, needed)?;
                let label = join_flow_values(&inputs);
                let shape = if inputs
                    .iter()
                    .any(|value| value.shape == FlowValueShape::Callable)
                {
                    FlowValueShape::CallableContainer
                } else if inputs.iter().all(|value| value.shape.is_closed()) {
                    FlowValueShape::FreshAggregate
                } else {
                    FlowValueShape::Unknown
                };
                // bd-pafik: an object literal is a supported stream-options
                // carrier when every entry is closed data or a function
                // literal with a supported callback summary; the aggregated
                // summary joins the function summaries.
                let mut aggregated = StreamCallbackSummary::Supported(Label::Public);
                for input in &inputs {
                    match &input.stream {
                        Some(StreamFlowInfo::CallbackCarrier(summary)) => {
                            aggregated = aggregated.join(summary);
                        }
                        None if input.shape.is_closed() => {}
                        _ => {
                            aggregated = StreamCallbackSummary::Unsupported;
                        }
                    }
                }
                let mut value = fresh_shaped_flow_value(label.clone(), shape, &mut next_identity);
                value.stream = Some(StreamFlowInfo::CallbackCarrier(aggregated));
                value_stack.push(value);
                label
            }
            Ir1Op::ArrayPush
            | Ir1Op::ArraySlice
            | Ir1Op::SpreadIntoArray
            | Ir1Op::SpreadIntoObject => {
                let rhs = pop_flow_value(&mut value_stack)?;
                let lhs = pop_flow_value(&mut value_stack)?;
                let label = lhs.label.join(&rhs.label);
                let preserve_identity = matches!(
                    op.inner(),
                    Ir1Op::ArrayPush | Ir1Op::SpreadIntoArray | Ir1Op::SpreadIntoObject
                );
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                if preserve_identity {
                    value_stack.push(FlowValue {
                        identity: lhs.identity,
                        label: label.clone(),
                        crypto_origin: None,
                        shape: FlowValueShape::Unknown,
                        process_operation: None,
                        stream: None,
                        fs_operation: None,
                    });
                } else {
                    value_stack.push(fresh_flow_value(label.clone(), &mut next_identity));
                }
                label
            }
            Ir1Op::LoadThis | Ir1Op::LoadNewTarget | Ir1Op::LoadSuper => {
                let label = Label::Internal;
                value_stack.push(fresh_flow_value(label.clone(), &mut next_identity));
                label
            }
            Ir1Op::DeclareFunction {
                binding_id,
                param_names,
                rest_param_index,
                free_vars,
                free_var_ids,
                body_ops,
                ..
            } => {
                let label = infer_function_capture_label(
                    free_vars,
                    free_var_ids,
                    body_ops,
                    binding_labels,
                    host_io_exception_provenance,
                    summary_depth.saturating_add(1),
                );
                bindings_changed |= join_binding_label(binding_labels, *binding_id, &label);
                binding_flow_shapes.insert(*binding_id, FlowValueShape::Callable);
                let mut value = fresh_shaped_flow_value(
                    label.clone(),
                    FlowValueShape::Callable,
                    &mut next_identity,
                );
                value.stream = Some(stream_callback_carrier_for_function(
                    param_names,
                    *rest_param_index,
                    body_ops,
                    free_vars,
                    free_var_ids,
                    binding_labels,
                    &binding_flow_shapes,
                ));
                value_stack.push(value);
                label
            }
            Ir1Op::CreateFunction {
                param_names,
                rest_param_index,
                free_vars,
                free_var_ids,
                body_ops,
                ..
            } => {
                let label = infer_function_capture_label(
                    free_vars,
                    free_var_ids,
                    body_ops,
                    binding_labels,
                    host_io_exception_provenance,
                    summary_depth.saturating_add(1),
                );
                let carrier = stream_callback_carrier_for_function(
                    param_names,
                    *rest_param_index,
                    body_ops,
                    free_vars,
                    free_var_ids,
                    binding_labels,
                    &binding_flow_shapes,
                );
                let mut value = fresh_shaped_flow_value(
                    label.clone(),
                    FlowValueShape::Callable,
                    &mut next_identity,
                );
                value.stream = Some(carrier);
                value_stack.push(value);
                label
            }
            Ir1Op::ForInInit | Ir1Op::ForOfInit => {
                let source = pop_flow_value(&mut value_stack)?;
                let label = source.label;
                let shape = if source.shape.is_closed() {
                    FlowValueShape::ClosedResult
                } else {
                    FlowValueShape::Unknown
                };
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                value_stack.push(fresh_shaped_flow_value(
                    label.clone(),
                    shape,
                    &mut next_identity,
                ));
                label
            }
            Ir1Op::ForInNext { done_label } | Ir1Op::ForOfNext { done_label } => {
                let iterator = value_stack
                    .last()
                    .cloned()
                    .ok_or(LoweringPipelineError::ValueStackUnderflow)?;
                iterator_cleanup_labels
                    .entry(*done_label)
                    .or_insert(iterator.identity);
                let label = iterator.label;
                let shape = if matches!(op.inner(), Ir1Op::ForInNext { .. }) {
                    FlowValueShape::Primitive
                } else if iterator.shape.is_closed() {
                    FlowValueShape::ClosedResult
                } else {
                    FlowValueShape::Unknown
                };
                let iterator_shape = iterator.shape;
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                if let Some(top) = value_stack.last_mut() {
                    top.shape = iterator_shape;
                }
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                value_stack.push(fresh_shaped_flow_value(
                    label.clone(),
                    shape,
                    &mut next_identity,
                ));
                label
            }
            Ir1Op::IteratorClose { .. } => {
                let label = pop_flow_value(&mut value_stack)?.label;
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                label
            }
            Ir1Op::Construct { arg_count } => {
                let count = (*arg_count as usize)
                    .checked_add(1)
                    .ok_or(LoweringPipelineError::ValueStackUnderflow)?;
                let inputs = pop_flow_values(&mut value_stack, count)?;
                let label = join_flow_values(&inputs);
                let callee_shape = inputs
                    .last()
                    .map_or(FlowValueShape::Unknown, |callee| callee.shape);
                let arguments = &inputs[..inputs.len().saturating_sub(1)];
                operation_exception_is_operand_derived = match callee_shape {
                    // Callable-only native construction rejects with an
                    // engine-owned TypeError before invoking the builtin.
                    FlowValueShape::ArrayIsArrayFunction => true,
                    // Function source fragments cannot invoke guest coercion
                    // when every direct argument is already primitive.
                    FlowValueShape::FunctionConstructor => arguments
                        .iter()
                        .all(|argument| argument.shape == FlowValueShape::Primitive),
                    _ => false,
                };
                let result_shape = match callee_shape {
                    FlowValueShape::EventEmitterConstructor => FlowValueShape::EventEmitterObject,
                    FlowValueShape::FunctionConstructor => FlowValueShape::Callable,
                    _ => FlowValueShape::Unknown,
                };
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                value_stack.push(fresh_shaped_flow_value(
                    label.clone(),
                    result_shape,
                    &mut next_identity,
                ));
                label
            }
            Ir1Op::ConstructSuper { arg_count } => {
                let inputs = pop_flow_values(&mut value_stack, *arg_count as usize)?;
                let label = Label::Internal.join(&join_flow_values(&inputs));
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                value_stack.push(fresh_flow_value(label.clone(), &mut next_identity));
                label
            }
            Ir1Op::RegisterDerivedConstructor { .. } => {
                let inputs = pop_flow_values(&mut value_stack, 2)?;
                let label = Label::Internal.join(&join_flow_values(&inputs));
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                label
            }
            Ir1Op::TemplateLiteral { quasi_count } => {
                let count = if *quasi_count == 0 {
                    0
                } else {
                    (*quasi_count as usize)
                        .checked_mul(2)
                        .and_then(|count| count.checked_sub(1))
                        .ok_or(LoweringPipelineError::ValueStackUnderflow)?
                };
                let inputs = pop_flow_values(&mut value_stack, count)?;
                let label = join_flow_values(&inputs);
                invalidate_nonprimitive_flow_shapes(&mut value_stack);
                invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                value_stack.push(fresh_flow_value(label.clone(), &mut next_identity));
                label
            }
            Ir1Op::HostCall {
                capability,
                arg_count,
            } => {
                let inputs = pop_flow_values(&mut value_stack, *arg_count as usize)?;
                let hostcall_is_operand_derived = hostcall_exception_is_operand_derived(
                    capability,
                    &inputs,
                    host_io_exception_provenance,
                );
                operation_exception_is_operand_derived = hostcall_is_operand_derived;
                if !hostcall_is_operand_derived {
                    // Dynamic/callback-capable hostcalls can observe or mutate
                    // escaped values. Audited operand-derived hostcalls cannot,
                    // so they preserve unrelated closed values that are still
                    // on the stack during nested argument evaluation.
                    invalidate_nonprimitive_flow_shapes(&mut value_stack);
                    invalidate_nonprimitive_binding_flow_shapes(&mut binding_flow_shapes);
                }
                // `child_process` callback closures remain inside the
                // interpreter and never cross the typed ProcessSpawnRequest
                // boundary. Joining every syntactic hostcall argument would
                // therefore misclassify every callback form as Internal
                // egress. The runtime process dispatcher performs the exact
                // request-field join (command/argv/options only) and blocks a
                // non-Public request before the provider is called.
                //
                // bd-dign3: entropy APIs share the shape of problem. The
                // completion callback never crosses the typed random-read
                // boundary - the engine schedules it on the bd-opsnv
                // macrotask lane and labels the delivered payload at
                // schedule time (invocation label joined with Secret) - so
                // joining the callback value's fail-high function summary
                // into the effect data misclassified every deferred-entropy
                // form as TopSecret -> Internal egress.
                let mut operation_data_label = if capability == "process_spawn" {
                    process_spawn_request_label(&inputs)
                } else if matches!(
                    capability.as_str(),
                    "builtin:CryptoRandomBytes"
                        | "builtin:CryptoRandomInt"
                        | "builtin:CryptoRandomFillSync"
                        | "builtin:CryptoRandomUUID"
                ) {
                    join_flow_values(
                        &inputs
                            .iter()
                            .filter(|value| value.shape != FlowValueShape::Callable)
                            .cloned()
                            .collect::<Vec<_>>(),
                    )
                } else {
                    join_flow_values(&inputs)
                };
                // A HostCall has two independent IFC edges: operands flowing
                // into the effect, and the value produced by the host. The old
                // single-label approximation made every empty-argument source
                // Public, while applying a source floor to that same label would
                // incorrectly guard the source operation before it produced a
                // value. Keep the operation annotation operand-derived and push
                // the shared result-contract label onto the value stack.
                let is_deferred_entropy_callback = matches!(
                    capability.as_str(),
                    "builtin:CryptoRandomBytes" | "builtin:CryptoRandomInt"
                ) && inputs.len() >= 2
                    && inputs[0].shape == FlowValueShape::Callable;
                let mut result_label = if is_deferred_entropy_callback {
                    // Deferred entropy callbacks return `undefined` synchronously;
                    // `schedule_io_callback_with_label` labels the macrotask payload
                    // at runtime (Secret on success, invocation label on redacted failure).
                    operation_data_label.clone()
                } else {
                    hostcall_result_contract(capability).result_label(&operation_data_label, None)
                };
                let mut result_origin = None;
                let mut result_shape = if is_deferred_entropy_callback {
                    FlowValueShape::Primitive
                } else {
                    FlowValueShape::Unknown
                };

                let constructor_kind = match capability.as_str() {
                    "builtin:CryptoCreateHash" => Some(CryptoFlowObjectKind::Hash),
                    "builtin:CryptoCreateHmac" => Some(CryptoFlowObjectKind::Hmac),
                    "builtin:CryptoCreateCipheriv" | "builtin:CryptoCreateDecipheriv" => {
                        Some(CryptoFlowObjectKind::Cipher)
                    }
                    _ => None,
                };
                if let Some(kind) = constructor_kind {
                    crypto_flow_states.insert(
                        op_index,
                        CryptoFlowObjectState {
                            kind,
                            lifecycle_label: result_label.clone(),
                        },
                    );
                    result_origin = Some(op_index);
                } else if matches!(
                    capability.as_str(),
                    "builtin:CryptoObjectUpdate"
                        | "builtin:CryptoObjectDigest"
                        | "builtin:CryptoObjectCopy"
                        | "builtin:CryptoObjectFinal"
                        | "builtin:CryptoObjectGetAuthTag"
                        | "builtin:CryptoObjectSetAuthTag"
                ) {
                    let receiver_origin = inputs.last().and_then(|value| value.crypto_origin);
                    if let Some((origin, prior)) = receiver_origin
                        .and_then(|origin| {
                            crypto_flow_states
                                .get(&origin)
                                .cloned()
                                .map(|state| (origin, state))
                        })
                        .filter(|(_, state)| {
                            crypto_flow_kind_supports_capability(state.kind, capability)
                        })
                    {
                        result_label = prior.lifecycle_label.join(&operation_data_label);
                        match capability.as_str() {
                            "builtin:CryptoObjectUpdate" => {
                                if prior.kind == CryptoFlowObjectKind::Hmac {
                                    // bd-vw7s1: `createHmac` already cleared key
                                    // ingress at `Internal` and elevated the
                                    // handle to `Secret`. Measure `hmac.update`
                                    // ingress over the message/encoding operands
                                    // so `Internal` messages remain legal while
                                    // `Secret` messages fail `Internal` clearance;
                                    // keep `Secret` on the returned handle and
                                    // on any thrown lifecycle error.
                                    let message_data_label =
                                        join_flow_values(&inputs[..inputs.len().saturating_sub(1)]);
                                    result_label = prior.lifecycle_label.join(&message_data_label);
                                    operation_exception_label_override = Some(result_label.clone());
                                    operation_data_label = message_data_label;
                                    hmac_update_indexes.insert(op_index);
                                }
                                crypto_flow_states.insert(
                                    origin,
                                    CryptoFlowObjectState {
                                        kind: prior.kind,
                                        lifecycle_label: result_label.clone(),
                                    },
                                );
                                if matches!(
                                    prior.kind,
                                    CryptoFlowObjectKind::Hash | CryptoFlowObjectKind::Hmac
                                ) {
                                    result_origin = Some(origin);
                                } else {
                                    // bd-dign3: `cipher.update(data)` yields a
                                    // Buffer; only a supplied output encoding
                                    // (arity >= 2 beyond the receiver) yields a
                                    // string. Arity alone cannot misreport a
                                    // Buffer as text, so ambiguous forms stay
                                    // closed rather than primitive.
                                    let arguments = &inputs[..inputs.len() - 1];
                                    result_shape = if arguments.len() == 1
                                        && arguments[0].shape == FlowValueShape::Primitive
                                    {
                                        FlowValueShape::BufferObject
                                    } else {
                                        FlowValueShape::ClosedResult
                                    };
                                }
                            }
                            "builtin:CryptoObjectCopy" => {
                                if prior.kind == CryptoFlowObjectKind::Hash {
                                    crypto_flow_states.insert(
                                        op_index,
                                        CryptoFlowObjectState {
                                            kind: CryptoFlowObjectKind::Hash,
                                            lifecycle_label: result_label.clone(),
                                        },
                                    );
                                    result_origin = Some(op_index);
                                }
                            }
                            "builtin:CryptoObjectDigest" | "builtin:CryptoObjectFinal" => {
                                crypto_flow_states.insert(
                                    origin,
                                    CryptoFlowObjectState {
                                        kind: prior.kind,
                                        lifecycle_label: result_label.clone(),
                                    },
                                );
                                // bd-dign3: `digest()` / `final()` yield a
                                // Buffer; `digest('hex')` and friends yield the
                                // encoded string. Arity is authoritative here
                                // because the optional argument IS the output
                                // encoding.
                                let arguments = &inputs[..inputs.len() - 1];
                                result_shape = match arguments {
                                    [] => FlowValueShape::BufferObject,
                                    [encoding] if encoding.shape == FlowValueShape::Primitive => {
                                        FlowValueShape::Primitive
                                    }
                                    _ => FlowValueShape::ClosedResult,
                                };
                            }
                            "builtin:CryptoObjectGetAuthTag" => {
                                crypto_flow_states.insert(
                                    origin,
                                    CryptoFlowObjectState {
                                        kind: prior.kind,
                                        lifecycle_label: result_label.clone(),
                                    },
                                );
                                result_shape = FlowValueShape::BufferObject;
                            }
                            "builtin:CryptoObjectSetAuthTag" => {
                                crypto_flow_states.insert(
                                    origin,
                                    CryptoFlowObjectState {
                                        kind: prior.kind,
                                        lifecycle_label: result_label.clone(),
                                    },
                                );
                                result_origin = Some(origin);
                            }
                            _ => unreachable!("matched finite crypto lifecycle capability"),
                        }
                    } else {
                        // A finite lifecycle capability without its statically
                        // authenticated origin is malformed or crossed an
                        // unsupported escape. Fail high instead of treating its
                        // direct arguments as the complete exception source.
                        result_label = Label::TopSecret;
                        operation_exception_label_override = Some(Label::TopSecret);
                    }
                }
                // bd-dign3: KDF results are engine-owned Buffers at runtime.
                // Carrying the authenticated BufferObject shape routes their
                // `toString([encoding])` reads through the existing audited
                // finite-method lane instead of failing high as unknown-
                // callee calls, without vouching for anything beyond the
                // buffer itself.
                if hostcall_is_operand_derived
                    && matches!(
                        capability.as_str(),
                        "builtin:CryptoPbkdf2Sync" | "builtin:CryptoScryptSync"
                    )
                {
                    result_shape = FlowValueShape::BufferObject;
                }
                if hostcall_is_operand_derived && capability == "builtin:BufferIsBuffer" {
                    result_shape = FlowValueShape::Primitive;
                }
                if hostcall_is_operand_derived && capability.starts_with("builtin:instanceof:") {
                    result_shape = FlowValueShape::Primitive;
                }
                // bd-53l89 slice 2: an Ed25519 signature is an engine-owned
                // 64-byte Buffer; the verify verdict is a plain boolean. Both
                // closed shapes keep chained sign->verify calls operand-derived.
                if hostcall_is_operand_derived && capability == "builtin:CryptoSign" {
                    result_shape = FlowValueShape::BufferObject;
                }
                if hostcall_is_operand_derived && capability == "builtin:CryptoVerify" {
                    result_shape = FlowValueShape::Primitive;
                }
                // bd-dign3: hash/cipher catalogs are engine-owned arrays of
                // primitive strings, `crypto.constants` is an engine-owned
                // bag of numeric primitives, and timing-safe comparison
                // yields a boolean. All closed, all runtime-truthful.
                if hostcall_is_operand_derived
                    && matches!(
                        capability.as_str(),
                        "builtin:CryptoGetHashes" | "builtin:CryptoGetCiphers"
                    )
                {
                    result_shape = FlowValueShape::ClosedResult;
                }
                if hostcall_is_operand_derived
                    && matches!(
                        capability.as_str(),
                        "builtin:CryptoConstants" | "builtin:ZlibConstants" | "builtin:OsConstants"
                    )
                {
                    result_shape = FlowValueShape::ConstantsObject;
                }
                if hostcall_is_operand_derived && capability == "builtin:CryptoTimingSafeEqual" {
                    result_shape = FlowValueShape::Primitive;
                }
                // bd-9vouw.19: `crypto.randomUUID()` returns a string (runtime
                // crypto_random_uuid); its Secret label is the result
                // contract. Without the primitive shape, every later finite
                // operation on the UUID (an fs path, a string method) failed
                // high to TopSecret instead of carrying the Secret operand.
                if hostcall_is_operand_derived && capability == "builtin:CryptoRandomUUID" {
                    result_shape = FlowValueShape::Primitive;
                }
                // bd-dign3 follow-up: the zlib sync family returns
                // engine-owned Buffers; the authenticated BufferObject shape
                // routes their toString/equals reads through the audited
                // finite-method lane instead of unknown-callee fail-high.
                if hostcall_is_operand_derived
                    && matches!(
                        capability.as_str(),
                        "builtin:ZlibGzipSync"
                            | "builtin:ZlibGunzipSync"
                            | "builtin:ZlibDeflateSync"
                            | "builtin:ZlibInflateSync"
                            | "builtin:ZlibDeflateRawSync"
                            | "builtin:ZlibInflateRawSync"
                            | "builtin:ZlibUnzipSync"
                            // bd-zlib-residual-l6ev2: brotli outputs are
                            // engine-owned Buffers like their deflate
                            // siblings and need the same authenticated
                            // BufferObject shape for finite-method reads.
                            | "builtin:ZlibBrotliCompressSync"
                            | "builtin:ZlibBrotliDecompressSync"
                    )
                {
                    result_shape = FlowValueShape::BufferObject;
                }
                if matches!(
                    capability.as_str(),
                    "builtin:BufferObjectToString" | "builtin:BufferObjectReadUInt32LE"
                ) {
                    let authenticated = inputs.split_last().is_some_and(|(receiver, arguments)| {
                        receiver.shape == FlowValueShape::BufferObject
                            && arguments
                                .iter()
                                .all(|value| value.shape == FlowValueShape::Primitive)
                    });
                    if authenticated && hostcall_is_operand_derived {
                        result_shape = FlowValueShape::Primitive;
                    } else {
                        // Hand-authored or malformed IR must not be able to
                        // manufacture the source-level Buffer proof.
                        result_label = Label::TopSecret;
                        result_shape = FlowValueShape::Unknown;
                        operation_exception_label_override = Some(Label::TopSecret);
                    }
                }
                // bd-dign3 follow-up: `buf.equals(other)` yields a boolean
                // derived from both operands' bytes. Authenticated receivers
                // with closed operands are finite; anything else keeps the
                // fail-high contract.
                if capability == "builtin:BufferObjectEquals" {
                    let authenticated = inputs.split_last().is_some_and(|(receiver, arguments)| {
                        receiver.shape == FlowValueShape::BufferObject
                            && !arguments.is_empty()
                            && arguments.iter().all(|value| value.shape.is_closed())
                    });
                    if authenticated && hostcall_is_operand_derived {
                        result_shape = FlowValueShape::Primitive;
                    } else {
                        result_label = Label::TopSecret;
                        result_shape = FlowValueShape::Unknown;
                        operation_exception_label_override = Some(Label::TopSecret);
                    }
                }
                if hostcall_is_operand_derived
                    && matches!(
                        capability.as_str(),
                        "builtin:BufferFrom" | "builtin:BufferAlloc"
                    )
                {
                    result_shape = FlowValueShape::BufferObject;
                }
                if hostcall_is_operand_derived
                    && matches!(
                        capability.as_str(),
                        "builtin:BufferAllocUnsafe"
                            | "builtin:BufferConcat"
                            // bd-dign3: an engine-owned zero-filled ArrayBuffer
                            // is a closed aggregate of primitive bytes, same as
                            // its typed-array views; leaving it Unknown made the
                            // crypto lifecycle exception contract fail high on
                            // valid binary-like inputs.
                            | "builtin:ArrayBuffer"
                            | "builtin:ArrayFrom"
                            | "builtin:Uint8Array"
                            | "builtin:Int32Array"
                            | "builtin:Uint32Array"
                            | "builtin:Int8Array"
                            | "builtin:Uint8ClampedArray"
                            | "builtin:Int16Array"
                            | "builtin:Uint16Array"
                            | "builtin:Float32Array"
                            | "builtin:Float64Array"
                            | "builtin:BigInt64Array"
                            | "builtin:BigUint64Array"
                            | "builtin:DataView"
                    )
                {
                    result_shape = FlowValueShape::ClosedResult;
                }
                if hostcall_is_operand_derived && capability == "builtin:ObjectKeys" {
                    result_shape = FlowValueShape::OwnKeyArray;
                }
                if hostcall_is_operand_derived
                    && matches!(
                        capability.as_str(),
                        "builtin:NetCreateServer"
                            | "builtin:NetConnect"
                            | "builtin:NetCreateConnection"
                            | "builtin:NetServerAddress"
                            | "builtin:HttpCreateServer"
                            | "builtin:HttpGet"
                            | "builtin:HttpRequest"
                            | "builtin:TlsCreateServer"
                            | "builtin:TlsConnect"
                            | "builtin:TlsCreateSecureContext"
                    )
                {
                    // bd-dmnqx / bd-jux2l: constructed net/tls server/socket
                    // (and the TLS secure-context handle) are engine-owned
                    // data aggregates.
                    result_shape = FlowValueShape::FreshAggregate;
                }
                if hostcall_is_operand_derived
                    && matches!(
                        capability.as_str(),
                        "builtin:TlsGetCiphers"
                            | "builtin:TlsRootCertificates"
                            | "builtin:TlsCheckServerIdentity"
                    )
                {
                    result_shape = FlowValueShape::ClosedResult;
                }
                if hostcall_is_operand_derived && capability == "builtin:ArrayIsArrayFunction" {
                    result_shape = FlowValueShape::ArrayIsArrayFunction;
                }
                if hostcall_is_operand_derived && capability == "builtin:EventEmitterConstructorRef"
                {
                    result_shape = FlowValueShape::EventEmitterConstructor;
                }
                // bd-zco6t: finite fd-lifecycle results are closed primitives.
                // Every operand-derived `fs:write` hostcall yields a primitive
                // (openSync's numeric fd, writeSync's byte count, and the
                // undefined of writeFileSync/append/mkdir/closeSync/fsyncSync
                // and friends), so the fd a later writeSync/readSync consumes
                // is a CLOSED input and those calls stay operand-derived —
                // preserving unrelated Buffer proofs instead of poisoning
                // them. `fs:read` stays Unknown-shaped EXCEPT the fd-based
                // read_fd form, whose JS value is the byte count (the Buffer
                // is mutated in place); a no-encoding readFileSync returns a
                // Buffer the static layer deliberately does not vouch for.
                if hostcall_is_operand_derived && capability == "fs:write" {
                    result_shape = FlowValueShape::Primitive;
                }
                if hostcall_is_operand_derived
                    && capability == "fs:read"
                    && inputs
                        .first()
                        .and_then(|discriminator| discriminator.fs_operation)
                        == Some(FsOperation::ReadFd)
                {
                    result_shape = FlowValueShape::Primitive;
                }
                // bd-zco6t: `String(x)` always evaluates to a primitive
                // string regardless of its input — the shape is a value-kind
                // truth, not a finiteness claim. The result LABEL still joins
                // the input's provenance, and a non-operand-derived
                // invocation keeps its fail-high exception contract and the
                if hostcall_is_operand_derived && capability == "builtin:QuerystringParse" {
                    result_shape = FlowValueShape::FreshAggregate;
                }
                // bd-qmy52: `os` pure-compute accessors that return aggregate
                // structures are engine-owned fresh arrays/objects; summarize
                // them so chained Array.prototype operations stay finite.
                if matches!(
                    capability.as_str(),
                    "builtin:OsLoadavg" | "builtin:OsCpus" | "builtin:OsNetworkInterfaces"
                ) {
                    result_shape = FlowValueShape::FreshAggregate;
                }
                // not opened up — only the catch observation
                // `String(error).includes(...)` gains a primitive receiver.
                if capability == "builtin:String" {
                    result_shape = FlowValueShape::Primitive;
                }
                if hostcall_is_operand_derived && capability == "builtin:QuerystringStringify" {
                    result_shape = FlowValueShape::Primitive;
                }
                // bd-pafik: authenticated stream construction and promise-
                // pipeline rejection provenance.
                let mut result_stream = None;
                match capability.as_str() {
                    // `Readable.from(iterable)` executes no user callbacks:
                    // its rejection sources are engine failures and the
                    // iterable's own data.
                    "builtin:StreamReadableFrom" => {
                        stream_states.insert(
                            op_index,
                            StreamCallbackSummary::Supported(
                                Label::Internal.join(&operation_data_label),
                            ),
                        );
                        result_stream = Some(StreamFlowInfo::Stream { origin: op_index });
                    }
                    "builtin:StreamReadable"
                    | "builtin:StreamWritable"
                    | "builtin:StreamTransform"
                    | "builtin:StreamPassThrough" => {
                        let summary = stream_constructor_summary(&inputs, &operation_data_label);
                        if let StreamCallbackSummary::Supported(bound) = &summary {
                            // The authenticated callback-error bound is also
                            // the constructed stream VALUE's provenance: the
                            // constructor consumes only the options object,
                            // and the raw JoinInputs label carries the
                            // bd-qjh7y fail-high return summary of the
                            // callback function value.
                            result_label = bound.clone();
                        }
                        stream_states.insert(op_index, summary);
                        result_stream = Some(StreamFlowInfo::Stream { origin: op_index });
                    }
                    "builtin:StreamPromisesPipeline" => {
                        // The pipeline can reject with (a) its own validation
                        // and engine failures, (b) any stage's data, and (c)
                        // anything a stage callback throws / reports via
                        // `callback(error)` / rejects with. All three are
                        // bounded only when EVERY stage is an authenticated
                        // stream whose callback summary is supported; any
                        // unknown stage keeps the fail-high default.
                        if let Some(rejection) = stream_pipeline_rejection(&inputs, &stream_states)
                        {
                            pipeline_rejections.insert(op_index, rejection.clone());
                            result_stream =
                                Some(StreamFlowInfo::PipelinePromise { origin: op_index });
                            // The settlement value and the synchronous throw
                            // path are both bounded by the rejection summary.
                            result_label = rejection.clone();
                            operation_exception_is_operand_derived = true;
                            operation_exception_label_override = Some(rejection);
                        }
                    }
                    _ => {}
                }
                let mut result =
                    fresh_crypto_flow_value(result_label, result_origin, &mut next_identity);
                result.shape = result_shape;
                result.stream = result_stream;
                value_stack.push(result);
                operation_data_label
            }
        };
        let exception_input_label = operation_exception_label_override
            .as_ref()
            .unwrap_or(&inferred);
        if let Some(exception_label) = ir1_exception_flow_label(
            op.inner(),
            exception_input_label,
            operation_exception_is_operand_derived,
            operation_exception_is_event_emitter_error,
        ) {
            // The runtime routes an exception to the innermost active handler.
            // An enclosing handler is tainted only if the inner handler later
            // rethrows while the enclosing protected region remains active.
            if let Some(catch_label) = active_catch_regions.last() {
                let Some(entry) = catch_entry_labels.get_mut(catch_label) else {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "active catch region is missing its flow label",
                    });
                };
                *entry = entry.join(&exception_label);
            }
        }
        inferred_labels.push(inferred);
    }

    Ok((
        inferred_labels,
        bindings_changed,
        catch_entry_store_indexes,
        hmac_update_indexes,
    ))
}

/// Sound upper bound on every IFC label a value, thrown exception, binding,
/// or catch parameter can carry while this lowering unit executes
/// (bd-9vouw.1).
///
/// The flow simulation fails high (`TopSecret`) wherever it cannot summarize
/// provenance: unsummarized callees, unaudited method calls, guest-throwable
/// operations. That is sound but made ordinary programs with no sensitive
/// source at all unrunnable (`console.log(Math.max(1, 2))`, closure calls,
/// recursion). Fail-high only has to cover information that could actually
/// exist, and every label above the simulator's engine floors enters a
/// program through one of the operations enumerated here:
///
/// - HostCall results, via the shared result contract registry;
/// - HostCall exceptions that can carry host-originated data (provider-backed
///   authorities under unauthenticated provenance, native crypto failures);
/// - code this IR does not contain (`ImportModule`, `module:require`,
///   `module:import`), which may perform its own effects.
///
/// Literals are Public: a literal's text is program code, not evidence that
/// it holds a secret (bd-9vouw.19); only a legacy `hostcall<"cap"> payload`
/// marker models a labeled argument (see [`infer_data_label_for_op`]). Every
/// other operation computes from its operands or from engine-owned state at
/// or below `Internal`. Function bodies are embedded as `body_ops`
/// and are walked recursively. Runtime-compiled `Function` source is lowered
/// again under the same deny-all ambient-authority policy (eval, env, and
/// ambient require stay denied), which is the same trust assumption the
/// simulation already makes when it summarizes `FunctionConstructor` results.
///
/// Clamping every annotation to this bound therefore cannot admit a flow of
/// information that the program is able to hold. Programs that do touch a
/// sensitive source keep today's per-operation precision below the bound.
pub(super) fn ir2_ops_contain_try_begin(ops: &[Ir2Op]) -> bool {
    fn ir1_op_contains_try_begin(op: &Ir1Op) -> bool {
        match op {
            Ir1Op::BeginTry { .. } => true,
            Ir1Op::DeclareFunction { body_ops, .. } | Ir1Op::CreateFunction { body_ops, .. } => {
                body_ops.iter().any(ir1_op_contains_try_begin)
            }
            _ => false,
        }
    }
    ops.iter().any(|op| ir1_op_contains_try_begin(&op.inner))
}

pub(super) fn ir2_flow_label_ceiling(
    ops: &[Ir2Op],
    host_io_exception_provenance: HostIoExceptionProvenance,
) -> Label {
    let bounded_imports = ops_assume_bounded_imports(ops);
    let has_try_begin = ir2_ops_contain_try_begin(ops);
    let mut ceiling = Label::Internal;
    let mut prev_op: Option<&Ir1Op> = None;
    for op in ops {
        accumulate_ir1_flow_label_ceiling(
            &op.inner,
            prev_op,
            host_io_exception_provenance,
            bounded_imports,
            has_try_begin,
            &mut ceiling,
        );
        prev_op = Some(&op.inner);
    }
    ceiling
}

pub(super) fn accumulate_ir1_flow_label_ceiling(
    op: &Ir1Op,
    prev_op: Option<&Ir1Op>,
    host_io_exception_provenance: HostIoExceptionProvenance,
    bounded_imports: bool,
    has_try_begin: bool,
    ceiling: &mut Label,
) {
    if *ceiling == Label::TopSecret {
        return;
    }
    let contribution = match op {
        Ir1Op::DeclareFunction { body_ops, .. } | Ir1Op::CreateFunction { body_ops, .. } => {
            let mut inner_prev: Option<&Ir1Op> = None;
            for inner in body_ops {
                accumulate_ir1_flow_label_ceiling(
                    inner,
                    inner_prev,
                    host_io_exception_provenance,
                    bounded_imports,
                    has_try_begin,
                    ceiling,
                );
                inner_prev = Some(inner);
            }
            return;
        }
        // Only a legacy hostcall marker literal can carry a label above Public.
        Ir1Op::LoadLiteral { .. } => infer_data_label_for_op(op, &BTreeMap::new(), Label::Public),
        // Loading a module runs code this IR does not contain, unless the unit
        // is bounded (bd-j8f7q) and the module is a local file or a package,
        // whose own ceiling the interpreter checks against the bound before
        // running it.
        Ir1Op::ImportModule { specifier, .. }
            if bounded_imports && specifier.as_str().is_some_and(is_bounded_import_specifier) =>
        {
            IFC_BOUNDED_IMPORT_LABEL
        }
        Ir1Op::ImportModule { .. } => Label::TopSecret,
        // An ImportCall's namespace is bounded like a static import's: in a
        // bounded unit the interpreter checks whichever module it loads.
        Ir1Op::HostCall { capability, .. }
            if bounded_imports && capability == crate::capability::DYNAMIC_IMPORT_CAPABILITY =>
        {
            IFC_BOUNDED_IMPORT_LABEL
        }
        Ir1Op::HostCall {
            capability,
            arg_count,
        } if !has_try_begin
            && matches!(
                capability.as_str(),
                "builtin:CryptoRandomBytes" | "builtin:CryptoRandomInt"
            )
            && *arg_count >= 2
            && matches!(prev_op, Some(Ir1Op::CreateFunction { .. })) =>
        {
            Label::Public
        }
        Ir1Op::HostCall { capability, .. } => hostcall_flow_label_ceiling_with_catch(
            capability,
            host_io_exception_provenance,
            has_try_begin,
        ),
        _ => return,
    };
    *ceiling = ceiling.join(&contribution);
}

/// Highest label one HostCall can introduce: its result contract applied to
/// public operands, joined with whatever its exceptional completion can carry
/// from outside the program.
pub(super) fn hostcall_flow_label_ceiling_with_catch(
    capability: &str,
    host_io_exception_provenance: HostIoExceptionProvenance,
    has_try_begin: bool,
) -> Label {
    use crate::capability::{RuntimeCapability, hostcall_registry_row};

    // Loading a module executes code this IR does not contain.
    if matches!(
        capability,
        "module:require"
            | "module:import"
            | "module.import"
            | "module_load"
            | crate::capability::DYNAMIC_IMPORT_CAPABILITY
    ) {
        return Label::TopSecret;
    }
    let Some(row) = hostcall_registry_row(capability) else {
        return Label::TopSecret;
    };
    let result_label = row.result_contract.result_label(&Label::Public, None);
    if !has_try_begin {
        return result_label;
    }
    // Native crypto failures are rethrown with a fail-high label at runtime.
    if capability.starts_with("builtin:Crypto") {
        return Label::TopSecret;
    }
    let exception_label = match row.authority {
        None
        | Some(
            RuntimeCapability::Console
            | RuntimeCapability::Timer
            | RuntimeCapability::Builtin
            | RuntimeCapability::VmDispatch
            | RuntimeCapability::GcInvoke
            | RuntimeCapability::IrLowering
            | RuntimeCapability::HeapAllocate
            | RuntimeCapability::EvidenceEmit
            | RuntimeCapability::DecisionInvoke
            | RuntimeCapability::IdempotencyDerive,
        ) => Label::Internal,
        Some(_) => match host_io_exception_provenance {
            HostIoExceptionProvenance::ProviderInternal => Label::Internal,
            HostIoExceptionProvenance::Unknown => Label::TopSecret,
        },
    };
    result_label.join(&exception_label)
}

pub(super) fn infer_ir2_flow_annotations(
    ir2: &mut Ir2Module,
    host_io_exception_provenance: HostIoExceptionProvenance,
) -> Result<FlowInferenceMetrics, LoweringPipelineError> {
    let flow_label_ceiling = ir2_flow_label_ceiling(&ir2.ops, host_io_exception_provenance);
    infer_ir2_flow_annotations_bounded(
        ir2,
        host_io_exception_provenance,
        &flow_label_ceiling,
        BTreeMap::new(),
    )
}

/// Flow-annotate `ir2` with every annotation clamped to `flow_label_ceiling`,
/// starting from `binding_labels` for bindings whose values enter from outside
/// `ir2.ops` (see [`annotate_nested_body_ops`]).
pub(super) fn infer_ir2_flow_annotations_bounded(
    ir2: &mut Ir2Module,
    host_io_exception_provenance: HostIoExceptionProvenance,
    flow_label_ceiling: &Label,
    mut binding_labels: BTreeMap<BindingId, Label>,
) -> Result<FlowInferenceMetrics, LoweringPipelineError> {
    const MAX_FLOW_INFERENCE_PASSES: usize = 16;
    let catch_region_events = ir2_catch_region_events(&ir2.ops)?;
    let memo_scope = FunctionSummaryMemoScope::enter(host_io_exception_provenance);
    // A reverse binding-dependency chain can otherwise force one complete IR2
    // rescan per binding, making inference quadratic in attacker-controlled
    // source size. The strict pass budget bounds work to O(n) and fails closed
    // when exact propagation would require a dedicated dependency worklist.
    // The pass that changes no binding label read the fixed point throughout,
    // so its labels are the converged ones: a further pass recomputed exactly
    // them (debug builds still check that).
    let mut fixed_point = None;
    for _ in 0..MAX_FLOW_INFERENCE_PASSES {
        let (labels, changed, catch_entry_store_indexes, hmac_update_indexes) =
            simulate_ir2_flow_labels(
                &ir2.ops,
                &mut binding_labels,
                &catch_region_events,
                host_io_exception_provenance,
                0,
            )?;
        if !changed {
            fixed_point = Some((labels, catch_entry_store_indexes, hmac_update_indexes));
            break;
        }
    }
    let Some((inferred_labels, catch_entry_store_indexes, hmac_update_indexes)) = fixed_point
    else {
        return Err(LoweringPipelineError::InvariantViolation {
            detail: "IR2 flow-label inference exceeded its pass budget",
        });
    };
    #[cfg(debug_assertions)]
    {
        let again = simulate_ir2_flow_labels(
            &ir2.ops,
            &mut binding_labels,
            &catch_region_events,
            host_io_exception_provenance,
            0,
        )?;
        debug_assert!(
            !again.1
                && again.0 == inferred_labels
                && again.2 == catch_entry_store_indexes
                && again.3 == hmac_update_indexes,
            "IR2 flow-label binding fixed point changed after convergence"
        );
    }
    drop(memo_scope);

    let mut metrics = FlowInferenceMetrics {
        total_flow_ops: 0,
        static_proven_ops: 0,
        runtime_check_ops: 0,
    };
    let (catch_region_starts, catch_region_ends, _) = &catch_region_events;
    let mut active_catch_regions = Vec::<u32>::new();

    for (op_index, (op, simulated_data_label)) in
        ir2.ops.iter_mut().zip(inferred_labels).enumerate()
    {
        // No operation can hold information above what the program is able
        // to introduce (see `ir2_flow_label_ceiling`); fail-high defaults stop
        // at that bound instead of at `TopSecret`.
        let inferred_data_label = simulated_data_label.meet(flow_label_ceiling);
        if let Some(ending) = catch_region_ends.get(&op_index) {
            for catch_label in ending {
                if active_catch_regions.pop().as_ref() != Some(catch_label) {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "catch annotation region termination is not properly nested",
                    });
                }
            }
        }
        if let Some(starting) = catch_region_starts.get(&op_index) {
            active_catch_regions.extend(starting.iter().copied());
        }
        let inferred_sink_clearance = if matches!(op.inner, Ir1Op::Throw)
            && !active_catch_regions.is_empty()
            && op.required_capability.is_none()
        {
            // A statically enclosed throw transfers its value to another
            // local binding; it is not host egress. Keep the exact label,
            // already joined into the innermost catch by flow simulation.
            // Releasing that caught value still checks the real sink. Throws
            // without a local catch (including finally-only regions) retain
            // the normal boundary clearance and fail closed when necessary.
            inferred_data_label.clone()
        } else if hmac_update_indexes.contains(&op_index) {
            // bd-vw7s1: authenticated HMAC message ingress shares `createHmac`'s
            // finite `Internal` clearance so un-declassified `Secret` payloads
            // cannot be converted into keyed tags via `hmac.update(...)`.
            Label::Internal
        } else {
            infer_sink_clearance(
                &op.effect,
                op.required_capability.as_ref(),
                &inferred_data_label,
            )
        };
        let requires_declassification = !inferred_data_label.can_flow_to(&inferred_sink_clearance);
        let runtime_guard_needed = op.required_capability.as_ref().is_some_and(|capability| {
            flow_requires_runtime_check(
                Some(&FlowAnnotation {
                    data_label: inferred_data_label.clone(),
                    sink_clearance: inferred_sink_clearance.clone(),
                    declassification_required: requires_declassification,
                }),
                capability,
            )
        });
        // bd-pafik: a catch-parameter binding store is where caught exception
        // provenance becomes observable to source code, so it materializes an
        // annotation; every other Pure, statically-unannotated op stays bare.
        let should_annotate = op.flow.is_some()
            || !matches!(op.effect, EffectBoundary::Pure)
            || catch_entry_store_indexes.contains(&op_index);
        if should_annotate {
            metrics.total_flow_ops = metrics.total_flow_ops.saturating_add(1);
            if requires_declassification || runtime_guard_needed {
                metrics.runtime_check_ops = metrics.runtime_check_ops.saturating_add(1);
            } else {
                metrics.static_proven_ops = metrics.static_proven_ops.saturating_add(1);
            }
            op.flow = Some(FlowAnnotation {
                data_label: inferred_data_label.clone(),
                sink_clearance: inferred_sink_clearance,
                declassification_required: requires_declassification,
            });
        } else {
            op.flow = None;
        }
    }

    Ok(metrics)
}

pub(super) fn infer_data_label_for_op(
    op: &Ir1Op,
    binding_labels: &BTreeMap<BindingId, Label>,
    last_label: Label,
) -> Label {
    match op {
        // bd-9vouw.19: a literal is Public whatever its text. Labelling string
        // literals that merely CONTAIN "secret", "token", "api_key",
        // "password" or "credential" refused benign programs at compile time
        // ("Unexpected token" messages, password prompts, a lexer's `tokens`
        // array, semver's `tokens` key) while the same text assembled at run
        // time stayed Public, so it was no boundary. Secret data enters through
        // HostCall result contracts (entropy, key material), which label it.
        //
        // The one exception is a legacy `hostcall<"cap"> payload` marker: it
        // is not program data but a modeled hostcall whose argument is the
        // payload text, and it takes no operands, so the payload's keywords
        // are its only way to model a secret argument (the orchestrator's
        // declassification-receipt fixtures rely on it).
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String(raw),
        } if extract_hostcall_capability(raw).is_some() => {
            let lowered = raw.to_ascii_lowercase();
            if ["secret", "token", "api_key", "password", "credential"]
                .iter()
                .any(|keyword| lowered.contains(keyword))
            {
                Label::Secret
            } else {
                Label::Public
            }
        }
        Ir1Op::LoadLiteral { .. } => Label::Public,
        Ir1Op::LoadBinding { binding_id } => binding_labels
            .get(binding_id)
            .cloned()
            .unwrap_or(Label::Internal),
        Ir1Op::StoreBinding { .. } | Ir1Op::InitializeBinding { .. } => last_label,
        Ir1Op::ImportModule { .. } | Ir1Op::Await | Ir1Op::Yield { .. } => Label::Internal,
        Ir1Op::Call { .. } => last_label,
        Ir1Op::ExportBinding { .. } => last_label,
        Ir1Op::Return | Ir1Op::Nop => last_label,
        // New IR1 ops (binary/unary/assign/control-flow) — propagate last label
        _ => last_label,
    }
}

pub(super) fn infer_sink_clearance(
    effect: &EffectBoundary,
    required_capability: Option<&CapabilityTag>,
    data_label: &Label,
) -> Label {
    if let Some(capability) = required_capability {
        return sink_clearance_from_capability(&capability.0);
    }

    match effect {
        EffectBoundary::NetworkEffect => Label::Public,
        EffectBoundary::FsEffect => Label::Internal,
        EffectBoundary::ReadEffect | EffectBoundary::WriteEffect => Label::Internal,
        EffectBoundary::HostcallEffect => Label::Internal,
        EffectBoundary::Pure => data_label.clone(),
    }
}

pub(crate) fn sink_clearance_from_capability(capability: &str) -> Label {
    // Canonicalizing a property name is internal computation, not disclosure
    // to a sink whose name happens to contain "key". Guest conversion hooks
    // keep their own hostcall gates; operand, callback and exception labels
    // must still reach the subsequent read/write or actual egress operation.
    // Deliberately exact: unauthenticated names must not inherit this contract.
    if matches!(
        capability,
        "builtin:ToPropertyKey"
            | "builtin:ReflectGet"
            | "builtin:ReflectSet"
            | "builtin:ReflectHas"
            | "builtin:ReflectDeleteProperty"
            | "builtin:ReflectGetPrototypeOf"
            | "builtin:ReflectSetPrototypeOf"
            | "builtin:ReflectIsExtensible"
            | "builtin:ReflectPreventExtensions"
            | "builtin:ObjectCreate"
            | "builtin:ObjectGetPrototypeOf"
            | "builtin:ObjectSetPrototypeOf"
            | "builtin:ObjectIsExtensible"
            | "builtin:ObjectPreventExtensions"
            | "builtin:ArrayPrototypeSome"
            | "builtin:StringPrototypeCharAt"
    ) {
        return Label::TopSecret;
    }
    // Proxy factories allocate only interpreter-owned target/handler carriers.
    // The result retains both argument labels; later traps and actual effects
    // still check their own boundaries. A high captured callback is not itself
    // disclosed merely by creating a Proxy. No future name inherits this rule.
    if matches!(capability, "builtin:Proxy" | "builtin:ProxyRevocable") {
        return Label::TopSecret;
    }
    // Authenticated builtin prototype membership is internal observation, not
    // egress. Share the runtime's exact finite-name recognizer rather than
    // allowing an unaudited future `instanceof:*` hostcall by prefix. The
    // boolean keeps its operand label; printing or exporting it still checks
    // the actual sink's clearance.
    if crate::baseline_interpreter::builtin_instanceof_capability_name(capability).is_some() {
        return Label::TopSecret;
    }
    let normalized = capability.to_ascii_lowercase();
    if normalized == "hostcall.invoke" {
        return Label::Internal;
    }
    // These four exact compiler intrinsics only manipulate interpreter-owned
    // iterator records. They are not sinks: operands and observed callback,
    // result-property and backing-storage labels remain on their outputs.
    // Future intrinsic names do not inherit this clearance implicitly.
    if matches!(
        normalized.as_str(),
        "builtin:destructureiteratorinit"
            | "builtin:destructureiteratornext"
            | "builtin:destructureiteratorelide"
            | "builtin:destructureiteratordone"
    ) {
        return Label::TopSecret;
    }
    // `builtin:Net*` / `builtin:Tls*` are authenticated, engine-owned
    // hermetic loopback facades. Callback registration and in-memory
    // socket/certificate state are not public network egress and may
    // retain values at any lattice level. Actual host network operations
    // use `net.*` capabilities and remain Public below.
    if normalized.starts_with("builtin:net") || normalized.starts_with("builtin:tls") {
        return Label::TopSecret;
    }
    // Authenticated crypto lifecycle calls only mutate/read the engine-private
    // side table. They are not egress: their result and exception labels retain
    // the receiver lifecycle joined with direct operands, so high inputs may
    // flow into the private state but cannot later cross a lower sink.
    if normalized.starts_with("builtin:cryptoobject") {
        return Label::TopSecret;
    }
    // Exact private-brand Buffer observations are internal computation, not
    // egress. Keep this allowlist finite so a future BufferObject method does
    // not silently inherit TopSecret clearance without its own provenance
    // audit.
    if matches!(
        normalized.as_str(),
        "builtin:bufferobjecttostring"
            | "builtin:bufferobjectreaduint32le"
            // bd-dign3 follow-up: equality over authenticated Buffer bytes is
            // a boolean oracle on possibly-secret content, so it carries the
            // same TopSecret clearance as the other byte-observing methods.
            | "builtin:bufferobjectequals"
            // bd-53l89 slice 2: Ed25519 sign/verify read the engine-private
            // key table and return derived values whose labels already ride
            // the operands (contract §6) — the call site itself is internal
            // computation over that private state, not egress. Real sinks
            // still see the Secret-floor signature label and refuse.
            | "builtin:cryptosign"
            | "builtin:cryptoverify"
    ) {
        return Label::TopSecret;
    }
    if normalized.starts_with("net:")
        || normalized.contains("net.")
        || normalized.contains("net_")
        || normalized.contains("network")
        || normalized.contains("process.")
        || normalized.contains("process_")
        || normalized.contains("spawn")
    {
        return Label::Public;
    }
    if normalized.contains("credential") || normalized.contains("key_material") {
        return Label::TopSecret;
    }
    if normalized.contains("secret") || normalized.contains("token") || normalized.contains("key") {
        return Label::Secret;
    }
    if normalized.contains("fs.read") {
        return Label::Internal;
    }
    if normalized.contains("fs.write")
        || normalized.contains("module.import")
        || normalized.contains("import")
    {
        return Label::Internal;
    }
    if normalized.starts_with("console:") || normalized == "console" {
        return Label::Internal;
    }
    if normalized.contains("declassify") {
        return Label::Public;
    }
    Label::Internal
}

/// Operand-aware flow annotations for a nested `DeclareFunction` /
/// `CreateFunction` body (bd-wyazf). Top-level IR1→IR2 only classifies the
/// function *value* op; body HostCalls otherwise reach IR3 without
/// `infer_ir2_flow_annotations` and skip the `ifc.check_flow` seam.
///
/// A body is annotated in isolation, but its parameters and captured
/// bindings carry values computed by the enclosing program. They therefore
/// start at `program_label_ceiling` (the bound for the whole lowering unit, see
/// [`ir2_flow_label_ceiling`]), and every annotation is clamped to that same
/// bound rather than to a ceiling derived from the body's own operations
/// (bd-9vouw.1): a body-local bound let a secret passed in as an argument or
/// captured from the outer scope be clamped below its label.
pub(super) fn annotate_nested_body_ops(
    body_ops: &[Ir1Op],
    host_io_exception_provenance: HostIoExceptionProvenance,
    program_label_ceiling: &Label,
) -> Result<Vec<Ir2Op>, LoweringPipelineError> {
    let mut ir2 = Ir2Module::new(
        ContentHash::compute(b"nested-function-body"),
        "nested_function_body",
    );
    for op in body_ops {
        let (effect, required_capability, flow) = classify_ir1_op(op);
        ir2.ops.push(Ir2Op {
            inner: op.clone(),
            effect,
            required_capability,
            flow,
            span: None,
        });
    }
    let external_bindings = nested_body_external_binding_reads(body_ops)
        .into_iter()
        .map(|binding_id| (binding_id, program_label_ceiling.clone()))
        .collect();
    infer_ir2_flow_annotations_bounded(
        &mut ir2,
        host_io_exception_provenance,
        program_label_ceiling,
        external_bindings,
    )?;
    Ok(ir2.ops)
}

/// Bindings a nested function body reads (directly, through inner function
/// bodies, or as inner-function captures) without declaring them itself:
/// parameters, captured outer bindings, and hoisted `var`s.
pub(super) fn nested_body_external_binding_reads(body_ops: &[Ir1Op]) -> BTreeSet<BindingId> {
    fn collect_reads(ops: &[Ir1Op], reads: &mut BTreeSet<BindingId>) {
        for op in ops {
            match op {
                Ir1Op::LoadBinding { binding_id }
                | Ir1Op::AssignOp { binding_id, .. }
                | Ir1Op::CreatePerIterationBinding { binding_id, .. } => {
                    reads.insert(*binding_id);
                }
                Ir1Op::DeclareFunction {
                    free_var_ids,
                    body_ops,
                    ..
                }
                | Ir1Op::CreateFunction {
                    free_var_ids,
                    body_ops,
                    ..
                } => {
                    reads.extend(free_var_ids.iter().copied());
                    collect_reads(body_ops, reads);
                }
                _ => {}
            }
        }
    }

    let mut reads = BTreeSet::new();
    collect_reads(body_ops, &mut reads);
    for op in body_ops {
        if let Ir1Op::InitializeBinding { binding_id } = op {
            reads.remove(binding_id);
        }
    }
    reads
}

pub(super) fn nested_function_body_ops(op: &Ir1Op) -> Option<&[Ir1Op]> {
    match op {
        Ir1Op::DeclareFunction { body_ops, .. } | Ir1Op::CreateFunction { body_ops, .. } => {
            Some(body_ops.as_slice())
        }
        _ => None,
    }
}

pub(super) fn collect_annotated_nested_function_bodies(
    ops: &[Ir2Op],
    host_io_exception_provenance: HostIoExceptionProvenance,
    program_label_ceiling: &Label,
    out: &mut Vec<Ir2Op>,
) -> Result<(), LoweringPipelineError> {
    for op in ops {
        let Some(body_ops) = nested_function_body_ops(&op.inner) else {
            continue;
        };
        let annotated = annotate_nested_body_ops(
            body_ops,
            host_io_exception_provenance,
            program_label_ceiling,
        )?;
        collect_annotated_nested_function_bodies(
            &annotated,
            host_io_exception_provenance,
            program_label_ceiling,
            out,
        )?;
        out.extend(annotated);
    }
    Ok(())
}

pub(super) fn flow_requires_runtime_check(
    flow: Option<&FlowAnnotation>,
    capability: &CapabilityTag,
) -> bool {
    let capability_is_dynamic = capability.0 == "hostcall.invoke";
    let flow_is_ambiguous = flow.is_some_and(|annotation| {
        matches!(annotation.data_label, Label::Custom { .. })
            || matches!(annotation.sink_clearance, Label::Custom { .. })
    });
    let flow_requires_declassification =
        flow.is_some_and(|annotation| annotation.declassification_required);
    capability_is_dynamic || flow_is_ambiguous || flow_requires_declassification
}

pub(super) fn extract_hostcall_capability(raw: &str) -> Option<String> {
    for (marker, terminator) in [("hostcall<\"", "\">"), ("hostcall<\\\"", "\\\">")] {
        let Some(start) = raw.find(marker) else {
            continue;
        };
        let remainder = &raw[start + marker.len()..];
        let Some(end) = remainder.find(terminator) else {
            continue;
        };
        let capability = remainder[..end].trim();
        if !capability.is_empty() {
            return Some(capability.to_string());
        }
    }

    None
}

/// bd-9vouw.491: `[]`'s `length` store. NewArray allocates an array with no
/// own `length` property; an element definition (CreateDataProperty of an
/// index) creates it, so only a literal with no element needs the store.
pub(super) fn emit_empty_array_length_store(
    instructions: &mut Vec<Ir3Instruction>,
    constant_pool: &mut ConstantPool,
    register_cursor: &mut Reg,
    array_reg: Reg,
) {
    let key_reg = alloc_register(register_cursor);
    let key_pool_index = push_constant_optimized(constant_pool, "length");
    instructions.push(Ir3Instruction::LoadStr {
        dst: key_reg,
        pool_index: key_pool_index,
    });
    let length_reg = alloc_register(register_cursor);
    instructions.push(Ir3Instruction::LoadInt {
        dst: length_reg,
        value: 0,
    });
    instructions.push(Ir3Instruction::SetProperty {
        obj: array_reg,
        key: key_reg,
        val: length_reg,
    });
}

/// bd-9vouw.496: the most constants one loop hoists, each into a register
/// pinned for the rest of the body.
pub(super) const MAX_HOISTED_LOOP_CONSTANTS: usize = 16;

/// bd-9vouw.496: the literals and static property keys an outermost loop
/// reads, loaded once into pinned registers at `insert_at` (before the
/// loop's entry `Jump` to its bottom test, or before the body label of a
/// loop entered by falling into it) instead of on every iteration.
pub(super) struct LoopConstantHoist {
    pub(super) insert_at: usize,
    pub(super) end: usize,
    pub(super) constants: Vec<Ir1Literal>,
}

/// bd-9vouw.496: plan the loop-invariant constant loads of a body. A loop is
/// a back edge, a `JumpIfTruthy` to an earlier label (while, do-while and
/// for loops test at the bottom, bd-9vouw.486); only outermost loops are
/// planned, so a constant of an inner loop is loaded before the outer one.
/// A loop is skipped when anything outside it, other than its own entry
/// jump, targets a label inside it (the loads could be bypassed). The loop's
/// `++`/`--` operand literal is not hoisted: no instruction loads it
/// (update_assignment_ignores_operand). BigInt literals are not hoisted.
/// The emitter applies a plan only when the value stack is empty at
/// `insert_at` (a statement boundary).
pub(super) fn plan_loop_constant_hoists(ops: &[Ir2Op]) -> Vec<LoopConstantHoist> {
    let mut label_at = BTreeMap::<u32, usize>::new();
    for (index, op) in ops.iter().enumerate() {
        if let Ir1Op::Label { id } = &op.inner {
            label_at.insert(*id, index);
        }
    }
    let targets = |op: &Ir1Op| -> Vec<u32> {
        match op {
            Ir1Op::Jump { label_id }
            | Ir1Op::JumpIfFalsy { label_id }
            | Ir1Op::JumpIfFalsyConsume { label_id }
            | Ir1Op::JumpIfTruthy { label_id }
            | Ir1Op::JumpIfNullish { label_id } => vec![*label_id],
            Ir1Op::BeginTry {
                catch_label,
                finally_label,
            } => std::iter::once(*catch_label)
                .chain(finally_label.iter().copied())
                .collect(),
            Ir1Op::ForInNext { done_label } | Ir1Op::ForOfNext { done_label } => {
                vec![*done_label]
            }
            _ => Vec::new(),
        }
    };
    let mut loops = ops
        .iter()
        .enumerate()
        .filter_map(|(index, op)| match &op.inner {
            Ir1Op::JumpIfTruthy { label_id } => label_at
                .get(label_id)
                .filter(|&&body| body < index)
                .map(|&body| (body, index)),
            _ => None,
        })
        .collect::<Vec<_>>();
    loops.sort_unstable();
    let mut outermost: Vec<(usize, usize)> = Vec::new();
    for (body, end) in loops {
        if outermost
            .last()
            .is_some_and(|&(outer_body, outer_end)| body >= outer_body && end <= outer_end)
        {
            continue;
        }
        outermost.push((body, end));
    }
    outermost
        .into_iter()
        .filter_map(|(body, end)| {
            let insert_at = match body.checked_sub(1).map(|index| &ops[index].inner) {
                Some(Ir1Op::Jump { label_id })
                    if label_at
                        .get(label_id)
                        .is_some_and(|&test| test > body && test <= end) =>
                {
                    body - 1
                }
                _ => body,
            };
            let entered_only_at_its_head = ops.iter().enumerate().all(|(index, op)| {
                (index >= insert_at && index <= end)
                    || targets(&op.inner).iter().all(|label| {
                        label_at
                            .get(label)
                            .is_none_or(|&target| target <= insert_at || target > end)
                    })
            });
            if !entered_only_at_its_head {
                return None;
            }
            let mut constants: Vec<Ir1Literal> = Vec::new();
            for index in body..=end {
                let literal = match &ops[index].inner {
                    Ir1Op::LoadLiteral { value }
                        if !update_assignment_ignores_operand(
                            ops.get(index + 1).map(|next| &next.inner),
                        ) =>
                    {
                        Some(value.clone())
                    }
                    Ir1Op::GetProperty {
                        key: Ir1PropertyKey::Static(key),
                    }
                    | Ir1Op::SetProperty {
                        key: Ir1PropertyKey::Static(key),
                        ..
                    } => Some(Ir1Literal::String(key.clone())),
                    _ => None,
                };
                if let Some(literal) = literal
                    && !matches!(literal, Ir1Literal::BigInt(_))
                    && !constants.contains(&literal)
                    && constants.len() < MAX_HOISTED_LOOP_CONSTANTS
                {
                    constants.push(literal);
                }
            }
            (!constants.is_empty()).then_some(LoopConstantHoist {
                insert_at,
                end,
                constants,
            })
        })
        .collect()
}

/// bd-9vouw.496: the pinned register a hoisted string constant was loaded
/// into, for a static property key inside its loop.
pub(super) fn hoisted_string_constant(
    hoisted: &[(Ir1Literal, Reg)],
    key: &JsString,
) -> Option<Reg> {
    hoisted
        .iter()
        .find_map(|(literal, register)| match literal {
            Ir1Literal::String(text) if text == key => Some(*register),
            _ => None,
        })
}

pub(super) fn lower_literal_to_ir3_optimized(
    value: &Ir1Literal,
    dst: Reg,
    instructions: &mut Vec<Ir3Instruction>,
    constant_pool: &mut ConstantPool,
) {
    match value {
        Ir1Literal::String(text) => {
            let pool_index = push_constant_optimized(constant_pool, text.clone());
            instructions.push(Ir3Instruction::LoadStr { dst, pool_index });
        }
        Ir1Literal::Integer(value) => {
            instructions.push(Ir3Instruction::LoadInt { dst, value: *value })
        }
        Ir1Literal::BigInt(value) => instructions.push(Ir3Instruction::LoadBigInt {
            dst,
            value: value.clone(),
        }),
        Ir1Literal::Float(bits) => {
            instructions.push(Ir3Instruction::LoadFloat { dst, bits: *bits })
        }
        Ir1Literal::Boolean(value) => {
            instructions.push(Ir3Instruction::LoadBool { dst, value: *value })
        }
        Ir1Literal::Null => instructions.push(Ir3Instruction::LoadNull { dst }),
        Ir1Literal::Undefined => instructions.push(Ir3Instruction::LoadUndefined { dst }),
    }
}

pub(super) fn push_constant_optimized(
    constant_pool: &mut ConstantPool,
    value: impl Into<JsString>,
) -> u32 {
    constant_pool.push(value)
}

/// ES2020 9.2.10 FunctionDeclarationInstantiation / 15.1.11
/// GlobalDeclarationInstantiation: a scope's function declarations are
/// instantiated before any of its statements run, so they lower first (in
/// source order), then every other statement in source order (bd-9vouw.43).
pub(super) fn hoisted_statement_order(body: &[Statement]) -> impl Iterator<Item = &Statement> {
    let is_function_declaration =
        |statement: &&Statement| matches!(statement, Statement::FunctionDeclaration(_));
    body.iter().filter(is_function_declaration).chain(
        body.iter()
            .filter(move |statement| !is_function_declaration(statement)),
    )
}

/// A module's top-level statements in evaluation order: function
/// declarations first (hoisted), then the exports of those functions and
/// every module request (`import`, `export ... from`), then the rest in
/// source order. ES2020 15.2.1.16.4 InitializeEnvironment creates a module's
/// function declarations and its exports of them before any module code
/// runs, and InnerModuleEvaluation evaluates every requested module before
/// the body (bd-9vouw.388): a dependency in a cycle can call an exported
/// function of the module that imported it, and a binding imported by a
/// statement at the end of the module is usable from its first line.
pub(super) fn module_statement_order(body: &[Statement]) -> std::vec::IntoIter<&Statement> {
    let function_names: BTreeSet<&str> = body
        .iter()
        .filter_map(|statement| match statement {
            Statement::FunctionDeclaration(function) => function.name.as_deref(),
            _ => None,
        })
        .collect();
    // A top-level `var` is initialized (undefined) when the module is
    // instantiated, before any import runs, as a function is: its export is
    // published there too, so a module in a cycle reads undefined, not a
    // binding in its temporal dead zone (bd-1lsy.4.10.1).
    let var_names: BTreeSet<&str> = body
        .iter()
        .filter_map(|statement| match statement {
            Statement::VariableDeclaration(declaration)
                if declaration.kind == VariableDeclarationKind::Var =>
            {
                Some(declaration.declarations.iter())
            }
            _ => None,
        })
        .flatten()
        .filter_map(|declarator| match &declarator.pattern {
            BindingPattern::Identifier(name) => Some(name.as_str()),
            _ => None,
        })
        .collect();
    let rank = |statement: &Statement| match statement {
        Statement::FunctionDeclaration(_) => 0u8,
        // `export default function () {}` (also a generator or async
        // function) is a hoistable declaration whose binding is *default*
        // (ES2020 15.2.3): it exists before any module request runs, so a
        // module in a cycle can call it (bd-9vouw.412). Its evaluation has
        // no side effect. A parenthesized `export default (function () {})`
        // has the same tree and is moved too, where the specification would
        // leave *default* uninitialized until the statement runs.
        Statement::Export(ExportDeclaration {
            kind: ExportKind::Default(Expression::Function { .. }),
            ..
        }) => 1,
        Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause(clause),
            ..
        }) if clause.source().is_none() => {
            let locals = parse_named_export_clause_bindings(clause.canonical_head());
            if !locals.is_empty()
                && locals.iter().all(|(local, _)| {
                    function_names.contains(local.as_str()) || var_names.contains(local.as_str())
                })
            {
                1
            } else {
                3
            }
        }
        Statement::Import(_) => 2,
        Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause(clause),
            ..
        }) if clause.source().is_some() => 2,
        _ => 3,
    };
    let mut ordered: Vec<&Statement> = body.iter().collect();
    ordered.sort_by_key(|statement| rank(statement));
    ordered.into_iter()
}

pub(super) fn alloc_register(cursor: &mut Reg) -> Reg {
    let register = *cursor;
    *cursor = cursor.checked_add(1).unwrap_or(u32::MAX);
    register
}

/// bd-9vouw.23: root-scope `let`/`const`/`var` bindings kept in frame
/// registers; the rest of a larger body's live in the runtime scope. Leaves
/// half of the 256-register QuickJS-lane frame for `var`/function bindings and
/// statement temporaries.
pub(super) const MAX_REGISTER_RESIDENT_ROOT_LEXICALS: usize = 128;

/// bd-9vouw.23: register-resident function-body locals. A body with more
/// spills the rest to its function-entry runtime scope. Within the budget a
/// lazily pinned local costs up to two registers (it lands above its own
/// initializer temporary), so 96 of them plus parameters and temporaries fit
/// the 256-register QuickJS-lane frame.
pub(super) const MAX_REGISTER_RESIDENT_FUNCTION_LOCALS: usize = 96;

/// bd-9vouw.23: array/object literals with more entries than this build
/// incrementally (NewArray/NewObject of zero, then one entry at a time) so
/// their entries' temporaries are reused. Smaller literals keep the batch
/// lowering unchanged.
pub(super) const MAX_BATCH_LITERAL_ENTRIES: usize = 64;

/// Sets an incrementally built object literal's prototype for its
/// `__proto__: v` entry and returns the literal (Annex B.3.1).
pub(super) const OBJECT_LITERAL_PROTOTYPE_CAPABILITY: &str = "builtin:ObjectLiteralPrototype";

/// An object literal entry `[key]: <anonymous function definition>`:
/// `(key, value)` to the one-entry object `{ [key]: value }` with the
/// function named by the key (ES2020 12.2.6.8, 9.2.11 SetFunctionName;
/// bd-9vouw.237). The literal spreads it in as any other entry.
pub(super) const OBJECT_LITERAL_NAMED_ENTRY_CAPABILITY: &str = "builtin:ObjectLiteralNamedEntry";
/// `export * from m` (bd-332pq): one argument, m's namespace object.
pub(crate) const MODULE_EXPORT_STAR_HOSTCALL: &str = "builtin:ModuleExportStar";

/// bd-j8f7q: marks a lowering unit whose static flow check assumed that each
/// local file or package it imports ([`is_bounded_import_specifier`]) yields
/// values labelled at most [`IFC_BOUNDED_IMPORT_LABEL`]. The interpreter
/// enforces the assumption at every such import edge before the imported
/// module runs. Lowering adds the marker only when the unit is refused
/// without it, so units that pass today are unchanged. At run time the
/// marker itself is a no-op.
pub(crate) const IFC_BOUNDED_IMPORTS_CONTRACT: &str = "builtin:IfcBoundedImportsContract";

/// The highest label a bounded unit assumes for a local import.
pub(crate) const IFC_BOUNDED_IMPORT_LABEL: Label = Label::Internal;

/// A specifier naming a local file (`./x.mjs`, `../x.mjs`, `/abs/x.mjs`), as
/// opposed to a package or builtin module name.
pub(crate) fn is_local_module_specifier(specifier: &str) -> bool {
    specifier.starts_with("./") || specifier.starts_with("../") || specifier.starts_with('/')
}

/// A specifier the bounded-imports contract covers (bd-j8f7q): a local file,
/// a package, or an engine-owned native provider. Source modules are lowered
/// and checked before execution. Native providers must authenticate their
/// exact descriptor and check their live exported state on every import;
/// all other core modules remain opaque.
pub(crate) fn is_bounded_import_specifier(specifier: &str) -> bool {
    is_local_module_specifier(specifier)
        || !crate::baseline_interpreter::is_node_core_module_specifier(specifier)
        || crate::module_resolver::NativeBuiltinModule::from_specifier(specifier).is_some()
}

pub(super) fn ops_assume_bounded_imports(ops: &[Ir2Op]) -> bool {
    ops.iter().any(|op| {
        matches!(&op.inner, Ir1Op::HostCall { capability, .. }
            if capability == IFC_BOUNDED_IMPORTS_CONTRACT)
    })
}

/// The flow label ceiling of a lowered unit, as its static check computed it
/// (bd-j8f7q): every value the unit can produce is at most this label.
pub(crate) fn lowered_unit_flow_label_ceiling(
    ir2: &Ir2Module,
    host_io_exception_provenance: HostIoExceptionProvenance,
) -> Label {
    ir2_flow_label_ceiling(&ir2.ops, host_io_exception_provenance)
}

/// Source-name slot of a spilled non-lexical function-body local's
/// identity-qualified runtime name (lexical ones keep their source name, as
/// TDZ locals do). Only the binding id distinguishes them: nothing resolves a
/// spilled local by its source name (captured locals take the child-capture
/// route instead).
pub(super) const SPILLED_FUNCTION_LOCAL_NAME: &str = "spilled-local";

/// Upper bound on dataflow passes in `short_lived_local_release_points`;
/// past it every local keeps its pinned register.
pub(super) const MAX_LOCAL_ASSIGNMENT_PASSES: usize = 64;

/// bd-9vouw.23: function locals that need a register only while they are in
/// use. Each candidate (register resident, reached only through
/// Load/Store/InitializeBinding) qualifies when every read follows a write on
/// every path from function entry. That is a forward must-analysis over the
/// body's labels and jumps; `BeginTry` passes its entry state to the catch
/// and finally handlers, since every protected op's state contains it.
/// A qualifying local never reads the frame's initial `undefined`, so a
/// reusable statement register serves it. The register stays reserved from
/// the first reference to the last. It is also reserved through the back
/// edge of every loop that starts after the first reference and before the
/// last, because a value written before such a loop is read inside it.
/// A loop that starts after the first reference cannot carry a value from
/// one iteration to the next: the loop head does not have the local
/// assigned, so each iteration writes it before reading it.
/// Returns the release point of each qualifying local: the op index after
/// which its register is free. `body_ops` is walked once per pass, so callers
/// pass a cheap iterator (the top-level body's ops are IR2-annotated).
pub(super) fn short_lived_local_release_points<'a>(
    body_ops: impl Iterator<Item = &'a Ir1Op> + Clone,
    candidates: &BTreeSet<BindingId>,
) -> BTreeMap<BindingId, usize> {
    fn flow_into(states: &mut BTreeMap<u32, Vec<u64>>, label: u32, state: &[u64]) -> bool {
        match states.get_mut(&label) {
            None => {
                states.insert(label, state.to_vec());
                true
            }
            Some(existing) => {
                let mut changed = false;
                for (word, incoming) in existing.iter_mut().zip(state) {
                    let met = *word & incoming;
                    changed |= met != *word;
                    *word = met;
                }
                changed
            }
        }
    }
    fn has(state: &[u64], index: usize) -> bool {
        state[index / 64] & (1 << (index % 64)) != 0
    }

    if candidates.is_empty() {
        return BTreeMap::new();
    }
    let index_of = candidates
        .iter()
        .enumerate()
        .map(|(index, binding_id)| (*binding_id, index))
        .collect::<BTreeMap<_, _>>();
    let words = candidates.len().div_ceil(64);
    let label_positions = body_ops
        .clone()
        .enumerate()
        .filter_map(|(index, op)| match op {
            Ir1Op::Label { id } => Some((*id, index)),
            _ => None,
        })
        .collect::<BTreeMap<u32, usize>>();

    let mut label_states = BTreeMap::<u32, Vec<u64>>::new();
    let mut read_before_write = vec![0u64; words];
    let mut converged = false;
    for _ in 0..MAX_LOCAL_ASSIGNMENT_PASSES {
        let mut changed = false;
        // `None`: unreachable by fallthrough (after a jump, return or throw).
        let mut state = Some(vec![0u64; words]);
        for op in body_ops.clone() {
            match op {
                Ir1Op::Label { id } => {
                    state = match (state, label_states.get(id)) {
                        (Some(mut current), Some(incoming)) => {
                            for (word, other) in current.iter_mut().zip(incoming) {
                                *word &= other;
                            }
                            Some(current)
                        }
                        (current, None) => current,
                        (None, Some(incoming)) => Some(incoming.clone()),
                    };
                }
                Ir1Op::LoadBinding { binding_id } => {
                    if let (Some(current), Some(&index)) = (&state, index_of.get(binding_id))
                        && !has(current, index)
                    {
                        read_before_write[index / 64] |= 1 << (index % 64);
                    }
                }
                Ir1Op::StoreBinding { binding_id } | Ir1Op::InitializeBinding { binding_id } => {
                    if let (Some(current), Some(&index)) = (&mut state, index_of.get(binding_id)) {
                        current[index / 64] |= 1 << (index % 64);
                    }
                }
                Ir1Op::Jump { label_id } => {
                    if let Some(current) = &state {
                        changed |= flow_into(&mut label_states, *label_id, current);
                    }
                    state = None;
                }
                Ir1Op::JumpIfFalsy { label_id }
                | Ir1Op::JumpIfFalsyConsume { label_id }
                | Ir1Op::JumpIfTruthy { label_id }
                | Ir1Op::JumpIfNullish { label_id }
                | Ir1Op::ForInNext {
                    done_label: label_id,
                }
                | Ir1Op::ForOfNext {
                    done_label: label_id,
                } => {
                    if let Some(current) = &state {
                        changed |= flow_into(&mut label_states, *label_id, current);
                    }
                }
                Ir1Op::BeginTry {
                    catch_label,
                    finally_label,
                } => {
                    if let Some(current) = &state {
                        changed |= flow_into(&mut label_states, *catch_label, current);
                        if let Some(finally_label) = finally_label {
                            changed |= flow_into(&mut label_states, *finally_label, current);
                        }
                    }
                }
                Ir1Op::Return | Ir1Op::Throw => state = None,
                _ => {}
            }
        }
        if !changed {
            converged = true;
            break;
        }
    }
    if !converged {
        return BTreeMap::new();
    }

    let mut back_edges = Vec::<(usize, usize)>::new();
    let mut reference_spans = BTreeMap::<BindingId, (usize, usize)>::new();
    for (index, op) in body_ops.enumerate() {
        match op {
            Ir1Op::Jump { label_id }
            | Ir1Op::JumpIfFalsy { label_id }
            | Ir1Op::JumpIfFalsyConsume { label_id }
            | Ir1Op::JumpIfTruthy { label_id }
            | Ir1Op::JumpIfNullish { label_id }
            | Ir1Op::ForInNext {
                done_label: label_id,
            }
            | Ir1Op::ForOfNext {
                done_label: label_id,
            } => match label_positions.get(label_id) {
                Some(&target) if target < index => back_edges.push((target, index)),
                Some(_) => {}
                // A jump out of the body: no sound loop structure to reason
                // about, so keep every local pinned.
                None => return BTreeMap::new(),
            },
            Ir1Op::LoadBinding { binding_id }
            | Ir1Op::StoreBinding { binding_id }
            | Ir1Op::InitializeBinding { binding_id }
                if index_of.contains_key(binding_id) =>
            {
                reference_spans
                    .entry(*binding_id)
                    .and_modify(|(_, last)| *last = index)
                    .or_insert((index, index));
            }
            _ => {}
        }
    }

    reference_spans
        .into_iter()
        .filter(|(binding_id, _)| {
            let index = index_of[binding_id];
            read_before_write[index / 64] & (1 << (index % 64)) == 0
        })
        .map(|(binding_id, (first, mut last))| {
            loop {
                let mut widened = false;
                for &(loop_head, back_edge) in &back_edges {
                    if first < loop_head && loop_head <= last && back_edge > last {
                        last = back_edge;
                        widened = true;
                    }
                }
                if !widened {
                    break (binding_id, last);
                }
            }
        })
        .collect()
}

/// bd-9vouw.214: the short-lived locals (`releases`: release point of each)
/// that must take the spill route so that at most `capacity` of them hold a
/// register at once. A local holds its register from its first reference
/// through its release point. Scanning first references in order, a local
/// that would exceed the capacity evicts the live one released last
/// (possibly itself), which spills the fewest locals an interval schedule
/// allows.
pub(super) fn short_lived_overlap_spills(
    body_ops: &[Ir1Op],
    releases: &BTreeMap<BindingId, usize>,
    capacity: usize,
) -> BTreeSet<BindingId> {
    if releases.len() <= capacity {
        return BTreeSet::new();
    }
    let mut first_reference = BTreeMap::<BindingId, usize>::new();
    for (index, op) in body_ops.iter().enumerate() {
        if let Ir1Op::LoadBinding { binding_id }
        | Ir1Op::StoreBinding { binding_id }
        | Ir1Op::InitializeBinding { binding_id } = op
            && releases.contains_key(binding_id)
        {
            first_reference.entry(*binding_id).or_insert(index);
        }
    }
    let mut ranges = first_reference
        .into_iter()
        .map(|(binding_id, first)| (first, releases[&binding_id], binding_id))
        .collect::<Vec<_>>();
    ranges.sort_unstable();
    let mut live = BTreeSet::<(usize, BindingId)>::new();
    let mut spilled = BTreeSet::new();
    for (first, release, binding_id) in ranges {
        while let Some(&(live_release, live_id)) = live.first()
            && live_release < first
        {
            live.remove(&(live_release, live_id));
        }
        live.insert((release, binding_id));
        if live.len() > capacity
            && let Some(latest) = live.pop_last()
        {
            spilled.insert(latest.1);
        }
    }
    spilled
}

/// bd-9vouw.23: register of a register-resident function local, allocated at
/// its first reference. A short-lived local takes the lowest register above
/// the pinned region that holds nothing live (not in the live set, not on the
/// value stack) and stays in the live set, which statement-boundary rewinds
/// never go below, until its release point. Taking the next statement
/// register instead placed each local above its own statement's temporaries,
/// so locals live across many statements (a `var` in an inlined `finally`
/// copy) ratcheted the frame by a statement's width each. Every other local
/// pins a fresh register for the rest of the body. The top-level body's
/// lowering-internal temporaries take the same route (bd-9vouw.255).
#[allow(clippy::too_many_arguments)]
pub(super) fn function_local_register(
    binding_id: BindingId,
    binding_registers: &mut BTreeMap<BindingId, Reg>,
    short_lived_locals: &BTreeMap<BindingId, usize>,
    live_registers: &mut BTreeSet<Reg>,
    value_stack: &[Reg],
    cursor: &mut Reg,
    pinned_high: &mut Reg,
    high_water: &mut Reg,
) -> Reg {
    *binding_registers.entry(binding_id).or_insert_with(|| {
        if short_lived_locals.contains_key(&binding_id) {
            let register = (*pinned_high..*cursor)
                .find(|register| {
                    !live_registers.contains(register) && !value_stack.contains(register)
                })
                .unwrap_or_else(|| alloc_register(cursor));
            live_registers.insert(register);
            register
        } else {
            alloc_pinned_register(cursor, pinned_high, high_water)
        }
    })
}

/// bd-9vouw.494: `x = <expr>` and `let x = <expr>` for a register-resident
/// binding computed the value into a temporary and copied it, `Add t, a, b;
/// Move x, t`. When the instruction just emitted wrote that temporary, it
/// writes the binding's register instead and the copy is not emitted.
///
/// Sound only when nothing else can observe the temporary or the order of the
/// two writes, which the caller establishes:
/// - `src` is a dead temporary: above the statement floor and the pinned
///   bindings, not a live slot or an iterator anchor, and not on the value
///   stack once the stored value is popped;
/// - no label is bound at the end of the stream (`label_at_end`), so no jump
///   lands between the producer and the copy (a conditional expression's
///   arms each write the temporary and join there);
/// - the producer sits in the current function (`first_index`).
///
/// The producer kinds read every operand before they write their destination
/// (a call writes it when it returns, a throwing producer never), and each
/// writes a label computed from its operands with `write_reg_with_label`,
/// which the copy reproduced exactly (`Move` writes the source's label the
/// same way). Kinds whose destination label depends on the destination's
/// previous label are excluded: literal loads (`write_reg` keeps the previous
/// label unless the context label dominates it) and `GetProperty` (joins the
/// prior destination label). One call path writes that way too: a call that
/// creates a generator or async-generator object (`write_reg`), so for
/// `g = gen()` the binding keeps its own previous label where the copy gave
/// it the temporary's; both are at least the context label.
pub(super) fn retarget_store_producer(
    instructions: &mut [Ir3Instruction],
    first_index: usize,
    src: Reg,
    dst: Reg,
    src_is_dead_temporary: bool,
    label_at_end: bool,
) -> bool {
    if !src_is_dead_temporary || label_at_end || src == dst || instructions.len() <= first_index {
        return false;
    }
    let Some(last) = instructions.last_mut() else {
        return false;
    };
    // A producer that can run guest code (a callee, a builtin's callbacks, a
    // part's toString) does not get the binding's register when it also
    // reads that register as an operand: `a = a.concat(b)` keeps its copy.
    let in_range = |range: &RegRange| dst >= range.start && dst - range.start < range.count;
    let reads_dst = match &*last {
        Ir3Instruction::Call { callee, args, .. } => *callee == dst || in_range(args),
        Ir3Instruction::CallMethod {
            receiver,
            callee,
            args,
            ..
        } => *receiver == dst || *callee == dst || in_range(args),
        Ir3Instruction::TemplateLiteral { parts, .. } => in_range(parts),
        _ => false,
    };
    if reads_dst {
        return false;
    }
    let written = match last {
        Ir3Instruction::Add { dst, .. }
        | Ir3Instruction::Sub { dst, .. }
        | Ir3Instruction::Mul { dst, .. }
        | Ir3Instruction::Div { dst, .. }
        | Ir3Instruction::Mod { dst, .. }
        | Ir3Instruction::Exp { dst, .. }
        | Ir3Instruction::UnaryNeg { dst, .. }
        | Ir3Instruction::UnaryPlus { dst, .. }
        | Ir3Instruction::LogicalNot { dst, .. }
        | Ir3Instruction::BitNot { dst, .. }
        | Ir3Instruction::TypeOf { dst, .. }
        | Ir3Instruction::Lt { dst, .. }
        | Ir3Instruction::Lte { dst, .. }
        | Ir3Instruction::Gt { dst, .. }
        | Ir3Instruction::Gte { dst, .. }
        | Ir3Instruction::Eq { dst, .. }
        | Ir3Instruction::StrictEq { dst, .. }
        | Ir3Instruction::NotEq { dst, .. }
        | Ir3Instruction::StrictNotEq { dst, .. }
        | Ir3Instruction::BitAnd { dst, .. }
        | Ir3Instruction::BitOr { dst, .. }
        | Ir3Instruction::BitXor { dst, .. }
        | Ir3Instruction::Shl { dst, .. }
        | Ir3Instruction::Shr { dst, .. }
        | Ir3Instruction::Ushr { dst, .. }
        | Ir3Instruction::Move { dst, .. }
        | Ir3Instruction::Call { dst, .. }
        | Ir3Instruction::CallMethod { dst, .. }
        | Ir3Instruction::LoadScoped { dst, .. }
        | Ir3Instruction::TemplateLiteral { dst, .. } => dst,
        _ => return false,
    };
    if *written != src {
        return false;
    }
    *written = dst;
    true
}

/// bd-9vouw.23: once a batch array or object literal is built, its element
/// and key registers are dead. When nothing live sits at or above the lowest
/// of them (no value-stack entry, and it is above the statement floor, pinned
/// bindings and live slots), move the literal to the first register above
/// the value stack's top and that floor, and rewind the cursor past it.
/// Without this, nested literals in one statement used
/// every register until the statement ended (Test262's
/// harness/byteConversionValues.js needed a 1295-register frame).
/// bd-9vouw.494: operands below the floor are binding registers a value read
/// in place (straight_line_consumer_reads_in_place), not temporaries; they
/// are left alone, and the temporaries among the rest are still reclaimed.
/// So are the registers of bindings a straight-line consumer read in place
/// above the floor (`bindings_read_in_place`): a short-lived local read in
/// place is not a temporary of the call or literal that consumes it, and
/// counting it made compaction give up below earlier results (the n68 gate:
/// top-level `[o.m(1), ...]` kept four registers per call).
#[allow(clippy::too_many_arguments)]
pub(super) fn compact_batch_literal(
    instructions: &mut Vec<Ir3Instruction>,
    literal: Reg,
    operands: &[Reg],
    value_stack: &[Reg],
    reserved_below: Reg,
    cursor: &mut Reg,
    high_water: &mut Reg,
    bindings_read_in_place: &BTreeSet<Reg>,
) -> Reg {
    let Some(&lowest_operand) = operands
        .iter()
        .filter(|&&operand| operand >= reserved_below && !bindings_read_in_place.contains(&operand))
        .min()
    else {
        return literal;
    };
    if lowest_operand >= literal
        || value_stack
            .iter()
            .any(|register| *register >= lowest_operand)
    {
        return literal;
    }
    // bd-9vouw.86: the temporaries between the value stack's top and the
    // lowest operand are dead as well: nothing names them but the stack,
    // pinned bindings and live slots, which the floor already excludes (a
    // member call's receiver copy and property key are consumed before the
    // call). So the result goes just above the stack top; taking the lowest
    // operand's register leaked two registers per top-level member call.
    let base = value_stack
        .iter()
        .max()
        .map_or(reserved_below, |top| top.saturating_add(1))
        .max(reserved_below);
    instructions.push(Ir3Instruction::Move {
        dst: base,
        src: literal,
    });
    *high_water = (*high_water).max(*cursor);
    *cursor = base.saturating_add(1);
    base
}

/// The value stack as call-result compaction sees it at the top level. The
/// binding registers a compound assignment reads in place
/// (compound_left_operand_reads_in_place) are pinned bindings, not
/// temporaries, so a stack holding only them compacts as an empty one does:
/// the result stays in its register.
pub(super) fn compaction_value_stack<'a>(
    value_stack: &'a [Reg],
    in_place: &BTreeSet<Reg>,
) -> &'a [Reg] {
    if value_stack
        .iter()
        .all(|register| in_place.contains(register))
    {
        &[]
    } else {
        value_stack
    }
}

/// bd-9vouw.23: once a call (Call, CallMethod, Construct, HostCall) has
/// produced `result`, its callee, receiver and argument registers and the
/// contiguous argument copies are dead. Reclaim the temporaries among them
/// as [`compact_batch_literal`] reclaims a built literal's operands; operands
/// below `reserved_below` (pinned bindings, live slots, the statement floor)
/// are not temporaries and are left alone. Without this each call held about
/// twice its arity plus two registers until its statement ended, so an array
/// literal or argument list of ~40 calls (`[f(1, 2), f(1, 2), ...]`)
/// overflowed the 256-register frame. A call that leaves the value stack
/// empty is left as it is: nothing accumulates above it, and the statement
/// boundary rewind reclaims its registers without an extra Move.
/// bd-9vouw.375: the argument window of a Call or CallMethod. When the
/// arguments already sit in contiguous temporaries that end at the register
/// cursor (each argument expression's own result, in order), at or above
/// `reserved_below`, and none of them is still on the value stack or another
/// operand of the call, the call reads them in place; otherwise each is
/// copied into a fresh contiguous window above the cursor, as before. A call
/// reads its arguments' values and labels from the window when it runs and
/// writes only its result, which is allocated above the window, so reading
/// in place observes the same values: `arg_count` fewer Moves per call.
pub(super) fn call_argument_window(
    args: &[Reg],
    other_operands: &[Reg],
    value_stack: &[Reg],
    reserved_below: Reg,
    cursor: &mut Reg,
    instructions: &mut Vec<Ir3Instruction>,
) -> RegRange {
    let count = u32::try_from(args.len()).unwrap_or(u32::MAX);
    if let (Some(&first), Some(&last)) = (args.first(), args.last())
        && first >= reserved_below
        && last.checked_add(1) == Some(*cursor)
        && args
            .iter()
            .zip(first..)
            .all(|(&arg, expected)| arg == expected)
        && !value_stack
            .iter()
            .chain(other_operands)
            .any(|register| (first..=last).contains(register))
    {
        return RegRange {
            start: first,
            count,
        };
    }
    let start = *cursor;
    for &arg in args {
        let dst = alloc_register(cursor);
        instructions.push(Ir3Instruction::Move { dst, src: arg });
    }
    RegRange { start, count }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn compact_call_result(
    instructions: &mut Vec<Ir3Instruction>,
    result: Reg,
    operands: &[Reg],
    copies: RegRange,
    value_stack: &[Reg],
    reserved_below: Reg,
    cursor: &mut Reg,
    high_water: &mut Reg,
    bindings_read_in_place: &BTreeSet<Reg>,
) -> Reg {
    if value_stack.is_empty() {
        return result;
    }
    let temporaries = operands
        .iter()
        .copied()
        .chain(copies.start..copies.start.saturating_add(copies.count))
        .filter(|register| *register >= reserved_below)
        .collect::<Vec<_>>();
    compact_batch_literal(
        instructions,
        result,
        &temporaries,
        value_stack,
        reserved_below,
        cursor,
        high_water,
        bindings_read_in_place,
    )
}

/// bd-9vouw.23: lowest register a statement-boundary rewind may return to
/// while name-status slots or short-lived locals are live (a status slot is
/// resolved before an assignment's RHS and consumed by its put). Pinning
/// them instead cost one register per assignment to an undeclared name, or
/// per expression temporary, for the rest of the body.
pub(super) fn live_status_register_ceiling(live: &BTreeSet<Reg>) -> Reg {
    live.last().map_or(0, |register| register.saturating_add(1))
}

/// bd-9vouw.494: whether `register` is an expression temporary that nothing
/// names once it has left the value stack: at or above the statement floor,
/// the pinned bindings and the innermost loop iterator's body floor, not a
/// live slot (a name status or a short-lived local, which may sit above it:
/// a method call's receiver local takes the register after its object's
/// copy), and not on the stack.
pub(super) fn is_dead_expression_temporary(
    register: Reg,
    value_stack: &[Reg],
    anchors: &[IteratorAnchor],
    floor: Reg,
    pinned_high: Reg,
    live: &BTreeSet<Reg>,
) -> bool {
    let reserved = floor.max(pinned_high);
    let reserved = anchors
        .last()
        .map_or(reserved, |anchor| reserved.max(anchor.body_floor));
    register >= reserved && !live.contains(&register) && !value_stack.contains(&register)
}

/// bd-9vouw.23: a for-in/for-of iterator that stays on the lowering value
/// stack for its loop's whole body: its stack slot, its register, and the
/// lowest register the body's statements may reuse (the loop head's
/// per-iteration value register, dead once the loop variable is stored).
#[derive(Debug, Clone, Copy)]
pub(super) struct IteratorAnchor {
    pub(super) depth: usize,
    pub(super) iterator: Reg,
    pub(super) body_floor: Reg,
}

/// bd-9vouw.23: where a statement-ending op (Pop, Discard, Return, Throw) may
/// rewind the cursor, if anywhere. An empty value stack ends a statement:
/// rewind to the statement floor. Inside a for-in/for-of body the loop's
/// iterator stays on the stack, so no statement there ever emptied it and a
/// body of ~40 statements overflowed the 256-register frame; when exactly the
/// innermost loop's iterator (and entries below it) remains, rewind to that
/// body's floor instead. Never below pinned bindings or live slots.
pub(super) fn statement_rewind_target(
    value_stack: &[Reg],
    anchors: &[IteratorAnchor],
    floor: Reg,
    pinned_high: Reg,
    live: &BTreeSet<Reg>,
) -> Option<Reg> {
    let base = match (value_stack.last(), anchors.last()) {
        (None, _) => floor,
        (Some(&top), Some(anchor))
            if value_stack.len() == anchor.depth.saturating_add(1)
                && top == anchor.iterator
                && value_stack
                    .iter()
                    .all(|register| *register < anchor.body_floor) =>
        {
            anchor.body_floor.max(floor)
        }
        _ => return None,
    };
    Some(
        base.max(pinned_high)
            .max(live_status_register_ceiling(live)),
    )
}

/// bd-9vouw.202: where the cursor may rewind after an op that consumed the
/// values above the stack's highest live register inside an expression (a
/// member definition leaving its target object, a Discard that did not end
/// the statement). Registers above every live stack value hold dead
/// temporaries: values that cross a label travel through bindings, which
/// `pinned_high` protects, as do live slots and an enclosing loop body's
/// floor. Only an emptied stack used to rewind, so an object or class
/// literal whose expression kept an assignment target on the stack
/// (`internals.Base = class { ... }`, joi's 70-method Base) took fresh
/// registers for every member and overflowed the 256-register frame.
pub(super) fn expression_rewind_target(
    value_stack: &[Reg],
    anchors: &[IteratorAnchor],
    floor: Reg,
    pinned_high: Reg,
    live: &BTreeSet<Reg>,
) -> Option<Reg> {
    let top = value_stack.iter().max()?;
    let target = top
        .saturating_add(1)
        .max(floor)
        .max(pinned_high)
        .max(live_status_register_ceiling(live));
    Some(
        anchors
            .last()
            .map_or(target, |anchor| target.max(anchor.body_floor)),
    )
}

/// bd-9vouw.23: forget loops whose iterator has left the value stack.
/// Whether the value a store into a register-resident binding leaves on the
/// value stack must be read from a copy of the binding's register. The
/// stack entry was the binding's register itself, so when the expression
/// went on to use the value, a later write to the same binding inside that
/// expression changed it: `[i = 2, i = 3]` was [3, 3], `f(++i, ++i)` passed
/// i's final value twice and `(j = 1) + (j = 2)` was 4. A value the next op
/// discards or stores again needs no copy (the statement form, and the
/// method-call chains of bd-9vouw.246, keep their register reuse), and one
/// carried into a jump or label, or expected at an iterator-cleanup label,
/// keeps its register because join points name it.
pub(super) fn store_result_needs_copy(
    next: Option<&Ir1Op>,
    stored: Reg,
    iterator_cleanup_labels: &BTreeMap<u32, Reg>,
) -> bool {
    // bd-9vouw.494: an op that pops the value at once (an operator, a
    // property read, a return) reads the binding's register before anything
    // can write the binding again, so it needs no copy either: a method
    // call's receiver store feeds its method lookup directly. Operator and
    // property-read results never reuse a binding's register, which sits
    // below every reusable temporary (pure_op_result_register).
    !matches!(
        next,
        None | Some(
            Ir1Op::Pop
                | Ir1Op::Discard
                | Ir1Op::StoreBinding { .. }
                | Ir1Op::InitializeBinding { .. }
                | Ir1Op::Label { .. }
                | Ir1Op::Jump { .. }
                | Ir1Op::JumpIfFalsy { .. }
                | Ir1Op::JumpIfFalsyConsume { .. }
                | Ir1Op::JumpIfTruthy { .. }
                | Ir1Op::JumpIfNullish { .. }
                | Ir1Op::BinaryOp { .. }
                | Ir1Op::GetProperty { .. }
                | Ir1Op::Return
        )
    ) && !iterator_cleanup_labels
        .values()
        .any(|register| *register == stored)
}

/// Whether the read of a pinned register binding at `ops[index]` may push the
/// binding's register itself instead of a copy: the op that consumes it comes
/// next, or after one more literal or binding load, so nothing in between can
/// write the binding (a register binding is written only by its own ops; a
/// closure's binding is scoped instead), and that op reads it before it
/// writes anything:
/// - an operator or a static property read (bd-9vouw.330), whose result
///   register is never a pinned one (pure_op_result_register's floor, or a
///   fresh register);
/// - the right operand of an arithmetic or bitwise compound assignment
///   (`s += i`), which pushes the target's value or a fresh register, never
///   its operand (bd-9vouw.486).
///
/// Any other read is a copy, as an assignment may follow it (`x + (x = 5)`).
pub(super) fn pinned_read_consumed_in_place(ops: &[Ir2Op], index: usize) -> bool {
    let op_at = |offset: usize| ops.get(index + offset).map(|op| &op.inner);
    let operator = |op: Option<&Ir1Op>| matches!(op, Some(Ir1Op::BinaryOp { .. }));
    operator(op_at(1))
        || matches!(
            op_at(1),
            Some(Ir1Op::GetProperty {
                key: Ir1PropertyKey::Static(_)
            })
        )
        || compound_assignment_consumes_operand(op_at(1))
        || (matches!(
            op_at(1),
            Some(Ir1Op::LoadLiteral { .. } | Ir1Op::LoadBinding { .. })
        ) && operator(op_at(2)))
}

/// The operator whose result is exactly the negation of `operator`'s, with
/// the same evaluation (`a != b` is `!(a == b)`, ES2020 13.11.1), for an
/// (in)equality; `None` for every other operator (a relational one is false
/// both ways on NaN).
pub(super) fn negated_equality(operator: BinaryOperator) -> Option<BinaryOperator> {
    match operator {
        BinaryOperator::Equal => Some(BinaryOperator::NotEqual),
        BinaryOperator::NotEqual => Some(BinaryOperator::Equal),
        BinaryOperator::StrictEqual => Some(BinaryOperator::StrictNotEqual),
        BinaryOperator::StrictNotEqual => Some(BinaryOperator::StrictEqual),
        _ => None,
    }
}

/// Whether `next` is an arithmetic or bitwise compound assignment to a
/// binding, which takes the IR1 stack top as its right operand.
pub(super) fn compound_assignment_consumes_operand(next: Option<&Ir1Op>) -> bool {
    matches!(
        next,
        Some(Ir1Op::AssignOp { operator, .. }) if matches!(
            operator,
            AssignmentOperator::AddAssign
                | AssignmentOperator::SubtractAssign
                | AssignmentOperator::MultiplyAssign
                | AssignmentOperator::DivideAssign
                | AssignmentOperator::RemainderAssign
                | AssignmentOperator::ExponentiateAssign
                | AssignmentOperator::LeftShiftAssign
                | AssignmentOperator::RightShiftAssign
                | AssignmentOperator::UnsignedRightShiftAssign
                | AssignmentOperator::BitwiseAndAssign
                | AssignmentOperator::BitwiseOrAssign
                | AssignmentOperator::BitwiseXorAssign
        )
    )
}

/// Whether `next` is a `++`/`--` of a binding, whose IR1 right operand (the
/// literal 1) no lowering reads: each steps the target's own value
/// (lower_assign_op_to_ir3, lower_postfix_update_to_ir3, the register arms'
/// `Inc`/`Dec`), so the literal needs a stack slot but no instruction
/// (bd-9vouw.486).
pub(super) fn update_assignment_ignores_operand(next: Option<&Ir1Op>) -> bool {
    matches!(
        next,
        Some(Ir1Op::AssignOp { operator, .. }) if matches!(
            operator,
            AssignmentOperator::IncrementAssign
                | AssignmentOperator::DecrementAssign
                | AssignmentOperator::PostIncrementAssign
                | AssignmentOperator::PostDecrementAssign
        )
    )
}

/// How far the in-place scans below look ahead: every read scans, so an
/// unbounded scan of nested right sides or argument lists was quadratic.
pub(super) const STRAIGHT_LINE_SCAN_LIMIT: usize = 64;

/// The (pops, pushes) of an op that runs no branch and does not write
/// `binding_id`, for the in-place scans below; `None` for every other op
/// (a jump, a label, a write of the binding, an op whose effect is not
/// listed), which ends a scan with a copy.
pub(super) fn straight_line_stack_effect(
    op: &Ir1Op,
    binding_id: BindingId,
) -> Option<(usize, usize)> {
    Some(match op {
        Ir1Op::LoadLiteral { .. } | Ir1Op::LoadName { .. } | Ir1Op::LoadBinding { .. } => (0, 1),
        Ir1Op::StoreBinding { binding_id: other }
        | Ir1Op::AssignOp {
            binding_id: other, ..
        } if *other != binding_id => (1, 1),
        Ir1Op::GetProperty {
            key: Ir1PropertyKey::Static(_),
        }
        | Ir1Op::UnaryOp { .. } => (1, 1),
        Ir1Op::GetProperty {
            key: Ir1PropertyKey::Dynamic,
        }
        | Ir1Op::BinaryOp { .. } => (2, 1),
        Ir1Op::Call { arg_count } => ((*arg_count as usize).saturating_add(1), 1),
        Ir1Op::CallMethod { arg_count } => ((*arg_count as usize).saturating_add(2), 1),
        Ir1Op::NewArray { count } => (*count as usize, 1),
        Ir1Op::NewObject { count } => ((*count as usize).saturating_mul(2), 1),
        Ir1Op::SetProperty {
            key: Ir1PropertyKey::Static(_),
            ..
        } => (2, 1),
        Ir1Op::SetProperty {
            key: Ir1PropertyKey::Dynamic,
            ..
        } => (3, 1),
        _ => return None,
    })
}

/// bd-9vouw.494: whether the read of register binding `binding_id` at
/// `ops[index]` reaches the op that consumes it across straight-line code
/// only, and that op reads it in place when it runs: scanning forward over
/// ops whose stack effect is known, with no op in between writing the
/// binding or branching, the consumer is
/// - a Call taking it as its callee, or a CallMethod taking it as its
///   receiver (the method value sits below it): a call reads both when it
///   runs;
/// - a batch array or object literal taking it as an element, key or value:
///   the literal's CreateDataProperty instructions read their registers when
///   they run, after every operand is evaluated, and write only the fresh
///   object;
/// - an operator or a property read taking it as an operand (bd-9vouw.330's
///   rule when the consumer comes next, now across straight-line code too:
///   `arr[i]`, `i < arr.length`), whose result register is never a
///   binding's (pure_op_result_register's floor, or a fresh register);
/// - a property write taking it as its object or key (`o.n = o.n + 1`).
///
/// A register binding is written only by its own ops (a closure's is
/// scoped), so the register still holds the value read: a method call's
/// receiver local (stored once, before the method lookup), `f(x)` of a local
/// `f` and `{ x: x, y: y }` need no copies. `f(f = g)` and
/// `[x, x = 5]` still read copies.
pub(super) fn straight_line_consumer_reads_in_place(
    ops: &[Ir2Op],
    index: usize,
    binding_id: BindingId,
) -> bool {
    let mut above = 0usize;
    for op in ops
        .iter()
        .skip(index.saturating_add(1))
        .take(STRAIGHT_LINE_SCAN_LIMIT)
    {
        let Some((pops, pushes)) = straight_line_stack_effect(&op.inner, binding_id) else {
            return false;
        };
        if pops > above {
            return match op.inner {
                Ir1Op::Call { arg_count } => {
                    arg_count as usize == above && pops == above.saturating_add(1)
                }
                Ir1Op::CallMethod { arg_count } => {
                    arg_count as usize == above && pops == above.saturating_add(2)
                }
                Ir1Op::NewArray { .. }
                | Ir1Op::NewObject { .. }
                | Ir1Op::BinaryOp { .. }
                | Ir1Op::UnaryOp { .. }
                | Ir1Op::GetProperty { .. } => true,
                // Its object or key, not its value: the property write
                // leaves the value's register on the stack as the
                // assignment's result, which a later op may read after the
                // binding changed (`f(o.p = x, x = 5)`).
                Ir1Op::SetProperty { .. } => above >= 1,
                _ => false,
            };
        }
        above = above - pops + pushes;
    }
    false
}

/// Whether the read of register binding `binding_id` at `ops[index]` is the
/// left operand of a compound assignment that straight-line code alone
/// separates from its operator: scanning forward over ops whose stack effect
/// is known, the op that consumes the read is a BinaryOp taking it as its
/// left operand, the next op assigns the result to the same binding, and no
/// op in between writes the binding or branches. `x op= rhs` reads x before
/// rhs (bd-9vouw.327), but a register binding is written only by its own
/// ops (a closure's binding is scoped instead), so after such an rhs the
/// register still holds the value read and the operator can read it in
/// place. Any other op, or a right side longer than
/// [`STRAIGHT_LINE_SCAN_LIMIT`] ops, ends the scan with a copy.
pub(super) fn compound_left_operand_reads_in_place(
    ops: &[Ir2Op],
    index: usize,
    binding_id: BindingId,
) -> bool {
    // Values pushed above the read and not yet consumed.
    let mut above = 0usize;
    for (offset, op) in ops
        .iter()
        .enumerate()
        .skip(index.saturating_add(1))
        .take(STRAIGHT_LINE_SCAN_LIMIT)
    {
        let Some((pops, pushes)) = straight_line_stack_effect(&op.inner, binding_id) else {
            return false;
        };
        if pops > above {
            return above == 1
                && matches!(op.inner, Ir1Op::BinaryOp { .. })
                && matches!(
                    ops.get(offset + 1).map(|next| &next.inner),
                    Some(Ir1Op::AssignOp {
                        binding_id: assigned,
                        operator: AssignmentOperator::Assign,
                        ..
                    }) if *assigned == binding_id
                );
        }
        above = above - pops + pushes;
    }
    false
}

pub(super) fn prune_iterator_anchors(anchors: &mut Vec<IteratorAnchor>, value_stack: &[Reg]) {
    while anchors
        .last()
        .is_some_and(|anchor| value_stack.get(anchor.depth) != Some(&anchor.iterator))
    {
        anchors.pop();
    }
}

/// bd-9vouw.23: record a loop head's iterator (the stack top) as an anchor for
/// its body, unless the same loop head already did.
pub(super) fn anchor_loop_iterator(
    anchors: &mut Vec<IteratorAnchor>,
    value_stack: &[Reg],
    iterator: Reg,
    body_floor: Reg,
) {
    let depth = value_stack.len().saturating_sub(1);
    if anchors
        .last()
        .is_some_and(|anchor| anchor.depth == depth && anchor.iterator == iterator)
    {
        return;
    }
    anchors.push(IteratorAnchor {
        depth,
        iterator,
        body_floor,
    });
}

/// bd-9vouw.23: allocate a register that must outlive the current statement
/// (a binding or a name-status slot) and raise the floor below which
/// statement-boundary reuse never rewinds the cursor.
pub(super) fn alloc_pinned_register(
    cursor: &mut Reg,
    pinned_high: &mut Reg,
    high_water: &mut Reg,
) -> Reg {
    // Never hand a pinned slot a register that held a rewound statement
    // temporary: a binding read before its first write (a hoisted `var`, a
    // use before a function declaration) must observe the frame's initial
    // `undefined`, not a leftover temporary.
    let register = (*cursor).max(*high_water);
    *cursor = register.saturating_add(1);
    *pinned_high = (*pinned_high).max(*cursor);
    *high_water = (*high_water).max(*cursor);
    register
}

/// bd-9vouw.23: the destination register of a pure operation (a binary or
/// unary operator). Its lowest operand that is a dead statement temporary
/// takes the result, and the registers above it are released: every such
/// IR3 operation reads its operands before it writes its destination. A
/// chain `c0 + c1 + ... + cN` then needs one temporary instead of N, which
/// is what overflowed the 256-register frame in large functions. A popped
/// operand is a dead temporary when it sits at or above `reserved_below`
/// (the statement floor, pinned bindings and live name-status slots) and no
/// value still on the stack sits at or above it.
pub(super) fn pure_op_result_register(
    operands: &[Reg],
    value_stack: &[Reg],
    reserved_below: Reg,
    cursor: &mut Reg,
    high_water: &mut Reg,
) -> Reg {
    let reusable = operands
        .iter()
        .copied()
        .filter(|&operand| {
            operand >= reserved_below && value_stack.iter().all(|&live| live < operand)
        })
        .min();
    match reusable {
        Some(register) => {
            *high_water = (*high_water).max(*cursor);
            *cursor = (*cursor).min(register.saturating_add(1));
            register
        }
        None => alloc_register(cursor),
    }
}

pub(super) fn scope_binding_ids_are_unique(scopes: &[ScopeNode]) -> bool {
    let mut seen = BTreeSet::<BindingId>::new();
    for scope in scopes {
        for binding in &scope.bindings {
            if !seen.insert(binding.binding_id) {
                return false;
            }
        }
    }
    true
}

pub(super) fn hash_string(hash: &ContentHash) -> String {
    format!("sha256:{}", hex::encode(hash.as_bytes()))
}

/// The hash a [`hash_string`] spells, or `None` for any other text.
pub(super) fn content_hash_from_hash_string(text: &str) -> Option<ContentHash> {
    let digits = text.strip_prefix("sha256:")?;
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(digits, &mut bytes).ok()?;
    Some(ContentHash::from_bytes(bytes))
}

pub(super) fn lowering_error_from_ir_error(error: IrError) -> LoweringPipelineError {
    LoweringPipelineError::IrContractValidation {
        code: error.code.as_str().to_string(),
        level: error.level,
        message: error.message,
    }
}

pub(super) fn ensure_checks_pass(
    checks: &[InvariantCheck],
    failure_detail: &'static str,
) -> Result<(), LoweringPipelineError> {
    if checks.iter().any(|check| !check.passed) {
        return Err(LoweringPipelineError::InvariantViolation {
            detail: failure_detail,
        });
    }
    Ok(())
}

pub(super) fn success_event(context: &LoweringContext, event: &str) -> LoweringEvent {
    LoweringEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: event.to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    }
}

pub(super) fn failure_event(
    context: &LoweringContext,
    event: &str,
    error_code: &str,
) -> LoweringEvent {
    LoweringEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: event.to_string(),
        outcome: "fail".to_string(),
        error_code: Some(error_code.to_string()),
    }
}
