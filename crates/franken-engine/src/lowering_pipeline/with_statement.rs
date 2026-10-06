//! ES2020 13.11 `with` statements, as a syntax rewrite ahead of lowering.
//!
//! Lowering binds every identifier to a static slot. In a `with` body, a name
//! the body does not declare itself resolves through an object at run time:
//! HasBinding of an object Environment Record (8.1.1.2.1), including the
//! @@unscopables check. This module rewrites each `with (E) S` into a block
//! the lowering already handles:
//!
//! ```text
//! {
//!   var v1, ...;                                    // `var` names S declares
//!   const __franken_with_object_K = %WithObject(E);  // ToObject(E)
//!   const __franken_with_scope_K = {                // the enclosing environment
//!     get n() { return n; }, set n(value) { n = value; }, ...
//!   };
//!   S'
//! }
//! ```
//!
//! In S', each reference to a name S does not declare resolves through the
//! object first:
//! - `n`, as a value or as an assignment or destructuring target:
//!   `%WithBase(object, scope, "n").n`. That is the object when it has a
//!   binding `n`, otherwise the scope object, whose accessors read and write
//!   the outer binding.
//! - `n(args)`: `%WithBase(object, scope, "n").n.call(receiver, args)`. The
//!   receiver is the object when it supplies `n` (13.3.6.1 step 6.b), and
//!   otherwise what the enclosing environment gives: `%WithReceiver("n")`,
//!   which is `undefined`.
//! - `typeof n`, `delete n`: `%WithHas(object, "n") ? typeof object.n : typeof n`.
//! - `var n = v` assigns `v` as the rewritten `n = v` does: its initializer
//!   assigns through the object environment (13.3.2.4). `var n;` is declared
//!   at the top of the block, since it is function-scoped either way.
//!
//! A nested `with` is rewritten first. The enclosing rewrite then treats the
//! inner block's object expression, accessor bodies and receiver markers like
//! any other code, so resolution continues outward through every enclosing
//! object.
//!
//! Refused, as before: destructuring `var` declarations and destructuring
//! `for-in`/`for-of` heads that bind through the object. `arguments` is never
//! looked up in the object.

use std::collections::BTreeSet;

use super::{LoweringPipelineError, unsupported_frontier_expression_error};
use crate::ast::{
    ArrowBody, AssignmentOperator, AssignmentStrictness, BindingPattern, BlockStatement,
    CatchClause, ExportKind, Expression, ExpressionStatement, FunctionParam, MethodDefinition,
    ObjectProperty, ObjectPropertyKind, ReturnStatement, SourceSpan, Statement, SwitchCase,
    SyntaxTree, UnaryOperator, VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
    WithStatement,
};

/// ToObject of the `with` expression; a TypeError for null and undefined.
pub(super) const WITH_OBJECT_CAPABILITY: &str = "builtin:WithObject";
/// HasBinding(name) of the object Environment Record: `(object, name)`.
pub(super) const WITH_HAS_CAPABILITY: &str = "builtin:WithHas";
/// `(object, fallback, name)`: the object when HasBinding(name), else
/// `fallback`.
pub(super) const WITH_BASE_CAPABILITY: &str = "builtin:WithBase";
/// `(name)`: the receiver of a call to `name` found outside every object;
/// always `undefined`.
pub(super) const WITH_RECEIVER_CAPABILITY: &str = "builtin:WithReceiver";

/// Callee names of the rewrite's intrinsic calls. `%` cannot start a source
/// identifier, so no program can name them.
const OBJECT_INTRINSIC: &str = "%WithObject";
const HAS_INTRINSIC: &str = "%WithHas";
const BASE_INTRINSIC: &str = "%WithBase";
const RECEIVER_INTRINSIC: &str = "%WithReceiver";

/// Prefix of the bindings the rewrite introduces; never looked up in an
/// object.
const SYNTHETIC_PREFIX: &str = "__franken_with_";
const SETTER_PARAMETER: &str = "__franken_with_value";

/// A member call on a free root keeps its source form as one branch (see
/// `Rewriter::member_call_on_free_root`), which copies its arguments. Calls
/// nested deeper than this are refused rather than rewritten in a form the
/// lowering's sink recognition would not see.
const MAX_DUAL_CALL_DEPTH: u32 = 6;

pub(super) type Outcome = Result<(), LoweringPipelineError>;

/// The HostCall tag of a rewrite intrinsic called by `name`, if it is one.
pub(super) fn intrinsic_capability(name: &str) -> Option<&'static str> {
    match name {
        OBJECT_INTRINSIC => Some(WITH_OBJECT_CAPABILITY),
        HAS_INTRINSIC => Some(WITH_HAS_CAPABILITY),
        BASE_INTRINSIC => Some(WITH_BASE_CAPABILITY),
        RECEIVER_INTRINSIC => Some(WITH_RECEIVER_CAPABILITY),
        _ => None,
    }
}

/// `tree` with every `with` statement rewritten, or `None` when it has none.
pub(super) fn rewrite_with_statements(
    tree: &SyntaxTree,
) -> Result<Option<SyntaxTree>, LoweringPipelineError> {
    if !tree
        .body
        .iter()
        .any(|statement| WITH_SEARCH.in_statement(statement))
    {
        return Ok(None);
    }
    let mut tree = tree.clone();
    let mut expander = Expander { next_id: 0 };
    expander.statements(&mut tree.body)?;
    Ok(Some(tree))
}

fn unsupported(message: &str, span: SourceSpan) -> LoweringPipelineError {
    unsupported_frontier_expression_error(
        "with_statement",
        "FE-PARSER-GAP-WITH-0002",
        "lower_ir0_to_ir1.with_statement_binding_pattern",
        message,
        Some(span),
    )
}

/// Replaces the root object of a member chain.
fn replace_member_chain_root(expression: &mut Expression, root: Expression) {
    if let Expression::Member { object, .. } = expression {
        if matches!(object.as_ref(), Expression::Member { .. }) {
            replace_member_chain_root(object, root);
        } else {
            **object = root;
        }
    }
}

fn identifier(name: &str) -> Expression {
    Expression::Identifier(name.to_string())
}

fn string(value: &str) -> Expression {
    Expression::StringLiteral(value.into())
}

fn member(object: Expression, name: &str) -> Expression {
    Expression::Member {
        object: Box::new(object),
        property: Box::new(identifier(name)),
        computed: false,
        span: None,
    }
}

fn intrinsic(name: &str, arguments: Vec<Expression>) -> Expression {
    Expression::Call {
        callee: Box::new(identifier(name)),
        arguments,
        span: None,
    }
}

fn expression_statement(expression: Expression, span: SourceSpan) -> Statement {
    Statement::Expression(ExpressionStatement { expression, span })
}

fn declarator(name: &str, initializer: Option<Expression>, span: SourceSpan) -> VariableDeclarator {
    VariableDeclarator {
        pattern: BindingPattern::Identifier(name.to_string()),
        initializer,
        span,
    }
}

/// A function's parts, as every function form shares them.
pub(super) struct FunctionParts<'a> {
    /// The name a named function expression binds in its own body.
    pub(super) own_name: Option<&'a str>,
    pub(super) params: &'a mut [FunctionParam],
    pub(super) body: FunctionBody<'a>,
}

pub(super) enum FunctionBody<'a> {
    Block(&'a mut BlockStatement),
    Expression(&'a mut Expression),
}

/// A mutable walk over statements and expressions. Each method's default
/// visits the node's children.
pub(super) trait Walk {
    fn statement(&mut self, statement: &mut Statement) -> Outcome {
        walk_statement(self, statement)
    }

    fn statements(&mut self, statements: &mut [Statement]) -> Outcome {
        statements
            .iter_mut()
            .try_for_each(|statement| self.statement(statement))
    }

    /// The statements of a block, switch or catch body.
    fn block(&mut self, statements: &mut [Statement]) -> Outcome {
        self.statements(statements)
    }

    fn catch_clause(&mut self, clause: &mut CatchClause) -> Outcome {
        self.block(&mut clause.body.body)
    }

    fn switch_cases(&mut self, cases: &mut [SwitchCase]) -> Outcome {
        walk_switch_cases(self, cases)
    }

    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        walk_expression(self, expression)
    }

    fn function(&mut self, function: FunctionParts<'_>) -> Outcome {
        walk_function(self, function)
    }

    fn class(
        &mut self,
        name: Option<&str>,
        super_class: Option<&mut Expression>,
        body: &mut [MethodDefinition],
    ) -> Outcome {
        let _ = name;
        walk_class(self, super_class, body)
    }

    fn pattern(&mut self, pattern: &mut BindingPattern) -> Outcome {
        walk_pattern(self, pattern)
    }
}

pub(super) fn walk_statement<W: Walk + ?Sized>(
    walker: &mut W,
    statement: &mut Statement,
) -> Outcome {
    match statement {
        Statement::Import(_) | Statement::Break(_) | Statement::Continue(_) => Ok(()),
        Statement::Export(export) => match &mut export.kind {
            ExportKind::Default(expression) => walker.expression(expression),
            ExportKind::NamedClause(_) => Ok(()),
        },
        Statement::VariableDeclaration(declaration) => {
            for declarator in &mut declaration.declarations {
                walker.pattern(&mut declarator.pattern)?;
                if let Some(initializer) = &mut declarator.initializer {
                    walker.expression(initializer)?;
                }
            }
            Ok(())
        }
        Statement::Expression(statement) => walker.expression(&mut statement.expression),
        Statement::Block(block) => walker.block(&mut block.body),
        Statement::If(statement) => {
            walker.expression(&mut statement.condition)?;
            walker.statement(&mut statement.consequent)?;
            match &mut statement.alternate {
                Some(alternate) => walker.statement(alternate),
                None => Ok(()),
            }
        }
        Statement::For(statement) => {
            if let Some(init) = &mut statement.init {
                walker.statement(init)?;
            }
            if let Some(condition) = &mut statement.condition {
                walker.expression(condition)?;
            }
            if let Some(update) = &mut statement.update {
                walker.expression(update)?;
            }
            walker.statement(&mut statement.body)
        }
        Statement::While(statement) => {
            walker.expression(&mut statement.condition)?;
            walker.statement(&mut statement.body)
        }
        Statement::DoWhile(statement) => {
            walker.statement(&mut statement.body)?;
            walker.expression(&mut statement.condition)
        }
        Statement::With(statement) => {
            walker.expression(&mut statement.object)?;
            walker.statement(&mut statement.body)
        }
        Statement::Return(statement) => match &mut statement.argument {
            Some(argument) => walker.expression(argument),
            None => Ok(()),
        },
        Statement::Throw(statement) => walker.expression(&mut statement.argument),
        Statement::TryCatch(statement) => {
            walker.block(&mut statement.block.body)?;
            if let Some(handler) = &mut statement.handler {
                walker.catch_clause(handler)?;
            }
            match &mut statement.finalizer {
                Some(finalizer) => walker.block(&mut finalizer.body),
                None => Ok(()),
            }
        }
        Statement::Switch(statement) => {
            walker.expression(&mut statement.discriminant)?;
            walker.switch_cases(&mut statement.cases)
        }
        Statement::FunctionDeclaration(function) => walker.function(FunctionParts {
            own_name: None,
            params: &mut function.params,
            body: FunctionBody::Block(&mut function.body),
        }),
        Statement::ClassDeclaration(class) => walker.class(
            class.name.as_deref(),
            class.super_class.as_deref_mut(),
            &mut class.body,
        ),
        Statement::ForIn(statement) => {
            walker.pattern(&mut statement.binding)?;
            walker.expression(&mut statement.object)?;
            walker.statement(&mut statement.body)
        }
        Statement::ForOf(statement) => {
            walker.pattern(&mut statement.binding)?;
            walker.expression(&mut statement.iterable)?;
            walker.statement(&mut statement.body)
        }
        Statement::Labeled(statement) => walker.statement(&mut statement.body),
    }
}

pub(super) fn walk_switch_cases<W: Walk + ?Sized>(
    walker: &mut W,
    cases: &mut [SwitchCase],
) -> Outcome {
    for case in cases {
        if let Some(test) = &mut case.test {
            walker.expression(test)?;
        }
        walker.statements(&mut case.consequent)?;
    }
    Ok(())
}

pub(super) fn walk_expression<W: Walk + ?Sized>(
    walker: &mut W,
    expression: &mut Expression,
) -> Outcome {
    match expression {
        Expression::Identifier(_)
        | Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::FloatLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral
        | Expression::UndefinedLiteral
        | Expression::This
        | Expression::SloppyThis
        | Expression::NewTarget
        | Expression::ImportMeta
        | Expression::Raw(_)
        | Expression::RegExpLiteral { .. }
        | Expression::Super => Ok(()),
        Expression::Await(inner) | Expression::SpreadElement(inner) => walker.expression(inner),
        Expression::Yield { argument, .. } => match argument {
            Some(argument) => walker.expression(argument),
            None => Ok(()),
        },
        Expression::Binary { left, right, .. } | Expression::Assignment { left, right, .. } => {
            walker.expression(left)?;
            walker.expression(right)
        }
        Expression::Unary { argument, .. } => walker.expression(argument),
        Expression::Conditional {
            test,
            consequent,
            alternate,
        } => {
            walker.expression(test)?;
            walker.expression(consequent)?;
            walker.expression(alternate)
        }
        Expression::Call {
            callee, arguments, ..
        }
        | Expression::OptionalCall {
            callee, arguments, ..
        }
        | Expression::New { callee, arguments } => {
            walker.expression(callee)?;
            arguments
                .iter_mut()
                .try_for_each(|argument| walker.expression(argument))
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
            walker.expression(object)?;
            if *computed {
                walker.expression(property)?;
            }
            Ok(())
        }
        Expression::ArrayLiteral(elements) => elements
            .iter_mut()
            .flatten()
            .try_for_each(|element| walker.expression(element)),
        Expression::ObjectLiteral(properties) => {
            for property in properties {
                if property.computed {
                    walker.expression(&mut property.key)?;
                }
                walker.expression(&mut property.value)?;
            }
            Ok(())
        }
        Expression::ArrowFunction { params, body, .. } => walker.function(FunctionParts {
            own_name: None,
            params,
            body: match body {
                ArrowBody::Expression(expression) => FunctionBody::Expression(expression),
                ArrowBody::Block(block) => FunctionBody::Block(block),
            },
        }),
        Expression::TemplateLiteral { expressions, .. } => expressions
            .iter_mut()
            .try_for_each(|expression| walker.expression(expression)),
        Expression::Function {
            name, params, body, ..
        } => walker.function(FunctionParts {
            own_name: name.as_deref(),
            params,
            body: FunctionBody::Block(body),
        }),
        Expression::ClassExpression {
            name,
            super_class,
            body,
        } => walker.class(name.as_deref(), super_class.as_deref_mut(), body),
    }
}

pub(super) fn walk_function<W: Walk + ?Sized>(
    walker: &mut W,
    function: FunctionParts<'_>,
) -> Outcome {
    for param in function.params.iter_mut() {
        walker.pattern(&mut param.pattern)?;
    }
    match function.body {
        FunctionBody::Block(block) => walker.block(&mut block.body),
        FunctionBody::Expression(expression) => walker.expression(expression),
    }
}

pub(super) fn walk_class<W: Walk + ?Sized>(
    walker: &mut W,
    super_class: Option<&mut Expression>,
    body: &mut [MethodDefinition],
) -> Outcome {
    if let Some(super_class) = super_class {
        walker.expression(super_class)?;
    }
    for method in body {
        if method.computed {
            walker.expression(&mut method.key)?;
        }
        walker.function(FunctionParts {
            own_name: None,
            params: &mut method.params,
            body: FunctionBody::Block(&mut method.body),
        })?;
    }
    Ok(())
}

pub(super) fn walk_pattern<W: Walk + ?Sized>(
    walker: &mut W,
    pattern: &mut BindingPattern,
) -> Outcome {
    match pattern {
        BindingPattern::Identifier(_) => Ok(()),
        BindingPattern::ObjectPattern(properties) => {
            for property in properties {
                if property.computed {
                    walker.expression(&mut property.key)?;
                }
                walker.pattern(&mut property.value)?;
            }
            Ok(())
        }
        BindingPattern::ArrayPattern(elements) => elements
            .iter_mut()
            .flatten()
            .try_for_each(|element| walker.pattern(element)),
        BindingPattern::Rest(inner) => walker.pattern(inner),
        BindingPattern::AssignmentPattern { left, right } => {
            walker.pattern(left)?;
            walker.expression(right)
        }
    }
}

/// Whether a `with` statement occurs anywhere in `statement`, including
/// inside function and class bodies.
/// A read-only search of a program for a statement or expression.
pub(super) struct Search {
    pub(super) statement: fn(&Statement) -> bool,
    pub(super) expression: fn(&Expression) -> bool,
}

/// A `with` statement anywhere.
const WITH_SEARCH: Search = Search {
    statement: |statement| matches!(statement, Statement::With(_)),
    expression: |_| false,
};

impl Search {
    pub(super) fn in_statement(&self, statement: &Statement) -> bool {
        if (self.statement)(statement) {
            return true;
        }
        let any_statement = |statements: &[Statement]| {
            statements
                .iter()
                .any(|statement| self.in_statement(statement))
        };
        match statement {
            Statement::With(statement) => {
                self.in_expression(&statement.object) || self.in_statement(&statement.body)
            }
            Statement::Import(_) | Statement::Break(_) | Statement::Continue(_) => false,
            Statement::Export(export) => match &export.kind {
                ExportKind::Default(expression) => self.in_expression(expression),
                ExportKind::NamedClause(_) => false,
            },
            Statement::VariableDeclaration(declaration) => {
                declaration.declarations.iter().any(|declarator| {
                    self.in_pattern(&declarator.pattern)
                        || declarator
                            .initializer
                            .as_ref()
                            .is_some_and(|node| self.in_expression(node))
                })
            }
            Statement::Expression(statement) => self.in_expression(&statement.expression),
            Statement::Block(block) => any_statement(&block.body),
            Statement::If(statement) => {
                self.in_expression(&statement.condition)
                    || self.in_statement(&statement.consequent)
                    || statement
                        .alternate
                        .as_deref()
                        .is_some_and(|node| self.in_statement(node))
            }
            Statement::For(statement) => {
                statement
                    .init
                    .as_deref()
                    .is_some_and(|node| self.in_statement(node))
                    || statement
                        .condition
                        .as_ref()
                        .is_some_and(|node| self.in_expression(node))
                    || statement
                        .update
                        .as_ref()
                        .is_some_and(|node| self.in_expression(node))
                    || self.in_statement(&statement.body)
            }
            Statement::While(statement) => {
                self.in_expression(&statement.condition) || self.in_statement(&statement.body)
            }
            Statement::DoWhile(statement) => {
                self.in_statement(&statement.body) || self.in_expression(&statement.condition)
            }
            Statement::Return(statement) => statement
                .argument
                .as_ref()
                .is_some_and(|node| self.in_expression(node)),
            Statement::Throw(statement) => self.in_expression(&statement.argument),
            Statement::TryCatch(statement) => {
                any_statement(&statement.block.body)
                    || statement
                        .handler
                        .as_ref()
                        .is_some_and(|handler| any_statement(&handler.body.body))
                    || statement
                        .finalizer
                        .as_ref()
                        .is_some_and(|finalizer| any_statement(&finalizer.body))
            }
            Statement::Switch(statement) => {
                self.in_expression(&statement.discriminant)
                    || statement.cases.iter().any(|case| {
                        case.test
                            .as_ref()
                            .is_some_and(|node| self.in_expression(node))
                            || any_statement(&case.consequent)
                    })
            }
            Statement::FunctionDeclaration(function) => {
                function
                    .params
                    .iter()
                    .any(|param| self.in_pattern(&param.pattern))
                    || any_statement(&function.body.body)
            }
            Statement::ClassDeclaration(class) => {
                self.in_class(class.super_class.as_deref(), &class.body)
            }
            Statement::ForIn(statement) => {
                self.in_pattern(&statement.binding)
                    || self.in_expression(&statement.object)
                    || self.in_statement(&statement.body)
            }
            Statement::ForOf(statement) => {
                self.in_pattern(&statement.binding)
                    || self.in_expression(&statement.iterable)
                    || self.in_statement(&statement.body)
            }
            Statement::Labeled(statement) => self.in_statement(&statement.body),
        }
    }

    pub(super) fn in_expression(&self, expression: &Expression) -> bool {
        if (self.expression)(expression) {
            return true;
        }
        let any = |expressions: &[Expression]| {
            expressions
                .iter()
                .any(|expression| self.in_expression(expression))
        };
        match expression {
            Expression::Identifier(_)
            | Expression::StringLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::FloatLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral
            | Expression::UndefinedLiteral
            | Expression::This
            | Expression::SloppyThis
            | Expression::NewTarget
            | Expression::ImportMeta
            | Expression::Raw(_)
            | Expression::RegExpLiteral { .. }
            | Expression::Super => false,
            Expression::Await(inner) | Expression::SpreadElement(inner) => {
                self.in_expression(inner)
            }
            Expression::Yield { argument, .. } => argument
                .as_deref()
                .is_some_and(|node| self.in_expression(node)),
            Expression::Binary { left, right, .. } | Expression::Assignment { left, right, .. } => {
                self.in_expression(left) || self.in_expression(right)
            }
            Expression::Unary { argument, .. } => self.in_expression(argument),
            Expression::Conditional {
                test,
                consequent,
                alternate,
            } => {
                self.in_expression(test)
                    || self.in_expression(consequent)
                    || self.in_expression(alternate)
            }
            Expression::Call {
                callee, arguments, ..
            }
            | Expression::OptionalCall {
                callee, arguments, ..
            }
            | Expression::New { callee, arguments } => self.in_expression(callee) || any(arguments),
            Expression::Member {
                object, property, ..
            }
            | Expression::OptionalMember {
                object, property, ..
            } => self.in_expression(object) || self.in_expression(property),
            Expression::ArrayLiteral(elements) => elements
                .iter()
                .flatten()
                .any(|node| self.in_expression(node)),
            Expression::ObjectLiteral(properties) => properties.iter().any(|property| {
                self.in_expression(&property.key) || self.in_expression(&property.value)
            }),
            Expression::ArrowFunction { params, body, .. } => {
                params.iter().any(|param| self.in_pattern(&param.pattern))
                    || match body {
                        ArrowBody::Expression(expression) => self.in_expression(expression),
                        ArrowBody::Block(block) => {
                            block.body.iter().any(|node| self.in_statement(node))
                        }
                    }
            }
            Expression::TemplateLiteral { expressions, .. } => any(expressions),
            Expression::Function { params, body, .. } => {
                params.iter().any(|param| self.in_pattern(&param.pattern))
                    || body.body.iter().any(|node| self.in_statement(node))
            }
            Expression::ClassExpression {
                super_class, body, ..
            } => self.in_class(super_class.as_deref(), body),
        }
    }

    fn in_class(&self, super_class: Option<&Expression>, body: &[MethodDefinition]) -> bool {
        super_class.is_some_and(|node| self.in_expression(node))
            || body.iter().any(|method| {
                self.in_expression(&method.key)
                    || method
                        .params
                        .iter()
                        .any(|param| self.in_pattern(&param.pattern))
                    || method.body.body.iter().any(|node| self.in_statement(node))
            })
    }

    fn in_pattern(&self, pattern: &BindingPattern) -> bool {
        match pattern {
            BindingPattern::Identifier(_) => false,
            BindingPattern::ObjectPattern(properties) => properties.iter().any(|property| {
                self.in_expression(&property.key) || self.in_pattern(&property.value)
            }),
            BindingPattern::ArrayPattern(elements) => {
                elements.iter().flatten().any(|node| self.in_pattern(node))
            }
            BindingPattern::Rest(inner) => self.in_pattern(inner),
            BindingPattern::AssignmentPattern { left, right } => {
                self.in_pattern(left) || self.in_expression(right)
            }
        }
    }
}

/// Rewrites every `with` statement, innermost first.
struct Expander {
    next_id: u32,
}

impl Walk for Expander {
    fn statement(&mut self, statement: &mut Statement) -> Outcome {
        walk_statement(self, statement)?;
        if let Statement::With(with_statement) = statement {
            let id = self.next_id;
            self.next_id += 1;
            let span = with_statement.span;
            let with_statement = std::mem::replace(
                with_statement,
                WithStatement {
                    object: Expression::UndefinedLiteral,
                    body: Box::new(Statement::Block(BlockStatement {
                        body: Vec::new(),
                        span,
                    })),
                    span,
                },
            );
            *statement = expand_with(id, with_statement)?;
        }
        Ok(())
    }
}

fn expand_with(id: u32, with_statement: WithStatement) -> Result<Statement, LoweringPipelineError> {
    let span = with_statement.span;
    let object = format!("{SYNTHETIC_PREFIX}object_{id}");
    let scope = format!("{SYNTHETIC_PREFIX}scope_{id}");
    let mut rewriter = Rewriter {
        object: &object,
        scope: &scope,
        id,
        scopes: Vec::new(),
        names: BTreeSet::new(),
        hoisted: BTreeSet::new(),
        next_iteration: 0,
        dual_call_depth: 0,
        span,
    };
    let mut body = *with_statement.body;
    rewriter.statement(&mut body)?;

    let mut statements = Vec::with_capacity(4);
    if !rewriter.hoisted.is_empty() {
        statements.push(Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Var,
            declarations: rewriter
                .hoisted
                .iter()
                .map(|name| declarator(name, None, span))
                .collect(),
            span,
        }));
    }
    statements.push(Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![declarator(
            &object,
            Some(intrinsic(OBJECT_INTRINSIC, vec![with_statement.object])),
            span,
        )],
        span,
    }));
    if !rewriter.names.is_empty() {
        statements.push(Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![declarator(
                &scope,
                Some(scope_object(&rewriter.names, span)),
                span,
            )],
            span,
        }));
    }
    statements.push(body);
    Ok(Statement::Block(BlockStatement {
        body: statements,
        span,
    }))
}

/// `{ get n() { return n; }, set n(value) { n = value; }, ... }`: the
/// bindings of the enclosing environment, as properties.
fn scope_object(names: &BTreeSet<String>, span: SourceSpan) -> Expression {
    let mut properties = Vec::with_capacity(names.len() * 2);
    for name in names {
        properties.push(ObjectProperty {
            key: identifier(name),
            value: Expression::Function {
                name: None,
                params: Vec::new(),
                body: BlockStatement {
                    body: vec![Statement::Return(ReturnStatement {
                        argument: Some(identifier(name)),
                        span,
                    })],
                    span,
                },
                is_async: false,
                is_generator: false,
            },
            computed: false,
            shorthand: false,
            kind: ObjectPropertyKind::Get,
        });
        properties.push(ObjectProperty {
            key: identifier(name),
            value: Expression::Function {
                name: None,
                params: vec![FunctionParam {
                    pattern: BindingPattern::Identifier(SETTER_PARAMETER.to_string()),
                    span,
                }],
                body: BlockStatement {
                    body: vec![expression_statement(
                        Expression::Assignment {
                            operator: AssignmentOperator::Assign,
                            left: Box::new(identifier(name)),
                            right: Box::new(identifier(SETTER_PARAMETER)),
                            assignment_strictness: AssignmentStrictness::Sloppy,
                        },
                        span,
                    )],
                    span,
                },
                is_async: false,
                is_generator: false,
            },
            computed: false,
            shorthand: false,
            kind: ObjectPropertyKind::Set,
        });
    }
    Expression::ObjectLiteral(properties)
}

/// Names a statement list declares for its own block: `let`, `const`,
/// classes and functions.
pub(super) fn lexical_names(statements: &[Statement], names: &mut BTreeSet<String>) {
    for statement in statements {
        match statement {
            Statement::VariableDeclaration(declaration)
                if declaration.kind != VariableDeclarationKind::Var =>
            {
                for declarator in &declaration.declarations {
                    names.extend(
                        declarator
                            .pattern
                            .binding_names()
                            .into_iter()
                            .map(str::to_string),
                    );
                }
            }
            Statement::ClassDeclaration(class) => names.extend(class.name.clone()),
            Statement::FunctionDeclaration(function) => names.extend(function.name.clone()),
            _ => {}
        }
    }
}

/// Names `var` and nested function declarations bind in a function body,
/// without entering nested functions.
pub(super) fn var_names(statements: &[Statement], names: &mut BTreeSet<String>) {
    fn visit(statement: &Statement, names: &mut BTreeSet<String>) {
        match statement {
            Statement::VariableDeclaration(declaration)
                if declaration.kind == VariableDeclarationKind::Var =>
            {
                for declarator in &declaration.declarations {
                    names.extend(
                        declarator
                            .pattern
                            .binding_names()
                            .into_iter()
                            .map(str::to_string),
                    );
                }
            }
            Statement::FunctionDeclaration(function) => names.extend(function.name.clone()),
            Statement::Block(block) => block.body.iter().for_each(|nested| visit(nested, names)),
            Statement::If(statement) => {
                visit(&statement.consequent, names);
                if let Some(alternate) = &statement.alternate {
                    visit(alternate, names);
                }
            }
            Statement::For(statement) => {
                if let Some(init) = &statement.init {
                    visit(init, names);
                }
                visit(&statement.body, names);
            }
            Statement::ForIn(statement) => {
                if statement.binding_kind == Some(VariableDeclarationKind::Var) {
                    names.extend(
                        statement
                            .binding
                            .binding_names()
                            .into_iter()
                            .map(str::to_string),
                    );
                }
                visit(&statement.body, names);
            }
            Statement::ForOf(statement) => {
                if statement.binding_kind == Some(VariableDeclarationKind::Var) {
                    names.extend(
                        statement
                            .binding
                            .binding_names()
                            .into_iter()
                            .map(str::to_string),
                    );
                }
                visit(&statement.body, names);
            }
            Statement::While(statement) => visit(&statement.body, names),
            Statement::DoWhile(statement) => visit(&statement.body, names),
            Statement::With(statement) => visit(&statement.body, names),
            Statement::Labeled(statement) => visit(&statement.body, names),
            Statement::TryCatch(statement) => {
                statement
                    .block
                    .body
                    .iter()
                    .for_each(|nested| visit(nested, names));
                if let Some(handler) = &statement.handler {
                    handler
                        .body
                        .body
                        .iter()
                        .for_each(|nested| visit(nested, names));
                }
                if let Some(finalizer) = &statement.finalizer {
                    finalizer
                        .body
                        .iter()
                        .for_each(|nested| visit(nested, names));
                }
            }
            Statement::Switch(statement) => {
                for case in &statement.cases {
                    case.consequent
                        .iter()
                        .for_each(|nested| visit(nested, names));
                }
            }
            _ => {}
        }
    }
    statements
        .iter()
        .for_each(|statement| visit(statement, names));
}

/// Rewrites the references of one `with` body.
struct Rewriter<'a> {
    object: &'a str,
    scope: &'a str,
    id: u32,
    /// Names declared inside the body, innermost last.
    scopes: Vec<BTreeSet<String>>,
    /// Names reached through the scope object.
    names: BTreeSet<String>,
    /// `var` names the body declares at its own function level.
    hoisted: BTreeSet<String>,
    next_iteration: u32,
    /// Nesting depth of member calls kept in both forms (see
    /// `member_call_on_free_root`).
    dual_call_depth: u32,
    /// The `with` statement's span, for diagnostics.
    span: SourceSpan,
}

impl Rewriter<'_> {
    /// Whether a reference to `name` here resolves through the object first.
    fn is_free(&self, name: &str) -> bool {
        !name.starts_with(SYNTHETIC_PREFIX)
            && !name.starts_with('%')
            && name != "arguments"
            && !self.scopes.iter().any(|scope| scope.contains(name))
    }

    fn free_identifier(&self, expression: &Expression) -> Option<String> {
        match expression {
            Expression::Identifier(name) if self.is_free(name) => Some(name.clone()),
            _ => None,
        }
    }

    /// `%WithBase(object, scope, "name").name`.
    fn reference(&mut self, name: &str) -> Expression {
        self.names.insert(name.to_string());
        member(
            intrinsic(
                BASE_INTRINSIC,
                vec![
                    identifier(self.object),
                    identifier(self.scope),
                    string(name),
                ],
            ),
            name,
        )
    }

    /// `%WithBase(object, %WithReceiver("name"), "name")`.
    fn receiver(&self, name: &str) -> Expression {
        intrinsic(
            BASE_INTRINSIC,
            vec![
                identifier(self.object),
                intrinsic(RECEIVER_INTRINSIC, vec![string(name)]),
                string(name),
            ],
        )
    }

    /// The free root of a member chain `n.a.b` (computed members included).
    fn member_chain_root(&self, expression: &Expression) -> Option<String> {
        match expression {
            Expression::Member { object, .. } => match object.as_ref() {
                Expression::Identifier(name) if self.is_free(name) => Some(name.clone()),
                Expression::Member { .. } => self.member_chain_root(object),
                _ => None,
            },
            _ => None,
        }
    }

    /// `n.a.b(args)` on a free root `n`:
    /// `%WithHas(object, "n") ? object.n.a.b(args) : n.a.b(args)`. The second
    /// branch is the source form, so the lowering still recognizes
    /// `console.log(...)`, module-alias calls and other syntactic sinks and
    /// builtins there, and checks the arguments' labels against them. The
    /// arguments are rewritten once and copied into both branches.
    fn member_call_on_free_root(
        &mut self,
        root: String,
        callee: &mut Expression,
        arguments: &mut Vec<Expression>,
        span: Option<SourceSpan>,
    ) -> Result<Expression, LoweringPipelineError> {
        if self.dual_call_depth >= MAX_DUAL_CALL_DEPTH {
            return Err(unsupported(
                "member calls nested too deeply inside a with statement are not supported",
                span.unwrap_or(self.span),
            ));
        }
        self.dual_call_depth += 1;
        let outcome = (|| {
            self.rewrite_member_chain_properties(callee)?;
            for argument in arguments.iter_mut() {
                self.expression(argument)?;
            }
            Ok(())
        })();
        self.dual_call_depth -= 1;
        outcome?;
        let mut object_callee = callee.clone();
        replace_member_chain_root(&mut object_callee, member(identifier(self.object), &root));
        Ok(Expression::Conditional {
            test: Box::new(intrinsic(
                HAS_INTRINSIC,
                vec![identifier(self.object), string(&root)],
            )),
            consequent: Box::new(Expression::Call {
                callee: Box::new(object_callee),
                arguments: arguments.clone(),
                span,
            }),
            alternate: Box::new(Expression::Call {
                callee: Box::new(callee.clone()),
                arguments: std::mem::take(arguments),
                span,
            }),
        })
    }

    /// Rewrites the computed properties of a member chain, leaving its root.
    fn rewrite_member_chain_properties(&mut self, expression: &mut Expression) -> Outcome {
        if let Expression::Member {
            object,
            property,
            computed,
            ..
        } = expression
        {
            if *computed {
                self.expression(property)?;
            }
            if matches!(object.as_ref(), Expression::Member { .. }) {
                self.rewrite_member_chain_properties(object)?;
            }
        }
        Ok(())
    }

    fn scoped(
        &mut self,
        names: BTreeSet<String>,
        walk: impl FnOnce(&mut Self) -> Outcome,
    ) -> Outcome {
        self.scopes.push(names);
        let outcome = walk(self);
        self.scopes.pop();
        outcome
    }

    /// `n = value`, through the object.
    fn assign(&mut self, name: &str, value: Expression) -> Expression {
        Expression::Assignment {
            operator: AssignmentOperator::Assign,
            left: Box::new(self.reference(name)),
            right: Box::new(value),
            assignment_strictness: AssignmentStrictness::Sloppy,
        }
    }

    /// The assignments a `var` declaration at the body's function level
    /// makes; its names are hoisted to the rewritten block.
    fn var_assignments(
        &mut self,
        declaration: VariableDeclaration,
    ) -> Result<Vec<(Expression, SourceSpan)>, LoweringPipelineError> {
        let mut assignments = Vec::new();
        for declarator in declaration.declarations {
            let BindingPattern::Identifier(name) = &declarator.pattern else {
                return Err(unsupported(
                    "a destructuring var declaration inside a with statement is not supported",
                    declarator.span,
                ));
            };
            self.hoisted.insert(name.clone());
            if let Some(mut initializer) = declarator.initializer {
                self.expression(&mut initializer)?;
                assignments.push((self.assign(name, initializer), declarator.span));
            }
        }
        Ok(assignments)
    }

    fn declares_outer_var(&self, declaration: &VariableDeclaration) -> bool {
        declaration.kind == VariableDeclarationKind::Var
            && declaration
                .declarations
                .iter()
                .flat_map(|declarator| declarator.pattern.binding_names())
                .any(|name| self.is_free(name))
    }

    /// `for (n in/of ...)` and `for (var n in/of ...)` assign each value to
    /// `n` through the object: iterate a fresh constant and assign it first.
    fn rebind_loop_head(
        &mut self,
        binding: &mut BindingPattern,
        binding_kind: &mut Option<VariableDeclarationKind>,
        body: &mut Statement,
        span: SourceSpan,
    ) -> Outcome {
        let BindingPattern::Identifier(name) = binding else {
            return Err(unsupported(
                "a destructuring for-in/for-of head inside a with statement is not supported",
                span,
            ));
        };
        let name = name.clone();
        if *binding_kind == Some(VariableDeclarationKind::Var) {
            self.hoisted.insert(name.clone());
        }
        let iteration = format!(
            "{SYNTHETIC_PREFIX}iteration_{}_{}",
            self.id, self.next_iteration
        );
        self.next_iteration += 1;
        *binding = BindingPattern::Identifier(iteration.clone());
        *binding_kind = Some(VariableDeclarationKind::Const);
        self.statement(body)?;
        let original = std::mem::replace(
            body,
            Statement::Block(BlockStatement {
                body: Vec::new(),
                span,
            }),
        );
        let assignment = self.assign(&name, identifier(&iteration));
        *body = Statement::Block(BlockStatement {
            body: vec![expression_statement(assignment, span), original],
            span,
        });
        Ok(())
    }
}

impl Walk for Rewriter<'_> {
    fn statement(&mut self, statement: &mut Statement) -> Outcome {
        match statement {
            Statement::VariableDeclaration(declaration) if self.declares_outer_var(declaration) => {
                let span = declaration.span;
                let declaration = std::mem::replace(
                    declaration,
                    VariableDeclaration {
                        kind: VariableDeclarationKind::Var,
                        declarations: Vec::new(),
                        span,
                    },
                );
                let assignments = self.var_assignments(declaration)?;
                *statement = Statement::Block(BlockStatement {
                    body: assignments
                        .into_iter()
                        .map(|(assignment, span)| expression_statement(assignment, span))
                        .collect(),
                    span,
                });
                Ok(())
            }
            Statement::For(for_statement) => {
                let (outer_var_init, loop_names) = match for_statement.init.as_deref() {
                    Some(Statement::VariableDeclaration(declaration))
                        if self.declares_outer_var(declaration) =>
                    {
                        (true, BTreeSet::new())
                    }
                    Some(Statement::VariableDeclaration(declaration))
                        if declaration.kind != VariableDeclarationKind::Var =>
                    {
                        let names = declaration
                            .declarations
                            .iter()
                            .flat_map(|declarator| declarator.pattern.binding_names())
                            .map(str::to_string)
                            .collect();
                        (false, names)
                    }
                    _ => (false, BTreeSet::new()),
                };
                if !outer_var_init {
                    return self.scoped(loop_names, |rewriter| walk_statement(rewriter, statement));
                }
                // `for (var i = 0; ...)` at the body's level: the initializers
                // assign through the object; the rest walks as usual.
                if let Some(init) = for_statement.init.take()
                    && let Statement::VariableDeclaration(declaration) = *init
                {
                    let span = declaration.span;
                    let mut assignments: Vec<Expression> = self
                        .var_assignments(declaration)?
                        .into_iter()
                        .map(|(assignment, _)| assignment)
                        .collect();
                    for_statement.init = match assignments.len() {
                        0 => None,
                        1 => Some(Box::new(expression_statement(assignments.remove(0), span))),
                        // No sequence expression in the syntax tree: an array
                        // literal evaluates its elements in order.
                        _ => Some(Box::new(expression_statement(
                            Expression::ArrayLiteral(assignments.into_iter().map(Some).collect()),
                            span,
                        ))),
                    };
                }
                if let Some(condition) = &mut for_statement.condition {
                    self.expression(condition)?;
                }
                if let Some(update) = &mut for_statement.update {
                    self.expression(update)?;
                }
                self.statement(&mut for_statement.body)
            }
            Statement::ForIn(for_in) => {
                let names: BTreeSet<String> = for_in
                    .binding
                    .binding_names()
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                if !matches!(
                    for_in.binding_kind,
                    Some(VariableDeclarationKind::Let | VariableDeclarationKind::Const)
                ) && names.iter().any(|name| self.is_free(name))
                {
                    self.expression(&mut for_in.object)?;
                    return self.rebind_loop_head(
                        &mut for_in.binding,
                        &mut for_in.binding_kind,
                        &mut for_in.body,
                        for_in.span,
                    );
                }
                let lexical = matches!(
                    for_in.binding_kind,
                    Some(VariableDeclarationKind::Let | VariableDeclarationKind::Const)
                );
                self.scoped(if lexical { names } else { BTreeSet::new() }, |rewriter| {
                    walk_statement(rewriter, statement)
                })
            }
            Statement::ForOf(for_of) => {
                let names: BTreeSet<String> = for_of
                    .binding
                    .binding_names()
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                if !matches!(
                    for_of.binding_kind,
                    Some(VariableDeclarationKind::Let | VariableDeclarationKind::Const)
                ) && names.iter().any(|name| self.is_free(name))
                {
                    self.expression(&mut for_of.iterable)?;
                    return self.rebind_loop_head(
                        &mut for_of.binding,
                        &mut for_of.binding_kind,
                        &mut for_of.body,
                        for_of.span,
                    );
                }
                let lexical = matches!(
                    for_of.binding_kind,
                    Some(VariableDeclarationKind::Let | VariableDeclarationKind::Const)
                );
                self.scoped(if lexical { names } else { BTreeSet::new() }, |rewriter| {
                    walk_statement(rewriter, statement)
                })
            }
            _ => walk_statement(self, statement),
        }
    }

    fn block(&mut self, statements: &mut [Statement]) -> Outcome {
        let mut names = BTreeSet::new();
        lexical_names(statements, &mut names);
        self.scoped(names, |rewriter| rewriter.statements(statements))
    }

    fn catch_clause(&mut self, clause: &mut CatchClause) -> Outcome {
        let mut names: BTreeSet<String> = clause.parameter.iter().cloned().collect();
        lexical_names(&clause.body.body, &mut names);
        self.scoped(names, |rewriter| rewriter.statements(&mut clause.body.body))
    }

    fn switch_cases(&mut self, cases: &mut [SwitchCase]) -> Outcome {
        let mut names = BTreeSet::new();
        for case in cases.iter() {
            lexical_names(&case.consequent, &mut names);
        }
        self.scoped(names, |rewriter| walk_switch_cases(rewriter, cases))
    }

    fn function(&mut self, function: FunctionParts<'_>) -> Outcome {
        let mut names = BTreeSet::new();
        names.extend(function.own_name.map(str::to_string));
        for param in function.params.iter() {
            names.extend(
                param
                    .pattern
                    .binding_names()
                    .into_iter()
                    .map(str::to_string),
            );
        }
        if let FunctionBody::Block(block) = &function.body {
            var_names(&block.body, &mut names);
            lexical_names(&block.body, &mut names);
        }
        self.scoped(names, |rewriter| walk_function(rewriter, function))
    }

    fn class(
        &mut self,
        name: Option<&str>,
        super_class: Option<&mut Expression>,
        body: &mut [MethodDefinition],
    ) -> Outcome {
        let names = name.map(str::to_string).into_iter().collect();
        self.scoped(names, |rewriter| walk_class(rewriter, super_class, body))
    }

    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        if let Some(name) = self.free_identifier(expression) {
            *expression = self.reference(&name);
            return Ok(());
        }
        match expression {
            Expression::Unary {
                operator: operator @ (UnaryOperator::Typeof | UnaryOperator::Delete),
                argument,
            } if self.free_identifier(argument).is_some() => {
                let Some(name) = self.free_identifier(argument) else {
                    return Ok(());
                };
                let operator = *operator;
                *expression = Expression::Conditional {
                    test: Box::new(intrinsic(
                        HAS_INTRINSIC,
                        vec![identifier(self.object), string(&name)],
                    )),
                    consequent: Box::new(Expression::Unary {
                        operator,
                        argument: Box::new(member(identifier(self.object), &name)),
                    }),
                    alternate: Box::new(Expression::Unary {
                        operator,
                        argument: Box::new(Expression::Identifier(name)),
                    }),
                };
                Ok(())
            }
            // An ImportCall's `import` names no binding, so the object
            // cannot supply it; only the specifier is rewritten.
            Expression::Call {
                callee, arguments, ..
            } if matches!(callee.as_ref(), Expression::Identifier(name) if name == "import") => {
                arguments
                    .iter_mut()
                    .try_for_each(|argument| self.expression(argument))
            }
            Expression::Call {
                callee,
                arguments,
                span,
            } if self.member_chain_root(callee).is_some() => {
                let Some(root) = self.member_chain_root(callee) else {
                    return Ok(());
                };
                let span = *span;
                *expression = self.member_call_on_free_root(root, callee, arguments, span)?;
                Ok(())
            }
            Expression::Call {
                callee,
                arguments,
                span,
            } if self.free_identifier(callee).is_some() => {
                let Some(name) = self.free_identifier(callee) else {
                    return Ok(());
                };
                for argument in arguments.iter_mut() {
                    self.expression(argument)?;
                }
                let mut call_arguments = vec![self.receiver(&name)];
                call_arguments.append(arguments);
                *expression = Expression::Call {
                    callee: Box::new(member(self.reference(&name), "call")),
                    arguments: call_arguments,
                    span: *span,
                };
                Ok(())
            }
            Expression::OptionalCall {
                callee,
                arguments,
                span,
            } if self.free_identifier(callee).is_some() => {
                let Some(name) = self.free_identifier(callee) else {
                    return Ok(());
                };
                for argument in arguments.iter_mut() {
                    self.expression(argument)?;
                }
                let mut call_arguments = vec![self.receiver(&name)];
                call_arguments.append(arguments);
                *expression = Expression::Call {
                    callee: Box::new(Expression::OptionalMember {
                        object: Box::new(self.reference(&name)),
                        property: Box::new(identifier("call")),
                        computed: false,
                        span: None,
                    }),
                    arguments: call_arguments,
                    span: *span,
                };
                Ok(())
            }
            // An inner rewrite's receiver for a name this body does not
            // declare: this object comes next.
            Expression::Call {
                callee, arguments, ..
            } if matches!(callee.as_ref(), Expression::Identifier(name) if name == RECEIVER_INTRINSIC)
                && matches!(arguments.as_slice(), [Expression::StringLiteral(name)] if self.is_free(name.as_ref())) =>
            {
                let [Expression::StringLiteral(name)] = arguments.as_slice() else {
                    return Ok(());
                };
                *expression = self.receiver(name.as_ref());
                Ok(())
            }
            Expression::ObjectLiteral(properties) => {
                for property in properties.iter_mut() {
                    if property.shorthand && self.free_identifier(&property.value).is_some() {
                        property.shorthand = false;
                    }
                }
                walk_expression(self, expression)
            }
            _ => walk_expression(self, expression),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::ParseGoal;
    use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    fn parse(source: &str) -> SyntaxTree {
        CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "with.js".into(),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("parse")
    }

    fn contains_with(statements: &[Statement]) -> bool {
        statements
            .iter()
            .any(|statement| WITH_SEARCH.in_statement(statement))
    }

    #[test]
    fn a_program_without_with_is_left_alone() {
        let tree = parse("var a = 1; function f(x) { return x + a; }");
        assert!(rewrite_with_statements(&tree).expect("rewrite").is_none());
    }

    #[test]
    fn nested_with_statements_are_all_rewritten() {
        let tree = parse(
            "var o = {a: 1}; function f() { with (o) { with ({b: 2}) { return a + b; } } } f();",
        );
        let rewritten = rewrite_with_statements(&tree)
            .expect("rewrite")
            .expect("has with");
        assert!(!contains_with(&rewritten.body));
    }

    #[test]
    fn declared_names_stay_static_and_free_names_go_through_the_object() {
        let tree = parse("with (o) { let a = 1; a + b; }");
        let rewritten = rewrite_with_statements(&tree)
            .expect("rewrite")
            .expect("has with");
        let Statement::Block(block) = &rewritten.body[0] else {
            panic!("with becomes a block");
        };
        // const object, const scope (for `b`), then the body.
        assert_eq!(block.body.len(), 3);
        let Statement::VariableDeclaration(scope) = &block.body[1] else {
            panic!("scope object declaration");
        };
        let Some(Expression::ObjectLiteral(properties)) = &scope.declarations[0].initializer else {
            panic!("scope object literal");
        };
        let keys: Vec<_> = properties
            .iter()
            .map(|property| match &property.key {
                Expression::Identifier(name) => name.as_str(),
                other => panic!("unexpected key {other:?}"),
            })
            .collect();
        assert_eq!(keys, ["b", "b"]);
    }

    #[test]
    fn destructuring_var_inside_with_is_refused() {
        let tree = parse("with (o) { var {a} = p; }");
        assert!(rewrite_with_statements(&tree).is_err());
    }
}
