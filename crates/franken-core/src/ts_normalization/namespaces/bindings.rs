//! Resolve namespace references without changing JavaScript lexical bindings.
//!
//! The declaration emitter owns namespace syntax. This pass reads its erased
//! JavaScript bodies, records lexical scopes and identifier roles, then resolves
//! references after every declaration has been seen. In particular, a later
//! `let` shadows the whole block, and a body `var` does not shadow a parameter
//! default. Edits affect identifier spans only; literals and trivia stay intact.

use std::collections::{BTreeMap, BTreeSet};

use super::{Edit, Lexed, Token, TokenKind};

const UNSUPPORTED: &str = "unsupported namespace reference syntax";
const MAX_DEPTH: usize = 256;

pub(super) fn rewrite(
    source: &str,
    lexed: &Lexed,
    replacements: &BTreeMap<String, String>,
    ignored_bindings: &BTreeSet<usize>,
) -> Result<Vec<Edit>, &'static str> {
    let mut resolver = Resolver::new(source, lexed, ignored_bindings);
    while resolver.cursor < resolver.tokens.len() {
        resolver.statement(0)?;
    }

    let mut edits = Vec::new();
    for reference in &resolver.references {
        let token = &resolver.tokens[reference.token];
        let Some(replacement) = replacements.get(&token.text) else {
            continue;
        };
        let mut scope = Some(reference.scope);
        let mut shadowed = false;
        while let Some(index) = scope {
            if resolver.scopes[index].names.contains(&token.text) {
                shadowed = true;
                break;
            }
            scope = resolver.scopes[index].parent;
        }
        if shadowed {
            continue;
        }
        let replacement = if reference.shorthand {
            // Unlike a shorthand, a literal `__proto__: value` changes the
            // object's prototype. A computed key preserves a data property.
            if token.text == "__proto__" {
                format!("[\"__proto__\"]: {replacement}")
            } else {
                format!("{}: {replacement}", &source[token.start..token.end])
            }
        } else {
            replacement.clone()
        };
        edits.push(Edit {
            start: token.start,
            end: token.end,
            replacement,
        });
    }
    edits.sort_by_key(|edit| edit.start);
    Ok(edits)
}

/// Locate an exported class with the same grammar used to resolve its names.
/// A heritage expression may itself contain classes, functions or object
/// literals, so its first opening brace need not be the declaration body.
pub(super) fn class_declaration_end(
    source: &str,
    lexed: &Lexed,
    start: usize,
) -> Result<usize, &'static str> {
    let ignored_bindings = BTreeSet::new();
    let mut resolver = Resolver::new(source, lexed, &ignored_bindings);
    resolver.cursor = start;
    resolver.class(0, true)?;
    Ok(resolver.cursor)
}

struct Scope {
    parent: Option<usize>,
    var_scope: usize,
    names: BTreeSet<String>,
    allow_await: bool,
    allow_yield: bool,
    return_allowed: bool,
    break_allowed: bool,
    continue_allowed: bool,
    control_boundary: bool,
    labels: BTreeMap<String, bool>,
}

struct Reference {
    token: usize,
    scope: usize,
    shorthand: bool,
}

struct Resolver<'a> {
    source: &'a str,
    tokens: &'a [Token],
    pairs: &'a [Option<usize>],
    ignored_bindings: &'a BTreeSet<usize>,
    cursor: usize,
    depth: usize,
    scopes: Vec<Scope>,
    references: Vec<Reference>,
}

impl<'a> Resolver<'a> {
    fn new(source: &'a str, lexed: &'a Lexed, ignored_bindings: &'a BTreeSet<usize>) -> Self {
        Self {
            source,
            tokens: &lexed.tokens,
            pairs: &lexed.pairs,
            ignored_bindings,
            cursor: 0,
            depth: 0,
            scopes: vec![Scope {
                parent: None,
                var_scope: 0,
                names: BTreeSet::new(),
                allow_await: false,
                allow_yield: false,
                return_allowed: false,
                break_allowed: false,
                continue_allowed: false,
                control_boundary: true,
                labels: BTreeMap::new(),
            }],
            references: Vec::new(),
        }
    }

    fn text(&self, index: usize) -> &str {
        self.tokens
            .get(index)
            .map_or("", |token| token.text.as_str())
    }

    fn at(&self, text: &str) -> bool {
        self.text(self.cursor) == text
    }

    fn eat(&mut self, text: &str) -> bool {
        if self.at(text) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, text: &str) -> Result<(), &'static str> {
        self.eat(text).then_some(()).ok_or(UNSUPPORTED)
    }

    fn word(&self, index: usize) -> bool {
        self.tokens
            .get(index)
            .is_some_and(|token| matches!(token.kind, TokenKind::Word))
    }

    fn line_break(&self, left: usize, right: usize) -> bool {
        let (Some(left), Some(right)) = (self.tokens.get(left), self.tokens.get(right)) else {
            return false;
        };
        self.source[left.end..right.start].contains(['\n', '\r', '\u{2028}', '\u{2029}'])
    }

    fn enter(&mut self) -> Result<(), &'static str> {
        if self.depth >= MAX_DEPTH {
            return Err("namespace reference nesting limit");
        }
        self.depth += 1;
        Ok(())
    }

    fn scope(&mut self, parent: usize, owns_vars: bool) -> usize {
        let index = self.scopes.len();
        self.scopes.push(Scope {
            parent: Some(parent),
            var_scope: if owns_vars {
                index
            } else {
                self.scopes[parent].var_scope
            },
            names: BTreeSet::new(),
            allow_await: self.scopes[parent].allow_await,
            allow_yield: self.scopes[parent].allow_yield,
            return_allowed: self.scopes[parent].return_allowed,
            break_allowed: self.scopes[parent].break_allowed,
            continue_allowed: self.scopes[parent].continue_allowed,
            control_boundary: false,
            labels: BTreeMap::new(),
        });
        index
    }

    fn function_context(
        &mut self,
        scope: usize,
        return_allowed: bool,
        is_async: bool,
        generator: bool,
    ) {
        let scope = &mut self.scopes[scope];
        scope.allow_await = is_async;
        scope.allow_yield = generator;
        scope.return_allowed = return_allowed;
        scope.break_allowed = false;
        scope.continue_allowed = false;
        scope.control_boundary = true;
    }

    fn label(&self, mut scope: usize, name: &str) -> Option<bool> {
        loop {
            if let Some(iteration) = self.scopes[scope].labels.get(name) {
                return Some(*iteration);
            }
            if self.scopes[scope].control_boundary {
                return None;
            }
            scope = self.scopes[scope].parent?;
        }
    }

    fn loop_scope(&mut self, parent: usize) -> usize {
        let scope = self.scope(parent, false);
        self.scopes[scope].break_allowed = true;
        self.scopes[scope].continue_allowed = true;
        scope
    }

    fn bind(&mut self, scope: usize, token: usize) {
        if !self.ignored_bindings.contains(&token) {
            self.scopes[scope]
                .names
                .insert(self.tokens[token].text.clone());
        }
    }

    fn reference(&mut self, scope: usize, token: usize, shorthand: bool) {
        self.references.push(Reference {
            token,
            scope,
            shorthand,
        });
    }

    fn end_statement(&mut self) -> Result<(), &'static str> {
        if self.eat(";") || self.cursor == self.tokens.len() || self.at("}") {
            return Ok(());
        }
        if self.cursor > 0 && self.line_break(self.cursor - 1, self.cursor) {
            return Ok(());
        }
        Err(UNSUPPORTED)
    }

    fn statement(&mut self, scope: usize) -> Result<(), &'static str> {
        self.enter()?;
        let result = self.statement_inner(scope);
        self.depth -= 1;
        result
    }

    fn statement_inner(&mut self, scope: usize) -> Result<(), &'static str> {
        match self.text(self.cursor) {
            ";" => {
                self.cursor += 1;
                Ok(())
            }
            "{" => self.block(scope, false),
            "export" => {
                self.cursor += 1;
                match self.text(self.cursor) {
                    "const" | "let" | "var" | "function" | "class" => self.statement(scope),
                    "async" if self.text(self.cursor + 1) == "function" => self.statement(scope),
                    _ => Err(UNSUPPORTED),
                }
            }
            "const" | "let" | "var" => {
                self.variables(scope, true)?;
                self.end_statement()
            }
            "function" => self.function(scope, true, false),
            "async"
                if self.text(self.cursor + 1) == "function"
                    && !self.line_break(self.cursor, self.cursor + 1) =>
            {
                self.cursor += 1;
                self.function(scope, true, true)
            }
            "class" => self.class(scope, true),
            "if" => {
                self.cursor += 1;
                self.parenthesized(scope)?;
                self.statement(scope)?;
                if self.eat("else") {
                    self.statement(scope)?;
                }
                Ok(())
            }
            "while" => {
                self.cursor += 1;
                self.parenthesized(scope)?;
                let body = self.loop_scope(scope);
                self.statement(body)
            }
            "do" => {
                self.cursor += 1;
                let body = self.loop_scope(scope);
                self.statement(body)?;
                self.expect("while")?;
                self.parenthesized(scope)?;
                self.eat(";");
                Ok(())
            }
            "for" => self.for_statement(scope),
            "switch" => self.switch_statement(scope),
            "try" => self.try_statement(scope),
            "return" | "throw" => {
                let throws = self.at("throw");
                if !throws && !self.scopes[scope].return_allowed {
                    return Err("return is not allowed in a namespace body");
                }
                let keyword = self.cursor;
                self.cursor += 1;
                if self.cursor == self.tokens.len()
                    || self.at(";")
                    || self.at("}")
                    || self.line_break(keyword, self.cursor)
                {
                    if throws {
                        return Err(UNSUPPORTED);
                    }
                } else {
                    self.expression(scope, 0, true)?;
                }
                self.end_statement()
            }
            "break" | "continue" => {
                let is_continue = self.at("continue");
                let keyword = self.cursor;
                self.cursor += 1;
                if self.word(self.cursor) && !self.line_break(keyword, self.cursor) {
                    let iteration = self
                        .label(scope, self.text(self.cursor))
                        .ok_or(UNSUPPORTED)?;
                    if is_continue && !iteration {
                        return Err(UNSUPPORTED);
                    }
                    self.cursor += 1; // A statement label is not a binding reference.
                } else if if is_continue {
                    !self.scopes[scope].continue_allowed
                } else {
                    !self.scopes[scope].break_allowed
                } {
                    return Err(UNSUPPORTED);
                }
                self.end_statement()
            }
            "debugger" => {
                self.cursor += 1;
                self.end_statement()
            }
            // A dynamic with environment cannot be resolved lexically. TypeScript
            // already rejects this form, rather than assigning namespace meaning.
            "with" | "namespace" => Err(UNSUPPORTED),
            _ if self.word(self.cursor) && self.text(self.cursor + 1) == ":" => {
                let name = self.text(self.cursor).to_string();
                if self.label(scope, &name).is_some() {
                    return Err(UNSUPPORTED);
                }
                self.cursor += 2;
                let mut target = self.cursor;
                while self.word(target) && self.text(target + 1) == ":" {
                    target += 2;
                }
                let iteration = matches!(self.text(target), "for" | "while" | "do");
                let labeled = self.scope(scope, false);
                self.scopes[labeled].labels.insert(name, iteration);
                self.statement(labeled)
            }
            _ => {
                self.expression(scope, 0, true)?;
                self.end_statement()
            }
        }
    }

    fn block(&mut self, parent: usize, owns_vars: bool) -> Result<(), &'static str> {
        let scope = self.scope(parent, owns_vars);
        self.block_in(scope)
    }

    fn block_in(&mut self, scope: usize) -> Result<(), &'static str> {
        self.expect("{")?;
        while !self.at("}") {
            if self.cursor == self.tokens.len() {
                return Err(UNSUPPORTED);
            }
            self.statement(scope)?;
        }
        self.expect("}")
    }

    fn parenthesized(&mut self, scope: usize) -> Result<(), &'static str> {
        self.expect("(")?;
        self.expression(scope, 0, true)?;
        self.expect(")")
    }

    fn variables(&mut self, scope: usize, allow_in: bool) -> Result<(), &'static str> {
        let target = if self.at("var") {
            self.scopes[scope].var_scope
        } else {
            scope
        };
        self.cursor += 1;
        loop {
            self.pattern(scope, target)?;
            if self.eat("=") {
                self.expression(scope, 1, allow_in)?;
            }
            if !self.eat(",") {
                break;
            }
        }
        Ok(())
    }

    /// Binding names are separate from expressions in computed keys/defaults.
    fn pattern(&mut self, scope: usize, target: usize) -> Result<(), &'static str> {
        self.enter()?;
        let result = self.pattern_inner(scope, target);
        self.depth -= 1;
        result
    }

    fn pattern_inner(&mut self, scope: usize, target: usize) -> Result<(), &'static str> {
        if self.eat("...") {
            return self.pattern(scope, target);
        }
        if self.word(self.cursor) {
            self.bind(target, self.cursor);
            self.cursor += 1;
            return Ok(());
        }
        if self.eat("[") {
            while !self.at("]") {
                if self.eat(",") {
                    continue;
                }
                self.pattern(scope, target)?;
                if self.eat("=") {
                    self.expression(scope, 1, true)?;
                }
                if !self.eat(",") {
                    break;
                }
            }
            return self.expect("]");
        }
        if self.eat("{") {
            while !self.at("}") {
                if self.eat("...") {
                    self.pattern(scope, target)?;
                } else if self.eat("[") {
                    self.expression(scope, 0, true)?;
                    self.expect("]")?;
                    self.expect(":")?;
                    self.pattern(scope, target)?;
                    if self.eat("=") {
                        self.expression(scope, 1, true)?;
                    }
                } else {
                    let key = self.cursor;
                    self.property_key()?;
                    if self.eat(":") {
                        self.pattern(scope, target)?;
                    } else if self.word(key) {
                        self.bind(target, key);
                    } else {
                        return Err(UNSUPPORTED);
                    }
                    if self.eat("=") {
                        self.expression(scope, 1, true)?;
                    }
                }
                if !self.eat(",") {
                    break;
                }
            }
            return self.expect("}");
        }
        Err(UNSUPPORTED)
    }

    fn function(
        &mut self,
        outer: usize,
        declaration: bool,
        is_async: bool,
    ) -> Result<(), &'static str> {
        self.expect("function")?;
        let generator = self.eat("*");
        let name = self.word(self.cursor).then_some(self.cursor);
        if name.is_some() {
            self.cursor += 1;
        } else if declaration {
            return Err(UNSUPPORTED);
        }
        let parent = if declaration {
            self.bind(outer, name.ok_or(UNSUPPORTED)?);
            outer
        } else if let Some(name) = name {
            let named = self.scope(outer, false);
            self.bind(named, name);
            named
        } else {
            outer
        };
        self.function_tail(parent, false, is_async, generator, false)
    }

    fn function_tail(
        &mut self,
        parent: usize,
        arrow: bool,
        is_async: bool,
        generator: bool,
        parameter_properties: bool,
    ) -> Result<(), &'static str> {
        let parameters = self.scope(parent, false);
        self.function_context(parameters, true, is_async, generator);
        if !arrow {
            self.scopes[parameters]
                .names
                .insert("arguments".to_string());
        }
        self.expect("(")?;
        while !self.at(")") {
            if parameter_properties {
                self.parameter_property_modifiers()?;
            }
            self.pattern(parameters, parameters)?;
            if self.eat("=") {
                self.expression(parameters, 1, true)?;
            }
            if !self.eat(",") {
                break;
            }
        }
        self.expect(")")?;
        if arrow {
            self.expect("=>")?;
        }
        let body = self.scope(parameters, true);
        if self.at("{") {
            self.block_in(body)
        } else if arrow {
            self.expression(body, 1, true)
        } else {
            Err(UNSUPPORTED)
        }
    }

    fn parameter_property_modifiers(&mut self) -> Result<(), &'static str> {
        let mut access = false;
        let mut readonly = false;
        let mut overrides = false;
        while self.word(self.cursor + 1) {
            match self.text(self.cursor) {
                "public" | "private" | "protected" if !access => access = true,
                "readonly" if !readonly => readonly = true,
                "override" if !overrides => overrides = true,
                "public" | "private" | "protected" | "readonly" | "override" => {
                    return Err(UNSUPPORTED);
                }
                _ => break,
            }
            // The normalizer's later parameter-property pass owns these
            // modifier bytes and `this.name = name` emission. Only the name
            // after them belongs in the constructor's lexical parameter scope.
            self.cursor += 1;
        }
        Ok(())
    }

    fn single_parameter_arrow(
        &mut self,
        parent: usize,
        is_async: bool,
    ) -> Result<(), &'static str> {
        let parameters = self.scope(parent, false);
        self.function_context(parameters, true, is_async, false);
        self.bind(parameters, self.cursor);
        self.cursor += 1;
        self.expect("=>")?;
        let body = self.scope(parameters, true);
        if self.at("{") {
            self.block_in(body)
        } else {
            self.expression(body, 1, true)
        }
    }

    fn class(&mut self, outer: usize, declaration: bool) -> Result<(), &'static str> {
        self.expect("class")?;
        let class_scope = self.scope(outer, false);
        if self.word(self.cursor) && !self.at("extends") {
            let name = self.cursor;
            self.cursor += 1;
            self.bind(class_scope, name);
            if declaration {
                self.bind(outer, name);
            }
        } else if declaration {
            return Err(UNSUPPORTED);
        }
        if self.eat("extends") {
            self.expression(class_scope, 15, true)?;
        }
        self.expect("{")?;
        while !self.at("}") {
            if self.eat(";") {
                continue;
            }
            if self.at("static") && self.text(self.cursor + 1) == "{" {
                self.cursor += 1;
                let block = self.scope(class_scope, true);
                self.function_context(block, false, false, false);
                self.block_in(block)?;
                continue;
            }
            let is_static = if self.at("static")
                && !matches!(self.text(self.cursor + 1), "(" | "=" | ";" | "}")
            {
                self.cursor += 1;
                true
            } else {
                false
            };
            let modifier_start = self.cursor;
            let is_async = self.method_modifier();
            let accessor = self.cursor != modifier_start && !is_async;
            let generator = self.eat("*");
            let constructor =
                !is_static && !is_async && !accessor && !generator && self.at("constructor");
            self.key(class_scope)?;
            if self.at("(") {
                self.function_tail(class_scope, false, is_async, generator, constructor)?;
            } else {
                if self.eat("=") {
                    let initializer = self.scope(class_scope, false);
                    self.function_context(initializer, false, false, false);
                    self.expression(initializer, 1, true)?;
                }
                self.end_statement()?;
            }
        }
        self.expect("}")
    }

    /// Accessor/async modifiers are contextual: `{ get }` is a shorthand.
    fn method_modifier(&mut self) -> bool {
        if !matches!(self.text(self.cursor), "get" | "set" | "async") {
            return false;
        }
        let next = self.cursor + 1;
        if self.at("async") && self.line_break(self.cursor, next) {
            return false;
        }
        let method = if self.text(next) == "*" {
            self.at("async")
        } else if self.text(next) == "[" {
            self.pairs
                .get(next)
                .copied()
                .flatten()
                .is_some_and(|end| self.text(end + 1) == "(")
        } else if self.text(next) == "#" {
            self.word(next + 1) && self.text(next + 2) == "("
        } else {
            self.tokens
                .get(next)
                .is_some_and(|token| matches!(token.kind, TokenKind::Word | TokenKind::Literal))
                && self.text(next + 1) == "("
        };
        if method {
            let is_async = self.at("async");
            self.cursor += 1;
            is_async
        } else {
            false
        }
    }

    fn property_key(&mut self) -> Result<(), &'static str> {
        if self.eat("#") {
            if !self.word(self.cursor) {
                return Err(UNSUPPORTED);
            }
            self.cursor += 1;
            return Ok(());
        }
        if self
            .tokens
            .get(self.cursor)
            .is_some_and(|token| matches!(token.kind, TokenKind::Word | TokenKind::Literal))
        {
            self.cursor += 1;
            Ok(())
        } else {
            Err(UNSUPPORTED)
        }
    }

    fn key(&mut self, scope: usize) -> Result<(), &'static str> {
        if self.eat("[") {
            self.expression(scope, 0, true)?;
            self.expect("]")
        } else {
            self.property_key()
        }
    }

    fn for_statement(&mut self, outer: usize) -> Result<(), &'static str> {
        self.expect("for")?;
        self.eat("await");
        self.expect("(")?;
        let scope = self.loop_scope(outer);
        if !self.at(";") {
            if matches!(self.text(self.cursor), "const" | "let" | "var") {
                self.variables(scope, false)?;
            } else {
                self.expression(scope, 0, false)?;
            }
        }
        if self.eat(";") {
            if !self.at(";") {
                self.expression(scope, 0, true)?;
            }
            self.expect(";")?;
            if !self.at(")") {
                self.expression(scope, 0, true)?;
            }
        } else if self.eat("in") || self.eat("of") {
            self.expression(scope, 0, true)?;
        } else {
            return Err(UNSUPPORTED);
        }
        self.expect(")")?;
        self.statement(scope)
    }

    fn switch_statement(&mut self, outer: usize) -> Result<(), &'static str> {
        self.expect("switch")?;
        // The discriminant precedes the case block's lexical environment.
        self.parenthesized(outer)?;
        self.expect("{")?;
        let scope = self.scope(outer, false);
        self.scopes[scope].break_allowed = true;
        while !self.at("}") {
            if self.eat("case") {
                self.expression(scope, 0, true)?;
                self.expect(":")?;
            } else if self.eat("default") {
                self.expect(":")?;
            } else {
                self.statement(scope)?;
            }
        }
        self.expect("}")
    }

    fn try_statement(&mut self, scope: usize) -> Result<(), &'static str> {
        self.expect("try")?;
        self.block(scope, false)?;
        let has_catch = self.eat("catch");
        if has_catch {
            let catch = self.scope(scope, false);
            if self.eat("(") {
                self.pattern(catch, catch)?;
                self.expect(")")?;
            }
            self.block(catch, false)?;
        }
        if self.eat("finally") {
            self.block(scope, false)?;
        } else if !has_catch {
            return Err(UNSUPPORTED);
        }
        Ok(())
    }

    fn expression(
        &mut self,
        scope: usize,
        minimum: u8,
        allow_in: bool,
    ) -> Result<(), &'static str> {
        self.enter()?;
        let result = self.expression_inner(scope, minimum, allow_in);
        self.depth -= 1;
        result
    }

    fn expression_inner(
        &mut self,
        scope: usize,
        minimum: u8,
        allow_in: bool,
    ) -> Result<(), &'static str> {
        self.prefix(scope, allow_in)?;
        loop {
            // The annotation eraser deliberately retains this capability
            // marker until the normalizer extracts its hostcall contract.
            // Read its arguments as a call, including zero arguments and a
            // trailing comma, without removing any annotation bytes here.
            if self.retained_hostcall_arguments() {
                self.cursor += 3;
                self.arguments(scope)?;
                continue;
            }
            match self.text(self.cursor) {
                "." => {
                    self.cursor += 1;
                    self.property_key()?;
                    continue;
                }
                "?." => {
                    self.cursor += 1;
                    if self.at("(") {
                        self.arguments(scope)?;
                    } else if self.eat("[") {
                        self.expression(scope, 0, true)?;
                        self.expect("]")?;
                    } else {
                        self.property_key()?;
                    }
                    continue;
                }
                "[" => {
                    self.cursor += 1;
                    self.expression(scope, 0, true)?;
                    self.expect("]")?;
                    continue;
                }
                "(" => {
                    self.arguments(scope)?;
                    continue;
                }
                "++" | "--"
                    if self.cursor > 0 && !self.line_break(self.cursor - 1, self.cursor) =>
                {
                    self.cursor += 1;
                    continue;
                }
                "?" if minimum <= 2 => {
                    self.cursor += 1;
                    self.expression(scope, 1, true)?;
                    self.expect(":")?;
                    self.expression(scope, 1, allow_in)?;
                    continue;
                }
                _ => {}
            }
            if self.tokens.get(self.cursor).is_some_and(|token| {
                matches!(token.kind, TokenKind::TemplateHead)
                    || (matches!(token.kind, TokenKind::Literal)
                        && self.source[token.start..token.end].starts_with('`'))
            }) {
                self.template(scope)?;
                continue;
            }
            let Some((power, right_associative)) = binary_power(self.text(self.cursor), allow_in)
            else {
                break;
            };
            if power < minimum {
                break;
            }
            self.cursor += 1;
            self.expression(scope, power + u8::from(!right_associative), allow_in)?;
        }
        Ok(())
    }

    fn prefix(&mut self, scope: usize, allow_in: bool) -> Result<(), &'static str> {
        let Some(token) = self.tokens.get(self.cursor) else {
            return Err(UNSUPPORTED);
        };
        match token.kind {
            TokenKind::Literal => {
                self.cursor += 1;
                return Ok(());
            }
            TokenKind::TemplateHead => return self.template(scope),
            TokenKind::TemplateMiddle | TokenKind::TemplateTail => return Err(UNSUPPORTED),
            TokenKind::Word | TokenKind::Punct => {}
        }
        match self.text(self.cursor) {
            "(" => {
                let end = self
                    .pairs
                    .get(self.cursor)
                    .copied()
                    .flatten()
                    .ok_or(UNSUPPORTED)?;
                if self.text(end + 1) == "=>" {
                    self.function_tail(scope, true, false, false, false)
                } else {
                    self.parenthesized(scope)
                }
            }
            "[" => self.array(scope),
            "{" => self.object(scope),
            "function" => self.function(scope, false, false),
            "class" => self.class(scope, false),
            "async"
                if self.text(self.cursor + 1) == "function"
                    && !self.line_break(self.cursor, self.cursor + 1) =>
            {
                self.cursor += 1;
                self.function(scope, false, true)
            }
            "async" if !self.line_break(self.cursor, self.cursor + 1) => {
                if self.word(self.cursor + 1) && self.text(self.cursor + 2) == "=>" {
                    self.cursor += 1;
                    self.single_parameter_arrow(scope, true)
                } else if self.text(self.cursor + 1) == "("
                    && self
                        .pairs
                        .get(self.cursor + 1)
                        .copied()
                        .flatten()
                        .is_some_and(|end| self.text(end + 1) == "=>")
                {
                    self.cursor += 1;
                    self.function_tail(scope, true, true, false, false)
                } else if self.text(self.cursor + 1) == "=>" {
                    self.single_parameter_arrow(scope, false)
                } else {
                    self.reference(scope, self.cursor, false);
                    self.cursor += 1;
                    Ok(())
                }
            }
            "await" if self.scopes[scope].allow_await => {
                self.cursor += 1;
                self.expression(scope, 15, allow_in)
            }
            "typeof" | "void" | "delete" | "!" | "~" | "+" | "-" | "++" | "--" | "..." => {
                self.cursor += 1;
                self.expression(scope, 15, allow_in)
            }
            "yield" if self.scopes[scope].allow_yield => {
                let keyword = self.cursor;
                self.cursor += 1;
                if self.eat("*") {
                    self.expression(scope, 1, allow_in)
                } else if self.cursor == self.tokens.len()
                    || matches!(self.text(self.cursor), ";" | "," | ")" | "]" | "}")
                    || self.line_break(keyword, self.cursor)
                {
                    Ok(())
                } else {
                    self.expression(scope, 1, allow_in)
                }
            }
            "new" => {
                self.cursor += 1;
                if self.eat(".") {
                    self.expect("target")
                } else {
                    self.expression(scope, 15, allow_in)
                }
            }
            "import" => {
                self.cursor += 1;
                if self.at("(") {
                    self.arguments(scope)
                } else if self.eat(".") {
                    self.expect("meta")
                } else {
                    Err(UNSUPPORTED)
                }
            }
            "true" | "false" | "null" | "this" | "super" => {
                self.cursor += 1;
                Ok(())
            }
            "#" => self.property_key(), // A private-brand check: `#name in value`.
            _ if self.word(self.cursor) => {
                if self.text(self.cursor + 1) == "=>" {
                    self.single_parameter_arrow(scope, false)
                } else {
                    self.reference(scope, self.cursor, false);
                    self.cursor += 1;
                    Ok(())
                }
            }
            _ => Err(UNSUPPORTED),
        }
    }

    fn arguments(&mut self, scope: usize) -> Result<(), &'static str> {
        self.expect("(")?;
        while !self.at(")") {
            self.expression(scope, 1, true)?;
            if !self.eat(",") {
                break;
            }
        }
        self.expect(")")
    }

    fn retained_hostcall_arguments(&self) -> bool {
        if self.cursor == 0
            || !self.at("<")
            || self.text(self.cursor - 1) != "hostcall"
            || self.text(self.cursor + 2) != ">"
            || self.text(self.cursor + 3) != "("
        {
            return false;
        }
        let name = &self.tokens[self.cursor - 1];
        let open = &self.tokens[self.cursor];
        let Some(literal) = self.tokens.get(self.cursor + 1) else {
            return false;
        };
        let close = &self.tokens[self.cursor + 2];
        if !matches!(literal.kind, TokenKind::Literal)
            || &self.source[name.start..name.end] != "hostcall"
            || name.end != open.start
            || open.end != literal.start
            || literal.end != close.start
        {
            return false;
        }
        // Match the normalizer's deliberate DSL, rather than admitting an
        // invalid ordinary comparison such as `hostcall < "cap" > ()`.
        self.source[literal.start..literal.end]
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .is_some_and(|value| !value.contains(['"', '\\', '\n', '\r']))
    }

    fn array(&mut self, scope: usize) -> Result<(), &'static str> {
        self.expect("[")?;
        while !self.at("]") {
            if self.eat(",") {
                continue;
            }
            self.expression(scope, 1, true)?;
            if !self.eat(",") {
                break;
            }
        }
        self.expect("]")
    }

    fn object(&mut self, scope: usize) -> Result<(), &'static str> {
        self.expect("{")?;
        while !self.at("}") {
            if self.eat("...") {
                self.expression(scope, 1, true)?;
            } else {
                let is_async = self.method_modifier();
                let generator = self.eat("*");
                let key = self.cursor;
                let computed = self.at("[");
                self.key(scope)?;
                if self.eat(":") {
                    self.expression(scope, 1, true)?;
                } else if self.at("(") {
                    self.function_tail(scope, false, is_async, generator, false)?;
                } else if !computed && !generator && self.word(key) {
                    self.reference(scope, key, true);
                    if self.eat("=") {
                        self.expression(scope, 1, true)?;
                    }
                } else {
                    return Err(UNSUPPORTED);
                }
            }
            if !self.eat(",") {
                break;
            }
        }
        self.expect("}")
    }

    fn template(&mut self, scope: usize) -> Result<(), &'static str> {
        if self
            .tokens
            .get(self.cursor)
            .is_some_and(|token| matches!(token.kind, TokenKind::Literal))
        {
            self.cursor += 1;
            return Ok(());
        }
        if !self
            .tokens
            .get(self.cursor)
            .is_some_and(|token| matches!(token.kind, TokenKind::TemplateHead))
        {
            return Err(UNSUPPORTED);
        }
        self.cursor += 1;
        loop {
            self.expect("${")?;
            self.expression(scope, 0, true)?;
            self.expect("}")?;
            match self.tokens.get(self.cursor).map(|token| &token.kind) {
                Some(TokenKind::TemplateMiddle) => self.cursor += 1,
                Some(TokenKind::TemplateTail) => {
                    self.cursor += 1;
                    return Ok(());
                }
                _ => return Err(UNSUPPORTED),
            }
        }
    }
}

fn binary_power(operator: &str, allow_in: bool) -> Option<(u8, bool)> {
    let (power, right_associative) = match operator {
        "," => (0, false),
        "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "**=" | "<<=" | ">>=" | ">>>=" | "&=" | "|="
        | "^=" | "&&=" | "||=" | "??=" => (1, true),
        "||" | "??" => (3, false),
        "&&" => (4, false),
        "|" => (5, false),
        "^" => (6, false),
        "&" => (7, false),
        "==" | "!=" | "===" | "!==" => (8, false),
        "<" | "<=" | ">" | ">=" | "instanceof" => (9, false),
        "in" if allow_in => (9, false),
        "<<" | ">>" | ">>>" => (10, false),
        "+" | "-" => (11, false),
        "*" | "/" | "%" => (12, false),
        "**" => (14, true),
        _ => return None,
    };
    Some((power, right_associative))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewritten(source: &str) -> String {
        rewritten_members(source, &["x"])
    }

    fn rewritten_members(source: &str, members: &[&str]) -> String {
        let lexed = super::super::lex(source).expect("JavaScript fixture tokens");
        let replacements = members
            .iter()
            .map(|name| ((*name).to_string(), format!("__namespace.{name}")))
            .collect();
        let edits = rewrite(source, &lexed, &replacements, &BTreeSet::new())
            .expect("supported JavaScript fixture");
        let mut out = String::new();
        let mut cursor = 0;
        for edit in edits {
            out.push_str(&source[cursor..edit.start]);
            out.push_str(&edit.replacement);
            cursor = edit.end;
        }
        out.push_str(&source[cursor..]);
        out
    }

    #[test]
    fn parameter_defaults_do_not_resolve_to_body_vars() {
        assert_eq!(
            rewritten("function f(a=x){var x=1;return a+x;}const g=(a=x)=>{let x=2;return a+x;};"),
            "function f(a=__namespace.x){var x=1;return a+x;}const g=(a=__namespace.x)=>{let x=2;return a+x;};"
        );
    }

    #[test]
    fn later_lexical_and_hoisted_var_bindings_shadow_their_whole_scope() {
        assert_eq!(
            rewritten(
                "function f(){{const before=typeof x;let x=2;}return x;}function g(){const before=typeof x;if(false){var x=1;}return before;}"
            ),
            "function f(){{const before=typeof x;let x=2;}return __namespace.x;}function g(){const before=typeof x;if(false){var x=1;}return before;}"
        );
    }

    #[test]
    fn property_names_and_shadows_stay_distinct_from_references() {
        assert_eq!(
            rewritten(
                "const f=(x)=>({x});const o={x,[x]:x,text:'x',get x(){return x;},set x(v){x=v;}};o.x=o?.[x];"
            ),
            "const f=(x)=>({x});const o={x: __namespace.x,[__namespace.x]:__namespace.x,text:'x',get x(){return __namespace.x;},set x(v){__namespace.x=v;}};o.x=o?.[__namespace.x];"
        );
    }

    #[test]
    fn templates_resolve_expressions_but_preserve_raw_text_and_inner_parameters() {
        assert_eq!(
            rewritten("const text=`x ${x} ${((x)=>x)(1)} ${`nested ${x}`}`;const re=/x/;"),
            "const text=`x ${__namespace.x} ${((x)=>x)(1)} ${`nested ${__namespace.x}`}`;const re=/x/;"
        );
    }

    #[test]
    fn patterns_resolve_defaults_and_assignment_targets_without_rebinding_keys() {
        assert_eq!(
            rewritten(
                "function f({a=x,x:local},[b=x]){return local+b;}try{run();}catch({x}){use(x);}({x}=source);"
            ),
            "function f({a=__namespace.x,x:local},[b=__namespace.x]){return local+b;}try{run();}catch({x}){use(x);}({x: __namespace.x}=source);"
        );
    }

    #[test]
    fn class_private_brand_names_and_multiline_accessors_are_not_references() {
        assert_eq!(
            rewritten(
                "class C{#x=1;has(value){return #x in value&&x;}}const o={get\nx(){return x;}};"
            ),
            "class C{#x=1;has(value){return #x in value&&__namespace.x;}}const o={get\nx(){return __namespace.x;}};"
        );
    }

    #[test]
    fn await_and_yield_are_contextual_inside_function_bodies() {
        // `await` is a legal namespace member in a script; `yield` is also
        // an identifier in the non-strict dialect. Neither is an operator
        // in an ordinary function, but async/generator bodies reserve them.
        assert_eq!(
            rewritten_members(
                "function read(){return await+yield+x;}async function wait(){return await Promise.resolve(x);}function* values(){yield x;}const a=async()=>await x;const b=()=>await;",
                &["await", "yield", "x"],
            ),
            "function read(){return __namespace.await+__namespace.yield+__namespace.x;}async function wait(){return await Promise.resolve(__namespace.x);}function* values(){yield __namespace.x;}const a=async()=>await __namespace.x;const b=()=>__namespace.await;"
        );
        assert_eq!(
            rewritten_members(
                "const o={async wait(){return await x;},*values(){yield x;},read(){return await;}};",
                &["await", "x"],
            ),
            "const o={async wait(){return await __namespace.x;},*values(){yield __namespace.x;},read(){return __namespace.await;}};"
        );
    }

    #[test]
    fn namespace_statements_do_not_gain_a_function_return_context() {
        for source in [
            "return x;",
            "{return x;}",
            "if(x){return x;}",
            "while(x){return x;}",
            "class C{static{return x;}}",
        ] {
            let lexed = super::super::lex(source).expect("fixture tokens");
            assert!(
                rewrite(source, &lexed, &BTreeMap::new(), &BTreeSet::new()).is_err(),
                "namespace body must reject {source}"
            );
        }
        assert_eq!(
            rewritten("function f(){if(x){return x;}}const g=()=>{return x;};"),
            "function f(){if(__namespace.x){return __namespace.x;}}const g=()=>{return __namespace.x;};"
        );
    }

    #[test]
    fn loop_and_label_targets_do_not_cross_function_boundaries() {
        for source in [
            "break;",
            "continue;",
            "while(x){function f(){break;}}",
            "label:{continue label;}",
            "outer:while(x){class C{static{break outer;}}}",
        ] {
            let lexed = super::super::lex(source).expect("fixture tokens");
            assert!(
                rewrite(source, &lexed, &BTreeMap::new(), &BTreeSet::new()).is_err(),
                "invalid control target must reject {source}"
            );
        }
        let source = "outer:for(let x of [1]){switch(x){case 1:continue outer;default:break;}}";
        assert_eq!(rewritten(source), source);
        assert_eq!(
            rewritten("outer:while(x){function f(){return x;}break outer;}"),
            "outer:while(__namespace.x){function f(){return __namespace.x;}break outer;}"
        );
    }

    #[test]
    fn retained_hostcall_capabilities_keep_zero_and_trailing_comma_arguments() {
        assert_eq!(
            rewritten(
                "function now(){return hostcall<\"clock.now\">();}function read(){return hostcall<\"fs.read\">(x,);}object.hostcall<\"fs.read\">(x,);"
            ),
            "function now(){return hostcall<\"clock.now\">();}function read(){return hostcall<\"fs.read\">(__namespace.x,);}object.hostcall<\"fs.read\">(__namespace.x,);"
        );
        assert_eq!(
            rewritten("const comparison=hostcall < \"clock.now\" > (x);"),
            "const comparison=hostcall < \"clock.now\" > (__namespace.x);"
        );
        for source in [
            "hostcall < \"clock.now\" > ();",
            "hostcall < \"clock.now\" > (x,);",
            "other<\"clock.now\">();",
            "hostcall<'clock.now'>();",
            "hostcall<\"clock\\.now\">();",
        ] {
            let lexed = super::super::lex(source).expect("comparison fixture tokens");
            assert!(
                rewrite(source, &lexed, &BTreeMap::new(), &BTreeSet::new()).is_err(),
                "ordinary invalid comparison must not become a capability call: {source}"
            );
        }
    }

    #[test]
    fn constructor_property_modifiers_preserve_local_parameter_bindings() {
        assert_eq!(
            rewritten(
                "class C extends B{constructor(public override readonly x,protected y=x){super();use(x,y);}}use(x);"
            ),
            "class C extends B{constructor(public override readonly x,protected y=x){super();use(x,y);}}use(__namespace.x);"
        );
        assert_eq!(
            rewritten("class C{constructor(private readonly value=x){use(value,x);}}"),
            "class C{constructor(private readonly value=__namespace.x){use(value,__namespace.x);}}"
        );
        assert_eq!(
            rewritten("class C{constructor(override readonly value=x){use(value,x);}}"),
            "class C{constructor(override readonly value=__namespace.x){use(value,__namespace.x);}}"
        );
    }

    #[test]
    fn modifier_words_are_ordinary_parameter_names_when_not_modifiers() {
        assert_eq!(
            rewritten(
                "function f(readonly,override){return readonly+override+x;}const o={constructor(readonly){return readonly+x;}};class C{public(readonly){return readonly+x;}readonly(override){return override+x;}constructor(readonly=x){use(readonly,x);}}"
            ),
            "function f(readonly,override){return readonly+override+__namespace.x;}const o={constructor(readonly){return readonly+__namespace.x;}};class C{public(readonly){return readonly+__namespace.x;}readonly(override){return override+__namespace.x;}constructor(readonly=__namespace.x){use(readonly,__namespace.x);}}"
        );
        // These are role checks, independent of strict-mode restrictions on
        // the identifier `public`: no modifier pass owns ordinary functions.
        assert_eq!(
            rewritten(
                "function f(public){return public+x;}class C{constructor(public=x){use(public,x);}}"
            ),
            "function f(public){return public+__namespace.x;}class C{constructor(public=__namespace.x){use(public,__namespace.x);}}"
        );
    }

    #[test]
    fn parameter_properties_require_an_actual_constructor() {
        for source in [
            "function constructor(public x){}",
            "const o={constructor(public x){}};",
            "class C{static constructor(public x){}}",
            "class C{static\nconstructor(public x){}}",
            "class C{[\"constructor\"](public x){}}",
            "class C{get constructor(public x){}}",
            "class C{async constructor(public x){}}",
            "class C{*constructor(public x){}}",
            "class C{constructor(private {x}){}}",
            "class C{constructor(public private x){}}",
            "class C{constructor(override override x){}}",
        ] {
            let lexed = super::super::lex(source).expect("constructor fixture tokens");
            assert!(
                rewrite(source, &lexed, &BTreeMap::new(), &BTreeSet::new()).is_err(),
                "parameter properties must reject unsupported context: {source}"
            );
        }
    }
}
