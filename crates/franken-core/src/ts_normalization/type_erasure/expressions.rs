//! Type-only expression suffixes on the same token/span stream as annotations.
//!
//! Assertions perform no conversion, validation, or evaluation. Keep their
//! operand and its reference identity: `(object.method as Callable)()` still
//! calls with `object` as receiver, and `target!.field = value` is still a Set.

use super::{Eraser, Kind};

impl Eraser<'_> {
    pub(super) fn erase_template_expressions(&mut self, depth: usize) {
        for index in 0..self.tokens.len() {
            let token = self.tokens[index];
            if self.removed[index] || token.kind != Kind::Literal || !token.text.starts_with('`') {
                continue;
            }
            // The lexer has validated this template's boundaries. Analyze
            // only interpolation expressions, never the cooked/raw quasis.
            let mut cursor = token.start + 1;
            while cursor < token.end - 1 {
                let ch = self.source[cursor..]
                    .chars()
                    .next()
                    .expect("validated template character");
                if ch == '\\' {
                    cursor += 1;
                    cursor += self.source[cursor..]
                        .chars()
                        .next()
                        .expect("validated template escape")
                        .len_utf8();
                } else if self.source[cursor..].starts_with("${") {
                    let start = cursor + 2;
                    let Some(end) = super::interpolation_end(self.source, start, depth + 1) else {
                        break;
                    };
                    if end > token.end {
                        break;
                    }
                    if let Some(inner) = super::analyze(&self.source[start..end - 1], depth + 1) {
                        // Translate the nested pass's exact source coordinates
                        // rather than reparsing or regenerating JavaScript.
                        self.spans
                            .extend(inner.spans.into_iter().map(|(a, b)| (start + a, start + b)));
                    }
                    cursor = end;
                } else {
                    cursor += ch.len_utf8();
                }
            }
        }
    }

    /// `<T>value` where an operand starts (no operand before the `<`): a
    /// type assertion, whose `<T>` is erased (bd-9vouw.426). A `<` after an
    /// operand is a comparison or type arguments, and `<T>(params) =>` (or
    /// `): R =>`) is a generic arrow function, which `erase` handles.
    pub(super) fn erase_prefix_assertions(&mut self) {
        let mut previous: Option<usize> = None;
        let mut cursor = 0;
        while cursor < self.tokens.len() {
            if self.text(cursor) == "<"
                && !previous.is_some_and(|index| self.suffix_operand(index))
                && let Some(end) = self.angle_end(cursor)
                && end > cursor + 1
                && self.assertion_operand_at(end)
                && !self.generic_arrow_parameters_at(end)
            {
                self.mark(cursor, end);
                cursor = end;
                continue;
            }
            previous = Some(cursor);
            cursor += 1;
        }
    }

    fn assertion_operand_at(&self, index: usize) -> bool {
        self.tokens
            .get(index)
            .is_some_and(|token| match token.kind {
                Kind::Word | Kind::Literal => true,
                Kind::Punctuation => matches!(
                    token.text,
                    "(" | "[" | "{" | "<" | "!" | "-" | "+" | "~" | "++" | "--"
                ),
            })
    }

    fn generic_arrow_parameters_at(&self, open: usize) -> bool {
        self.text(open) == "("
            && self
                .pairs
                .get(open)
                .copied()
                .flatten()
                .is_some_and(|close| matches!(self.text(close + 1), "=>" | ":"))
    }

    pub(super) fn erase_expression_types(&mut self, module_scope: bool) {
        self.erase_type_only_declarations(module_scope);
        let mut cursor = 0;
        let mut previous = None;
        let mut asserted = false;
        let mut conditionals = vec![0usize];
        let mut in_unmatched_return_type = false;
        while cursor < self.tokens.len() {
            if self.removed[cursor] {
                cursor += 1;
                continue;
            }
            // `as` in a module binding clause names a runtime binding. Skip
            // only the clause, not export-default expressions or import().
            if let Some(end) = self.module_clause_end(cursor) {
                previous = end.checked_sub(1);
                asserted = false;
                in_unmatched_return_type = false;
                cursor = end;
                continue;
            }
            match self.text(cursor) {
                "(" | "[" | "{" => {
                    if self.text(cursor) == "{" {
                        in_unmatched_return_type = false;
                    }
                    conditionals.push(0);
                }
                ")" | "]" | "}" => {
                    if conditionals.len() > 1 {
                        conditionals.pop();
                    }
                }
                "?" => {
                    *conditionals.last_mut().expect("root conditional scope") += 1;
                }
                ":" => {
                    let pending = conditionals.last_mut().expect("root conditional scope");
                    if *pending > 0 {
                        *pending -= 1;
                    } else if previous.is_some_and(|rparen| {
                        self.text(rparen) == ")"
                            && self
                                .pairs
                                .get(rparen)
                                .copied()
                                .flatten()
                                .is_none_or(|lparen| lparen == 0 || self.text(lparen - 1) != "case")
                    }) {
                        // An un-erased `):` outside a conditional branch is an
                        // incomplete or effectful signature's return type, not
                        // an instantiation expression operand.
                        in_unmatched_return_type = true;
                    }
                }
                ";" | "=" => {
                    *conditionals.last_mut().expect("root conditional scope") = 0;
                    in_unmatched_return_type = false;
                }
                _ => {}
            }
            // Type arguments do not evaluate and must not turn a method
            // reference into a detached function. Keep the entire callee,
            // optional-chain punctuation, argument list and template intact.
            // An unparenthesized `as` expression has already left the call
            // grammar: `value as number < other > (third)` is a comparison.
            let optional = self.text(cursor) == "?.";
            let arguments = cursor + usize::from(optional);
            if !asserted
                && !in_unmatched_return_type
                && self.text(arguments) == "<"
                && previous.is_some_and(|index| self.suffix_operand(index))
                && !previous.is_some_and(|index| {
                    self.text(index) == "hostcall" && !self.property_name(index)
                })
                && let Some(end) = self.expression_type_arguments_end(arguments)
                && self.generic_suffix_follows(end, optional)
            {
                self.mark(arguments, end);
                if optional {
                    previous = Some(cursor);
                }
                cursor = end;
                continue;
            }
            if matches!(self.text(cursor), "as" | "satisfies" | "!")
                && !self.newline_before(cursor)
                && previous.is_some_and(|index| self.suffix_operand(index))
            {
                match self.text(cursor) {
                    "as" | "satisfies" if !self.property_name(cursor) => {
                        if let Some(end) = self.type_end(cursor + 1, 0)
                            && self.expression_type_boundary(end)
                        {
                            self.mark(cursor, end);
                            asserted = true;
                            cursor = end;
                            continue;
                        }
                    }
                    "!" if self.expression_type_boundary(cursor + 1) => {
                        self.mark(cursor, cursor + 1);
                        cursor += 1;
                        continue;
                    }
                    _ => {}
                }
            }
            previous = Some(cursor);
            asserted = false;
            cursor += 1;
        }
    }

    /// Type-only declarations have no executable body or local binding.
    /// Remove the complete declaration before processing expression suffixes,
    /// so its name/generics cannot be mistaken for a generic call. The actual
    /// implementation is left in place, preserving hoisting and identity.
    fn erase_type_only_declarations(&mut self, module_scope: bool) {
        let mut index = 0;
        let mut nesting = 0usize;
        while index < self.tokens.len() {
            let exported = module_scope && nesting == 0;
            let declaration = if self.removed[index] {
                None
            } else {
                match self.text(index) {
                    "function" => self.function_overload_span(index, exported),
                    "declare" => self.ambient_variable_span(index, exported),
                    _ => None,
                }
            };
            if let Some((start, end)) = declaration {
                self.mark_type_declaration(start, end);
                index = end;
            } else {
                match self.text(index) {
                    "(" | "[" | "{" => nesting += 1,
                    ")" | "]" | "}" => nesting = nesting.saturating_sub(1),
                    _ => {}
                }
                index += 1;
            }
        }
    }

    fn mark_type_declaration(&mut self, start: usize, end: usize) {
        if self.text(start) == "export" {
            let offset = self.tokens[start].start;
            self.module_marker = Some(self.module_marker.map_or(offset, |old| old.min(offset)));
        }
        self.mark(start, end);
    }

    fn function_overload_span(&self, function: usize, exported: bool) -> Option<(usize, usize)> {
        if self.property_name(function) {
            return None;
        }
        let mut start = function;
        if start > 0 && self.text(start - 1) == "async" && !self.newline_before(start) {
            start -= 1;
        }
        if start > 0 && self.text(start - 1) == "declare" && !self.newline_before(start) {
            start -= 1;
        }
        if start > 0 && self.text(start - 1) == "default" {
            start -= 1;
            if start == 0 || self.text(start - 1) != "export" {
                return None;
            }
            start -= 1;
        } else if start > 0 && self.text(start - 1) == "export" {
            start -= 1;
        }
        if (self.text(start) == "export" && !exported) || !self.type_declaration_site(start) {
            return None;
        }
        // Anonymous expressions and generator declarations do not admit
        // overload signatures. Do not turn malformed executable code into
        // a successful empty statement by erasing either form.
        let mut cursor = function + 1;
        if self.tokens.get(cursor)?.kind != Kind::Word {
            return None;
        }
        cursor += 1;
        if self.text(cursor) == "<" {
            cursor = self.angle_end(cursor)?;
        }
        if self.text(cursor) != "(" || !self.type_parameter_list(cursor, 0) {
            return None;
        }
        let close = self.pairs[cursor]?;
        // A destructuring default can contain effects even though the outer
        // signature has no body. Such invalid overloads stay for diagnostics.
        let mut parameter = cursor + 1;
        while parameter < close {
            if self.text(parameter) == "..." {
                parameter += 1;
            }
            let binding_end = self.binding_end(parameter)?;
            if self.tokens[parameter..binding_end]
                .iter()
                .any(|token| token.text == "=")
            {
                return None;
            }
            parameter = binding_end;
            if self.text(parameter) == "?" {
                parameter += 1;
            }
            if self.text(parameter) == ":" {
                parameter = self.type_end(parameter + 1, 0)?;
            }
            if parameter < close {
                if self.text(parameter) != "," {
                    return None;
                }
                parameter += 1;
            }
        }
        cursor = close + 1;
        if self.text(cursor) == ":" {
            cursor = self.type_end(cursor + 1, 0)?;
        }
        if self.text(cursor) == ";" {
            return Some((start, cursor + 1));
        }
        // A braced implementation on the following line is still a body.
        // Other punctuation may continue malformed syntax and is not an
        // automatic-semicolon boundary at which deleting code is safe.
        if cursor == self.tokens.len()
            || self.text(cursor) == "}"
            || (self.newline_before(cursor) && self.tokens[cursor].kind == Kind::Word)
        {
            Some((start, cursor))
        } else {
            None
        }
    }

    /// Ambient host bindings describe existing values; they must not allocate
    /// local var/let/const slots or evaluate initializer expressions. Admit
    /// the whole list atomically, retaining unsupported/effectful initializers
    /// for parser diagnostics instead of deleting their effects.
    fn ambient_variable_span(&self, declare: usize, exported: bool) -> Option<(usize, usize)> {
        if self.property_name(declare) || self.newline_before(declare + 1) {
            return None;
        }
        let start = if declare > 0 && self.text(declare - 1) == "export" {
            if !exported {
                return None;
            }
            declare - 1
        } else {
            declare
        };
        if !self.type_declaration_site(start) {
            return None;
        }
        // `declare global { ... }`, `declare module "m" { ... }`, `declare
        // namespace N.M { ... }`: ambient blocks declare types only
        // (bd-9vouw.435).
        if matches!(self.text(declare + 1), "global" | "module" | "namespace") {
            let mut body = declare + 2;
            if self.text(declare + 1) != "global" {
                if !self
                    .tokens
                    .get(body)
                    .is_some_and(|token| matches!(token.kind, Kind::Word | Kind::Literal))
                {
                    return None;
                }
                body += 1;
                while self.text(body) == "."
                    && self
                        .tokens
                        .get(body + 1)
                        .is_some_and(|token| token.kind == Kind::Word)
                {
                    body += 2;
                }
            }
            if self.text(body) != "{" {
                return None;
            }
            return Some((start, self.pairs[body]? + 1));
        }
        let constant = self.text(declare + 1) == "const";
        if !matches!(self.text(declare + 1), "var" | "let" | "const") {
            return None;
        }
        let mut cursor = declare + 2;
        loop {
            // Ambient variable declarations have identifier bindings, not
            // destructuring patterns with possibly executable defaults.
            if self.tokens.get(cursor)?.kind != Kind::Word {
                return None;
            }
            cursor += 1;
            if self.text(cursor) == ":" {
                cursor = self.type_end(cursor + 1, 0)?;
            }
            if self.text(cursor) == "=" {
                if !constant {
                    return None;
                }
                cursor = self.ambient_constant_end(cursor + 1)?;
            }
            match self.text(cursor) {
                "," => cursor += 1,
                ";" => return Some((start, cursor + 1)),
                "}" => return Some((start, cursor)),
                _ if cursor == self.tokens.len()
                    || (self.newline_before(cursor) && self.tokens[cursor].kind == Kind::Word) =>
                {
                    return Some((start, cursor));
                }
                _ => return None,
            }
        }
    }

    fn ambient_constant_end(&self, mut cursor: usize) -> Option<usize> {
        let signed = matches!(self.text(cursor), "-" | "+");
        if signed {
            cursor += 1;
        }
        let token = self.tokens.get(cursor)?;
        let numeric = token.kind == Kind::Literal
            && token
                .text
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_digit);
        let quoted = token.kind == Kind::Literal && token.text.starts_with(['\'', '"']);
        if numeric || (!signed && (quoted || matches!(token.text, "true" | "false"))) {
            Some(cursor + 1)
        } else {
            None
        }
    }

    fn type_declaration_site(&self, start: usize) -> bool {
        if start == 0 {
            return true;
        }
        match self.text(start - 1) {
            ";" | "}" => true,
            "{" => {
                // The first statement in a function/block is a declaration
                // site; the first property in an object/class is not. Look
                // past a previously erased return type to the real `)`.
                let mut before = start - 1;
                while before > 0 && self.removed[before - 1] {
                    before -= 1;
                }
                before == 0
                    || matches!(
                        self.text(before - 1),
                        ")" | "=>" | ";" | "{" | "}" | "else" | "try" | "finally" | "do" | "static"
                    )
            }
            _ => {
                self.newline_before(start)
                    && (self.tokens[start - 1].kind != Kind::Punctuation
                        || matches!(self.text(start - 1), ")" | "]" | "++" | "--"))
                    && !matches!(
                        self.text(start - 1),
                        "throw"
                            | "new"
                            | "delete"
                            | "void"
                            | "typeof"
                            | "instanceof"
                            | "in"
                            | "of"
                            | "await"
                            | "yield"
                            | "extends"
                            | "case"
                    )
            }
        }
    }

    /// Require complete, comma-separated types rather than erasing everything
    /// between two angle brackets. In particular `a < b + c > (d)` is runtime
    /// arithmetic, whereas `a < B<C>, D > (d)` is a generic call. Nested type
    /// groups and the recursion limit belong to the existing type parser.
    pub(super) fn expression_type_arguments_end(&self, open: usize) -> Option<usize> {
        let mut cursor = open + 1;
        loop {
            let end = self.type_end(cursor, 0)?;
            if end <= cursor {
                return None;
            }
            match self.text(end) {
                ">" => return Some(end + 1),
                "," => {
                    cursor = end + 1;
                    if self.text(cursor) == ">" {
                        return Some(cursor + 1);
                    }
                }
                _ => return None,
            }
        }
    }

    fn generic_suffix_follows(&self, end: usize, optional: bool) -> bool {
        if self.text(end) == "(" {
            return true;
        }
        // `callee?.<T>(args)` can only be an optional call, never an
        // instantiation expression or optional tagged template.
        if optional {
            return false;
        }
        if (self.text(end) == "?." && self.text(end + 1) == "(")
            || self
                .tokens
                .get(end)
                .is_some_and(|token| token.kind == Kind::Literal && token.text.starts_with('`'))
        {
            return true;
        }
        // Instantiation expressions specialize a *type*, not a runtime
        // function. `const specialized = factory<T>` must retain the exact
        // original callable, with no invocation or wrapper allocation.
        // The same boundary admits `new Constructor<T>` without arguments.
        // These ambiguous followers instead continue relational expressions,
        // even across a line break: `a < b > +c` must still read b and c.
        if matches!(self.text(end), "<" | ">" | "+" | "-") {
            return false;
        }
        // The parent lexer splits angle brackets for nested types. Do not
        // steal the `>` from the runtime >= operator in `a < b >= c`.
        if self.tokens.get(end).is_some_and(|token| {
            self.tokens[end - 1].end == token.start && token.text.starts_with('=')
        }) {
            return false;
        }
        end == self.tokens.len()
            || self.newline_before(end)
            || matches!(
                self.text(end),
                ";" | ","
                    | ")"
                    | "]"
                    | "}"
                    | "?"
                    | ":"
                    | "="
                    | "=="
                    | "!="
                    | "*"
                    | "/"
                    | "%"
                    | "&"
                    | "|"
                    | "^"
                    | "&&"
                    | "||"
                    | "??"
                    | "in"
                    | "instanceof"
                    | "as"
                    | "satisfies"
            )
    }

    fn suffix_operand(&self, previous: usize) -> bool {
        let token = self.tokens[previous];
        match token.kind {
            Kind::Literal => true,
            Kind::Word => {
                // Keywords are property names after a dot, including `new`
                // and `return`. Otherwise these tokens start/continue syntax,
                // not the operand of a postfix assertion.
                self.property_name(previous)
                    || !matches!(
                        token.text,
                        "return"
                            | "throw"
                            | "yield"
                            | "await"
                            | "void"
                            | "typeof"
                            | "delete"
                            | "new"
                            | "in"
                            | "instanceof"
                            | "of"
                            | "case"
                            | "else"
                            | "do"
                            | "const"
                            | "let"
                            | "var"
                            | "function"
                            | "class"
                            | "extends"
                            | "implements"
                            | "import"
                            | "export"
                            | "default"
                    )
            }
            Kind::Punctuation => match token.text {
                "]" | "}" => true,
                ")" => {
                    let Some(open) = self.pairs[previous] else {
                        return false;
                    };
                    !open.checked_sub(1).is_some_and(|head| {
                        !self.property_name(head)
                            && matches!(
                                self.text(head),
                                "if" | "while" | "for" | "with" | "switch" | "catch"
                            )
                    })
                }
                _ => false,
            },
        }
    }

    fn expression_type_boundary(&self, index: usize) -> bool {
        index == self.tokens.len()
            || self.newline_before(index)
            || self
                .tokens
                .get(index)
                .is_some_and(|token| token.kind == Kind::Literal && token.text.starts_with('`'))
            || matches!(
                self.text(index),
                ";" | ","
                    | ")"
                    | "]"
                    | "}"
                    | "("
                    | "["
                    | "."
                    | "?."
                    | "?"
                    | ":"
                    | "!"
                    | "="
                    | "=="
                    | "!="
                    | "+"
                    | "-"
                    | "*"
                    | "/"
                    | "%"
                    | "<"
                    | ">"
                    | "&"
                    | "|"
                    | "^"
                    | "&&"
                    | "||"
                    | "??"
                    | "++"
                    | "--"
                    | "in"
                    | "instanceof"
                    | "as"
                    | "satisfies"
            )
    }

    fn module_clause_end(&self, index: usize) -> Option<usize> {
        if self.property_name(index) {
            return None;
        }
        let mut cursor = index + 1;
        match self.text(index) {
            "export" => match self.text(cursor) {
                "{" => return self.group_end(cursor),
                "*" => cursor += 1,
                _ => return None,
            },
            "import" => {
                if self.tokens.get(cursor)?.kind == Kind::Literal {
                    return Some(cursor + 1);
                }
                if self.tokens.get(cursor)?.kind == Kind::Word {
                    cursor += 1;
                    if self.text(cursor) == "," {
                        cursor += 1;
                    }
                }
                match self.text(cursor) {
                    "{" => cursor = self.group_end(cursor)?,
                    "*" => cursor += 1,
                    "from" => {}
                    _ => return None,
                }
            }
            _ => return None,
        }
        if self.text(cursor) == "as" {
            if self.tokens.get(cursor + 1)?.kind != Kind::Word {
                return None;
            }
            cursor += 2;
        }
        if self.text(cursor) == "from" && self.tokens.get(cursor + 1)?.kind == Kind::Literal {
            Some(cursor + 2)
        } else {
            None
        }
    }
}
