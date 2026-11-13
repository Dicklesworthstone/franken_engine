//! Lower constructor parameter properties after annotation erasure.
//!
//! Source tokens and delimiter pairs keep comments, regular expressions and
//! defaults out of the syntax being rewritten. The generated assignments follow
//! a direct `super(...)` statement (including redundant parentheses), or the
//! constructor's directive prologue when there is no such statement. Existing
//! class-field initialization is left to the class lowering/runtime contract.

use super::namespaces::{Lexed, TokenKind, lex};

const MAX_STATEMENT_DEPTH: usize = 128;

struct Edit {
    start: usize,
    end: usize,
    replacement: String,
}

#[derive(Clone, Copy)]
struct Insertion {
    offset: usize,
    semicolon: bool,
}

struct Constructor<'a> {
    names: Vec<&'a str>,
    erased: Vec<(usize, usize)>,
    close: usize,
}

/// Lower parameter-property modifiers into ordinary parameters and assignments.
/// Unbalanced or unsupported syntax is retained for the ordinary parser.
pub fn lower(source: &str) -> String {
    let Ok(lexed) = lex(source) else {
        return source.to_owned();
    };
    let syntax = Syntax {
        source,
        lexed: &lexed,
    };
    let mut edits = Vec::new();
    for index in 0..lexed.tokens.len() {
        if syntax.text(index) != "constructor"
            || syntax.text(index + 1) != "("
            || index > 0 && matches!(syntax.text(index - 1), "." | "?.")
        {
            continue;
        }
        let Some(constructor) = syntax.parameters(index + 1) else {
            continue;
        };
        if constructor.names.is_empty() {
            continue;
        }
        let body = constructor.close + 1;
        let insertion = if syntax.text(body) == "{" {
            let Some(end) = syntax.pair(body) else {
                continue;
            };
            let Ok(insertion) = syntax.constructor_insertion(body, end) else {
                continue;
            };
            let mut assignments = String::new();
            if insertion.semicolon {
                assignments.push(';');
            }
            for name in constructor.names {
                assignments.push_str(&format!(" this.{name} = {name};"));
            }
            assignments.push(' ');
            Some(Edit {
                start: insertion.offset,
                end: insertion.offset,
                replacement: assignments,
            })
        } else if syntax.text(body) != ";" {
            // Keep the normalizer's standalone constructor-signature contract.
            let offset = lexed.tokens[constructor.close].end;
            Some(Edit {
                start: offset,
                end: offset,
                replacement: ";".to_string(),
            })
        } else {
            None
        };
        for (start, end) in constructor.erased {
            edits.push(Edit {
                start,
                end,
                replacement: " ".repeat(end - start),
            });
        }
        edits.extend(insertion);
    }
    edits.sort_by_key(|edit| (edit.start, edit.end));
    let mut output = String::with_capacity(source.len());
    let mut cursor = 0;
    for edit in edits {
        if edit.start < cursor {
            return source.to_owned();
        }
        output.push_str(&source[cursor..edit.start]);
        output.push_str(&edit.replacement);
        cursor = edit.end;
    }
    output.push_str(&source[cursor..]);
    output
}

struct Syntax<'a> {
    source: &'a str,
    lexed: &'a Lexed,
}

impl<'a> Syntax<'a> {
    fn text(&self, index: usize) -> &str {
        self.lexed
            .tokens
            .get(index)
            .map_or("", |token| token.text.as_str())
    }

    fn word(&self, index: usize) -> bool {
        self.lexed
            .tokens
            .get(index)
            .is_some_and(|token| token.kind == TokenKind::Word)
    }

    fn pair(&self, index: usize) -> Option<usize> {
        self.lexed.pairs.get(index).copied().flatten()
    }

    fn after_group(&self, index: usize) -> Option<usize> {
        matches!(self.text(index), "(" | "[" | "{" | "${")
            .then(|| self.pair(index).map(|end| end + 1))
            .flatten()
    }

    fn newline_before(&self, index: usize) -> bool {
        index > 0
            && self.lexed.tokens.get(index).is_some_and(|token| {
                self.source[self.lexed.tokens[index - 1].end..token.start]
                    .contains(['\n', '\r', '\u{2028}', '\u{2029}'])
            })
    }

    fn parameters(&self, open: usize) -> Option<Constructor<'a>> {
        let close = self.pair(open)?;
        let mut cursor = open + 1;
        let mut names = Vec::new();
        let mut erased = Vec::new();
        while cursor < close {
            let start = cursor;
            let mut end = cursor;
            while end < close && self.text(end) != "," {
                end = self.after_group(end).unwrap_or(end + 1);
            }
            let mut access = false;
            let mut readonly = false;
            let mut overrides = false;
            while cursor + 1 < end && self.word(cursor + 1) {
                match self.text(cursor) {
                    "public" | "private" | "protected" if !access => access = true,
                    "readonly" if !readonly => readonly = true,
                    "override" if !overrides => overrides = true,
                    "public" | "private" | "protected" | "readonly" | "override" => {
                        return None;
                    }
                    _ => break,
                }
                let token = &self.lexed.tokens[cursor];
                erased.push((token.start, token.end));
                cursor += 1;
            }
            if cursor != start {
                if !self.word(cursor) {
                    return None;
                }
                let token = &self.lexed.tokens[cursor];
                names.push(&self.source[token.start..token.end]);
                cursor += 1;
                if self.text(cursor) == "?" {
                    let token = &self.lexed.tokens[cursor];
                    erased.push((token.start, token.end));
                    cursor += 1;
                }
                // Standalone constructor signatures are not necessarily
                // recognized by annotation erasure. Retain any annotation
                // bytes while preserving their historical modifier/semicolon
                // normalization; the ordinary parser still owns validity.
                if cursor < end && !matches!(self.text(cursor), "=" | ":") {
                    return None;
                }
            }
            cursor = end + 1;
        }
        Some(Constructor {
            names,
            erased,
            close,
        })
    }

    fn constructor_insertion(&self, open: usize, end: usize) -> Result<Insertion, ()> {
        let mut start = open + 1;
        let mut fallback = Insertion {
            offset: self.lexed.tokens[open].end,
            semicolon: false,
        };
        while start < end {
            let token = &self.lexed.tokens[start];
            if token.kind != TokenKind::Literal
                || !self.source[token.start..token.end].starts_with(['\'', '"'])
            {
                break;
            }
            let Some((next, insertion)) = self.expression_ending(start + 1, end) else {
                break;
            };
            fallback = insertion;
            start = next;
        }
        Ok(self.find_super(start, end, 0)?.unwrap_or(fallback))
    }

    // A completed expression followed by a semicolon or a valid ASI boundary.
    fn expression_ending(&self, after: usize, end: usize) -> Option<(usize, Insertion)> {
        if self.text(after) == ";" {
            return Some((
                after + 1,
                Insertion {
                    offset: self.lexed.tokens[after].end,
                    semicolon: false,
                },
            ));
        }
        if after == end || self.newline_before(after) && !self.continues_expression(after) {
            return Some((
                after,
                Insertion {
                    offset: self.lexed.tokens[after - 1].end,
                    semicolon: true,
                },
            ));
        }
        None
    }

    fn direct_super(&self, start: usize, end: usize) -> Option<Insertion> {
        let mut cursor = start;
        let mut wrappers = Vec::new();
        while self.text(cursor) == "(" {
            wrappers.push(self.pair(cursor)?);
            cursor += 1;
        }
        if self.text(cursor) != "super" || self.text(cursor + 1) != "(" {
            return None;
        }
        let mut after = self.pair(cursor + 1)? + 1;
        for close in wrappers.into_iter().rev() {
            if close != after {
                return None;
            }
            after += 1;
        }
        self.expression_ending(after, end)
            .map(|(_, insertion)| insertion)
    }

    fn find_super(
        &self,
        mut cursor: usize,
        end: usize,
        depth: usize,
    ) -> Result<Option<Insertion>, ()> {
        if depth >= MAX_STATEMENT_DEPTH {
            return Err(());
        }
        while cursor < end {
            if let Some(insertion) = self.direct_super(cursor, end) {
                return Ok(Some(insertion));
            }
            // TypeScript also searches a try statement's try-block, not its
            // catch/finally handlers or arbitrary nested control-flow bodies.
            if self.text(cursor) == "try" && self.text(cursor + 1) == "{" {
                let close = self.pair(cursor + 1).ok_or(())?;
                if let Some(insertion) = self.find_super(cursor + 2, close, depth + 1)? {
                    return Ok(Some(insertion));
                }
            }
            cursor = self.statement_end(cursor, end, depth + 1)?;
        }
        Ok(None)
    }

    fn statement_end(&self, start: usize, end: usize, depth: usize) -> Result<usize, ()> {
        if depth >= MAX_STATEMENT_DEPTH || start >= end {
            return Err(());
        }
        let next = match self.text(start) {
            ";" => start + 1,
            "{" => self.pair(start).ok_or(())? + 1,
            "if" => {
                let body = self.condition_end(start + 1)?;
                let after = self.statement_end(body, end, depth + 1)?;
                if self.text(after) == "else" {
                    self.statement_end(after + 1, end, depth + 1)?
                } else {
                    after
                }
            }
            "for" | "while" | "with" | "switch" => {
                let condition = start + 1 + usize::from(self.text(start + 1) == "await");
                self.statement_end(self.condition_end(condition)?, end, depth + 1)?
            }
            "do" => {
                let after = self.statement_end(start + 1, end, depth + 1)?;
                if self.text(after) != "while" {
                    return Err(());
                }
                let after = self.condition_end(after + 1)?;
                after + usize::from(self.text(after) == ";")
            }
            "try" => {
                if self.text(start + 1) != "{" {
                    return Err(());
                }
                let mut after = self.pair(start + 1).ok_or(())? + 1;
                if self.text(after) == "catch" {
                    after += 1;
                    if self.text(after) == "(" {
                        after = self.condition_end(after)?;
                    }
                    if self.text(after) != "{" {
                        return Err(());
                    }
                    after = self.pair(after).ok_or(())? + 1;
                }
                if self.text(after) == "finally" {
                    if self.text(after + 1) != "{" {
                        return Err(());
                    }
                    after = self.pair(after + 1).ok_or(())? + 1;
                }
                after
            }
            "function" => self.function_end(start, end)?,
            "async" if self.text(start + 1) == "function" && !self.newline_before(start + 1) => {
                self.function_end(start + 1, end)?
            }
            "class" => self.class_end(start, end, depth + 1)?,
            "<" => match self.standalone_jsx_end(start, end) {
                Some(after) => after,
                None => self.expression_statement_end(start, end)?,
            },
            "return" | "break" | "continue" if self.newline_before(start + 1) => start + 1,
            _ if self.word(start) && self.text(start + 1) == ":" => {
                self.statement_end(start + 2, end, depth + 1)?
            }
            _ => self.expression_statement_end(start, end)?,
        };
        (next > start && next <= end).then_some(next).ok_or(())
    }

    fn condition_end(&self, open: usize) -> Result<usize, ()> {
        if self.text(open) != "(" {
            return Err(());
        }
        self.pair(open).map(|close| close + 1).ok_or(())
    }

    // JSX lowering runs later. Recognize its existing standalone-line forms
    // only as statement boundaries, without rewriting JSX or changing the
    // caller's `jsx: preserve` contract.
    fn standalone_jsx_end(&self, start: usize, end: usize) -> Option<usize> {
        let offset = self.lexed.tokens[start].start;
        if !self.source[..offset]
            .rsplit(['\n', '\r', '\u{2028}', '\u{2029}'])
            .next()?
            .trim()
            .is_empty()
        {
            return None;
        }
        let line_end = self.source[offset..]
            .find(['\n', '\r', '\u{2028}', '\u{2029}'])
            .map_or(self.source.len(), |length| offset + length);
        let line = self.source[offset..line_end].trim_end();
        let supported = if line.ends_with("/>") {
            !line
                .trim_start_matches('<')
                .trim_end_matches("/>")
                .trim()
                .is_empty()
        } else if let Some(open_end) = line.find('>') {
            let tag = line[1..open_end].trim();
            line.ends_with(&format!("</{tag}>"))
        } else {
            false
        };
        if !supported {
            return None;
        }
        let mut after = start + 1;
        while after < end && self.lexed.tokens[after].start < line_end {
            after += 1;
        }
        Some(after)
    }

    fn function_end(&self, start: usize, end: usize) -> Result<usize, ()> {
        let mut cursor = start + 1;
        if self.text(cursor) == "*" {
            cursor += 1;
        }
        if self.word(cursor) {
            cursor += 1;
        }
        let body = self.condition_end(cursor)?;
        if body >= end || self.text(body) != "{" {
            return Err(());
        }
        self.pair(body).map(|close| close + 1).ok_or(())
    }

    fn class_end(&self, start: usize, end: usize, depth: usize) -> Result<usize, ()> {
        if depth >= MAX_STATEMENT_DEPTH {
            return Err(());
        }
        let mut cursor = start + 1;
        if self.word(cursor) && self.text(cursor) != "extends" {
            cursor += 1;
        }
        if self.text(cursor) == "extends" {
            cursor += 1;
            while cursor < end && self.text(cursor) != "{" {
                cursor = if !matches!(self.text(cursor - 1), "." | "?.") {
                    match self.text(cursor) {
                        "class" => self.class_end(cursor, end, depth + 1)?,
                        "function" => self.function_end(cursor, end)?,
                        "async"
                            if self.text(cursor + 1) == "function"
                                && !self.newline_before(cursor + 1) =>
                        {
                            self.function_end(cursor + 1, end)?
                        }
                        _ => self.after_group(cursor).unwrap_or(cursor + 1),
                    }
                } else {
                    self.after_group(cursor).unwrap_or(cursor + 1)
                };
            }
        }
        if cursor >= end || self.text(cursor) != "{" {
            return Err(());
        }
        self.pair(cursor).map(|close| close + 1).ok_or(())
    }

    fn expression_statement_end(&self, start: usize, end: usize) -> Result<usize, ()> {
        let mut cursor = start;
        while cursor < end {
            if self.text(cursor) == ";" {
                return Ok(cursor + 1);
            }
            if cursor > start
                && self.newline_before(cursor)
                && self.ends_expression(cursor - 1)
                && !self.continues_expression(cursor)
            {
                return Ok(cursor);
            }
            if matches!(self.text(cursor), ")" | "]" | "}") {
                return Err(());
            }
            cursor = self.after_group(cursor).unwrap_or(cursor + 1);
        }
        Ok(end)
    }

    fn ends_expression(&self, index: usize) -> bool {
        let token = &self.lexed.tokens[index];
        matches!(token.kind, TokenKind::Literal | TokenKind::TemplateTail)
            || token.kind == TokenKind::Word
                && !matches!(
                    token.text.as_str(),
                    "return"
                        | "throw"
                        | "new"
                        | "yield"
                        | "await"
                        | "typeof"
                        | "void"
                        | "delete"
                        | "instanceof"
                        | "in"
                        | "of"
                        | "var"
                        | "let"
                        | "const"
                )
            || matches!(token.text.as_str(), ")" | "]" | "}" | "++" | "--")
    }

    fn continues_expression(&self, index: usize) -> bool {
        let Some(token) = self.lexed.tokens.get(index) else {
            return false;
        };
        token.kind == TokenKind::TemplateHead
            || token.kind == TokenKind::Literal
                && self.source[token.start..token.end].starts_with('`')
            || matches!(
                token.text.as_str(),
                "(" | "["
                    | "."
                    | "?."
                    | ","
                    | "?"
                    | ":"
                    | "=>"
                    | "+"
                    | "-"
                    | "*"
                    | "**"
                    | "/"
                    | "%"
                    | "<"
                    | ">"
                    | "<="
                    | ">="
                    | "=="
                    | "!="
                    | "==="
                    | "!=="
                    | "&"
                    | "|"
                    | "^"
                    | "&&"
                    | "||"
                    | "??"
                    | "<<"
                    | ">>"
                    | ">>>"
                    | "="
                    | "+="
                    | "-="
                    | "*="
                    | "**="
                    | "/="
                    | "%="
                    | "&="
                    | "|="
                    | "^="
                    | "&&="
                    | "||="
                    | "??="
                    | "<<="
                    | ">>="
                    | ">>>="
                    | "in"
                    | "instanceof"
            )
    }
}

#[cfg(test)]
mod tests {
    use super::lower;

    fn lower_typescript(source: &str) -> String {
        lower(&super::super::type_erasure::erase(source))
    }

    fn compact(source: &str) -> String {
        source.chars().filter(|ch| !ch.is_whitespace()).collect()
    }

    #[test]
    fn inline_multiline_and_optional_properties_preserve_defaults() {
        let output = lower_typescript(
            "class C { constructor(\n private readonly left: number = next(1, 2),\n public right?: number,\n override third = {value: [3, 4]},\n) { use(left); } }",
        );
        let compact = compact(&output);
        assert!(compact.contains("constructor(left=next(1,2),right,third={value:[3,4]},)"));
        assert!(compact.contains("{this.left=left;this.right=right;this.third=third;use(left);}"));
        assert_eq!(output.lines().count(), 5);
    }

    #[test]
    fn comments_and_regexp_delimiters_are_not_parameter_syntax() {
        let source = "class C { constructor(public /* property */ x = /[)]/.test(\")\"), private y = /[,{}]/) {} }";
        let output = lower(source);
        assert!(output.contains("/* property */ x = /[)]/.test(\")\")"));
        assert!(output.contains("y = /[,{}]/"));
        assert!(output.contains("this.x = x; this.y = y;"));
        assert!(!output.contains("public"));
        assert!(!output.contains("private"));
    }

    #[test]
    fn modifier_words_can_be_parameter_and_property_names() {
        let output = lower_typescript(
            "class C { constructor(readonly: number = 3, public value: number = readonly) {} } class D { constructor(public readonly: number = 4, public override: number = 5) {} }",
        );
        let compact = compact(&output);
        assert!(compact.contains("constructor(readonly=3,value=readonly){this.value=value;}"));
        assert!(compact.contains(
            "constructor(readonly=4,override=5){this.readonly=readonly;this.override=override;}"
        ));
        assert_eq!(output.matches("this.readonly = readonly;").count(), 1);
    }

    #[test]
    fn comments_and_early_returns_do_not_move_initialization_before_super() {
        let output = lower(
            "class C extends B { constructor(public x = 3, skip = false) { /* super(0); */ log('prefix'); if (skip) return {x: 99}; super(); use(this.x); } }",
        );
        let early_return = output.find("return {x: 99};").unwrap();
        let real_super = output.find(" super();").unwrap();
        let assignment = output.find("this.x = x;").unwrap();
        let observed = output.find("use(this.x)").unwrap();
        assert!(early_return < real_super && real_super < assignment && assignment < observed);
        assert!(output.contains("/* super(0); */"));
        assert_eq!(output.matches("this.x = x;").count(), 1);
    }

    #[test]
    fn directives_parenthesized_super_and_asi_keep_their_roles() {
        let output = lower(
            "class B { constructor(public x) { 'use strict'; use(this.x); } }\nclass D extends B { constructor(public y) { /* before */ (super(2)) // after\n/* next */ use(this.y); } }",
        );
        assert!(output.contains("'use strict'; this.x = x;"));
        assert!(output.contains("(super(2)); this.y = y;  // after"));
        assert!(output.contains("/* before */"));
        assert!(output.contains("\n/* next */ use(this.y);"));
        assert_eq!(output.lines().count(), 3);
    }

    #[test]
    fn only_a_direct_super_statement_is_selected() {
        let output = lower(
            "class D extends B { constructor(public x, flag) { if (flag) super(1); function other(){ return 'super()'; } class Inner {} super(2); try { super(3); } catch {} } }",
        );
        assert!(output.contains("super(2); this.x = x;"));
        assert!(!output.contains("super(1); this.x"));
        assert!(!output.contains("super(3); this.x"));
        assert_eq!(output.matches("this.x = x;").count(), 1);
    }

    #[test]
    fn try_block_search_matches_typescript_without_using_catch_or_finally() {
        let output = lower(
            "class D extends B { constructor(public x) { try { before(); super(); after(); } catch { fail(); } finally { done(); } } }",
        );
        assert!(output.contains("super(); this.x = x;  after();"));
        assert_eq!(output.matches("this.x = x;").count(), 1);
    }

    #[test]
    fn nested_constructor_properties_have_independent_edits() {
        let output = lower(
            "class Outer { constructor(public factory = class Inner { constructor(public value = 2) {} }) {} }",
        );
        assert_eq!(output.matches("this.factory = factory;").count(), 1);
        assert_eq!(output.matches("this.value = value;").count(), 1);
        assert!(
            output.find("this.value = value;").unwrap()
                < output.find("this.factory = factory;").unwrap()
        );
    }

    #[test]
    fn class_heritage_function_bodies_do_not_hide_the_outer_super_statement() {
        let output = lower_typescript(
            "class B {} class D extends B { constructor(public x: number = 3) { class Local extends function(){return B;}() {} super(); } }",
        );
        assert!(output.contains("function(){return B;}() {} super(); this.x = x;"));
        assert_eq!(output.matches("this.x = x;").count(), 1);
    }

    #[test]
    fn supported_standalone_jsx_lines_do_not_hide_a_later_super_statement() {
        for jsx in ["<Widget />", "<Widget>value</Widget>"] {
            let source = format!(
                "class D extends B {{ constructor(public x) {{\n  {jsx}\n  super(); use(this.x);\n}} }}"
            );
            let output = lower(&source);
            assert!(output.contains(&format!("\n  {jsx}\n")));
            assert!(output.contains("super(); this.x = x;  use(this.x);"));
            assert_eq!(output.matches("this.x = x;").count(), 1);
        }
    }

    #[test]
    fn ordinary_constructors_and_literal_text_are_unchanged() {
        for source in [
            "class C { constructor(readonly = 3, override = 4) {} }",
            "const text = 'constructor(public fake)'; const pattern = /constructor\\(private fake\\)/;",
            "// constructor(public fake)\nconst object = { constructor(value) { return value; } };",
            "obj.constructor(privateValue);",
        ] {
            assert_eq!(lower(source), source);
        }
    }

    #[test]
    fn standalone_constructor_signatures_keep_the_existing_contract() {
        let output = lower("constructor(private x)");
        assert_eq!(compact(&output), "constructor(x);");
        let output = lower_typescript("constructor(private x: number)");
        assert_eq!(compact(&output), "constructor(x:number);");
        let output = lower_typescript("constructor(private x: number) { use(x); }");
        assert_eq!(compact(&output), "constructor(x){this.x=x;use(x);}");
    }
}
