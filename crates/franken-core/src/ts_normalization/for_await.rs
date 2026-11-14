//! Shared `for await ... of` protocol lowering for JavaScript and TypeScript.
//!
//! The parsers retain their grammar and source-span checks; this renderer owns
//! iterator acquisition, Async-from-Sync continuations and abrupt completion.
//! Generated bindings avoid every identifier in the head and body, including
//! Unicode-escaped names. The synchronous adapter follows current Node's
//! close-on-rejected-value behavior while preserving AsyncIteratorClose's
//! original-throw precedence.

use std::collections::BTreeSet;

use super::namespaces::{Lexed, TokenKind, lex};

const INVALID_HEADER: &str = "for await requires one binding or assignment target followed by of";

// `%` cannot begin a source identifier. Only the parser-created AST can name
// these operations, so guest bindings and replaced global properties cannot
// change the language's iterator protocol.
pub const CALL_INTRINSIC: &str = "%ForAwaitCall";
pub const TYPE_ERROR_INTRINSIC: &str = "%ForAwaitTypeError";
pub const ASYNC_ITERATOR_INTRINSIC: &str = "%ForAwaitAsyncIterator";
pub const ITERATOR_INTRINSIC: &str = "%ForAwaitIterator";

#[derive(Debug)]
pub struct LoweredLoop {
    pub source: String,
    /// The parser uses this fresh prefix to authenticate its four generated
    /// intrinsic initializers. No guest declaration is rewritten.
    pub prefix: String,
}

/// Whether a statement is a for-await loop, possibly preceded by labels.
/// Parsers use this only after validating the labels themselves, to attach
/// them to the generated iteration statement rather than its setup block.
pub fn is_for_await_statement(source: &str) -> bool {
    let Ok(lexed) = lex(source) else {
        return false;
    };
    let mut cursor = 0;
    while lexed
        .tokens
        .get(cursor)
        .is_some_and(|token| token.kind == TokenKind::Word)
        && lexed
            .tokens
            .get(cursor + 1)
            .is_some_and(|token| token.text == ":")
    {
        cursor += 2;
    }
    ["for", "await", "("]
        .iter()
        .enumerate()
        .all(|(offset, expected)| {
            lexed
                .tokens
                .get(cursor + offset)
                .is_some_and(|token| token.text == *expected)
        })
}

fn top_level_tokens(lexed: &Lexed) -> Vec<usize> {
    let mut result = Vec::new();
    let mut cursor = 0;
    while cursor < lexed.tokens.len() {
        result.push(cursor);
        cursor = lexed.pairs[cursor]
            .filter(|close| *close > cursor)
            .map_or(cursor + 1, |close| close + 1);
    }
    result
}

fn split_header(header: &str) -> Result<(&str, &str, bool), &'static str> {
    let lexed = lex(header)?;
    let top = top_level_tokens(&lexed);
    for (position, &index) in top.iter().enumerate() {
        let token = &lexed.tokens[index];
        if token.kind != TokenKind::Word || token.text != "of" || position == 0 {
            continue;
        }
        // `of` itself may be the name in `const of of values`, and an
        // assignment target may contain an ordinary `.of` member.
        if matches!(lexed.tokens[top[position - 1]].text.as_str(), "." | "?.")
            || (position == 1
                && matches!(lexed.tokens[top[0]].text.as_str(), "let" | "const" | "var"))
        {
            continue;
        }
        if top[..position].iter().any(|&index| {
            matches!(
                lexed.tokens[index].text.as_str(),
                "," | ";"
                    | "="
                    | "?"
                    | ":"
                    | "?."
                    | "+"
                    | "-"
                    | "*"
                    | "/"
                    | "%"
                    | "**"
                    | "&&"
                    | "||"
                    | "??"
                    | "!"
                    | "~"
                    | "++"
                    | "--"
                    | "&"
                    | "|"
                    | "^"
                    | "<"
                    | ">"
                    | "<="
                    | ">="
                    | "=="
                    | "!="
                    | "==="
                    | "!=="
            )
        }) {
            return Err(INVALID_HEADER);
        }
        let target = header[..token.start].trim();
        let iterable = header[token.end..].trim();
        if target.is_empty() || iterable.is_empty() {
            return Err(INVALID_HEADER);
        }
        // The RHS is an AssignmentExpression, so an unparenthesized comma
        // sequence cannot become valid merely because the renderer wraps it.
        if top[position + 1..]
            .iter()
            .any(|&index| matches!(lexed.tokens[index].text.as_str(), "," | ";"))
        {
            return Err(INVALID_HEADER);
        }
        let lexical = matches!(lexed.tokens[top[0]].text.as_str(), "let" | "const");
        return Ok((target, iterable, lexical));
    }
    Err(INVALID_HEADER)
}

fn fresh_prefix(header: &str, body: &str, labels: &[&str]) -> Result<String, &'static str> {
    let mut names = BTreeSet::new();
    for source in [header, body] {
        for token in lex(source)?.tokens {
            if token.kind == TokenKind::Word {
                names.insert(token.text);
            }
        }
    }
    names.extend(labels.iter().map(|name| name.to_string()));
    for index in 0usize.. {
        let prefix = format!("__franken_fa_{index}_");
        if !names.iter().any(|name| name.starts_with(&prefix)) {
            return Ok(prefix);
        }
    }
    unreachable!("a finite source cannot occupy every generated prefix")
}

/// Lower one already-delimited loop. Labels are attached to the generated
/// while so `continue label` keeps iterating without closing the producer.
pub fn lower(header: &str, body: &str, labels: &[&str]) -> Result<LoweredLoop, &'static str> {
    let (target, iterable, lexical) = split_header(header)?;
    if body.trim().is_empty() {
        return Err("for await requires a loop body");
    }
    let body_tokens = lex(body)?;
    if body_tokens.tokens.first().is_some_and(|first| {
        matches!(first.text.as_str(), "const" | "class" | "function")
            || (first.text == "async"
                && body_tokens
                    .tokens
                    .get(1)
                    .is_some_and(|next| next.text == "function"))
            || (first.text == "let"
                && body_tokens.tokens.get(1).is_some_and(|next| {
                    next.kind == TokenKind::Word || matches!(next.text.as_str(), "[" | "{")
                }))
    }) {
        return Err("a declaration cannot be the unbraced body of a for-await loop");
    }
    let p = fresh_prefix(header, body, labels)?;
    let source = if lexical {
        // The head's lexical names are uninitialized while its RHS runs,
        // but their environment ends before GetIterator. An unreachable
        // declaration establishes exactly that TDZ without evaluating any
        // destructuring defaults. Each iteration declares its own binding.
        format!(
            "let {p}src; {p}head: {{ {p}src = ({iterable}); break {p}head; {target} = void 0; }}"
        )
    } else {
        format!("let {p}src = ({iterable});")
    };
    let bind = if target.starts_with('{') {
        format!("({target} = {p}value);")
    } else {
        format!("{target} = {p}value;")
    };
    let label_prefix = labels
        .iter()
        .map(|label| format!("{label}: "))
        .collect::<String>();
    let body = body.trim();
    let terminator = if body.ends_with('}') || body.ends_with(';') {
        ""
    } else {
        ";"
    };
    let source = format!(
        "{{ \
         const {p}apply = function(target, receiver) {{ return Reflect.apply(target, receiver, []); }}; \
         const {p}TypeError = function(message) {{ return TypeError(message); }}; \
         const {p}asyncKey = Symbol.asyncIterator; const {p}syncKey = Symbol.iterator; \
         {source} \
         const {p}object = function(value) {{ \
           if (value === null || (typeof value !== 'object' && typeof value !== 'function')) \
             throw {p}TypeError('Iterator result is not an object'); \
           return value; \
         }}; \
         let {p}method = {p}src[{p}asyncKey]; \
         const {p}sync = {p}method == null; \
         if ({p}sync) {p}method = {p}src[{p}syncKey]; \
         const {p}iterator = {p}object({p}apply({p}method, {p}src)); \
         const {p}next = {p}iterator.next; \
         const {p}syncNext = async function() {{ \
           const result = {p}object({p}apply({p}next, {p}iterator)); \
           const done = !!result.done; let value = result.value; \
           try {{ value = await value; }} catch (error) {{ \
             if (!done) {{ try {{ \
               const close = {p}iterator.return; \
               if (close != null) {p}apply(close, {p}iterator); \
             }} catch (ignored) {{}} }} \
             throw error; \
           }} \
           return {{ value: value, done: done }}; \
         }}; \
         const {p}syncReturn = async function() {{ \
           const close = {p}iterator.return; \
           if (close == null) return {{ value: void 0, done: true }}; \
           const result = {p}object({p}apply(close, {p}iterator)); \
           const done = !!result.done; const value = await result.value; \
           return {{ value: value, done: done }}; \
         }}; \
         let {p}active = false; let {p}thrown = false; \
         try {{ {label_prefix}while (true) {{ \
           {p}active = false; \
           const {p}result = {p}sync ? await {p}syncNext() : \
             {p}object(await {p}apply({p}next, {p}iterator)); \
           if ({p}result.done) break; \
           const {p}value = {p}result.value; \
           {p}active = true; \
           {bind} {body}{terminator} \
         }} }} catch ({p}error) {{ {p}thrown = true; throw {p}error; }} \
         finally {{ if ({p}active) {{ try {{ \
           if ({p}sync) {{ await {p}syncReturn(); }} else {{ \
             const {p}close = {p}iterator.return; \
             if ({p}close != null) {p}object(await {p}apply({p}close, {p}iterator)); \
           }} \
         }} catch ({p}closeError) {{ if (!{p}thrown) throw {p}closeError; }} }} }} \
         }}"
    );
    Ok(LoweredLoop { source, prefix: p })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minified_patterns_contextual_names_and_members_split_at_the_actual_of() {
        for (header, target, iterable) in [
            ("const[k,v]of values", "const[k,v]", "values"),
            ("let{a:x=of}of values", "let{a:x=of}", "values"),
            ("const of of values", "const of", "values"),
            ("target.of of values", "target.of", "values"),
            ("target['of']of values", "target['of']", "values"),
        ] {
            let (actual_target, actual_iterable, _) = split_header(header).unwrap();
            assert_eq!((actual_target, actual_iterable), (target, iterable));
        }
    }

    #[test]
    fn invalid_for_await_heads_do_not_fall_back_to_synchronous_iteration() {
        for header in [
            "const x in values",
            "let x,y of values",
            "var x=1 of values",
            ";;",
            "x of",
            "const x of values,values",
            "x ? y : z of values",
            "x + y of values",
            "x?.value of values",
        ] {
            assert!(lower(header, "{}", &[]).is_err(), "{header}");
        }
    }

    #[test]
    fn declarations_need_a_block_body() {
        for body in [
            "",
            "const x=1;",
            "let x;",
            "function f() {}",
            "class C {}",
            "async function f() {}",
        ] {
            assert!(lower("const value of source", body, &[]).is_err(), "{body}");
        }
        for body in [";", "{}", "let();", "let.value();", "var x;"] {
            assert!(lower("const value of source", body, &[]).is_ok(), "{body}");
        }
    }

    #[test]
    fn helper_names_are_fresh_even_for_escaped_identifiers_and_template_expressions() {
        let body =
            r#"{ use(__franken_fa_0_src, __franken_fa_\u0031_next, `${__franken_fa_2_value}`); }"#;
        let output = lower("const value of source", body, &[]).unwrap();
        assert!(output.source.starts_with("{ const __franken_fa_3_apply"));
        assert!(output.source.contains(body));
    }

    #[test]
    fn labels_are_placed_on_the_iteration_statement() {
        let output = lower(
            "const value of source",
            "{ continue outer; }",
            &["outer", "inner"],
        )
        .unwrap();
        assert!(output.source.contains("try { outer: inner: while (true)"));
        assert!(is_for_await_statement(
            "outer: inner: for await (x of xs) {}"
        ));
        assert!(!is_for_await_statement("outer: { for await (x of xs) {} }"));
        assert!(!is_for_await_statement("for (const value of xs) {}"));
    }

    #[test]
    fn lexical_rhs_names_remain_uninitialized_before_acquisition() {
        let output = lower("const { value } of value", "{}", &[]).unwrap();
        assert!(
            output
                .source
                .contains("src = (value); break __franken_fa_0_head; const { value } = void 0;")
        );
        let var_output = lower("var value of value", "{}", &[]).unwrap();
        assert!(!var_output.source.contains("head:"));
    }
}
