//! TypeScript erasure shared with core source ingestion.
//!
//! Engine entry points retain their annotation and angle-assertion API while
//! both ingestion paths use one implementation. The existing regression suites
//! exercise that implementation through this facade.

#[cfg(test)]
mod classes;
#[cfg(test)]
mod expressions;

pub(super) fn erase(source: &str) -> String {
    frankenengine_core::ts_normalization::type_erasure::erase(source)
}

pub(super) fn erase_angle_assertions(source: &str) -> String {
    frankenengine_core::ts_normalization::type_erasure::erase_angle_assertions(source)
}

#[cfg(test)]
mod tests {
    use super::{erase, erase_angle_assertions};

    // Mark the exact erased spans. Everything else, including whitespace and
    // runtime colons, must remain byte-for-byte identical to the source.
    /// Like [`check`], for [`erase_angle_assertions`] (bd-9vouw.426).
    fn check_assertions(marked: &str) {
        let mut source = String::new();
        let mut expected = String::new();
        let mut rest = marked;
        while let Some(open) = rest.find('⟦') {
            source.push_str(&rest[..open]);
            expected.push_str(&rest[..open]);
            rest = &rest[open + '⟦'.len_utf8()..];
            let close = rest.find('⟧').expect("closed test marker");
            source.push_str(&rest[..close]);
            expected.extend(std::iter::repeat_n(' ', rest[..close].len()));
            rest = &rest[close + '⟧'.len_utf8()..];
        }
        source.push_str(rest);
        expected.push_str(rest);
        assert_eq!(
            erase_angle_assertions(&source),
            expected,
            "source: {source}"
        );
    }

    #[test]
    fn prefix_type_assertions_are_erased_bd_9vouw_426() {
        check_assertions("const a = ⟦<Box>⟧raw;");
        check_assertions("const b = (⟦<any>⟧raw).v + 1;");
        check_assertions("const c = ⟦<number>⟧⟦<unknown>⟧\"7\";");
        check_assertions("const d = ⟦<Array<string>>⟧[\"x\"];");
        check_assertions("const e = ⟦<{ v: number }>⟧raw;");
        check_assertions("function f(i) { return ⟦<string>⟧i; }");
        check_assertions("if (ok) ⟦<T>⟧x.run();");
        check_assertions("const i = 1 < 2 ? ⟦<number>⟧3 : 4;");
        check_assertions("[⟦<number>⟧1].map(⟦<(n: number) => number>⟧((n) => n));");
        // Generic arrows, comparisons and calls keep their angle brackets.
        check_assertions("const g = <T>(x: T): T => x;");
        check_assertions("const h = <T,>(x: T) => [x];");
        check_assertions("const k = a < b && c > d;");
        check_assertions("const m = f<number>(1);");
        check_assertions("const n = async <T>(x: T) => x;");
        check_assertions("const r = /<b>x/.test(\"<T>x\");");
    }

    pub(super) fn check(marked: &str) {
        let mut source = String::new();
        let mut expected = String::new();
        let mut rest = marked;
        while let Some(open) = rest.find('⟦') {
            source.push_str(&rest[..open]);
            expected.push_str(&rest[..open]);
            rest = &rest[open + '⟦'.len_utf8()..];
            let close = rest.find('⟧').expect("closed test marker");
            let annotation = &rest[..close];
            source.push_str(annotation);
            for ch in annotation.chars() {
                if matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}') {
                    expected.push(ch);
                } else {
                    expected.extend(std::iter::repeat_n(' ', ch.len_utf8()));
                }
            }
            rest = &rest[close + '⟧'.len_utf8()..];
        }
        source.push_str(rest);
        expected.push_str(rest);
        assert_eq!(erase(&source), expected, "source: {source}");
        assert_eq!(
            source.len(),
            expected.len(),
            "erasure preserves byte offsets"
        );
        assert_eq!(erase(&expected), expected, "erasure is idempotent");
    }

    #[test]
    fn generic_declaration_parameters_are_not_runtime_comparison_operators() {
        check("function identity⟦<T extends {value: number}>⟧(input⟦: T⟧)⟦: T⟧ { return input; }");
        check("const identity = ⟦<T>⟧(input⟦: T⟧)⟦: T⟧ => input;");
        check("class Box⟦<T>⟧ { value⟦: T⟧; choose⟦<U>⟧(value⟦: U⟧)⟦: U⟧ { return value; } }");
        // In TypeScript these are generic calls, not chained comparisons.
        // The explicitly parenthesized comparison remains a runtime operation.
        check("const value = a ⟦< b >⟧ (c); const other = (a < b) ? c : d;");
        check("a ⟦< b >⟧ (c)\n{ work(); }");
    }

    #[test]
    fn class_access_modifiers_are_erased_but_runtime_modifiers_and_names_remain() {
        check(
            "class Box { ⟦public⟧ ⟦readonly⟧ value⟦: number⟧ = 1; ⟦private⟧ run(x⟦: number⟧)⟦: number⟧ { return x; } }",
        );
        check("class Box { static value⟦: number⟧ = 1; get count()⟦: number⟧ { return 1; } }");
        check("class Box { readonly⟦: number⟧ = 1; public⟦: number⟧ = 2; }");
    }

    #[test]
    fn variables_and_destructuring_erase_only_outer_annotations() {
        check("let a⟦: number⟧ = 1, b⟦: string | null⟧ = null;");
        check("const {left: a, right: b}⟦: {left: number; right: number}⟧ = {left: 1, right: 2};");
        check("const [head, ...tail]⟦: [number, ...number[]]⟧ = [1, 2, 3];");
        check("for (const entry⟦: number⟧ of entries) { const value⟦: number⟧ = entry; }");
    }

    #[test]
    fn initializers_keep_conditionals_objects_and_nested_callbacks() {
        check("const a⟦: number⟧ = yes ? first : second, b⟦: number⟧ = 4;");
        check("const o⟦: {value: number}⟧ = {value: yes ? 1 : 2};");
        check(
            "const f = (x⟦: number⟧, o⟦: {value: number}⟧ = {value: 3})⟦: number⟧ => x + o.value;",
        );
    }

    #[test]
    fn functions_methods_and_object_returns_keep_their_bodies() {
        check("function make(x⟦: number⟧)⟦: {value: number}⟧ { return {value: x}; }");
        check("const o = { run(x⟦: number⟧)⟦: number⟧ { return x ? 1 : 0; } };");
        check("const o = { 'run'(x⟦: number⟧)⟦: number⟧ { return x; } };");
        check("function* values(x⟦: number⟧)⟦: Iterable<number>⟧ { yield x; }");
        check("try { work(); } catch (error⟦: unknown⟧) { throw error; }");
    }

    #[test]
    fn typed_keyword_methods_are_not_control_flow_heads() {
        check(
            "const object = { if(value⟦: number⟧)⟦: number⟧ { return value; }, while()⟦: number⟧ { return 1; } };",
        );
        check(
            "class Object { for(value⟦: number⟧) { return value; } switch()⟦: number⟧ { return 1; } }",
        );
        check("if (x ? y : z) { work(); } while (x = yes ? first : second) { work(); }");
        check("if ({value: true}.value) { work(); } switch (value) { case 1: work(); }");
    }

    #[test]
    fn higher_order_return_types_do_not_consume_the_runtime_arrow() {
        check("const make = ()⟦: ((x: number) => number)⟧ => x => x + 1;");
        check("const make = ()⟦: () => number⟧ => () => 3;");
        check("const invoke⟦: (x: number, rest: [number, number]) => number⟧ = (x, rest) => x;");
    }

    #[test]
    fn nested_type_arguments_tuples_and_conditional_types_are_whole_spans() {
        for ty in [
            "Record<string, Array<{value: number} | null>>",
            "readonly [first: number, second?: string]",
            "T extends U ? {yes: T} : {no: U}",
            "{ [K in keyof T]?: T[K] }",
            "keyof typeof object",
            "typeof import('package').Value",
            "new <T>(value: T) => {value: T}",
            "`prefix${number}`",
        ] {
            check(&format!("const value⟦: {ty}⟧ = original;"));
        }
    }

    #[test]
    fn receiver_and_optional_parameters_keep_runtime_arity() {
        check(
            "function read(⟦this: {base: number},⟧ offset⟦?: number⟧)⟦: number⟧ { return this.base; }",
        );
        check("function rest(first⟦?: number⟧, ...values⟦: number[]⟧) { return values; }");
        check("function receiverOnly(⟦this: object⟧) { return this; }");
    }

    /// bd-9vouw.435: a parameter named like a parameter-property modifier.
    #[test]
    fn modifier_named_parameters_keep_their_annotations_erased() {
        check("function pick(evidence⟦: Evidence⟧, override⟦: unknown⟧) { return override; }");
        check("function pick(readonly⟦?: boolean⟧, count⟦: number⟧ = 1) { return readonly; }");
    }

    #[test]
    fn class_fields_do_not_erase_runtime_object_properties() {
        check(
            "class Box { value⟦: {count: number}⟧ = {count: 3}; run(x⟦: number⟧)⟦: number⟧ { return x; } }",
        );
        check(
            "class Box { missing⟦?: string⟧; assigned⟦!: number⟧; ['key']⟦: string⟧ = 'value'; }",
        );
        check("class Box ⟦implements Contract⟧ { value⟦: number⟧ = 1; }");
        check("class Box { value⟦: number⟧ = 1\n other⟦: string⟧ = 'x'\n }");
    }

    #[test]
    fn runtime_colons_and_arrow_branches_remain_unchanged() {
        for source in [
            "const o = {left: 1, right: yes ? 2 : 3};",
            "const {left: renamed} = value;",
            "outer: for (;;) { break outer; }",
            "switch (value) { case 1: work(); break; default: stop(); }",
            "const choose = yes ? f(value) : other => other;",
            "const choose = yes ? (value) : other => other;",
            "const choose = yes ? first ? f(x) : g(x) : other => other;",
            "const o = {const: 1, let: 2, var: 3, class: 4};",
            "const f = (x = yes ? first : second) => ({value: x});",
        ] {
            check(source);
        }
    }

    #[test]
    fn strings_comments_and_regular_expressions_are_opaque() {
        check(r#"const label⟦: string⟧ = 'const x: T'; const pattern⟦: RegExp⟧ = /a:b[{}]/;"#);
        check("// const x: number;\nconst value⟦: number⟧ = 1; /* function f(x: T): U {} */");
        check(r#"if (ready) /const x: T/.test(text); const value⟦: number⟧ = 1;"#);
    }

    #[test]
    fn templates_preserve_nested_interpolations_and_raw_text() {
        check("const text⟦: string⟧ = `raw ${true ? 'a:b' : 'c:d'}: text`; ");
        check("const text⟦: string⟧ = `outer ${`inner ${true ? 1 : 2}`} done`; ");
        check("const text⟦: string⟧ = `${(a)/b/2}`;");
    }

    #[test]
    fn source_offsets_and_all_line_terminators_are_preserved() {
        check("const value⟦: {\r\n 名: 'é';\u{2028} ok: boolean\u{2029}}⟧ = {名: 'é', ok: true};");
        check("function identity(value⟦:\n number⟧)⟦:\n number⟧ { return value; }");
    }

    #[test]
    fn unbalanced_and_unrecognized_annotations_are_left_for_the_parser() {
        for source in [
            "const x: {value: number = 1;",
            "const x: number = 'unterminated",
            "const x: = 1;",
            "const x: ? = 1;",
            "const x: number /* unterminated",
            "const x: Array<number = 1;",
        ] {
            assert_eq!(erase(source), source);
        }
    }

    #[test]
    fn excessive_type_recursion_is_bounded_without_partial_type_removal() {
        let source = format!("const value: {}number = original;", "() => ".repeat(256));
        assert_eq!(erase(&source), source);
    }
}
