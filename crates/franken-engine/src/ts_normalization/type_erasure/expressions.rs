//! Expression, declaration, and template erasure regressions through the shared core facade.

#[cfg(test)]
mod tests {
    use super::super::tests::check;

    #[test]
    fn ambient_variables_never_create_runtime_bindings() {
        check("⟦declare const host: {read(path: string): string};⟧ host.read('a');");
        check("⟦declare let count: number, name: string;⟧ const local = 3;");
        check("⟦declare var legacy;⟧ use(legacy);");
        check("⟦declare const code = -42, label = 'ready', active = true;⟧ use(code);");
        check("⟦declare var 名称:\n {名: 'é'}⟧\nuse(名称);");
    }

    /// bd-9vouw.435: ambient blocks declare types only.
    #[test]
    fn ambient_global_module_and_namespace_blocks_are_erased() {
        check("⟦declare global { interface P { x(): void; } }⟧ const a = 1;");
        check("⟦declare module \"pkg\" { export const v: number; }⟧ run();");
        check("⟦declare namespace NS.Inner { const v: number; }⟧ run();");
        check("const declare = { global: 1 }; use(declare.global);");
    }

    #[test]
    fn ambient_lists_with_effectful_initializers_are_not_partially_deleted() {
        check("declare const bad⟦: number⟧ = effect();");
        check("declare let bad⟦: number⟧ = 1;");
        check("declare const good⟦: number⟧, bad = effect();");
        check("declare const {value = effect()}⟦: Shape⟧;");
        check("const value = 'declare const host: Host'; object.declare(value);");
        check("const declare = 3; const object = {declare};");
    }

    #[test]
    fn exported_ambient_bindings_preserve_an_empty_module_and_byte_positions() {
        let declaration = "export declare const host: Host;";
        let source = format!("{declaration}\nconst value = 3;");
        let expected = format!(
            "export{{}};{}\nconst value = 3;",
            " ".repeat(declaration.len() - 9)
        );
        assert_eq!(super::super::erase(&source), expected);
        assert_eq!(expected.len(), source.len());
        assert_eq!(super::super::erase(&expected), expected);
        let source = "export\ndeclare const 名称:\n 'é';";
        let expected = format!(
            "export\n{{}};{}\n{}",
            " ".repeat("declare const 名称:".len() - 3),
            " ".repeat(" 'é';".len())
        );
        assert_eq!(super::super::erase(source), expected);
        assert_eq!(expected.len(), source.len());
    }

    #[test]
    fn only_one_empty_export_is_emitted_for_multiple_erased_declarations() {
        let first = "export declare const value: number;";
        let second = "export declare function external(): void;";
        let source = format!("{first}\n{second}");
        assert_eq!(
            super::super::erase(&source),
            format!(
                "export{{}};{}\n{}",
                " ".repeat(first.len() - 9),
                " ".repeat(second.len())
            )
        );
    }

    #[test]
    fn invalid_nested_exports_are_not_hidden_by_declaration_erasure() {
        check("function outer() { export declare function invalid(): void; }");
        check(
            "const text = `${(() => { export declare function invalid(): void; return 1; })()}`;",
        );
        check("function outer() { export declare const invalid⟦: number⟧; }");
        check("class Object { ⟦export(value: number): number;⟧ export(value) { return value; } }");
    }

    #[test]
    fn declare_is_a_modifier_only_without_a_line_terminator() {
        // On a new line `declare` is an identifier expression, not a modifier.
        // Deleting it could hide a ReferenceError or a host getter's effects.
        check("declare\nconst value⟦: number⟧ = 1;");
        check("declare /*\n*/ const value⟦: number⟧ = 1;");
        check(
            "declare\n⟦function run(value: number): number;⟧ function run(value) { return value; }",
        );
        check("⟦declare /* inline */ const host: Host;⟧");
        check("⟦declare /* inline */ function run(value: number): number;⟧");
    }

    #[test]
    fn free_function_overloads_leave_one_runtime_implementation() {
        check(
            "⟦function choose(value: number): number;⟧ ⟦function choose(value: string): string;⟧ function choose(value⟦: unknown⟧) { return value; }",
        );
        check(
            "⟦function map<T extends {value: number}>(value: T): {result: T};⟧ function map(value) { return {result: value}; }",
        );
        check(
            "⟦function run(...values: [number, string]): void;⟧ function run(...values) { effect(values); }",
        );
    }

    #[test]
    fn exported_and_ambient_functions_have_no_runtime_binding() {
        check("⟦declare function external(value: number): string;⟧ use(external);");
        check(
            "⟦async function load(value: number): Promise<number>;⟧ async function load(value) { return value; }",
        );
        let declaration = "export default function choose(value: number): number;";
        let implementation = " export default function choose(value) { return value; }";
        assert_eq!(
            super::super::erase(&format!("{declaration}{implementation}")),
            format!(
                "export{{}};{}{implementation}",
                " ".repeat(declaration.len() - 9)
            )
        );
        let declaration = "export declare function external<T>(value: T): T;";
        assert_eq!(
            super::super::erase(declaration),
            format!("export{{}};{}", " ".repeat(declaration.len() - 9))
        );
    }

    #[test]
    fn overload_boundaries_respect_newlines_and_implementation_bodies() {
        check(
            "⟦function choose(value: number): number⟧\nfunction choose(value⟦: unknown⟧)\n{ return value; }",
        );
        check("⟦function done(value?: number)⟧\nconst value = 1;");
        check("⟦declare function done(): void⟧");
        check(
            "function outer()⟦: number⟧ { ⟦function nested(value: number): number;⟧ function nested(value) { return value; } return nested(1); }",
        );
        check(
            "first()\n⟦function choose(value: number): number;⟧ function choose(value) { return value; }",
        );
    }

    #[test]
    fn overloads_preserve_receiver_types_destructuring_and_literal_bytes() {
        check(
            "⟦function run(this: {value: number}, {offset}: {offset: number}): number;⟧ function run(offset) { return this.value + offset; }",
        );
        check(
            "⟦function 名称(値: 'é'):\n {名: string};⟧ const text = 'function f(x: T): U;'; // function f(x: T): U;",
        );
        check("const pattern = /function f(x: T): U;/; const text = `function f(x: T): U;`;");
    }

    #[test]
    fn overloads_inside_template_callbacks_use_the_same_pass() {
        check(
            "const text = `${(() => { ⟦function f(x: number): number;⟧ function f(x⟦: number⟧) { return x; } return f(1); })()}`;",
        );
    }

    #[test]
    fn incomplete_expressions_and_effectful_signatures_are_not_erased() {
        check("const value = function named(x: number): number;");
        check("(function named(x: number): number); object.function(value);");
        check("function broken(x = effect()): number;");
        check("function broken({x = effect()}: {x: number}): number;");
        check("function* broken(x: number): Iterator<number>;");
        check("declare function broken() { effect(); }");
        check("const value = { function broken(x: number): number; };");
    }

    #[test]
    fn instantiation_expressions_preserve_callable_and_constructor_values() {
        check("const specialized = factory⟦<Result>⟧; return factory⟦<number>⟧;");
        check("const constructors = [Map⟦<string, number>⟧, Set⟦<number>⟧];");
        check("const value = new Box⟦<{name: string}>⟧; new ns.Box⟦<number>⟧;");
        check("const value = (factory⟦<number>⟧) === factory;");
        check("const value = factory⟦<number>⟧ ⟦as Callable⟧;");
    }

    #[test]
    fn instantiation_expressions_respect_runtime_operator_precedence() {
        check("const value = yes ? first⟦<Type>⟧ : second⟦<Other>⟧;");
        check("const value = factory⟦<Type>⟧ === original;");
        check("const value = factory⟦<Type>⟧ && fallback;");
        check("const value = factory⟦<Type>⟧ || fallback;");
        check("const value = factory⟦<Type>⟧ ?? fallback;");
        check("const value = factory⟦<Type>⟧ / 2;");
        check("const value = factory⟦<Type>⟧\nnext();");
    }

    #[test]
    fn instantiation_lookahead_cannot_consume_relational_or_prefix_operators() {
        check("a < b >= c; a < b>=c; a < b >> c; a < b >>> c;");
        check("a < b > +c; a < b > -c; a < b > ++c; a < b > --c;");
        check("a < b > !c; a < b > ~c; a < b > [c]; a ⟦<b>⟧ ({c});");
        check("a < b >\n+c; a < b >\n-c; a < b > c;");
        check("const value = factory<Type>.property;");
    }

    #[test]
    fn generic_calls_erase_nested_and_multiple_type_arguments() {
        check("load⟦<Result>⟧(input); object.load⟦<Map<string, {x: number}[]>, number>⟧(input);");
        check("choose⟦<T extends U ? {yes: T} : {no: U}>⟧(input);");
        check("invoke⟦<(x: number) => string, readonly [number, string],>⟧(callback);");
        check("new Store⟦<{name: string}>⟧(input); new ns.Store⟦<number>⟧();");
    }

    #[test]
    fn generic_calls_keep_receivers_and_optional_call_punctuation() {
        check("object[key]⟦<number>⟧(3); (object.method)⟦<number>⟧(3);");
        check("object?.method⟦<number>⟧(3); object.method?.⟦<number>⟧(3);");
        check("object.method⟦<number>⟧?.(3); object⟦!⟧.method⟦!⟧⟦<number>⟧(3);");
        check("object.if⟦<number>⟧(3); (factory())⟦<number>⟧(3);");
    }

    #[test]
    fn generic_tags_and_interpolations_share_the_expression_pass() {
        check("object.tag⟦<{name: string}>⟧`raw\\n${load⟦<number>⟧(3)} tail`;");
        check("const text = `outer ${`inner ${load⟦<number>⟧(3)}`}`;");
        check("const text = `${load⟦<number>⟧(3) / 2}: raw / slash`;");
    }

    #[test]
    fn generic_call_lookahead_preserves_comparisons_and_shift_operators() {
        check("a < b > c; a < b > +c; a < b > -c; a < b + c > (d);");
        check("a < b >> (c); a < b >>> (c); a < b >= (c); a << b > (c);");
        check("if (ready) <Type>(value); while (ready) <Type>(value);");
        check("call ⟦<Type>⟧ (value); call\n⟦<Type>⟧(value);");
    }

    #[test]
    fn generic_call_lookahead_retains_incomplete_types_and_literal_text() {
        check("call<Type(value); call<Type, , Other>(value); call<>(value);");
        check("const text = 'call<Type>(value)'; const pattern = /call<Type>/;");
        check("const text = `call<Type>(value)`; // call<Type>(value)");
        check("call⟦</*é*/ {名: 'é'},\nreadonly number[]>⟧(value);");
    }

    #[test]
    fn hostcall_type_arguments_survive_until_capability_extraction() {
        // normalize_typescript_to_es2020 extracts capability intents after
        // this pass, then removes the reserved hostcall DSL's type arguments.
        check("const result = hostcall<\"fs.read\">();");
        check("hostcall<\"declassify.audit\">(value); load⟦<Result>⟧(value);");
    }

    #[test]
    fn templates_erase_only_interpolation_code() {
        check("const text = `raw as number: ${value ⟦as number⟧}: done`;");
        check("const text = `outer ${`inner ${object⟦!⟧.value}`} end`;");
        check(
            "const text = `\\${notCode as Type}: ${(object ⟦satisfies {value: number}⟧).value}`;",
        );
    }

    #[test]
    fn template_callbacks_use_the_same_binding_and_signature_pass() {
        check("const text = `${((value⟦: number⟧)⟦: number⟧ => value + 1)(3)}`;");
        check(
            "const text = `${(() => { const value⟦: {x: number}⟧ = {x: 3}; return value.x; })()}`;",
        );
        check("const text = `${({run(value⟦: number⟧)⟦: number⟧ { return value; }}).run(3)}`;");
    }

    #[test]
    fn interpolation_lexer_distinguishes_division_from_regular_expressions() {
        check("const text = `${(value ⟦as number⟧) / 2}: slash / raw`;");
        check("const text = `${object.if(value ⟦as number⟧) / 2}: slash / raw`;");
        check(
            "const text = `${(() => { if (ready) /}/.test('}'); return value ⟦as number⟧; })()}`;",
        );
        check("const text = `${/a}b/.test('a}b') ? value⟦!⟧ : 0}`;");
    }

    #[test]
    fn template_type_literals_and_raw_unicode_keep_their_own_spaces() {
        check("const text⟦: `prefix${number}`⟧ = `prefix${value ⟦as number⟧}`;");
        check("const text = `é\n  ${value ⟦as {名: 'é'}⟧}\n\n    tail`;");
        check("tag`raw\\n${value⟦!⟧}\\${untouched: text}`;");
    }

    #[test]
    fn nested_template_transforms_have_a_depth_bound() {
        let mut source = "value as number".to_owned();
        // Keep the original 129-level input, one beyond the 128-level budget.
        for _ in 0..129 {
            source = format!("`nested ${{{source}}}`");
        }
        assert_eq!(super::super::erase(&source), source);
    }

    #[test]
    fn assertions_erase_whole_nested_types_without_evaluating_them() {
        check("const value = original ⟦as Record<string, {value: number}[]>⟧;");
        check("const value = original ⟦as unknown⟧ ⟦as {value: number}⟧;");
        check("const value = ({port: 80}) ⟦satisfies {port: number}⟧;");
        check("const value = original ⟦as T extends U ? {yes: T} : {no: U}⟧;");
    }

    #[test]
    fn asserted_calls_and_assignment_targets_keep_reference_identity() {
        check("(object.method ⟦as (value: number) => number⟧)(3);");
        check("object⟦!⟧.field = value; array[index]⟦!⟧ += 1;");
        check("const value = (get()⟦!⟧ ⟦as {value: number}⟧).value;");
    }

    #[test]
    fn non_null_is_postfix_not_a_boolean_negation_or_inequality() {
        check("const a = value⟦!⟧; const b = value⟦!⟧⟦!⟧.field;");
        check("!value; !!value; value != other; value !== other;");
        check("if (value) !(other); while (value) !other;");
        check("value\n!other; value\n!(other);");
        check("object.if(value)⟦!⟧; object.return⟦!⟧.value;");
    }

    #[test]
    fn module_aliases_and_runtime_property_names_are_preserved() {
        check("import {value as Type, satisfies as other} from 'pkg';");
        check("import primary, {value as Type} from 'pkg';");
        check("import * as namespace from 'pkg'; export * as namespace from 'pkg';");
        check("export {value as Type, satisfies as other};");
        check("export default (value ⟦as number⟧); import(value ⟦as string⟧);");
        check("const as = 1; const satisfies = 2; const o = {as, satisfies};");
        check("function as(value) { return value; } object.as(value);");
        check("const o = {as: 1, satisfies: 2, get as() { return 1; }};");
    }

    #[test]
    fn assertion_boundaries_preserve_operators_and_conditional_branches() {
        check("const value = yes ? first ⟦as number⟧ : second ⟦as number⟧;");
        check("const value = (left ⟦as number⟧) + (right ⟦as number⟧);");
        check("const value = first ⟦as number⟧ < second;");
        check("const value = first ⟦as (number)⟧ < second > third;");
        check("const value = first ⟦as number[]⟧ < second > third;");
        check("const value = first ⟦as number⟧ === second;");
        check("const value = first ⟦as number⟧\nconst next = 2;");
    }

    #[test]
    fn asserted_comparisons_keep_their_javascript_parse() {
        // The output language is JavaScript, not TypeScript. Reinterpreting
        // `first < second > (third)` as TS makes it a generic call, whereas
        // the original assertion forces a runtime comparison. TypeScript
        // itself has this distinction, so idempotence under a *second TS
        // parse* is not a valid invariant for this case. Keep exact bytes
        // and verify both parses explicitly, rather than dropping coverage.
        for assertion in ["as number", "satisfies number"] {
            let source = format!("const value = first {assertion} < second > (third);");
            let expected = format!(
                "const value = first {} < second > (third);",
                " ".repeat(assertion.len())
            );
            assert_eq!(super::super::erase(&source), expected);
            assert_eq!(
                super::super::erase(&expected),
                format!(
                    "const value = first {} {} (third);",
                    " ".repeat(assertion.len()),
                    " ".repeat("< second >".len())
                )
            );
        }
    }

    #[test]
    fn literal_text_and_newline_separated_names_are_not_assertions() {
        check("const text = 'value as number'; const r = /value! as number/;");
        check("const text = `value satisfies Shape`;");
        check("value\nas(Type); value\nsatisfies(Type);");
        check("const value = source ⟦as /* note */ {\n名: 'é'}⟧;");
    }
}
