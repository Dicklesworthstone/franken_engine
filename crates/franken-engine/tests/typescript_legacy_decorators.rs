//! Execute legacy decorators through the public TypeScript ingestion path.
//! The same specimens are suitable for differential execution against a
//! TypeScript compiler with experimentalDecorators and ES2020 field semantics.

fn assert_native_output(source: &str, expected: &[&str]) {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
    use frankenengine_engine::ts_normalization::prepare_source_entry_for_public_entrypoints;

    let prepared = prepare_source_entry_for_public_entrypoints(
        source,
        "legacy-decorators.ts",
        "decorator-trace",
        "decorator-decision",
        "decorator-policy",
    )
    .expect("public TypeScript ingestion");
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: prepared.source_label,
                text: prepared.prepared_source,
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("decorator output parses as JavaScript");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "legacy-decorators.ts"),
        &LoweringContext::new("decorator-trace", "decorator-decision", "decorator-policy"),
    )
    .expect("decorator program lowers")
    .ir3;
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "legacy-decorators");
        let result = core.execute(&module).expect("native decorator execution");
        let actual: Vec<&str> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn stacked_factories_preserve_multiline_classes_and_replacement_identity() {
    assert_native_output(
        r#"
        const events: string[] = [];
        function base() { events.push('base'); return class {}; }
        function mark(label: string): any {
            events.push('eval:' + label);
            return function(target: any) {
                events.push('apply:' + label);
                return class extends target {};
            };
        }
        @mark('outer')
        @mark('inner')
        class Box extends base() {
            value: number = 7;
            self() { return Box; }
            static self() { return Box; }
        }
        const box = new Box();
        console.log(events.join(','));
        console.log(box.value, box.self() === Box, Box.self() === Box);
        "#,
        &[
            "base,eval:outer,eval:inner,apply:inner,apply:outer",
            "7 true true",
        ],
    );
}

#[test]
fn instance_static_and_constructor_decorators_follow_legacy_order() {
    assert_native_output(
        r#"
        const events: string[] = [];
        function member(label: string): any {
            events.push('eval:' + label);
            return function(target: any, key: string, descriptor: any) {
                events.push('apply:' + label + ':' + key + ':' + arguments.length);
            };
        }
        function parameter(label: string): any {
            events.push('eval:' + label);
            return function(target: any, key: string, index: number) {
                events.push('param:' + label + ':' + String(key) + ':' + index);
            };
        }
        class Subject {
            @member('static') static run(@parameter('s0') x: number) { return x; }
            @member('method') run(@parameter('p0') x: number, @parameter('p1a') @parameter('p1b') y: number) { return x + y; }
            @member('field') value: number = 3;
            constructor(@parameter('ctor') public seed: number) {}
        }
        console.log(events.join(','));
        const subject = new Subject(8);
        console.log(subject.run(1, 2), Subject.run(4), subject.value, subject.seed);
        "#,
        &[
            "eval:method,eval:p0,eval:p1a,eval:p1b,param:p1b:run:1,param:p1a:run:1,param:p0:run:0,apply:method:run:3,eval:field,apply:field:value:3,eval:static,eval:s0,param:s0:run:0,apply:static:run:3,eval:ctor,param:ctor:undefined:0",
            "3 4 3 8",
        ],
    );
}

#[test]
fn method_replacement_and_accessor_parameter_descriptors_are_installed() {
    assert_native_output(
        r#"
        const events: string[] = [];
        function wrap(target: any, key: string, descriptor: any): any {
            const original = descriptor.value;
            return { configurable: true, enumerable: true, writable: true,
                     value: function(...args: number[]) { return original.apply(this, args) * 2; } };
        }
        function accessor(target: any, key: string, descriptor: any): any {
            const get = descriptor.get;
            events.push('accessor:' + key + ':' + typeof descriptor.set);
            return { configurable: true, enumerable: true,
                     get: function() { return get.call(this) * 3; }, set: descriptor.set };
        }
        function parameter(target: any, key: string, index: number) { events.push(key + ':' + index); }
        class Counter {
            current = 2;
            @wrap add(value: number) { return this.current + value; }
            get total() { return this.current; }
            @accessor set total(@parameter value: number) { this.current = value; }
        }
        const counter = new Counter();
        counter.total = 5;
        const descriptor = Object.getOwnPropertyDescriptor(Counter.prototype, 'total');
        console.log(events.join(','));
        console.log(counter.total, counter.add(4), descriptor.enumerable, typeof descriptor.set);
        "#,
        &["total:0,accessor:total:function", "15 18 true function"],
    );
}

#[test]
fn property_decorators_observe_assignment_field_initialization() {
    assert_native_output(
        r#"
        const events: string[] = [];
        function tracked(target: any, key: string) {
            Object.defineProperty(target, key, {
                configurable: true,
                get: function() { return this['_' + key]; },
                set: function(value: number) { events.push(key + '=' + value); this['_' + key] = value; }
            });
        }
        class TrackedRecord {
            @tracked value = 4;
            @tracked optional: number;
            constructor(public seed: number) {}
        }
        const record = new TrackedRecord(9);
        console.log(events.join(','));
        console.log(record.value, record.seed, Object.prototype.hasOwnProperty.call(record, 'value'), Object.prototype.hasOwnProperty.call(record, 'optional'));
        "#,
        &["value=4", "4 9 false false"],
    );
}

#[test]
fn computed_method_and_accessor_names_evaluate_once_at_class_definition() {
    assert_native_output(
        r#"
        const events: string[] = [];
        const symbol = Symbol('method');
        function key(label: string): any { events.push('key:' + label); return label === 'symbol' ? symbol : label; }
        function decorate(label: string): any {
            events.push('eval:' + label);
            return function(target: any, name: any, descriptor: any) {
                events.push('apply:' + label + ':' + String(name));
            };
        }
        class Computed {
            @decorate('symbol') [key('symbol')]() { return 2; }
            @decorate('get') get [key('value')]() { return 3; }
            @decorate('set') set [key('value')](value: number) {}
            @decorate('static') static [key('static')]() { return 4; }
        }
        const instance: any = new Computed();
        console.log(events.join(','));
        console.log(instance[symbol](), instance.value, (Computed as any).static());
        "#,
        &[
            "key:symbol,key:value,key:value,key:static,eval:symbol,apply:symbol:Symbol(method),eval:get,apply:get:value,eval:set,apply:set:value,eval:static,apply:static:static",
            "2 3 4",
        ],
    );
}

#[test]
fn namespaces_publish_replacements_after_decorators_and_keep_enum_bindings() {
    assert_native_output(
        r#"
        const events: string[] = [];
        function replace(target: any): any {
            events.push(String(Package.Service));
            return class extends target {};
        }
        function parameter(target: any, key: string, index: number) { events.push('parameter:' + index); }
        namespace Package {
            export enum Mode { Ready = 2, Busy = Ready + 1 }
            @replace export class Service {
                constructor(@parameter public mode: Mode = Mode.Ready) {}
                self() { return Service; }
            }
            export namespace Service { export const tag = 'service'; }
            export function retained() { return Service; }
        }
        namespace Package { export enum Mode { Done = Busy + 1 } }
        const service = new Package.Service();
        const retained = Package.retained();
        console.log(events.join(','));
        console.log(service.mode, service.self() === Package.Service, Package.Service.tag, Package.Mode.Done);
        (Package as any).Service = {};
        console.log(Package.retained() === retained, service.self() === retained);
        "#,
        &["parameter:0,undefined", "2 true service 4", "true true"],
    );
}

#[test]
fn decorator_helpers_preserve_strict_mode_literals_and_lexical_shadowing() {
    assert_native_output(
        r#""use strict";
        const __applyClassDecorator = 11;
        const __franken_parameter_decorator = 12;
        const __franken_decorated_class = 13;
        const __applyClassDecorator_\u0030 = 14;
        const literal = '@notADecorator class Text {}';
        const pattern = /@notADecorator/;
        const template = `@notADecorator ${literal.length}`;
        let strict = false;
        function sealed<T>(target: any): any { strict = this === undefined; return class extends target {}; }
        @sealed
        class Outer {
            self() { return { Outer }.Outer; }
            shadow(Outer: number) { return Outer; }
            local() { class Outer {} return Outer.name; }
        }
        console.log(strict, new Outer().self() === Outer, new Outer().shadow(8), new Outer().local());
        console.log(__applyClassDecorator, __franken_parameter_decorator, __franken_decorated_class, __applyClassDecorator_0);
        console.log(pattern.test(literal), template.startsWith('@notADecorator'));
        "#,
        &["true false 8 Outer", "11 12 13 14", "true true"],
    );
}

#[test]
fn decorator_failure_stops_application_and_namespace_publication() {
    assert_native_output(
        r#"
        const events: string[] = [];
        function factory(label: string): any {
            events.push('eval:' + label);
            return function(target: any) {
                events.push('apply:' + label);
                if (label === 'inner') throw new Error('decoration failed');
                return target;
            };
        }
        try {
            @factory('outer') @factory('inner') class Failed {}
        } catch (error) { events.push(error.message); }
        console.log(events.join(','));
        function keep(target: any): any { return 0; }
        @keep class Original {}
        console.log(new Original() instanceof Original);
        "#,
        &[
            "eval:outer,eval:inner,apply:inner,decoration failed",
            "true",
        ],
    );
}

#[test]
fn reflect_decorate_hook_receives_legacy_target_and_descriptor_arguments() {
    assert_native_output(
        r#"
        const events: string[] = [];
        const original = (Reflect as any).decorate;
        (Reflect as any).decorate = function(decorators: any[], target: any, key: any, descriptor: any) {
            events.push(decorators.length + ':' + String(key) + ':' + typeof descriptor);
            return key === undefined ? target : descriptor;
        };
        function ignored(...args: any[]): any { throw new Error('the Reflect hook owns application'); }
        @ignored class Hooked { @ignored method() { return 6; } }
        console.log(events.join(','));
        console.log(new Hooked().method());
        let captured: any;
        (Reflect as any).decorate = function(decorators: any[], target: any) {
            captured = target;
            return 0;
        };
        @ignored class Falsy { static self() { return Falsy; } }
        console.log(typeof Falsy, captured.self());
        (Reflect as any).decorate = original;
        "#,
        &["1:method:object,1:undefined:undefined", "6", "number 0"],
    );
}

#[test]
fn class_self_references_follow_static_initialization_and_nested_scopes() {
    assert_native_output(
        r#"
        let original: any;
        function replace(target: any): any { original = target; return class extends target {}; }
        @replace class Self {
            static before = Self;
            static called = Self.read();
            static read() { return Self; }
            nested() {
                function same(target: any) { return target; }
                @same class Local { value() { return Self; } }
                return new Local().value();
            }
        }
        console.log(Self.before === original, Self.called === original, Self.read() === Self, new Self().nested() === Self);
        "#,
        &["true true true true"],
    );
}

#[test]
fn generic_and_parenthesized_decorator_factories_keep_evaluation_order() {
    assert_native_output(
        r#"
        const events: string[] = [];
        function factory<T>(name: string): any {
            events.push('eval:' + name);
            return function(target: any) { events.push('apply:' + name); return target; };
        }
        const registry = { dec: factory<number>('registry') };
        @factory<Map<string, number>>('generic')
        @(registry['dec'])
        class Generic { value: number = 5; }
        console.log(events.join(','));
        console.log(new Generic().value);
        "#,
        &[
            "eval:registry,eval:generic,apply:registry,apply:generic",
            "5",
        ],
    );
}
