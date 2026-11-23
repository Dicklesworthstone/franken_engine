//! Observable CanonicalizeLocaleList behavior shared by Intl consumers.
//! Expected results are checked against the same JavaScript in Node; the
//! engine tests execute real source through HybridRouter without test doubles.

use frankenengine_engine::HybridRouter;

fn output(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("locale-list program failed: {error}"))
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn locale_lists_visit_sparse_inherited_and_live_properties_in_order() {
    let source = r#"
        const log = [];
        const inherited = { 1: 'de-de' };
        const locales = Object.create(inherited);
        Object.defineProperty(locales, 'length', {
            get() { log.push('length'); return { valueOf() { log.push('size'); return 4.9; } }; }
        });
        Object.defineProperty(locales, '0', {
            get() {
                log.push('0');
                locales[3] = 'EN-us';
                return { toString() { log.push('tag'); return 'en-US'; } };
            }
        });
        console.log(Intl.getCanonicalLocales(locales).join('|'), log.join('|'));
        console.log(Intl.getCanonicalLocales([, 'ja', , 'JA']).join('|'));
    "#;
    assert_eq!(output(source), "en-US|de-DE length|size|0|tag\nja");
}

#[test]
fn locale_lists_preserve_proxy_has_get_and_conversion_order() {
    let source = r#"
        const log = [];
        const item = { [Symbol.toPrimitive](hint) { log.push('convert:' + hint); return 'fr-FR'; } };
        const locales = new Proxy({ 1: item, length: 3 }, {
            get(target, key, receiver) { log.push('get:' + key); return Reflect.get(target, key, receiver); },
            has(target, key) { log.push('has:' + key); return Reflect.has(target, key); }
        });
        console.log(Intl.getCanonicalLocales(locales).join('|'));
        console.log(log.join('|'));
    "#;
    assert_eq!(
        output(source),
        "fr-FR\nget:length|has:0|has:1|get:1|convert:string|has:2"
    );
}

#[test]
fn locale_lists_box_inputs_but_reject_non_string_primitive_elements() {
    let source = r#"
        const out = [];
        for (const value of [undefined, true, 12, 12n, Symbol('locale')]) {
            out.push(Intl.getCanonicalLocales(value).length);
        }
        for (const value of [null, [undefined], [null], [true], [12], [12n], [Symbol('locale')]]) {
            try { Intl.getCanonicalLocales(value); out.push('missed'); }
            catch (error) { out.push(error.constructor.name); }
        }
        function locales() {}
        Object.defineProperty(locales, 'length', { value: 1 });
        Object.defineProperty(locales, '0', { get() { return this === locales ? 'ja' : 'de'; } });
        out.push(Intl.getCanonicalLocales(locales).join('|'));
        console.log(out.join('|'));
    "#;
    assert_eq!(
        output(source),
        "0|0|0|0|0|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|ja"
    );
}

#[test]
fn locale_lists_stop_at_the_first_abrupt_completion() {
    let source = r#"
        const marker = {};
        const log = [];
        const locales = {
            get length() { log.push('length'); return 3; },
            get 0() { log.push('0'); return 'en'; },
            get 1() { log.push('1'); return { toString() { log.push('throw'); throw marker; } }; },
            get 2() { log.push('unreachable'); return 'de'; }
        };
        try { Intl.getCanonicalLocales(locales); } catch (error) { console.log(error === marker); }
        console.log(log.join('|'));
        const invalid = { length: 2, 0: 'not_a_locale', get 1() { throw marker; } };
        try { Intl.getCanonicalLocales(invalid); } catch (error) { console.log(error.constructor.name); }
    "#;
    assert_eq!(output(source), "true\nlength|0|1|throw\nRangeError");
}

#[test]
fn intl_constructors_and_locale_methods_share_observable_locale_lists() {
    let source = r#"
        let count = 0;
        const locales = { length: 1, get 0() { count++; return { toString() { return 'de-DE'; } }; } };
        console.log(new Intl.NumberFormat(locales).format(1234.5));
        console.log((1234.5).toLocaleString(locales));
        console.log(new Date(0).toLocaleDateString(locales, { timeZone: 'UTC' }));
        console.log(new Intl.DateTimeFormat(locales).resolvedOptions().locale);
        console.log(count);
    "#;
    assert_eq!(output(source), "1.234,5\n1.234,5\n1.1.1970\nde-DE\n4");
}

#[test]
fn locale_conversion_precedes_option_validation_and_keeps_length_fixed() {
    let source = r#"
        const marker = {};
        const broken = { get length() { throw marker; } };
        const out = [];
        for (const run of [
            () => new Intl.NumberFormat(broken, null),
            () => new Intl.DateTimeFormat(broken, null),
            () => (1).toLocaleString(broken, null),
            () => new Date(0).toLocaleDateString(broken, null)
        ]) {
            try { run(); out.push(false); } catch (error) { out.push(error === marker); }
        }
        const locales = { length: 2, get 0() { this.length = 0; this[1] = 'de'; return 'en'; } };
        out.push(Intl.getCanonicalLocales(locales).join(','));
        console.log(out.join('|'));
    "#;
    assert_eq!(output(source), "true|true|true|true|en,de");
}

#[test]
fn enormous_sparse_locale_lists_consume_the_instruction_budget() {
    let error = HybridRouter::default()
        .eval_with_instruction_budget("Intl.getCanonicalLocales({ length: Infinity });", 1_000)
        .expect_err("a native sparse traversal must not bypass execution limits")
        .to_string();
    assert!(
        error.to_ascii_lowercase().contains("budget"),
        "expected the resource refusal, got {error}"
    );
}
