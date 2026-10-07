//! bd-9vouw.53: Date.prototype getters, setters, toISOString, toJSON and
//! toUTCString (ES2020 20.4.4).
//!
//! Before this, a Date exposed only getTime/toString/toLocale*, and
//! `JSON.stringify({d: new Date(0)})` leaked `{"__type":"Date",...}`.
//!
//! FrankenEngine is hermetic: local time is UTC, so each local accessor
//! equals its UTC twin and getTimezoneOffset() is 0. The expected strings are
//! what Node v22.2.0 prints for the same programs under `TZ=UTC`.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node_utc: &str) {
    assert_eq!(
        eval_to_string(source),
        node_utc,
        "`{source}` must match Node v22.2.0 (TZ=UTC)"
    );
}

#[test]
fn component_getters() {
    check(
        "var d = new Date(0); [d.getFullYear(), d.getMonth(), d.getDate(), d.getDay(), \
         d.getHours(), d.getTimezoneOffset(), d.valueOf()].join();",
        "1970,0,1,4,0,0,0",
    );
    check(
        "var d = new Date(1582977600000); [d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), \
         d.getUTCDay(), d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds(), \
         d.getUTCMilliseconds()].join();",
        "2020,1,29,6,12,0,0,0",
    );
}

#[test]
fn iso_json_and_utc_strings() {
    check(
        "new Date(1582977600123).toISOString() + '|' + new Date(-62198755200000).toISOString() + \
         '|' + new Date(253402300800000).toISOString();",
        "2020-02-29T12:00:00.123Z|-000001-01-01T00:00:00.000Z|+010000-01-01T00:00:00.000Z",
    );
    check(
        "JSON.stringify({d: new Date(0)}) + '|' + new Date(0).toJSON();",
        "{\"d\":\"1970-01-01T00:00:00.000Z\"}|1970-01-01T00:00:00.000Z",
    );
    check(
        "new Date(0).toUTCString();",
        "Thu, 01 Jan 1970 00:00:00 GMT",
    );
    check(
        "var r; try { new Date(NaN).toISOString(); r = 'no'; } catch (e) { r = e instanceof RangeError; } \
         r + ':' + new Date(NaN).toJSON() + ':' + isNaN(new Date(NaN).getFullYear());",
        "true:null:true",
    );
}

#[test]
fn setters_normalize_through_make_day() {
    check(
        "var d = new Date(0); d.setUTCFullYear(2021, 1, 28); d.setUTCHours(13, 5); \
         d.toISOString() + '|' + d.setUTCDate(31) + '|' + d.toISOString();",
        "2021-02-28T13:05:00.000Z|1614776700000|2021-03-03T13:05:00.000Z",
    );
    check(
        "var d = new Date(0); d.setTime(86400000); d.getDate() + ':' + d.setMonth(13) + ':' + \
         d.toISOString();",
        "2:34300800000:1971-02-02T00:00:00.000Z",
    );
}

/// Date.prototype.toString / toDateString / toTimeString (20.4.4.41) and the
/// string conversions of a Date, which go through toString. Without them
/// `d.toString()` reached Object.prototype.toString ("[object Date]") while
/// `d + ''` rendered "[object Object]", so `d == d.toString()` was false.
/// A setter ToNumbers each argument it takes exactly once, in order, after
/// reading the time value and even when that is NaN: an object's valueOf
/// runs (it was skipped, so `setHours(0, { valueOf })` gave NaN), a Symbol
/// throws, and an argument past the setter's own is not read (Test262
/// Date/prototype/setHours/arg-min-to-number, setDate/arg-coercion-order,
/// setUTCFullYear/date-value-read-before-tonumber-when-date-is-valid).
#[test]
fn setter_arguments_are_to_numbered_once_in_order() {
    check(
        "var d = new Date(2016, 6), calls = 0; \
         var r1 = d.setHours(0, { valueOf() { calls++; return 2; } }); \
         var nd = new Date(NaN), n1 = 0; var r2 = nd.setDate({ valueOf() { n1++; return 0; } }); \
         var dt = new Date(0), n2 = 0; \
         var r3 = dt.setUTCFullYear({ valueOf() { n2++; dt.setTime(NaN); return 1; } }); \
         var sym; try { new Date(0).setMinutes(Symbol()); sym = 'none'; } \
         catch (e) { sym = e.constructor.name; } \
         var n3 = 0; new Date(0).setDate(1, { valueOf() { n3++; return 0; } }); \
         var log = []; new Date(0).setHours({ valueOf() { log.push('h'); return 1; } }, \
         { valueOf() { log.push('m'); return 2; } }); \
         [calls, r1 === new Date(2016, 6, 1, 0, 2).getTime(), n1, r2, nd.getTime(), n2, \
         r3 === dt.getTime(), dt.getUTCFullYear(), sym, n3, log.join('')].join();",
        "1,true,1,NaN,NaN,1,true,1,TypeError,0,hm",
    );
}

#[test]
fn to_string_forms_and_string_conversion() {
    check(
        "var d = new Date(1582977600123); var e = new Date(-62198755200000); \
         [d.toString(), d.toDateString(), d.toTimeString(), e.toString(), \
         new Date(NaN).toString(), new Date(NaN).toTimeString()].join('|');",
        "Sat Feb 29 2020 12:00:00 GMT+0000 (Coordinated Universal Time)|Sat Feb 29 2020|\
         12:00:00 GMT+0000 (Coordinated Universal Time)|\
         Fri Jan 01 -0001 00:00:00 GMT+0000 (Coordinated Universal Time)|Invalid Date|Invalid Date",
    );
    check(
        "var d = new Date(1582977600123); [d == d.toString(), String(d) === d.toString(), \
         `${d}` === d.toString(), d + 1, d - 0, d == 1582977600123, \
         Object.prototype.toString.call(d), Date.prototype.toString.length].join('|');",
        "true|true|true|Sat Feb 29 2020 12:00:00 GMT+0000 (Coordinated Universal Time)1|\
         1582977600123|false|[object Date]|0",
    );
}

/// `toLocaleString`, `toLocaleDateString` and `toLocaleTimeString` format
/// the UTC fields (local time is UTC) in the numeric layouts of en-US,
/// en-GB, de, fr and ja, as Node does with TZ=UTC. They were undefined.
#[test]
fn locale_strings() {
    check(
        "var d = new Date(Date.UTC(2020, 11, 25, 15, 30, 5)); \
         [d.toLocaleString(), d.toLocaleDateString(), d.toLocaleTimeString(), \
         d.toLocaleString('en-GB'), d.toLocaleDateString('de-DE'), d.toLocaleString('ja-JP'), \
         d.toLocaleString(['fr-FR']), d.toLocaleString('en-US', { timeZone: 'UTC' }), \
         new Date(NaN).toLocaleString(), typeof d.toLocaleDateString, \
         d.toLocaleDateString.length, d.toLocaleString.name].join(' | ');",
        "12/25/2020, 3:30:05 PM | 12/25/2020 | 3:30:05 PM | 25/12/2020, 15:30:05 | 25.12.2020 | \
         2020/12/25 15:30:05 | 25/12/2020 15:30:05 | 12/25/2020, 3:30:05 PM | Invalid Date | \
         function | 0 | toLocaleString",
    );
}

/// Another time zone or an unknown locale are a TypeError naming what is
/// not formatted: the engine's typed refusal, where Node would print a
/// string. Component options (`{ month: 'long' }`) format as an
/// Intl.DateTimeFormat does (Node's value); they were refused before Intl.
#[test]
fn locale_strings_refuse_what_they_do_not_format() {
    assert_eq!(
        eval_to_string(
            "var d = new Date(0); function attempt(f) { try { f(); return 'ok'; } \
             catch (e) { return e.constructor.name; } } \
             [d.toLocaleDateString('en-US', { month: 'long' }), \
             attempt(() => d.toLocaleString('en-US', { timeZone: 'America/New_York' })), \
             attempt(() => d.toLocaleString('es-ES'))].join();"
        ),
        "January,TypeError,TypeError"
    );
}

/// bd-9vouw.240: Annex B B.2.4 getYear (the year minus 1900), setYear
/// (MakeFullYear: 0..=99 is 1900 plus it, a NaN year makes the date NaN, a
/// NaN date starts from +0; the argument's valueOf runs) and toGMTString,
/// which is toUTCString itself. Node v22.2.0 (TZ=UTC) gives this value; Bun
/// 1.4.2 agrees.
#[test]
fn annex_b_get_year_set_year_and_to_gmt_string_bd_9vouw_240() {
    check(
        "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\nvar d = new Date(Date.UTC(2024, 2, 15, 10, 30));\nvar n = new Date(NaN);\nvar out = [d.getYear(), new Date(Date.UTC(1899, 0, 1)).getYear(), n.getYear(), Date.prototype.getYear.length, Date.prototype.setYear.length,\n  d.setYear(99), d.toISOString(), d.setYear(2001), d.toISOString(), d.setYear(-5.7), d.getUTCFullYear(), d.setYear(NaN), String(d.getTime()),\n  n.setYear(50), new Date(n.getTime()).toISOString(),\n  Date.prototype.toGMTString === Date.prototype.toUTCString, Date.prototype.toGMTString.name, attempt(() => Date.prototype.getYear.call({})),\n  attempt(() => new Date(0).setYear({ valueOf() { return 3; } }))];\nout.join(' ');\n",
        "124 -1 NaN 0 1 921493800000 1999-03-15T10:30:00.000Z 984652200000 2001-03-15T10:30:00.000Z -62318640600000 -5 NaN NaN -631152000000 1950-01-01T00:00:00.000Z true toUTCString TypeError -2114380800000",
    );
}
