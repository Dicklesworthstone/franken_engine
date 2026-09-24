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
    check("new Date(0).toUTCString();", "Thu, 01 Jan 1970 00:00:00 GMT");
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
