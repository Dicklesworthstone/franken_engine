//! bd-9vouw.443: Date.parse and `new Date(string)` accept V8's legacy
//! formats after the ES date-time format: month names (`Feb 29, 2024`,
//! `29 February 2024`), `M/D/Y` and `Y/M/D` numbers, `h:m[:s[.ms]]` times
//! with AM/PM, the zones UTC/GMT/Z and the US abbreviations, `GMT+0000` and
//! `+05:30` offsets, parenthesized comments, and Date.prototype.toString's
//! own output, which the specification says Date.parse should read back.
//! Only the ISO form and the toUTCString form parsed; the rest were NaN.
//! Expected lines are Node v22.2.0's with TZ=UTC (the engine's local time
//! is UTC), V8's quirks included: `Jan 1` is 2001, a two-digit year is
//! 19xx/20xx, `foo 2024` is January 1 and `29.02.2024` is NaN.

use std::process::Command;

const PROGRAM: &str = r#"const inputs = [
  'Feb 29, 2024 UTC',
  'February 29, 2024 13:05:09 GMT',
  '29 Feb 2024 13:05:09 +0100',
  'Thu Feb 29 2024 13:05:09 GMT+0000 (Coordinated Universal Time)',
  '2024/02/29 13:05:09 UTC',
  '2024-02-29 13:05:09Z',
  'Sat Jan 01 2000 00:00:00 GMT',
  'December 17, 1995 03:24:00 UTC',
  'Thu, 29 Feb 2024 13:05:09 GMT',
  '2024-02-29T13:05:09.123+05:30',
  '2024-13-01',
  'not a date',
  'Jan 1',
  '1/2/2024',
  '12/31/99',
  'Feb 29, 2024 1:05 PM',
  'Feb 29, 2024 12:00 AM',
  'Mon, 01 Jan 2024 10:00:00 -0500',
  '2024/2/29 24:00',
  '2024/2/29 25:00',
  'Wed Mar 06 2024 08:30:15 GMT-0800 (Pacific Standard Time)',
  '3 March 2024 4:05:06.789 PST',
  '2024-02-29 13:05:09.5',
  'Thursday, February 29, 2024',
  '29.02.2024',
  'Feb 2024',
  '1.5.2024 10:00',
  '2024 02 29',
  'foo 2024',
  'Feb 29 2024 13:05 GMT+05:30',
  'Feb 29 2024 13:05 EDT',
  '1 1 1',
];
for (const text of inputs) {
  console.log(JSON.stringify(text) + ' ' + Date.parse(text) + ' ' + new Date(text).getTime());
}
for (const time of [Date.UTC(2024, 1, 29, 13, 5, 9), Date.UTC(1969, 6, 20, 20, 17, 40)]) {
  const d = new Date(time);
  console.log(d.toUTCString() + ' ' + (Date.parse(d.toString()) === time) + ' ' + (Date.parse(d.toUTCString()) === time) + ' ' + (Date.parse(d.toISOString()) === time));
}
"#;

const EXPECTED: &[&str] = &[
    "\"Feb 29, 2024 UTC\" 1709164800000 1709164800000",
    "\"February 29, 2024 13:05:09 GMT\" 1709211909000 1709211909000",
    "\"29 Feb 2024 13:05:09 +0100\" 1709208309000 1709208309000",
    "\"Thu Feb 29 2024 13:05:09 GMT+0000 (Coordinated Universal Time)\" 1709211909000 1709211909000",
    "\"2024/02/29 13:05:09 UTC\" 1709211909000 1709211909000",
    "\"2024-02-29 13:05:09Z\" 1709211909000 1709211909000",
    "\"Sat Jan 01 2000 00:00:00 GMT\" 946684800000 946684800000",
    "\"December 17, 1995 03:24:00 UTC\" 819170640000 819170640000",
    "\"Thu, 29 Feb 2024 13:05:09 GMT\" 1709211909000 1709211909000",
    "\"2024-02-29T13:05:09.123+05:30\" 1709192109123 1709192109123",
    "\"2024-13-01\" NaN NaN",
    "\"not a date\" NaN NaN",
    "\"Jan 1\" 978307200000 978307200000",
    "\"1/2/2024\" 1704153600000 1704153600000",
    "\"12/31/99\" 946598400000 946598400000",
    "\"Feb 29, 2024 1:05 PM\" 1709211900000 1709211900000",
    "\"Feb 29, 2024 12:00 AM\" 1709164800000 1709164800000",
    "\"Mon, 01 Jan 2024 10:00:00 -0500\" 1704121200000 1704121200000",
    "\"2024/2/29 24:00\" 1709251200000 1709251200000",
    "\"2024/2/29 25:00\" NaN NaN",
    "\"Wed Mar 06 2024 08:30:15 GMT-0800 (Pacific Standard Time)\" 1709742615000 1709742615000",
    "\"3 March 2024 4:05:06.789 PST\" 1709467506789 1709467506789",
    "\"2024-02-29 13:05:09.5\" 1709211909500 1709211909500",
    "\"Thursday, February 29, 2024\" 1709164800000 1709164800000",
    "\"29.02.2024\" NaN NaN",
    "\"Feb 2024\" 1706745600000 1706745600000",
    "\"1.5.2024 10:00\" 1704448800000 1704448800000",
    "\"2024 02 29\" 1709164800000 1709164800000",
    "\"foo 2024\" 1704067200000 1704067200000",
    "\"Feb 29 2024 13:05 GMT+05:30\" 1709192100000 1709192100000",
    "\"Feb 29 2024 13:05 EDT\" 1709226300000 1709226300000",
    "\"1 1 1\" 978307200000 978307200000",
    "Thu, 29 Feb 2024 13:05:09 GMT true true true",
    "Sun, 20 Jul 1969 20:17:40 GMT true true true",
];

#[test]
fn date_parse_accepts_v8_legacy_formats() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("date_parse.mjs");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--goal",
            "module",
            "--extension-id",
            "date-parse-legacy-formats",
            "--out",
            report.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("frankenctl should execute");
    assert!(
        output.status.success(),
        "frankenctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("read report")).expect("json");
    let printed: Vec<&str> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .collect();
    assert_eq!(printed, EXPECTED);
}
