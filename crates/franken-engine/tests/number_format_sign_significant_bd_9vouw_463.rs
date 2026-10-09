//! bd-9vouw.463: Intl.NumberFormat and toLocaleString honor `signDisplay`
//! (auto, never, always, exceptZero, negative; zero means the rounded
//! value) and `minimumSignificantDigits` / `maximumSignificantDigits`
//! (1..21; either brings in the other's default, and they replace the
//! fraction digits, in resolvedOptions too). Both were typed refusals
//! ("expected a locale and options Intl.NumberFormat supports"). Out-of-range
//! values are RangeErrors. Expected lines are Node v22.2.0's.

use std::process::Command;

const PROGRAM: &str = r#"const values = [0, -0, 1, -1, 0.0004, -0.0004, 1234.5678, -1234.5678, 123456, 0.000123456, 99.95, 999.95, NaN, Infinity, -Infinity];
const optsList = [
  { signDisplay: 'always' },
  { signDisplay: 'never' },
  { signDisplay: 'exceptZero' },
  { signDisplay: 'negative' },
  { signDisplay: 'auto' },
  { maximumSignificantDigits: 3 },
  { minimumSignificantDigits: 3 },
  { minimumSignificantDigits: 2, maximumSignificantDigits: 4 },
  { maximumSignificantDigits: 1 },
  { maximumSignificantDigits: 3, signDisplay: 'exceptZero' },
  { style: 'percent', signDisplay: 'always' },
  { style: 'currency', currency: 'USD', signDisplay: 'always' },
  { style: 'currency', currency: 'USD', maximumSignificantDigits: 2 },
  { style: 'percent', maximumSignificantDigits: 2 },
  { maximumFractionDigits: 1, maximumSignificantDigits: 5 },
];
for (const o of optsList) {
  const nf = new Intl.NumberFormat('en-US', o);
  console.log(JSON.stringify(o) + ' => ' + JSON.stringify(values.map((v) => nf.format(v))));
}
for (const o of [{ maximumSignificantDigits: 3 }, { minimumSignificantDigits: 2 }, { signDisplay: 'never' }, { maximumFractionDigits: 1, maximumSignificantDigits: 5 }]) {
  const r = new Intl.NumberFormat('en-US', o).resolvedOptions();
  console.log('resolved ' + JSON.stringify(o) + ' => ' + JSON.stringify(r));
}
for (const bad of [{ maximumSignificantDigits: 0 }, { maximumSignificantDigits: 22 }, { minimumSignificantDigits: 5, maximumSignificantDigits: 3 }, { signDisplay: 'bogus' }]) {
  try { new Intl.NumberFormat('en-US', bad); console.log('ok ' + JSON.stringify(bad)); } catch (e) { console.log(e.name + ' ' + JSON.stringify(bad)); }
}
console.log((1234.5678).toLocaleString('en-US', { maximumSignificantDigits: 2, signDisplay: 'always' }));
"#;

const EXPECTED: &[&str] = &[
    "{\"signDisplay\":\"always\"} => [\"+0\",\"-0\",\"+1\",\"-1\",\"+0\",\"-0\",\"+1,234.568\",\"-1,234.568\",\"+123,456\",\"+0\",\"+99.95\",\"+999.95\",\"+NaN\",\"+∞\",\"-∞\"]",
    "{\"signDisplay\":\"never\"} => [\"0\",\"0\",\"1\",\"1\",\"0\",\"0\",\"1,234.568\",\"1,234.568\",\"123,456\",\"0\",\"99.95\",\"999.95\",\"NaN\",\"∞\",\"∞\"]",
    "{\"signDisplay\":\"exceptZero\"} => [\"0\",\"0\",\"+1\",\"-1\",\"0\",\"0\",\"+1,234.568\",\"-1,234.568\",\"+123,456\",\"0\",\"+99.95\",\"+999.95\",\"NaN\",\"+∞\",\"-∞\"]",
    "{\"signDisplay\":\"negative\"} => [\"0\",\"0\",\"1\",\"-1\",\"0\",\"0\",\"1,234.568\",\"-1,234.568\",\"123,456\",\"0\",\"99.95\",\"999.95\",\"NaN\",\"∞\",\"-∞\"]",
    "{\"signDisplay\":\"auto\"} => [\"0\",\"-0\",\"1\",\"-1\",\"0\",\"-0\",\"1,234.568\",\"-1,234.568\",\"123,456\",\"0\",\"99.95\",\"999.95\",\"NaN\",\"∞\",\"-∞\"]",
    "{\"maximumSignificantDigits\":3} => [\"0\",\"-0\",\"1\",\"-1\",\"0.0004\",\"-0.0004\",\"1,230\",\"-1,230\",\"123,000\",\"0.000123\",\"100\",\"1,000\",\"NaN\",\"∞\",\"-∞\"]",
    "{\"minimumSignificantDigits\":3} => [\"0.00\",\"-0.00\",\"1.00\",\"-1.00\",\"0.000400\",\"-0.000400\",\"1,234.5678\",\"-1,234.5678\",\"123,456\",\"0.000123456\",\"99.95\",\"999.95\",\"NaN\",\"∞\",\"-∞\"]",
    "{\"minimumSignificantDigits\":2,\"maximumSignificantDigits\":4} => [\"0.0\",\"-0.0\",\"1.0\",\"-1.0\",\"0.00040\",\"-0.00040\",\"1,235\",\"-1,235\",\"123,500\",\"0.0001235\",\"99.95\",\"1,000\",\"NaN\",\"∞\",\"-∞\"]",
    "{\"maximumSignificantDigits\":1} => [\"0\",\"-0\",\"1\",\"-1\",\"0.0004\",\"-0.0004\",\"1,000\",\"-1,000\",\"100,000\",\"0.0001\",\"100\",\"1,000\",\"NaN\",\"∞\",\"-∞\"]",
    "{\"maximumSignificantDigits\":3,\"signDisplay\":\"exceptZero\"} => [\"0\",\"0\",\"+1\",\"-1\",\"+0.0004\",\"-0.0004\",\"+1,230\",\"-1,230\",\"+123,000\",\"+0.000123\",\"+100\",\"+1,000\",\"NaN\",\"+∞\",\"-∞\"]",
    "{\"style\":\"percent\",\"signDisplay\":\"always\"} => [\"+0%\",\"-0%\",\"+100%\",\"-100%\",\"+0%\",\"-0%\",\"+123,457%\",\"-123,457%\",\"+12,345,600%\",\"+0%\",\"+9,995%\",\"+99,995%\",\"+NaN%\",\"+∞%\",\"-∞%\"]",
    "{\"style\":\"currency\",\"currency\":\"USD\",\"signDisplay\":\"always\"} => [\"+$0.00\",\"-$0.00\",\"+$1.00\",\"-$1.00\",\"+$0.00\",\"-$0.00\",\"+$1,234.57\",\"-$1,234.57\",\"+$123,456.00\",\"+$0.00\",\"+$99.95\",\"+$999.95\",\"+$NaN\",\"+$∞\",\"-$∞\"]",
    "{\"style\":\"currency\",\"currency\":\"USD\",\"maximumSignificantDigits\":2} => [\"$0\",\"-$0\",\"$1\",\"-$1\",\"$0.0004\",\"-$0.0004\",\"$1,200\",\"-$1,200\",\"$120,000\",\"$0.00012\",\"$100\",\"$1,000\",\"$NaN\",\"$∞\",\"-$∞\"]",
    "{\"style\":\"percent\",\"maximumSignificantDigits\":2} => [\"0%\",\"-0%\",\"100%\",\"-100%\",\"0.04%\",\"-0.04%\",\"120,000%\",\"-120,000%\",\"12,000,000%\",\"0.012%\",\"10,000%\",\"100,000%\",\"NaN%\",\"∞%\",\"-∞%\"]",
    "{\"maximumFractionDigits\":1,\"maximumSignificantDigits\":5} => [\"0\",\"-0\",\"1\",\"-1\",\"0.0004\",\"-0.0004\",\"1,234.6\",\"-1,234.6\",\"123,460\",\"0.00012346\",\"99.95\",\"999.95\",\"NaN\",\"∞\",\"-∞\"]",
    "resolved {\"maximumSignificantDigits\":3} => {\"locale\":\"en-US\",\"numberingSystem\":\"latn\",\"style\":\"decimal\",\"minimumIntegerDigits\":1,\"minimumSignificantDigits\":1,\"maximumSignificantDigits\":3,\"useGrouping\":\"auto\",\"notation\":\"standard\",\"signDisplay\":\"auto\",\"roundingIncrement\":1,\"roundingMode\":\"halfExpand\",\"roundingPriority\":\"auto\",\"trailingZeroDisplay\":\"auto\"}",
    "resolved {\"minimumSignificantDigits\":2} => {\"locale\":\"en-US\",\"numberingSystem\":\"latn\",\"style\":\"decimal\",\"minimumIntegerDigits\":1,\"minimumSignificantDigits\":2,\"maximumSignificantDigits\":21,\"useGrouping\":\"auto\",\"notation\":\"standard\",\"signDisplay\":\"auto\",\"roundingIncrement\":1,\"roundingMode\":\"halfExpand\",\"roundingPriority\":\"auto\",\"trailingZeroDisplay\":\"auto\"}",
    "resolved {\"signDisplay\":\"never\"} => {\"locale\":\"en-US\",\"numberingSystem\":\"latn\",\"style\":\"decimal\",\"minimumIntegerDigits\":1,\"minimumFractionDigits\":0,\"maximumFractionDigits\":3,\"useGrouping\":\"auto\",\"notation\":\"standard\",\"signDisplay\":\"never\",\"roundingIncrement\":1,\"roundingMode\":\"halfExpand\",\"roundingPriority\":\"auto\",\"trailingZeroDisplay\":\"auto\"}",
    "resolved {\"maximumFractionDigits\":1,\"maximumSignificantDigits\":5} => {\"locale\":\"en-US\",\"numberingSystem\":\"latn\",\"style\":\"decimal\",\"minimumIntegerDigits\":1,\"minimumSignificantDigits\":1,\"maximumSignificantDigits\":5,\"useGrouping\":\"auto\",\"notation\":\"standard\",\"signDisplay\":\"auto\",\"roundingIncrement\":1,\"roundingMode\":\"halfExpand\",\"roundingPriority\":\"auto\",\"trailingZeroDisplay\":\"auto\"}",
    "RangeError {\"maximumSignificantDigits\":0}",
    "RangeError {\"maximumSignificantDigits\":22}",
    "RangeError {\"minimumSignificantDigits\":5,\"maximumSignificantDigits\":3}",
    "RangeError {\"signDisplay\":\"bogus\"}",
    "+1,200",
];

#[test]
fn sign_display_and_significant_digits_match_node() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("number_format.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "number-format-sign-significant",
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
        .flat_map(|message| message.split('\n'))
        .collect();
    assert_eq!(printed, EXPECTED);
}
