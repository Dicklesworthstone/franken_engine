//! bd-9vouw.462: number formatting follows ICU region by region. The engine
//! chose number symbols by language alone, so every English region got
//! US separators and US currency symbols: en-IN `1,234,567.891` (ICU
//! `12,34,567.891`), en-GB `-$1,234.50` for USD (ICU `-US$1,234.50`),
//! zh/ko `$`, ja `¥` for JPY (ICU fullwidth `￥`). Regions whose layout the
//! engine does not produce are now refused (unit tests); these lines are
//! the supported ones, as Node v22.2.0 prints them.

use std::process::Command;

const PROGRAM: &str = r#"const lines = [];
const decimalLocales = ['en-IN', 'en-GB', 'en-CA', 'en-AU', 'zh-TW', 'zh-Hant', 'ja-JP', 'ko-KR', 'de-LU', 'en-PH'];
for (const locale of decimalLocales) {
  lines.push(locale + ' ' + (1234567.891).toLocaleString(locale) + ' ' + new Intl.NumberFormat(locale).format(-98765.4321));
}
const currencyLocales = ['en-US', 'en-GB', 'en-IN', 'en-PH', 'ja-JP', 'zh-CN', 'zh-TW', 'ko-KR'];
for (const locale of currencyLocales) {
  const row = ['USD', 'EUR', 'GBP', 'JPY'].map((currency) => (-1234.5).toLocaleString(locale, { style: 'currency', currency }));
  lines.push(locale + ' ' + row.join(' '));
}
console.log(lines.join('\n'));
"#;

const EXPECTED: &[&str] = &[
    "en-IN 12,34,567.891 -98,765.432",
    "en-GB 1,234,567.891 -98,765.432",
    "en-CA 1,234,567.891 -98,765.432",
    "en-AU 1,234,567.891 -98,765.432",
    "zh-TW 1,234,567.891 -98,765.432",
    "zh-Hant 1,234,567.891 -98,765.432",
    "ja-JP 1,234,567.891 -98,765.432",
    "ko-KR 1,234,567.891 -98,765.432",
    "de-LU 1.234.567,891 -98.765,432",
    "en-PH 1,234,567.891 -98,765.432",
    "en-US -$1,234.50 -€1,234.50 -£1,234.50 -¥1,235",
    "en-GB -US$1,234.50 -€1,234.50 -£1,234.50 -JP¥1,235",
    "en-IN -$1,234.50 -€1,234.50 -£1,234.50 -JP¥1,235",
    "en-PH -$1,234.50 -€1,234.50 -£1,234.50 -¥1,235",
    "ja-JP -$1,234.50 -€1,234.50 -£1,234.50 -￥1,235",
    "zh-CN -US$1,234.50 -€1,234.50 -£1,234.50 -JP¥1,235",
    "zh-TW -US$1,234.50 -€1,234.50 -£1,234.50 -¥1,235",
    "ko-KR -US$1,234.50 -€1,234.50 -£1,234.50 -JP¥1,235",
];

#[test]
fn regional_number_and_currency_formats_match_icu() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("number_locale.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "number-locale-regions",
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
