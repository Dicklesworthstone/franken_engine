//! bd-9vouw.440: util.inspect.colors (Node's SGR code pairs and
//! their non-enumerable aliases), util.styleText(format, text),
//! util.stripVTControlCharacters(str) and util.toUSVString(input). Each
//! was missing: colors undefined, the functions "expected function, got
//! undefined". Expected lines are Node v22.2.0's, including its
//! ERR_INVALID_ARG_TYPE / ERR_INVALID_ARG_VALUE texts.

use std::process::Command;

const PROGRAM: &str = r#"import util from 'node:util';
const out = [];
const t = (name, f) => {
  try { out.push(name + ' = ' + JSON.stringify(f())); } catch (e) { out.push(name + ' ! ' + e.name + ' ' + (e.code || '') + ' ' + e.message); }
};
t('colors keys', () => Object.keys(util.inspect.colors).join());
t('colors red', () => util.inspect.colors.red);
t('colors grey alias', () => util.inspect.colors.grey);
t('colors proto', () => Object.getPrototypeOf(util.inspect.colors));
t('colors names', () => Object.getOwnPropertyNames(util.inspect.colors).length);
t('styleText red', () => util.styleText('red', 'x'));
t('styleText array', () => util.styleText(['bold', 'underline'], 'y'));
t('styleText alias', () => util.styleText('grey', 'g'));
t('styleText empty', () => util.styleText([], 'e'));
t('styleText bad format', () => util.styleText('nope', 'x'));
t('styleText bad in array', () => util.styleText(['red', 5], 'x'));
t('styleText bad text', () => util.styleText('red', 5));
t('strip', () => util.stripVTControlCharacters('\u001b[1m\u001b[31mhi\u001b[39m\u001b[22m \u001b]8;;http://x\u0007link\u001b]8;;\u0007'));
t('strip bad', () => util.stripVTControlCharacters(5));
t('toUSVString', () => [util.toUSVString('a\ud800b').length, util.toUSVString(12)]);
console.log(out.join('\n'));
"#;

const EXPECTED: &[&str] = &[
    "colors keys = \"reset,bold,dim,italic,underline,blink,inverse,hidden,strikethrough,doubleunderline,black,red,green,yellow,blue,magenta,cyan,white,bgBlack,bgRed,bgGreen,bgYellow,bgBlue,bgMagenta,bgCyan,bgWhite,framed,overlined,gray,redBright,greenBright,yellowBright,blueBright,magentaBright,cyanBright,whiteBright,bgGray,bgRedBright,bgGreenBright,bgYellowBright,bgBlueBright,bgMagentaBright,bgCyanBright,bgWhiteBright\"",
    "colors red = [31,39]",
    "colors grey alias = [90,39]",
    "colors proto = null",
    "colors names = 56",
    "styleText red = \"\\u001b[31mx\\u001b[39m\"",
    "styleText array = \"\\u001b[1m\\u001b[4my\\u001b[24m\\u001b[22m\"",
    "styleText alias = \"\\u001b[90mg\\u001b[39m\"",
    "styleText empty = \"e\"",
    "styleText bad format ! TypeError ERR_INVALID_ARG_VALUE The argument 'format' must be one of: 'reset', 'bold', 'dim', 'italic', 'underline', 'blink', 'inverse', 'hidden', 'strikethrough', 'doubleunderline', 'black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white', 'bgBlack', 'bgRed', 'bgGreen', 'bgYellow', 'bgBlue', 'bgMagenta', 'bgCyan', 'bgWhite', 'framed', 'overlined', 'gray', 'redBright', 'greenBright', 'yellowBright', 'blueBright', 'magentaBright', 'cyanBright', 'whiteBright', 'bgGray', 'bgRedBright', 'bgGreenBright', 'bgYellowBright', 'bgBlueBright', 'bgMagentaBright', 'bgCyanBright', 'bgWhiteBright'. Received 'nope'",
    "styleText bad in array ! TypeError ERR_INVALID_ARG_VALUE The argument 'format' must be one of: 'reset', 'bold', 'dim', 'italic', 'underline', 'blink', 'inverse', 'hidden', 'strikethrough', 'doubleunderline', 'black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white', 'bgBlack', 'bgRed', 'bgGreen', 'bgYellow', 'bgBlue', 'bgMagenta', 'bgCyan', 'bgWhite', 'framed', 'overlined', 'gray', 'redBright', 'greenBright', 'yellowBright', 'blueBright', 'magentaBright', 'cyanBright', 'whiteBright', 'bgGray', 'bgRedBright', 'bgGreenBright', 'bgYellowBright', 'bgBlueBright', 'bgMagentaBright', 'bgCyanBright', 'bgWhiteBright'. Received 5",
    "styleText bad text ! TypeError ERR_INVALID_ARG_TYPE The \"text\" argument must be of type string. Received type number (5)",
    "strip = \"hi link\"",
    "strip bad ! TypeError ERR_INVALID_ARG_TYPE The \"str\" argument must be of type string. Received type number (5)",
    "toUSVString = [3,\"12\"]",
];

#[test]
fn util_colors_style_text_and_strip_match_node() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("util_style.mjs");
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
            "util-style-text",
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
    let printed: Vec<String> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .flat_map(|message| message.split('\n').map(str::to_string))
        .collect();
    assert_eq!(printed, EXPECTED);
}
