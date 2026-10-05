#![forbid(unsafe_code)]

//! bd-9vouw.185: the Annex B String HTML methods (`anchor`, `big`, `blink`,
//! `bold`, `fixed`, `fontcolor`, `fontsize`, `italics`, `link`, `small`,
//! `strike`, `sub`, `sup`) were missing (`'x'.bold()` threw "expected
//! function"). Expected lines are Node v22.2.0's output for the same
//! programs, captured programmatically (Bun 1.4.2 prints the same).

use frankenengine_engine::HybridRouter;

fn console_output(source: &str) -> Vec<String> {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect()
}

/// Each Annex B HTML method wraps the string in its tag; the attribute value's double quotes become &quot;.
#[test]
fn html_methods_wrap_the_string() {
    let source = "const s = 'x';\nconsole.log([s.anchor('a\"b'), s.big(), s.blink(), s.bold(), s.fixed(), s.fontcolor('red'), s.fontsize(7), s.italics(), s.link('https://e.x/?q=\"1\"'), s.small(), s.strike(), s.sub(), s.sup()].join(' '));\nconsole.log(typeof String.prototype.anchor, String.prototype.anchor.length, String.prototype.link.name, String.prototype.big.length);\n";
    assert_eq!(
        console_output(source),
        [
            "<a name=\"a&quot;b\">x</a> <big>x</big> <blink>x</blink> <b>x</b> <tt>x</tt> <font color=\"red\">x</font> <font size=\"7\">x</font> <i>x</i> <a href=\"https://e.x/?q=&quot;1&quot;\">x</a> <small>x</small> <strike>x</strike> <sub>x</sub> <sup>x</sup>",
            "function 1 link 0"
        ]
    );
}

/// The receiver converts with ToString before the attribute value; null throws; a Symbol value throws a TypeError.
#[test]
fn html_methods_convert_receiver_then_value() {
    let source = "const order = [];\nconst receiver = { toString() { order.push('receiver'); return 'R'; } };\nconst value = { toString() { order.push('value'); return 'V'; } };\nconsole.log(String.prototype.anchor.call(receiver, value), order.join());\nconsole.log(String.prototype.bold.call(42), String.prototype.sub.call(true));\ntry { String.prototype.bold.call(null); } catch (e) { console.log(e.constructor.name); }\ntry { 'x'.anchor(Symbol('s')); } catch (e) { console.log(e.constructor.name); }\n";
    assert_eq!(
        console_output(source),
        [
            "<a name=\"V\">R</a> receiver,value",
            "<b>42</b> <sub>true</sub>",
            "TypeError",
            "TypeError"
        ]
    );
}
