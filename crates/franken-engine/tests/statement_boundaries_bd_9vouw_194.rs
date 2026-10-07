#![forbid(unsafe_code)]

//! Where a statement ends when the line ends without a semicolon, as npm
//! package sources write it:
//!
//! - bd-9vouw.194: a line ending with a regular-expression literal is a
//!   complete statement. Its closing `/` was taken for a division operator
//!   waiting for its right operand, so the next line joined it (json5's
//!   `module.exports.Space_Separator = /[...]/`, mime-types, fast-uri under
//!   ajv: "invalid assignment target").
//! - bd-9vouw.195: a line ending with an operator keyword (`new`, `in`,
//!   `instanceof`, `extends`) continues: babel's istanbul output writes
//!   `var d = new\n/*istanbul ignore start*/\n_base[...]()` (jsdiff), which
//!   ended at `new` and read it as a variable ("new is not defined").
//! - bd-9vouw.196: a do statement that is an else clause keeps its
//!   `while (...)`: minified `if(k)a();else do{..}while(c)` (preact) had the
//!   condition split off ("do-while requires a parenthesized condition"),
//!   and without a semicolon the next line became the body of a new
//!   `while (c)` loop and never ran.
//! - bd-9vouw.207: a lone `.` line continues a member access.
//! - bd-9vouw.212: a line ending with `function` or `class` continues.
//!
//! Expected lines are Node v22.2.0's output (Bun 1.4.2 prints the same).

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

/// Runs `source` as a script, as frankenctl does, on both lanes.
fn run(source: &str) -> Vec<String> {
    let mut outputs = [LaneChoice::QuickJs, LaneChoice::V8].map(|lane| {
        let package = ExtensionPackage {
            extension_id: "statement-boundaries".to_string(),
            source: source.to_string(),
            source_file: None,
            module_root: None,
            capabilities: vec!["builtin".to_string()],
            version: "1.0.0".to_string(),
            metadata: Default::default(),
        };
        ExecutionOrchestrator::new(OrchestratorConfig {
            force_lane: Some(lane),
            parse_goal: ParseGoal::Script,
            ..OrchestratorConfig::default()
        })
        .execute(&package)
        .unwrap_or_else(|error| panic!("{lane:?}: {error}"))
        .console_output
        .into_iter()
        .map(|line| line.message)
        .collect::<Vec<_>>()
    });
    assert_eq!(outputs[0], outputs[1], "lanes disagree");
    std::mem::take(&mut outputs[0])
}

#[test]
fn a_line_ending_with_a_regular_expression_literal_is_complete_bd_9vouw_194() {
    let source = "var a = /x/\nvar b = /^\\s*([^;\\s]*)(?:;|\\s|$)/\nvar c = /[^#/:?]+/u\n\n// a comment line\nvar d = /^text\\//i\nvar e = 6 /\n  3\nconsole.log(String(a), String(b), String(c), String(d), a.test('x'), b.exec('  ab;c')[1], e)\n";
    assert_eq!(
        run(source),
        ["/x/ /^\\s*([^;\\s]*)(?:;|\\s|$)/ /[^#/:?]+/u /^text\\//i true ab 2"]
    );
}

#[test]
fn a_line_ending_with_an_operator_keyword_continues_bd_9vouw_195() {
    // `o.new` is a property name: that line ends.
    let source = "function Base() { this.v = 1 }\nvar lib = { 'default': Base }\nvar d = new\n/*istanbul ignore start*/\nlib\n/*istanbul ignore end*/\n[\n'default'\n]()\nvar o = { new: 2 }\nvar n = o.new\nvar t = 'v' in\n  d\nconsole.log(d.v, d instanceof Base, n, t)\n";
    assert_eq!(run(source), ["1 true 2 true"]);
}

/// bd-9vouw.195 follow-up: the line scanners read a word after a space as a
/// word of its own. They appended it to the word before (`k in` was `kin`,
/// `else return` was `elsereturn`), so `var t = k in` ended its line (the
/// .195 unit test failed in finalgate21/22) and the regex after
/// `else return` was read as a division.
#[test]
fn a_keyword_after_a_space_is_read_alone_bd_9vouw_195() {
    let source = "function f(s) { if (!s) return 0; else return /b+/.test(s) ? 2 : 1 }\nfunction g() { return new\nDate(0).getTime() }\nvar k = 'v', o = { v: 1 }\nvar t = k in\n  o\nconsole.log(f(''), f('abb'), f('a'), g(), t)\n";
    assert_eq!(run(source), ["0 2 1 0 true"]);
}

#[test]
fn a_do_statement_in_an_else_clause_keeps_its_condition_bd_9vouw_196() {
    // The last if statement's `while` on the next line is a loop of its own.
    let source = "var i = 0\nif (i > 5) i = 9; else do { i++ } while (i < 3)\nconsole.log('after', i)\nfunction f(k, a) { if (k) { a.z = 1 } else do { a.s = (a.s || 0) + 1 } while (a.s < 2); a.t = 4; return a }\nvar g = function (k, a) {if(k)a.z=1;else do{a.s=3}while(a.d);return a}\nconsole.log(JSON.stringify(f(1, {})), JSON.stringify(f(0, {})), JSON.stringify(g(0, {})))\nvar j = 0\nif (j) j = 1; else j = 2\nwhile (j < 5) j++\nconsole.log('loop', j)\n";
    assert_eq!(
        run(source),
        [
            "after 3",
            "{\"z\":1,\"t\":4} {\"s\":2,\"t\":4} {\"s\":3}",
            "loop 5"
        ]
    );
}

/// bd-9vouw.207: babel's istanbul output (jsdiff's json.js) puts the `.` of a
/// member access on a line of its own between comment lines; that line
/// continues the previous one and the line after it continues the dot. A
/// decimal point at a line end (`1.`) still ends its number.
#[test]
fn a_lone_dot_line_continues_a_member_access_bd_9vouw_207() {
    let source = "var _line = { lineDiff: { tokenize: 42 } };\nvar o = {};\no.tokenize =\n/*istanbul ignore start*/\n_line\n/*istanbul ignore end*/\n.\n/*istanbul ignore start*/\nlineDiff\n/*istanbul ignore end*/\n.tokenize;\nvar n = 1.\nvar m = 2\nconsole.log(o.tokenize, n + m);\n";
    assert_eq!(run(source), ["42 3"]);
}

/// bd-9vouw.212: `function` and `class` at a line end still need their name
/// or body. jsdiff's distance-iterator.js (istanbul) declares
/// `function\n/*istanbul ignore start*/\n_default\n/*istanbul ignore end*/\n(start, minLine, maxLine) {`,
/// which ended at `function` ("_default is not defined"). As property names
/// (`o.function`) they end the line, and `async` alone on a line is a
/// statement of its own (no line break may follow `async` in
/// `async function`).
#[test]
fn a_line_ending_with_function_or_class_continues_bd_9vouw_212() {
    let source = "var first = _default(1, 2, 3)()\nfunction\n/*istanbul ignore start*/\n_default\n/*istanbul ignore end*/\n(start, minLine, maxLine) {\n  return function iterator() { return start + minLine + maxLine }\n}\nvar g = function\nnamed\n(a) { return a + 5 }\nasync function\nnamedA\n(a) { return a + 7 }\nclass\nK\n{ m() { return 9 } }\nvar o = { function: 3, class: 4 }\nvar p = o.function\nvar q = o.class\nvar async = 5\nasync\nfunction h() { return 6 }\nconsole.log(first, g(1), new K().m(), p, q, async, h())\nnamedA(1).then(function (v) { console.log('async', v) })\n";
    assert_eq!(run(source), ["6 6 9 3 4 5 6", "async 8"]);
}

/// bd-9vouw.219: a for-in/of head's `in` / `of` is a whole word, with or
/// without spaces: minifiers write `for(const[k,v]of m)`, `for(const{a}of
/// xs)`, `for(const c of"abc")`, `for(const k in{...})` (ts-pattern), which
/// read as C-style headers ("for statement header must have three
/// semicolon-separated parts"). A loop variable spelled `index` or `of` and
/// an `in` test of a C-style loop keep their meaning.
#[test]
fn minified_for_in_of_heads_parse_bd_9vouw_219() {
    let source = "var out=[];for(const[n,r]of[[1,2],[3,4]])out.push(n+r);for(const{a,b}of[{a:1,b:2}])out.push(a*b);\nlet s=0;for(let[a]of[[5]])s+=a;for(var{b}of[{b:6}])s+=b;out.push(s);var t=[];for(t[0]of[7,8]);out.push(t[0]);\nfor(const x of\"ab\")out.push(x);for(const y of`cd`)out.push(y);for(const k in{p:1,q:2})out.push(k);\nfor(let index=0;index<2;index++)out.push('i'+index);var o={z:1},c=0;for(;'z'in o&&c<1;c++)out.push('in');for(let of of[9])out.push(of);\nconsole.log(out.join());\n";
    assert_eq!(run(source), ["3,7,2,11,8,a,b,c,d,p,q,i0,i1,in,9"]);
}

/// bd-9vouw.229: a for-in/of head that destructures into member targets
/// (`for ([o.a, o.b] of xs)`, `for ({ k: o.v, ...o.rest } of xs)`, defaults,
/// nesting, element targets, a labeled `continue`) assigns them at the start
/// of each iteration. The head was parsed as a binding pattern, which has no
/// member targets ("unsupported binding pattern"). Node v22.2.0 prints this
/// line; Bun 1.4.2 agrees.
#[test]
fn for_in_of_heads_destructure_into_member_targets_bd_9vouw_229() {
    let source = "const o = {}; const r = [];\nfor ([o.a, o.b] of [[1, 2], [3, 4]]) r.push(o.a + o.b);\nfor ({ k: o.v, ...o.rest } of [{ k: 5, x: 6 }]) r.push(o.v, JSON.stringify(o.rest));\nfor ([o.d = 9, [o.e]] of [[undefined, [7]]]) r.push(o.d, o.e);\nfor ([o.f] in { ab: 1 }) r.push(o.f);\nconst arr = [];\nfor ([arr[0], arr[1]] of [['p', 'q']]) r.push(arr.join(''));\nouter: for ([o.g] of [[1], [2], [3]]) { if (o.g === 2) continue outer; r.push('g' + o.g); }\nconsole.log(r.join(' '));\n";
    assert_eq!(run(source), ["3 7 5 {\"x\":6} 9 7 a pq g1 g3"]);
}

/// bd-9vouw.232: TypeScript's and babel's CommonJS export preamble
/// `exports.a = exports.b = ... = void 0;` runs at any length (1,000 links
/// here; it was refused at 255 by the parser's recursion budget and
/// overflowed the registers near 200), for `module.exports.<name>` and
/// `this.<name>` targets too, storing innermost first (property creation
/// order and a proxy's set order show it); a chain with a computed target
/// keeps the general path. Node v22.2.0 prints these lines; Bun 1.4.2 agrees.
#[test]
fn long_export_void_chains_run_bd_9vouw_232() {
    let source = "\"use strict\";\nexports.x0 = exports.x1 = exports.x2 = exports.x3 = exports.x4 = exports.x5 = exports.x6 = exports.x7 = exports.x8 = exports.x9 = exports.x10 = exports.x11 = exports.x12 = exports.x13 = exports.x14 = exports.x15 = exports.x16 = exports.x17 = exports.x18 = exports.x19 = exports.x20 = exports.x21 = exports.x22 = exports.x23 = exports.x24 = exports.x25 = exports.x26 = exports.x27 = exports.x28 = exports.x29 = exports.x30 = exports.x31 = exports.x32 = exports.x33 = exports.x34 = exports.x35 = exports.x36 = exports.x37 = exports.x38 = exports.x39 = exports.x40 = exports.x41 = exports.x42 = exports.x43 = exports.x44 = exports.x45 = exports.x46 = exports.x47 = exports.x48 = exports.x49 = exports.x50 = exports.x51 = exports.x52 = exports.x53 = exports.x54 = exports.x55 = exports.x56 = exports.x57 = exports.x58 = exports.x59 = exports.x60 = exports.x61 = exports.x62 = exports.x63 = exports.x64 = exports.x65 = exports.x66 = exports.x67 = exports.x68 = exports.x69 = exports.x70 = exports.x71 = exports.x72 = exports.x73 = exports.x74 = exports.x75 = exports.x76 = exports.x77 = exports.x78 = exports.x79 = exports.x80 = exports.x81 = exports.x82 = exports.x83 = exports.x84 = exports.x85 = exports.x86 = exports.x87 = exports.x88 = exports.x89 = exports.x90 = exports.x91 = exports.x92 = exports.x93 = exports.x94 = exports.x95 = exports.x96 = exports.x97 = exports.x98 = exports.x99 = exports.x100 = exports.x101 = exports.x102 = exports.x103 = exports.x104 = exports.x105 = exports.x106 = exports.x107 = exports.x108 = exports.x109 = exports.x110 = exports.x111 = exports.x112 = exports.x113 = exports.x114 = exports.x115 = exports.x116 = exports.x117 = exports.x118 = exports.x119 = exports.x120 = exports.x121 = exports.x122 = exports.x123 = exports.x124 = exports.x125 = exports.x126 = exports.x127 = exports.x128 = exports.x129 = exports.x130 = exports.x131 = exports.x132 = exports.x133 = exports.x134 = exports.x135 = exports.x136 = exports.x137 = exports.x138 = exports.x139 = exports.x140 = exports.x141 = exports.x142 = exports.x143 = exports.x144 = exports.x145 = exports.x146 = exports.x147 = exports.x148 = exports.x149 = exports.x150 = exports.x151 = exports.x152 = exports.x153 = exports.x154 = exports.x155 = exports.x156 = exports.x157 = exports.x158 = exports.x159 = exports.x160 = exports.x161 = exports.x162 = exports.x163 = exports.x164 = exports.x165 = exports.x166 = exports.x167 = exports.x168 = exports.x169 = exports.x170 = exports.x171 = exports.x172 = exports.x173 = exports.x174 = exports.x175 = exports.x176 = exports.x177 = exports.x178 = exports.x179 = exports.x180 = exports.x181 = exports.x182 = exports.x183 = exports.x184 = exports.x185 = exports.x186 = exports.x187 = exports.x188 = exports.x189 = exports.x190 = exports.x191 = exports.x192 = exports.x193 = exports.x194 = exports.x195 = exports.x196 = exports.x197 = exports.x198 = exports.x199 = exports.x200 = exports.x201 = exports.x202 = exports.x203 = exports.x204 = exports.x205 = exports.x206 = exports.x207 = exports.x208 = exports.x209 = exports.x210 = exports.x211 = exports.x212 = exports.x213 = exports.x214 = exports.x215 = exports.x216 = exports.x217 = exports.x218 = exports.x219 = exports.x220 = exports.x221 = exports.x222 = exports.x223 = exports.x224 = exports.x225 = exports.x226 = exports.x227 = exports.x228 = exports.x229 = exports.x230 = exports.x231 = exports.x232 = exports.x233 = exports.x234 = exports.x235 = exports.x236 = exports.x237 = exports.x238 = exports.x239 = exports.x240 = exports.x241 = exports.x242 = exports.x243 = exports.x244 = exports.x245 = exports.x246 = exports.x247 = exports.x248 = exports.x249 = exports.x250 = exports.x251 = exports.x252 = exports.x253 = exports.x254 = exports.x255 = exports.x256 = exports.x257 = exports.x258 = exports.x259 = exports.x260 = exports.x261 = exports.x262 = exports.x263 = exports.x264 = exports.x265 = exports.x266 = exports.x267 = exports.x268 = exports.x269 = exports.x270 = exports.x271 = exports.x272 = exports.x273 = exports.x274 = exports.x275 = exports.x276 = exports.x277 = exports.x278 = exports.x279 = exports.x280 = exports.x281 = exports.x282 = exports.x283 = exports.x284 = exports.x285 = exports.x286 = exports.x287 = exports.x288 = exports.x289 = exports.x290 = exports.x291 = exports.x292 = exports.x293 = exports.x294 = exports.x295 = exports.x296 = exports.x297 = exports.x298 = exports.x299 = exports.x300 = exports.x301 = exports.x302 = exports.x303 = exports.x304 = exports.x305 = exports.x306 = exports.x307 = exports.x308 = exports.x309 = exports.x310 = exports.x311 = exports.x312 = exports.x313 = exports.x314 = exports.x315 = exports.x316 = exports.x317 = exports.x318 = exports.x319 = exports.x320 = exports.x321 = exports.x322 = exports.x323 = exports.x324 = exports.x325 = exports.x326 = exports.x327 = exports.x328 = exports.x329 = exports.x330 = exports.x331 = exports.x332 = exports.x333 = exports.x334 = exports.x335 = exports.x336 = exports.x337 = exports.x338 = exports.x339 = exports.x340 = exports.x341 = exports.x342 = exports.x343 = exports.x344 = exports.x345 = exports.x346 = exports.x347 = exports.x348 = exports.x349 = exports.x350 = exports.x351 = exports.x352 = exports.x353 = exports.x354 = exports.x355 = exports.x356 = exports.x357 = exports.x358 = exports.x359 = exports.x360 = exports.x361 = exports.x362 = exports.x363 = exports.x364 = exports.x365 = exports.x366 = exports.x367 = exports.x368 = exports.x369 = exports.x370 = exports.x371 = exports.x372 = exports.x373 = exports.x374 = exports.x375 = exports.x376 = exports.x377 = exports.x378 = exports.x379 = exports.x380 = exports.x381 = exports.x382 = exports.x383 = exports.x384 = exports.x385 = exports.x386 = exports.x387 = exports.x388 = exports.x389 = exports.x390 = exports.x391 = exports.x392 = exports.x393 = exports.x394 = exports.x395 = exports.x396 = exports.x397 = exports.x398 = exports.x399 = exports.x400 = exports.x401 = exports.x402 = exports.x403 = exports.x404 = exports.x405 = exports.x406 = exports.x407 = exports.x408 = exports.x409 = exports.x410 = exports.x411 = exports.x412 = exports.x413 = exports.x414 = exports.x415 = exports.x416 = exports.x417 = exports.x418 = exports.x419 = exports.x420 = exports.x421 = exports.x422 = exports.x423 = exports.x424 = exports.x425 = exports.x426 = exports.x427 = exports.x428 = exports.x429 = exports.x430 = exports.x431 = exports.x432 = exports.x433 = exports.x434 = exports.x435 = exports.x436 = exports.x437 = exports.x438 = exports.x439 = exports.x440 = exports.x441 = exports.x442 = exports.x443 = exports.x444 = exports.x445 = exports.x446 = exports.x447 = exports.x448 = exports.x449 = exports.x450 = exports.x451 = exports.x452 = exports.x453 = exports.x454 = exports.x455 = exports.x456 = exports.x457 = exports.x458 = exports.x459 = exports.x460 = exports.x461 = exports.x462 = exports.x463 = exports.x464 = exports.x465 = exports.x466 = exports.x467 = exports.x468 = exports.x469 = exports.x470 = exports.x471 = exports.x472 = exports.x473 = exports.x474 = exports.x475 = exports.x476 = exports.x477 = exports.x478 = exports.x479 = exports.x480 = exports.x481 = exports.x482 = exports.x483 = exports.x484 = exports.x485 = exports.x486 = exports.x487 = exports.x488 = exports.x489 = exports.x490 = exports.x491 = exports.x492 = exports.x493 = exports.x494 = exports.x495 = exports.x496 = exports.x497 = exports.x498 = exports.x499 = exports.x500 = exports.x501 = exports.x502 = exports.x503 = exports.x504 = exports.x505 = exports.x506 = exports.x507 = exports.x508 = exports.x509 = exports.x510 = exports.x511 = exports.x512 = exports.x513 = exports.x514 = exports.x515 = exports.x516 = exports.x517 = exports.x518 = exports.x519 = exports.x520 = exports.x521 = exports.x522 = exports.x523 = exports.x524 = exports.x525 = exports.x526 = exports.x527 = exports.x528 = exports.x529 = exports.x530 = exports.x531 = exports.x532 = exports.x533 = exports.x534 = exports.x535 = exports.x536 = exports.x537 = exports.x538 = exports.x539 = exports.x540 = exports.x541 = exports.x542 = exports.x543 = exports.x544 = exports.x545 = exports.x546 = exports.x547 = exports.x548 = exports.x549 = exports.x550 = exports.x551 = exports.x552 = exports.x553 = exports.x554 = exports.x555 = exports.x556 = exports.x557 = exports.x558 = exports.x559 = exports.x560 = exports.x561 = exports.x562 = exports.x563 = exports.x564 = exports.x565 = exports.x566 = exports.x567 = exports.x568 = exports.x569 = exports.x570 = exports.x571 = exports.x572 = exports.x573 = exports.x574 = exports.x575 = exports.x576 = exports.x577 = exports.x578 = exports.x579 = exports.x580 = exports.x581 = exports.x582 = exports.x583 = exports.x584 = exports.x585 = exports.x586 = exports.x587 = exports.x588 = exports.x589 = exports.x590 = exports.x591 = exports.x592 = exports.x593 = exports.x594 = exports.x595 = exports.x596 = exports.x597 = exports.x598 = exports.x599 = exports.x600 = exports.x601 = exports.x602 = exports.x603 = exports.x604 = exports.x605 = exports.x606 = exports.x607 = exports.x608 = exports.x609 = exports.x610 = exports.x611 = exports.x612 = exports.x613 = exports.x614 = exports.x615 = exports.x616 = exports.x617 = exports.x618 = exports.x619 = exports.x620 = exports.x621 = exports.x622 = exports.x623 = exports.x624 = exports.x625 = exports.x626 = exports.x627 = exports.x628 = exports.x629 = exports.x630 = exports.x631 = exports.x632 = exports.x633 = exports.x634 = exports.x635 = exports.x636 = exports.x637 = exports.x638 = exports.x639 = exports.x640 = exports.x641 = exports.x642 = exports.x643 = exports.x644 = exports.x645 = exports.x646 = exports.x647 = exports.x648 = exports.x649 = exports.x650 = exports.x651 = exports.x652 = exports.x653 = exports.x654 = exports.x655 = exports.x656 = exports.x657 = exports.x658 = exports.x659 = exports.x660 = exports.x661 = exports.x662 = exports.x663 = exports.x664 = exports.x665 = exports.x666 = exports.x667 = exports.x668 = exports.x669 = exports.x670 = exports.x671 = exports.x672 = exports.x673 = exports.x674 = exports.x675 = exports.x676 = exports.x677 = exports.x678 = exports.x679 = exports.x680 = exports.x681 = exports.x682 = exports.x683 = exports.x684 = exports.x685 = exports.x686 = exports.x687 = exports.x688 = exports.x689 = exports.x690 = exports.x691 = exports.x692 = exports.x693 = exports.x694 = exports.x695 = exports.x696 = exports.x697 = exports.x698 = exports.x699 = exports.x700 = exports.x701 = exports.x702 = exports.x703 = exports.x704 = exports.x705 = exports.x706 = exports.x707 = exports.x708 = exports.x709 = exports.x710 = exports.x711 = exports.x712 = exports.x713 = exports.x714 = exports.x715 = exports.x716 = exports.x717 = exports.x718 = exports.x719 = exports.x720 = exports.x721 = exports.x722 = exports.x723 = exports.x724 = exports.x725 = exports.x726 = exports.x727 = exports.x728 = exports.x729 = exports.x730 = exports.x731 = exports.x732 = exports.x733 = exports.x734 = exports.x735 = exports.x736 = exports.x737 = exports.x738 = exports.x739 = exports.x740 = exports.x741 = exports.x742 = exports.x743 = exports.x744 = exports.x745 = exports.x746 = exports.x747 = exports.x748 = exports.x749 = exports.x750 = exports.x751 = exports.x752 = exports.x753 = exports.x754 = exports.x755 = exports.x756 = exports.x757 = exports.x758 = exports.x759 = exports.x760 = exports.x761 = exports.x762 = exports.x763 = exports.x764 = exports.x765 = exports.x766 = exports.x767 = exports.x768 = exports.x769 = exports.x770 = exports.x771 = exports.x772 = exports.x773 = exports.x774 = exports.x775 = exports.x776 = exports.x777 = exports.x778 = exports.x779 = exports.x780 = exports.x781 = exports.x782 = exports.x783 = exports.x784 = exports.x785 = exports.x786 = exports.x787 = exports.x788 = exports.x789 = exports.x790 = exports.x791 = exports.x792 = exports.x793 = exports.x794 = exports.x795 = exports.x796 = exports.x797 = exports.x798 = exports.x799 = exports.x800 = exports.x801 = exports.x802 = exports.x803 = exports.x804 = exports.x805 = exports.x806 = exports.x807 = exports.x808 = exports.x809 = exports.x810 = exports.x811 = exports.x812 = exports.x813 = exports.x814 = exports.x815 = exports.x816 = exports.x817 = exports.x818 = exports.x819 = exports.x820 = exports.x821 = exports.x822 = exports.x823 = exports.x824 = exports.x825 = exports.x826 = exports.x827 = exports.x828 = exports.x829 = exports.x830 = exports.x831 = exports.x832 = exports.x833 = exports.x834 = exports.x835 = exports.x836 = exports.x837 = exports.x838 = exports.x839 = exports.x840 = exports.x841 = exports.x842 = exports.x843 = exports.x844 = exports.x845 = exports.x846 = exports.x847 = exports.x848 = exports.x849 = exports.x850 = exports.x851 = exports.x852 = exports.x853 = exports.x854 = exports.x855 = exports.x856 = exports.x857 = exports.x858 = exports.x859 = exports.x860 = exports.x861 = exports.x862 = exports.x863 = exports.x864 = exports.x865 = exports.x866 = exports.x867 = exports.x868 = exports.x869 = exports.x870 = exports.x871 = exports.x872 = exports.x873 = exports.x874 = exports.x875 = exports.x876 = exports.x877 = exports.x878 = exports.x879 = exports.x880 = exports.x881 = exports.x882 = exports.x883 = exports.x884 = exports.x885 = exports.x886 = exports.x887 = exports.x888 = exports.x889 = exports.x890 = exports.x891 = exports.x892 = exports.x893 = exports.x894 = exports.x895 = exports.x896 = exports.x897 = exports.x898 = exports.x899 = exports.x900 = exports.x901 = exports.x902 = exports.x903 = exports.x904 = exports.x905 = exports.x906 = exports.x907 = exports.x908 = exports.x909 = exports.x910 = exports.x911 = exports.x912 = exports.x913 = exports.x914 = exports.x915 = exports.x916 = exports.x917 = exports.x918 = exports.x919 = exports.x920 = exports.x921 = exports.x922 = exports.x923 = exports.x924 = exports.x925 = exports.x926 = exports.x927 = exports.x928 = exports.x929 = exports.x930 = exports.x931 = exports.x932 = exports.x933 = exports.x934 = exports.x935 = exports.x936 = exports.x937 = exports.x938 = exports.x939 = exports.x940 = exports.x941 = exports.x942 = exports.x943 = exports.x944 = exports.x945 = exports.x946 = exports.x947 = exports.x948 = exports.x949 = exports.x950 = exports.x951 = exports.x952 = exports.x953 = exports.x954 = exports.x955 = exports.x956 = exports.x957 = exports.x958 = exports.x959 = exports.x960 = exports.x961 = exports.x962 = exports.x963 = exports.x964 = exports.x965 = exports.x966 = exports.x967 = exports.x968 = exports.x969 = exports.x970 = exports.x971 = exports.x972 = exports.x973 = exports.x974 = exports.x975 = exports.x976 = exports.x977 = exports.x978 = exports.x979 = exports.x980 = exports.x981 = exports.x982 = exports.x983 = exports.x984 = exports.x985 = exports.x986 = exports.x987 = exports.x988 = exports.x989 = exports.x990 = exports.x991 = exports.x992 = exports.x993 = exports.x994 = exports.x995 = exports.x996 = exports.x997 = exports.x998 = exports.x999 = void 0;\nexports.x7 = 7;\nconsole.log(Object.keys(exports).length, exports.x0, exports.x7, exports.x999, 'x500' in exports);\nmodule.exports.m1 = module.exports.m2 = void 0;\nconsole.log('m1' in module.exports, module.exports.m2);\nfunction T() { this.a = this.b = void 0; this.b = 2; }\nconsole.log(JSON.stringify(Object.entries(new T())));\nconst k = 'q'; exports[k] = exports.r = void 0;\nconsole.log('q' in exports, 'r' in exports);\nconst order = []; const p = new Proxy({}, { set(t, key, v) { order.push(key); t[key] = v; return true; } });\n(function () { this.s1 = this.s2 = this.s3 = void 0; }).call(p);\nconsole.log(order.join());\n";
    assert_eq!(
        run(source),
        [
            "1000 undefined 7 undefined true",
            "true undefined",
            "[[\"b\",2],[\"a\",null]]",
            "true true",
            "s3,s2,s1"
        ]
    );
}

/// bd-9vouw.233: a for-in head excludes only `let [`, so sloppy
/// `for (let in o)` assigns the variable `let` each iteration (the
/// whole-word `in` / `of` finder of bd-9vouw.219 skipped an `in` after a bare
/// `let` and refused the header). Node v22.2.0 prints these lines; Bun 1.4.2
/// agrees.
#[test]
fn a_for_in_head_assigns_the_variable_let_bd_9vouw_233() {
    let source = "var let;\nfor (let in { a: 1, b: 2 }) {}\nconsole.log(let);\nvar o = { p: 0 };\nfor (let in o) { o.p += 1; }\nconsole.log(o.p, let);\n";
    assert_eq!(run(source), ["b", "1 p"]);
}

/// bd-9vouw.219 (follow-up): a declaration keyword followed directly by a
/// pattern (`for(let{a}of xs)`, `for(var[c]in o)`, `for await(const[k,v]of
/// xs)`) declares it; the head was read as `let` / `const` / `var`
/// variables (`const is not defined`, "invalid assignment target"), which
/// failed minified_for_in_of_heads_parse_bd_9vouw_219 at its first gate.
/// Node v22.2.0 prints this line; Bun 1.4.2 agrees.
#[test]
fn declaration_keywords_glued_to_patterns_declare_them_bd_9vouw_219() {
    let source = "var out=[];for(let{a}of[{a:1}])out.push(a);for(let[b]of[[2]])out.push(b);var let_=3;for(var[c]in{x:1})out.push(c);(async()=>{for await(const[k,v]of[[4,5]])out.push(k+v);for await(let{z}of[{z:6}])out.push(z);console.log(out.join());})();\n";
    assert_eq!(run(source), ["1,2,x,9,6"]);
}

/// bd-9vouw.248: a with statement's braced body ends the statement, so a
/// statement after it on the same line runs on its own. It was glued onto
/// the body and failed as an expression ("unsupported expression syntax:
/// { var q = a; } console"). Node v22.2.0 prints these lines.
#[test]
fn a_statement_after_a_with_body_on_the_same_line_runs_bd_9vouw_248() {
    let source = "var o = { a: 1 }; with (o) { var q = a; } console.log(q);\nfunction f() { with ({ b: 2 }) { var r = b; } return r; } console.log(f());\nvar withdrawn = 3; console.log(withdrawn);\n";
    assert_eq!(run(source), ["1", "2", "3"]);
}
