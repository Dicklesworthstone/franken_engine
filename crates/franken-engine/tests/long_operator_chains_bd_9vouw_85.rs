//! Long flat chains of binary operators (bd-9vouw.85).
//!
//! The parser split a left-associative chain at its rightmost operator and
//! recursed into the rest, so its depth grew by one per term: 256 or more
//! terms (`q + q + ... + q`, a long string concatenation, `t && t && ...`)
//! failed with "recursion budget exceeded". Minified bundles contain such
//! chains. Expected values are Node v22.2.0's completion values for the same
//! programs (`vm.runInThisContext`). `HybridRouter::eval` sizes its frame to
//! the program; a fixed 256-register frame runs out of temporaries on a
//! 300-term chain, which is register allocation (bd-9vouw.23), not parsing.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(eval_to_string(source), node, "must match Node v22.2.0");
}

#[test]
fn three_hundred_additions() {
    check(
        r#"const q = 1; String(q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q);"#,
        "300",
    );
}

#[test]
fn three_hundred_string_concatenations() {
    check(
        r#"const s = '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9'; String([s.length, s.slice(0, 12)]);"#,
        "300,012345678901",
    );
}

#[test]
fn three_hundred_logical_ands() {
    check(
        r#"const t = true; String(t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t);"#,
        "true",
    );
}

#[test]
fn mixed_subtraction_and_addition_stay_left_associative() {
    check(
        r#"String(- 1 + 2 - 3 + 4 - 5 + 6 - 7 + 8 - 9 + 10 - 11 + 12 - 13 + 14 - 15 + 16 - 17 + 18 - 19 + 20 - 21 + 22 - 23 + 24 - 25 + 26 - 27 + 28 - 29 + 30 - 31 + 32 - 33 + 34 - 35 + 36 - 37 + 38 - 39 + 40 - 41 + 42 - 43 + 44 - 45 + 46 - 47 + 48 - 49 + 50 - 51 + 52 - 53 + 54 - 55 + 56 - 57 + 58 - 59 + 60 - 61 + 62 - 63 + 64 - 65 + 66 - 67 + 68 - 69 + 70 - 71 + 72 - 73 + 74 - 75 + 76 - 77 + 78 - 79 + 80 - 81 + 82 - 83 + 84 - 85 + 86 - 87 + 88 - 89 + 90 - 91 + 92 - 93 + 94 - 95 + 96 - 97 + 98 - 99 + 100 - 101 + 102 - 103 + 104 - 105 + 106 - 107 + 108 - 109 + 110 - 111 + 112 - 113 + 114 - 115 + 116 - 117 + 118 - 119 + 120 - 121 + 122 - 123 + 124 - 125 + 126 - 127 + 128 - 129 + 130 - 131 + 132 - 133 + 134 - 135 + 136 - 137 + 138 - 139 + 140 - 141 + 142 - 143 + 144 - 145 + 146 - 147 + 148 - 149 + 150 - 151 + 152 - 153 + 154 - 155 + 156 - 157 + 158 - 159 + 160 - 161 + 162 - 163 + 164 - 165 + 166 - 167 + 168 - 169 + 170 - 171 + 172 - 173 + 174 - 175 + 176 - 177 + 178 - 179 + 180 - 181 + 182 - 183 + 184 - 185 + 186 - 187 + 188 - 189 + 190 - 191 + 192 - 193 + 194 - 195 + 196 - 197 + 198 - 199 + 200 - 201 + 202 - 203 + 204 - 205 + 206 - 207 + 208 - 209 + 210 - 211 + 212 - 213 + 214 - 215 + 216 - 217 + 218 - 219 + 220 - 221 + 222 - 223 + 224 - 225 + 226 - 227 + 228 - 229 + 230 - 231 + 232 - 233 + 234 - 235 + 236 - 237 + 238 - 239 + 240 - 241 + 242 - 243 + 244 - 245 + 246 - 247 + 248 - 249 + 250 - 251 + 252 - 253 + 254 - 255 + 256 - 257 + 258 - 259 + 260 - 261 + 262 - 263 + 264 - 265 + 266 - 267 + 268 - 269 + 270 - 271 + 272 - 273 + 274 - 275 + 276 - 277 + 278 - 279 + 280 - 281 + 282 - 283 + 284 - 285 + 286 - 287 + 288 - 289 + 290 - 291 + 292 - 293 + 294 - 295 + 296 - 297 + 298 - 299 + 300);"#,
        "150",
    );
}

#[test]
fn three_hundred_comma_sequence() {
    check(
        r#"let n = 0; const r = (n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1); String([n, r]);"#,
        "300,300",
    );
}
