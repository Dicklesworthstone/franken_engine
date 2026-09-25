//! Bounded evaluation of a deliberately small, side-effect-free Number subset.
//!
//! This is not a JavaScript parser. Only decimal Number literals, parentheses,
//! unary signs and `+ - * /` are accepted. Anything outside this grammar is left
//! to the baseline runtime. In particular, no identifier, call, property access,
//! string, BigInt, comment or assignment may acquire an algebraic certificate.

const MAX_INPUT_BYTES: usize = 16_384;
const MAX_DEPTH: usize = 64;
const MAX_OPERATIONS: usize = 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Rule {
    Constant,
    AddZero,
    MultiplyOne,
    MultiplyZero,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operator {
    Add,
    Subtract,
    Multiply,
    Divide,
}

#[derive(Clone, Copy)]
struct Value {
    number: f64,
    root: Option<(Operator, f64, f64)>,
}

impl Value {
    fn literal(number: f64) -> Self {
        Self { number, root: None }
    }
}

struct Parser<'a> {
    source: &'a str,
    offset: usize,
    operations: usize,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Option<Self> {
        if source.is_empty() || source.len() > MAX_INPUT_BYTES || !source.is_ascii() {
            return None;
        }
        // Adjacent signs are update tokens in ECMAScript, not two unary signs.
        // Whitespace-separated signs remain valid: `1 - -2`, `+ +2`.
        if source
            .as_bytes()
            .windows(2)
            .any(|pair| pair == b"++" || pair == b"--")
        {
            return None;
        }
        Some(Self {
            source,
            offset: 0,
            operations: 0,
        })
    }

    fn parse(mut self) -> Option<(Value, usize)> {
        let value = self.sum(0)?;
        self.skip_space();
        (self.offset == self.source.len()).then_some((value, self.operations))
    }

    fn peek(&self) -> Option<u8> {
        self.source.as_bytes().get(self.offset).copied()
    }

    fn skip_space(&mut self) {
        while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
            self.offset += 1;
        }
    }

    fn record_operation(&mut self) -> Option<()> {
        self.operations += 1;
        (self.operations <= MAX_OPERATIONS).then_some(())
    }

    fn sum(&mut self, depth: usize) -> Option<Value> {
        let mut left = self.product(depth)?;
        loop {
            self.skip_space();
            let operator = match self.peek() {
                Some(b'+') => Operator::Add,
                Some(b'-') => Operator::Subtract,
                _ => return Some(left),
            };
            self.offset += 1;
            self.record_operation()?;
            let right = self.product(depth)?;
            let number = match operator {
                Operator::Add => left.number + right.number,
                Operator::Subtract => left.number - right.number,
                _ => return None,
            };
            left = Value {
                number,
                root: Some((operator, left.number, right.number)),
            };
        }
    }

    fn product(&mut self, depth: usize) -> Option<Value> {
        let mut left = self.unary(depth)?;
        loop {
            self.skip_space();
            let operator = match self.peek() {
                Some(b'*') => Operator::Multiply,
                Some(b'/') => Operator::Divide,
                _ => return Some(left),
            };
            self.offset += 1;
            self.record_operation()?;
            let right = self.unary(depth)?;
            let number = match operator {
                Operator::Multiply => left.number * right.number,
                Operator::Divide => left.number / right.number,
                _ => return None,
            };
            left = Value {
                number,
                root: Some((operator, left.number, right.number)),
            };
        }
    }

    fn unary(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.skip_space();
        match self.peek()? {
            sign @ (b'+' | b'-') => {
                self.offset += 1;
                self.record_operation()?;
                let inner = self.unary(depth + 1)?;
                Some(Value::literal(if sign == b'-' {
                    -inner.number
                } else {
                    inner.number
                }))
            }
            b'(' => {
                self.offset += 1;
                let value = self.sum(depth + 1)?;
                self.skip_space();
                if self.peek()? != b')' {
                    return None;
                }
                self.offset += 1;
                Some(value)
            }
            _ => self.literal(),
        }
    }

    fn literal(&mut self) -> Option<Value> {
        let start = self.offset;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.offset += 1;
        }
        let integer_digits = self.offset - start;
        // Legacy leading-zero literals depend on strict/sloppy context. Never
        // interpret them as decimal without knowing that context.
        if integer_digits > 1 && self.source.as_bytes()[start] == b'0' {
            return None;
        }
        let mut fraction_digits = 0;
        if self.peek() == Some(b'.') {
            self.offset += 1;
            let fraction_start = self.offset;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.offset += 1;
            }
            fraction_digits = self.offset - fraction_start;
        }
        if integer_digits + fraction_digits == 0 {
            return None;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.offset += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            let exponent_start = self.offset;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.offset += 1;
            }
            if self.offset == exponent_start {
                return None;
            }
        }
        // The lexer above, not Rust's broader float syntax, defines admission.
        let number = self.source[start..self.offset].parse::<f64>().ok()?;
        Some(Value::literal(number))
    }
}

fn evaluate(program: &str) -> Option<(Value, usize)> {
    Parser::new(program)?.parse()
}

/// Fold only after both operands (and all their subexpressions) are known to
/// have Number type and no effects. Evaluate the operation, never just return
/// an operand: even `-0 + 0` and `-3 * 0` make naive identities unsound.
pub(super) fn rewrite(program: &str, rule: Rule) -> Option<String> {
    let (value, operations) = evaluate(program)?;
    let applicable = match rule {
        Rule::Constant => operations > 0,
        Rule::AddZero => matches!(
            value.root,
            Some((Operator::Add, left, right)) if left == 0.0 || right == 0.0
        ),
        Rule::MultiplyOne => matches!(
            value.root,
            Some((Operator::Multiply, left, right)) if left == 1.0 || right == 1.0
        ),
        Rule::MultiplyZero => matches!(
            value.root,
            Some((Operator::Multiply, left, right)) if left == 0.0 || right == 0.0
        ),
    };
    if !applicable || !value.number.is_finite() {
        // `NaN` and `Infinity` are shadowable names, not numeric literals.
        return None;
    }
    let candidate = if value.number == 0.0 && value.number.is_sign_negative() {
        "-0".to_string()
    } else {
        value.number.to_string()
    };
    (candidate != program.trim()).then_some(candidate)
}

/// Compare evaluations independently of rewrite selection. Bit equality
/// preserves the distinction between +0 and -0. Non-finite results are outside
/// the admitted output subset; an unprovable candidate must fail closed.
pub(super) fn equivalent(before: &str, after: &str) -> bool {
    let Some((before, _)) = evaluate(before) else {
        return false;
    };
    let Some((after, _)) = evaluate(after) else {
        return false;
    };
    before.number.is_finite()
        && after.number.is_finite()
        && before.number.to_bits() == after.number.to_bits()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_folding_preserves_binary64_semantics() {
        for (before, after) in [
            ("5 / 2", "2.5"),
            ("-5 / 2", "-2.5"),
            ("0 / -1", "-0"),
            ("-3 * 0", "-0"),
            ("-0 + 0", "0"),
            ("-0 + -0", "-0"),
            ("1 + 2 * 3", "7"),
            ("(1 + 2) * 3", "9"),
            ("8 / 4 / 2", "1"),
            ("8 - 4 - 2", "2"),
            ("1 - -2", "3"),
            ("+ +2", "2"),
            (".5 + .25", "0.75"),
            ("1. + 2.", "3"),
            ("1e-2 + 2E-2", "0.03"),
            ("0.1 + 0.2", "0.30000000000000004"),
            ("9007199254740993 - 9007199254740992", "0"),
            ("9007199254740992 + 1", "9007199254740992"),
            ("1 / (1 / 0)", "0"),
        ] {
            assert_eq!(rewrite(before, Rule::Constant).as_deref(), Some(after), "{before}");
            assert!(equivalent(before, after), "{before} -> {after}");
            assert!(rewrite(after, Rule::Constant).is_none(), "not a fixed point: {after}");
        }
    }

    #[test]
    fn identities_require_pure_number_operands() {
        for program in [
            "x + 0", "0 + x", "x * 1", "1 * x", "x * 0", "0 * x",
            "effect() * 0", "0 * effect()", "object.value * 0", "missing * 0",
            "'5' + 0", "'5' * 1", "1n * 0", "NaN * 0", "Infinity * 0",
            "1; effect() * 0", "(effect(), 1) * 0", "[1] * 1", "true + 0",
        ] {
            for rule in [Rule::Constant, Rule::AddZero, Rule::MultiplyOne, Rule::MultiplyZero] {
                assert!(rewrite(program, rule).is_none(), "{rule:?}: {program}");
            }
        }
        assert_eq!(rewrite("-0 + 0", Rule::AddZero).as_deref(), Some("0"));
        assert_eq!(rewrite("-3 * 0", Rule::MultiplyZero).as_deref(), Some("-0"));
        assert_eq!(rewrite(".5 * 1", Rule::MultiplyOne).as_deref(), Some("0.5"));
    }

    #[test]
    fn unsupported_or_invalid_syntax_never_becomes_a_rewrite() {
        for program in [
            "", " ", "1++2", "1--2", "--1", "++1", "1**2", "1//2", "1/*x*/+2",
            "1+", "+", ".", "1e+", "1e-", "1e", "01+1", "00.5+1", "0x10+1",
            "0o10+1", "0b10+1", "1_000+1", "(1+2", "1+2)", "1+2;", "1 2",
            "1.0.0", "1+2 trailing", "1\u{a0}+2", "1/0", "0/0", "1e308*1e308",
        ] {
            assert!(rewrite(program, Rule::Constant).is_none(), "{program:?}");
        }
    }

    #[test]
    fn equivalence_rejects_observably_different_or_unknown_values() {
        for (before, after) in [
            ("5 / 2", "2"), ("-3 * 0", "0"), ("-0", "0"),
            ("x * 0", "0"), ("effect() * 0", "0"), ("'1' + 0", "1"),
            ("1 / 0", "Infinity"), ("0 / 0", "NaN"), ("1", "1; effect()"),
        ] {
            assert!(!equivalent(before, after), "{before} -> {after}");
        }
        assert!(equivalent("(2 + 3) * 4", "20"));
        assert!(equivalent("-0", "-0"));
    }

    #[test]
    fn resource_limits_fail_closed() {
        let deeply_nested = format!("{}1 + 1{}", "(".repeat(MAX_DEPTH + 1), ")".repeat(MAX_DEPTH + 1));
        let many_operations = format!("1{}", "+1".repeat(MAX_OPERATIONS + 1));
        let long_literal = "1".repeat(MAX_INPUT_BYTES + 1);
        for program in [&deeply_nested, &many_operations, &long_literal] {
            assert!(rewrite(program, Rule::Constant).is_none());
            assert!(!equivalent(program, "2"));
        }
    }
}
