fn parse_i64(input: &str) -> Option<i64> {
    let (is_neg, digits) = if let Some(rest) = input.strip_prefix('-') {
        (true, rest)
    } else {
        (false, input)
    };
    if digits.is_empty() { return None; }
    let value = digits.parse::<i64>().ok()?;
    Some(if is_neg { -value } else { value })
}
fn main() {
    println!("{:?}", parse_i64("-9223372036854775808"));
}
