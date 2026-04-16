fn isqrt_i128(n: i128) -> i128 {
    if n <= 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

fn main() {
    println!("{}", isqrt_i128(i128::MAX - 1));
    println!("{}", isqrt_i128(i128::MAX));
}
