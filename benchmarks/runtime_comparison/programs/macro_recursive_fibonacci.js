function fib(n) {
  if (n < 2) {
    return n;
  }
  return fib(n - 1) + fib(n - 2);
}

var i = 0;
var sum = 0;
while (i < 28) {
  sum = sum + fib(20);
  i = i + 1;
}

console.log(sum);
