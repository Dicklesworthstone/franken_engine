function makeAdder(a, b, c) {
  return function (x) {
    return x + a + b + c;
  };
}

var add = makeAdder(1, 2, 3);
var i = 0;
var sum = 0;
while (i < 500000) {
  sum = sum + add(i);
  i = i + 1;
}
console.log(sum);
