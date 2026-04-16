function add(a, b) {
  return a + b;
}

var i = 0;
var sum = 0;
while (i < 500000) {
  sum = sum + add(i, 1);
  i = i + 1;
}
console.log(sum);
