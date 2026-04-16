var obj = { a: 1, b: 2, c: 3, d: 4 };
var i = 0;
var sum = 0;
while (i < 500000) {
  sum = sum + obj.a + obj.b + obj.c + obj.d;
  i = i + 1;
}
console.log(sum);
