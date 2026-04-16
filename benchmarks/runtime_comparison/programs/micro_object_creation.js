var i = 0;
var sum = 0;
while (i < 200000) {
  var obj = { a: i, b: i + 1, c: i + 2 };
  sum = sum + obj.a;
  i = i + 1;
}
console.log(sum);
