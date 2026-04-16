var obj = { a: 0, b: 0, c: 0 };
var i = 0;
while (i < 200000) {
  obj.a = i;
  obj.b = i + 1;
  obj.c = i + 2;
  i = i + 1;
}
console.log(obj.a + obj.b + obj.c);
