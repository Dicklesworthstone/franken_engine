var acc = 0;
var i = 0;
while (i < 100000) {
  acc = acc + (i % 7);
  i = i + 1;
}
console.log(acc);
