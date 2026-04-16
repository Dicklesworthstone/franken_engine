var i = 1;
var acc = 0;
while (i < 500000) {
  acc = acc + (i % 7);
  i = i + 1;
}
console.log(acc);
