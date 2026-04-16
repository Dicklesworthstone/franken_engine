var i = 0;
var acc = 0;
while (i < 500000) {
  acc = (acc ^ i) & 0xffff;
  i = i + 1;
}
console.log(acc);
