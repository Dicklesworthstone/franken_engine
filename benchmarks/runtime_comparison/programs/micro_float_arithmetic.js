var i = 0;
var acc = 0.0;
while (i < 1000000) {
  acc = acc + (i * 0.5) / 3.14159;
  acc = acc * 1.0000001 - 0.0000001;
  i = i + 1;
}
console.log(acc);
