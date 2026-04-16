var i = 0;
var count = 0;
while (i < 500000) {
  if (i < 250000) {
    count = count + 1;
  }
  if (i >= 100000 && i <= 400000) {
    count = count + 1;
  }
  i = i + 1;
}
console.log(count);
