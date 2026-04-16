var i = 0;
var sum = 0;
while (i < 500000) {
  if ((i & 1) === 0) {
    sum = sum + i;
  } else {
    sum = sum - i;
  }
  i = i + 1;
}
console.log(sum);
