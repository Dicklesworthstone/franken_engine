var i = 0;
var sum = 0;
while (i < 200000) {
  try {
    if ((i & 127) === 0) {
      throw i;
    }
    sum = sum + i;
  } catch (err) {
    sum = sum + err;
  }
  i = i + 1;
}
console.log(sum);
