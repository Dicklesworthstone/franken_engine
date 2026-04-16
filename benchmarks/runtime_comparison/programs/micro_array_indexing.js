var arr = [1, 2, 3, 4, 5, 6, 7, 8];
var i = 0;
var sum = 0;
while (i < 500000) {
  sum = sum + arr[0] + arr[3] + arr[7];
  i = i + 1;
}
console.log(sum);
