var arr = [];
var i = 0;
while (i < 1000) {
  arr.push(i);
  i = i + 1;
}

var sum = 0;
var j = 0;
while (j < arr.length) {
  sum = sum + arr[j];
  j = j + 1;
}

console.log(sum);
