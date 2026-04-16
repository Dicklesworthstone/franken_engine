var seed = 123456789;
function next() {
  seed = (seed * 1664525 + 1013904223) >>> 0;
  return seed;
}

var i = 0;
var checksum = 0;
while (i < 200) {
  var arr = [];
  var j = 0;
  while (j < 2000) {
    arr.push(next() % 100000);
    j = j + 1;
  }
  arr.sort(function (a, b) {
    return a - b;
  });
  checksum = checksum + arr[0] + arr[arr.length - 1];
  i = i + 1;
}
console.log(checksum);
