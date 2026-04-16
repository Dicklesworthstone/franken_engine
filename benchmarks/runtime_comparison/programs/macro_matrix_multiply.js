var size = 40;
var a = [];
var b = [];
var i = 0;
while (i < size) {
  var rowA = [];
  var rowB = [];
  var j = 0;
  while (j < size) {
    rowA.push((i + j) % 7);
    rowB.push((i - j) % 5);
    j = j + 1;
  }
  a.push(rowA);
  b.push(rowB);
  i = i + 1;
}

var sum = 0;
var r = 0;
while (r < size) {
  var c = 0;
  while (c < size) {
    var k = 0;
    var acc = 0;
    while (k < size) {
      acc = acc + (a[r][k] * b[k][c]);
      k = k + 1;
    }
    sum = sum + acc;
    c = c + 1;
  }
  r = r + 1;
}

console.log(sum);
