var limit = 100000;
var flags = [];
var i = 0;
while (i <= limit) {
  flags[i] = 1;
  i = i + 1;
}
flags[0] = 0;
flags[1] = 0;

var p = 2;
while (p * p <= limit) {
  if (flags[p]) {
    var m = p * p;
    while (m <= limit) {
      flags[m] = 0;
      m = m + p;
    }
  }
  p = p + 1;
}

var count = 0;
i = 2;
while (i <= limit) {
  if (flags[i]) {
    count = count + 1;
  }
  i = i + 1;
}
console.log(count);
