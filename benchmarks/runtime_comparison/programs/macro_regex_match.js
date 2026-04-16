var pattern = /fox\d+bar/;
var i = 0;
var hits = 0;
while (i < 500000) {
  var text = "quick" + i + "fox" + i + "bar" + (i % 7);
  if (pattern.test(text)) {
    hits = hits + 1;
  }
  i = i + 1;
}
console.log(hits);
