var text = "";
var i = 0;
while (i < 5000) {
  text = text + "abcdefg";
  i = i + 1;
}

var target = "def";
var count = 0;
var idx = 0;
while (idx < text.length) {
  if (text.substr(idx, 3) === target) {
    count = count + 1;
  }
  idx = idx + 1;
}

console.log(count);
