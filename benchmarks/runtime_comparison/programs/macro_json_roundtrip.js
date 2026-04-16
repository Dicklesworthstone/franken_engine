var i = 0;
var data = [];
while (i < 2000) {
  data.push({ idx: i, value: "v" + i });
  i = i + 1;
}

var j = 0;
var sum = 0;
while (j < 200) {
  var text = JSON.stringify(data);
  var parsed = JSON.parse(text);
  sum = sum + parsed.length;
  j = j + 1;
}

console.log(sum);
