var i = 0;
var sum = 0;
var payload = [];
var j = 0;
while (j < 100) {
  payload.push({ idx: j, value: j * 2 });
  j = j + 1;
}

while (i < 5000) {
  var text = JSON.stringify(payload);
  var out = JSON.parse(text);
  sum = sum + out.length;
  i = i + 1;
}
console.log(sum);
