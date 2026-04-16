var blocks = [];
var i = 0;
while (i < 2000) {
  var chunk = [];
  var j = 0;
  while (j < 200) {
    chunk.push({ idx: j, payload: "x" + j });
    j = j + 1;
  }
  blocks.push(chunk);
  i = i + 1;
}

var sum = 0;
var a = 0;
while (a < blocks.length) {
  sum = sum + blocks[a].length;
  a = a + 1;
}

console.log(sum);
