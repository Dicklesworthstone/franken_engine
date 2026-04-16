var nodes = [];
var i = 0;
while (i < 1000) {
  nodes.push({ id: i, edges: [] });
  i = i + 1;
}

var j = 0;
while (j < nodes.length) {
  if (j + 1 < nodes.length) {
    nodes[j].edges.push(nodes[j + 1]);
  }
  if (j + 2 < nodes.length) {
    nodes[j].edges.push(nodes[j + 2]);
  }
  j = j + 1;
}

var count = 0;
var k = 0;
while (k < nodes.length) {
  count = count + nodes[k].edges.length;
  k = k + 1;
}

console.log(count);
