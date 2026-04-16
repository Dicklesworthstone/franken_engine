var nodes = [];
var i = 0;
while (i < 2000) {
  nodes.push({ left: (i * 2) + 1, right: (i * 2) + 2, value: i });
  i = i + 1;
}

var sum = 0;
var stack = [0];
while (stack.length > 0) {
  var idx = stack.pop();
  if (idx >= nodes.length) {
    continue;
  }
  var node = nodes[idx];
  sum = sum + node.value;
  if (node.left < nodes.length) {
    stack.push(node.left);
  }
  if (node.right < nodes.length) {
    stack.push(node.right);
  }
}

console.log(sum);
