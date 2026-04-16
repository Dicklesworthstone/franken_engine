var queue = [];
var i = 0;
while (i < 100000) {
  queue.push(i);
  if (queue.length > 50) {
    queue.shift();
  }
  i = i + 1;
}

var sum = 0;
var j = 0;
while (j < queue.length) {
  sum = sum + queue[j];
  j = j + 1;
}

console.log(sum);
