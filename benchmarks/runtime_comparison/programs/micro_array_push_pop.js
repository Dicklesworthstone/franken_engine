var arr = [];
var i = 0;
while (i < 100000) {
  arr.push(i);
  arr.push(i + 1);
  arr.pop();
  i = i + 1;
}
console.log(arr.length);
