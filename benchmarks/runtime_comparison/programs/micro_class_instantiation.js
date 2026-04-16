class Counter {
  constructor(value) {
    this.value = value;
  }
  bump() {
    this.value = this.value + 1;
    return this.value;
  }
}

var i = 0;
var sum = 0;
while (i < 100000) {
  var c = new Counter(i);
  sum = sum + c.bump();
  i = i + 1;
}
console.log(sum);
