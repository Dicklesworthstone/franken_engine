let sum = 0;
for (let i = 0; i < 1000; i += 1) {
  sum += i;
}

if (typeof process !== "undefined") {
  console.log(sum);
}

sum;
