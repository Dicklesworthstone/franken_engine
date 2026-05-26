const base = 10;
const doubled = base * 2;
const items = [base, doubled, base + doubled];
let total = 0;
for (const item of items) {
    total = total + item;
}
total;
