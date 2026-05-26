const seed = 7;
const scaled = seed * 6;
const parts = [seed, scaled, seed + scaled];
let acc = 0;
for (const p of parts) {
    acc = acc + p;
}
acc;
