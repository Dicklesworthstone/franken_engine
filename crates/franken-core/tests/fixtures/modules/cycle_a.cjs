exports.ready = false;
const sibling = require('./cycle_b.cjs');
exports.seen = sibling.seen;
exports.ready = true;
console.log('cycle-a');
