const sibling = require('./cycle_a.cjs');
exports.seen = sibling.ready;
console.log('cycle-b');
