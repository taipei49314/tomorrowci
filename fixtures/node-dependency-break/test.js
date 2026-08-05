// Deterministic fixture: requires left-pad API at exact locked version behavior.
const leftPad = require('left-pad');
const assert = require('assert');

assert.strictEqual(leftPad('x', 3, '0'), '00x');
console.log('ok');
