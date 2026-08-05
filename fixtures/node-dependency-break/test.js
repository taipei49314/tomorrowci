// Baseline: Node padStart works.
// Future node candidates remain pass unless we assert engines later.
const assert = require('assert');

const nodeMajor = Number(process.versions.node.split('.')[0]);
assert.ok(nodeMajor >= 18, `requires Node >= 18, got ${process.versions.node}`);
assert.strictEqual('x'.padStart(3, '0'), '00x');

// Simulated dependency-contract break under TOMORROWCI_DEP_MODE=latest_allowed
// (set by node adapter for non-locked modes).
if (process.env.TOMORROWCI_DEP_MODE === 'latest_allowed') {
  // Intentionally fail to prove dependency-axis FUTURE_FAIL + horizon.
  assert.fail('simulated dependency API break under latest_allowed mode');
}

console.log('ok');
