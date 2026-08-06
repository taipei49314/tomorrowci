'use strict';

// Array.prototype.toSorted is available in Node 20+.
// Baseline Node 20 passes; Node 18 fails with TypeError.
function sortCopy(arr) {
  return arr.toSorted((a, b) => a - b);
}

module.exports = { sortCopy };
