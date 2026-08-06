'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { sortCopy } = require('../index.js');

describe('sortCopy', () => {
  it('returns a sorted copy', () => {
    assert.deepEqual(sortCopy([3, 1, 2]), [1, 2, 3]);
  });
});
