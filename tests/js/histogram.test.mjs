// Tests for widgets/histogram.js against the UI-19 contract (LOG-03): earlierCut() finds a few
// stragglers far before a burst so the chart can leave them out, and chooseStep() keeps bars at least
// 6 px wide. Owned by SHARED (tests/js/**); the widget is LOGS'. Run: node --test tests/js/*.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import * as hg from '../../src/jwicket/static/js/widgets/histogram.js';

const MIN = 60000;
const T0 = Date.UTC(2026, 10, 24, 7, 0, 0);
const burst = (n, start, spanMs) => Array.from({ length: n }, (_, i) => start + Math.round((i * spanMs) / Math.max(1, n - 1)));

test('earlierCut: three stragglers two hours before a 10-minute burst are cut', () => {
  assert.equal(typeof hg.earlierCut, 'function', 'histogram.js exports earlierCut (LOG-03)');
  const stragglers = [T0, T0 + 1000, T0 + 2000];
  const main = burst(100, T0 + 120 * MIN, 10 * MIN);
  const cut = hg.earlierCut([...stragglers, ...main]);
  assert.equal(cut.earlier, 3);
  assert.ok(cut.clipAt > stragglers[2], `clipAt ${cut.clipAt} is after the stragglers`);
  assert.ok(cut.clipAt <= main[0], `clipAt ${cut.clipAt} keeps the whole burst`);
});

test('earlierCut: no cut under 20 times, or when the gap is under 60 % of the span', () => {
  assert.equal(typeof hg.earlierCut, 'function', 'histogram.js exports earlierCut (LOG-03)');
  const few = [T0, T0 + 1000, T0 + 2000, ...burst(16, T0 + 120 * MIN, 10 * MIN)];
  assert.equal(few.length, 19);
  assert.equal(hg.earlierCut(few).earlier, 0);
  // Gap of 5 min in a 15 min span (33 %): keep everything.
  const near = [T0, T0 + 1000, T0 + 2000, ...burst(100, T0 + 5 * MIN, 10 * MIN)];
  assert.equal(hg.earlierCut(near).earlier, 0);
  // An even spread has no gap at all.
  assert.equal(hg.earlierCut(burst(200, T0, 60 * MIN)).earlier, 0);
  assert.equal(hg.earlierCut([]).earlier, 0);
});

test('chooseStep keeps bars at least 6 px wide', () => {
  for (const widthPx of [60, 120, 390, 800, 1440]) {
    for (const spanMs of [10_000, MIN, 10 * MIN, 60 * MIN, 6 * 60 * MIN, 24 * 60 * MIN, 7 * 24 * 60 * MIN]) {
      const step = hg.chooseStep(spanMs, widthPx);
      assert.ok(step > 0, `${spanMs} ms over ${widthPx} px`);
      assert.ok((spanMs / step) * 6 <= widthPx, `${spanMs} ms over ${widthPx} px: step ${step} gives bars under 6 px`);
    }
  }
});
