// Tests for widgets/palette.js against the UI-19 contract (SL-10, SH-05): rank() orders items by match
// tier, then recent use, then group, then name length and label. Owned by SHARED (tests/js/**); the
// palette is SHELL's. Run: node --test tests/js/*.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import * as pal from '../../src/jwicket/static/js/widgets/palette.js';

const ITEMS = [
  { id: 'view:logs', name: 'Logs', label: 'Go to Logs', group: 'Views' },
  { id: 'view:sessions', name: 'Sessions', label: 'Go to Sessions', group: 'Views' },
  { id: 'policy:root|zone|trust>untrust|allow-web', label: 'allow-web', detail: 'trust → untrust', keywords: 'permit corp-lan', group: 'Policies' },
  { id: 'policy:root|zone|trust>untrust|allow-logging', label: 'allow-logging', detail: 'trust → untrust', group: 'Policies' },
  { id: 'zone:web', label: 'web', group: 'Zones' },
  { id: 'action:refresh', label: 'Refresh', group: 'Actions' },
];

const need = () => assert.equal(typeof pal.rank, 'function', 'palette.js exports rank (SL-10)');
const ids = (text, opts) => pal.rank(ITEMS, text, opts).map((r) => r.item.id);
const tierOf = (text, id) => (pal.rank(ITEMS, text).find((r) => r.item.id === id) || {}).tier;

test('GROUP_ORDER and fuzzy stay exported', () => {
  assert.deepEqual(pal.GROUP_ORDER, ['Look up', 'Views', 'Scopes', 'Recent filters', 'Actions', 'Policies', 'Zones', 'Addresses', 'Applications', 'Filters']);
  assert.equal(typeof pal.fuzzy, 'function');
});

test('rank: tiers 0 to 5, computed on name (default label), case-insensitive', () => {
  need();
  assert.equal(tierOf('logs', 'view:logs'), 0, 'exact');
  assert.equal(tierOf('WEB', 'zone:web'), 0, 'exact, any case');
  assert.equal(tierOf('lo', 'view:logs'), 1, 'prefix');
  assert.equal(tierOf('web', 'policy:root|zone|trust>untrust|allow-web'), 2, 'word-start substring');
  assert.equal(tierOf('ow', 'policy:root|zone|trust>untrust|allow-web'), 3, 'substring');
  assert.equal(tierOf('aw', 'policy:root|zone|trust>untrust|allow-web'), 4, 'initials');
  assert.equal(tierOf('web untrust', 'policy:root|zone|trust>untrust|allow-web'), 5, 'every word in label, detail or keywords');
  assert.equal(tierOf('corp-lan', 'policy:root|zone|trust>untrust|allow-web'), 5, 'keywords');
  assert.equal(tierOf('zzz', 'view:logs'), undefined, 'no match is left out');
  assert.deepEqual(ids('zzz'), []);
});

test('rank: "lo" puts Go to Logs first; order is tier, recent, group, shorter name, label', () => {
  need();
  assert.equal(ids('lo')[0], 'view:logs');
  // Same tier (prefix "allow"): shorter name first.
  assert.deepEqual(ids('allow'), ['policy:root|zone|trust>untrust|allow-web', 'policy:root|zone|trust>untrust|allow-logging']);
  // Recent use breaks the tie before the group and the length.
  assert.deepEqual(ids('allow', { recent: ['policy:root|zone|trust>untrust|allow-logging'] }), ['policy:root|zone|trust>untrust|allow-logging', 'policy:root|zone|trust>untrust|allow-web']);
  // The exact zone "web" (tier 0) beats the policy (tier 2), whatever the group order.
  assert.equal(ids('web')[0], 'zone:web');
  // Same tier, different groups: GROUP_ORDER (Views before Actions before Policies).
  const same = [
    { id: 'p', label: 'refresh-policy', group: 'Policies' },
    { id: 'a', label: 'refresh-all', group: 'Actions' },
  ];
  assert.deepEqual(pal.rank(same, 'refresh').map((r) => r.item.id), ['a', 'p']);
});

test('rank: hits are label indices when name is the label, else none; NFC', () => {
  need();
  const hit = (text, id) => pal.rank(ITEMS, text).find((r) => r.item.id === id).hits;
  assert.deepEqual(hit('web', 'policy:root|zone|trust>untrust|allow-web'), [6, 7, 8]);
  assert.deepEqual(hit('ow', 'policy:root|zone|trust>untrust|allow-web'), [3, 4]);
  assert.deepEqual(hit('lo', 'view:logs'), [], 'name differs from label');
  const cafe = [{ id: 'z', label: 'café', group: 'Zones' }];
  assert.equal(pal.rank(cafe, 'café')[0].tier, 0, 'compared in NFC');
});
