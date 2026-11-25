// Tests for src/jwicket/static/js/brand.js: the colour schemes with Obsidian & Phosphor as the default,
// and the emblem built through dom.svg() (no HTML parsing). A minimal fake document stands in for the
// browser. tests/test_static.py checks that index.html, logo.svg and brand.js draw the same emblem.
// Run: node --test tests/js/*.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import * as brand from '../../src/jwicket/static/js/brand.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

class FakeElement {
  constructor(tag, ns) {
    this.tagName = tag;
    this.namespaceURI = ns;
    this.nodeType = 1;
    this.attributes = new Map();
    this.childNodes = [];
    this.dataset = {};
  }
  setAttribute(k, v) {
    this.attributes.set(k, String(v));
  }
  getAttribute(k) {
    return this.attributes.has(k) ? this.attributes.get(k) : null;
  }
  append(...nodes) {
    this.childNodes.push(...nodes);
  }
}

globalThis.document = {
  createElement: () => {
    throw new Error('the emblem is SVG only');
  },
  createElementNS: (ns, tag) => new FakeElement(tag, ns),
  createTextNode: (data) => ({ nodeType: 3, data: String(data) }),
};

test('schemes: Obsidian & Phosphor first and the default; HPE and Nordic Steel stay selectable', () => {
  assert.deepEqual(brand.SCHEMES.map((s) => s.id), ['obsidian', 'hpe', 'nordic']);
  assert.equal(brand.DEFAULT_SCHEME, 'obsidian');
  assert.equal(brand.SCHEMES[0].label, 'Obsidian & Phosphor');
  assert.match(brand.SCHEMES[0].detail, /default/i, 'the picker and palette say which one is the default');
  for (const s of brand.SCHEMES.slice(1)) assert.doesNotMatch(s.detail, /default/i, s.id);
});

test('schemeId: nothing stored or an unknown value gets the default; a stored choice is kept', () => {
  assert.equal(brand.schemeId(null), 'obsidian', 'first visit (localStorage.getItem returns null)');
  assert.equal(brand.schemeId(undefined), 'obsidian', 'no data-scheme attribute');
  assert.equal(brand.schemeId(''), 'obsidian');
  assert.equal(brand.schemeId('cricket'), 'obsidian', 'an unknown value');
  assert.equal(brand.schemeId('HPE'), 'obsidian', 'ids are exact');
  assert.equal(brand.schemeId('nordic'), 'nordic');
  assert.equal(brand.schemeId('hpe'), 'hpe');
  assert.equal(brand.schemeId('obsidian'), 'obsidian');
});

test('logoMark: a decorative SVG of the Sentinel Gate emblem, colours left to CSS classes', () => {
  const el = brand.logoMark();
  assert.equal(el.tagName, 'svg');
  assert.equal(el.namespaceURI, SVG_NS);
  assert.equal(el.getAttribute('class'), 'logo-mark');
  assert.equal(el.getAttribute('viewBox'), '15 13 236 236');
  assert.equal(el.getAttribute('aria-hidden'), 'true');
  assert.equal(el.getAttribute('focusable'), 'false');
  const parts = el.childNodes.map((c) => `${c.tagName}.${c.getAttribute('class')}`);
  assert.deepEqual(parts, [
    'polygon.lg-frame',
    'polygon.lg-j',
    'rect.lg-acc',
    'rect.lg-acc',
    'rect.lg-acc',
    'polygon.lg-acc',
    'polygon.lg-acc',
    'polyline.lg-acc-stroke',
  ]);
  for (const c of el.childNodes) {
    assert.equal(c.namespaceURI, SVG_NS);
    assert.equal(c.getAttribute('style'), null, 'no inline style (CSP)');
    assert.equal(c.getAttribute('fill') === null || c.getAttribute('fill') === 'none', true, 'no colour in the markup');
    assert.equal(c.getAttribute('stroke'), null, 'no colour in the markup');
  }
  const svgText = JSON.stringify(brand.EMBLEM_PARTS);
  assert.doesNotMatch(svgText, /stump|bail/, 'the cricket-wicket mark is gone');
});

test('logoMark: attributes add to the <svg>, for nesting in another drawing', () => {
  const el = brand.logoMark({ class: 'logo-mark fd-mark', x: 10, y: 4, width: 18, height: 18 });
  assert.equal(el.getAttribute('class'), 'logo-mark fd-mark');
  assert.equal(el.getAttribute('width'), '18');
  assert.equal(el.getAttribute('x'), '10');
  assert.equal(el.getAttribute('viewBox'), '15 13 236 236');
  assert.equal(el.getAttribute('aria-hidden'), 'true');
  assert.equal(el.childNodes.length, 8);
});
