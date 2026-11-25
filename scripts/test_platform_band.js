/* Behaviour tests for the platform band (assets/platform-band.js), driven against the
   generated markup in a small DOM stand-in — no browser or npm dependency. Run:
     node scripts/test_platform_band.js
   Covers: hover opens; one top-level menu open at a time; the 220ms close; the side
   fly-out; the edge-flip (flips when it would cross the right edge, not otherwise); one
   fly-out at a time; and the keyboard path (Escape, ArrowRight, ArrowLeft). */
'use strict';
const assert = require('assert');
const { wireTswBand } = require('../assets/platform-band.js');

// ----- a minimal DOM stand-in: only what the handlers use -----
function matchSimple(el, simple) {         // 'tag.a.b' / '.a' / 'div'
  const parts = simple.split('.');
  const tag = parts[0];
  if (tag && el.tagName !== tag.toUpperCase()) return false;
  return parts.slice(1).every((c) => el.classList.contains(c));
}
function descendants(el, out) { el.children.forEach((c) => { out.push(c); descendants(c, out); }); return out; }
function selectAll(scope, selector) {
  const results = [];
  selector.split(',').forEach((partRaw) => {
    const part = partRaw.trim();
    let base = [scope], rel = false;
    const steps = part.split(/\s+/);
    steps.forEach((stepRaw, i) => {
      let step = stepRaw;
      if (step === ':scope') { rel = true; return; }
      if (step === '>') { rel = true; return; }
      let cand = [];
      base.forEach((b) => { (rel ? b.children : descendants(b, [])).forEach((n) => { if (matchSimple(n, step)) cand.push(n); }); });
      base = cand; rel = (steps[i + 1] === '>');
    });
    base.forEach((n) => { if (n !== scope && results.indexOf(n) < 0) results.push(n); });
  });
  return results;
}
class El {
  constructor(tag) {
    this.tagName = tag.toUpperCase(); this.children = []; this.parentElement = null;
    this._cls = new Set(); this._attr = {}; this._ev = {}; this._rect = { left: 0, right: 0 };
    this.type = ''; this.innerHTML = ''; this.focused = false;
    const self = this;
    this.classList = {
      add() { [].forEach.call(arguments, (c) => self._cls.add(c)); },
      remove() { [].forEach.call(arguments, (c) => self._cls.delete(c)); },
      contains: (c) => self._cls.has(c),
      toggle(c) { if (self._cls.has(c)) { self._cls.delete(c); return false; } self._cls.add(c); return true; },
    };
  }
  get className() { return [...this._cls].join(' '); }
  set className(v) { this._cls = new Set(String(v).split(/\s+/).filter(Boolean)); }
  setAttribute(k, v) { this._attr[k] = String(v); }
  getAttribute(k) { return k in this._attr ? this._attr[k] : null; }
  appendChild(c) { c.parentElement = this; this.children.push(c); return c; }
  insertBefore(c, ref) { c.parentElement = this; const i = ref ? this.children.indexOf(ref) : 0; this.children.splice(i < 0 ? 0 : i, 0, c); return c; }
  get firstChild() { return this.children[0] || null; }
  querySelector(sel) { return selectAll(this, sel)[0] || null; }
  querySelectorAll(sel) { return selectAll(this, sel); }
  closest(sel) { let n = this; while (n) { if (matchSimple(n, sel.replace(/^\./, '.'))) return n; n = n.parentElement; } return null; }
  contains(n) { while (n) { if (n === this) return true; n = n.parentElement; } return false; }
  getBoundingClientRect() { return this._rect; }
  focus() { this.focused = true; }
  addEventListener(t, fn) { (this._ev[t] = this._ev[t] || []).push(fn); }
  dispatchEvent(evt) { evt.target = evt.target || this; (this._ev[evt.type] || []).forEach((fn) => fn(evt)); }
}
function matchSimpleClosestFix() {}  // closest uses matchSimple via '.' prefix handled above

function ev(type, extra) { return Object.assign({ type, preventDefault() {}, stopPropagation() {} }, extra || {}); }

// ----- build the generated markup: two top-level items, the 2nd (Bookmarks) nested -----
function el(tag, cls, text) { const e = new El(tag); if (cls) e.className = cls; if (text) e.textContent = text; return e; }
function buildBar() {
  const bar = el('div', 'tsw-bar');
  const ul = el('ul', 'tsw-bar__list'); bar.appendChild(ul);
  function item(label, withGroup) {
    const li = el('li', 'tsw-bar__item');
    li.appendChild(el('a', 'tsw-bar__link', label));
    li.appendChild(el('button', 'tsw-bar__toggle'));
    const panel = el('div', 'tsw-bar__panel'); li.appendChild(panel);
    if (withGroup) {
      const g = el('div', 'tsw-bar__group'); panel.appendChild(g);
      g.appendChild(el('a', 'tsw-bar__mlink tsw-bar__mlink--parent', 'Vuln mgmt'));
      g.appendChild(el('button', 'tsw-bar__caret'));
      const fly = el('div', 'tsw-bar__flyout'); g.appendChild(fly);
      fly.appendChild(el('a', 'tsw-bar__mlink', 'CVE databases'));
      const g2 = el('div', 'tsw-bar__group'); panel.appendChild(g2);
      g2.appendChild(el('a', 'tsw-bar__mlink tsw-bar__mlink--parent', 'Advisories'));
      g2.appendChild(el('button', 'tsw-bar__caret'));
      g2.appendChild(el('div', 'tsw-bar__flyout'));
    } else {
      panel.appendChild(el('a', 'tsw-bar__mlink', 'Front page'));
    }
    ul.appendChild(li); return li;
  }
  return { bar, a: item('A', false), b: item('Bookmarks', true) };
}

function fakeWin(opts) {
  const timers = [];
  return {
    innerWidth: opts.innerWidth,
    matchMedia: (q) => ({ matches: q.indexOf('max-width') >= 0 ? !!opts.narrow : !!opts.fine }),
    setTimeout: (fn) => { timers.push(fn); return timers.length; },
    clearTimeout: () => {},
    _flush: () => { const t = timers.splice(0); t.forEach((fn) => fn()); },
  };
}
const fakeDoc = { createElement: (t) => new El(t), addEventListener() {} };

let ran = 0;
function test(name, fn) { fn(); ran++; }

// desktop (fine pointer, wide): hover opens, one at a time, 220ms close
test('hover opens, single-open, 220ms close', () => {
  const { bar, a, b } = buildBar();
  const win = fakeWin({ fine: true, narrow: false, innerWidth: 1280 });
  wireTswBand(bar, win, fakeDoc);
  a.dispatchEvent(ev('mouseenter'));
  assert.ok(a.classList.contains('tsw-open'), 'A opens on hover');
  assert.strictEqual(a.querySelector(':scope > .tsw-bar__toggle').getAttribute('aria-expanded'), 'true');
  b.dispatchEvent(ev('mouseenter'));
  assert.ok(b.classList.contains('tsw-open') && !a.classList.contains('tsw-open'), 'only one top-level open');
  b.dispatchEvent(ev('mouseleave'));
  assert.ok(b.classList.contains('tsw-open'), 'still open before the 220ms timer fires');
  win._flush();
  assert.ok(!b.classList.contains('tsw-open'), 'closed after the timer');
});

// side fly-out, edge-flip, one fly-out at a time
test('fly-out opens, flips at the right edge, one at a time', () => {
  const { bar, b } = buildBar();
  const win = fakeWin({ fine: true, narrow: false, innerWidth: 1280 });
  wireTswBand(bar, win, fakeDoc);
  const groups = b.querySelectorAll('.tsw-bar__group');
  const g1 = groups[0], g2 = groups[1];
  g1.querySelector(':scope > .tsw-bar__flyout')._rect = { left: 600, right: 850 };  // fits in 1280
  g1.dispatchEvent(ev('mouseenter'));
  assert.ok(g1.classList.contains('tsw-open') && !g1.classList.contains('tsw-flip'), 'opens right when it fits');
  g2.querySelector(':scope > .tsw-bar__flyout')._rect = { left: 1100, right: 1340 };  // overflows 1280
  g2.dispatchEvent(ev('mouseenter'));
  assert.ok(g2.classList.contains('tsw-flip'), 'flips left near the right edge');
  assert.ok(!g1.classList.contains('tsw-open'), 'opening a second fly-out closes the first');
});

// keyboard: ArrowRight opens the fly-out, ArrowLeft closes it, Escape closes the panel
test('keyboard: ArrowRight / ArrowLeft / Escape', () => {
  const { bar, b } = buildBar();
  const win = fakeWin({ fine: true, narrow: false, innerWidth: 1280 });
  wireTswBand(bar, win, fakeDoc);
  const g1 = b.querySelector('.tsw-bar__group');
  const parent = g1.querySelector('.tsw-bar__mlink--parent');
  bar.dispatchEvent(ev('keydown', { key: 'ArrowRight', target: parent }));
  assert.ok(g1.classList.contains('tsw-open'), 'ArrowRight opens the fly-out');
  bar.dispatchEvent(ev('keydown', { key: 'ArrowLeft', target: g1.querySelector('.tsw-bar__caret') }));
  assert.ok(!g1.classList.contains('tsw-open'), 'ArrowLeft closes the fly-out');
  b.classList.add('tsw-open');
  bar.dispatchEvent(ev('keydown', { key: 'Escape', target: b.querySelector(':scope > .tsw-bar__toggle') }));
  assert.ok(!b.classList.contains('tsw-open'), 'Escape closes the open panel');
});

// coarse pointer / phone: hover does nothing; the toggle button opens the accordion
test('coarse pointer: buttons drive it, hover ignored', () => {
  const { bar, a } = buildBar();
  const win = fakeWin({ fine: false, narrow: true, innerWidth: 390 });
  wireTswBand(bar, win, fakeDoc);
  a.dispatchEvent(ev('mouseenter'));
  assert.ok(!a.classList.contains('tsw-open'), 'hover ignored on a coarse pointer');
  a.querySelector(':scope > .tsw-bar__toggle').dispatchEvent(ev('click'));
  assert.ok(a.classList.contains('tsw-open'), 'the toggle button opens the section');
});

console.log('platform-band behaviour tests: ' + ran + ' of ' + ran + ' pass');
