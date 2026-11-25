/* Behaviour tests for the platform band (assets/platform-band.js), driven against the
   generated markup in a small DOM stand-in (no browser or npm dependency). Run:
     node scripts/test_platform_band.js
   Covers: hover opens; one top-level menu open at a time; the 220ms close; the side
   fly-out; the edge-flip (flips when it would cross the right edge, not otherwise); one
   fly-out at a time; the keyboard path (Escape, ArrowRight, ArrowLeft); and a plain-link
   top item (no menu) that closes open menus on hover/focus and never opens itself. */
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
    this._cls = new Set(); this._attr = {}; this._ev = {}; this._rect = { left: 0, right: 0, top: 0, bottom: 0 };
    this.style = {};
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

// ----- build the generated markup: a plain item A, and Bookmarks nested THREE levels
// (item > panel > category > fly-out > subsection > fly-out > external leaves) -----
function el(tag, cls, text) { const e = new El(tag); if (cls) e.className = cls; if (text) e.textContent = text; return e; }
function buildBar() {
  const bar = el('div', 'tsw-bar');
  const ul = el('ul', 'tsw-bar__list'); bar.appendChild(ul);
  function topItem(label) {
    const li = el('li', 'tsw-bar__item');
    li.appendChild(el('a', 'tsw-bar__link', label));
    li.appendChild(el('button', 'tsw-bar__toggle'));
    const panel = el('div', 'tsw-bar__panel'); li.appendChild(panel);
    ul.appendChild(li); return { li, panel };
  }
  function group(label) {
    const g = el('div', 'tsw-bar__group');
    g.appendChild(el('a', 'tsw-bar__mlink tsw-bar__mlink--parent', label));
    g.appendChild(el('button', 'tsw-bar__caret'));
    const fly = el('div', 'tsw-bar__flyout'); g.appendChild(fly);
    return { g, fly };
  }
  function leaf(label, ext) { return el('a', ext ? 'tsw-bar__mlink tsw-bar__mlink--ext' : 'tsw-bar__mlink', label); }

  const A = topItem('A'); A.panel.appendChild(leaf('Front page', false));
  const B = topItem('Bookmarks');
  const cat1 = group('Cat1'); B.panel.appendChild(cat1.g);
  const sub1 = group('Sub1'); cat1.fly.appendChild(sub1.g);          // third level
  sub1.fly.appendChild(leaf('NVD', true)); sub1.fly.appendChild(leaf('OWASP', true));
  cat1.fly.appendChild(leaf('Direct leaf', false));
  const cat2 = group('Cat2'); B.panel.appendChild(cat2.g);
  cat2.fly.appendChild(leaf('Other', true));
  return { bar, a: A.li, b: B.li, cat1: cat1.g, sub1: sub1.g, cat2: cat2.g };
}

function fakeWin(opts) {
  const timers = [];
  return {
    innerWidth: opts.innerWidth,
    innerHeight: opts.innerHeight || 1000,
    matchMedia: (q) => ({ matches: q.indexOf('max-width') >= 0 ? !!opts.narrow : !!opts.fine }),
    setTimeout: (fn) => { timers.push(fn); return timers.length; },
    clearTimeout: () => {},
    _flush: () => { const t = timers.splice(0); t.forEach((fn) => fn()); },
  };
}
const fakeDoc = { createElement: (t) => new El(t), addEventListener() {} };
function fits(g) { g.querySelector(':scope > .tsw-bar__flyout')._rect = { left: 200, right: 420, top: 100, bottom: 300 }; }

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

// three levels: a subsection opens WITHOUT closing its category; a second category closes the first
test('three levels: nested open keeps the ancestor, siblings close', () => {
  const { bar, cat1, sub1, cat2 } = buildBar();
  const win = fakeWin({ fine: true, narrow: false, innerWidth: 1280 });
  wireTswBand(bar, win, fakeDoc);
  [cat1, sub1, cat2].forEach(fits);
  cat1.dispatchEvent(ev('mouseenter'));
  sub1.dispatchEvent(ev('mouseenter'));
  assert.ok(cat1.classList.contains('tsw-open'), 'the category stays open while its subsection opens');
  assert.ok(sub1.classList.contains('tsw-open'), 'the subsection (third level) opens');
  cat2.dispatchEvent(ev('mouseenter'));
  assert.ok(cat2.classList.contains('tsw-open'), 'the sibling category opens');
  assert.ok(!cat1.classList.contains('tsw-open') && !sub1.classList.contains('tsw-open'),
    'opening a sibling category closes the first category and its open subsection');
});

// per-level flip at the right edge, and vertical clamp that stops at the top of the viewport
test('fly-out flips at the right edge and clamps on screen, per level', () => {
  const { bar, cat1, sub1 } = buildBar();
  const win = fakeWin({ fine: true, narrow: false, innerWidth: 1280, innerHeight: 800 });
  wireTswBand(bar, win, fakeDoc);
  const cfly = cat1.querySelector(':scope > .tsw-bar__flyout');
  cfly._rect = { left: 300, right: 520, top: 80, bottom: 300 }; // fully on screen
  cat1.dispatchEvent(ev('mouseenter'));
  assert.ok(cat1.classList.contains('tsw-open') && !cat1.classList.contains('tsw-flip'), 'category opens right when it fits');
  assert.strictEqual(cfly.style.top, '', 'a fly-out that fits is not repositioned');
  const sfly = sub1.querySelector(':scope > .tsw-bar__flyout');
  sfly._rect = { left: 1100, right: 1360, top: 80, bottom: 900 }; // off the right edge AND taller than 800
  sub1.dispatchEvent(ev('mouseenter'));
  assert.ok(sub1.classList.contains('tsw-flip'), 'the subsection flyout flips left near the right edge');
  assert.strictEqual(sfly.style.top, '8px', 'a too-tall fly-out is pinned to the top of the viewport, not above it');
  assert.strictEqual(sfly.style.overflowY, 'auto', 'and scrolls inside itself');
  assert.ok(cat1.classList.contains('tsw-open'), 'flipping/clamping the subsection does not close the category');
});

// keyboard: ArrowRight opens, ArrowLeft closes, Escape walks back out deepest-first
test('keyboard: ArrowRight / ArrowLeft / Escape deepest-first', () => {
  const { bar, b, cat1, sub1 } = buildBar();
  const win = fakeWin({ fine: true, narrow: false, innerWidth: 1280 });
  wireTswBand(bar, win, fakeDoc);
  [cat1, sub1].forEach(fits);
  b.classList.add('tsw-open');
  bar.dispatchEvent(ev('keydown', { key: 'ArrowRight', target: cat1.querySelector('.tsw-bar__mlink--parent') }));
  assert.ok(cat1.classList.contains('tsw-open'), 'ArrowRight opens the category fly-out');
  bar.dispatchEvent(ev('keydown', { key: 'ArrowRight', target: sub1.querySelector('.tsw-bar__mlink--parent') }));
  assert.ok(sub1.classList.contains('tsw-open'), 'ArrowRight opens the subsection fly-out');
  bar.dispatchEvent(ev('keydown', { key: 'Escape', target: sub1.querySelector(':scope > .tsw-bar__caret') }));
  assert.ok(!sub1.classList.contains('tsw-open') && cat1.classList.contains('tsw-open'), 'Escape closes the subsection first');
  bar.dispatchEvent(ev('keydown', { key: 'Escape', target: cat1.querySelector(':scope > .tsw-bar__caret') }));
  assert.ok(!cat1.classList.contains('tsw-open'), 'Escape then closes the category');
  bar.dispatchEvent(ev('keydown', { key: 'Escape', target: b.querySelector(':scope > .tsw-bar__toggle') }));
  assert.ok(!b.classList.contains('tsw-open'), 'Escape then closes the panel');
  bar.dispatchEvent(ev('keydown', { key: 'ArrowLeft', target: cat1.querySelector('.tsw-bar__mlink--parent') }));  // no throw when nothing open
});

// coarse pointer / phone: hover does nothing; buttons drive the accordion, nested caret keeps the category open
test('coarse pointer: buttons drive the accordion', () => {
  const { bar, a, cat1, sub1 } = buildBar();
  const win = fakeWin({ fine: false, narrow: true, innerWidth: 390 });
  wireTswBand(bar, win, fakeDoc);
  a.dispatchEvent(ev('mouseenter'));
  assert.ok(!a.classList.contains('tsw-open'), 'hover ignored on a coarse pointer');
  a.querySelector(':scope > .tsw-bar__toggle').dispatchEvent(ev('click'));
  assert.ok(a.classList.contains('tsw-open'), 'the toggle button opens the section');
  cat1.querySelector(':scope > .tsw-bar__caret').dispatchEvent(ev('click'));
  sub1.querySelector(':scope > .tsw-bar__caret').dispatchEvent(ev('click'));
  assert.ok(cat1.classList.contains('tsw-open') && sub1.classList.contains('tsw-open'),
    'the nested caret opens the subsection inline without closing the category');
});

// short + wide viewport (phone held sideways): the OR'd narrow condition matches on height, so
// even with a fine pointer the band uses the accordion - hover is ignored and the button opens it
test('short viewport uses the accordion even with a fine pointer', () => {
  const { bar, a } = buildBar();
  const win = fakeWin({ fine: true, narrow: true, innerWidth: 844, innerHeight: 390 });
  wireTswBand(bar, win, fakeDoc);
  a.dispatchEvent(ev('mouseenter'));
  assert.ok(!a.classList.contains('tsw-open'), 'hover is ignored when the viewport is short, even with a fine pointer');
  a.querySelector(':scope > .tsw-bar__toggle').dispatchEvent(ev('click'));
  assert.ok(a.classList.contains('tsw-open'), 'the toggle button opens the section (accordion)');
});

// a top-level item with no menu is a plain link: no toggle, no panel; hovering or focusing it
// closes any open menu, it never opens itself, and the keyboard handlers do not assume a panel.
// A "menu": [] item and a no-"menu" item both reach the renderer as this same plain shape.
test('plain-link top item: no toggle/panel, closes menus on hover and focus, never opens', () => {
  const bar = el('div', 'tsw-bar');
  const ul = el('ul', 'tsw-bar__list'); bar.appendChild(ul);
  const home = el('li', 'tsw-bar__item tsw-bar__item--plain');       // Home: a plain link
  const homeLink = el('a', 'tsw-bar__link', 'Home'); home.appendChild(homeLink); ul.appendChild(home);
  const mi = el('li', 'tsw-bar__item');                              // a normal menu item
  mi.appendChild(el('a', 'tsw-bar__link', 'Library'));
  mi.appendChild(el('button', 'tsw-bar__toggle'));
  mi.appendChild(el('div', 'tsw-bar__panel')); ul.appendChild(mi);
  const win = fakeWin({ fine: true, narrow: false, innerWidth: 1280 });
  wireTswBand(bar, win, fakeDoc);
  assert.strictEqual(home.querySelector(':scope > .tsw-bar__toggle'), null, 'a plain item has no toggle');
  assert.strictEqual(home.querySelector(':scope > .tsw-bar__panel'), null, 'a plain item has no panel');
  mi.dispatchEvent(ev('mouseenter'));
  assert.ok(mi.classList.contains('tsw-open'), 'the menu item opens on hover');
  home.dispatchEvent(ev('mouseenter'));
  assert.ok(!mi.classList.contains('tsw-open'), 'hovering the plain link closes the open menu');
  assert.ok(!home.classList.contains('tsw-open'), 'the plain link never opens itself');
  mi.dispatchEvent(ev('mouseenter'));
  assert.ok(mi.classList.contains('tsw-open'), 'the menu item opens again');
  homeLink.dispatchEvent(ev('focus'));
  assert.ok(!mi.classList.contains('tsw-open'), 'focusing the plain link closes the open menu');
  bar.dispatchEvent(ev('keydown', { key: 'ArrowDown', target: homeLink }));  // no panel to assume: must not throw
  bar.dispatchEvent(ev('keydown', { key: 'Escape', target: homeLink }));     // nothing open: must not throw
  assert.ok(!home.classList.contains('tsw-open'), 'keyboard on the plain link leaves it closed');
});

console.log('platform-band behaviour tests: ' + ran + ' of ' + ran + ' pass');
