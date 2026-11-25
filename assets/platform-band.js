/* Platform band behaviour, extracted into one function so it can be driven against the
   generated markup in a DOM stand-in (scripts/test_platform_band.js). In a browser the UMD
   wrapper at the bottom finds the band and wires it; under Node it is exported, not run.

   wireTswBand(bar, win, doc): bar is the <div class="tsw-bar">; win supplies matchMedia /
   innerWidth / setTimeout / clearTimeout; doc supplies createElement / addEventListener.
   Desktop (fine pointer): a top-level menu opens on hover and stays while the pointer is in
   its panel; the toggle button (aria-expanded) opens it for keyboard and click; a Bookmarks
   category opens a side fly-out that flips left when it would cross the right edge. Close
   waits 220ms; one fly-out at a time. Phones and coarse pointers use the buttons. */
function wireTswBand(bar, win, doc) {
  win = win || window;
  doc = doc || document;
  var fine = win.matchMedia('(hover: hover) and (pointer: fine)');
  var narrow = win.matchMedia('(max-width: 760px)');
  var CLOSE_MS = 220;
  var timer = null;
  function cancel() { if (timer) { win.clearTimeout(timer); timer = null; } }
  function setExp(el, v) {
    var b = el.querySelector(':scope > .tsw-bar__toggle, :scope > .tsw-bar__caret');
    if (b) { b.setAttribute('aria-expanded', v ? 'true' : 'false'); }
  }
  function closeGroups(root, except) {
    [].forEach.call(root.querySelectorAll('.tsw-bar__group.tsw-open'), function (g) {
      if (g !== except) { g.classList.remove('tsw-open', 'tsw-flip'); setExp(g, false); }
    });
  }
  function closeItem(it) { it.classList.remove('tsw-open'); setExp(it, false); closeGroups(it, null); }
  function closeAll() { items.forEach(closeItem); }
  function openItem(it) {
    items.forEach(function (o) { if (o !== it) { closeItem(o); } });
    it.classList.add('tsw-open'); setExp(it, true);
  }
  function openGroup(g) {
    closeGroups(bar, g);
    g.classList.add('tsw-open'); g.classList.remove('tsw-flip'); setExp(g, true);
    var fly = g.querySelector(':scope > .tsw-bar__flyout');
    if (fly && !narrow.matches) {
      var r = fly.getBoundingClientRect();
      if (r.right > win.innerWidth - 8) { g.classList.add('tsw-flip'); }
    }
  }

  var menuBtn = doc.createElement('button');
  menuBtn.type = 'button';
  menuBtn.className = 'tsw-bar__menubtn';
  menuBtn.setAttribute('aria-expanded', 'false');
  menuBtn.setAttribute('aria-label', 'Platform menu');
  var burger = doc.createElement('span');
  burger.className = 'tsw-bar__burger';
  burger.setAttribute('aria-hidden', 'true');
  menuBtn.appendChild(burger);
  bar.insertBefore(menuBtn, bar.firstChild);
  menuBtn.addEventListener('click', function () {
    var open = bar.classList.toggle('tsw-bar--open');
    menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
  });

  var items = [].slice.call(bar.querySelectorAll('.tsw-bar__item'));
  items.forEach(function (it) {
    it.addEventListener('mouseenter', function () { if (fine.matches && !narrow.matches) { cancel(); openItem(it); } });
    it.addEventListener('mouseleave', function () { if (fine.matches && !narrow.matches) { cancel(); timer = win.setTimeout(function () { closeItem(it); }, CLOSE_MS); } });
  });
  [].forEach.call(bar.querySelectorAll('.tsw-bar__group'), function (g) {
    g.addEventListener('mouseenter', function () { if (fine.matches && !narrow.matches) { openGroup(g); } });
  });
  [].forEach.call(bar.querySelectorAll('.tsw-bar__toggle'), function (t) {
    t.addEventListener('click', function (e) {
      e.preventDefault();
      var it = t.closest('.tsw-bar__item');
      if (it.classList.contains('tsw-open')) { closeItem(it); } else { openItem(it); }
    });
  });
  [].forEach.call(bar.querySelectorAll('.tsw-bar__caret'), function (c) {
    c.addEventListener('click', function (e) {
      e.preventDefault();
      var g = c.closest('.tsw-bar__group');
      if (g.classList.contains('tsw-open')) { g.classList.remove('tsw-open', 'tsw-flip'); setExp(g, false); } else { openGroup(g); }
    });
  });

  bar.addEventListener('keydown', function (e) {
    var g = e.target.closest ? e.target.closest('.tsw-bar__group') : null;
    if (e.key === 'Escape') {
      var openG = bar.querySelector('.tsw-bar__group.tsw-open');
      if (openG) { var c = openG.querySelector(':scope > .tsw-bar__caret'); openG.classList.remove('tsw-open', 'tsw-flip'); if (c) { c.setAttribute('aria-expanded', 'false'); c.focus(); } return; }
      var it = e.target.closest('.tsw-bar__item');
      if (it && it.classList.contains('tsw-open')) { closeItem(it); var t = it.querySelector(':scope > .tsw-bar__toggle'); if (t) { t.focus(); } }
    } else if (e.key === 'ArrowRight' && g && !narrow.matches) {
      openGroup(g); var first = g.querySelector(':scope > .tsw-bar__flyout .tsw-bar__mlink'); if (first) { first.focus(); e.preventDefault(); }
    } else if (e.key === 'ArrowLeft' && g) {
      var c2 = g.querySelector(':scope > .tsw-bar__caret'); g.classList.remove('tsw-open', 'tsw-flip'); if (c2) { c2.setAttribute('aria-expanded', 'false'); c2.focus(); } e.preventDefault();
    }
  });
  doc.addEventListener('click', function (e) {
    if (!bar.contains(e.target)) { closeAll(); bar.classList.remove('tsw-bar--open'); menuBtn.setAttribute('aria-expanded', 'false'); }
  });
  return { openItem: openItem, closeItem: closeItem, openGroup: openGroup, closeAll: closeAll };
}

(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) { module.exports = { wireTswBand: wireTswBand }; }
  else {
    root.wireTswBand = wireTswBand;
    var b = document.querySelector('.tsw-bar');
    if (b) { wireTswBand(b, window, document); }
  }
})(typeof self !== 'undefined' ? self : this, null);
