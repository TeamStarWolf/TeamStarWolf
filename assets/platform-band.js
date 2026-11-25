/* Platform band behaviour, extracted into one function so it can be driven against the
   generated markup in a DOM stand-in (scripts/test_platform_band.js). In a browser the UMD
   wrapper at the bottom finds the band and wires it; under Node it is exported, not run.

   wireTswBand(bar, win, doc): bar is the <div class="tsw-bar">; win supplies matchMedia /
   innerWidth / innerHeight / setTimeout / clearTimeout; doc supplies createElement /
   addEventListener. Desktop (fine pointer): a top-level menu opens on hover and stays while
   the pointer is in its panel; the toggle button (aria-expanded) opens it for keyboard and
   click. A group (a Bookmarks category or, nested inside it, a subsection) opens a side
   fly-out; at each level independently the fly-out flips left when it would cross the right
   edge, is pulled up when it would cross the bottom, and scrolls inside itself only if it
   still does not fit. One path is open per level: opening a group closes its siblings, not
   its ancestors. Close waits 220ms. Escape closes the deepest open level and focuses its
   caret, so repeated Escape walks back out. Phones and coarse pointers use the buttons and
   the inline accordion. */
function wireTswBand(bar, win, doc) {
  win = win || window;
  doc = doc || document;
  var fine = win.matchMedia('(hover: hover) and (pointer: fine)');
  // Small-screen (accordion) layout when the viewport is narrow OR too short for the tallest
  // top-level panel - the same condition as the stylesheet. A short, wide viewport (a phone held
  // sideways) uses the accordion too, so the fixed band never leaves a panel off the bottom.
  var narrow = win.matchMedia('(max-width: 760px), (max-height: 560px)');
  var CLOSE_MS = 220;
  var timer = null;
  function cancel() { if (timer) { win.clearTimeout(timer); timer = null; } }
  function setExp(el, v) {
    var b = el.querySelector(':scope > .tsw-bar__toggle, :scope > .tsw-bar__caret');
    if (b) { b.setAttribute('aria-expanded', v ? 'true' : 'false'); }
  }
  function clearPos(g) {
    g.classList.remove('tsw-flip');
    var fly = g.querySelector(':scope > .tsw-bar__flyout');
    if (fly && fly.style) { fly.style.top = ''; fly.style.maxHeight = ''; fly.style.overflowY = ''; }
  }
  // Close a group and every group open inside it.
  function closeGroup(g) {
    [].forEach.call(g.querySelectorAll('.tsw-bar__group.tsw-open'), function (d) {
      d.classList.remove('tsw-open'); clearPos(d); setExp(d, false);
    });
    g.classList.remove('tsw-open'); clearPos(g); setExp(g, false);
  }
  // Close only the sibling groups at this level (same parent container), leaving ancestors open.
  function closeSiblings(g) {
    var parent = g.parentElement;
    if (!parent) { return; }
    [].forEach.call(parent.children, function (c) {
      if (c !== g && c.classList && c.classList.contains('tsw-bar__group') && c.classList.contains('tsw-open')) {
        closeGroup(c);
      }
    });
  }
  // Keep a fly-out on screen: flip left at the right edge; pull it up when its bottom would
  // cross, but never past the TOP of the viewport; and scroll inside itself only when it is
  // taller than the viewport. Each level runs this for its own fly-out. Vertical placement is
  // set as an inline offset relative to the group (the fly-out's positioned ancestor).
  function positionFlyout(g) {
    var fly = g.querySelector(':scope > .tsw-bar__flyout');
    if (!fly || narrow.matches) { return; }
    clearPos(g);
    var vw = win.innerWidth, vh = win.innerHeight;
    var r = fly.getBoundingClientRect();
    if (vw && r.right > vw - 8) { g.classList.add('tsw-flip'); }
    if (!vh) { return; }
    var h = (r.height != null) ? r.height : (r.bottom - r.top);
    var availTop = 8, availBottom = vh - 8, availH = availBottom - availTop;
    if (r.top >= availTop && r.bottom <= availBottom) { return; }   // already fully on screen
    var gr = g.getBoundingClientRect();
    if (h <= availH) {
      // pull up so the bottom sits on screen, but keep the top at or below the viewport top
      var topVp = Math.min(Math.max(availTop, r.top), availBottom - h);
      fly.style.top = (topVp - gr.top) + 'px';
    } else {
      // taller than the viewport: pin the top to the viewport and scroll inside
      fly.style.top = (availTop - gr.top) + 'px';
      fly.style.maxHeight = availH + 'px';
      fly.style.overflowY = 'auto';
    }
  }
  function openGroup(g) {
    closeSiblings(g);
    g.classList.add('tsw-open'); setExp(g, true);
    positionFlyout(g);
  }
  function closeItem(it) {
    it.classList.remove('tsw-open'); setExp(it, false);
    [].forEach.call(it.querySelectorAll('.tsw-bar__group.tsw-open'), function (g) {
      g.classList.remove('tsw-open'); clearPos(g); setExp(g, false);
    });
  }
  function openItem(it) {
    items.forEach(function (o) { if (o !== it) { closeItem(o); } });
    it.classList.add('tsw-open'); setExp(it, true);
  }
  function closeAll() { items.forEach(closeItem); }
  function deepestOpenGroup() {
    var open = [].slice.call(bar.querySelectorAll('.tsw-bar__group.tsw-open'));
    for (var i = 0; i < open.length; i++) {
      if (!open[i].querySelector('.tsw-bar__group.tsw-open')) { return open[i]; }
    }
    return open.length ? open[open.length - 1] : null;
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
    if (!open) { closeAll(); }
  });

  var items = [].slice.call(bar.querySelectorAll('.tsw-bar__item'));
  items.forEach(function (it) {
    it.addEventListener('mouseenter', function () { if (fine.matches && !narrow.matches) { cancel(); openItem(it); } });
    it.addEventListener('mouseleave', function () { if (fine.matches && !narrow.matches) { cancel(); timer = win.setTimeout(function () { closeItem(it); }, CLOSE_MS); } });
  });
  [].forEach.call(bar.querySelectorAll('.tsw-bar__group'), function (g) {
    g.addEventListener('mouseenter', function () { if (fine.matches && !narrow.matches) { cancel(); openGroup(g); } });
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
      if (g.classList.contains('tsw-open')) { closeGroup(g); } else { openGroup(g); }
    });
  });

  bar.addEventListener('keydown', function (e) {
    var g = e.target.closest ? e.target.closest('.tsw-bar__group') : null;
    if (e.key === 'Escape') {
      // When the band handles Escape (closing one level), stop it bubbling so a document-level
      // Escape handler elsewhere on the page does not also fire and close everything.
      var deepest = deepestOpenGroup();
      if (deepest) {
        var c = deepest.querySelector(':scope > .tsw-bar__caret');
        closeGroup(deepest);
        if (c) { c.focus(); }
        e.stopPropagation();
        return;
      }
      var it = e.target.closest('.tsw-bar__item');
      if (it && it.classList.contains('tsw-open')) {
        closeItem(it);
        var t = it.querySelector(':scope > .tsw-bar__toggle'); if (t) { t.focus(); }
        e.stopPropagation();
      }
    } else if (e.key === 'ArrowDown' && e.target.classList && e.target.classList.contains('tsw-bar__toggle') && !narrow.matches) {
      var it2 = e.target.closest('.tsw-bar__item'); openItem(it2);
      var f = it2.querySelector('.tsw-bar__panel .tsw-bar__mlink'); if (f) { f.focus(); } e.preventDefault();
    } else if (e.key === 'ArrowRight' && g && !narrow.matches) {
      openGroup(g); var first = g.querySelector(':scope > .tsw-bar__flyout .tsw-bar__mlink'); if (first) { first.focus(); } e.preventDefault();
    } else if (e.key === 'ArrowLeft' && g) {
      var c2 = g.querySelector(':scope > .tsw-bar__caret'); closeGroup(g); if (c2) { c2.focus(); } e.preventDefault();
    }
  });
  doc.addEventListener('click', function (e) {
    if (!bar.contains(e.target)) { closeAll(); bar.classList.remove('tsw-bar--open'); menuBtn.setAttribute('aria-expanded', 'false'); }
  });
  return { openItem: openItem, closeItem: closeItem, openGroup: openGroup, closeGroup: closeGroup, closeAll: closeAll };
}

(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) { module.exports = { wireTswBand: wireTswBand }; }
  else {
    root.wireTswBand = wireTswBand;
    var b = document.querySelector('.tsw-bar');
    if (b) { wireTswBand(b, window, document); }
  }
})(typeof self !== 'undefined' ? self : this, null);
