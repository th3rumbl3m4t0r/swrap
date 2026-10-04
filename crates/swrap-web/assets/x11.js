/* x11 theme script, shared with the author's other web pages.
   swrap-web has no nav[data-x11-nav], so the menu stays out; the theme controls go into the
   top bar ([data-x11-controls]). */
/* x11 theme — night / day + one accent, shared by every page on this
   origin through one localStorage key. Load in <head> (not deferred) so the
   classes land before first paint. Controls go into any [data-x11-controls]
   element; pages without one get a small floating bar top-right. The site
   menu goes into any empty nav[data-x11-nav]. */
(function () {
  'use strict';
  var KEY = 'x11.theme';
  var DEFAULT = { theme: 'night', accent: '#3b8a3e' };
  var root = document.documentElement;
  var cur;

  function load() {
    var s = null;
    try { s = JSON.parse(localStorage.getItem(KEY)); } catch (e) {}
    s = s || {};
    return {
      theme: s.theme === 'day' ? 'day' : 'night',
      accent: /^#[0-9a-f]{6}$/i.test(s.accent || '') ? s.accent : DEFAULT.accent
    };
  }

  function save() {
    try { localStorage.setItem(KEY, JSON.stringify(cur)); } catch (e) {}
  }

  function apply() {
    root.classList.toggle('theme-night', cur.theme === 'night');
    root.classList.toggle('theme-day', cur.theme === 'day');
    root.style.setProperty('--accent', cur.accent);
    var els = document.querySelectorAll('[data-x11-controls]');
    for (var i = 0; i < els.length; i++) {
      var b = els[i].querySelector('.x11-mode'), c = els[i].querySelector('.x11-accent');
      if (b) b.textContent = cur.theme;
      if (c && c.value !== cur.accent) c.value = cur.accent;
    }
    try { document.dispatchEvent(new CustomEvent('x11-theme', { detail: { theme: cur.theme, accent: cur.accent } })); } catch (e) {}
  }

  function set(p) {
    if (p.theme === 'day' || p.theme === 'night') cur.theme = p.theme;
    if (/^#[0-9a-f]{6}$/i.test(p.accent || '')) cur.accent = p.accent;
    save(); apply();
  }

  var seq = 0;
  function fill(el) {
    if (el.querySelector('.x11-mode')) return;
    var id = 'x11-accent-' + (++seq);
    el.classList.add('x11-controls');
    el.innerHTML =
      '<button type="button" class="x11-mode" title="toggle night / day">' + cur.theme + '</button>' +
      '<label class="lbl" for="' + id + '">accent</label>' +
      '<input type="color" class="x11-accent" id="' + id + '" value="' + cur.accent + '" title="accent colour (shared by all pages on this origin)">';
    el.querySelector('.x11-mode').addEventListener('click', function () {
      set({ theme: cur.theme === 'night' ? 'day' : 'night' });
    });
    el.querySelector('.x11-accent').addEventListener('input', function (e) {
      set({ accent: e.target.value });
    });
  }

  // the site menu, one list for every page: an empty <nav data-x11-nav> gets it,
  // the page's own entry marked .on; links to another host are .ext (arrowed).
  // A page elsewhere can bring its own list: window.X11_CONFIG = { nav: [...] }
  // set before this script.
  var NAV = (window.X11_CONFIG && window.X11_CONFIG.nav) || [];

  function nav(el) {
    if (el.children.length) return;
    NAV.forEach(function (n) {
      var a = document.createElement('a');
      a.href = n.href;
      a.textContent = n.name;
      if (a.host !== location.host) { a.className = 'ext'; a.title = n.title || a.host; }
      else if (location.pathname.indexOf(a.pathname) === 0) a.className = 'on';
      el.appendChild(a);
    });
  }

  function mount() {
    var navs = document.querySelectorAll('nav[data-x11-nav]');
    for (var j = 0; j < navs.length; j++) nav(navs[j]);
    var els = document.querySelectorAll('[data-x11-controls]');
    if (!els.length && document.body && !root.hasAttribute('data-x11-nofloat')) {
      var f = document.createElement('div');
      f.className = 'x11-float';
      f.setAttribute('data-x11-controls', '');
      document.body.appendChild(f);
      els = [f];
    }
    for (var i = 0; i < els.length; i++) fill(els[i]);
  }

  cur = load();
  apply();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
  else mount();

  // another tab changed it: follow along
  window.addEventListener('storage', function (e) {
    if (e.key === KEY) { cur = load(); apply(); }
  });

  window.X11 = {
    get: function () { return { theme: cur.theme, accent: cur.accent }; },
    set: set,
    reset: function () { set(DEFAULT); },
    mount: mount,
    NAV: NAV,
    DEFAULT: DEFAULT
  };
})();
