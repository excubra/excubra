// EX0 console — the little interactivity the pages need. No framework, no inline
// scripts (the CSP forbids them), nothing that talks to the network on its own.
(function () {
  'use strict';
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  // ---- clock and relative times ------------------------------------------------
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function humanDur(ms) {
    var s = Math.max(0, Math.floor(ms / 1000));
    if (s < 60) return s + ' s';
    var m = Math.floor(s / 60);
    if (m < 60) return m + ' min';
    var h = Math.floor(m / 60);
    if (h < 48) return h + ' h ' + pad(m % 60) + ' min';
    return Math.floor(h / 24) + ' Tage';
  }
  function tick() {
    var now = new Date();
    var c = $('#clock');
    if (c) c.textContent = pad(now.getHours()) + ':' + pad(now.getMinutes()) + ':' + pad(now.getSeconds());
    $$('[data-ago]').forEach(function (el) {
      var t = Number(el.getAttribute('data-ago')) * 1000;
      if (!t) return;
      var d = now.getTime() - t;
      el.textContent = d < 0 ? 'in ' + humanDur(-d) : 'vor ' + humanDur(d);
    });
  }
  setInterval(tick, 1000);
  tick();

  // ---- tabs (server renders every pane; the URL keeps the chosen one) ----------
  function initTabs() {
  $$('[data-tabs]').forEach(function (bar) {
    if (bar.dataset.wired) return;
    bar.dataset.wired = '1';
    var scope = bar.getAttribute('data-tabs');
    var panes = $$('[data-pane]').filter(function (p) { return p.getAttribute('data-pane').indexOf(scope + ':') === 0; });
    function show(name, push) {
      $$('button', bar).forEach(function (b) { b.classList.toggle('on', b.getAttribute('data-t') === name); });
      panes.forEach(function (p) { p.classList.toggle('on', p.getAttribute('data-pane') === scope + ':' + name); });
      if (push && history.replaceState) {
        var u = new URL(location.href); u.searchParams.set('tab', name); history.replaceState(null, '', u);
      }
    }
    $$('button', bar).forEach(function (b) { b.addEventListener('click', function () { show(b.getAttribute('data-t'), true); }); });
    $$('[data-goto-tab]').forEach(function (b) { b.addEventListener('click', function () { show(b.getAttribute('data-goto-tab'), true); window.scrollTo(0, 0); }); });
    var want = new URL(location.href).searchParams.get('tab');
    if (want && $$('button', bar).some(function (b) { return b.getAttribute('data-t') === want; })) show(want, false);
  });
  }
  initTabs();
  document.body.addEventListener('htmx:afterSwap', initTabs);

  // ---- device filter: chips by kind, free text, "beobachtet" -------------------
  var grid = $('#devs');
  if (grid) {
    var q = $('#dq'), chips = $$('#fchips .fchip'), filter = 'all';
    function apply() {
      var text = (q ? q.value : '').trim().toLowerCase(), shown = 0;
      $$('.dev', grid).forEach(function (card) {
        var ok = filter === 'all' || (filter === 'mon' ? card.getAttribute('data-mon') === '1' : card.getAttribute('data-kind') === filter);
        if (ok && text) ok = card.getAttribute('data-text').indexOf(text) >= 0;
        card.hidden = !ok;
        if (ok) shown++;
      });
      var e = $('#devs-empty');
      if (e) e.hidden = shown > 0;
    }
    chips.forEach(function (c) {
      c.addEventListener('click', function () {
        filter = c.getAttribute('data-f');
        chips.forEach(function (x) { x.classList.toggle('on', x === c); });
        apply();
      });
    });
    if (q) q.addEventListener('input', apply);
    var top = $('#q');
    if (top) top.addEventListener('input', function () { if (q) { q.value = top.value; apply(); } });
  }

  // ---- event tables: "nur rot" ---------------------------------------------------
  $$('[data-evfilter]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var on = !btn.classList.contains('on');
      btn.classList.toggle('on', on);
      $$('tr[data-sev]').forEach(function (tr) { tr.hidden = on && tr.getAttribute('data-sev') !== 'bad'; });
    });
  });

  // ---- confirm before destructive forms (no inline handlers under the CSP) -----
  $$('form[data-confirm]').forEach(function (f) {
    f.addEventListener('submit', function (e) { if (!window.confirm(f.getAttribute('data-confirm'))) e.preventDefault(); });
  });

  // ---- "/" focuses the search -----------------------------------------------------
  document.addEventListener('keydown', function (e) {
    var tag = document.activeElement && document.activeElement.tagName;
    if (e.key === '/' && tag !== 'INPUT' && tag !== 'TEXTAREA' && tag !== 'SELECT') {
      var s = $('#q') || $('#dq');
      if (s) { e.preventDefault(); s.focus(); }
    }
  });
})();
