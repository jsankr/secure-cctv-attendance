'use strict';
/* Presentation layer: glass sheen + tilt, theme, command palette, mobile navigation, password helpers.
   No business logic and no network calls; app.js keeps working if this file fails to load. */
(() => {
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const fine = matchMedia('(pointer: fine)');
  const store = {
    get: k => { try { return localStorage.getItem(k); } catch { return null; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* private mode: not remembered */ } },
  };

  /* ---------------------------------------------------------------- theme */
  function applyTheme(t) {
    document.documentElement.dataset.theme = t;
    document.querySelectorAll('[data-action=theme] use').forEach(u => u.setAttribute('href', t === 'dark' ? '#i-sun' : '#i-moon'));
  }
  applyTheme(store.get('theme') || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'));
  function toggleTheme() {
    const t = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    applyTheme(t); store.set('theme', t);
  }

  /* -------------------------------------------- sheen follows the pointer; slab + KPI tiles tilt in 3D */
  let raf = 0, last = null;
  document.addEventListener('pointermove', e => {
    last = e;
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = 0;
      const el = last.target.closest?.('.glass, .slab');
      if (!el) return;
      const r = el.getBoundingClientRect();
      const x = (last.clientX - r.left) / r.width, y = (last.clientY - r.top) / r.height;
      el.style.setProperty('--mx', `${(x * 100).toFixed(1)}%`);
      el.style.setProperty('--my', `${(y * 100).toFixed(1)}%`);
      if (reduced.matches || !fine.matches) return;
      if (el.classList.contains('kpi')) el.style.transform = `perspective(700px) rotateX(${((0.5 - y) * 6).toFixed(2)}deg) rotateY(${((x - 0.5) * 8).toFixed(2)}deg) translateZ(4px)`;
      else if (el.classList.contains('slab')) el.style.transform = `rotateY(${((x - 0.5) * 7 - 2).toFixed(2)}deg) rotateX(${((0.5 - y) * 5 + 1).toFixed(2)}deg)`;
    });
  }, { passive: true });
  document.addEventListener('pointerout', e => {
    const el = e.target.closest?.('.kpi, .slab');
    if (el && !el.contains(e.relatedTarget)) el.style.transform = '';
  });

  /* ---------------------------------------------------------------- password helpers */
  function strength(pw) {
    const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(r => r.test(pw)).length;
    if (!pw) return [0, ''];
    if (pw.length < 12) return [15, `${12 - pw.length} more characters`];
    if (new Set(pw).size < 6) return [25, 'Too repetitive'];
    if (pw.length < 16 && classes < 3) return [40, 'Add symbols or digits, or make it 16+ characters'];
    if (pw.length >= 20 || (pw.length >= 14 && classes === 4)) return [100, 'Strong'];
    return [72, 'Good'];
  }
  document.addEventListener('input', e => {
    const id = e.target.dataset?.meter;
    if (!id) return;
    const m = document.getElementById(id);
    const [w, label] = strength(e.target.value);
    const bar = m.querySelector('i');
    bar.style.setProperty('--w', `${w}%`);
    bar.style.setProperty('--c', w >= 72 ? 'var(--mint)' : w >= 40 ? 'var(--sun)' : 'var(--coral)');
    m.querySelector('span').textContent = label;
  });

  /* ---------------------------------------------------------------- command palette */
  const pal = () => document.getElementById('palette');
  let items = [], sel = 0;
  function paletteItems() {
    const nav = [...document.querySelectorAll('#nav a')].filter(a => !a.classList.contains('hidden'))  // role-filtered by app.js
      .map(a => ({ label: a.textContent.trim(), icon: a.querySelector('use')?.getAttribute('href') || '#i-chevron', run: () => { location.hash = a.getAttribute('href'); } }));
    return [...nav,
      { label: 'Switch light / dark theme', icon: '#i-sun', run: toggleTheme },
      { label: 'Change password', icon: '#i-key', run: () => document.querySelector('[data-action=password]')?.click() },
      { label: 'Sign out', icon: '#i-logout', run: () => document.querySelector('[data-action=logout]')?.click() }];
  }
  function renderPalette() {
    const q = document.getElementById('paletteInput').value.trim().toLowerCase();
    items = paletteItems().filter(i => i.label.toLowerCase().includes(q));
    sel = Math.min(sel, Math.max(0, items.length - 1));
    const ul = document.getElementById('paletteList');
    ul.replaceChildren(...items.map((it, n) => {
      const li = document.createElement('li');
      li.setAttribute('role', 'option'); li.setAttribute('aria-selected', String(n === sel)); li.dataset.n = n;
      li.innerHTML = `<svg class="i"><use href="${it.icon}"/></svg><span></span>`;
      li.querySelector('span').textContent = it.label;
      return li;
    }));
    if (!items.length) { const li = document.createElement('li'); li.textContent = 'No match'; ul.append(li); }
  }
  function openPalette() {
    if (document.getElementById('app').classList.contains('hidden')) return;
    pal().classList.remove('hidden'); sel = 0;
    const inp = document.getElementById('paletteInput'); inp.value = ''; renderPalette(); inp.focus();
  }
  function closePalette() { pal().classList.add('hidden'); }
  function runSel() { const it = items[sel]; closePalette(); it?.run(); }
  document.addEventListener('keydown', e => {
    const open = !pal().classList.contains('hidden');
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); open ? closePalette() : openPalette(); return; }
    if (!open) return;
    if (e.key === 'Escape') { e.preventDefault(); closePalette(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(items.length - 1, sel + 1); renderPalette(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(0, sel - 1); renderPalette(); }
    else if (e.key === 'Enter') { e.preventDefault(); runSel(); }
  });
  document.addEventListener('input', e => { if (e.target.id === 'paletteInput') { sel = 0; renderPalette(); } });

  /* ---------------------------------------------------------------- clicks owned by this file */
  document.addEventListener('click', e => {
    if (e.target.id === 'palette') return closePalette();
    const li = e.target.closest('#paletteList li[data-n]');
    if (li) { sel = +li.dataset.n; return runSel(); }
    const t = e.target.closest('[data-action]');
    if (!t) { if (document.body.classList.contains('nav-open') && !e.target.closest('.side')) document.body.classList.remove('nav-open'); return; }
    const a = t.dataset.action;
    if (a === 'theme') toggleTheme();
    else if (a === 'palette') openPalette();
    else if (a === 'nav-toggle') { e.stopPropagation(); document.body.classList.toggle('nav-open'); }
    else if (a === 'reveal') {
      const inp = t.parentElement.querySelector('input');
      const show = inp.type === 'password';
      inp.type = show ? 'text' : 'password';
      t.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    }
  });
  window.addEventListener('hashchange', () => document.body.classList.remove('nav-open'));

  window.FX = { toggleTheme, openPalette, closePalette, strength };
})();
