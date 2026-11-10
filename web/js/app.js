'use strict';
/* Sentinel Attend console. No inline handlers or styles (strict CSP); all events are delegated.
   Presentation helpers (theme, palette, glass effects) live in fx.js. */

const S = { csrf: null, user: null, cams: [], camMap: {}, ws: null, muted: false, players: [], modalPlayers: [],
  grid: 4, page: 0, site: '', focus: null, tour: null, setupToken: null, unacked: 0, lastActive: Date.now(),
  evOldest: null, ruleDraft: null };
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const RANK = { kiosk: 0, viewer: 1, operator: 2, admin: 3, superadmin: 4 };
const can = r => !!S.user && RANK[S.user.role] >= RANK[r];
const fmt = iso => iso ? new Date(iso).toLocaleString() : '—';
const camName = id => S.camMap[id]?.name || `Camera ${id}`;
const CLASSES = ['person', 'car', 'motorcycle', 'bus', 'truck', 'bicycle', 'dog', 'cat', 'backpack', 'handbag',
  'suitcase', 'knife', 'loitering', 'watchlist', 'tamper', 'video_loss'];
const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const ic = (name, label = '') => `<svg class="i"${label ? ` role="img" aria-label="${esc(label)}"` : ' aria-hidden="true"'}><use href="#i-${name}"/></svg>`;
const empty = (icon, text, cols) => `<tr><td colspan="${cols}"><div class="empty-state">${ic(icon)}${esc(text)}</div></td></tr>`;

function toast(msg, bad = false) {
  const t = document.createElement('div');
  t.className = 'toast' + (bad ? ' bad' : '');
  t.textContent = msg;
  $('#toasts').append(t);
  setTimeout(() => t.remove(), 4500);
}

async function api(path, { method = 'GET', body, form } = {}) {
  const headers = {};
  if (method !== 'GET') headers['X-CSRF-Token'] = S.csrf || '';
  let payload;
  if (form) payload = form;
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  const r = await fetch(path, { method, headers, body: payload, credentials: 'same-origin' });
  const isAuth = ['/api/auth/login', '/api/auth/mfa', '/api/setup/', '/api/register'].some(p => path.startsWith(p));
  if (r.status === 401 && !isAuth) { showLogin(); throw new Error('Session expired — sign in again'); }
  const data = (r.headers.get('content-type') || '').includes('json') ? await r.json() : await r.text();
  if (!r.ok) {
    const d = data && data.detail;
    throw new Error(Array.isArray(d) ? d.map(x => `${x.loc?.slice(-1)[0]}: ${x.msg}`).join('; ') : (d || r.statusText));
  }
  return data;
}

/* ------------------------------------------------------------------ auth */
function showPane(name) {
  $$('#authSlab .pane').forEach(p => p.classList.toggle('hidden', p.dataset.pane !== name));
  $('#login').setAttribute('aria-label', { signin: 'Sign in', setup: 'First-run setup', register: 'Create your account' }[name]);
  const first = $(`#authSlab [data-pane="${name}"] input:not([type=hidden])`);
  if (first && first.offsetParent) setTimeout(() => first.focus(), 50);
}

function showLogin() {
  stopPlayers(); closeModal();
  clearInterval(S.tour); S.tour = null;
  S.user = null; S.csrf = null;
  if (S.ws) { const w = S.ws; S.ws = null; w.close(); }
  $('#app').classList.add('hidden');
  $('#login').classList.remove('hidden');
  S.setupToken = null;
  $('#loginStep1').classList.remove('hidden');
  $('#mfaSetup').classList.add('hidden');
  $('#loginBtn').textContent = 'Sign in';
  showPane('signin');
}

/* Decide which public screen to show: invitation link, first-run setup, or sign in. */
async function showPublic() {
  showLogin();
  const m = location.hash.match(/^#\/register\?code=([A-Za-z0-9_-]{20,100})/);
  if (m) return openRegister(m[1]);
  try {
    if ((await api('/api/setup/status')).needs_setup) showPane('setup');
  } catch { /* stay on sign in */ }
}

$('#loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target;
  $('#loginErr').textContent = '';
  const btn = $('#loginBtn'); btn.disabled = true;
  try {
    const res = S.setupToken
      ? await api('/api/auth/mfa/enroll', { method: 'POST', body: { setup_token: S.setupToken, totp: f.enrollCode.value } })
      : await api('/api/auth/login', { method: 'POST', body: { username: f.username.value, password: f.password.value, totp: f.totp.value } });
    if (res.mfa_setup_required) {
      S.setupToken = res.setup_token;
      $('#mfaQr').src = res.qr;
      $('#mfaSecret').textContent = res.secret;
      $('#loginStep1').classList.add('hidden');
      $('#mfaSetup').classList.remove('hidden');
      btn.textContent = 'Verify and sign in';
      f.enrollCode.focus();
      return;
    }
    S.setupToken = null;
    f.reset();
    await start(res);
  } catch (err) { $('#loginErr').textContent = err.message; }
  finally { btn.disabled = false; }
});

/* --- first-run setup wizard (only while no account exists) */
function setupStep(n) {
  $$('#setupSteps li').forEach(li => { const k = +li.dataset.step; li.className = k < n ? 'done' : k === n ? 'on' : ''; });
  const forms = { 1: 'setupAccount', 3: 'setupMfa', 4: 'setupVault' };
  $$('[data-pane=setup] form').forEach(f => f.classList.toggle('hidden', f.dataset.form !== forms[n === 2 ? 1 : n]));
  $('[data-pane=setup] [data-done]').classList.toggle('hidden', n !== 5);
  const inp = $(`[data-pane=setup] form[data-form="${forms[n]}"] input`);
  if (inp) setTimeout(() => inp.focus(), 50);
}
function showMfa(form, d) {
  $('img.qr', form).src = d.qr;
  $('code.secret', form).textContent = d.secret;
  form.dataset.token = d.setup_token;
}
const formErr = (f, msg) => { const p = $('.err', f); if (p) p.textContent = msg; };

/* --- invitation / reset link */
async function openRegister(code) {
  S.regCode = code;
  history.replaceState(null, '', '#/register');  // keep the token out of history and screenshots of the address bar
  showPane('register');
  const pane = $('[data-pane=register]');
  try {
    const d = await api('/api/register/check', { method: 'POST', body: { code } });
    S.regKind = d.kind;
    const reset = d.kind === 'reset';
    $('#regTitle').textContent = reset ? 'Choose a new password' : 'Create your account';
    $('#regLede').textContent = reset
      ? `Password reset for ${d.username}. This link works once and expires ${fmt(d.expires_at)}.`
      : `You have been invited as ${d.role === 'superadmin' ? 'a super admin' : d.role === 'admin' ? 'an admin' : `an ${d.role}`}. Choose your own username and password; nobody else will know them. The link expires ${fmt(d.expires_at)}.`;
    $('[data-field=username]', pane).classList.toggle('hidden', reset);
    $('[data-field=contact]', pane).classList.toggle('hidden', reset);
    if (!reset && d.email) $('input[name=email]', pane).value = d.email;
  } catch {
    $$('form', pane).forEach(f => f.classList.add('hidden'));
    $('[data-invalid]', pane).classList.remove('hidden');
  }
}

async function start(res) {
  S.csrf = res.csrf; S.user = res.user;
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');
  $('#whoami').innerHTML = `<b>${esc(S.user.username)}</b> ${esc(S.user.role === 'superadmin' ? 'super admin' : S.user.role)}`;
  if (location.hash.startsWith('#/register')) location.hash = '#/dashboard';
  $$('[data-role]').forEach(el => el.classList.toggle('hidden', !can(el.dataset.role)));
  const kiosk = S.user.role === 'kiosk';
  document.body.classList.toggle('kiosk-mode', kiosk);
  if (kiosk) { location.hash = '#/kiosk'; route(); return; }
  await loadCams();
  connectWs();
  refreshBadge();
  if (can('admin')) refreshBell();
  route();
}

async function loadCams() {
  S.cams = await api('/api/cameras');
  S.camMap = Object.fromEntries(S.cams.map(c => [c.id, c]));
}

['pointerdown', 'keydown'].forEach(ev => document.addEventListener(ev, () => { S.lastActive = Date.now(); }, { passive: true }));
setInterval(() => {  // sliding session only while the operator is active (idle sessions expire)
  if (S.user && Date.now() - S.lastActive < 25 * 60 * 1000) api('/api/auth/refresh', { method: 'POST' }).catch(() => {});
}, 8 * 60 * 1000);
setInterval(() => { $('#clock').textContent = new Date().toLocaleTimeString(); }, 1000);

/* ------------------------------------------------------------- realtime */
function connectWs() {
  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/api/ws`);
  S.ws = ws;
  ws.onopen = () => { setWs(true); ws._ping = setInterval(() => ws.readyState === 1 && ws.send('ping'), 25000); };
  ws.onclose = () => { setWs(false); clearInterval(ws._ping); if (S.user && S.ws === ws) setTimeout(connectWs, 3000); };
  ws.onmessage = m => {
    const d = JSON.parse(m.data);
    if (d.type === 'event') onEvent(d.event);
    else if (d.type === 'security') onSecurity(d.notification);
    else if (d.type === 'attendance' && location.hash.startsWith('#/attendance')) route();
    else if (d.type === 'unblur') { toast(`Unblur request #${d.id}: ${d.status}`); if (location.hash.startsWith('#/privacy')) route(); }
  };
}
function setWs(on) { const p = $('#wsState'); p.textContent = on ? 'Live' : 'Offline'; p.className = 'pill ' + (on ? 'on' : 'off'); }

function onEvent(ev) {
  const alerting = ev.rules?.length || ['medium', 'high', 'critical'].includes(ev.severity);
  if (!alerting) return;
  addAlert(ev);
  S.unacked++; paintBadge();
  const tile = $(`.tile[data-cam="${ev.camera_id}"]`);
  if (tile) { tile.classList.remove('alerting'); void tile.offsetWidth; tile.classList.add('alerting'); }
  if (ev.rules?.some(r => r.alarm) || ['high', 'critical'].includes(ev.severity)) siren();
  if (location.hash.startsWith('#/events') && $('#evBody')) $('#evBody').prepend(evRow(ev));
}

function addAlert(ev) {
  const list = $('#alertList');
  if (list.querySelector('p')) list.innerHTML = '';
  const div = document.createElement('div');
  div.className = `alert sev-${ev.severity}`;
  div.dataset.action = 'open-event';
  div.dataset.ev = JSON.stringify(ev);
  div.innerHTML = `${ev.has_snapshot ? `<img alt="" src="/api/events/${ev.id}/snapshot">` : '<img alt="">'}
    <div><b>${esc(evTitle(ev))}</b><div class="small muted">${esc(camName(ev.camera_id))}</div>
    <div class="small muted">${esc(new Date(ev.ts).toLocaleTimeString())} · <span class="sev sev-${ev.severity}">${ev.severity}</span></div></div>`;
  list.prepend(div);
  while (list.children.length > 60) list.lastChild.remove();
}

function evTitle(ev) {
  const wl = ev.meta?.watchlist?.[0];
  if (wl) return `Watchlist: ${wl.label}`;
  const plate = ev.meta?.enrich?.plate?.text;
  if (plate) return `${ev.label} · ${plate}`;
  return ev.kind === 'object' ? ev.label : ev.kind.replace('_', ' ');
}

async function refreshBadge() {
  try { S.unacked = (await api('/api/events/stats')).unacked_alerts; paintBadge(); } catch { /* ignore */ }
}
function paintBadge() { const b = $('#navBadge'); b.textContent = S.unacked; b.classList.toggle('hidden', !S.unacked); }

let actx;
function siren() {
  if (S.muted) return;
  try {
    actx = actx || new AudioContext();
    const o = actx.createOscillator(), g = actx.createGain(), t = actx.currentTime;
    o.type = 'sawtooth'; o.connect(g); g.connect(actx.destination);
    g.gain.setValueAtTime(0.0001, t); g.gain.exponentialRampToValueAtTime(0.12, t + 0.05);
    for (let i = 0; i < 8; i++) o.frequency.setValueAtTime(i % 2 ? 640 : 900, t + i * 0.22);
    g.gain.exponentialRampToValueAtTime(0.0001, t + 1.8);
    o.start(t); o.stop(t + 1.85);
  } catch { /* autoplay policy: needs a prior user gesture */ }
}

/* ---------------------------------------------------------------- player */
class Player {
  constructor(video, camId, quality = 'sub') {
    Object.assign(this, { v: video, cam: camId, q: quality, pc: null, hls: null, tok: null, path: null, timer: null, dead: false });
    this.onstate = () => {};
  }
  async token() {
    const r = await api('/api/streams/token', { method: 'POST', body: { camera_id: this.cam, quality: this.q } });
    this.tok = r.token; this.path = r.path;
  }
  async start() {
    try {
      await this.token();
      this.timer = setInterval(() => this.token().catch(() => {}), 5 * 60 * 1000);
      try { await this.webrtc(); this.onstate('live', 'WebRTC'); }
      catch { if (this.dead) return; this.startHls(); this.onstate('live', 'HLS'); }
    } catch (e) { this.onstate('error', e.message); }
  }
  async webrtc() {
    const pc = new RTCPeerConnection({ bundlePolicy: 'max-bundle' });
    this.pc = pc;
    pc.addTransceiver('video', { direction: 'recvonly' });
    pc.addTransceiver('audio', { direction: 'recvonly' });
    pc.ontrack = e => { if (e.streams[0] && this.v.srcObject !== e.streams[0]) { this.v.srcObject = e.streams[0]; this.v.play().catch(() => {}); } };
    const connected = new Promise((res, rej) => {
      const to = setTimeout(() => rej(new Error('ICE timeout')), 6000);
      pc.addEventListener('connectionstatechange', () => {
        if (pc.connectionState === 'connected') { clearTimeout(to); res(); }
        else if (pc.connectionState === 'failed') { clearTimeout(to); rej(new Error('ICE failed')); }
      });
    });
    connected.catch(() => {});  // avoid unhandled rejection if signalling fails before we await it
    await pc.setLocalDescription(await pc.createOffer());
    await new Promise(r => {  // non-trickle ICE: no PATCH round-trips through the proxy
      if (pc.iceGatheringState === 'complete') return r();
      const t = setTimeout(r, 1500);
      pc.addEventListener('icegatheringstatechange', () => { if (pc.iceGatheringState === 'complete') { clearTimeout(t); r(); } });
    });
    const r = await fetch(`/webrtc/${this.path}/whep`, { method: 'POST', body: pc.localDescription.sdp,
      headers: { 'Content-Type': 'application/sdp', Authorization: `Bearer ${this.tok}` } });
    if (!r.ok) { pc.close(); this.pc = null; throw new Error(`WHEP ${r.status}`); }
    await pc.setRemoteDescription({ type: 'answer', sdp: await r.text() });
    try { await connected; } catch (e) { pc.close(); this.pc = null; throw e; }
  }
  startHls() {
    if (!(window.Hls && Hls.isSupported())) throw new Error('Browser lacks MSE for HLS fallback');
    const h = new Hls({ lowLatencyMode: true, liveSyncDurationCount: 2,
      xhrSetup: x => x.setRequestHeader('Authorization', `Bearer ${this.tok}`) });
    this.hls = h;
    h.loadSource(`/hls/${this.path}/index.m3u8`);
    h.attachMedia(this.v);
    h.on(Hls.Events.MANIFEST_PARSED, () => this.v.play().catch(() => {}));
    h.on(Hls.Events.ERROR, (_, d) => { if (d.fatal) this.onstate('error', `HLS ${d.details}`); });
  }
  stop() {
    this.dead = true;
    clearInterval(this.timer);
    if (this.pc) this.pc.close();
    if (this.hls) this.hls.destroy();
    this.v.srcObject = null;
    this.v.removeAttribute('src');
  }
}
function stopPlayers() { S.players.forEach(p => p.stop()); S.players = []; }

/* ---------------------------------------------------------------- router */
const VIEWS = {
  dashboard: ['Overview', vDashboard], live: ['Live wall', vLive],  // playback + campus views: campus.js
  events: ['Events', vEvents], cameras: ['Cameras', vCameras], rules: ['Alert rules', vRules],
  watchlists: ['Watchlists', vWatchlists], users: ['Users', vUsers], audit: ['Audit log', vAudit],
};
function route() {
  if (!S.user) return;
  if (location.hash.startsWith('#/register')) return showPublic();
  const name = (location.hash.replace('#/', '') || 'dashboard').split('?')[0];
  const [title, fn] = VIEWS[name] || VIEWS.dashboard;
  stopPlayers();
  clearInterval(S.tour); S.tour = null;
  $$('#nav a').forEach(a => a.classList.toggle('active', a.dataset.view === name));
  $('#viewTitle').textContent = title;
  const el = $('#view');
  el.innerHTML = '<p class="muted">Loading…</p>';
  el.focus({ preventScroll: true });
  fn(el).catch(e => { el.innerHTML = `<div class="glass panel err">${esc(e.message)}</div>`; });
}
window.addEventListener('hashchange', route);
const hashParams = () => new URLSearchParams(location.hash.split('?')[1] || '');

/* ------------------------------------------------------------- dashboard */
async function vDashboard(el) {
  const [st, status] = await Promise.all([api('/api/events/stats'), api('/api/cameras/status')]);
  await loadCams();
  const online = S.cams.filter(c => status[c.id]?.ready).length;
  const kpi = (icon, label, v, cls = '') => `<div class="glass kpi"><div class="muted small">${ic(icon)}${label}</div><div class="v ${cls}">${v}</div></div>`;
  el.innerHTML = `<div class="cards">
      ${kpi('cameras', 'Cameras online', `${online}/${S.cams.length}`, online === S.cams.length ? 'ok' : 'bad')}
      ${kpi('events', 'Events in 24 h', st.total_24h)}
      ${kpi('bell', 'Open alerts', st.unacked_alerts, st.unacked_alerts ? 'bad' : 'ok')}
      ${kpi('lock', 'Recording, encrypted', S.cams.filter(c => c.record).length)}
      ${kpi('overview', 'AI analytics on', S.cams.filter(c => c.ai_enabled).length)}
    </div>
    <div class="grid2">
      <div class="glass panel"><h2>Activity in the last 24 hours</h2><div class="bars" id="bars"></div>
        <div class="row between small muted"><span>24 h ago</span><span>now</span></div></div>
      <div class="glass panel"><h2>Detections by class</h2><div id="hbars"><p class="muted small">No detections yet.</p></div></div>
    </div>
    <div class="glass panel"><h2>Camera health</h2><table><thead><tr><th>Camera</th><th>Site</th><th>Stream</th>
      <th>Viewers</th><th>AI</th><th>Recording</th><th>IR mode</th></tr></thead><tbody>
      ${S.cams.map(c => `<tr><td>${esc(c.name)}</td><td>${esc(c.site)}</td>
        <td><i class="dot ${status[c.id]?.ready ? 'live' : ''}"></i> ${status[c.id]?.ready ? 'online' : 'offline'}</td>
        <td>${status[c.id]?.readers ?? 0}</td><td>${c.ai_enabled ? 'on' : 'off'}</td><td>${c.record ? 'on' : 'off'}</td>
        <td>${esc(c.ir_mode)}${c.auto_ir ? ' (software auto)' : ''}</td></tr>`).join('') || empty('cameras', 'No cameras yet. Admins add them under Cameras.', 7)}
    </tbody></table></div>`;
  const max = Math.max(1, ...st.by_hour);
  $('#bars').append(...st.by_hour.map(n => { const s = document.createElement('span'); s.style.height = `${(n / max) * 100}%`; s.title = `${n} events`; return s; }));
  if (st.by_label.length) {
    const top = st.by_label[0].count;
    $('#hbars').innerHTML = '';
    st.by_label.slice(0, 8).forEach(x => {
      const row = document.createElement('div');
      row.className = 'hbar';
      row.innerHTML = `<span>${esc(x.label)}</span><i></i><span class="mono">${x.count}</span>`;
      row.querySelector('i').style.width = `${(x.count / top) * 100}%`;
      $('#hbars').append(row);
    });
  }
}

/* -------------------------------------------------------------- live wall */
async function vLive(el) {
  await loadCams();
  const sites = [...new Set(S.cams.map(c => c.site).filter(Boolean))];
  el.innerHTML = `<div class="wall-bar">
      ${[1, 4, 9, 16, 25].map(n => `<button class="btn small ${S.grid === n ? 'on' : ''}" data-action="grid" data-n="${n}">${n}</button>`).join('')}
      <select id="siteFilter" aria-label="Site"><option value="">All sites</option>${sites.map(s => `<option ${s === S.site ? 'selected' : ''}>${esc(s)}</option>`).join('')}</select>
      <button class="btn small" data-action="page" data-d="-1" aria-label="Previous page">‹</button><span id="pageInfo" class="small muted"></span>
      <button class="btn small" data-action="page" data-d="1" aria-label="Next page">›</button>
      <button class="btn small ${S.tour ? 'on' : ''}" data-action="tour" id="tourBtn">Auto-tour</button>
      <span class="muted small">Double-click a tile to focus it. Hover or tab to a tile for controls.</span></div>
    <div id="wall" class="wall"></div>`;
  $('#siteFilter').addEventListener('change', e => { S.site = e.target.value; S.page = 0; S.focus = null; renderWall(); });
  renderWall();
}

function wallCams() {
  if (S.focus) return S.cams.filter(c => c.id === S.focus);
  return S.cams.filter(c => c.enabled && (!S.site || c.site === S.site));
}

function renderWall() {
  stopPlayers();
  const wall = $('#wall');
  if (!wall) return;
  const all = wallCams(), grid = S.focus ? 1 : S.grid;
  const pages = Math.max(1, Math.ceil(all.length / grid));
  S.page = ((S.page % pages) + pages) % pages;
  const list = all.slice(S.page * grid, S.page * grid + grid);
  $('#pageInfo').textContent = S.focus ? 'focused' : `page ${S.page + 1}/${pages}`;
  wall.className = `wall g${grid}`;
  wall.innerHTML = list.map(tileHtml).join('') +
    Array.from({ length: Math.max(0, grid - list.length) }, () => '<div class="tile"><div class="empty">No camera</div></div>').join('');
  list.forEach(c => {
    const tile = $(`.tile[data-cam="${c.id}"]`, wall);
    const p = new Player($('video', tile), c.id, grid === 1 ? 'main' : 'sub');
    p.onstate = (s, info) => { $('.dot', tile).classList.toggle('live', s === 'live'); $('.proto', tile).textContent = info; };
    S.players.push(p);
    p.start();
  });
}

function tileHtml(c) {
  const op = can('operator') && c.ptz;
  return `<div class="tile" data-cam="${c.id}" tabindex="0">
    <video muted playsinline autoplay></video>
    <div class="cap"><span><i class="dot"></i> ${esc(c.name)}</span><span class="proto small">connecting…</span></div>
    ${op ? `<div class="ptz">
      <button data-ptz="-0.5,0.5,0" title="Up-left">↖</button><button data-ptz="0,0.5,0" title="Up">↑</button><button data-ptz="0.5,0.5,0" title="Up-right">↗</button>
      <button data-ptz="-0.5,0,0" title="Left">←</button><button data-ptz="0,0,0.5" title="Zoom in">＋</button><button data-ptz="0.5,0,0" title="Right">→</button>
      <button data-ptz="0,0,-0.5" title="Zoom out">－</button><button data-ptz="0,-0.5,0" title="Down">↓</button><button data-action="presets" title="Presets" aria-label="Presets">${ic('star')}</button></div>` : ''}
    <div class="ctl">
      ${op ? `<button class="btn" data-action="ir" data-mode="night" title="Force infrared night mode">${ic('moon')}IR</button>
        <button class="btn" data-action="ir" data-mode="day" title="Force day mode" aria-label="Day mode">${ic('sun')}</button>
        <button class="btn" data-action="ir" data-mode="auto" title="Let the camera's light sensor decide">Auto</button>
        <button class="btn danger" data-action="alarm">${ic('alarm')}Alarm</button>` : ''}
      ${can('superadmin') ? `<button class="btn" data-action="snap">${ic('camera')}Snapshot</button>` : ''}
      <button class="btn" data-action="rewind">${ic('rewind')}Rewind</button>
      <button class="btn" data-action="fs" aria-label="Full screen">${ic('expand')}</button>
    </div></div>`;
}

document.addEventListener('dblclick', e => {
  const tile = e.target.closest('.tile[data-cam]');
  if (!tile || e.target.closest('button')) return;
  S.focus = S.focus ? null : +tile.dataset.cam;
  renderWall();
});

let ptzCam = null;
document.addEventListener('pointerdown', e => {
  const b = e.target.closest('[data-ptz]');
  if (!b) return;
  const [pan, tilt, zoom] = b.dataset.ptz.split(',').map(Number);
  ptzCam = +b.closest('[data-cam]').dataset.cam;
  api(`/api/cameras/${ptzCam}/ptz`, { method: 'POST', body: { action: 'move', pan, tilt, zoom } }).catch(err => toast(err.message, true));
});
['pointerup', 'pointercancel'].forEach(ev => document.addEventListener(ev, () => {
  if (ptzCam == null) return;
  api(`/api/cameras/${ptzCam}/ptz`, { method: 'POST', body: { action: 'stop' } }).catch(() => {});
  ptzCam = null;
}));

/* playback: see campus.js (encrypted, blurred recordings) */

/* ----------------------------------------------------------------- events */
async function vEvents(el) {
  await loadCams();
  el.innerHTML = `<div class="glass panel"><form class="row" data-form="evFilter">
      <label>Camera<select name="camera_id"><option value="">All</option>${S.cams.map(c => `<option value="${c.id}">${esc(c.name)}</option>`).join('')}</select></label>
      <label>Type<select name="kind"><option value="">All</option>${['object', 'loitering', 'watchlist', 'tamper', 'video_loss', 'lowlight'].map(k => `<option>${k}</option>`).join('')}</select></label>
      <label>Class<input name="label" placeholder="person, car…" maxlength="40"></label>
      <label>Severity<select name="severity"><option value="">All</option>${['info', 'low', 'medium', 'high', 'critical'].map(k => `<option>${k}</option>`).join('')}</select></label>
      <label>From<input type="datetime-local" name="since"></label>
      <label class="check"><input type="checkbox" name="unacked"> Unacknowledged only</label>
      <button class="btn primary">Apply</button>
      ${can('operator') ? '<button type="button" class="btn" data-action="ack-all">Acknowledge all</button>' : ''}</form></div>
    <div class="glass panel"><table><thead><tr><th></th><th>Time</th><th>Camera</th><th>Event</th><th>Conf.</th>
      <th>Severity</th><th>Rules</th><th>Status</th><th></th></tr></thead><tbody id="evBody"></tbody></table>
      <div class="row"><button class="btn" data-action="ev-more">Load older</button></div></div>`;
  S.evFilter = {};
  await loadEvents(true);
}

async function loadEvents(reset) {
  const p = new URLSearchParams({ limit: 50 });
  Object.entries(S.evFilter || {}).forEach(([k, v]) => v && p.set(k, v));
  if (!reset && S.evOldest) p.set('before_id', S.evOldest);
  const rows = await api(`/api/events?${p}`);
  if (reset) $('#evBody').innerHTML = '';
  rows.forEach(e => $('#evBody').append(evRow(e)));
  if (rows.length) S.evOldest = rows[rows.length - 1].id;
  if (reset && !rows.length) $('#evBody').innerHTML = empty('events', 'No events match these filters.', 9);
}

function evRow(e) {
  const tr = document.createElement('tr');
  tr.innerHTML = `<td>${e.has_snapshot ? `<img class="thumb" alt="" loading="lazy" src="/api/events/${e.id}/snapshot" data-action="open-event">` : ''}</td>
    <td class="mono small">${esc(fmt(e.ts))}</td><td>${esc(camName(e.camera_id))}</td><td><b>${esc(evTitle(e))}</b>
    ${e.meta?.enrich?.attributes ? `<div class="small muted">${esc(Object.values(e.meta.enrich.attributes).join(' / '))}</div>` : ''}</td>
    <td class="mono">${e.confidence ? Math.round(e.confidence * 100) + '%' : ''}</td>
    <td><span class="sev sev-${e.severity}">${e.severity}</span></td><td class="small">${esc((e.rules || []).map(r => r.name).join(', '))}</td>
    <td class="small">${e.acknowledged ? `✓ ${esc(e.ack_by)}` : '<span class="muted">open</span>'}</td>
    <td><button class="btn small" data-action="open-event">Details</button></td>`;
  tr.dataset.ev = JSON.stringify(e);
  return tr;
}

function openEvent(e) {
  const m = e.meta || {};
  const facts = [
    ['Camera', camName(e.camera_id)], ['Time', fmt(e.ts)], ['Type', e.kind], ['Class', e.label],
    ['Confidence', e.confidence ? `${Math.round(e.confidence * 100)}%` : ''],
    ['Plate', m.enrich?.plate ? `${m.enrich.plate.text} (${Math.round(m.enrich.plate.conf * 100)}%)` : ''],
    ['Attributes', m.enrich?.attributes ? Object.entries(m.enrich.attributes).map(([k, v]) => `${k.replace('_', ' ')}: ${v}`).join(', ') : ''],
    ['Watchlist', (m.watchlist || []).map(w => `${w.label} [${w.list}${w.score ? ' ' + w.score : ''}]`).join(', ')],
    ['Dwell', m.dwell_s ? `${m.dwell_s}s` : ''], ['Rules fired', (e.rules || []).map(r => r.name).join(', ')],
    ['Acknowledged', e.acknowledged ? `${e.ack_by} · ${fmt(e.ack_at)}` : 'no'],
  ].filter(f => f[1]);
  openModal(`<div class="row between"><h2>${esc(evTitle(e))} <span class="sev sev-${e.severity}">${e.severity}</span></h2>
      <button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
    ${e.has_snapshot ? `<img class="full" alt="Event snapshot" src="/api/events/${e.id}/snapshot">` : ''}
    <table>${facts.map(([k, v]) => `<tr><th>${k}</th><td>${esc(v)}</td></tr>`).join('')}</table>
    <div class="row" data-ev-id="${e.id}" data-cam="${e.camera_id}" data-ts="${e.ts}">
      ${can('operator') && !e.acknowledged ? '<button class="btn primary" data-action="ack">Acknowledge</button>' : ''}
      <button class="btn" data-action="clip">Play clip</button>
      ${can('operator') && e.searchable ? '<button class="btn" data-action="similar">Find across cameras</button>' : ''}</div>
    <div id="similar"></div>`);
}

/* ---------------------------------------------------------------- cameras */
async function vCameras(el) {
  await loadCams();
  el.innerHTML = `<div class="glass panel"><div class="row between"><h2>${S.cams.length} cameras</h2>
      <button class="btn primary" data-action="cam-new">Add camera</button></div>
    <table><thead><tr><th>Name</th><th>Site</th><th>PTZ/ONVIF</th><th>AI</th><th>Recording</th><th>Low-light IR</th><th></th></tr></thead><tbody>
    ${S.cams.map(c => `<tr><td>${esc(c.name)}${c.enabled ? '' : ' <span class="muted">(disabled)</span>'}</td><td>${esc(c.site)}</td>
      <td>${c.ptz ? 'yes' : '—'}</td><td>${c.ai_enabled ? 'on' : 'off'}</td><td>${c.record ? 'on' : 'off'}</td>
      <td>${c.auto_ir ? 'software auto' : esc(c.ir_mode)}</td>
      <td class="row"><button class="btn small" data-action="cam-edit" data-id="${c.id}">Edit</button>
      <button class="btn small danger" data-action="cam-del" data-id="${c.id}">Delete</button></td></tr>`).join('')}
    </tbody></table></div>`;
}

function camForm(c = {}) {
  const v = k => esc(c[k] ?? '');
  const chk = (k, def) => (c[k] ?? def) ? 'checked' : '';
  openModal(`<div class="row between"><h2>${c.id ? 'Edit' : 'Add'} camera</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
    <form data-form="camera" data-id="${c.id || ''}">
      <div class="grid2"><label>Name<input name="name" required maxlength="120" value="${v('name')}"></label>
      <label>Site / zone<input name="site" maxlength="120" value="${v('site')}"></label></div>
      <h3>ONVIF (auto-discover streams, PTZ, IR, alarm relay)</h3>
      <div class="grid2"><label>Host / IP<input name="onvif_host" value="${v('onvif_host')}"></label>
      <label>Port<input name="onvif_port" type="number" value="${c.onvif_port || 80}"></label>
      <label>User<input name="onvif_user" autocomplete="off" value="${v('onvif_user')}"></label>
      <label>Password<input name="onvif_pass" type="password" autocomplete="new-password" placeholder="${c.id ? 'unchanged' : ''}"></label></div>
      <div class="row"><button type="button" class="btn" data-action="probe">Probe ONVIF</button><span id="probeOut" class="small muted"></span></div>
      <h3>Streams</h3>
      <label>Main stream (recording, full screen)<input name="main_url" placeholder="rtsp://<user>:<password>@10.0.20.11:554/Streaming/Channels/101" value="${v('main_url')}" ${c.id ? '' : 'required'}></label>
      <label>Substream (AI + grid tiles; strongly recommended)<input name="sub_url" placeholder="rtsp://…/102" value="${v('sub_url')}"></label>
      <h3>Analytics</h3>
      <div class="row"><label class="check"><input type="checkbox" name="enabled" ${chk('enabled', true)}> Enabled</label>
        <label class="check"><input type="checkbox" name="record" ${chk('record', true)}> Record 24×7</label>
        <label class="check"><input type="checkbox" name="ai_enabled" ${chk('ai_enabled', true)}> AI detection</label>
        <label class="check"><input type="checkbox" name="auto_ir" ${chk('auto_ir', false)}> Software low-light IR switching</label>
        <label class="check"><input type="checkbox" name="attendance" ${chk('attendance', false)}> CCTV attendance point (passive liveness)</label></div>
      <div class="grid2"><label>Low-light threshold (luma 0-255)<input name="lowlight_threshold" type="number" min="1" max="200" value="${c.lowlight_threshold || 40}"></label>
        <label>Loitering after (seconds)<input name="loiter_seconds" type="number" min="10" value="${c.loiter_seconds || 60}"></label>
        <label>Daylight window start<input name="day_start" type="time" value="${c.day_start || '06:00'}"></label>
        <label>Daylight window end<input name="day_end" type="time" value="${c.day_end || '18:30'}"></label>
        <label>Relay token (blank = first relay)<input name="relay_token" value="${v('relay_token')}"></label></div>
      <p class="small muted">Prefer the camera's own "Auto" IR mode when it has a light sensor. Software switching is for cameras without one.</p>
      <button class="btn primary wide">Save camera</button></form>`);
}

/* ------------------------------------------------------------------ rules */
async function vRules(el) {
  await loadCams();
  const rules = await api('/api/rules');
  el.innerHTML = `<div class="glass panel"><div class="row between"><h2>Alert rules</h2>
      ${can('admin') ? '<button class="btn primary" data-action="rule-new">New rule</button>' : ''}</div>
    <table><thead><tr><th>Rule</th><th>Cameras</th><th>Triggers</th><th>Schedule</th><th>Actions</th><th>Severity</th><th></th></tr></thead><tbody>
    ${rules.map(r => `<tr><td>${esc(r.name)}${r.enabled ? '' : ' <span class="muted">(off)</span>'}${r.zone ? ' <span class="pill small">zone</span>' : ''}</td>
      <td class="small">${r.camera_ids.length ? esc(r.camera_ids.map(camName).join(', ')) : 'All'}</td>
      <td class="small">${esc(r.classes.join(', ') || 'any')}</td>
      <td class="small">${esc((r.schedule.days || []).map(d => DAYS[d]).join(' '))} ${esc(r.schedule.start)}–${esc(r.schedule.end)}</td>
      <td class="small">${esc([r.actions.sms?.length && 'SMS', r.actions.whatsapp?.length && 'WhatsApp', r.actions.alarm && 'Alarm', r.actions.webhook && 'Webhook'].filter(Boolean).join(', ') || 'console only')}</td>
      <td><span class="sev sev-${r.severity}">${r.severity}</span></td>
      <td>${can('admin') ? `<button class="btn small" data-action="rule-edit" data-rule='${esc(JSON.stringify(r))}'>Edit</button>
        <button class="btn small danger" data-action="rule-del" data-id="${r.id}">Delete</button>` : ''}</td></tr>`).join('') || '<tr><td colspan="7" class="muted">No rules yet — events are logged but nobody is alerted.</td></tr>'}
    </tbody></table></div>`;
}

function ruleForm(r = {}) {
  S.ruleDraft = { zone: r.zone || null };
  const sched = r.schedule || { days: [0, 1, 2, 3, 4, 5, 6], start: '00:00', end: '23:59' };
  const a = r.actions || {};
  const chips = (name, items, sel, lbl = x => x) => `<div class="chips" data-chips="${name}">${items.map(x =>
    `<span class="chip ${sel.includes(x) ? 'on' : ''}" data-action="chip" data-v="${esc(x)}">${esc(lbl(x))}</span>`).join('')}</div>`;
  openModal(`<div class="row between"><h2>${r.id ? 'Edit' : 'New'} rule</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
    <form data-form="rule" data-id="${r.id || ''}">
      <div class="grid2"><label>Name<input name="name" required maxlength="120" value="${esc(r.name || '')}"></label>
      <label>Severity<select name="severity">${['low', 'medium', 'high', 'critical'].map(s => `<option ${s === (r.severity || 'medium') ? 'selected' : ''}>${s}</option>`).join('')}</select></label></div>
      <label>Cameras (none selected = all)</label>${chips('camera_ids', S.cams.map(c => String(c.id)), (r.camera_ids || []).map(String), id => camName(+id))}
      <label>Triggers</label>${chips('classes', CLASSES, r.classes || ['person'])}
      <div class="grid2"><label>Min confidence<input name="min_conf" type="number" step="0.05" min="0" max="1" value="${r.min_conf ?? 0.5}"></label>
      <label>Cooldown per camera (s)<input name="cooldown_s" type="number" min="0" value="${r.cooldown_s ?? 60}"></label></div>
      <label>Active days</label>${chips('days', ['0', '1', '2', '3', '4', '5', '6'], sched.days.map(String), d => DAYS[+d])}
      <div class="grid2"><label>From<input name="start" type="time" value="${sched.start}"></label><label>To (overnight allowed)<input name="end" type="time" value="${sched.end}"></label></div>
      <h3>Zone</h3><div class="row"><button type="button" class="btn" data-action="zone-edit">Draw zone on live view</button>
        <button type="button" class="btn ghost" data-action="zone-clear">Clear</button><span id="zoneInfo" class="small muted">${r.zone ? `${r.zone.length}-point zone` : 'Whole frame'}</span></div>
      <div id="zoneBox"></div>
      <h3>Actions</h3>
      <label>SMS numbers (E.164, comma separated)<input name="sms" placeholder="+9198XXXXXXXX" value="${esc((a.sms || []).join(', '))}"></label>
      <label>WhatsApp numbers<input name="whatsapp" placeholder="+9198XXXXXXXX" value="${esc((a.whatsapp || []).join(', '))}"></label>
      <div class="row"><label class="check"><input type="checkbox" name="alarm" ${a.alarm ? 'checked' : ''}> Trigger siren/strobe (camera relay + webhook)</label>
        <label class="check"><input type="checkbox" name="webhook" ${a.webhook ? 'checked' : ''}> Webhook only</label>
        <label class="check"><input type="checkbox" name="enabled" ${r.enabled ?? true ? 'checked' : ''}> Rule enabled</label></div>
      <button class="btn primary wide">Save rule</button></form>`);
}

function zoneEditor() {
  const ids = $$('[data-chips="camera_ids"] .chip.on').map(c => +c.dataset.v);
  const cam = ids[0] || S.cams[0]?.id;
  if (!cam) return toast('Add a camera first', true);
  const box = $('#zoneBox');
  box.innerHTML = `<p class="small muted">Click to add points on ${esc(camName(cam))}. The alert fires when an object's feet are inside.</p>
    <div class="zone-wrap"><video muted playsinline autoplay></video><canvas></canvas></div>`;
  const video = $('video', box), canvas = $('canvas', box);
  const p = new Player(video, cam, 'sub');
  S.modalPlayers.push(p);
  p.start();
  const pts = S.ruleDraft.zone ? [...S.ruleDraft.zone] : [];
  const draw = () => {
    const w = canvas.width = canvas.clientWidth, h = canvas.height = canvas.clientHeight, g = canvas.getContext('2d');
    g.clearRect(0, 0, w, h);
    if (!pts.length) return;
    g.beginPath();
    pts.forEach(([x, y], i) => (i ? g.lineTo(x * w, y * h) : g.moveTo(x * w, y * h)));
    g.closePath();
    g.fillStyle = 'rgba(92,225,255,.18)'; g.strokeStyle = '#5ce1ff'; g.lineWidth = 2; g.fill(); g.stroke();
    pts.forEach(([x, y]) => { g.beginPath(); g.arc(x * w, y * h, 4, 0, 7); g.fillStyle = '#fff'; g.fill(); });
  };
  canvas.addEventListener('click', e => {
    const r = canvas.getBoundingClientRect();
    pts.push([+((e.clientX - r.left) / r.width).toFixed(4), +((e.clientY - r.top) / r.height).toFixed(4)]);
    S.ruleDraft.zone = pts.length >= 3 ? [...pts] : null;
    $('#zoneInfo').textContent = pts.length >= 3 ? `${pts.length}-point zone` : `${pts.length} points (need 3+)`;
    draw();
  });
  setTimeout(draw, 50);
}

/* ------------------------------------------------------------- watchlists */
async function vWatchlists(el) {
  const rows = await api('/api/watchlists');
  el.innerHTML = `${can('admin') ? `<div class="grid2">
    <div class="glass panel"><h2>Add vehicle plate</h2><form data-form="plate">
      <label>Label<input name="label" required maxlength="120" placeholder="Blocked vendor van"></label>
      <label>Plate<input name="plate" required maxlength="20" placeholder="TN09AB1234"></label>
      <div class="grid2"><label>List<select name="list_type"><option value="deny">Deny (alert)</option><option value="allow">Allow</option></select></label>
      <label>Expires after (days)<input name="days" type="number" value="365" min="1" max="3650"></label></div>
      <button class="btn primary wide">Add plate</button></form></div>
    <div class="glass panel"><h2>Enrol a face</h2><form data-form="face">
      <label>Label<input name="label" required maxlength="120"></label>
      <label>Lawful basis / consent reference (required)<input name="consent_ref" required minlength="3" maxlength="255" placeholder="Consent form #, police request ref…"></label>
      <div class="grid2"><label>List<select name="list_type"><option value="deny">Deny (alert)</option><option value="allow">Allow</option></select></label>
      <label>Expires after (days)<input name="days" type="number" value="90" min="1" max="365"></label></div>
      <label>Photo (frontal face)<input name="image" type="file" accept="image/jpeg,image/png" required></label>
      <p class="small muted">Only the face signature is kept — the photo is discarded. Entries expire automatically (DPDP Act 2023 minimisation).</p>
      <button class="btn primary wide">Enrol face</button></form></div></div>` : ''}
    <div class="glass panel"><table><thead><tr><th>Type</th><th>Label</th><th>Value</th><th>List</th><th>Basis</th><th>Added</th><th>Expires</th><th></th></tr></thead><tbody>
    ${rows.map(w => `<tr><td>${w.kind}</td><td>${esc(w.label)}</td><td class="mono">${esc(w.value || (w.has_embedding ? 'face signature' : ''))}</td>
      <td><span class="sev ${w.list_type === 'deny' ? 'sev-high' : 'sev-low'}">${w.list_type}</span></td><td class="small">${esc(w.consent_ref)}</td>
      <td class="small">${esc(w.created_by)} · ${esc(fmt(w.created_at))}</td><td class="small">${esc(fmt(w.expires_at))}</td>
      <td>${can('admin') ? `<button class="btn small danger" data-action="wl-del" data-id="${w.id}">Remove</button>` : ''}</td></tr>`).join('') || '<tr><td colspan="8" class="muted">Empty.</td></tr>'}
    </tbody></table></div>`;
}

/* ------------------------------------------------------------ users/audit */
const ROLE_HELP = {
  kiosk: 'Check-in screen only.', viewer: 'Live view and playback; faces always blurred.',
  operator: 'Adds camera control, attendance, and requesting an unblur.', admin: 'Adds configuration, people, reports and inviting staff.',
  superadmin: 'Approves unblurring with MFA and the vault passphrase; the only role that can export video or invite admins.',
};
async function vUsers(el) {
  const [users, invites] = await Promise.all([api('/api/users'), api('/api/users/invites')]);
  const pending = invites.filter(i => i.state === 'pending');
  el.innerHTML = `<div class="grid2">
    <div class="glass panel"><h2>${ic('link')} Invite someone</h2>
      <form data-form="invite">
        <label>Role<select name="role">${roleOptions('operator')}</select></label>
        <p class="small muted" id="roleHelp">${ROLE_HELP.operator}</p>
        <div class="grid2"><label>Email (optional, for alerts)<input name="email" type="email"></label>
          <label>Mobile (optional)<input name="phone" placeholder="+9198XXXXXXXX" pattern="\\+[1-9][0-9]{7,14}"></label></div>
        <label>Note for the audit log<input name="note" maxlength="255" placeholder="e.g. HOD, Computer Science"></label>
        <label>Link valid for<select name="hours"><option value="24">24 hours</option><option value="72" selected>3 days</option><option value="168">7 days</option></select></label>
        <button class="btn primary wide">Create invitation link</button></form>
      <p class="small muted">The person opens the link, picks their own username and password, and sets up MFA. Nobody else ever sees their password.
        ${can('superadmin') ? 'Invitations for admins and super admins alert every super admin.' : 'Only a super admin can invite admins.'}</p></div>
    <div class="glass panel"><h2>Open invitations</h2>
      <table><thead><tr><th>Role</th><th>For</th><th>By</th><th>Expires</th><th></th></tr></thead><tbody>
      ${pending.map(i => `<tr><td>${esc(i.role)}${i.kind === 'reset' ? ' <span class="sev sev-info">reset</span>' : ''}</td><td class="small">${esc(i.email || i.note || '—')}</td>
        <td class="small">${esc(i.created_by)}</td><td class="small">${esc(fmt(i.expires_at))}</td>
        <td><button class="btn small ghost" data-action="invite-revoke" data-id="${i.id}">Revoke</button></td></tr>`).join('') || empty('link', 'No open invitations.', 5)}
      </tbody></table>
      ${invites.length > pending.length ? `<details><summary class="small">History (${invites.length - pending.length})</summary><table><tbody>
        ${invites.filter(i => i.state !== 'pending').slice(0, 30).map(i => `<tr><td class="small">${esc(i.role)}</td><td class="small">${esc(i.state)}${i.used_by ? ` by ${esc(i.used_by)}` : ''}</td>
          <td class="small">${esc(i.created_by)}</td><td class="small">${esc(fmt(i.used_at || i.expires_at))}</td></tr>`).join('')}</tbody></table></details>` : ''}</div></div>
    <div class="glass panel"><h2>${users.length} ${users.length === 1 ? 'account' : 'accounts'}</h2><table><thead><tr><th>User</th><th>Role</th><th>MFA</th><th>Alert contacts</th><th>Status</th><th>Joined</th><th></th></tr></thead><tbody>
    ${users.map(u => `<tr data-uid="${u.id}"><td><b>${esc(u.username)}</b>${u.id === S.user.id ? ' <span class="muted small">(you)</span>' : ''}</td>
      <td>${u.role === 'superadmin' && !can('superadmin') ? '<span class="pill">super admin</span>' : `<select data-action-change="role" aria-label="Role of ${esc(u.username)}">${roleOptions(u.role)}</select>`}</td>
      <td>${u.mfa ? `<span class="sev sev-low">on</span>` : '<span class="sev sev-medium">pending</span>'}</td>
      <td class="small">${esc([u.phone, u.email].filter(Boolean).join(', ')) || '<span class="muted">none</span>'}
        <button class="btn ghost small" data-action="user-contacts" data-phone="${esc(u.phone)}" data-email="${esc(u.email)}">Edit</button></td>
      <td>${u.disabled ? '<span class="sev sev-info">disabled</span>' : u.locked ? '<span class="sev sev-high">locked</span>' : '<span class="sev sev-low">active</span>'}</td>
      <td class="small">${esc(fmt(u.created_at))}</td>
      <td class="row">${u.locked ? '<button class="btn small" data-action="user-patch" data-p="unlock">Unlock</button>' : ''}
        <button class="btn small" data-action="user-patch" data-p="reset_mfa">Reset MFA</button>
        <button class="btn small" data-action="user-patch" data-p="reset_password">Send reset link</button>
        <button class="btn small" data-action="user-patch" data-p="${u.disabled ? 'enable' : 'disable'}">${u.disabled ? 'Enable' : 'Disable'}</button>
        <button class="btn small danger" data-action="user-del">Delete</button></td></tr>`).join('')}
    </tbody></table></div>`;
  $('form[data-form=invite] select[name=role]').addEventListener('change', e => { $('#roleHelp').textContent = ROLE_HELP[e.target.value]; });
}

function showLink(title, link, note) {
  const url = `${location.origin}${link.path}`;
  openModal(`<div class="row between"><h2>${esc(title)}</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
    <p class="muted">${esc(note)} It works once and expires ${esc(fmt(link.expires_at))}. Send it over a channel you trust (in person, official email); anyone holding it can use it.</p>
    <div class="linkbox"><code class="secret" id="linkOut">${esc(url)}</code><button class="btn" data-action="copy-link">Copy</button></div>
    <button class="btn primary wide" data-action="close">Done</button>`);
}

async function vAudit(el) {
  const rows = await api('/api/audit?limit=500');
  el.innerHTML = `<div class="glass panel"><table><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Target</th><th>IP</th><th>Detail</th></tr></thead><tbody>
    ${rows.map(r => `<tr><td class="mono small">${esc(fmt(r.ts))}</td><td>${esc(r.user)}</td><td>${esc(r.action)}</td><td>${esc(r.target)}</td>
      <td class="mono small">${esc(r.ip)}</td><td class="small muted">${esc(Object.keys(r.detail || {}).length ? JSON.stringify(r.detail) : '')}</td></tr>`).join('')}
    </tbody></table></div>`;
}

/* ------------------------------------------------------------------ modal */
function openModal(html) {
  closeModal();
  $('#modalCard').innerHTML = html;
  $('#modal').classList.remove('hidden');
}
function closeModal() {
  S.modalPlayers.forEach(p => p.stop());
  S.modalPlayers = [];
  $('#modal').classList.add('hidden');
  $('#modalCard').innerHTML = '';
}
$('#modal').addEventListener('click', e => { if (e.target.id === 'modal') closeModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

function showSecret(title, value) {
  openModal(`<h2>${esc(title)}</h2><p class="muted">Shown once. Share it over a separate channel; the user sets up MFA at first sign-in.</p>
    <div class="secret">${esc(value)}</div><button class="btn primary wide" data-action="close">Done</button>`);
}

/* ----------------------------------------------------------------- actions */
const evFrom = t => JSON.parse(t.closest('[data-ev]').dataset.ev);
const ACTIONS = {
  close: () => closeModal(),
  logout: async () => { await api('/api/auth/logout', { method: 'POST' }).catch(() => {}); showLogin(); },
  mute: t => { S.muted = !S.muted; t.textContent = S.muted ? 'Sound off' : 'Sound on'; },
  password: () => openModal(`<div class="row between"><h2>Change password</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
    <form data-form="password"><label>Current password<input type="password" name="old_password" required autocomplete="current-password"></label>
    <label>New password (12+ characters)<input type="password" name="new_password" required minlength="12" autocomplete="new-password"></label>
    <button class="btn primary wide">Update and sign out other sessions</button></form>`),
  grid: t => { S.grid = +t.dataset.n; S.page = 0; S.focus = null; $$('[data-action=grid]').forEach(b => b.classList.toggle('on', b === t)); renderWall(); },
  page: t => { S.focus = null; S.page += +t.dataset.d; renderWall(); },
  tour: t => {
    if (S.tour) { clearInterval(S.tour); S.tour = null; t.classList.remove('on'); return; }
    S.tour = setInterval(() => { S.page++; renderWall(); }, 20000);
    t.classList.add('on');
  },
  fs: t => t.closest('.tile').requestFullscreen?.(),
  snap: async t => {
    const tile = t.closest('.tile'), v = $('video', tile);
    if (!v.videoWidth) return toast('No video yet', true);
    await api('/api/audit/client-snapshot', { method: 'POST', body: { camera_id: +tile.dataset.cam } });  // super admin only; reported
    const c = document.createElement('canvas');
    c.width = v.videoWidth; c.height = v.videoHeight;
    c.getContext('2d').drawImage(v, 0, 0);
    c.toBlob(b => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(b);
      a.download = `${camName(+tile.dataset.cam)}-${new Date().toISOString().replace(/[:.]/g, '-')}.png`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    }, 'image/png');
  },
  rewind: t => { location.hash = `#/playback?cam=${t.closest('[data-cam]').dataset.cam}&ts=${new Date(Date.now() - 6 * 60000).toISOString()}`; },
  ir: async t => {
    const cam = t.closest('[data-cam]').dataset.cam;
    await api(`/api/cameras/${cam}/ir`, { method: 'POST', body: { mode: t.dataset.mode } });
    toast(`IR mode → ${t.dataset.mode}`);
  },
  alarm: async t => {
    const cam = +t.closest('[data-cam]').dataset.cam;
    if (!confirm(`Activate the siren/strobe on ${camName(cam)} for 30 seconds?`)) return;
    await api(`/api/cameras/${cam}/relay`, { method: 'POST', body: { active: true } });
    toast('Alarm activated');
    setTimeout(() => api(`/api/cameras/${cam}/relay`, { method: 'POST', body: { active: false } }).catch(() => {}), 30000);
  },
  presets: async t => {
    const cam = t.closest('[data-cam]').dataset.cam;
    const r = await api(`/api/cameras/${cam}/ptz`, { method: 'POST', body: { action: 'presets' } });
    const list = r.result || [];
    if (!list.length) return toast('No presets on this camera');
    openModal(`<h2>PTZ presets · ${esc(camName(+cam))}</h2><div class="chips" data-cam="${cam}">${list.map(p =>
      `<span class="chip" data-action="goto-preset" data-token="${esc(p.token)}">${esc(p.name || p.token)}</span>`).join('')}</div>`);
  },
  'goto-preset': async t => {
    await api(`/api/cameras/${t.closest('[data-cam]').dataset.cam}/ptz`, { method: 'POST', body: { action: 'goto_preset', preset: t.dataset.token } });
    closeModal();
  },
  'open-event': t => openEvent(evFrom(t)),
  ack: async t => {
    const id = t.closest('[data-ev-id]').dataset.evId;
    await api(`/api/events/${id}/ack`, { method: 'POST' });
    t.remove(); refreshBadge(); toast('Acknowledged');
  },
  'ack-all': async () => {
    if (!confirm('Acknowledge every open event?')) return;
    const r = await api('/api/events/ack-all', { method: 'POST' });
    toast(`${r.acknowledged} acknowledged`); refreshBadge();
    $('#alertList').innerHTML = '<p class="muted small">No alerts yet.</p>';
    if (location.hash.startsWith('#/events')) loadEvents(true);
  },
  clip: t => {
    const d = t.closest('[data-ev-id]').dataset;
    closeModal();
    location.hash = `#/playback?cam=${d.cam}&ts=${new Date(new Date(d.ts) - 15000).toISOString()}`;
  },
  similar: async t => {
    const id = t.closest('[data-ev-id]').dataset.evId;
    const rows = await api(`/api/events/${id}/similar`, { method: 'POST' });
    $('#similar').innerHTML = `<h3>${rows.length} likely matches (last 24 h)</h3><div class="cards">${rows.map(r =>
      `<div class="glass kpi" data-ev='${esc(JSON.stringify(r))}' data-action="open-event">
        ${r.has_snapshot ? `<img class="thumb" alt="" src="/api/events/${r.id}/snapshot">` : ''}
        <div class="small">${esc(camName(r.camera_id))}</div><div class="small muted">${esc(fmt(r.ts))} · ${Math.round(r.score * 100)}%</div></div>`).join('')}</div>`;
  },
  'ev-more': () => loadEvents(false),
  'cam-new': () => camForm(),
  'cam-edit': async t => camForm(await api(`/api/cameras/${t.dataset.id}`)),
  'cam-del': async t => {
    if (!confirm(`Delete ${camName(+t.dataset.id)}? Recordings stay on disk until retention removes them.`)) return;
    await api(`/api/cameras/${t.dataset.id}`, { method: 'DELETE' }); route();
  },
  probe: async () => {
    const f = $('form[data-form=camera]');
    $('#probeOut').textContent = 'Probing…';
    try {
      const prof = await api('/api/cameras/probe', { method: 'POST', body: { host: f.onvif_host.value, port: +f.onvif_port.value || 80, user: f.onvif_user.value, password: f.onvif_pass.value } });
      if (prof[0]) f.main_url.value = prof[0].uri;
      if (prof[1]) f.sub_url.value = prof[prof.length - 1].uri;
      $('#probeOut').textContent = prof.map(p => `${p.profile} ${p.width}×${p.height} ${p.encoding || ''}`).join(' · ');
    } catch (e) { $('#probeOut').textContent = e.message; }
  },
  chip: t => t.classList.toggle('on'),
  'rule-new': () => ruleForm(),
  'rule-edit': t => ruleForm(JSON.parse(t.dataset.rule)),
  'rule-del': async t => { if (confirm('Delete this rule?')) { await api(`/api/rules/${t.dataset.id}`, { method: 'DELETE' }); route(); } },
  'zone-edit': () => zoneEditor(),
  'zone-clear': () => { S.ruleDraft.zone = null; $('#zoneInfo').textContent = 'Whole frame'; S.modalPlayers.forEach(p => p.stop()); S.modalPlayers = []; $('#zoneBox').innerHTML = ''; },
  'wl-del': async t => { if (confirm('Remove this watchlist entry?')) { await api(`/api/watchlists/${t.dataset.id}`, { method: 'DELETE' }); route(); } },
  'user-patch': async t => {
    const uid = t.closest('[data-uid]').dataset.uid, p = t.dataset.p;
    const body = p === 'disable' ? { disabled: true } : p === 'enable' ? { disabled: false } : { [p]: true };
    if (['reset_mfa', 'reset_password', 'disable'].includes(p) && !confirm(`${t.textContent}? The person is signed out everywhere.`)) return;
    const r = await api(`/api/users/${uid}`, { method: 'PATCH', body });
    if (r.reset_link) { showLink('Password reset link', r.reset_link, 'The old password has stopped working and every session is signed out.'); route(); }
    else route();
  },
  'invite-revoke': async t => { if (confirm('Revoke this invitation? The link stops working.')) { await api(`/api/users/invites/${t.dataset.id}`, { method: 'DELETE' }); route(); } },
  'copy-link': async () => {
    try { await navigator.clipboard.writeText($('#linkOut').textContent); toast('Link copied'); }
    catch { const r = document.createRange(); r.selectNodeContents($('#linkOut')); getSelection().removeAllRanges(); getSelection().addRange(r); toast('Select and copy the link'); }
  },
  'setup-skip': () => { setupStep(5); $('#setupRecovery').textContent = 'No vault yet. Create it later under Privacy, then Encryption vault.'; },
  'setup-finish': async () => { await start(await api('/api/auth/me')); },
  'user-del': async t => { if (confirm('Delete this user?')) { await api(`/api/users/${t.closest('[data-uid]').dataset.uid}`, { method: 'DELETE' }); route(); } },
};

document.addEventListener('click', async e => {
  const t = e.target.closest('[data-action]');
  if (!t || !ACTIONS[t.dataset.action]) return;
  if (t.tagName === 'A') e.preventDefault();
  try { await ACTIONS[t.dataset.action](t, e); } catch (err) { toast(err.message, true); }
});

document.addEventListener('change', async e => {
  if (e.target.dataset.actionChange !== 'role') return;
  try {
    await api(`/api/users/${e.target.closest('[data-uid]').dataset.uid}`, { method: 'PATCH', body: { role: e.target.value } });
    toast('Role updated');
  } catch (err) { toast(err.message, true); route(); }
});

/* ------------------------------------------------------------------ forms */
const list = s => s.split(',').map(x => x.trim()).filter(Boolean);
const chipVals = (f, name) => $$(`[data-chips="${name}"] .chip.on`, f).map(c => c.dataset.v);
const FORMS = {
  evFilter: async f => {
    S.evFilter = { camera_id: f.camera_id.value, kind: f.kind.value, label: f.label.value.trim(), severity: f.severity.value,
      unacked: f.unacked.checked ? 'true' : '', since: f.since.value ? new Date(f.since.value).toISOString() : '' };
    S.evOldest = null;
    await loadEvents(true);
  },
  camera: async f => {
    const g = n => f[n].value.trim();
    const body = { name: g('name'), site: g('site'), main_url: g('main_url'), sub_url: g('sub_url'), onvif_host: g('onvif_host'),
      onvif_port: +g('onvif_port') || 80, onvif_user: g('onvif_user'), onvif_pass: f.onvif_pass.value, relay_token: g('relay_token'),
      enabled: f.enabled.checked, record: f.record.checked, ai_enabled: f.ai_enabled.checked, auto_ir: f.auto_ir.checked, attendance: f.attendance.checked,
      lowlight_threshold: +g('lowlight_threshold'), day_start: g('day_start'), day_end: g('day_end'), loiter_seconds: +g('loiter_seconds') };
    const id = f.dataset.id;
    await api(id ? `/api/cameras/${id}` : '/api/cameras', { method: id ? 'PUT' : 'POST', body });
    closeModal(); toast('Camera saved'); route();
  },
  rule: async f => {
    const days = chipVals(f, 'days').map(Number);
    const body = { name: f.name.value.trim(), enabled: f.enabled.checked, severity: f.severity.value,
      camera_ids: chipVals(f, 'camera_ids').map(Number), classes: chipVals(f, 'classes'), zone: S.ruleDraft.zone,
      min_conf: +f.min_conf.value, cooldown_s: +f.cooldown_s.value,
      schedule: { days: days.length ? days : [0, 1, 2, 3, 4, 5, 6], start: f.start.value || '00:00', end: f.end.value || '23:59' },
      actions: { sms: list(f.sms.value), whatsapp: list(f.whatsapp.value), alarm: f.alarm.checked, webhook: f.webhook.checked } };
    const id = f.dataset.id;
    await api(id ? `/api/rules/${id}` : '/api/rules', { method: id ? 'PUT' : 'POST', body });
    closeModal(); toast('Rule saved'); route();
  },
  plate: async f => { await api('/api/watchlists/plate', { method: 'POST', form: new FormData(f) }); toast('Plate added'); route(); },
  face: async f => { await api('/api/watchlists/face', { method: 'POST', form: new FormData(f) }); toast('Face enrolled'); route(); },
  invite: async f => {
    const r = await api('/api/users/invites', { method: 'POST', body: { role: f.role.value, email: f.email.value.trim(),
      phone: f.phone.value.trim(), note: f.note.value.trim(), hours: +f.hours.value } });
    showLink(`Invitation for a new ${r.role === 'superadmin' ? 'super admin' : r.role}`, r, 'Share this link with the person you are inviting.');
    vUsers($('#view'));
  },
  setupAccount: async f => {
    formErr(f, '');
    if (f.password.value !== f.password2.value) return formErr(f, 'The passwords do not match.');
    try {
      const d = await api('/api/setup/register', { method: 'POST', body: { setup_code: f.setup_code.value.trim(), username: f.username.value.trim(),
        password: f.password.value, email: f.email.value.trim(), phone: f.phone.value.trim() } });
      showMfa($('[data-form=setupMfa]'), d);
      f.reset();
      setupStep(3);
    } catch (e) { formErr(f, e.message); }
  },
  setupMfa: async f => {
    formErr(f, '');
    try {
      const res = await api('/api/auth/mfa/enroll', { method: 'POST', body: { setup_token: f.dataset.token, totp: f.totp.value.trim() } });
      S.csrf = res.csrf; S.user = res.user;
      setupStep(4);
    } catch (e) { formErr(f, e.message); }
  },
  setupVault: async f => {
    formErr(f, '');
    if (f.passphrase.value !== f.passphrase2.value) return formErr(f, 'The passphrases do not match.');
    try {
      const r = await api('/api/vault/setup', { method: 'POST', body: { passphrase: f.passphrase.value, totp: f.totp.value.trim() } });
      f.reset();
      $('#setupRecovery').textContent = r.recovery_code;
      setupStep(5);
    } catch (e) { formErr(f, e.message.includes('authenticator') ? `${e.message}. Wait for the next code in your app and try again.` : e.message); }
  },
  register: async f => {
    formErr(f, '');
    if (f.password.value !== f.password2.value) return formErr(f, 'The passwords do not match.');
    try {
      const body = { code: S.regCode, password: f.password.value };
      if (S.regKind !== 'reset') Object.assign(body, { username: f.username.value.trim(), email: f.email.value.trim(), phone: f.phone.value.trim() });
      const d = await api('/api/register', { method: 'POST', body });
      f.reset();
      S.regCode = null;
      if (d.mfa_setup_required) {
        const m = $('[data-form=registerMfa]');
        showMfa(m, d);
        f.classList.add('hidden'); m.classList.remove('hidden');
        m.totp.focus();
      } else {
        location.hash = '#/';
        showLogin();
        $('#loginErr').textContent = '';
        toast('Password changed. Sign in with your new password.');
      }
    } catch (e) { formErr(f, e.message); }
  },
  registerMfa: async f => {
    formErr(f, '');
    try {
      const res = await api('/api/auth/mfa/enroll', { method: 'POST', body: { setup_token: f.dataset.token, totp: f.totp.value.trim() } });
      location.hash = '#/dashboard';
      await start(res);
    } catch (e) { formErr(f, e.message); }
  },
  password: async f => {
    const r = await api('/api/auth/password', { method: 'POST', body: { old_password: f.old_password.value, new_password: f.new_password.value } });
    S.csrf = r.csrf; closeModal(); toast('Password changed; other sessions signed out');
  },
};
document.addEventListener('submit', async e => {
  const f = e.target;
  if (!f.dataset.form) return;
  e.preventDefault();
  const btn = f.querySelector('button:not([type=button])');
  if (btn) btn.disabled = true;
  if (f.dataset.form === 'setupAccount') setupStep(2);
  try { await FORMS[f.dataset.form](f); } catch (err) { toast(err.message, true); } finally { if (btn) btn.disabled = false; }
});

/* ------------------------------------------------------------------- boot */
function roleOptions(sel) {
  return ['kiosk', 'viewer', 'operator', ...(can('superadmin') ? ['admin', 'superadmin'] : sel === 'admin' ? ['admin'] : [])]
    .map(r => `<option value="${r}" ${r === sel ? 'selected' : ''}>${r === 'superadmin' ? 'super admin' : r}</option>`).join('');
}
document.addEventListener('DOMContentLoaded', async () => {
  if (location.hash.startsWith('#/register?')) return showPublic();  // invitation links always open the registration screen
  try { await start(await api('/api/auth/me')); } catch { showPublic(); }
});
