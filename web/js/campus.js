'use strict';
/* Campus edition: encrypted playback, attendance, people, live-liveness kiosk, privacy centre.
   Extends VIEWS / ACTIONS / FORMS from app.js (loaded first). */

const pad2 = n => String(n).padStart(2, '0');
const hms = d => `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
const ymd = d => `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
const STATUS = { present: 'sev-low', late: 'sev-medium', review: 'sev-high', rejected: 'sev-critical', absent: 'sev-info' };

/* ------------------------------------------------------------ security feed */
function onSecurity(n) {
  S.bell = (S.bell || 0) + 1;
  paintBell();
  toast(`Security: ${n.message}`, n.severity === 'high');
  if (location.hash.startsWith('#/privacy')) route();
}
async function refreshBell() {
  try { S.bell = (await api('/api/notifications?limit=200')).unread; paintBell(); } catch { /* ignore */ }
}
function paintBell() { const b = $('#bellCount'); if (b) { b.textContent = S.bell; b.classList.toggle('hidden', !S.bell); } }

async function askStepUp(title, html, fields = ['totp']) {
  return new Promise(resolve => {
    openModal(`<div class="row between"><h2>${esc(title)}</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
      ${html}<form data-form="stepup">
      ${fields.includes('reason') ? '<label>Reason / case reference (logged and sent to all admins)<input name="reason" required minlength="5" maxlength="300"></label>' : ''}
      ${fields.includes('passphrase') ? '<label>Vault passphrase<input name="passphrase" type="password" required autocomplete="off"></label>' : ''}
      <label>Your authenticator code<input name="totp" inputmode="numeric" maxlength="6" required autocomplete="one-time-code"></label>
      <button class="btn primary wide">Confirm</button></form>`);
    S.stepUp = resolve;
  });
}

/* ---------------------------------------------------- playback (encrypted) */
async function vPlayback(el) {
  await loadCams();
  const q = hashParams();
  const ts = q.get('ts') ? new Date(q.get('ts')) : new Date();
  el.innerHTML = `<div class="glass panel"><div class="row">
      <label>Camera<select id="pbCam">${S.cams.map(c => `<option value="${c.id}" ${String(c.id) === q.get('cam') ? 'selected' : ''}>${esc(c.name)}${c.record ? '' : ' (not recording)'}</option>`).join('')}</select></label>
      <label>Date<input type="date" id="pbDate" value="${ymd(ts)}"></label>
      <button class="btn" data-action="pb-load">Refresh</button>
      ${can('superadmin') ? '<button class="btn" data-action="pb-export">Export clip (super admin)</button>' : ''}</div>
      <div class="timeline" id="pbTimeline"></div><div class="row between small muted"><span>00:00</span><span>12:00</span><span>24:00</span></div>
      <p id="pbMsg" class="small muted"></p></div>
    <div class="glass panel"><video id="pbVideo" class="pbv" controls playsinline controlslist="nodownload noremoteplayback" disablepictureinpicture></video>
      <p class="small muted">Recordings are stored encrypted (AES-256-GCM) with every face blurred. Unblurred footage exists only sealed to the super admin vault.</p></div>`;
  $('#pbVideo').addEventListener('contextmenu', e => e.preventDefault());
  $('#pbCam').addEventListener('change', () => pbLoad());
  $('#pbDate').addEventListener('change', () => pbLoad());
  await pbLoad(q.get('ts') ? ts : null);
}
function pbMsg(t, bad = false) { const m = $('#pbMsg'); m.textContent = t; m.className = 'small ' + (bad ? 'err' : 'muted'); }
async function pbLoad(at = null) {
  const cam = S.camMap[+$('#pbCam').value];
  S.pbSegs = (await api(`/api/recordings?camera_id=${cam.id}&day=${$('#pbDate').value}`))
    .map(s => ({ ...s, from: new Date(s.start), to: new Date(s.end) }));
  const day = new Date(`${$('#pbDate').value}T00:00:00`), tl = $('#pbTimeline');
  tl.innerHTML = '';
  if (!S.pbSegs.length) {
    return pbMsg(cam.record ? 'No recordings for this camera on this day yet (segments appear every 5 minutes).'
      : `${cam.name} is not recording. Enable "Record 24×7" under Cameras → Edit.`, true);
  }
  S.pbSegs.forEach(s => {
    const i = document.createElement('i');
    i.style.left = `${Math.max(0, (s.from - day) / 864e5) * 100}%`;
    i.style.width = `${Math.max(0.15, ((s.to - s.from) / 864e5) * 100)}%`;
    i.title = `${hms(s.from)} – ${hms(s.to)}`;
    i.dataset.action = 'pb-seg';
    i.dataset.id = s.id;
    tl.append(i);
  });
  const mins = S.pbSegs.reduce((n, s) => n + (s.to - s.from), 0) / 60000;
  pbMsg(`${Math.round(mins)} min recorded, ${hms(S.pbSegs[0].from)} – ${hms(S.pbSegs.at(-1).to)}. Click a bar to play.`);
  const target = at ? S.pbSegs.find(s => at >= s.from && at < s.to) || S.pbSegs.find(s => s.from > at) : null;
  if (target) pbPlay(target, at > target.from ? (at - target.from) / 1000 : 0);
}
function pbPlay(seg, offset = 0) {
  S.pbCur = seg;
  const v = $('#pbVideo');
  v.src = `/api/recordings/${seg.id}/media`;
  v.onloadedmetadata = () => { if (offset) v.currentTime = offset; v.play().catch(() => {}); };
  v.onerror = () => pbMsg('This recording could not be played (it may have passed retention).', true);
  pbMsg(`Playing ${hms(seg.from)} – ${hms(seg.to)}`);
}

/* --------------------------------------------------------------- attendance */
async function vAttendance(el) {
  const q = hashParams();
  const day = q.get('day') || ymd(new Date());
  const f = { kind: q.get('kind') || '', department: q.get('department') || '', section: q.get('section') || '' };
  const d = await api(`/api/attendance/day?day=${day}&kind=${encodeURIComponent(f.kind)}&department=${encodeURIComponent(f.department)}&section=${encodeURIComponent(f.section)}`);
  const c = d.counts;
  const kpi = (l, v, cls = '', icon = 'attendance') => `<div class="glass kpi"><div class="muted small">${ic(icon)}${l}</div><div class="v ${cls}">${v}</div></div>`;
  const opt = (arr, sel) => arr.map(x => `<option ${x === sel ? 'selected' : ''}>${esc(x)}</option>`).join('');
  el.innerHTML = `<div class="glass panel"><form class="row" data-form="attFilter">
      <label>Date<input type="date" name="day" value="${day}"></label>
      <label>Type<select name="kind"><option value="">All</option>${opt(['student', 'staff'], f.kind)}</select></label>
      <label>Department<select name="department"><option value="">All</option>${opt(d.departments, f.department)}</select></label>
      <label>Class / section<select name="section"><option value="">All</option>${opt(d.sections, f.section)}</select></label>
      <button class="btn primary">Show</button>
      ${can('admin') ? '<button type="button" class="btn" data-action="att-export">Export CSV</button><button type="button" class="btn ghost" data-action="att-settings">Settings</button>' : ''}
      ${can('operator') ? '<a class="btn ghost" href="#/kiosk">Open kiosk</a>' : ''}</form>
      <p class="small muted">Late after ${esc(d.late_after)}. "Review" = recognised by CCTV without liveness proof; an admin must approve it.</p></div>
    <div class="cards">${kpi('Present', c.present, 'ok', 'check')}${kpi('Late', c.late, '', 'playback')}${kpi('Needs review', c.review, c.review ? 'bad' : '', 'eye')}
      ${kpi('Absent', c.absent, c.absent ? 'bad' : '', 'people')}${kpi('Attendance rate', d.total ? Math.round(((c.present + c.late) / d.total) * 100) + '%' : '—', '', 'overview')}</div>
    <div class="glass panel"><table><thead><tr><th></th><th>Roll / ID</th><th>Name</th><th>Dept · Section</th><th>Status</th><th>Time</th>
      <th>Method</th><th>Liveness</th><th>Match</th><th></th></tr></thead><tbody>
    ${d.rows.map(r => { const rec = r.record, p = r.person; return `<tr data-rec='${esc(JSON.stringify({ ...rec, person: { id: p.id, code: p.code, name: p.name } }))}'>
      <td>${rec?.has_evidence ? `<img class="thumb" alt="" loading="lazy" src="/api/attendance/records/${rec.id}/evidence" data-action="att-evidence">` : ''}</td>
      <td class="mono">${esc(p.code)}</td><td>${esc(p.name)}${p.enrolled ? '' : ' <span class="pill small">not enrolled</span>'}</td>
      <td class="small">${esc([p.department, p.section].filter(Boolean).join(' · '))}</td>
      <td><span class="sev ${STATUS[r.status]}">${r.status}</span></td>
      <td class="mono small">${rec?.first_seen ? new Date(rec.first_seen).toLocaleTimeString() : ''}</td>
      <td class="small">${esc(rec ? rec.method + (rec.camera_id ? ' · ' + camName(rec.camera_id) : '') : '')}</td>
      <td class="small">${rec ? (rec.liveness?.ok ? '✓ live' : rec.method === 'manual' ? '—' : '<span class="err">unverified</span>') : ''}</td>
      <td class="mono small">${rec?.score ? Math.round(rec.score * 100) + '%' : ''}</td>
      <td class="row">${rec && rec.status === 'review' && can('admin') ? `<button class="btn small" data-action="att-review" data-a="approve">Approve</button>
          <button class="btn small danger" data-action="att-review" data-a="reject">Reject</button>` : ''}
        ${rec && rec.has_raw && can('operator') ? '<button class="btn small" data-action="unblur-request">Request unblur</button>' : ''}
        ${can('admin') ? '<button class="btn small ghost" data-action="att-manual">Mark</button>' : ''}</td></tr>`; }).join('') || empty('people', 'No people yet. Add students and staff under People.', 10)}
    </tbody></table></div>`;
}

/* ------------------------------------------------------------------- people */
async function vPeople(el) {
  const q = hashParams().get('q') || '';
  const rows = await api(`/api/persons?q=${encodeURIComponent(q)}`);
  el.innerHTML = `<div class="glass panel"><form class="row" data-form="peopleSearch">
      <label>Search<input name="q" value="${esc(q)}" placeholder="Name or roll number"></label><button class="btn">Search</button>
      ${can('admin') ? '<button type="button" class="btn primary" data-action="person-new">Add person</button>' : ''}</form>
      <p class="small muted">Live enrolment uses the same anti-spoof challenge as the kiosk, so templates come from a real, present face.
      Only an encrypted face template is stored; photos are discarded.</p></div>
    <div class="glass panel"><table><thead><tr><th>Roll / ID</th><th>Name</th><th>Type</th><th>Dept · Section</th><th>Face</th><th>Consent</th><th></th></tr></thead><tbody>
    ${rows.map(p => `<tr data-person='${esc(JSON.stringify(p))}'><td class="mono">${esc(p.code)}</td><td>${esc(p.name)}${p.active ? '' : ' <span class="muted">(inactive)</span>'}</td>
      <td>${p.kind}</td><td class="small">${esc([p.department, p.section].filter(Boolean).join(' · '))}</td>
      <td>${p.enrolled ? `<span class="sev ${p.template_source === 'live' ? 'sev-low' : 'sev-medium'}">${p.template_source}</span>` : '<span class="muted">none</span>'}</td>
      <td class="small">${esc(p.consent_ref)}${p.is_minor ? ` · guardian: ${esc(p.guardian_consent_ref)}` : ''}</td>
      <td class="row"><button class="btn small" data-action="person-history">History</button>
      ${can('admin') ? `<button class="btn small" data-action="person-enrol-live">Enrol live</button>
        <button class="btn small ghost" data-action="person-enrol-photo">Photo</button>
        <button class="btn small ghost" data-action="person-edit">Edit</button>
        <button class="btn small danger" data-action="person-erase">Erase</button>` : ''}</td></tr>`).join('') || empty('people', 'Nobody here yet. Add a person, then enrol their face live.', 7)}
    </tbody></table></div>`;
}

function personForm(p = {}) {
  const v = k => esc(p[k] ?? '');
  openModal(`<div class="row between"><h2>${p.id ? 'Edit' : 'Add'} person</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
    <form data-form="person" data-id="${p.id || ''}"><div class="grid2">
      <label>Roll / employee number<input name="code" required value="${v('code')}" pattern="[A-Za-z0-9/_.\\-]+"></label>
      <label>Full name<input name="name" required value="${v('name')}"></label>
      <label>Type<select name="kind"><option ${p.kind === 'staff' ? '' : 'selected'}>student</option><option ${p.kind === 'staff' ? 'selected' : ''}>staff</option></select></label>
      <label>Department<input name="department" value="${v('department')}"></label>
      <label>Class / section / year<input name="section" value="${v('section')}"></label>
      <label>Consent reference (form no. / e-sign id)<input name="consent_ref" required minlength="3" value="${v('consent_ref')}"></label></div>
      <label class="check"><input type="checkbox" name="is_minor" ${p.is_minor ? 'checked' : ''}> Under 18</label>
      <label>Parent / guardian consent reference (required if under 18)<input name="guardian_consent_ref" value="${v('guardian_consent_ref')}"></label>
      <label class="check"><input type="checkbox" name="active" ${p.active === false ? '' : 'checked'}> Active</label>
      <p class="small muted">Biometric attendance needs informed consent and a stated purpose (DPDP Act 2023). Offer a non-biometric alternative to anyone who declines.</p>
      <button class="btn primary wide">Save</button></form>`);
}

/* -------------------------------------------------------------------- kiosk */
const ARROW = { left: '⟵ YOUR LEFT', right: 'YOUR RIGHT ⟶', up: '⤒ TILT UP', center: '◉ LOOK STRAIGHT' };

async function vKiosk(el) {
  el.innerHTML = `<div class="glass panel kiosk">
      <div class="kiosk-stage"><video id="kVideo" muted playsinline autoplay></video>
        <div class="kiosk-ring" id="kRing"></div><div class="kiosk-prompt" id="kPrompt">Tap “Check in” to start</div>
        <div class="kiosk-bar"><i id="kBar"></i></div></div>
      <div class="row between"><div><h2 id="kTitle">Attendance check-in</h2>
        <p class="small muted">Follow the on-screen movements. Photos, screens and videos are rejected. Your face is matched against your enrolled template only.</p></div>
        <div class="row"><button class="btn primary big" data-action="kiosk-start" id="kStart">Check in</button>
        <button class="btn ghost icon" data-action="kiosk-fs" aria-label="Full screen">${ic('expand')}</button></div></div>
      <div id="kResult" class="kiosk-result hidden"></div></div>`;
  await kioskCamera();
}

async function kioskCamera() {
  if (S.kStream) S.kStream.getTracks().forEach(t => t.stop());
  try {
    S.kStream = await navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 640 }, height: { ideal: 480 }, facingMode: 'user' }, audio: false });
    $('#kVideo').srcObject = S.kStream;
  } catch (e) {
    $('#kPrompt').textContent = `Camera unavailable: ${e.message}`;
  }
}
window.addEventListener('hashchange', () => {
  if (!location.hash.startsWith('#/kiosk') && S.kStream && !$('#kVideo')) { S.kStream.getTracks().forEach(t => t.stop()); S.kStream = null; }
});

/* Runs the challenge: returns server JSON. purpose 'attend' | 'enroll'. */
async function runChallenge(purpose, personId = null) {
  const v = $('#kVideo');
  if (!v?.videoWidth) throw new Error('Camera not ready');
  const ch = await api('/api/kiosk/challenge', { method: 'POST', body: { purpose, person_id: personId } });
  const plan = [['center', 1.8], ...ch.steps.map(s => [s, ch.seconds_per_step])];
  const total = plan.reduce((n, p) => n + p[1], 0);
  const canvas = document.createElement('canvas');
  canvas.width = v.videoWidth; canvas.height = v.videoHeight;
  const g = canvas.getContext('2d');
  const frames = [], t0 = performance.now();
  $('#kRing').className = 'kiosk-ring on';
  await new Promise(done => {
    const tick = setInterval(() => {
      const el = (performance.now() - t0) / 1000;
      let acc = 0, step = plan[0][0];
      for (const [s, d] of plan) { if (el < acc + d) { step = s; break; } acc += d; }
      $('#kPrompt').textContent = ARROW[step];
      $('#kBar').style.width = `${Math.min(100, (el / total) * 100)}%`;
      g.drawImage(v, 0, 0);
      canvas.toBlob(b => b && frames.push(b), 'image/jpeg', 0.8);
      if (el >= total) { clearInterval(tick); setTimeout(done, 150); }
    }, 1000 / ch.fps);
  });
  $('#kRing').className = 'kiosk-ring';
  $('#kPrompt').textContent = 'Verifying…';
  const fd = new FormData();
  fd.append('challenge_id', ch.id);
  frames.slice(0, 90).forEach((b, i) => fd.append('frames', b, `f${i}.jpg`));
  return api('/api/kiosk/verify', { method: 'POST', form: fd });
}

function kioskShow(ok, html) {
  const r = $('#kResult');
  r.className = `kiosk-result ${ok ? 'good' : 'bad'}`;
  r.innerHTML = html;
  $('#kPrompt').textContent = ok ? '✓' : '✕';
  clearTimeout(S.kReset);
  S.kReset = setTimeout(() => { r.className = 'kiosk-result hidden'; $('#kPrompt').textContent = 'Tap “Check in” to start'; $('#kBar').style.width = '0'; }, 6000);
}

/* ------------------------------------------------------------------ privacy */
async function vPrivacy(el) {
  const tab = hashParams().get('tab') || 'requests';
  const tabs = [['requests', 'Unblur requests'], ...(can('admin') ? [['alerts', 'Security alerts'], ['vault', 'Encryption vault']] : [])];
  el.innerHTML = `<div class="row tabs">${tabs.map(([k, l]) => `<a class="btn small ${k === tab ? 'on' : ''}" href="#/privacy?tab=${k}">${l}</a>`).join('')}</div><div id="pv"></div>`;
  const pv = $('#pv');
  if (tab === 'alerts') {
    const n = await api('/api/notifications?limit=300');
    pv.innerHTML = `<div class="glass panel"><div class="row between"><h2>${n.unread} unread</h2><button class="btn small" data-action="bell-read">Mark all read</button></div>
      <table><thead><tr><th>Time</th><th>Severity</th><th>Event</th><th>By</th><th>Detail</th></tr></thead><tbody>
      ${n.items.map(x => `<tr class="${x.read ? '' : 'unread'}"><td class="mono small">${esc(fmt(x.ts))}</td><td><span class="sev sev-${x.severity}">${x.severity}</span></td>
        <td>${esc(x.kind.replace(/_/g, ' '))}</td><td>${esc(x.actor)}</td><td class="small">${esc(x.message)}</td></tr>`).join('') || '<tr><td colspan="5" class="muted">None.</td></tr>'}
      </tbody></table></div>`;
    return;
  }
  if (tab === 'vault') {
    const v = await api('/api/vault');
    pv.innerHTML = `<div class="glass panel"><h2>Encryption vault ${v.configured ? '<span class="sev sev-low">active</span>' : '<span class="sev sev-high">not set up</span>'}</h2>
      ${v.configured ? `<p>Key fingerprint <span class="mono">${esc(v.fingerprint)}</span> · created by ${esc(v.created_by || '?')} ${esc(fmt(v.created_at))}</p>
        <p class="small muted">Raw (unblurred) recordings and attendance face crops are sealed to this key (X25519 + AES-256-GCM). The private key is stored only wrapped by your
        passphrase (Argon2id, 256 MiB) and by the offline recovery code. Unsealing always needs a super admin's authenticator code too.</p>
        ${can('superadmin') ? '<button class="btn" data-action="vault-rotate">Change passphrase</button>' : ''}`
      : `<p class="err">Until the vault is set up, only blurred footage is recorded — raw footage is discarded, so nothing can be unblurred later.</p>
        ${can('superadmin') ? `<form data-form="vaultSetup">
          <label>Vault passphrase (16+ characters; a 4–5 word phrase works well)<input name="passphrase" type="password" required minlength="16" autocomplete="new-password"></label>
          <label>Repeat passphrase<input name="passphrase2" type="password" required minlength="16" autocomplete="new-password"></label>
          <label>Your authenticator code<input name="totp" inputmode="numeric" maxlength="6" required></label>
          <p class="small muted">There is no "forgot passphrase": if both the passphrase and the recovery code are lost, sealed footage can never be decrypted. That is the point.</p>
          <button class="btn primary">Create vault</button></form>` : '<p class="muted">A super admin must create the vault.</p>'}`}</div>`;
    return;
  }
  const rows = await api('/api/unblur');
  pv.innerHTML = `<div class="glass panel"><p class="small muted">Requests start from an attendance record (Attendance → Request unblur). A super admin approves with their
    authenticator code and the vault passphrase. Only the requested person is revealed; everyone else stays blurred. Results are watermarked and expire after 15 minutes.
    Every request, approval, view and export is reported to all admins.</p>
    <table><thead><tr><th>#</th><th>Requested</th><th>Person</th><th>By</th><th>Reason</th><th>Status</th><th></th></tr></thead><tbody>
    ${rows.map(r => `<tr data-req='${esc(JSON.stringify(r))}'><td>${r.id}</td><td class="small">${esc(fmt(r.created_at))}</td>
      <td>${esc(r.person ? `${r.person.name} (${r.person.code})` : '?')}</td><td>${esc(r.requester)}</td><td class="small">${esc(r.reason)}</td>
      <td><span class="sev ${r.status === 'ready' ? 'sev-low' : r.status === 'pending' ? 'sev-medium' : 'sev-info'}">${r.status}</span>
        ${r.detail ? `<div class="small muted">${esc(r.detail)}</div>` : ''}${r.expires_at && r.status === 'ready' ? `<div class="small muted">expires ${new Date(r.expires_at).toLocaleTimeString()}</div>` : ''}</td>
      <td class="row">${r.status === 'pending' && can('superadmin') ? `<button class="btn small primary" data-action="unblur-approve">Approve</button>
          <button class="btn small danger" data-action="unblur-deny">Deny</button>` : ''}
        ${r.status === 'ready' && (r.requester === S.user.username || can('superadmin')) ? '<button class="btn small primary" data-action="unblur-view">View</button>' : ''}
        ${r.status === 'ready' && can('superadmin') && r.has_video ? '<button class="btn small" data-action="unblur-export">Export</button>' : ''}</td></tr>`).join('') || empty('privacy', 'No unblur requests. Everyone stays blurred.', 7)}
    </tbody></table></div>`;
}


/* ----------------------------------------------------------- anti-spoof lab */
async function vAntispoof(el) {
  const st = await api('/api/antispoof/status');
  const c = st.settings, m = st.metrics;
  el.innerHTML = `<div class="grid2">
    <div class="glass panel"><h2>Anti-spoof model ${st.loaded ? '<span class="sev sev-low">loaded</span>' : '<span class="sev sev-high">unavailable</span>'}</h2>
      <table>
        <tr><th>Model</th><td>MiniFASNetV2-SE · release ${esc(m.release)} · <b>${esc(c.variant.toUpperCase())}</b></td></tr>
        <tr><th>Provider</th><td>${esc(st.provider || '—')}</td></tr><tr><th>CPU</th><td class="small">${esc(st.cpu)}</td></tr>
        <tr><th>GPU</th><td>${esc(st.gpu || 'none detected')}</td></tr>
        <tr><th>Threshold</th><td>${c.threshold} ${c.threshold >= 0.8 ? '(high security)' : c.threshold === 0.5 ? '(balanced)' : ''} · ${c.frames} consecutive real frames</td></tr>
        <tr><th>Reference accuracy</th><td class="small">${m.overall_accuracy}% overall · real ${m.real_accuracy}% · spoof ${m.spoof_accuracy}% · ROC-AUC ${m.roc_auc} (${esc(m.dataset)})</td></tr>
        <tr><th>Trained on</th><td class="small">${esc(m.trained_attacks)} — <span class="err">not ${esc(m.not_trained)}</span></td></tr>
        <tr><th>Source</th><td class="small mono">${esc((st.source_commit || '').slice(0, 12))} · ${esc(st.license)}</td></tr>
      </table>${st.error ? `<p class="err small">${esc(st.error)}</p>` : ''}
      ${can('admin') ? `<form data-form="asSettings" class="row">
        <label>Model<select name="variant"><option value="int8" ${c.variant === 'int8' ? 'selected' : ''}>INT8 (600 KB, production)</option>
          <option value="fp32" ${c.variant === 'fp32' ? 'selected' : ''}>FP32 (1.8 MB)</option></select></label>
        <label>Threshold<select name="threshold">${[0.5, 0.6, 0.7, 0.8, 0.9].map(v => `<option ${v === c.threshold ? 'selected' : ''}>${v}</option>`).join('')}</select></label>
        <label>Consecutive frames<select name="frames">${[3, 4, 5].map(v => `<option ${v === c.frames ? 'selected' : ''}>${v}</option>`).join('')}</select></label>
        <button class="btn primary">Save</button><button type="button" class="btn" data-action="as-bench">Benchmark</button></form>
        <p class="small muted">Higher threshold = fewer spoofs accepted, more genuine users asked to retry. Lowering it alerts all admins.</p>` : ''}
      <div id="asBench"></div></div>
    <div class="glass panel"><h2>Live check</h2>
      <div class="kiosk-stage small"><video id="asVideo" muted playsinline autoplay></video><canvas id="asOverlay"></canvas></div>
      <div class="row"><button class="btn primary" data-action="as-live" id="asLiveBtn">Start webcam test</button>
        <label class="btn ghost">Test an image<input type="file" id="asFile" accept="image/*" class="hidden"></label>
        <span id="asStat" class="small muted"></span></div>
      <p class="small muted">Green = real, red = spoof, with the model's logit difference (as in the reference demo). Hold a printed photo or phone screen
      to the camera to see it flagged. Frames are analysed in memory and never stored. Works best with even lighting, frontal faces (±30°) and faces ≥ 64 px.</p>
    </div></div>`;
  $('#asFile').addEventListener('change', e => e.target.files[0] && asImage(e.target.files[0]));
}

function asDraw(canvas, w, h, faces, mirror) {
  canvas.width = w; canvas.height = h;
  const g = canvas.getContext('2d');
  g.clearRect(0, 0, w, h);
  g.lineWidth = Math.max(2, w / 300); g.font = `${Math.max(14, w / 40)}px Inter, sans-serif`;
  faces.forEach(f => {
    let [x, y, bw, bh] = f.box; x *= w; y *= h; bw *= w; bh *= h;
    if (mirror) x = w - x - bw;
    const col = f.status === 'real' ? '#3ee6a0' : f.status === 'spoof' ? '#ff2e63' : '#ffc857';
    g.strokeStyle = col; g.fillStyle = col; g.strokeRect(x, y, bw, bh);
    const label = f.status === 'real' || f.status === 'spoof' ? `${f.status.toUpperCase()}: ${f.logit_diff.toFixed(2)}` : (f.quality || f.note || f.status);
    g.fillText(label, x, Math.max(16, y - 8));
  });
}

async function asImage(file) {
  const fd = new FormData(); fd.append('image', file);
  const r = await api('/api/antispoof/check', { method: 'POST', form: fd });
  const img = new Image();
  img.onload = () => {
    const v = $('#asVideo'), c = $('#asOverlay');
    v.classList.add('hidden');
    c.classList.add('still');
    c.width = r.width; c.height = r.height;
    c.getContext('2d').drawImage(img, 0, 0);
    const tmp = document.createElement('canvas');
    asDraw(tmp, r.width, r.height, r.faces, false);
    c.getContext('2d').drawImage(tmp, 0, 0);
    URL.revokeObjectURL(img.src);
    $('#asStat').textContent = `${r.faces.length} face(s): ${r.faces.map(f => f.status).join(', ') || 'none'}`;
  };
  img.src = URL.createObjectURL(file);
}

window.addEventListener('hashchange', () => {
  if (!location.hash.startsWith('#/antispoof')) { clearInterval(S.asTimer); S.asTimer = null; if (S.asStream) { S.asStream.getTracks().forEach(t => t.stop()); S.asStream = null; } }
});

/* ---------------------------------------------------------------- wiring */
Object.assign(VIEWS, {
  playback: ['Playback', vPlayback], attendance: ['Attendance', vAttendance], people: ['People', vPeople],
  kiosk: ['Attendance kiosk', vKiosk], privacy: ['Privacy centre', vPrivacy], antispoof: ['Anti-spoof lab', vAntispoof],
});

const blobDownload = async (url, body, name) => {
  const r = await fetch(url, { method: 'POST', credentials: 'same-origin', body: JSON.stringify(body),
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': S.csrf || '' } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
  const a = document.createElement('a');
  a.href = URL.createObjectURL(await r.blob());
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
};
const recFrom = t => JSON.parse(t.closest('[data-rec]').dataset.rec);
const personFrom = t => JSON.parse(t.closest('[data-person]').dataset.person);
const reqFrom = t => JSON.parse(t.closest('[data-req]').dataset.req);

Object.assign(ACTIONS, {
  'pb-load': () => pbLoad(),
  'pb-seg': t => pbPlay(S.pbSegs.find(s => s.id === +t.dataset.id)),
  'pb-export': async () => {
    if (!S.pbCur) return toast('Play a recording first', true);
    const v = await askStepUp('Export recording', `<p>${esc(camName(+$('#pbCam').value))}, ${hms(S.pbCur.from)} – ${hms(S.pbCur.to)} (faces blurred). The file is watermarked with your name.</p>`, ['reason', 'totp']);
    pbMsg('Preparing watermarked export…');
    await blobDownload(`/api/recordings/${S.pbCur.id}/export`, v, `camera${$('#pbCam').value}_${hms(S.pbCur.from).replace(/:/g, '')}.mp4`);
    pbMsg('Exported. All admins have been notified.');
  },
  bell: () => { location.hash = '#/privacy?tab=alerts'; },
  'bell-read': async () => { await api('/api/notifications/read', { method: 'POST' }); S.bell = 0; paintBell(); route(); },
  'att-evidence': t => {
    const r = recFrom(t);
    openModal(`<div class="row between"><h2>${esc(r.person.name)} · ${esc(r.day)}</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
      <img class="full" alt="Blurred evidence" src="/api/attendance/records/${r.id}/evidence">
      <p class="small muted">Faces are blurred. ${r.has_raw && can('operator') ? 'To see this person unblurred, use “Request unblur” (super admin approval required).' : ''}</p>`);
  },
  'att-review': async t => {
    const r = recFrom(t);
    await api(`/api/attendance/records/${r.id}/review`, { method: 'POST', body: { action: t.dataset.a, note: '' } });
    route();
  },
  'att-manual': t => {
    const r = recFrom(t);
    openModal(`<div class="row between"><h2>Mark ${esc(r.person.name)}</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
      <form data-form="attManual" data-pid="${r.person.id}"><label>Status<select name="status"><option>present</option><option>late</option><option>absent</option></select></label>
      <label>Reason (logged; admins are notified)<input name="note" required minlength="3"></label><button class="btn primary wide">Save</button></form>`);
  },
  'att-export': () => {
    const day = hashParams().get('day') || ymd(new Date());
    openModal(`<div class="row between"><h2>Export attendance (CSV)</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
      <form data-form="attExport"><div class="grid2"><label>From<input type="date" name="start" value="${day.slice(0, 8)}01"></label><label>To<input type="date" name="end" value="${day}"></label></div>
      <p class="small muted">Attendance marks only (no images). Every export is reported to all admins and super admins.</p><button class="btn primary wide">Download</button></form>`);
  },
  'att-settings': async () => {
    const s = await api('/api/attendance/settings');
    openModal(`<div class="row between"><h2>Attendance settings</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
      <form data-form="attSettings"><label>Late after<input type="time" name="late_after" value="${s.late_after}"></label>
      <label class="check"><input type="checkbox" name="cctv_requires_liveness" ${s.cctv_requires_liveness ? 'checked' : ''}> CCTV sightings without liveness proof go to review (recommended)</label>
      <button class="btn primary wide">Save</button></form>`);
  },
  'unblur-request': t => {
    const r = recFrom(t);
    openModal(`<div class="row between"><h2>Request unblur: ${esc(r.person.name)}</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
      <form data-form="unblurRequest" data-rec="${r.id}"><p class="small muted">A super admin must approve with their authenticator and the vault passphrase.
      Only this person will be revealed. The request and its reason are sent to all admins.</p>
      <label>Reason (min. 10 characters)<textarea name="reason" required minlength="10" maxlength="500" rows="3"></textarea></label>
      <button class="btn primary wide">Send request</button></form>`);
  },
  'unblur-approve': async t => {
    const r = reqFrom(t);
    const v = await askStepUp(`Approve unblur #${r.id}`, `<p><b>${esc(r.person?.name)}</b> (${esc(r.person?.code)}), requested by ${esc(r.requester)}:</p>
      <p class="small">“${esc(r.reason)}”</p>`, ['passphrase', 'totp']);
    toast('Unlocking vault and rendering… this can take a minute.');
    await api(`/api/unblur/${r.id}/approve`, { method: 'POST', body: v });
    route();
  },
  'unblur-deny': async t => {
    const r = reqFrom(t);
    const note = prompt('Reason for denial (optional)') ?? null;
    if (note === null) return;
    await api(`/api/unblur/${r.id}/deny`, { method: 'POST', body: { note } });
    route();
  },
  'unblur-view': t => {
    const r = reqFrom(t);
    openModal(`<div class="row between"><h2>Unblurred · #${r.id} · ${esc(r.person?.name)}</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
      <p class="small err">Confidential. Viewing is logged and reported. Watermarked with your request number. Expires ${new Date(r.expires_at).toLocaleTimeString()}.</p>
      ${r.has_image ? `<img class="full" alt="Face" src="/api/unblur/${r.id}/image">` : ''}
      ${r.has_video ? `<video class="pbv" src="/api/unblur/${r.id}/video" controls autoplay playsinline controlslist="nodownload noremoteplayback" disablepictureinpicture></video>` : ''}
      ${r.detail ? `<p class="small muted">${esc(r.detail)}</p>` : ''}`);
    $$('#modalCard video, #modalCard img').forEach(m => m.addEventListener('contextmenu', e => e.preventDefault()));
  },
  'unblur-export': async t => {
    const r = reqFrom(t);
    const v = await askStepUp(`Export UNBLURRED footage #${r.id}`, '<p class="err">This exports identifiable footage. It is watermarked and every admin is notified.</p>', ['reason', 'totp']);
    await blobDownload(`/api/unblur/${r.id}/export`, v, `unblurred_${r.id}.mp4`);
    toast('Exported; admins notified');
  },
  'vault-rotate': () => openModal(`<div class="row between"><h2>Change vault passphrase</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
    <form data-form="vaultRotate"><label>Current passphrase (or leave empty and use the recovery code)<input name="current_passphrase" type="password"></label>
    <label>Recovery code<input name="recovery_code" autocomplete="off"></label>
    <label>New passphrase (16+ chars)<input name="new_passphrase" type="password" required minlength="16"></label>
    <label>Authenticator code<input name="totp" inputmode="numeric" maxlength="6" required></label><button class="btn primary wide">Change</button></form>`),
  'person-new': () => personForm(),
  'person-edit': t => personForm(personFrom(t)),
  'person-history': async t => {
    const p = personFrom(t);
    const rows = await api(`/api/persons/${p.id}/history`);
    openModal(`<div class="row between"><h2>${esc(p.name)} · ${esc(p.code)}</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
      <table><thead><tr><th>Day</th><th>Status</th><th>Time</th><th>Method</th><th></th></tr></thead><tbody>
      ${rows.map(r => `<tr data-rec='${esc(JSON.stringify({ ...r, person: { id: p.id, code: p.code, name: p.name } }))}'><td>${r.day}</td><td><span class="sev ${STATUS[r.status]}">${r.status}</span></td>
        <td class="small">${new Date(r.first_seen).toLocaleTimeString()}</td><td class="small">${esc(r.method)}</td>
        <td>${r.has_raw && can('operator') ? '<button class="btn small" data-action="unblur-request">Request unblur</button>' : ''}</td></tr>`).join('') || '<tr><td colspan="5" class="muted">No attendance in the last 60 days.</td></tr>'}</tbody></table>`);
  },
  'person-enrol-photo': t => {
    const p = personFrom(t);
    openModal(`<div class="row between"><h2>Enrol from photo: ${esc(p.name)}</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
      <form data-form="enrolPhoto" data-id="${p.id}"><p class="small err">Lower assurance: a photo proves nothing about who submitted it. Prefer “Enrol live”.</p>
      <label>Frontal photo<input type="file" name="image" accept="image/jpeg,image/png" required></label><button class="btn primary wide">Enrol</button></form>`);
  },
  'person-enrol-live': async t => {
    const p = personFrom(t);
    openModal(`<div class="row between"><h2>Live enrolment: ${esc(p.name)}</h2><button class="btn ghost icon" data-action="close" aria-label="Close">${ic('close')}</button></div>
      <div class="kiosk-stage small"><video id="kVideo" muted playsinline autoplay></video><div class="kiosk-ring" id="kRing"></div>
      <div class="kiosk-prompt" id="kPrompt">Ask ${esc(p.name.split(' ')[0])} to face the camera</div><div class="kiosk-bar"><i id="kBar"></i></div></div>
      <button class="btn primary wide" data-action="enrol-go" data-id="${p.id}">Start (repeat 2–3× for best accuracy)</button><p id="enrolMsg" class="small"></p>`);
    await kioskCamera();
  },
  'enrol-go': async t => {
    t.disabled = true;
    try {
      const r = await runChallenge('enroll', +t.dataset.id);
      $('#enrolMsg').textContent = r.ok ? '✓ Template added from a verified live face.' : `✕ ${r.reason}`;
      $('#enrolMsg').className = 'small ' + (r.ok ? '' : 'err');
      $('#kPrompt').textContent = r.ok ? '✓ Enrolled' : '✕ Try again';
    } finally { t.disabled = false; }
  },
  'person-erase': async t => {
    const p = personFrom(t);
    const mode = prompt(`Erase ${p.name}:\n  type "biometrics" to delete the face template only (consent withdrawn), or\n  type "all" to delete the person and all attendance + evidence.`);
    if (!['biometrics', 'all'].includes(mode)) return;
    await api(`/api/persons/${p.id}?mode=${mode}`, { method: 'DELETE' });
    toast('Erased'); route();
  },
  'kiosk-start': async t => {
    t.disabled = true;
    $('#kResult').className = 'kiosk-result hidden';
    try {
      const r = await runChallenge('attend');
      if (r.ok) kioskShow(true, `<div class="big">✓ ${esc(r.name)}</div><div>${esc(r.code)} · ${r.already ? 'already checked in at' : 'checked in at'} ${esc(r.time)}
        · <span class="sev ${STATUS[r.status]}">${r.status}</span></div>${r.antispoof ? `<div class="small muted">Live-face check: ${r.antispoof.real_frames}/${r.antispoof.frames} frames real</div>` : ''}`);
      else kioskShow(false, `<div class="big">Not accepted</div><div>${esc(r.reason)}</div>`);
    } catch (e) { kioskShow(false, `<div class="big">Error</div><div>${esc(e.message)}</div>`); }
    finally { t.disabled = false; }
  },
  'kiosk-fs': () => document.querySelector('.kiosk')?.requestFullscreen?.(),
  'as-live': async t => {
    if (S.asTimer) { clearInterval(S.asTimer); S.asTimer = null; S.asStream?.getTracks().forEach(x => x.stop()); S.asStream = null; t.textContent = 'Start webcam test'; return; }
    const v = $('#asVideo'), c = $('#asOverlay');
    v.classList.remove('hidden'); c.classList.remove('still');
    S.asStream = await navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 640 }, height: { ideal: 480 } }, audio: false });
    v.srcObject = S.asStream;
    t.textContent = 'Stop';
    const cap = document.createElement('canvas');
    let busy = false;
    S.asTimer = setInterval(async () => {
      if (busy || !v.videoWidth) return;
      busy = true;
      cap.width = v.videoWidth; cap.height = v.videoHeight;
      cap.getContext('2d').drawImage(v, 0, 0);
      const blob = await new Promise(r => cap.toBlob(r, 'image/jpeg', 0.85));
      const fd = new FormData(); fd.append('image', blob, 'f.jpg');
      const t0 = performance.now();
      try {
        const r = await api('/api/antispoof/check', { method: 'POST', form: fd });
        asDraw(c, v.clientWidth, v.clientHeight, r.faces, true);
        $('#asStat').textContent = `${Math.round(performance.now() - t0)} ms round trip · ${r.faces.length} face(s)`;
      } catch (e) { $('#asStat').textContent = e.message; }
      busy = false;
    }, 400);
  },
  'as-bench': async () => {
    $('#asBench').innerHTML = '<p class="muted small">Benchmarking FP32 vs INT8…</p>';
    const b = await api('/api/antispoof/benchmark', { method: 'POST' });
    const rows = Object.entries(b.models).map(([k, v]) => `<tr><td>${k.toUpperCase()}</td><td>${v.size_kb} KB</td><td>${v.p50_ms} ms</td><td>${v.p95_ms} ms</td><td>${v.throughput_fps}/s</td><td>${esc(v.provider)}</td></tr>`).join('');
    $('#asBench').innerHTML = `<table><thead><tr><th>Model</th><th>Size</th><th>p50</th><th>p95</th><th>Throughput</th><th>Provider</th></tr></thead><tbody>${rows}</tbody></table>
      <p class="small ${b.size_gate_60pct ? '' : 'err'}">INT8 size reduction ${b.size_reduction_pct}% (gate ≥ 60%: ${b.size_gate_60pct ? 'pass' : 'FAIL'}) · INT8 speed-up ${b.speedup_int8}×</p>`;
  },
  'user-contacts': async t => {
    const uid = t.closest('[data-uid]').dataset.uid;
    const phone = prompt('Mobile for security alerts (E.164, e.g. +9198…; empty to clear)', t.dataset.phone);
    if (phone === null) return;
    const email = prompt('Email for security alerts (empty to clear)', t.dataset.email);
    if (email === null) return;
    await api(`/api/users/${uid}`, { method: 'PATCH', body: { phone: phone.trim(), email: email.trim() } });
    route();
  },
});

Object.assign(FORMS, {
  asSettings: async f => {
    await api('/api/antispoof/settings', { method: 'PUT', body: { variant: f.variant.value, threshold: +f.threshold.value, frames: +f.frames.value } });
    toast('Anti-spoof settings saved'); route();
  },
  stepup: async f => {
    const v = { totp: f.totp.value.trim() };
    if (f.reason) v.reason = f.reason.value.trim();
    if (f.passphrase) v.passphrase = f.passphrase.value;
    const resolve = S.stepUp;
    S.stepUp = null;
    closeModal();
    resolve?.(v);
  },
  attFilter: async f => {
    const p = new URLSearchParams({ day: f.day.value, kind: f.kind.value, department: f.department.value, section: f.section.value });
    location.hash = `#/attendance?${p}`;
  },
  peopleSearch: async f => { location.hash = `#/people?q=${encodeURIComponent(f.q.value.trim())}`; },
  person: async f => {
    const body = { code: f.code.value.trim(), name: f.name.value.trim(), kind: f.kind.value, department: f.department.value.trim(),
      section: f.section.value.trim(), consent_ref: f.consent_ref.value.trim(), is_minor: f.is_minor.checked,
      guardian_consent_ref: f.guardian_consent_ref.value.trim(), active: f.active.checked };
    const id = f.dataset.id;
    await api(id ? `/api/persons/${id}` : '/api/persons', { method: id ? 'PUT' : 'POST', body });
    closeModal(); toast('Saved'); route();
  },
  enrolPhoto: async f => {
    await api(`/api/persons/${f.dataset.id}/enroll-photo`, { method: 'POST', form: new FormData(f) });
    closeModal(); toast('Template added (photo)'); route();
  },
  attManual: async f => {
    await api('/api/attendance/manual', { method: 'POST', body: { person_id: +f.dataset.pid, day: hashParams().get('day') || ymd(new Date()),
      status: f.status.value, note: f.note.value.trim() } });
    closeModal(); route();
  },
  attExport: async f => {
    const q = hashParams();
    const p = new URLSearchParams({ start: f.start.value, end: f.end.value, kind: q.get('kind') || '', department: q.get('department') || '', section: q.get('section') || '' });
    const r = await fetch(`/api/attendance/export.csv?${p}`, { credentials: 'same-origin' });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(await r.blob());
    a.download = `attendance_${f.start.value}_${f.end.value}.csv`;
    a.click();
    closeModal(); toast('Exported; admins notified');
  },
  attSettings: async f => {
    await api('/api/attendance/settings', { method: 'PUT', body: { late_after: f.late_after.value, cctv_requires_liveness: f.cctv_requires_liveness.checked } });
    closeModal(); route();
  },
  unblurRequest: async f => {
    await api('/api/unblur', { method: 'POST', body: { attendance_id: +f.dataset.rec, reason: f.reason.value.trim() } });
    closeModal(); toast('Request sent to super admins'); location.hash = '#/privacy';
  },
  vaultSetup: async f => {
    if (f.passphrase.value !== f.passphrase2.value) throw new Error('Passphrases do not match');
    const r = await api('/api/vault/setup', { method: 'POST', body: { passphrase: f.passphrase.value, totp: f.totp.value.trim() } });
    openModal(`<h2>Vault created</h2><p>Fingerprint <span class="mono">${esc(r.fingerprint)}</span></p>
      <p class="err">Recovery code — shown ONCE. Print it and lock it away (e.g. principal's safe). It can unlock the vault if the passphrase is lost.</p>
      <div class="secret">${esc(r.recovery_code)}</div><button class="btn primary wide" data-action="close">I have stored it offline</button>`);
    route();
  },
  vaultRotate: async f => {
    await api('/api/vault/passphrase', { method: 'POST', body: { current_passphrase: f.current_passphrase.value, recovery_code: f.recovery_code.value.trim(),
      new_passphrase: f.new_passphrase.value, totp: f.totp.value.trim() } });
    closeModal(); toast('Vault passphrase changed');
  },
});
