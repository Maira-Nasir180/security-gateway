let token = null, mode = 'login';
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function log(label, status, data) {
  const li = document.createElement('li'); li.className = status < 400 ? '' : 'bad';
  li.innerHTML = `<b>${esc(label)} → ${status}</b>${esc(data.error || data.message || (data.profile ? data.profile.email + ' (' + data.profile.role + ')' : 'OK'))}`;
  const l = $('#log'); l.querySelector('.empty')?.remove(); l.prepend(li);
}
async function api(path, method = 'GET', body, base = '/api/v1', retry = true) {
  const r = await fetch(base + path, { method, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && data.code === 'TOKEN_EXPIRED' && retry && (await refresh(true))) return api(path, method, body, base, false);
  return { status: r.status, ok: r.ok, data };
}
function show(user) {
  $('#login').hidden = true; $('#app').hidden = false;
  $('#hello').textContent = 'Welcome, ' + user.name; $('#role').textContent = user.role; $('#tok').textContent = token;
}
async function refresh(silent) {
  const r = await api('/auth/refresh', 'POST', null, '/api/v1', false);
  if (r.ok) { token = r.data.accessToken; show(r.data.user); if (!silent) log('POST /auth/refresh (new token issued, old one retired)', r.status, { message: 'Token rotated' }); return true; }
  if (!silent) log('POST /auth/refresh', r.status, r.data); return false;
}
function setMode(m) {
  mode = m; $('#tLogin').classList.toggle('on', m === 'login'); $('#tReg').classList.toggle('on', m === 'reg');
  $('#nameRow').hidden = m === 'login'; $('#submit').textContent = m === 'login' ? 'Sign in' : 'Create account';
  $('#password').autocomplete = m === 'login' ? 'current-password' : 'new-password'; $('#msg').textContent = '';
}
$('#tLogin').onclick = () => setMode('login'); $('#tReg').onclick = () => setMode('reg');
$('#form').onsubmit = async (e) => {
  e.preventDefault(); const msg = $('#msg'); msg.className = 'msg'; msg.textContent = '';
  const body = { email: $('#email').value, password: $('#password').value, name: $('#name').value };
  if (mode === 'reg') {
    const r = await api('/auth/register', 'POST', body);
    if (!r.ok) { msg.textContent = r.data.error; return; }
    msg.className = 'msg ok'; msg.textContent = 'Account created. Sign in to continue.'; setMode('login'); msg.className = 'msg ok'; msg.textContent = 'Account created. Sign in to continue.'; return;
  }
  const r = await api('/auth/login', 'POST', body);
  if (r.ok) { token = r.data.accessToken; show(r.data.user); } else msg.textContent = r.data.error;
};
document.querySelectorAll('[data-r]').forEach((b) => b.onclick = async () => {
  const [m, p] = b.dataset.r.split(' '); const r = await api(p, m, m === 'POST' ? { payrollId: 'PR-1001' } : null); log(b.dataset.r, r.status, r.data);
});
$('#bUsers').onclick = async () => {
  const r = await api('/users'); log('GET /users', r.status, r.data); const ul = $('#users'); ul.innerHTML = '';
  (r.data.users || []).forEach((u) => { const li = document.createElement('li'); li.innerHTML = `<span>${esc(u.name)} <small>${esc(u.role)}</small></span>`;
    const b = document.createElement('button'); b.textContent = 'Delete user'; b.onclick = async () => { const d = await api('/users/' + u.id, 'DELETE'); log('DELETE /users/:id', d.status, d.data); if (d.ok) li.remove(); };
    li.append(b); ul.append(li); });
};
$('#bRefresh').onclick = () => refresh(false);
$('#bOut').onclick = async () => { await api('/auth/logout', 'POST'); token = null; $('#app').hidden = true; $('#login').hidden = false; $('#users').innerHTML = ''; };
const q = new URLSearchParams(location.search).get('oauth');
if (q) { history.replaceState({}, '', '/'); if (q !== 'success') { $('#msg').textContent = q === 'not_configured' ? 'GitHub login is not configured yet.' : 'GitHub sign-in failed. Try again.'; } }
refresh(true);
