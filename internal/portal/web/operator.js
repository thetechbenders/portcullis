'use strict';
// Portcullis operator console. The token lives only in sessionStorage for
// this tab and is sent as a bearer header. Server data is written with
// textContent only.
(function () {
  const REFRESH_MS = 2000;
  const KEY = 'portcullis.operator.token';
  const RULES = {
    'guest-dhcp': ['DHCP from guests to the gateway', 'accept'],
    'guest-dns': ['Bound guests to portal DNS', 'accept'],
    'guest-portal': ['Bound guests to the portal', 'accept'],
    'guest-input': ['Any other guest traffic to the gateway', 'drop'],
    'guest-protected': ['Guests to protected networks', 'drop'],
    'grant-egress': ['Granted guests to the uplink', 'accept'],
    'guest-egress': ['Ungranted guest forwarding', 'drop'],
    'grant-ingress': ['Replies to granted guests', 'accept'],
    'guest-ingress': ['Any other traffic to guests', 'drop'],
  };
  const $ = (id) => document.getElementById(id);
  const ui = {
    conn: $('conn'), lock: $('lock'), login: $('login'), form: $('unlock'), token: $('token'),
    loginError: $('login-error'), dash: $('dash'), enforcement: $('enforcement'),
    enfState: $('enf-state'), enfReason: $('enf-reason'), attAge: $('att-age'), snapTime: $('snap-time'),
    countBindings: $('count-bindings'), countGrants: $('count-grants'),
    counters: $('counters'), grants: $('grants'), bindings: $('bindings'), events: $('events'),
    reset: $('reset'), toast: $('toast'),
  };

  let token = '';
  try { token = sessionStorage.getItem(KEY) || ''; } catch (_) { token = ''; }
  let timer = 0;
  let inflight = false;
  let previous = new Map();
  let toastTimer = 0;

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = String(text);
    return e;
  }
  const n = (v) => (Number.isFinite(v) ? v : 0);
  const fmt = (v) => n(v).toLocaleString();
  function bytes(v) {
    v = n(v);
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
    return (i ? v.toFixed(1) : String(v)) + ' ' + units[i];
  }
  function secs(v) {
    v = Math.max(0, Math.floor(n(v)));
    return Math.floor(v / 60) + ':' + String(v % 60).padStart(2, '0');
  }
  function stamp(iso) {
    const t = Date.parse(iso);
    return Number.isFinite(t) && t > 0 ? new Date(t).toLocaleTimeString() : '—';
  }

  function toast(text) {
    ui.toast.textContent = text;
    ui.toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { ui.toast.hidden = true; }, 4000);
  }

  async function api(method, path, body) {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 8000);
    const init = {
      method, cache: 'no-store', mode: 'same-origin', credentials: 'omit', redirect: 'error',
      referrerPolicy: 'same-origin', signal: ctl.signal,
      headers: { Accept: 'application/json', Authorization: 'Bearer ' + token },
    };
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.headers['X-Portcullis-Request'] = '1';
      init.body = JSON.stringify(body);
    }
    try {
      const res = await fetch(path, init);
      let data = null;
      try { data = await res.json(); } catch (_) { data = null; }
      return { status: res.status, data };
    } finally {
      clearTimeout(t);
    }
  }

  function lock(message) {
    clearTimeout(timer);
    token = '';
    try { sessionStorage.removeItem(KEY); } catch (_) { /* ignore */ }
    ui.dash.hidden = true;
    ui.lock.hidden = true;
    ui.login.hidden = false;
    ui.loginError.textContent = message || '';
    ui.loginError.hidden = !message;
    ui.conn.textContent = 'Locked';
    ui.conn.classList.remove('is-error');
    ui.token.focus();
  }

  function unlocked() {
    ui.login.hidden = true;
    ui.dash.hidden = false;
    ui.lock.hidden = false;
    refresh();
  }

  function emptyRow(tbody, cols, text) {
    const tr = el('tr', 'empty');
    const td = el('td', '', text);
    td.colSpan = cols;
    tr.append(td);
    tbody.replaceChildren(tr);
  }

  function revokeButton(mac) {
    const b = el('button', 'btn btn-small', 'Revoke');
    b.type = 'button';
    b.dataset.mac = mac;
    b.setAttribute('aria-label', 'Revoke access for ' + mac);
    return b;
  }

  function render(s) {
    const ok = s.enforcement === 'ok';
    const gen = Date.parse(s.generated_at);
    const att = Date.parse(s.last_attestation);
    const hasAtt = Number.isFinite(att) && new Date(att).getUTCFullYear() > 1;
    const age = hasAtt && Number.isFinite(gen) ? Math.max(0, (gen - att) / 1000) : NaN;
    ui.enforcement.dataset.tone = !ok ? 'bad' : (!hasAtt || age > 10) ? 'warn' : 'ok';
    const isolated = s.isolation === 'confirmed';
    ui.enfState.textContent = ok ? (hasAtt ? 'Verified' : 'Not yet attested') :
      (isolated ? 'DEGRADED: guest link DOWN at last check' : 'DEGRADED: ISOLATION UNCONFIRMED');
    ui.enfReason.textContent = ok ? 'The kernel guard matched its expected structure.' :
      (s.degraded_reason || 'Attestation failed.') +
      (isolated ? ' Link-down verified on the last retry; access remains disabled.' :
        ' Could not verify guest link-down. Do not assume traffic is blocked.');
    ui.attAge.textContent = Number.isFinite(age) ? age.toFixed(1) + ' s ago' : 'never';
    ui.snapTime.textContent = stamp(s.generated_at);

    const counters = Array.isArray(s.counters) ? s.counters : [];
    const next = new Map();
    if (!counters.length) emptyRow(ui.counters, 5, 'No counters reported.');
    else ui.counters.replaceChildren(...counters.map((c) => {
      const name = String(c.rule || '');
      const info = RULES[name] || ['', ''];
      const before = previous.get(name);
      const delta = before === undefined ? 0 : n(c.packets) - before;
      next.set(name, n(c.packets));
      const tr = el('tr', delta > 0 ? 'moved' : '');
      const rule = el('td');
      rule.append(el('code', '', name), el('span', 'rule-desc', info[0]));
      const verdict = el('td');
      verdict.append(el('span', info[1] === 'drop' ? 'tag tag-bad' : info[1] === 'accept' ? 'tag tag-ok' : 'tag', info[1] || '—'));
      tr.append(rule, verdict, el('td', 'num big', fmt(c.packets)), el('td', 'num delta', delta > 0 ? '+' + fmt(delta) : '—'), el('td', 'num', bytes(c.bytes)));
      return tr;
    }));
    previous = next;

    const grants = Array.isArray(s.grants) ? s.grants : [];
    ui.countGrants.textContent = String(grants.filter((g) => g.kernel_present).length);
    if (!grants.length) emptyRow(ui.grants, 7, 'No grants.');
    else ui.grants.replaceChildren(...grants.map((g) => {
      const mismatch = !g.kernel_present || Math.abs(n(g.desired_remaining_seconds) - n(g.kernel_remaining_seconds)) > 2;
      const tr = el('tr', mismatch ? 'mismatch' : '');
      const kern = el('td');
      kern.append(el('span', g.kernel_present ? 'tag tag-ok' : 'tag tag-bad', g.kernel_present ? 'present' : 'missing'));
      if (mismatch) kern.append(' ', el('span', 'tag tag-warn', 'mismatch'));
      const act = el('td');
      act.append(revokeButton(String(g.mac || '')));
      tr.append(el('td', '', g.address || ''), el('td', '', g.mac || ''), el('td', 'num', secs(g.granted_seconds)),
        el('td', 'num', secs(g.desired_remaining_seconds)), el('td', 'num', g.kernel_present ? secs(g.kernel_remaining_seconds) : '—'), kern, act);
      return tr;
    }));

    const bindings = Array.isArray(s.bindings) ? s.bindings : [];
    ui.countBindings.textContent = String(bindings.length);
    if (!bindings.length) emptyRow(ui.bindings, 5, 'No DHCP bindings yet.');
    else ui.bindings.replaceChildren(...bindings.map((b) => {
      const tr = el('tr');
      const state = el('td');
      const tone = b.state === 'granted' ? 'tag tag-ok' : (b.state === 'revoked' || b.state === 'ambiguous') ? 'tag tag-bad' : 'tag';
      state.append(el('span', tone, b.state || 'unknown'));
      if (n(b.revoked_for_seconds) > 0) state.append(' ', el('span', 'rule-desc', 'cooldown ' + secs(b.revoked_for_seconds)));
      const act = el('td');
      act.append(revokeButton(String(b.mac || '')));
      tr.append(el('td', '', b.address || ''), el('td', '', b.mac || ''), el('td', 'num', secs(b.lease_remaining_seconds)), state, act);
      return tr;
    }));

    const events = Array.isArray(s.events) ? s.events : [];
    if (!events.length) ui.events.replaceChildren(el('li', 'muted', 'No events yet.'));
    else ui.events.replaceChildren(...events.slice(0, 100).map((e) => {
      const li = el('li');
      const t = el('time', '', stamp(e.at));
      if (e.at) t.dateTime = String(e.at);
      li.append(t, el('span', 'kind', e.kind || ''), el('span', 'detail', e.detail || ''));
      return li;
    }));
  }

  async function refresh() {
    clearTimeout(timer);
    if (!token || inflight) return;
    inflight = true;
    try {
      const { status, data } = await api('GET', '/api/snapshot');
      if (status === 401) { inflight = false; lock('That token was not accepted.'); return; }
      if (status === 200 && data && data.ok && data.snapshot) {
        render(data.snapshot);
        ui.conn.textContent = 'Live · updated ' + new Date().toLocaleTimeString();
        ui.conn.classList.remove('is-error');
      } else {
        ui.conn.textContent = (data && data.message) || 'The controller did not answer.';
        ui.conn.classList.add('is-error');
      }
    } catch (_) {
      ui.conn.textContent = 'Dashboard cannot reach the controller.';
      ui.conn.classList.add('is-error');
    } finally {
      inflight = false;
      if (token) timer = setTimeout(refresh, REFRESH_MS);
    }
  }

  async function mutate(path, body, done) {
    try {
      const { status, data } = await api('POST', path, body);
      if (status === 401) { lock('That token was not accepted.'); return; }
      toast(status === 200 ? done : 'Refused: ' + ((data && data.message) || 'status ' + status));
    } catch (_) {
      toast('The controller could not be reached.');
    }
    refresh();
  }

  ui.form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const value = ui.token.value.trim();
    ui.token.value = '';
    if (value.length < 32) { lock('Tokens are at least 32 characters.'); return; }
    token = value;
    try { sessionStorage.setItem(KEY, token); } catch (_) { /* tab-only fallback */ }
    unlocked();
  });
  ui.lock.addEventListener('click', () => lock(''));
  ui.dash.addEventListener('click', (ev) => {
    const b = ev.target instanceof Element ? ev.target.closest('button[data-mac]') : null;
    if (!b) return;
    const mac = b.dataset.mac;
    b.disabled = true;
    mutate('/api/revoke', { mac }, 'Revoked ' + mac + '. A cooldown now applies.');
  });
  ui.reset.addEventListener('click', () => {
    if (!window.confirm('Revoke every grant and clear all cooldowns? DHCP bindings are kept.')) return;
    mutate('/api/reset', {}, 'All grants revoked and cooldowns cleared.');
  });

  if (token) unlocked(); else lock('');
})();
