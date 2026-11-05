'use strict';
// Portcullis guest portal. Every state shown here comes from the gateway's
// /api/session answer; the page never infers or simulates access. Server
// data is written with textContent only.
(function () {
  const POLL_MS = 3000;
  const TICK_MS = 250;
  const FETCH_TIMEOUT_MS = 8000;
  const MIN_GRANT = 30;
  const KNOWN = new Set(['unrecognized', 'ambiguous', 'denied', 'granted', 'revoked', 'unavailable']);

  const $ = (id) => document.getElementById(id);
  const ui = {
    card: $('card'), pill: $('pill'), title: $('title'), detail: $('detail'),
    banner: $('banner'), bannerText: $('banner-text'),
    request: $('panel-request'), choices: $('choices'), grid: $('choice-grid'),
    wait: $('request-wait'), requestBtn: $('request'), requestLabel: $('request-label'),
    granted: $('panel-granted'), time: $('time'), timeCaption: $('time-caption'),
    meter: $('meter'), meterFill: $('meter-fill'), synced: $('synced'), release: $('release'),
    cooldownPanel: $('panel-cooldown'), cooldown: $('cooldown'),
    address: $('net-address'), device: $('net-device'),
  };
  document.documentElement.classList.remove('no-js');

  let session = null;   // last valid session from the gateway
  let receivedAt = 0;   // performance.now() when it arrived
  let busy = '';        // '' | 'request' | 'release'
  let failures = 0;     // consecutive failed polls
  let epoch = 0;        // bumps on every action; older polls are discarded
  let pollTimer = 0;
  let lastPoll = -Infinity;
  let choice = 0;
  let choiceKey = '';
  let note = '';        // '' | 'ended' | 'released'

  const pad = (n) => String(n).padStart(2, '0');
  const num = (v) => (Number.isFinite(v) && v > 0 ? Math.floor(v) : 0);
  function clock(sec) {
    sec = Math.max(0, Math.floor(sec));
    const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
    return (h ? h + ':' + pad(m) : String(m)) + ':' + pad(s);
  }
  function human(sec) {
    if (sec < 60) return sec + ' s';
    return Math.floor(sec / 60) + ' min' + (sec % 60 ? ' ' + (sec % 60) + ' s' : '');
  }
  const elapsed = () => Math.floor((performance.now() - receivedAt) / 1000);
  const remaining = () => (session ? Math.max(0, num(session.remaining_seconds) - elapsed()) : 0);
  const retryLeft = () => (session ? Math.max(0, num(session.retry_after_seconds) - elapsed()) : 0);
  function setText(el, text) { if (el.textContent !== text) el.textContent = text; }
  function validSession(s) { return s && typeof s === 'object' && KNOWN.has(s.state) ? s : null; }

  async function call(method, path, body) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);
    const init = {
      method, cache: 'no-store', credentials: 'same-origin', mode: 'same-origin',
      redirect: 'error', referrerPolicy: 'same-origin', signal: ctl.signal,
      headers: { Accept: 'application/json' },
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
      return { status: res.status, data: data && typeof data === 'object' ? data : null };
    } finally {
      clearTimeout(timer);
    }
  }

  function accept(s) {
    if (session && session.state === 'granted' && s.state === 'denied' && note !== 'released') note = 'ended';
    if (s.state === 'granted') note = '';
    session = s;
    receivedAt = performance.now();
  }

  function showBanner(text) {
    setText(ui.bannerText, text);
    ui.banner.hidden = !text;
  }

  function messageFor(status, data, action) {
    switch (data && data.error) {
      case 'rate_limited': return 'Too many requests. Please wait a moment, then try again.';
      case 'conflict': return 'Your network lease is about to run out. Reconnect to the Wi-Fi, then try again.';
      case 'forbidden': return action === 'request' ? 'This device is not allowed to request access right now.' : 'That action is not allowed right now.';
      case 'identity': return "The gateway couldn't verify this device, so nothing was granted.";
      case 'bad_request': return "The gateway didn't accept that request.";
      case 'unavailable': return 'The gateway is not granting access right now. Nothing has been opened.';
      case 'internal': return "The gateway couldn't confirm the change, so access is not shown as granted. Checking again…";
      default: return status >= 500 ? 'The gateway is having trouble. Please try again in a moment.' : 'The portal refused that request. Please reload the page.';
    }
  }

  function view() {
    if (busy === 'request') return 'requesting';
    if (failures >= 2) return 'offline';
    if (!session) return 'loading';
    if (session.state === 'granted' && remaining() <= 0) return 'checking';
    return session.state;
  }

  function copyFor(v) {
    const reason = session && typeof session.reason === 'string' ? session.reason : '';
    switch (v) {
      case 'loading': return ['busy', 'Checking', 'Checking your connection…', 'Asking the gateway to identify this device.'];
      case 'requesting': return ['busy', 'Requesting', 'Requesting access…', 'Waiting for the gateway firewall to confirm.'];
      case 'checking': return ['busy', 'Checking', 'Checking with the gateway…', 'Your time is up. Confirming that access has closed for this device.'];
      case 'offline': return ['bad', 'Offline', "Can't reach the portal", 'This device may have left the guest Wi-Fi. Reconnect and this page will update by itself.'];
      case 'unrecognized': return ['warn', 'Not recognized', 'Device not recognized', "This device isn't recognized on the guest network yet — reconnect to Wi-Fi so it receives an address."];
      case 'ambiguous': return ['warn', 'Unverified', "Your connection couldn't be verified", reason || 'The gateway found conflicting information about this device, so nothing was granted.'];
      case 'granted': return ['ok', 'Online', "You're online", 'The gateway firewall is letting this device through.'];
      case 'revoked': return ['bad', 'Revoked', 'Access was revoked', 'The network operator ended access for this device.'];
      case 'unavailable': return ['bad', 'Unavailable', 'Access is unavailable', reason || 'The gateway cannot verify its firewall right now, so it is not granting access. Nothing is open.'];
      default:
        if (note === 'ended') return ['neutral', 'No internet access', 'Your time is up', 'The gateway closed the firewall for this device. Request access again whenever you need it.'];
        if (note === 'released') return ['neutral', 'No internet access', 'Access ended', 'You ended access. The firewall is closed for this device again.'];
        return ['neutral', 'No internet access', 'Get online', 'Choose how long you need. The gateway opens its firewall for this device only, then closes it automatically.'];
    }
  }

  function buildChoices() {
    const def = num(session && session.default_duration_seconds);
    const max = num(session && session.max_duration_seconds);
    const key = def + '/' + max;
    if (key === choiceKey) return;
    choiceKey = key;
    const opts = [];
    if (def >= MIN_GRANT && (!max || def <= max)) opts.push([def, 'Default']);
    if (max >= MIN_GRANT && max !== def) opts.push([max, 'Maximum']);
    if (!opts.some((o) => o[0] === choice)) choice = opts.length ? opts[0][0] : 0;
    ui.grid.replaceChildren(...opts.map(([value, label]) => {
      const wrap = document.createElement('div');
      wrap.className = 'choice';
      const input = document.createElement('input');
      input.type = 'radio';
      input.name = 'duration';
      input.id = 'duration-' + value;
      input.value = String(value);
      input.checked = value === choice;
      input.addEventListener('change', () => { if (input.checked) choice = value; });
      const lab = document.createElement('label');
      lab.htmlFor = input.id;
      const main = document.createElement('span');
      main.className = 'choice-main';
      main.textContent = human(value);
      const sub = document.createElement('span');
      sub.className = 'choice-sub';
      sub.textContent = label;
      lab.append(main, sub);
      wrap.append(input, lab);
      return wrap;
    }));
    ui.choices.hidden = opts.length === 0;
  }

  function paint() {
    const v = view();
    const [tone, pill, title, detail] = copyFor(v);
    ui.card.dataset.tone = tone;
    ui.card.setAttribute('aria-busy', v === 'loading' || v === 'requesting' || v === 'checking' ? 'true' : 'false');
    setText(ui.pill, pill);
    setText(ui.title, title);
    setText(ui.detail, detail);

    const focusInside = (el) => el.contains(document.activeElement);
    const showRequest = v === 'denied' || v === 'requesting';
    const showGranted = v === 'granted';
    const showCooldown = v === 'revoked' && retryLeft() > 0;
    if ((!showRequest && focusInside(ui.request)) || (!showGranted && focusInside(ui.granted))) ui.title.focus();
    ui.request.hidden = !showRequest;
    ui.granted.hidden = !showGranted;
    ui.cooldownPanel.hidden = !showCooldown;

    if (showRequest) {
      buildChoices();
      const wait = retryLeft();
      const blocked = !session || !session.can_request || wait > 0;
      ui.requestBtn.disabled = v === 'requesting' || blocked;
      ui.requestBtn.classList.toggle('is-busy', v === 'requesting');
      setText(ui.requestLabel, v === 'requesting' ? 'Requesting…' : 'Request access');
      ui.grid.querySelectorAll('input').forEach((i) => { i.disabled = v === 'requesting'; });
      ui.wait.hidden = !(blocked && v !== 'requesting');
      setText(ui.wait, wait > 0 ? 'You can request access again in ' + clock(wait) + '.' : "Requests aren't available for this device right now.");
    }
    if (showGranted) {
      const left = remaining();
      const total = Math.max(num(session.granted_seconds), left, 1);
      const frac = Math.min(1, left / total);
      setText(ui.time, clock(left));
      setText(ui.timeCaption, 'remaining of ' + clock(total));
      ui.meterFill.style.transform = 'scaleX(' + frac.toFixed(4) + ')';
      ui.meter.classList.toggle('is-low', left <= 30);
      ui.meter.setAttribute('aria-valuenow', String(Math.round(frac * 100)));
      ui.meter.setAttribute('aria-valuetext', clock(left) + ' remaining');
      const age = elapsed();
      setText(ui.synced, failures ? 'Reconnecting to the gateway…' : age < 2 ? 'Confirmed by the gateway just now' : 'Confirmed by the gateway ' + age + ' s ago');
      ui.release.disabled = busy === 'release';
      setText(ui.release, busy === 'release' ? 'Ending access…' : 'End access now');
    }
    if (showCooldown) setText(ui.cooldown, clock(retryLeft()));
    setText(ui.address, (session && session.client_address) || '—');
    setText(ui.device, session && session.client_mac_hint ? 'Hardware address ' + session.client_mac_hint : '—');
  }

  function schedule() {
    clearTimeout(pollTimer);
    if (!document.hidden) pollTimer = setTimeout(poll, POLL_MS);
  }

  async function poll() {
    clearTimeout(pollTimer);
    if (document.hidden || busy) return;
    const mine = epoch;
    lastPoll = performance.now();
    let s = null;
    let failed = false;
    try {
      const { data } = await call('GET', '/api/session');
      s = validSession(data && data.session);
      failed = !s;
    } catch (_) {
      failed = true;
    }
    if (busy || mine !== epoch) return; // an action superseded this answer
    if (failed) {
      failures += 1;
      if (failures >= 2) session = null;
      showBanner(failures === 1 ? 'Reconnecting to the gateway…' : '');
    } else {
      failures = 0;
      if (ui.bannerText.textContent === 'Reconnecting to the gateway…') showBanner('');
      accept(s);
    }
    paint();
    schedule();
  }

  async function act(kind, path, body) {
    if (busy) return;
    busy = kind;
    epoch += 1;
    clearTimeout(pollTimer);
    showBanner('');
    paint();
    try {
      const { status, data } = await call('POST', path, body);
      const s = validSession(data && data.session);
      if (s) {
        failures = 0;
        if (kind === 'release' && status === 200) note = 'released';
        accept(s);
      }
      const succeeded = kind === 'request' ? status === 200 && s && s.state === 'granted' : status === 200;
      if (!succeeded) showBanner(messageFor(status, data, kind));
    } catch (_) {
      showBanner(kind === 'request'
        ? "Couldn't reach the gateway. Nothing was granted — check your Wi-Fi connection and try again."
        : "Couldn't reach the gateway to end access. Your time will still run out automatically.");
    } finally {
      busy = '';
      paint();
      poll();
    }
  }

  ui.requestBtn.addEventListener('click', () => {
    if (!session || session.state !== 'denied') return;
    note = '';
    act('request', '/api/access', choice >= MIN_GRANT ? { duration_seconds: choice } : {});
  });
  ui.release.addEventListener('click', () => act('release', '/api/release', {}));
  document.addEventListener('visibilitychange', () => { if (document.hidden) clearTimeout(pollTimer); else poll(); });

  setInterval(() => {
    if (!session || busy) return;
    const v = view();
    const due = (v === 'checking' || (num(session.retry_after_seconds) && retryLeft() === 0));
    if (due && performance.now() - lastPoll > 1500) poll();
    paint();
  }, TICK_MS);

  paint();
  poll();
})();
