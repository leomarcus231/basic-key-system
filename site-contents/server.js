// Key system backend. No dependencies. Run: node server.js
const http = require('http'), crypto = require('crypto'), fs = require('fs'), path = require('path');

const PORT = process.env.PORT || 3000;
const ADMIN = process.env.ADMIN_TOKEN || '';          // set to enable /api/admin/revoke
const TRUST_PROXY = !!process.env.TRUST_PROXY;        // set if behind nginx/cloudflare
const KEY_TTL = 24 * 3600 * 1000;                     // key lifetime
const STAY_MS = 10000;                                // required time on page
const DIFF = 4;                                       // proof-of-work: leading hex zeros
const TS_SITE = process.env.TURNSTILE_SITE || '', TS_SECRET = process.env.TURNSTILE_SECRET || '';  // Cloudflare Turnstile (optional)
const DB = path.join(__dirname, 'keys.json');

let keys = {};
try { keys = JSON.parse(fs.readFileSync(DB, 'utf8')); } catch {}
const save = () => fs.writeFileSync(DB, JSON.stringify(keys, null, 2));

const sessions = new Map(), starts = new Map();
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const ipOf = req => (TRUST_PROXY ? (req.headers['x-forwarded-for'] || '').split(',')[0].trim() : '') || req.socket.remoteAddress || '';

// Same tiny "program" the browser must run (the JavaScript challenge)
function run(seed, ops) {
  let x = seed >>> 0;
  for (const [o, c] of ops) {
    if (o === 'add') x = (x + c) >>> 0;
    else if (o === 'xor') x = (x ^ c) >>> 0;
    else if (o === 'mul') x = Math.imul(x, c) >>> 0;
    else { const r = c % 31 + 1; x = ((x << r) | (x >>> (32 - r))) >>> 0; }
  }
  return x;
}
function makeProgram() {
  const names = ['add', 'xor', 'mul', 'rot'], ops = [];
  for (let i = 0; i < 8; i++) {
    const o = names[crypto.randomInt(4)];
    ops.push([o, o === 'mul' ? crypto.randomInt(1, 5000) * 2 + 1 : crypto.randomInt(1, 2 ** 31 - 1)]);
  }
  return { seed: crypto.randomInt(1, 2 ** 31 - 1), ops };
}

// Built-in image captcha, used when Turnstile keys are not set
function makeCaptcha() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let text = '', g = '', n = '';
  for (let i = 0; i < 5; i++) {
    const ch = chars[crypto.randomInt(chars.length)]; text += ch;
    const x = 18 + i * 28, y = 40 + crypto.randomInt(-5, 6), r = crypto.randomInt(-25, 26);
    g += `<text x="${x}" y="${y}" font-size="${28 + crypto.randomInt(0, 8)}" font-family="monospace" font-weight="700" transform="rotate(${r} ${x} ${y})" fill="hsl(${crypto.randomInt(360)},65%,65%)">${ch}</text>`;
  }
  for (let i = 0; i < 7; i++) {
    const p = () => crypto.randomInt(0, 170) + ' ' + crypto.randomInt(0, 60);
    n += `<path d="M${p()} Q${p()} ${p()}" stroke="hsl(${crypto.randomInt(360)},50%,60%)" fill="none" stroke-width="2"/>`;
  }
  return { text, svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 170 60" width="170" height="60"><rect width="170" height="60" rx="8" fill="#1d212b"/>${n}${g}</svg>` };
}

const send = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(obj)); };
const readBody = req => new Promise(r => {
  let d = '';
  req.on('data', c => { d += c; if (d.length > 4096) req.destroy(); });
  req.on('end', () => { try { r(JSON.parse(d || '{}')); } catch { r({}); } });
});
const getSession = (b, ip) => {
  const s = sessions.get(b.sid);
  return s && s.ip === ip && Date.now() - s.created < 30 * 60000 ? s : null;
};

setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) if (now - s.created > 30 * 60000) sessions.delete(k);
  for (const [k, v] of starts) { const f = v.filter(t => now - t < 3600000); f.length ? starts.set(k, f) : starts.delete(k); }
}, 60000);

const routes = {
  // Create a session (rate limited per IP)
  async start(b, ip) {
    const list = (starts.get(ip) || []).filter(t => Date.now() - t < 3600000);
    if (list.length >= 8) return [429, { error: 'Too many attempts. Try again later.' }];
    list.push(Date.now()); starts.set(ip, list);
    const sid = crypto.randomBytes(16).toString('hex');
    sessions.set(sid, { ip, created: Date.now(), step: 1, beats: 0, lastBeat: 0, fails: 0 });
    return [200, { sid }];
  },
  // Step 1 -> 2
  async ack(b, ip) {
    const s = getSession(b, ip); if (!s || s.step !== 1) return [400, { error: 'Invalid session.' }];
    s.step = 2; s.stayStart = Date.now();
    return [200, { ok: true }];
  },
  // Step 2: heartbeat, only counts while the page reports it is visible
  async beat(b, ip) {
    const s = getSession(b, ip); if (!s || s.step !== 2) return [400, { error: 'Invalid session.' }];
    const now = Date.now();
    if (b.visible === true && now - s.lastBeat >= 900) { s.beats++; s.lastBeat = now; }
    return [200, { beats: s.beats }];
  },
  async stay(b, ip) {
    const s = getSession(b, ip); if (!s || s.step !== 2) return [400, { error: 'Invalid session.' }];
    if (s.beats < 10 || Date.now() - s.stayStart < STAY_MS) return [400, { error: 'You did not stay on the page long enough.' }];
    s.step = 3;
    return [200, { ok: true }];
  },
  // Step 3a: captcha (Turnstile if configured, otherwise built-in image captcha)
  async captcha(b, ip) {
    const s = getSession(b, ip); if (!s || s.step !== 3) return [400, { error: 'Invalid session.' }];
    if (TS_SECRET) return [200, { mode: 'turnstile', sitekey: TS_SITE }];
    const c = makeCaptcha(); s.capText = c.text;
    return [200, { mode: 'svg', svg: c.svg }];
  },
  async captchaCheck(b, ip) {
    const s = getSession(b, ip); if (!s || s.step !== 3) return [400, { error: 'Invalid session.' }];
    let ok = false;
    if (TS_SECRET) {
      try {
        const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
          method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ secret: TS_SECRET, response: String(b.token || ''), remoteip: ip }),
        });
        ok = (await r.json()).success === true;
      } catch {}
    } else {
      ok = !!s.capText && String(b.answer || '').trim().toUpperCase() === s.capText;
      s.capText = null;                                  // each image is single use
    }
    if (!ok) { if (++s.fails >= 5) sessions.delete(b.sid); return [400, { error: 'Captcha failed, try again.' }]; }
    s.capOk = true;
    return [200, { ok: true }];
  },
  // Step 3b: issue JS challenge (proof of work + program)
  async challenge(b, ip) {
    const s = getSession(b, ip); if (!s || s.step !== 3 || !s.capOk) return [400, { error: 'Invalid session.' }];
    const p = makeProgram();
    s.chal = { salt: crypto.randomBytes(12).toString('hex'), ...p, issued: Date.now() };
    return [200, { salt: s.chal.salt, diff: DIFF, seed: p.seed, ops: p.ops }];
  },
  async solve(b, ip) {
    const s = getSession(b, ip); if (!s || s.step !== 3 || !s.chal) return [400, { error: 'Invalid session.' }];
    const c = s.chal; s.chal = null;
    const okPow = typeof b.nonce === 'string' && b.nonce.length < 20 && sha(c.salt + b.nonce).startsWith('0'.repeat(DIFF));
    const okRun = b.result === run(c.seed, c.ops);
    if (!okPow || !okRun || b.wd === true) {
      if (++s.fails >= 5) sessions.delete(b.sid);
      return [400, { error: 'Challenge failed.' }];
    }
    s.step = 4;
    return [200, { ok: true }];
  },
  // Step 4: issue key (one active key per IP)
  async key(b, ip) {
    const s = getSession(b, ip); if (!s || s.step !== 4) return [400, { error: 'Invalid session.' }];
    s.step = 5;
    const h = sha(ip).slice(0, 16), now = Date.now();
    for (const [k, v] of Object.entries(keys)) if (v.ip === h && v.expires > now && !v.revoked) return [200, { key: k, expires: v.expires, reused: true }];
    const key = 'key_' + crypto.randomBytes(24).toString('base64');
    keys[key] = { ip: h, created: now, expires: now + KEY_TTL, hwid: null, revoked: false };
    save();
    return [200, { key, expires: keys[key].expires }];
  },
};

function validate(key, hwid) {
  key = String(key || '').replace(/ /g, '+');          // '+' becomes ' ' in query strings
  const k = keys[key];
  if (!k) return { valid: false, reason: 'not_found' };
  if (k.revoked) return { valid: false, reason: 'revoked' };
  if (k.expires < Date.now()) return { valid: false, reason: 'expired' };
  if (hwid) {
    if (!k.hwid) { k.hwid = String(hwid).slice(0, 128); save(); }
    else if (k.hwid !== hwid) return { valid: false, reason: 'hwid_mismatch' };
  }
  return { valid: true, expires: k.expires };
}

http.createServer(async (req, res) => {
  const ip = ipOf(req), url = new URL(req.url, 'http://x');
  res.setHeader('x-content-type-options', 'nosniff');
  try {
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(path.join(__dirname, 'index.html')));
    }
    // Roblox / your script calls this
    if (url.pathname === '/api/validate') {
      const b = req.method === 'POST' ? await readBody(req) : Object.fromEntries(url.searchParams);
      return send(res, 200, validate(b.key, b.hwid));
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/revoke') {
      const b = await readBody(req);
      if (!ADMIN || req.headers['x-admin-token'] !== ADMIN) return send(res, 403, { error: 'Forbidden' });
      if (keys[b.key]) { keys[b.key].revoked = true; save(); return send(res, 200, { ok: true }); }
      return send(res, 404, { error: 'Not found' });
    }
    const name = url.pathname.replace('/api/', '');
    if (req.method === 'POST' && url.pathname.startsWith('/api/') && routes[name]) {
      const [code, out] = await routes[name](await readBody(req), ip);
      return send(res, code, out);
    }
    send(res, 404, { error: 'Not found' });
  } catch (e) { send(res, 500, { error: 'Server error' }); }
}).listen(PORT, () => console.log('Key system running on http://localhost:' + PORT));
