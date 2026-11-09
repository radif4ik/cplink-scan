// «Штаб производства» для руководителей: https://cplink-lk.ru/shtab/ → служба Штаба на ПК цеха.
// Как и мост кабинета, соединение открывает ПК (исходящий HTTPS, опрос): облако ничего не хранит,
// только держит запрос, пока ПК не ответит. Ключ — свой (HMAC от CABINET_SIGNING_KEY с назначением
// shtab-relay-v1): с ним нельзя ни опрашивать мост кабинета, ни войти в кабинет.
import {createHmac, timingSafeEqual, randomUUID} from 'node:crypto';

const PREFIX = '/shtab';
const PASS_REQ = ['content-type', 'accept', 'accept-language', 'user-agent', 'if-none-match'];
const PASS_RES = ['content-type', 'cache-control', 'etag', 'set-cookie', 'content-disposition'];

export function createShtabRelay(signingKey, {timeoutMs = 25000, maxPending = 60, pollMs = 15000, maxBody = 1000000} = {}) {
  const token = createHmac('sha256', Buffer.from(signingKey, 'hex')).update('shtab-relay-v1').digest('hex');
  const expected = Buffer.from('Bearer ' + token);
  const pending = new Map();
  let wake = null, lastPoll = 0;

  const authorized = (value) => { const s = Buffer.from(value || ''); return s.length === expected.length && timingSafeEqual(s, expected); };
  const reply = (res, status, body, headers = {}) => { res.writeHead(status, {'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers}); res.end(typeof body === 'string' ? body : JSON.stringify(body)); return true; };

  async function readBody(req, limit) {
    let size = 0; const chunks = [];
    for await (const c of req) { size += c.length; if (size > limit) throw Object.assign(Error('too large'), {code: 413}); chunks.push(c); }
    return Buffer.concat(chunks);
  }

  // Запрос руководителя → задание для ПК.
  async function forward(req, res, url) {
    if (url.pathname === PREFIX) return reply(res, 301, '', {Location: PREFIX + '/' + url.search, 'Content-Type': 'text/plain'});
    if (Date.now() - lastPoll > 60000) return reply(res, 503, page('Штаб сейчас недоступен', 'Служба Штаба на ПК цеха не на связи. Попробуйте через минуту.'), {'Content-Type': 'text/html; charset=utf-8'});
    if (pending.size >= maxPending) return reply(res, 503, {error: 'Штаб перегружен, повторите'});
    if (!['GET', 'HEAD', 'POST'].includes(req.method)) return reply(res, 405, {error: 'Метод не поддерживается'});
    const body = req.method === 'POST' ? await readBody(req, 64000) : Buffer.alloc(0);
    const headers = {};
    for (const h of PASS_REQ) if (req.headers[h]) headers[h] = String(req.headers[h]).slice(0, 500);
    // Только cookie входа Штаба: сессии кабинета сотрудников на ПК не уходят.
    const own = String(req.headers.cookie || '').split(/;\s*/).filter((c) => c.startsWith('shtab_s='));
    if (own.length) headers.cookie = own.join('; ');
    headers['x-forwarded-for'] = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    headers['x-forwarded-proto'] = 'https';
    const id = randomUUID();
    const job = {id, method: req.method, path: url.pathname.slice(PREFIX.length) || '/', query: url.search, headers, body: body.toString('base64'), sent: false};
    const result = new Promise((resolve, reject) => { job.resolve = resolve; job.reject = reject; });
    const timer = setTimeout(() => { pending.delete(id); job.reject(Error('timeout')); }, timeoutMs);
    pending.set(id, job); wake?.();
    try {
      const r = await result;
      const out = {};
      for (const [k, v] of Object.entries(r.headers || {})) {
        if (!PASS_RES.includes(k.toLowerCase())) continue;
        // Cookie Штаба живёт только под /shtab/.
        out[k] = k.toLowerCase() === 'set-cookie' ? [].concat(v).map((c) => String(c).replace(/Path=\/(?=;|$)/i, 'Path=' + PREFIX + '/')) : v;
      }
      out['X-Content-Type-Options'] = 'nosniff'; out['Referrer-Policy'] = 'no-referrer';
      const payload = Buffer.from(r.body || '', 'base64');
      res.writeHead(r.status, out); res.end(req.method === 'HEAD' ? undefined : payload); return true;
    } catch {
      return reply(res, 504, page('Штаб не ответил', 'ПК цеха не ответил вовремя. Обновите страницу.'), {'Content-Type': 'text/html; charset=utf-8'});
    } finally { clearTimeout(timer); pending.delete(id); }
  }

  // ПК забирает задания (долгий опрос, как у моста кабинета).
  async function poll() {
    lastPoll = Date.now();
    if (![...pending.values()].some((x) => !x.sent)) {
      await new Promise((resolve) => { const t = setTimeout(done, pollMs); function done() { clearTimeout(t); if (wake === done) wake = null; resolve(); } wake = done; });
    }
    lastPoll = Date.now();
    return [...pending.values()].filter((x) => !x.sent).slice(0, 8).map((x) => { x.sent = true; return {id: x.id, method: x.method, path: x.path, query: x.query, headers: x.headers, body: x.body}; });
  }
  function complete(v) {
    const job = pending.get(v?.id);
    if (!job || !job.sent || !Number.isInteger(v.status) || v.status < 200 || v.status > 599 || typeof v.body !== 'string') return false;
    job.resolve({status: v.status, headers: v.headers || {}, body: v.body}); pending.delete(job.id); return true;
  }

  // Обработчик: true — запрос обслужен здесь, false — это не Штаб.
  return async function handle(req, res) {
    const path = (req.url || '').split('?')[0];
    if (path === '/internal/shtab/poll' || path === '/internal/shtab/result') {
      if (req.method !== 'POST' || !authorized(req.headers.authorization)) { res.writeHead(401, {'Cache-Control': 'no-store'}); res.end(); return true; }
      try {
        const value = JSON.parse((await readBody(req, path.endsWith('result') ? 8000000 : 1000)).toString('utf8') || '{}');
        if (path.endsWith('poll')) return reply(res, 200, {jobs: await poll()});
        res.writeHead(complete(value) ? 200 : 409, {'Cache-Control': 'no-store'}); res.end(); return true;
      } catch (e) { res.writeHead(e.code === 413 ? 413 : 400, {'Cache-Control': 'no-store'}); res.end(); return true; }
    }
    if (path !== PREFIX && !path.startsWith(PREFIX + '/')) return false;
    try { return await forward(req, res, new URL(req.url, 'https://cplink-lk.ru')); }
    catch (e) { if (res.headersSent) { res.destroy(); return true; } return reply(res, e.code === 413 ? 413 : 500, {error: 'Штаб временно недоступен'}); }
  };
}

function page(title, text) {
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#0A0D13;color:#EDF0F6;font-family:sans-serif;padding:24px;text-align:center">
<div><h1 style="font-size:22px">${title}</h1><p style="color:#8C94A8">${text}</p><button onclick="location.reload()" style="height:48px;padding:0 24px;border:0;border-radius:14px;background:#36CFF0;font-weight:700">Обновить</button></div></body>`;
}
