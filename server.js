'use strict';
/**
 * SMART TOPOLOGY — Network Monitoring System (NOC)
 * Zero-dependency Node.js server (Node >= 18)
 *  - Login / session (scrypt hashed passwords, HttpOnly cookie)
 *  - Users & roles: admin / operator / viewer
 *  - Device inventory (switch, router, server, IP ...)
 *  - Real monitoring: ICMP ping (system `ping`) or TCP port check
 *  - Alerts on status change, live updates via Server-Sent Events
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const { execFile } = require('child_process');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const PUBLIC = path.join(__dirname, 'public');
const HISTORY_LEN = 60;
const SESSION_TTL = 12 * 3600 * 1000;
const TYPES = ['isp', 'firewall', 'router', 'core', 'switch', 'ap', 'server', 'vm', 'database',
  'client', 'laptop', 'camera', 'printer', 'medical', 'kiosk', 'iot', 'other'];
const ROLE_RANK = { viewer: 1, operator: 2, admin: 3 };

/* ------------------------------------------------------------------ DB */
let db;
function defaultDB() {
  return {
    users: [], devices: [], alerts: [],
    settings: { intervalSec: 10, timeoutMs: 1000, warnMs: 100, slaTarget: 99.8, siteName: 'โรงพยาบาล' },
    notify: defaultNotify(),
    seq: { device: 0, alert: 0, user: 0 },
  };
}
const MOPH_URL = 'https://morpromt2f.moph.go.th/api/notify/send';
function defaultNotify() {
  return { enabled: false, onDown: true, onRecover: true, onWarning: false, criticalOnly: false,
    suppressChildren: true, repeatMin: 0, publicUrl: '', channels: [], log: [] };
}
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(String(pw), salt, 64).toString('hex');
}
function checkPw(pw, stored) {
  try {
    const [salt, h] = stored.split(':');
    const a = crypto.scryptSync(String(pw), salt, 64);
    const b = Buffer.from(h, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch { return false; }
}
function loadDB() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const def = defaultDB();
  if (fs.existsSync(DB_FILE)) {
    db = Object.assign(def, JSON.parse(fs.readFileSync(DB_FILE, 'utf8')));
    db.settings = Object.assign(defaultDB().settings, db.settings);
    db.seq = Object.assign(defaultDB().seq, db.seq);
    db.notify = Object.assign(defaultNotify(), db.notify);
  } else db = def;
  if (!db.users.length) {
    const pw = process.env.ADMIN_PASSWORD || 'admin1234';
    db.users.push({ id: ++db.seq.user, username: 'admin', name: 'ผู้ดูแลระบบ', role: 'admin',
      pass: hashPw(pw), mustChange: !process.env.ADMIN_PASSWORD, created: Date.now() });
    console.log(`[init] สร้างผู้ใช้ admin (รหัสผ่าน: ${process.env.ADMIN_PASSWORD ? '(จาก ADMIN_PASSWORD)' : 'admin1234'}) — กรุณาเปลี่ยนรหัสผ่านหลังเข้าระบบ`);
  }
  saveNow();
}
let saveTimer = null;
function save() { if (!saveTimer) saveTimer = setTimeout(() => { saveTimer = null; saveNow(); }, 400); }
function saveNow() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 1));
  fs.renameSync(tmp, DB_FILE);
}

/* ------------------------------------------------------------- Checks */
let pingMissingLogged = false;
function icmp(host, timeout) {
  return new Promise((resolve) => {
    const p = process.platform;
    const tSec = Math.max(1, Math.ceil(timeout / 1000));
    const args = p === 'win32' ? ['-n', '1', '-w', String(timeout), host]
      : p === 'darwin' ? ['-c', '1', '-t', String(tSec), host]
        : ['-c', '1', '-W', String(tSec), host];
    const start = process.hrtime.bigint();
    execFile('ping', args, { timeout: timeout + 2500, windowsHide: true }, (err, stdout) => {
      const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
      const out = String(stdout || '');
      if (err) {
        if (err.code === 'ENOENT' && !pingMissingLogged) {
          pingMissingLogged = true;
          console.warn('[warn] ไม่พบคำสั่ง ping ในระบบ — ติดตั้ง iputils-ping หรือใช้การตรวจแบบ TCP');
        }
        return resolve(null);
      }
      if (p === 'win32' && !/TTL=/i.test(out)) return resolve(null);
      const m = out.match(/time[=<]\s*([\d.]+)\s*ms/i) || out.match(/[=<]\s*([\d.]+)\s*ms/);
      resolve(m ? parseFloat(m[1]) : elapsed);
    });
  });
}
function tcp(host, port, timeout) {
  return new Promise((resolve) => {
    const s = new net.Socket();
    const start = process.hrtime.bigint();
    let done = false;
    const fin = (v) => { if (done) return; done = true; s.destroy(); resolve(v); };
    s.setTimeout(timeout);
    s.once('connect', () => fin(Number(process.hrtime.bigint() - start) / 1e6));
    s.once('timeout', () => fin(null));
    s.once('error', () => fin(null));
    try { s.connect(port, host); } catch { fin(null); }
  });
}

/* ------------------------------------------------------------ Monitor */
const rt = new Map();
let cycle = 0, lastCycleAt = 0, cycleRunning = false, timer = null;
const trend = [];
function getRt(id) {
  if (!rt.has(id)) rt.set(id, { status: 'unknown', latency: null, history: [], lastCheck: 0, since: Date.now(), fails: 0 });
  return rt.get(id);
}
const r2 = (v) => (v == null ? null : Math.round(v * 100) / 100);

function addAlert(d, severity, kind, message) {
  const open = db.alerts.find((a) => a.deviceId === d.id && a.kind === kind && a.status !== 'resolved');
  if (open) return null;
  const a = { id: ++db.seq.alert, deviceId: d.id, deviceName: d.name, ip: d.ip, severity, kind, message,
    status: 'active', created: Date.now(), ackBy: null, resolvedAt: null };
  db.alerts.push(a);
  if (db.alerts.length > 2000) db.alerts.splice(0, db.alerts.length - 2000);
  save();
  return a;
}
function resolveAlerts(d, kinds) {
  const done = [];
  for (const a of db.alerts) {
    if (a.deviceId === d.id && a.status !== 'resolved' && (!kinds || kinds.includes(a.kind))) {
      a.status = 'resolved'; a.resolvedAt = Date.now(); done.push(a);
    }
  }
  if (done.length) save();
  return done;
}
function onTransition(d, prev, st) {
  if (st === 'offline') {
    resolveAlerts(d, ['latency']);
    const a = addAlert(d, d.critical ? 'critical' : 'warning', 'down',
      `${d.name} (${d.ip}) ไม่ตอบสนอง${d.method === 'tcp' ? ` ที่พอร์ต ${d.port}` : ' ICMP'}`);
    if (a) queueNotify('down', d, a);
  } else if (st === 'warning') {
    resolveAlerts(d, ['down']).forEach((a) => queueNotify('recover', d, a));
    const a = addAlert(d, 'info', 'latency', `${d.name} มีค่า latency สูงเกินเกณฑ์ ${db.settings.warnMs} ms`);
    if (a) queueNotify('warning', d, a);
  } else if (st === 'online') {
    resolveAlerts(d).filter((a) => a.kind === 'down').forEach((a) => queueNotify('recover', d, a));
  } else if (st === 'maintenance' || st === 'disabled') {
    resolveAlerts(d); // ไม่ส่งแจ้งเตือนภายนอกเมื่อเข้าโหมดบำรุงรักษา/ปิดตรวจ
  }
}

/* ------------------------------------------------- External notification */
const pendingN = [];
function queueNotify(kind, d, a) {
  pendingN.push({ kind, id: d.id, alertId: a.id, created: a.created, resolvedAt: a.resolvedAt });
}
const NMETA = {
  down: { icon: '🔴', title: 'อุปกรณ์ขาดการเชื่อมต่อ', color: '#E5384F' },
  repeat: { icon: '⏰', title: 'อุปกรณ์ยังขาดการเชื่อมต่อ', color: '#B42339' },
  recover: { icon: '🟢', title: 'อุปกรณ์กลับมาใช้งานได้', color: '#12A372' },
  warning: { icon: '🟠', title: 'อุปกรณ์ตอบสนองช้า', color: '#E08A00' },
  test: { icon: '✅', title: 'ทดสอบการแจ้งเตือน', color: '#0E7C6B' },
};
const thTime = (t) => new Date(t).toLocaleString('th-TH', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
function thDur(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s} วินาที`;
  if (s < 3600) return `${Math.floor(s / 60)} นาที`;
  if (s < 86400) return `${Math.floor(s / 3600)} ชม. ${Math.floor((s % 3600) / 60)} นาที`;
  return `${Math.floor(s / 86400)} วัน ${Math.floor((s % 86400) / 3600)} ชม.`;
}
function buildMessage(kind, items, hidden = 0) {
  const m = NMETA[kind], now = Date.now(), N = db.notify, site = db.settings.siteName || 'Smart Topology';
  const rows = items.slice(0, 10).map(({ d, e }) => {
    const tgt = d.ip + (d.method === 'tcp' ? ':' + d.port : '');
    let info = '';
    if (kind === 'down') info = `ขาดการเชื่อมต่อเมื่อ ${thTime(e.created)}`;
    else if (kind === 'repeat') info = `ขาดการเชื่อมต่อมาแล้ว ${thDur(now - e.created)}`;
    else if (kind === 'recover') info = `กลับมาเมื่อ ${thTime(e.resolvedAt || now)} (ใช้งานไม่ได้ ${thDur((e.resolvedAt || now) - e.created)})`;
    else if (kind === 'warning') info = `Latency ${getRt(d.id).latency ?? '-'} ms (เกณฑ์ ${db.settings.warnMs} ms)`;
    else info = e.info || '';
    return { name: (d.critical ? '[สำคัญ] ' : '') + d.name, target: tgt, location: d.location || '', info,
      detail: `${tgt}${d.location ? ' · ' + d.location : ''}\n${info}` };
  });
  const extra = [];
  if (items.length > 10) extra.push(`…และอีก ${items.length - 10} รายการ`);
  if (hidden) extra.push(`+ อุปกรณ์ปลายทางที่ได้รับผลกระทบอีก ${hidden} รายการ`);
  const title = `${m.icon} ${m.title}${kind === 'test' ? '' : ` (${items.length} รายการ)`}`;
  const text = `${title}\n${site}\n\n` + rows.map((r, i) => `${i + 1}. ${r.name}\n   ${r.detail.replace('\n', '\n   ')}`).join('\n')
    + (extra.length ? '\n' + extra.join('\n') : '') + `\n\nเวลา ${thTime(now)}` + (N.publicUrl ? `\n${N.publicUrl}` : '');
  return { kind, title, site, color: m.color, rows, extra, text, time: now };
}
function flexBubble(msg) {
  const T = (text, o = {}) => ({ type: 'text', text: String(text || '-').slice(0, 300), wrap: true, ...o });
  const body = [];
  msg.rows.forEach((r, i) => {
    if (i) body.push({ type: 'separator', margin: 'md' });
    body.push({ type: 'box', layout: 'vertical', margin: i ? 'md' : 'none', spacing: 'xs', contents: [
      T(r.name, { weight: 'bold', size: 'sm', color: '#1B2533' }),
      T(`${r.target}${r.location ? ' · ' + r.location : ''}`, { size: 'xs', color: '#0E7C6B' }),
      T(r.info, { size: 'xs', color: '#66768A' })] });
  });
  msg.extra.forEach((x) => body.push(T(x, { size: 'xs', color: '#E5384F', margin: 'md' })));
  const footer = [T(`Smart Topology NOC · ${thTime(msg.time)}`, { size: 'xxs', color: '#9AA8B8', align: 'center' })];
  if (/^https?:\/\//i.test(db.notify.publicUrl || '')) {
    footer.unshift({ type: 'button', style: 'primary', color: '#0E7C6B', height: 'sm',
      action: { type: 'uri', label: 'เปิดระบบ NOC', uri: db.notify.publicUrl } });
  }
  return { type: 'bubble', size: 'mega',
    header: { type: 'box', layout: 'vertical', backgroundColor: msg.color, paddingAll: '14px', contents: [
      T(msg.title, { color: '#FFFFFF', weight: 'bold', size: 'md' }), T(msg.site, { color: '#FFFFFFCC', size: 'xs' })] },
    body: { type: 'box', layout: 'vertical', contents: body.length ? body : [T('-')] },
    footer: { type: 'box', layout: 'vertical', spacing: 'sm', contents: footer } };
}
function parseHeaderLines(txt) {
  const h = {};
  String(txt || '').split(/\r?\n/).forEach((line) => {
    const i = line.indexOf(':');
    if (i > 0) { const k = line.slice(0, i).trim(), v = line.slice(i + 1).trim(); if (/^[A-Za-z0-9-]+$/.test(k)) h[k] = v; }
  });
  return h;
}
async function sendChannel(c, msg, attempt = 1) {
  const entry = { t: Date.now(), channel: c.name || c.type, type: c.type, kind: msg.kind, ok: false, status: null, info: '' };
  try {
    let url, body;
    const headers = { 'Content-Type': 'application/json' };
    if (c.type === 'moph') {
      url = c.url || MOPH_URL;
      headers['client-key'] = c.clientKey || ''; headers['secret-key'] = c.secretKey || '';
      body = { messages: [c.format === 'text' ? { type: 'text', text: msg.text.slice(0, 4900) }
        : { type: 'flex', altText: msg.title.slice(0, 390), contents: flexBubble(msg) }] };
    } else if (c.type === 'telegram') {
      url = `https://api.telegram.org/bot${c.botToken}/sendMessage`;
      body = { chat_id: c.chatId, text: msg.text.slice(0, 4000), disable_web_page_preview: true };
    } else {
      url = c.url;
      Object.assign(headers, parseHeaderLines(c.headers));
      body = { event: msg.kind, title: msg.title, text: msg.text, content: msg.text.slice(0, 1900), site: msg.site,
        time: new Date(msg.time).toISOString(), devices: msg.rows.map((r) => ({ name: r.name, target: r.target, location: r.location, info: r.info })) };
    }
    const r = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(10000) });
    const txt = (await r.text()).slice(0, 300);
    entry.status = r.status; entry.ok = r.ok; entry.info = txt;
    // บาง API ตอบ 200 แต่แจ้ง error ใน body
    try { const j = JSON.parse(txt); if (j && (j.ok === false || j.success === false || /error|fail/i.test(String(j.status || '')))) entry.ok = false; } catch { /* not json */ }
  } catch (e) {
    entry.info = e.name === 'TimeoutError' ? 'หมดเวลาเชื่อมต่อ (10 วินาที)' : String((e.cause && (e.cause.code || e.cause.message)) || e.message);
  }
  if (!entry.ok && attempt === 1 && (entry.status == null || entry.status >= 500)) {
    await new Promise((r) => setTimeout(r, 5000));
    return sendChannel(c, msg, 2);
  }
  if (attempt > 1) entry.info = `(ส่งซ้ำ) ${entry.info}`;
  db.notify.log.push(entry);
  if (db.notify.log.length > 100) db.notify.log.splice(0, db.notify.log.length - 100);
  save();
  if (!entry.ok) console.warn(`[notify] ส่งไม่สำเร็จ (${entry.channel}): ${entry.status || ''} ${entry.info}`);
  return entry;
}
function eligible(d) { const N = db.notify; return d.notify !== false && (!N.criticalOnly || d.critical); }
function hasOfflineAncestor(d, downIds) {
  let cur = d.parentId, g = 0;
  while (cur != null && g++ < 100) {
    const p = db.devices.find((x) => x.id === cur);
    if (!p) return false;
    if (downIds.has(p.id) && eligible(p)) return true;
    cur = p.parentId;
  }
  return false;
}
let flushing = Promise.resolve();
function flushNotify() {
  flushing = flushing.then(doFlush).catch((e) => console.error('[notify]', e));
  return flushing;
}
async function doFlush() {
  const N = db.notify;
  if (!N.repeatMin || !N.enabled) { /* no-op */ } else {
    const now = Date.now();
    for (const a of db.alerts) {
      if (a.kind === 'down' && a.status === 'active' && a.lastNotified && now - a.lastNotified >= N.repeatMin * 60000) {
        a.lastNotified = now; pendingN.push({ kind: 'repeat', id: a.deviceId, alertId: a.id, created: a.created });
      }
    }
  }
  if (!pendingN.length) return;
  const evs = pendingN.splice(0);
  const chans = N.channels.filter((c) => c.enabled);
  if (!N.enabled || !chans.length) return;
  const allow = { down: N.onDown, repeat: N.onDown, recover: N.onRecover, warning: N.onWarning };
  const groups = { down: [], repeat: [], recover: [], warning: [] };
  for (const e of evs) {
    const d = db.devices.find((x) => x.id === e.id);
    if (!d || !allow[e.kind] || !eligible(d)) continue;
    // แจ้ง "กลับมา" เฉพาะอุปกรณ์ที่เคยส่งแจ้ง "ล่ม" ไปแล้วจริง
    if (e.kind === 'recover') { const a = db.alerts.find((x) => x.id === e.alertId); if (!a || !a.lastNotified) continue; }
    groups[e.kind].push({ d, e });
  }
  const downIds = new Set(db.devices.filter((x) => getRt(x.id).status === 'offline').map((x) => x.id));
  for (const kind of Object.keys(groups)) {
    let items = groups[kind], hidden = 0;
    if (!items.length) continue;
    if (N.suppressChildren && (kind === 'down' || kind === 'repeat')) {
      const keep = items.filter((it) => !hasOfflineAncestor(it.d, downIds));
      hidden = items.length - keep.length;
      items = keep;
      if (!items.length) continue; // อุปกรณ์ต้นทางถูกแจ้งไปแล้ว ไม่ต้องแจ้งซ้ำ
    }
    if (kind === 'down') items.forEach(({ e }) => { const a = db.alerts.find((x) => x.id === e.alertId); if (a) a.lastNotified = Date.now(); });
    const msg = buildMessage(kind, items, hidden);
    await Promise.all(chans.map((c) => sendChannel(c, msg)));
  }
}
const SECRET_FIELDS = ['clientKey', 'secretKey', 'botToken'];
const maskVal = (v) => (v ? '••••' + String(v).slice(-4) : '');
function notifyView() {
  const N = db.notify;
  return { ...N, defaultUrl: MOPH_URL, log: N.log.slice(-30).reverse(),
    channels: N.channels.map((c) => { const o = { ...c }; SECRET_FIELDS.forEach((k) => { if (o[k]) o[k] = maskVal(o[k]); }); return o; }) };
}
function validChannel(c, strict) {
  const old = db.notify.channels.find((x) => x.id === c.id);
  const type = ['moph', 'webhook', 'telegram'].includes(c.type) ? c.type : null;
  if (!type) throw bad('ประเภทช่องทางไม่ถูกต้อง');
  const keep = (k) => { const v = c[k]; return typeof v === 'string' && v.startsWith('••••') && old ? old[k] : str(v, 500); };
  const ch = { id: old ? old.id : crypto.randomBytes(6).toString('hex'), type, enabled: c.enabled !== false,
    name: str(c.name, 60) || { moph: 'MOPH Notify (หมอพร้อม)', webhook: 'Webhook', telegram: 'Telegram' }[type] };
  if (type === 'moph') {
    ch.url = str(c.url, 500) || MOPH_URL; ch.clientKey = keep('clientKey'); ch.secretKey = keep('secretKey');
    ch.format = c.format === 'text' ? 'text' : 'flex';
    if (strict && (!ch.clientKey || !ch.secretKey)) throw bad(`${ch.name}: กรุณาระบุ client-key และ secret-key`);
  } else if (type === 'telegram') {
    ch.botToken = keep('botToken'); ch.chatId = str(c.chatId, 60);
    if (strict && (!ch.botToken || !ch.chatId)) throw bad(`${ch.name}: กรุณาระบุ Bot Token และ Chat ID`);
  } else {
    ch.url = str(c.url, 500); ch.headers = str(c.headers, 2000);
  }
  if (ch.url && !/^https?:\/\/[^\s]+$/i.test(ch.url)) throw bad(`${ch.name}: URL ต้องขึ้นต้นด้วย http:// หรือ https://`);
  if (type === 'webhook' && strict && !ch.url) throw bad(`${ch.name}: กรุณาระบุ URL`);
  return ch;
}
async function checkDevice(d) {
  const r = getRt(d.id);
  const ms = d.method === 'tcp' ? await tcp(d.ip, d.port, db.settings.timeoutMs) : await icmp(d.ip, db.settings.timeoutMs);
  // อุปกรณ์อาจถูกลบระหว่างตรวจ
  if (!db.devices.find((x) => x.id === d.id)) return;
  r.lastCheck = Date.now();
  r.history.push(r2(ms));
  if (r.history.length > HISTORY_LEN) r.history.shift();
  r.latency = r2(ms);
  let st;
  if (ms == null) {
    r.fails++;
    st = (r.fails >= 2 || r.status === 'unknown' || r.status === 'offline') ? 'offline' : r.status;
  } else {
    r.fails = 0;
    st = ms > db.settings.warnMs ? 'warning' : 'online';
  }
  if (d.maintenance) st = 'maintenance';
  if (st !== r.status) {
    const prev = r.status; r.status = st; r.since = Date.now();
    onTransition(d, prev, st);
  }
}
async function pool(items, n, fn) {
  let i = 0;
  const workers = Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const it = items[i++]; try { await fn(it); } catch (e) { console.error(e); } }
  });
  await Promise.all(workers);
}
async function runCycle() {
  if (cycleRunning) return;
  cycleRunning = true;
  try {
    const list = db.devices.filter((d) => d.enabled);
    await pool(list, 48, checkDevice);
    for (const d of db.devices.filter((x) => !x.enabled)) {
      const r = getRt(d.id);
      if (r.status !== 'disabled') { r.status = 'disabled'; r.since = Date.now(); r.latency = null; onTransition(d, null, 'disabled'); }
    }
    cycle++; lastCycleAt = Date.now();
    const mon = list.filter((d) => !d.maintenance);
    const lats = mon.map((d) => getRt(d.id).latency).filter((v) => v != null);
    const avg = lats.length ? lats.reduce((a, b) => a + b, 0) / lats.length : null;
    const jitter = lats.length > 1 ? Math.sqrt(lats.reduce((a, b) => a + (b - avg) ** 2, 0) / lats.length) : 0;
    const up = mon.filter((d) => ['online', 'warning'].includes(getRt(d.id).status)).length;
    trend.push({ t: lastCycleAt, avg: r2(avg), jitter: r2(jitter), up, total: mon.length });
    if (trend.length > HISTORY_LEN) trend.shift();
    broadcast();
    flushNotify();
  } finally { cycleRunning = false; }
}
function schedule() {
  clearInterval(timer);
  timer = setInterval(runCycle, Math.max(3, db.settings.intervalSec) * 1000);
}

/* -------------------------------------------------------------- State */
function lossPct(h) {
  if (!h.length) return null;
  const s = h.slice(-20);
  return Math.round((s.filter((v) => v == null).length / s.length) * 100);
}
function devView(d) {
  const r = getRt(d.id);
  const status = d.enabled ? (d.maintenance && r.status !== 'unknown' ? 'maintenance' : r.status) : 'disabled';
  return { ...d, status, latency: r.latency, lastCheck: r.lastCheck, since: r.since, history: r.history, loss: lossPct(r.history) };
}
function stateView() {
  return {
    cycle, lastCycleAt, serverTime: Date.now(), settings: db.settings,
    devices: db.devices.map(devView), trend, alerts: db.alerts.slice(-300),
  };
}
const clients = new Set();
function broadcast() {
  if (!clients.size) return;
  const payload = `event: state\ndata: ${JSON.stringify(stateView())}\n\n`;
  for (const c of clients) {
    const u = db.users.find((x) => x.id === c.uid);
    if (!u) { c.res.end(); clients.delete(c); continue; }
    c.res.write(payload);
  }
}
setInterval(() => { for (const c of clients) c.res.write(': ping\n\n'); }, 25000);

/* --------------------------------------------------------- Validation */
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = (m) => new HttpError(400, m);
const str = (v, n = 200) => String(v == null ? '' : v).trim().slice(0, n);
const HOST_RE = /^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9.\-:]*[a-zA-Z0-9])?$/;

function wouldCycle(id, parentId) {
  let cur = parentId, guard = 0;
  while (cur != null && guard++ < 10000) {
    if (cur === id) return true;
    const p = db.devices.find((x) => x.id === cur);
    cur = p ? p.parentId : null;
  }
  return false;
}
function validDevice(b, existing) {
  const d = {};
  d.name = str(b.name, 120);
  if (!d.name) throw bad('กรุณาระบุชื่ออุปกรณ์');
  d.ip = str(b.ip, 253);
  if (!HOST_RE.test(d.ip)) throw bad('รูปแบบ IP / Hostname ไม่ถูกต้อง');
  d.type = TYPES.includes(b.type) ? b.type : 'other';
  d.method = b.method === 'tcp' ? 'tcp' : 'icmp';
  d.port = null;
  if (d.method === 'tcp') {
    d.port = parseInt(b.port, 10);
    if (!(d.port >= 1 && d.port <= 65535)) throw bad('พอร์ต TCP ต้องอยู่ระหว่าง 1-65535');
  }
  d.vendor = str(b.vendor, 40);
  d.model = str(b.model, 120);
  d.code = str(b.code, 40);
  d.location = str(b.location, 160);
  d.vlan = str(b.vlan, 20);
  d.mac = str(b.mac, 40);
  d.linkLabel = str(b.linkLabel, 40);
  d.description = str(b.description, 500);
  d.critical = !!b.critical;
  d.maintenance = !!b.maintenance;
  d.enabled = b.enabled !== false;
  d.notify = b.notify !== false;
  const pid = b.parentId === '' || b.parentId == null ? null : parseInt(b.parentId, 10);
  if (pid != null) {
    if (!db.devices.find((x) => x.id === pid)) throw bad('ไม่พบอุปกรณ์ต้นทาง (Uplink) ที่เลือก');
    if (existing && (pid === existing.id || wouldCycle(existing.id, pid))) throw bad('ไม่สามารถเชื่อมต่อแบบวนซ้ำได้');
  }
  d.parentId = pid;
  const dup = db.devices.find((x) => x.ip === d.ip && x.method === d.method && x.port === d.port && (!existing || x.id !== existing.id));
  if (dup) throw bad(`IP นี้ถูกใช้แล้วโดย "${dup.name}" (ใช้วิธีตรวจหรือพอร์ตอื่นหากต้องการซ้ำ)`);
  return d;
}

/* ------------------------------------------------------------- Auth */
const sessions = new Map();
const failures = new Map();
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function getUser(req) {
  const t = parseCookies(req).nms_sid;
  if (!t) return null;
  const s = sessions.get(t);
  if (!s || s.exp < Date.now()) { sessions.delete(t); return null; }
  s.exp = Date.now() + SESSION_TTL;
  const u = db.users.find((x) => x.id === s.uid);
  return u ? { u, token: t } : null;
}
function isSecure(req) { return process.env.COOKIE_SECURE === '1' || req.headers['x-forwarded-proto'] === 'https'; }
function setCookie(req, res, val, maxAge) {
  res.setHeader('Set-Cookie', `nms_sid=${val}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${isSecure(req) ? '; Secure' : ''}`);
}
const publicUser = (u) => ({ id: u.id, username: u.username, name: u.name, role: u.role, mustChange: !!u.mustChange, created: u.created, lastLogin: u.lastLogin || null });
function need(user, role) { if (ROLE_RANK[user.role] < ROLE_RANK[role]) throw new HttpError(403, 'สิทธิ์ไม่เพียงพอสำหรับการดำเนินการนี้'); }

/* ------------------------------------------------------------- HTTP */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json', '.woff2': 'font/woff2' };
function secHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");
}
function send(res, code, obj) {
  if (res.headersSent) return res.end();
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > 2e6) { reject(new HttpError(413, 'ข้อมูลใหญ่เกินไป')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(bad('รูปแบบ JSON ไม่ถูกต้อง')); }
    });
    req.on('error', reject);
  });
}
function serveStatic(req, res, pathname) {
  if (pathname === '/') pathname = '/index.html';
  if (pathname === '/login') pathname = '/login.html';
  const file = path.normalize(path.join(PUBLIC, pathname));
  if (!file.startsWith(PUBLIC + path.sep)) { res.writeHead(403); return res.end(); }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    fs.createReadStream(file).pipe(res);
  });
}
function clientIp(req) { return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || ''; }
function csvCell(v) { const s = String(v == null ? '' : v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; }
function parseCsvLine(line) {
  const out = []; let cur = '', q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') q = false; else cur += c; }
    else if (c === '"') q = true; else if (c === ',') { out.push(cur); cur = ''; } else cur += c;
  }
  out.push(cur); return out.map((s) => s.trim());
}

function demoDevices() {
  const D = [
    { k: 'isp1', name: 'Internet Uplink (Cloudflare DNS)', ip: '1.1.1.1', type: 'isp', vendor: 'ISP', model: 'Public DNS / Internet', location: 'WAN', critical: true, linkLabel: 'WAN' },
    { k: 'isp2', name: 'Backup Uplink (Google DNS)', ip: '8.8.8.8', type: 'isp', vendor: 'ISP', model: 'Public DNS / Internet', location: 'WAN', linkLabel: 'WAN' },
    { k: 'fw', p: 'isp1', name: 'FortiGate 100F', ip: '127.0.0.1', type: 'firewall', vendor: 'Fortinet', model: 'FortiGate 100F', location: 'Data Center', critical: true, vlan: '1', linkLabel: 'Fiber 10Gbps' },
    { k: 'core', p: 'fw', name: 'Cisco Catalyst 9300-24T (Core)', ip: 'localhost', type: 'core', vendor: 'Cisco', model: 'Catalyst 9300-24T', location: 'Data Center', critical: true, vlan: '1', linkLabel: 'Fiber 10Gbps' },
    { k: 'his', p: 'core', name: 'HIS Database (ตัวอย่างตรวจพอร์ต TCP)', ip: '127.0.0.1', method: 'tcp', port: PORT, type: 'database', vendor: 'Server', model: 'MySQL / HOSxP', location: 'Data Center', critical: true, vlan: '250', linkLabel: 'Fiber 10Gbps' },
    { k: 'sw1', p: 'core', name: 'Aruba 1930 24G (OPD)', ip: '10.255.255.11', type: 'switch', vendor: 'Aruba', model: 'Aruba 1930 24G 4SFP/SFP+', location: 'อาคารผู้ป่วยนอก ชั้น 1', vlan: '31', linkLabel: 'Fiber 10Gbps' },
    { k: 'sw2', p: 'core', name: 'Aruba 1930 24G (ER)', ip: '10.255.255.12', type: 'switch', vendor: 'Aruba', model: 'Aruba 1930 24G 4SFP/SFP+', location: 'อาคารอุบัติเหตุฉุกเฉิน', vlan: '24', linkLabel: 'Fiber 10Gbps' },
    { k: 'ap1', p: 'sw1', name: 'Wi-Fi 6 AP (OPD)', ip: '10.255.255.21', type: 'ap', vendor: 'Cisco', model: 'Catalyst 9120AX', location: 'โถง OPD', vlan: '51' },
    { k: 'pc1', p: 'sw1', name: 'PC ห้องตรวจแพทย์ 1', ip: '10.255.255.31', type: 'client', vendor: 'HP', model: 'ProDesk 400 G9', location: 'OPD ห้องตรวจ 1', vlan: '31' },
    { k: 'cam1', p: 'sw2', name: 'CCTV ทางเข้า ER', ip: '10.255.255.41', type: 'camera', vendor: 'Hikvision', model: 'DS-2CD2186G2-I', location: 'ทางเข้าอุบัติเหตุ', vlan: '24' },
    { k: 'mon1', p: 'sw2', name: 'Bedside Monitor ICU 1', ip: '10.255.255.51', type: 'medical', vendor: 'Mindray', model: 'BeneVision N19', location: 'ICU เตียง 1', vlan: '30' },
  ];
  const map = {}; let added = 0;
  for (const x of D) {
    const exists = db.devices.find((d) => d.ip === x.ip && d.name === x.name);
    if (exists) { map[x.k] = exists.id; continue; }
    let d;
    try { d = validDevice({ ...x, parentId: x.p ? map[x.p] : null, enabled: true }, null); }
    catch {
      const dup = db.devices.find((y) => y.ip === x.ip && y.method === (x.method || 'icmp') && y.port === (x.port || null));
      if (dup) map[x.k] = dup.id;
      continue;
    }
    d.id = ++db.seq.device; d.created = Date.now(); d.code = d.code || `DEV-${String(d.id).padStart(3, '0')}`;
    db.devices.push(d); map[x.k] = d.id; added++;
  }
  return added;
}

async function handleApi(req, res, url) {
  const p = url.pathname, m = req.method;
  if (m !== 'GET' && m !== 'HEAD') {
    const ct = req.headers['content-type'] || '';
    if (!ct.includes('application/json')) throw bad('ต้องส่งข้อมูลแบบ application/json');
  }

  if (p === '/api/login' && m === 'POST') {
    const b = await readBody(req);
    const key = clientIp(req) + '|' + str(b.username).toLowerCase();
    const f = failures.get(key);
    if (f && f.until > Date.now()) throw new HttpError(429, `เข้าสู่ระบบผิดหลายครั้ง กรุณารอ ${Math.ceil((f.until - Date.now()) / 60000)} นาที`);
    const u = db.users.find((x) => x.username.toLowerCase() === str(b.username).toLowerCase());
    if (!u || !checkPw(b.password || '', u.pass)) {
      const n = (f && f.until <= Date.now() && f.count >= 5 ? 0 : (f ? f.count : 0)) + 1;
      failures.set(key, { count: n, until: n >= 5 ? Date.now() + 5 * 60000 : 0 });
      throw new HttpError(401, 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
    }
    failures.delete(key);
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { uid: u.id, exp: Date.now() + (b.remember ? 7 * 24 * 3600 * 1000 : SESSION_TTL) });
    u.lastLogin = Date.now(); save();
    setCookie(req, res, token, b.remember ? 7 * 24 * 3600 : SESSION_TTL / 1000);
    return send(res, 200, { user: publicUser(u) });
  }

  const auth = getUser(req);
  if (!auth) throw new HttpError(401, 'กรุณาเข้าสู่ระบบ');
  const user = auth.u;

  if (p === '/api/logout' && m === 'POST') { sessions.delete(auth.token); setCookie(req, res, '', 0); return send(res, 200, { ok: true }); }
  if (p === '/api/me' && m === 'GET') return send(res, 200, { user: publicUser(user) });
  if (p === '/api/me/password' && m === 'POST') {
    const b = await readBody(req);
    if (!checkPw(b.current || '', user.pass)) throw bad('รหัสผ่านปัจจุบันไม่ถูกต้อง');
    if (String(b.newPassword || '').length < 8) throw bad('รหัสผ่านใหม่ต้องมีอย่างน้อย 8 ตัวอักษร');
    user.pass = hashPw(b.newPassword); user.mustChange = false; save();
    for (const [t, s] of sessions) if (s.uid === user.id && t !== auth.token) sessions.delete(t);
    return send(res, 200, { ok: true });
  }
  if (p === '/api/state' && m === 'GET') return send(res, 200, stateView());
  if (p === '/api/events' && m === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    res.write(`event: state\ndata: ${JSON.stringify(stateView())}\n\n`);
    const c = { res, uid: user.id };
    clients.add(c);
    req.on('close', () => clients.delete(c));
    return;
  }

  // ---------- devices
  if (p === '/api/devices' && m === 'POST') {
    need(user, 'operator');
    const d = validDevice(await readBody(req), null);
    d.id = ++db.seq.device; d.created = Date.now();
    if (!d.code) d.code = `DEV-${String(d.id).padStart(3, '0')}`;
    db.devices.push(d); save();
    checkDevice(d).then(broadcast);
    return send(res, 201, { device: devView(d) });
  }
  if (p === '/api/devices/bulk' && m === 'POST') {
    need(user, 'operator');
    const b = await readBody(req);
    const lines = String(b.text || '').split(/\r?\n/);
    const added = [], errors = [];
    lines.forEach((line, i) => {
      if (!line.trim() || line.trim().startsWith('#')) return;
      const c = parseCsvLine(line);
      if (i === 0 && /^name$/i.test(c[0])) return;
      try {
        const parentRef = c[7] || '';
        const parent = parentRef ? db.devices.find((x) => x.name === parentRef || x.ip === parentRef) : null;
        if (parentRef && !parent) throw bad(`ไม่พบ Uplink "${parentRef}"`);
        const port = c[8] ? parseInt(c[8], 10) : null;
        const d = validDevice({ name: c[0], ip: c[1], type: (c[2] || 'other').toLowerCase(), vendor: c[3], model: c[4], location: c[5],
          vlan: c[6], parentId: parent ? parent.id : null, method: port ? 'tcp' : 'icmp', port }, null);
        d.id = ++db.seq.device; d.created = Date.now(); d.code = `DEV-${String(d.id).padStart(3, '0')}`;
        db.devices.push(d); added.push(d);
      } catch (e) { errors.push({ line: i + 1, error: e.message }); }
    });
    save();
    pool(added, 32, checkDevice).then(broadcast);
    return send(res, 200, { added: added.length, errors });
  }
  if (p === '/api/devices/demo' && m === 'POST') {
    need(user, 'operator');
    const n = demoDevices(); save(); runCycle();
    return send(res, 200, { added: n });
  }
  if (p === '/api/devices/positions' && m === 'DELETE') {
    need(user, 'operator');
    db.devices.forEach((d) => { delete d.x; delete d.y; }); save(); broadcast();
    return send(res, 200, { ok: true });
  }
  if (p === '/api/check-all' && m === 'POST') { need(user, 'operator'); await runCycle(); return send(res, 200, { ok: true, cycle }); }

  let mm = p.match(/^\/api\/devices\/(\d+)(?:\/(check|position))?$/);
  if (mm) {
    const d = db.devices.find((x) => x.id === +mm[1]);
    if (!d) throw new HttpError(404, 'ไม่พบอุปกรณ์');
    if (!mm[2] && m === 'GET') return send(res, 200, { device: devView(d) });
    if (!mm[2] && m === 'PUT') {
      need(user, 'operator');
      const nd = validDevice(await readBody(req), d);
      const methodChanged = nd.ip !== d.ip || nd.method !== d.method || nd.port !== d.port;
      Object.assign(d, nd, { updated: Date.now() });
      if (methodChanged) { const r = getRt(d.id); r.history = []; r.fails = 0; }
      save(); await checkDevice(d); broadcast();
      return send(res, 200, { device: devView(d) });
    }
    if (!mm[2] && m === 'DELETE') {
      need(user, 'operator');
      db.devices = db.devices.filter((x) => x.id !== d.id);
      db.devices.forEach((x) => { if (x.parentId === d.id) x.parentId = d.parentId || null; });
      resolveAlerts(d); rt.delete(d.id); save(); broadcast();
      return send(res, 200, { ok: true });
    }
    if (mm[2] === 'check' && m === 'POST') { need(user, 'viewer'); await checkDevice(d); broadcast(); flushNotify(); return send(res, 200, { device: devView(d) }); }
    if (mm[2] === 'position' && m === 'PUT') {
      need(user, 'operator');
      const b = await readBody(req);
      if (Number.isFinite(b.x) && Number.isFinite(b.y)) { d.x = Math.round(b.x); d.y = Math.round(b.y); save(); }
      return send(res, 200, { ok: true });
    }
  }

  if (p === '/api/export.csv' && m === 'GET') {
    const head = 'name,ip,type,vendor,model,location,vlan,uplink,tcp_port';
    const rows = db.devices.map((d) => {
      const par = db.devices.find((x) => x.id === d.parentId);
      return [d.name, d.ip, d.type, d.vendor, d.model, d.location, d.vlan, par ? par.name : '', d.method === 'tcp' ? d.port : ''].map(csvCell).join(',');
    });
    res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="devices.csv"' });
    return res.end('﻿' + [head, ...rows].join('\n'));
  }

  // ---------- alerts
  mm = p.match(/^\/api\/alerts\/(\d+)\/(ack|resolve)$/);
  if (mm && m === 'POST') {
    need(user, 'operator');
    const a = db.alerts.find((x) => x.id === +mm[1]);
    if (!a) throw new HttpError(404, 'ไม่พบการแจ้งเตือน');
    if (mm[2] === 'ack') { a.status = a.status === 'resolved' ? a.status : 'acknowledged'; a.ackBy = user.username; }
    else { a.status = 'resolved'; a.resolvedAt = Date.now(); a.ackBy = a.ackBy || user.username; }
    save(); broadcast(); return send(res, 200, { ok: true });
  }
  if (p === '/api/alerts/clear-resolved' && m === 'POST') {
    need(user, 'operator');
    db.alerts = db.alerts.filter((a) => a.status !== 'resolved'); save(); broadcast();
    return send(res, 200, { ok: true });
  }

  // ---------- settings
  if (p === '/api/settings' && m === 'PUT') {
    need(user, 'admin');
    const b = await readBody(req), s = db.settings;
    const num = (v, lo, hi, def) => { const n = Number(v); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : def; };
    s.intervalSec = Math.round(num(b.intervalSec, 3, 3600, s.intervalSec));
    s.timeoutMs = Math.round(num(b.timeoutMs, 200, 10000, s.timeoutMs));
    s.warnMs = Math.round(num(b.warnMs, 1, 10000, s.warnMs));
    s.slaTarget = num(b.slaTarget, 50, 100, s.slaTarget);
    if (b.siteName != null) s.siteName = str(b.siteName, 100);
    save(); schedule(); broadcast();
    return send(res, 200, { settings: s });
  }

  // ---------- external notification
  if (p === '/api/notify' && m === 'GET') { need(user, 'admin'); return send(res, 200, notifyView()); }
  if (p === '/api/notify' && m === 'PUT') {
    need(user, 'admin');
    const b = await readBody(req), N = db.notify;
    const chans = (Array.isArray(b.channels) ? b.channels : []).slice(0, 20).map((c) => validChannel(c, c.enabled !== false));
    const url = str(b.publicUrl, 300);
    if (url && !/^https?:\/\/[^\s]+$/i.test(url)) throw bad('ลิงก์ระบบ NOC ต้องขึ้นต้นด้วย http:// หรือ https://');
    Object.assign(N, { enabled: !!b.enabled, onDown: !!b.onDown, onRecover: !!b.onRecover, onWarning: !!b.onWarning,
      criticalOnly: !!b.criticalOnly, suppressChildren: !!b.suppressChildren,
      repeatMin: Math.min(1440, Math.max(0, parseInt(b.repeatMin, 10) || 0)), publicUrl: url, channels: chans });
    save();
    return send(res, 200, notifyView());
  }
  if (p === '/api/notify/test' && m === 'POST') {
    need(user, 'admin');
    const b = await readBody(req);
    const ch = validChannel(b.channel || {}, true);
    const sample = db.devices.find((d) => d.critical) || db.devices[0]
      || { name: 'อุปกรณ์ทดสอบ', ip: '10.0.0.1', method: 'icmp', location: 'ห้อง Server', id: 0 };
    const msg = buildMessage('test', [{ d: sample, e: { info: `ส่งโดย ${user.username} — หากเห็นข้อความนี้แสดงว่าตั้งค่าถูกต้อง` } }]);
    const r = await sendChannel(ch, msg);
    return send(res, 200, { result: r });
  }

  // ---------- users
  if (p === '/api/users' && m === 'GET') { need(user, 'admin'); return send(res, 200, { users: db.users.map(publicUser) }); }
  if (p === '/api/users' && m === 'POST') {
    need(user, 'admin');
    const b = await readBody(req);
    const username = str(b.username, 40);
    if (!/^[a-zA-Z0-9._-]{3,40}$/.test(username)) throw bad('ชื่อผู้ใช้ต้องเป็น a-z, 0-9, . _ - อย่างน้อย 3 ตัว');
    if (db.users.find((x) => x.username.toLowerCase() === username.toLowerCase())) throw bad('ชื่อผู้ใช้นี้มีอยู่แล้ว');
    if (String(b.password || '').length < 8) throw bad('รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร');
    const u = { id: ++db.seq.user, username, name: str(b.name, 80) || username, role: ROLE_RANK[b.role] ? b.role : 'viewer',
      pass: hashPw(b.password), mustChange: !!b.mustChange, created: Date.now() };
    db.users.push(u); save();
    return send(res, 201, { user: publicUser(u) });
  }
  mm = p.match(/^\/api\/users\/(\d+)$/);
  if (mm) {
    need(user, 'admin');
    const u = db.users.find((x) => x.id === +mm[1]);
    if (!u) throw new HttpError(404, 'ไม่พบผู้ใช้');
    const admins = db.users.filter((x) => x.role === 'admin');
    if (m === 'DELETE') {
      if (u.id === user.id) throw bad('ไม่สามารถลบบัญชีของตนเองได้');
      if (u.role === 'admin' && admins.length <= 1) throw bad('ต้องมีผู้ดูแลระบบอย่างน้อย 1 คน');
      db.users = db.users.filter((x) => x.id !== u.id);
      for (const [t, s] of sessions) if (s.uid === u.id) sessions.delete(t);
      save(); return send(res, 200, { ok: true });
    }
    if (m === 'PUT') {
      const b = await readBody(req);
      if (b.role && ROLE_RANK[b.role]) {
        if (u.role === 'admin' && b.role !== 'admin' && admins.length <= 1) throw bad('ต้องมีผู้ดูแลระบบอย่างน้อย 1 คน');
        u.role = b.role;
      }
      if (b.name != null) u.name = str(b.name, 80) || u.username;
      if (b.password) {
        if (String(b.password).length < 8) throw bad('รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร');
        u.pass = hashPw(b.password); u.mustChange = true;
        for (const [t, s] of sessions) if (s.uid === u.id) sessions.delete(t);
      }
      save(); return send(res, 200, { user: publicUser(u) });
    }
  }
  throw new HttpError(404, 'ไม่พบ API');
}

const server = http.createServer(async (req, res) => {
  secHeaders(res);
  const url = new URL(req.url, 'http://x');
  try {
    if (url.pathname.startsWith('/api/')) await handleApi(req, res, url);
    else if (req.method === 'GET' || req.method === 'HEAD') serveStatic(req, res, url.pathname);
    else { res.writeHead(405); res.end(); }
  } catch (e) {
    if (!e.status) console.error(e);
    send(res, e.status || 500, { error: e.status ? e.message : 'เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์' });
  }
});

loadDB();
if (process.env.SEED_DEMO === '1' && !db.devices.length) { demoDevices(); saveNow(); }
server.listen(PORT, HOST, () => {
  console.log(`SMART TOPOLOGY NOC พร้อมใช้งานที่ http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  runCycle(); schedule();
});
process.on('SIGINT', () => { saveNow(); process.exit(0); });
process.on('SIGTERM', () => { saveNow(); process.exit(0); });
