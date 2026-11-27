import crypto from 'node:crypto';
import { config } from './config.js';

export const rand = (n = 24) => crypto.randomBytes(n).toString('base64url');
export const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

export function sign(payload) {
  return crypto.createHmac('sha256', config.secret).update(payload).digest('base64url');
}

export function verifySig(payload, sig) {
  const a = Buffer.from(sign(payload));
  const b = Buffer.from(String(sig || ''));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const norm = (ip) => String(ip || '').trim().replace(/^::ffff:/, '').replace(/^\[|\]$/g, '');

export function clientIp(req) {
  if (config.trustCf) {
    const cf = req.headers['cf-connecting-ip'];
    if (cf) return norm(cf);
  }
  const xff = (req.headers['x-forwarded-for'] || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const raw = (xff.length ? xff[xff.length - 1] : '')
    || req.headers['x-real-ip']
    || req.socket.remoteAddress
    || '';
  return norm(raw);
}

export const ts = (d) => `<t:${Math.floor(new Date(d).getTime() / 1000)}:F>`;

/* --- ユーザートークンのローカル判定 -------------------------------------
   ユーザートークンは「base64url(ユーザーID).base64url(発行時刻).署名」の3分割。
   先頭をデコードすれば所有者IDが分かるので、Discord API に頼らず照合できる。
   --------------------------------------------------------------------- */

export function looksLikeToken(token) {
  const t = String(token || '').trim();
  const p = t.split('.');
  if (p.length !== 3) return false;
  if (t.length < 50 || t.length > 220) return false;
  return p.every((s) => s.length > 0 && /^[A-Za-z0-9_-]+$/.test(s));
}

export function tokenUserId(token) {
  const p = String(token || '').trim().split('.');
  if (p.length !== 3 || !p[0]) return null;
  try {
    const id = Buffer.from(p[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return /^\d{15,25}$/.test(id) ? id : null;
  } catch {
    return null;
  }
}

export function parseUA(ua = '') {
  const out = { raw: ua, browser: '?', os: '?', device: 'PC' };
  out.browser = /Edg\//.test(ua) ? 'Edge'
    : /OPR\//.test(ua) ? 'Opera'
    : /Firefox\//.test(ua) ? 'Firefox'
    : /Chrome\//.test(ua) ? 'Chrome'
    : /Safari\//.test(ua) ? 'Safari'
    : '?';
  out.os = /Windows NT/.test(ua) ? 'Windows'
    : /Android/.test(ua) ? 'Android'
    : /iPhone|iPad|iPod/.test(ua) ? 'iOS'
    : /Mac OS X/.test(ua) ? 'macOS'
    : /Linux/.test(ua) ? 'Linux'
    : '?';
  out.device = /Mobile|Android|iPhone/.test(ua) ? 'Mobile'
    : /iPad|Tablet/.test(ua) ? 'Tablet'
    : 'PC';
  return out;
}

export function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}