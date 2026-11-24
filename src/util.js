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