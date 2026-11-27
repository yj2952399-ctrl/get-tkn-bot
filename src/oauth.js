import { config, SCOPES } from './config.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function authorizeUrl(state) {
  const p = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.callbackUrl,
    response_type: 'code',
    scope: SCOPES.join(' '),
    state,
    prompt: 'consent'
  });
  return `https://discord.com/oauth2/authorize?${p.toString()}`;
}

export async function exchangeCode(code) {
  const r = await fetch('https://discord.com/api/v10/oauth2/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      grant_type: 'authorization_code',
      code,
      redirect_uri: config.callbackUrl
    })
  });
  if (!r.ok) throw new Error(`token exchange ${r.status}: ${await r.text()}`);
  return r.json();
}

/**
 * Discord API 呼び出し。429 / 5xx / ネットワーク断はリトライし、
 * 失敗時は e.status に HTTP ステータス（ネットワーク断は 0）を入れて投げる。
 */
export async function apiWith(token, path, bearer = true, { retries = 2 } = {}) {
  let last = null;

  for (let i = 0; i <= retries; i++) {
    let r;
    try {
      r = await fetch(`https://discord.com/api/v10${path}`, {
        headers: { authorization: (bearer ? 'Bearer ' : '') + token }
      });
    } catch (e) {
      const err = new Error(`network ${e?.message || e}`);
      err.status = 0;
      last = err;
      await sleep(500 * (i + 1));
      continue;
    }

    if (r.ok) return r.json();

    const body = await r.text().catch(() => '');
    const err = new Error(`${path} -> ${r.status} ${body.slice(0, 160)}`);
    err.status = r.status;
    last = err;

    if (r.status !== 429 && r.status < 500) break;

    const retryAfter = Number(r.headers.get('retry-after') || 0);
    await sleep(Math.max(retryAfter * 1000, 500 * (i + 1)));
  }

  throw last;
}