import { config, SCOPES } from './config.js';

export function authorizeUrl(state) {
  const p = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.callbackUrl,
    response_type: 'code',
    scope: SCOPES.join(' '),
    state,
    prompt: 'consent'
  });
  return `https://discord.com/oauth2/authorize?${p}`;
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

export async function apiWith(token, path, bearer = true) {
  const r = await fetch(`https://discord.com/api/v10${path}`, {
    headers: { authorization: (bearer ? 'Bearer ' : '') + token }
  });
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
  return r.json();
}