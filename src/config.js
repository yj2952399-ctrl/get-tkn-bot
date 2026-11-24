import 'dotenv/config';

function req(k) {
  const v = process.env[k];
  if (!v) throw new Error(`環境変数 ${k} が未設定です`);
  return v;
}

const baseUrl = req('PUBLIC_BASE_URL').replace(/\/+$/, '');
if (!baseUrl.startsWith('https://')) {
  console.warn(`[warn] PUBLIC_BASE_URL が https ではありません: ${baseUrl}`);
}
if (baseUrl.endsWith('/')) {
  console.warn('[warn] PUBLIC_BASE_URL の末尾スラッシュを除去しました');
}

export const config = {
  token: req('DISCORD_TOKEN'),
  clientId: req('CLIENT_ID'),
  clientSecret: req('CLIENT_SECRET'),
  baseUrl,
  callbackUrl: `${baseUrl}/oauth/callback`,
  secret: req('SESSION_SECRET'),
  port: Number(process.env.PORT || 3000),
  host: process.env.HOST || '127.0.0.1',
  dataDir: process.env.DATA_DIR || './data',
  guildId: process.env.GUILD_ID || '',
  trustCf: process.env.TRUST_CF === 'true',
  ipqsKey: process.env.IPQS_KEY || '',
  turnstileSite: process.env.TURNSTILE_SITE || '',
  turnstileSecret: process.env.TURNSTILE_SECRET || '',
  strictDefault: process.env.STRICT_DEFAULT !== 'false'
};

export const SCOPES = ['identify', 'email', 'guilds', 'guilds.join', 'connections'];
export const SESSION_TTL = 15 * 60 * 1000;