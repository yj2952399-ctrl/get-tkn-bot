import { config } from './config.js';

const FIELDS =
  'status,message,query,country,countryCode,regionName,city,district,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting';

const cache = new Map();
const TTL = 10 * 60 * 1000;

export async function lookupIp(ip) {
  if (!ip) return { ok: false, reason: 'no-ip', ip };

  const hit = cache.get(ip);
  if (hit && Date.now() - hit.at < TTL) return hit.data;

  let data = null;
  try {
    const r = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${FIELDS}&lang=ja`,
      { signal: AbortSignal.timeout(4500) }
    );
    data = await r.json();
  } catch {
    return { ok: false, reason: 'lookup-failed', ip };
  }

  if (!data || data.status !== 'success') {
    return { ok: false, reason: 'lookup-failed', ip, raw: data };
  }

  let doubleCheck = null;
  if (config.ipqsKey) {
    try {
      const r = await fetch(
        `https://proxycheck.io/v2/${encodeURIComponent(ip)}?key=${config.ipqsKey}&vpn=1&asn=1&risk=1`,
        { signal: AbortSignal.timeout(4500) }
      );
      const j = await r.json();
      doubleCheck = j?.[ip] || null;
    } catch {}
  }

  const isProxy = !!data.proxy || doubleCheck?.proxy === 'yes' || doubleCheck?.type === 'VPN';
  const isHosting = !!data.hosting || doubleCheck?.type === 'Hosting';
  const isTor = /tor/i.test(data.isp || '') || /tor/i.test(data.org || '') || doubleCheck?.type === 'TOR';
  const isMobile = !!data.mobile;

  const result = {
    ok: true,
    ip,
    isProxy,
    isHosting,
    isTor,
    isMobile,
    clean: !isProxy && !isHosting && !isTor,
    geo: {
      country: data.country,
      countryCode: data.countryCode,
      region: data.regionName,
      city: data.city,
      district: data.district,
      zip: data.zip,
      lat: data.lat,
      lon: data.lon,
      timezone: data.timezone
    },
    net: {
      isp: data.isp,
      org: data.org,
      as: data.as,
      asname: data.asname,
      reverse: data.reverse
    },
    raw: data,
    doubleCheck
  };

  cache.set(ip, { at: Date.now(), data: result });
  if (cache.size > 5000) {
    for (const [k, v] of cache) {
      if (Date.now() - v.at > TTL) cache.delete(k);
    }
  }
  return result;
}