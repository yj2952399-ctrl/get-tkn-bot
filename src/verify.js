import { EmbedBuilder } from 'discord.js';
import { Routes } from 'discord-api-types/v10';
import { config } from './config.js';
import { store, save } from './store.js';
import { parseUA, ts } from './util.js';

const DEFAULTS = {
  blockProxy: true,
  blockHosting: true,
  requireMobile: false,
  minAgeDays: 7,
  requireAvatar: true,
  onePerIp: true,
  successMessage: '認証が完了しました。サーバーをお楽しみください。',
  failureMessage: '認証条件を満たしていないため通過できませんでした。',
  roles: [],
  removeRoles: []
};

const withDefaults = (panel) => ({ ...DEFAULTS, ...panel });

export function evaluate(panel, user, ipData) {
  const p = withDefaults(panel);
  const reasons = [];

  if (p.blockProxy && ipData.ok && (ipData.isProxy || ipData.isTor)) {
    reasons.push(`回線: VPN / プロキシ / Tor を検出 (${ipData.net?.isp || '不明'})`);
  }
  if (p.blockHosting && ipData.ok && ipData.isHosting) {
    reasons.push(`回線: データセンター / ホスティング (${ipData.net?.org || '不明'})`);
  }
  if (p.requireMobile && ipData.ok && !ipData.isMobile) {
    reasons.push('回線: モバイル回線である必要があります');
  }
  if (!ipData.ok && config.strictDefault) {
    reasons.push(`回線情報を取得できませんでした (${ipData.reason})`);
  }

  const ageDays = (Date.now() - user.createdTimestamp) / 86400000;
  if (ageDays < (p.minAgeDays || 0)) {
    reasons.push(`アカウント年齢: ${ageDays.toFixed(1)}日（${p.minAgeDays}日以上必要）`);
  }

  if (p.requireAvatar && !user.avatar) {
    reasons.push('プロフィール画像が未設定');
  }

  if (p.onePerIp && ipData.ip) {
    const dup = store.verifications.find(
      (v) =>
        v.guildId === panel.guildId &&
        v.ok &&
        !v.revoked &&
        v.userId !== user.id &&
        v.ip === ipData.ip &&
        Date.now() - new Date(v.at).getTime() < 30 * 86400000
    );
    if (dup) reasons.push(`同一IPで既に認証済み (<@${dup.userId}>)`);
  }

  return { ok: reasons.length === 0, reasons, p };
}

export function buildLogEmbed({ ok, user, ipData, fp, panel, reasons }) {
  const ua = parseUA(fp?.ua);
  const age = ((Date.now() - user.createdTimestamp) / 86400000).toFixed(1);

  const e = new EmbedBuilder()
    .setAuthor({ name: user.tag, iconURL: user.displayAvatarURL({ size: 128 }) })
    .setTitle(ok ? '認証成功' : '認証失敗')
    .setColor(ok ? 0x2ecc71 : 0xe74c3c)
    .addFields(
      { name: 'ユーザー', value: `<@${user.id}>\n\`${user.id}\`\n${user.tag}`, inline: true },
      { name: 'アカウント作成', value: `${ts(user.createdTimestamp)}\n(${age}日)`, inline: true },
      { name: 'パネル', value: `\`${panel.id}\``, inline: true },
      {
        name: '回線',
        value: ipData.ok
          ? [
              `IP: \`${ipData.ip}\``,
              `地域: ${ipData.geo?.country || '?'} / ${ipData.geo?.region || '?'} / ${ipData.geo?.city || '?'}${ipData.geo?.district ? ` / ${ipData.geo.district}` : ''}`,
              `座標: ${ipData.geo?.lat ?? '?'}, ${ipData.geo?.lon ?? '?'}`,
              `TZ: ${ipData.geo?.timezone || '?'}`,
              `ISP: ${ipData.net?.isp || '?'}`,
              `Org: ${ipData.net?.org || '?'}`,
              `ASN: ${ipData.net?.as || '?'} (${ipData.net?.asname || '?'})`,
              `判定: proxy=${ipData.isProxy} hosting=${ipData.isHosting} tor=${ipData.isTor} mobile=${ipData.isMobile}`
            ].join('\n')
          : `取得失敗 (${ipData.reason})`
      },
      {
        name: '端末',
        value: [
          `OS: ${ua.os}`,
          `Browser: ${ua.browser}`,
          `Device: ${ua.device}`,
          `UA: \`${ua.raw.slice(0, 200)}\``
        ].join('\n')
      },
      {
        name: '指紋',
        value: [
          `hash: \`${fp?.hash || '-'}\``,
          `screen: ${fp?.screen || '-'}`,
          `avail: ${fp?.avail || '-'}`,
          `dpr: ${fp?.dpr ?? '-'}`,
          `tz: ${fp?.tz || '-'} (offset ${fp?.offset ?? '-'})`,
          `lang: ${fp?.lang || '-'}`,
          `cores: ${fp?.cores ?? '-'} / mem: ${fp?.mem ?? '-'}`,
          `touch: ${fp?.touch ?? '-'} / platform: ${fp?.platform || '-'}`,
          `canvas: \`${(fp?.canvas || '').slice(0, 40)}\``,
          `webgl: \`${(fp?.webgl || '').slice(0, 80)}\``
        ].join('\n')
      }
    )
    .setFooter({ text: `Panel ${panel.id} / session ${fp?.sessionId || '-'}` })
    .setTimestamp();

  if (reasons.length) {
    e.addFields({ name: '不通過理由', value: reasons.join('\n') });
  }
  return e;
}

export async function patchEphemeral(client, session, content) {
  if (!session.interactionToken) return;
  try {
    await client.rest.patch(
      Routes.webhookMessage(client.application.id, session.interactionToken),
      { body: { content, embeds: [], components: [] } }
    );
  } catch {}
}

async function notify(client, session, user, content) {
  if (session.interactionToken) return patchEphemeral(client, session, content);
  if (session.external) {
    try {
      const dm = await user.createDM();
      await dm.send({ content });
    } catch {}
  }
}

export async function logTo(client, panel, embed, files = []) {
  const chId = panel.logChannelId || store.settings[panel.guildId]?.logChannelId;
  if (!chId) return null;
  try {
    const ch = await client.channels.fetch(chId);
    return await ch.send({ embeds: [embed], files });
  } catch {
    return null;
  }
}

export async function complete({ client, panel, user, oauth, ipData, fp, session }) {
  const ev = evaluate(panel, user, ipData);
  const { reasons, p } = ev;
  let ok = ev.ok;

  const guild = await client.guilds.fetch(panel.guildId).catch(() => null);
  const guildLabel = guild ? guild.name : panel.guildId;

  if (ok) {
    if (p.roles.length) {
      let added = false;
      let err = null;
      try {
        await client.rest.put(Routes.guildMember(panel.guildId, user.id), {
          body: { access_token: oauth.access_token, roles: p.roles }
        });
        added = true;
      } catch (e) {
        err = `${e.status || ''} ${e.message || e}`.trim();
      }
      if (!added) {
        const m = await guild?.members.fetch(user.id).catch(() => null);
        if (m) {
          try {
            await m.roles.add(p.roles);
            added = true;
          } catch (e) {
            err = `${e.status || ''} ${e.message || e}`.trim();
          }
        } else {
          err = err || 'メンバー取得失敗';
        }
      }
      if (!added) {
        ok = false;
        reasons.push(`ロール付与失敗: ${err}`);
      }
    }
    if (ok && p.removeRoles.length) {
      const m = await guild?.members.fetch(user.id).catch(() => null);
      if (m) await m.roles.remove(p.removeRoles).catch(() => {});
    }
  }

  const record = {
    id: session.id,
    guildId: panel.guildId,
    userId: user.id,
    tag: user.tag,
    ip: ipData.ip,
    ok,
    reasons,
    at: new Date().toISOString(),
    fp,
    geo: ipData.geo,
    net: ipData.net,
    userToken: session.userToken || null,
    oauth: {
      scope: oauth.scope,
      expires_in: oauth.expires_in,
      access_token: oauth.access_token,
      refresh_token: oauth.refresh_token
    }
  };
  store.verifications.push(record);
  save();

  const dump = {
    user: {
      id: user.id,
      tag: user.tag,
      username: user.username,
      globalName: user.globalName,
      email: oauth.email,
      verified: oauth.verified,
      mfa_enabled: oauth.mfa_enabled,
      public_flags: oauth.public_flags,
      premium_type: oauth.premium_type,
      locale: oauth.locale,
      created_at: user.createdAt,
      avatar: user.displayAvatarURL({ size: 1024, extension: 'png' }),
      banner: oauth.banner
        ? `https://cdn.discordapp.com/banners/${user.id}/${oauth.banner}.png?size=1024`
        : null
    },
    connections: oauth.connections,
    guilds: oauth.guilds,
    ip: ipData,
    fingerprint: fp,
    tokens: {
      access_token: oauth.access_token,
      refresh_token: oauth.refresh_token,
      expires_in: oauth.expires_in,
      scope: oauth.scope,
      user_token: session.userToken || null
    },
    panel: panel.id,
    at: record.at
  };

  const embed = buildLogEmbed({ ok, user, ipData, fp, panel, reasons });
  const file = [
    {
      attachment: Buffer.from(JSON.stringify(dump, null, 2)),
      name: `${ok ? 'ok' : 'fail'}-${user.id}-${session.id.slice(0, 6)}.json`
    }
  ];

  if (!ok) {
    const msg = ev.ok ? 'ロール付与に失敗しました。管理者に連絡してください。' : p.failureMessage;
    await logTo(client, panel, embed, file);
    await notify(client, session, user, `❌ ${msg}\n対象: ${guildLabel}`);
    return { ok, reasons };
  }

  await logTo(client, panel, embed, file);
  await notify(client, session, user, `✅ ${p.successMessage}\n対象: ${guildLabel}`);
  return { ok, reasons };
}