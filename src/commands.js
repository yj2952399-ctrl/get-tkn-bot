import {
  SlashCommandBuilder,
  EmbedBuilder,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  PermissionFlagsBits,
  MessageFlags
} from 'discord.js';
import { config } from './config.js';
import { store, save } from './store.js';
import { rand } from './util.js';

/* --- オプション値の正規化 ---------------------------------------------
   環境によっては options.get() が生のオプション({name,type,value})を返すため、
   値だけを取り出して文字列/ID として扱えるようにする。
   ------------------------------------------------------------------- */
const unwrap = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v.value : v);

const text = (v) => {
  const x = unwrap(v);
  if (x == null) return undefined;
  return typeof x === 'string' ? x : String(x);
};

const idOf = (v) => {
  const x = unwrap(v);
  if (!x) return undefined;
  return typeof x === 'string' ? x : (x.id ?? undefined);
};

const toColor = (v, fallback) => {
  const s = text(v);
  if (!s) return fallback;
  const n = parseInt(s.replace(/^#/, ''), 16);
  return Number.isFinite(n) ? n : fallback;
};

function addPanelOptions(s) {
  return s
    .addChannelOption((o) =>
      o.setName('channel').setDescription('パネルを設置するチャンネル').addChannelTypes(0)
    )
    .addRoleOption((o) => o.setName('role1').setDescription('認証成功時に付与するロール'))
    .addRoleOption((o) => o.setName('role2').setDescription('追加で付与するロール'))
    .addRoleOption((o) => o.setName('role3').setDescription('追加で付与するロール'))
    .addRoleOption((o) => o.setName('remove_role').setDescription('認証成功時に外すロール（未認証ロール等）'))
    .addStringOption((o) => o.setName('title').setDescription('パネルタイトル').setMaxLength(120))
    .addStringOption((o) => o.setName('description').setDescription('説明文').setMaxLength(1500))
    .addStringOption((o) => o.setName('button_label').setDescription('ボタン名').setMaxLength(60))
    .addStringOption((o) => o.setName('color').setDescription('埋め込み色 #RRGGBB'))
    .addBooleanOption((o) => o.setName('external_mode').setDescription('外部サイトURLを自動発行してリンクボタンにする'))
    .addStringOption((o) => o.setName('external_url').setDescription('任意の外部URL（指定時はこちらを優先）'))
    .addChannelOption((o) => o.setName('log_channel').setDescription('認証ログの送信先'))
    .addIntegerOption((o) =>
      o.setName('min_age_days').setDescription('最低アカウント年齢(日)').setMinValue(0).setMaxValue(3650)
    )
    .addBooleanOption((o) => o.setName('require_avatar').setDescription('アイコン設定を必須にする'))
    .addBooleanOption((o) => o.setName('block_proxy').setDescription('VPN/プロキシ/Torを遮断'))
    .addBooleanOption((o) => o.setName('block_hosting').setDescription('データセンター回線を遮断'))
    .addBooleanOption((o) => o.setName('require_mobile').setDescription('モバイル回線のみ許可'))
    .addBooleanOption((o) => o.setName('one_per_ip').setDescription('同一IPの複数アカウントを拒否'))
    .addStringOption((o) => o.setName('success_message').setDescription('成功時メッセージ').setMaxLength(400))
    .addStringOption((o) => o.setName('failure_message').setDescription('失敗時メッセージ').setMaxLength(400));
}

export const commands = [
  new SlashCommandBuilder()
    .setName('panel')
    .setDescription('認証パネルを管理します')
    .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
    .addSubcommand((s) => addPanelOptions(s.setName('create').setDescription('パネルを作成')))
    .addSubcommand((s) =>
      addPanelOptions(
        s
          .setName('edit')
          .setDescription('パネルを編集')
          .addStringOption((o) => o.setName('id').setDescription('パネルID').setRequired(true))
      )
    )
    .addSubcommand((s) =>
      s.setName('delete').setDescription('パネルを削除')
        .addStringOption((o) => o.setName('id').setDescription('パネルID').setRequired(true))
    )
    .addSubcommand((s) => s.setName('list').setDescription('パネル一覧'))
    .addSubcommand((s) =>
      s.setName('repost').setDescription('パネルを再送信')
        .addStringOption((o) => o.setName('id').setDescription('パネルID').setRequired(true))
    ),

  new SlashCommandBuilder()
    .setName('verify')
    .setDescription('ユーザーを手動認証')
    .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
    .addUserOption((o) => o.setName('user').setDescription('対象ユーザー').setRequired(true)),

  new SlashCommandBuilder()
    .setName('unverify')
    .setDescription('認証を解除')
    .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
    .addUserOption((o) => o.setName('user').setDescription('対象ユーザー').setRequired(true)),

  new SlashCommandBuilder()
    .setName('whois')
    .setDescription('保存済み認証情報を表示')
    .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
    .addUserOption((o) => o.setName('user').setDescription('対象ユーザー').setRequired(true)),

  new SlashCommandBuilder()
    .setName('export')
    .setDescription('認証ログをJSONで出力')
    .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild),

  new SlashCommandBuilder()
    .setName('verify-url')
    .setDescription('パネルの公開認証URLを発行')
    .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
    .addStringOption((o) => o.setName('id').setDescription('パネルID').setRequired(true))
];

export function buildPanelMessage(panel) {
  const e = new EmbedBuilder()
    .setTitle(text(panel.title) || 'サーバー認証')
    .setDescription(text(panel.description) || '下のボタンから認証を完了してください。')
    .setColor(Number.isFinite(panel.color) ? panel.color : 0x5865f2);

  const reqs = [];
  if (panel.blockProxy) reqs.push('- VPN / プロキシ / Tor 不可');
  if (panel.blockHosting) reqs.push('- データセンター回線 不可');
  if (panel.requireMobile) reqs.push('- モバイル回線のみ');
  if (Number(panel.minAgeDays) > 0) reqs.push(`- アカウント作成から ${panel.minAgeDays} 日以上`);
  if (panel.requireAvatar) reqs.push('- プロフィール画像の設定');
  if (panel.onePerIp) reqs.push('- 同一IPでの複数アカウント不可');
  if (reqs.length) e.addFields({ name: '認証条件', value: reqs.join('\n') });

  if (panel.roles?.length) {
    e.addFields({ name: '付与ロール', value: panel.roles.map((r) => `<@&${r}>`).join(' ') });
  }
  if (panel.removeRoles?.length) {
    e.addFields({ name: '解除ロール', value: panel.removeRoles.map((r) => `<@&${r}>`).join(' ') });
  }

  e.setFooter({ text: `Panel ${panel.id}` });

  const label = text(panel.buttonLabel) || '認証する';
  const url = text(panel.externalUrl);

  const btn = url
    ? new ButtonBuilder()
        .setStyle(ButtonStyle.Link)
        .setLabel(label)
        .setURL(url)
    : new ButtonBuilder()
        .setStyle(ButtonStyle.Success)
        .setLabel(label)
        .setCustomId(`vp:${panel.id}`);

  return { embeds: [e], components: [new ActionRowBuilder().addComponents(btn)] };
}

function collectOptions(i, base = {}) {
  const g = (n) => i.options.get(n);

  const roles = [g('role1'), g('role2'), g('role3')].map(idOf).filter(Boolean);
  const removeRole = idOf(g('remove_role'));
  const color = text(g('color'));

  return {
    ...base,
    roles,
    removeRoles: removeRole ? [removeRole] : base.removeRoles || [],
    title: text(g('title')) ?? base.title,
    description: text(g('description')) ?? base.description,
    buttonLabel: text(g('button_label')) ?? base.buttonLabel,
    color: toColor(color, base.color),
    externalMode: unwrap(g('external_mode')) ?? base.externalMode ?? false,
    externalUrl: text(g('external_url')) ?? base.externalUrl,
    logChannelId: idOf(g('log_channel')) ?? base.logChannelId,
    minAgeDays: unwrap(g('min_age_days')) ?? base.minAgeDays ?? 7,
    requireAvatar: unwrap(g('require_avatar')) ?? base.requireAvatar ?? true,
    blockProxy: unwrap(g('block_proxy')) ?? base.blockProxy ?? true,
    blockHosting: unwrap(g('block_hosting')) ?? base.blockHosting ?? true,
    requireMobile: unwrap(g('require_mobile')) ?? base.requireMobile ?? false,
    onePerIp: unwrap(g('one_per_ip')) ?? base.onePerIp ?? true,
    successMessage: text(g('success_message')) ?? base.successMessage,
    failureMessage: text(g('failure_message')) ?? base.failureMessage
  };
}

function applyExternal(panel) {
  if (panel.externalUrl) return panel;
  if (panel.externalMode) panel.externalUrl = `${config.baseUrl}/p/${panel.id}`;
  return panel;
}

export async function handleCommand(interaction) {
  const { commandName } = interaction;

  if (commandName === 'panel') {
    const sub = interaction.options.getSubcommand();

    if (sub === 'create') {
      const channel = interaction.options.getChannel('channel') || interaction.channel;
      const id = rand(4).toLowerCase().replace(/[-_]/g, '').slice(0, 6);
      const panel = applyExternal({
        id,
        guildId: interaction.guildId,
        channelId: channel.id,
        ...collectOptions(interaction)
      });

      const msg = await channel.send(buildPanelMessage(panel));
      panel.messageId = msg.id;
      store.panels[id] = panel;
      save();

      return interaction.reply({
        content: `パネルを作成しました: \`${id}\`\n設置先: <#${channel.id}>${panel.externalUrl ? `\n公開URL: ${panel.externalUrl}` : ''}`,
        flags: MessageFlags.Ephemeral
      });
    }

    if (sub === 'edit') {
      const id = interaction.options.getString('id');
      const panel = store.panels[id];
      if (!panel || panel.guildId !== interaction.guildId) {
        return interaction.reply({ content: 'パネルが見つかりません', flags: MessageFlags.Ephemeral });
      }

      Object.assign(panel, collectOptions(interaction, panel));
      applyExternal(panel);
      save();

      try {
        const ch = await interaction.client.channels.fetch(panel.channelId);
        const msg = await ch.messages.fetch(panel.messageId);
        await msg.edit(buildPanelMessage(panel));
      } catch {}

      return interaction.reply({ content: `パネル \`${id}\` を更新しました`, flags: MessageFlags.Ephemeral });
    }

    if (sub === 'delete') {
      const id = interaction.options.getString('id');
      const panel = store.panels[id];
      if (!panel || panel.guildId !== interaction.guildId) {
        return interaction.reply({ content: 'パネルが見つかりません', flags: MessageFlags.Ephemeral });
      }
      try {
        const ch = await interaction.client.channels.fetch(panel.channelId);
        const msg = await ch.messages.fetch(panel.messageId);
        await msg.delete();
      } catch {}
      delete store.panels[id];
      save();
      return interaction.reply({ content: `パネル \`${id}\` を削除しました`, flags: MessageFlags.Ephemeral });
    }

    if (sub === 'list') {
      const list = Object.values(store.panels).filter((p) => p.guildId === interaction.guildId);
      if (!list.length) {
        return interaction.reply({ content: 'パネルはありません', flags: MessageFlags.Ephemeral });
      }
      const text2 = list
        .map((p) => `\`${p.id}\` <#${p.channelId}> roles:${p.roles?.length || 0} ext:${p.externalUrl ? 'yes' : 'no'} age:${p.minAgeDays}`)
        .join('\n');
      return interaction.reply({ content: text2, flags: MessageFlags.Ephemeral });
    }

    if (sub === 'repost') {
      const panel = store.panels[interaction.options.getString('id')];
      if (!panel || panel.guildId !== interaction.guildId) {
        return interaction.reply({ content: 'パネルが見つかりません', flags: MessageFlags.Ephemeral });
      }
      const ch = await interaction.client.channels.fetch(panel.channelId);
      const msg = await ch.send(buildPanelMessage(panel));
      panel.messageId = msg.id;
      save();
      return interaction.reply({ content: '再送信しました', flags: MessageFlags.Ephemeral });
    }
  }

  if (commandName === 'verify') {
    const user = interaction.options.getUser('user');
    const member = await interaction.guild.members.fetch(user.id).catch(() => null);
    if (!member) {
      return interaction.reply({ content: 'サーバーにいません', flags: MessageFlags.Ephemeral });
    }
    const panels = Object.values(store.panels).filter((p) => p.guildId === interaction.guildId);
    const add = [...new Set(panels.flatMap((p) => p.roles || []))];
    const remove = [...new Set(panels.flatMap((p) => p.removeRoles || []))];
    if (add.length) await member.roles.add(add).catch(() => {});
    if (remove.length) await member.roles.remove(remove).catch(() => {});

    store.verifications.push({
      id: rand(24),
      guildId: interaction.guildId,
      userId: user.id,
      tag: user.tag,
      ip: null,
      ok: true,
      manual: true,
      reasons: [`手動認証 (${interaction.user.tag})`],
      at: new Date().toISOString(),
      fp: null,
      geo: null,
      net: null,
      oauth: null
    });
    save();

    return interaction.reply({ content: `${user.tag} を認証済みにしました`, flags: MessageFlags.Ephemeral });
  }

  if (commandName === 'unverify') {
    const user = interaction.options.getUser('user');
    const member = await interaction.guild.members.fetch(user.id).catch(() => null);
    const panels = Object.values(store.panels).filter((p) => p.guildId === interaction.guildId);
    const add = [...new Set(panels.flatMap((p) => p.roles || []))];
    if (member && add.length) await member.roles.remove(add).catch(() => {});

    let n = 0;
    for (const v of store.verifications) {
      if (v.userId === user.id && v.guildId === interaction.guildId && v.ok && !v.revoked) {
        v.revoked = true;
        v.revokedAt = new Date().toISOString();
        n++;
      }
    }
    if (n) save();

    return interaction.reply({
      content: `${user.tag} の認証を解除しました（記録 ${n} 件を解除扱い）`,
      flags: MessageFlags.Ephemeral
    });
  }

  if (commandName === 'whois') {
    const user = interaction.options.getUser('user');
    const recs = store.verifications.filter(
      (v) => v.userId === user.id && v.guildId === interaction.guildId
    );
    if (!recs.length) return interaction.reply({ content: '記録がありません', flags: MessageFlags.Ephemeral });

    const r = recs[recs.length - 1];
    const e = new EmbedBuilder()
      .setTitle(user.tag)
      .setColor(r.revoked ? 0x95a5a6 : r.ok ? 0x2ecc71 : 0xe74c3c)
      .addFields(
        {
          name: '状態',
          value: r.revoked ? `解除済み (${r.revokedAt})` : r.manual ? '手動認証' : r.ok ? '有効' : '不通過',
          inline: true
        },
        { name: 'IP', value: `\`${r.ip || '-'}\``, inline: true },
        { name: '地域', value: `${r.geo?.country || '?'} / ${r.geo?.city || '?'}`, inline: true },
        { name: 'ISP', value: r.net?.isp || '-', inline: true },
        { name: '認証回数', value: String(recs.length), inline: true },
        { name: '最終試行', value: r.at, inline: true },
        { name: '不通過理由', value: r.reasons?.join('\n') || 'なし' }
      );
    return interaction.reply({ embeds: [e], flags: MessageFlags.Ephemeral });
  }

  if (commandName === 'export') {
    const data = store.verifications.filter((v) => v.guildId === interaction.guildId);
    return interaction.reply({
      content: `${data.length} 件`,
      files: [{ attachment: Buffer.from(JSON.stringify(data, null, 2)), name: 'verifications.json' }],
      flags: MessageFlags.Ephemeral
    });
  }

  if (commandName === 'verify-url') {
    const panel = store.panels[interaction.options.getString('id')];
    if (!panel || panel.guildId !== interaction.guildId) {
      return interaction.reply({ content: 'パネルが見つかりません', flags: MessageFlags.Ephemeral });
    }
    return interaction.reply({
      content: `${config.baseUrl}/p/${panel.id}`,
      flags: MessageFlags.Ephemeral
    });
  }
}