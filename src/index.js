import {
  Client,
  GatewayIntentBits,
  Events,
  REST,
  Routes,
  MessageFlags
} from 'discord.js';
import { config, SESSION_TTL } from './config.js';
import { commands, handleCommand } from './commands.js';
import { createRouter } from './routes.js';
import { store, save, gcSessions, trimVerifications } from './store.js';
import { rand } from './util.js';

const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers]
});

client.once(Events.ClientReady, async () => {
  console.log(`[ready] ${client.user.tag} / ${config.baseUrl}`);

  const rest = new REST({ version: '10' }).setToken(config.token);
  const body = commands.map((c) => c.toJSON());
  try {
    if (config.guildId) {
      await rest.put(Routes.applicationGuildCommands(config.clientId, config.guildId), { body });
    } else {
      await rest.put(Routes.applicationCommands(config.clientId), { body });
    }
    console.log('[commands] registered');
  } catch (e) {
    console.error('[commands] registration failed', e);
  }
});

client.on(Events.InteractionCreate, async (i) => {
  try {
    if (i.isChatInputCommand()) return await handleCommand(i);

    if (i.isButton() && i.customId.startsWith('vp:')) {
      const panelId = i.customId.slice(3);
      const panel = store.panels[panelId];
      if (!panel) {
        return i.reply({ content: 'このパネルは無効です', flags: MessageFlags.Ephemeral });
      }

      if (panel.externalUrl) {
        return i.reply({
          content: `ここから認証してください（15分以内）\n${panel.externalUrl}`,
          flags: MessageFlags.Ephemeral
        });
      }

      const token = rand(24);
      store.sessions[token] = {
        id: token,
        panelId,
        guildId: panel.guildId,
        userId: i.user.id,
        interactionToken: i.token,
        external: false,
        createdAt: Date.now(),
        expiresAt: Date.now() + SESSION_TTL,
        used: false
      };
      save();

      return i.reply({
        content: `下のリンクから認証してください（15分有効）\n${config.baseUrl}/v/${token}`,
        flags: MessageFlags.Ephemeral
      });
    }
  } catch (e) {
    console.error(e);
    if (i.isRepliable() && !i.replied && !i.deferred) {
      i.reply({ content: 'エラーが発生しました', flags: MessageFlags.Ephemeral }).catch(() => {});
    }
  }
});

process.on('unhandledRejection', (e) => console.error('[unhandledRejection]', e));
process.on('SIGTERM', () => {
  console.log('[shutdown]');
  client.destroy();
  process.exit(0);
});

setInterval(gcSessions, 5 * 60 * 1000).unref();
setInterval(trimVerifications, 60 * 60 * 1000).unref();

const app = createRouter(client);
app.listen(config.port, config.host, () => {
  console.log(`[http] http://${config.host}:${config.port} -> ${config.callbackUrl}`);
});

client.login(config.token);