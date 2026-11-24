# discord-verify

Discord 認証ボット。https://cloud.m-ws.cc で稼働させる前提の自前ホスト構成。

## 必要要件

- VPS（Ubuntu 22.04 以上推奨）
- ドメイン `cloud.m-ws.cc` の A レコード → VPS
- Docker / Docker Compose
- Discord アプリ（Bot + OAuth2）

## セットアップ

### 1. Discord アプリ

1. https://discord.com/developers/applications でアプリ作成
2. OAuth2 → Redirects に完全一致で登録
   `https://cloud.m-ws.cc/oauth/callback`
3. Bot → Token 取得、Server Members Intent を ON
4. 招待 URL は scopes `bot` + `applications.commands`、権限は
   Manage Roles / Create Instant Invite / Send Messages / Embed Links / Read Message History
5. Bot のロールを付与対象ロールより上に配置

### 2. サーバー

```bash
git clone <repo> /opt/discord-verify
cd /opt/discord-verify
cp .env.example .env
openssl rand -base64 48   # SESSION_SECRET
nano .env
chmod +x deploy.sh
./deploy.sh