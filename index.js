import { existsSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));

if (!existsSync(`${root}node_modules/discord.js`)) {
  console.log('[bootstrap] 依存関係をインストールします...');
  execSync('npm install --omit=dev --no-audit --no-fund', {
    cwd: root,
    stdio: 'inherit'
  });
}

await import('./src/index.js');