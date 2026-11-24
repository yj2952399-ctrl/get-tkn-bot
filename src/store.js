import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.js';

const FILE = path.join(config.dataDir, 'db.json');
fs.mkdirSync(config.dataDir, { recursive: true });

let loaded = {};
try {
  loaded = JSON.parse(fs.readFileSync(FILE, 'utf8'));
} catch {}

export const store = {
  panels: loaded.panels || {},
  sessions: loaded.sessions || {},
  verifications: loaded.verifications || [],
  settings: loaded.settings || {}
};

let timer = null;

export function save() {
  clearTimeout(timer);
  timer = setTimeout(() => {
    const tmp = `${FILE}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(store, null, 2));
    fs.renameSync(tmp, FILE);
  }, 250);
}

export function saveNow() {
  clearTimeout(timer);
  const tmp = `${FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(store, null, 2));
  fs.renameSync(tmp, FILE);
}

export function gcSessions() {
  const now = Date.now();
  let dirty = false;
  for (const [k, s] of Object.entries(store.sessions)) {
    if (s.expiresAt < now || s.used) {
      delete store.sessions[k];
      dirty = true;
    }
  }
  if (dirty) save();
}

export function trimVerifications(max = 50000) {
  if (store.verifications.length > max) {
    store.verifications = store.verifications.slice(-max);
    save();
  }
}