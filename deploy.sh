#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f .env ]; then
  cp .env.example .env
  echo ".env を作成しました。DISCORD_TOKEN / CLIENT_ID / CLIENT_SECRET / SESSION_SECRET を入れて再実行してください。"
  exit 1
fi

grep -q '^PUBLIC_BASE_URL=https://cloud.m-ws.cc$' .env || {
  echo "PUBLIC_BASE_URL は https://cloud.m-ws.cc にしてください"; exit 1; }

grep -q '^SESSION_SECRET=.\+' .env || {
  echo "SESSION_SECRET が空です: openssl rand -base64 48"; exit 1; }

mkdir -p data
chmod 700 data

docker compose build
docker compose up -d --remove-orphans
docker compose ps
echo "-> https://cloud.m-ws.cc/health を確認してください"