#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

[ -f .env ] || { cp .env.example .env; echo ".env を作成しました。編集して再実行してください。"; exit 1; }

grep -q '^PUBLIC_BASE_URL=https://cloud.m-ws.cc$' .env || {
  echo "PUBLIC_BASE_URL は https://cloud.m-ws.cc にしてください"; exit 1; }

mkdir -p data
chmod 700 data

docker compose build
docker compose up -d
docker compose ps
echo "-> https://cloud.m-ws.cc/health を確認してください"