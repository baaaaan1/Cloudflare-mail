#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DEPLOY_WORKER=false
if [[ "${1:-}" == "--deploy-worker" ]]; then
  DEPLOY_WORKER=true
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: '$1' not found. Install it and re-run." >&2
    exit 1
  fi
}

require_cmd docker

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: Docker Compose plugin not found. Install Docker Compose and re-run." >&2
  exit 1
fi

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example. Please edit .env and re-run."
  exit 1
fi

docker compose up -d --build

if [[ "${DEPLOY_WORKER}" == "true" ]]; then
  CF_TOKEN="$(grep -E '^CLOUDFLARE_API_TOKEN=' .env | sed -E 's/^CLOUDFLARE_API_TOKEN=//')"
  if [[ -z "${CF_TOKEN}" ]]; then
    echo "ERROR: CLOUDFLARE_API_TOKEN missing in .env. Cannot deploy worker."
    exit 1
  fi
  echo "Deploying worker using CLOUDFLARE_API_TOKEN..."
  docker run --rm \
    -v "$ROOT_DIR/worker":/app \
    -w /app \
    -e CLOUDFLARE_API_TOKEN="${CF_TOKEN}" \
    node:22-alpine \
    sh -c "npm i -g wrangler >/dev/null 2>&1 && wrangler deploy"
fi

DOMAIN="$(grep -E '^CADDY_DOMAIN=' .env | sed -E 's/^CADDY_DOMAIN=//' || true)"
echo "Done. Panel should be running on https://${DOMAIN:-mail.example.com}"
