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

if [[ ! -f .register-request.json ]]; then
  echo '{"pending":null}' > .register-request.json
fi

if [[ ! -f worker/wrangler.toml ]] && [[ -f worker/wrangler.toml.example ]]; then
  cp worker/wrangler.toml.example worker/wrangler.toml
fi

if [[ -f worker/wrangler.toml ]]; then
  DB_ID="$(grep -E '^CF_D1_DATABASE_ID=' .env | sed -E 's/^CF_D1_DATABASE_ID=//')"
  if [[ -n "${DB_ID}" ]]; then
    sed -i "s/^database_id = \".*\"/database_id = \"${DB_ID}\"/" worker/wrangler.toml
  fi
fi

docker compose up -d --build

if [[ "${DEPLOY_WORKER}" == "true" ]]; then
  CF_TOKEN="$(grep -E '^CF_API_TOKEN=' .env | sed -E 's/^CF_API_TOKEN=//')"
  if [[ -z "${CF_TOKEN}" ]]; then
    echo "ERROR: CF_API_TOKEN missing in .env. Cannot deploy worker."
    exit 1
  fi
  echo "Deploying worker using CF_API_TOKEN..."
  docker run --rm \
    -v "$ROOT_DIR/worker":/app \
    -w /app \
    -e CLOUDFLARE_API_TOKEN="${CF_TOKEN}" \
    node:22-alpine \
    sh -c "npm i -g wrangler >/dev/null 2>&1 && wrangler deploy"
fi

echo "Done. Panel should be running on http://<VPS-IP>:3000"
