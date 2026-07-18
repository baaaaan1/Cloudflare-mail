#!/usr/bin/env bash
# Ubuntu/Debian all-in-one VPS installer. Run: sudo bash scripts/install_vps.sh
set -Eeuo pipefail

DEFAULT_DOMAIN="mail.ayaneo.my.id"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: Run with sudo: sudo bash scripts/install_vps.sh" >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "ERROR: This installer supports Ubuntu/Debian (apt) only." >&2
  exit 1
fi

install_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    echo "Docker Engine and Docker Compose are already installed."
    return
  fi

  echo "Installing Docker Engine and Docker Compose plugin..."
  apt-get update
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  local os_id codename
  os_id="$(. /etc/os-release; echo "$ID")"
  codename="$(. /etc/os-release; echo "$VERSION_CODENAME")"
  curl -fsSL "https://download.docker.com/linux/${os_id}/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${os_id} ${codename} stable" > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

prepare_env() {
  if [[ ! -f "$ROOT_DIR/.env" ]]; then
    cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
    chmod 600 "$ROOT_DIR/.env"
    echo "Created .env from .env.example."
  fi

  local existing_domain domain
  existing_domain="$(sed -n 's/^CADDY_DOMAIN=//p' "$ROOT_DIR/.env" | head -n 1)"
  read -r -p "Domain for this panel [$DEFAULT_DOMAIN]: " domain
  domain="${domain:-${existing_domain:-$DEFAULT_DOMAIN}}"
  if [[ ! "$domain" =~ ^[A-Za-z0-9.-]+$ ]]; then
    echo "ERROR: Invalid domain name." >&2
    exit 1
  fi

  if grep -q '^CADDY_DOMAIN=' "$ROOT_DIR/.env"; then
    sed -i "s/^CADDY_DOMAIN=.*/CADDY_DOMAIN=$domain/" "$ROOT_DIR/.env"
  else
    printf '\nCADDY_DOMAIN=%s\n' "$domain" >> "$ROOT_DIR/.env"
  fi

  echo
  echo "Fill the Cloudflare credentials in $ROOT_DIR/.env."
  read -r -p "Open .env now with nano? [Y/n] " edit_env
  if [[ ! "$edit_env" =~ ^[Nn]$ ]]; then
    apt-get install -y nano
    nano "$ROOT_DIR/.env"
  fi
}

install_docker
prepare_env

cd "$ROOT_DIR"
echo "Building and starting panel + HTTPS reverse proxy..."
docker compose up -d --build --remove-orphans
docker compose ps

echo
echo "Deployment complete: https://$(sed -n 's/^CADDY_DOMAIN=//p' .env | head -n 1)"
echo "Ensure the domain A record points to this VPS and TCP ports 80/443 are allowed."