#!/usr/bin/env bash
# Cloudflare Email Panel - CLI UI for Ubuntu/Debian VPS.
#
# Usage:
#   sudo bash scripts/cliui.sh                 # interactive menu
#   sudo bash scripts/cliui.sh install [--domain mail.example.com] [--yes]
#   sudo bash scripts/cliui.sh uninstall [--purge] [--yes]
#   sudo bash scripts/cliui.sh run
#   sudo bash scripts/cliui.sh stop
#   sudo bash scripts/cliui.sh restart
#   sudo bash scripts/cliui.sh status
#   sudo bash scripts/cliui.sh logs [--no-follow]
#   sudo bash scripts/cliui.sh cf-setup [args...]
#   sudo bash scripts/cliui.sh update
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
SELF="$SCRIPT_DIR/cliui.sh"
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"
ENV_FILE="$ROOT_DIR/.env"
ENV_EXAMPLE="$ROOT_DIR/.env.example"
DEFAULT_DOMAIN="mail.example.com"
APP_TITLE="Cloudflare Email Panel"

ORIG_ARGS=("$@")
REEXEC_CMD=()
ASSUME_YES=0
PURGE=0
DOMAIN=""
NO_EDIT=0
FOLLOW_LOGS=1
GENERATED_PASSWORD=""
COMPOSE_CMD=()

if [[ -t 1 ]]; then
  BOLD=$'\033[1m'
  RED=$'\033[31m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  CYAN=$'\033[36m'
  NC=$'\033[0m'
else
  BOLD=""
  RED=""
  GREEN=""
  YELLOW=""
  CYAN=""
  NC=""
fi

have() { command -v "$1" >/dev/null 2>&1; }

trap 'err "Command failed at line ${LINENO}."' ERR

info() { printf '%s==>%s %s\n' "$CYAN" "$NC" "$*"; }
ok() { printf '%s[ok]%s %s\n' "$GREEN" "$NC" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$YELLOW" "$NC" "$*" >&2; }
err() { printf '%s[error]%s %s\n' "$RED" "$NC" "$*" >&2; }
die() {
  err "$*"
  exit 1
}
hr() { printf '%s\n' "------------------------------------------------------------"; }

banner() {
  printf '%s\n' "============================================================"
  printf '  %s%s%s  |  VPS CLI UI\n' "$BOLD" "$APP_TITLE" "$NC"
  printf '%s\n' "============================================================"
  local domain
  domain="$(get_env CADDY_DOMAIN)"
  printf '  Project : %s\n' "$ROOT_DIR"
  printf '  Domain  : %s\n' "${domain:-<not configured>}"
  hr
}

confirm() {
  local prompt="$1" default="${2:-n}" answer
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    return 0
  fi
  if [[ ! -t 0 ]]; then
    [[ "$default" == "y" ]]
    return
  fi
  read -r -p "$prompt " answer || true
  answer="${answer:-$default}"
  [[ "$answer" =~ ^[Yy]$ ]]
}

press_enter() {
  [[ -t 0 ]] || return 0
  read -r -p "Press Enter to continue..." _ || true
}

get_env() {
  local key="$1" value
  [[ -f "$ENV_FILE" ]] || return 0
  value="$(sed -n "s/^${key}=//p" "$ENV_FILE" | tail -n 1 | tr -d '\r')"
  printf '%s' "$value"
}

set_env() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  awk -v k="$key" -v v="$value" '
    $0 ~ "^" k "=" { print k "=" v; found = 1; next }
    { print }
    END { if (!found) print k "=" v }
  ' "$ENV_FILE" >"$tmp"
  mv "$tmp" "$ENV_FILE"
}

gen_password() {
  if have openssl; then
    openssl rand -hex 16
    return
  fi
  head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-32
}

reexec_with_sudo() {
  local -a args=()
  if ((${#REEXEC_CMD[@]})); then
    args=("${REEXEC_CMD[@]}")
  else
    args=("${ORIG_ARGS[@]}")
  fi
  have sudo || die "Root privileges are required and sudo is not available."
  exec sudo -E bash "$SELF" ${args[@]+"${args[@]}"}
}

ensure_root() {
  if [[ "$EUID" -eq 0 ]]; then
    return 0
  fi
  warn "Root privileges required, re-running with sudo..."
  reexec_with_sudo
}

docker_ok() {
  if have docker && docker info >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

start_docker() {
  systemctl enable --now docker >/dev/null 2>&1 || service docker start >/dev/null 2>&1 || true
}

ensure_docker_access() {
  have docker || die "Docker is not installed. Run: sudo bash $SELF install"
  if docker info >/dev/null 2>&1; then
    return 0
  fi
  if [[ "$EUID" -ne 0 ]]; then
    warn "Cannot access the Docker daemon as $(id -un), re-running with sudo..."
    reexec_with_sudo
  fi
  die "Cannot connect to the Docker daemon. Start it with: systemctl start docker"
}

detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker compose)
    return 0
  fi
  if have docker-compose; then
    COMPOSE_CMD=(docker-compose)
    return 0
  fi
  return 1
}

compose() {
  "${COMPOSE_CMD[@]}" -p "$(project_name)" --project-directory "$ROOT_DIR" -f "$COMPOSE_FILE" "$@"
}

project_name() {
  basename "$ROOT_DIR" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9_-]//g'
}

ensure_env_file() {
  [[ -f "$ENV_FILE" ]] || die "Missing .env. Run install first: sudo bash $SELF install"
}

check_platform() {
  [[ "$(uname -s)" == "Linux" ]] || die "This script supports Linux only."
  have apt-get || die "This script supports Ubuntu/Debian (apt) only."
}

check_ports() {
  have ss || return 0
  local busy="" port
  for port in 80 443; do
    if ss -ltn 2>/dev/null | awk 'NR > 1 { print $4 }' | grep -Eq "[:.]${port}$"; then
      busy+=" $port"
    fi
  done
  if [[ -n "$busy" ]]; then
    warn "Port(s)$busy already in use (nginx/apache?). Caddy cannot bind until they are stopped."
  fi
}

install_docker() {
  if have docker && docker compose version >/dev/null 2>&1; then
    ok "Docker Engine and Docker Compose are already installed."
    start_docker
    return 0
  fi

  info "Installing Docker Engine and Docker Compose plugin..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl gnupg

  local os_id codename
  os_id="$(. /etc/os-release; echo "$ID")"
  codename="$(. /etc/os-release; echo "$VERSION_CODENAME")"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${os_id}/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/%s %s stable\n' \
    "$(dpkg --print-architecture)" "$os_id" "$codename" >/etc/apt/sources.list.d/docker.list

  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  start_docker
  ok "Docker installed."
}

prepare_env() {
  if [[ ! -f "$ENV_FILE" ]]; then
    [[ -f "$ENV_EXAMPLE" ]] || die "Missing .env.example template."
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    ok "Created .env from .env.example."
  fi

  local current domain
  current="$(get_env CADDY_DOMAIN)"
  domain="$DOMAIN"
  if [[ -z "$domain" ]]; then
    domain="$current"
  fi
  if [[ -z "$domain" || "$domain" == "mail.example.com" ]]; then
    domain="$DEFAULT_DOMAIN"
    if [[ -t 0 && "$ASSUME_YES" -eq 0 ]]; then
      read -r -p "Domain for this panel [$DEFAULT_DOMAIN]: " input || true
      domain="${input:-$DEFAULT_DOMAIN}"
    fi
  fi
  [[ "$domain" =~ ^[A-Za-z0-9.-]+$ ]] || die "Invalid domain name: $domain"
  set_env CADDY_DOMAIN "$domain"

  if [[ -z "$(get_env PORT)" ]]; then
    set_env PORT "3000"
  fi
  if [[ -z "$(get_env DATA_DIR)" ]]; then
    set_env DATA_DIR "/app/data"
  fi

  local password
  password="$(get_env APP_PASSWORD)"
  if [[ -z "$password" || "$password" == "change-me-now-please" ]]; then
    password="$(gen_password)"
    set_env APP_PASSWORD "$password"
    GENERATED_PASSWORD="$password"
    ok "Generated a random APP_PASSWORD."
  fi

  chown 1000:1000 "$ENV_FILE" 2>/dev/null || warn "Could not chown .env to 1000:1000."
  chmod 600 "$ENV_FILE" || true
  ok ".env is ready and writable by the panel container (UID 1000)."
}

edit_env_file() {
  if [[ "$NO_EDIT" -eq 1 || "$ASSUME_YES" -eq 1 || ! -t 0 ]]; then
    return 0
  fi
  if ! confirm "Edit .env now to add Cloudflare credentials? [Y/n]" y; then
    return 0
  fi
  have nano || {
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y nano >/dev/null 2>&1 || true
  }
  "${EDITOR:-nano}" "$ENV_FILE" || true
  chown 1000:1000 "$ENV_FILE" 2>/dev/null || true
  chmod 600 "$ENV_FILE" || true
}

warn_missing_credentials() {
  local missing=() key
  for key in CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID; do
    [[ -n "$(get_env "$key")" ]] || missing+=("$key")
  done
  if ((${#missing[@]})); then
    warn "Not set in .env yet: ${missing[*]}"
    warn "You can add them now or save them later from the panel Settings screen."
  fi
}

wait_healthy() {
  local timeout="${1:-120}" start=$SECONDS
  info "Waiting for the panel to become healthy (up to ${timeout}s)..."
  while ((SECONDS - start < timeout)); do
    if compose exec -T panel node -e "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" >/dev/null 2>&1; then
      printf '\n'
      ok "Panel is healthy."
      return 0
    fi
    printf '.'
    sleep 3
  done
  printf '\n'
  warn "Panel did not report healthy within ${timeout}s."
  return 1
}

print_access() {
  local domain
  domain="$(get_env CADDY_DOMAIN)"
  hr
  ok "Panel URL: https://${domain:-$DEFAULT_DOMAIN}"
  if [[ -n "$GENERATED_PASSWORD" ]]; then
    printf '%s\n' "  Login password (generated): $GENERATED_PASSWORD"
  else
    printf '%s\n' "  Login password: value of APP_PASSWORD in .env"
  fi
  printf '%s\n' "  Logs: sudo bash $SELF logs"
  warn "Point the domain's DNS A record at this VPS and keep TCP 80/443 open."
}

open_firewall() {
  have ufw || return 0
  local status
  status="$(ufw status 2>/dev/null || true)"
  [[ "$status" == *"Status: active"* ]] || return 0
  ufw allow 80/tcp >/dev/null 2>&1 || true
  ufw allow 443/tcp >/dev/null 2>&1 || true
  ok "Allowed TCP 80/443 in ufw."
}

cmd_install() {
  ensure_root
  check_platform
  banner
  install_docker

  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y git >/dev/null 2>&1 || true

  check_ports
  prepare_env
  edit_env_file
  warn_missing_credentials

  ensure_env_file
  detect_compose || die "Docker Compose not found after installing Docker."
  ensure_docker_access

  info "Building and starting the panel + HTTPS reverse proxy..."
  compose up -d --build --remove-orphans
  wait_healthy 180 || true
  compose ps
  open_firewall
  print_access
}

cmd_uninstall() {
  ensure_docker_access
  detect_compose || die "Docker Compose not found."
  banner

  if ! confirm "Stop and remove the panel containers? (files and data are kept)" n; then
    info "Uninstall cancelled."
    return 0
  fi

  compose down --remove-orphans || true
  docker rm -f cf-email-panel cf-email-caddy >/dev/null 2>&1 || true
  ok "Containers removed."

  if [[ "$PURGE" -eq 1 ]]; then
    if ! confirm "PURGE also deletes data volumes, local images, and .env. Continue?" n; then
      warn "Purge skipped. Volumes and .env were kept."
      return 0
    fi
    compose down --volumes --rmi local >/dev/null 2>&1 || true
    docker volume rm "$(project_name)_auth_data" >/dev/null 2>&1 || true
    rm -f "$ENV_FILE"
    ok "Volumes, images, and .env removed."
  else
    printf '%s\n' "  Data volume, Caddy certificates, and .env were kept."
    printf '%s\n' "  Run 'sudo bash $SELF uninstall --purge' to delete them too."
  fi
}

cmd_run() {
  ensure_env_file
  ensure_docker_access
  detect_compose || die "Docker Compose not found. Run install first."
  banner
  info "Starting containers..."
  compose up -d --remove-orphans
  wait_healthy 180 || true
  compose ps
  print_access
}

cmd_stop() {
  ensure_env_file
  ensure_docker_access
  detect_compose || die "Docker Compose not found."
  info "Stopping containers..."
  compose stop
  ok "Panel stopped. Data and .env were kept."
}

cmd_restart() {
  ensure_env_file
  ensure_docker_access
  detect_compose || die "Docker Compose not found."
  info "Recreating containers to apply the current .env..."
  compose up -d --remove-orphans
  if ! wait_healthy 120; then
    compose restart >/dev/null 2>&1 || true
    wait_healthy 120 || true
  fi
  compose ps
  print_access
}

cmd_status() {
  ensure_env_file
  ensure_docker_access
  detect_compose || die "Docker Compose not found."
  banner
  compose ps -a || true
  hr
  if compose exec -T panel node -e "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" >/dev/null 2>&1; then
    ok "Panel API is healthy."
  else
    warn "Panel API is not responding. Check logs: sudo bash $SELF logs"
  fi
  printf '  URL: https://%s\n' "$(get_env CADDY_DOMAIN)"
}

cmd_logs() {
  ensure_env_file
  ensure_docker_access
  detect_compose || die "Docker Compose not found."
  if [[ "$FOLLOW_LOGS" -eq 1 ]]; then
    compose logs -f --tail=200 || true
  else
    compose logs --tail=200 || true
  fi
}

cmd_cf_setup() {
  ensure_env_file
  [[ -n "$(get_env CLOUDFLARE_API_TOKEN)" ]] || die "CLOUDFLARE_API_TOKEN is empty in .env"
  [[ -n "$(get_env CLOUDFLARE_ACCOUNT_ID)" ]] || die "CLOUDFLARE_ACCOUNT_ID is empty in .env"

  if have node; then
    (cd "$ROOT_DIR" && node scripts/cf-setup.mjs "$@")
    return 0
  fi

  ensure_docker_access
  info "Node.js not found on the host, running Cloudflare setup in a container..."
  docker run --rm \
    -v "$ROOT_DIR:/app" \
    -v cf-email-panel-npm:/app/node_modules \
    -w /app \
    --env-file "$ENV_FILE" \
    node:22-alpine \
    sh -c 'npm ci --omit=dev --ignore-scripts --no-audit --no-fund >/dev/null && node scripts/cf-setup.mjs "$@"' sh "$@"
}

cmd_update() {
  ensure_env_file
  ensure_docker_access
  detect_compose || die "Docker Compose not found."
  have git || die "git is not installed."
  cd "$ROOT_DIR"

  if [[ -n "$(git status --porcelain)" ]]; then
    warn "The working tree has local changes."
    confirm "Continue with git pull anyway? [y/N]" n || die "Update cancelled."
  fi

  info "Pulling latest code..."
  git pull --ff-only
  info "Rebuilding containers..."
  compose up -d --build --remove-orphans
  wait_healthy 180 || true
  compose ps
  print_access
}

show_help() {
  cat <<EOF
$APP_TITLE - VPS CLI UI (Ubuntu/Debian)

Usage: sudo bash scripts/cliui.sh [command] [options]

Commands:
  (none)          Open the interactive menu
  install         Install Docker, create .env, build and start
  uninstall       Stop and remove containers (--purge: also volumes, images, .env)
  run             Start the panel
  stop            Stop the panel
  restart         Recreate containers with the current .env
  status          Show container and health status
  logs            Follow container logs (--no-follow to print once)
  cf-setup        Run scripts/cf-setup.mjs (D1 + Worker + Routing)
  update          git pull, rebuild, and restart
  help            Show this help

Options:
  --domain <name> Domain for Caddy/HTTPS (install)
  --yes, -y       Non-interactive, answer yes
  --purge         Also remove data volumes, images, and .env (uninstall)
  --no-edit       Do not open the .env editor (install)
  --no-follow     Print logs once instead of following

Examples:
  sudo bash scripts/cliui.sh install --domain mail.example.com
  sudo bash scripts/cliui.sh uninstall --purge --yes
  sudo bash scripts/cliui.sh logs --no-follow
EOF
}

parse_flags() {
  while (($#)); do
    case "$1" in
      -y | --yes) ASSUME_YES=1 ;;
      --purge) PURGE=1 ;;
      --domain)
        DOMAIN="${2:-}"
        shift
        ;;
      --domain=*) DOMAIN="${1#*=}" ;;
      --no-edit) NO_EDIT=1 ;;
      --no-follow) FOLLOW_LOGS=0 ;;
      -h | --help)
        show_help
        exit 0
        ;;
      *)
        die "Unknown option: $1 (see: bash $SELF help)"
        ;;
    esac
    shift
  done
}

main_menu() {
  local choice
  while true; do
    clear 2>/dev/null || true
    banner
    printf '  %2s) %s\n' 1 "Install / setup"
    printf '  %2s) %s\n' 2 "Run (start)"
    printf '  %2s) %s\n' 3 "Stop"
    printf '  %2s) %s\n' 4 "Restart"
    printf '  %2s) %s\n' 5 "Status"
    printf '  %2s) %s\n' 6 "Logs (follow)"
    printf '  %2s) %s\n' 7 "Cloudflare setup (D1 + Worker + Routing)"
    printf '  %2s) %s\n' 8 "Update (git pull + rebuild)"
    printf '  %2s) %s\n' 9 "Uninstall"
    printf '  %2s) %s\n' 0 "Exit"
    hr
    if ! read -r -p "Select an option: " choice; then
      printf '\n'
      return 0
    fi
    case "$choice" in
      1)
        REEXEC_CMD=(install)
        cmd_install
        ;;
      2)
        REEXEC_CMD=(run)
        cmd_run
        ;;
      3)
        REEXEC_CMD=(stop)
        cmd_stop
        ;;
      4)
        REEXEC_CMD=(restart)
        cmd_restart
        ;;
      5)
        REEXEC_CMD=(status)
        cmd_status
        ;;
      6)
        REEXEC_CMD=(logs)
        cmd_logs
        ;;
      7)
        REEXEC_CMD=(cf-setup)
        cmd_cf_setup
        ;;
      8)
        REEXEC_CMD=(update)
        cmd_update
        ;;
      9)
        REEXEC_CMD=(uninstall)
        cmd_uninstall
        ;;
      0 | q | Q)
        return 0
        ;;
      *)
        warn "Invalid option: $choice"
        ;;
    esac
    press_enter
  done
}

main() {
  local command="${1:-menu}"
  if (($#)); then
    shift
  fi

  case "$command" in
    menu)
      main_menu
      ;;
    install | setup)
      parse_flags "$@"
      cmd_install
      ;;
    uninstall | remove)
      parse_flags "$@"
      cmd_uninstall
      ;;
    run | start)
      cmd_run
      ;;
    stop)
      cmd_stop
      ;;
    restart)
      cmd_restart
      ;;
    status | ps)
      cmd_status
      ;;
    logs)
      parse_flags "$@"
      cmd_logs
      ;;
    cf-setup | cloudflare)
      cmd_cf_setup "$@"
      ;;
    update | upgrade)
      cmd_update
      ;;
    help | --help | -h)
      show_help
      ;;
    *)
      err "Unknown command: $command"
      show_help
      exit 1
      ;;
  esac
}

main "$@"
