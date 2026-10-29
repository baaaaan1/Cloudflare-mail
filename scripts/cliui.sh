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

# --- Terminal styling --------------------------------------------------------
COLOR_MODE=0
UNICODE=0
RESET=""
BOLD=""
DIM=""
RED=""
GREEN=""
YELLOW=""
BLUE=""
MAGENTA=""
CYAN=""
WHITE=""
GREY=""
ORANGE=""
SYM_INFO=""
SYM_OK=""
SYM_WARN=""
SYM_ERR=""
SYM_ASK=""
SYM_ARROW=""

LOGO=(
  ' ██████╗  ███████╗  ███╗   ███╗   █████╗   ██╗ ██╗'
  '██╔════╝  ██╔════╝  ████╗ ████║  ██╔══██╗  ██║ ██║'
  '██║       █████╗    ██╔████╔██║  ███████║  ██║ ██║'
  '██║       ██╔══╝    ██║╚██╔╝██║  ██╔══██║  ██║ ██║'
  '╚██████╗  ██║       ██║ ╚═╝ ██║  ██║  ██║  ██║ ███████╗'
  ' ╚═════╝  ╚═╝       ╚═╝     ╚═╝  ╚═╝  ╚═╝  ╚═╝ ╚══════╝'
)
LOGO_SHADES=(202 208 214 220 214 208)

is_utf8() {
  local loc="${LC_ALL:-${LC_CTYPE:-${LANG:-}}}"
  if [[ -z "$loc" ]]; then
    return 0
  fi
  if [[ "$loc" == *[Uu][Tt][Ff]-8* || "$loc" == *[Uu][Tt][Ff]8* ]]; then
    return 0
  fi
  case "${loc^^}" in
    C | POSIX | *ANSI_X3.4*) return 1 ;;
  esac
  return 0
}

init_colors() {
  local colors=8
  if is_utf8; then
    UNICODE=1
  fi

  if [[ -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" && -t 1 ]]; then
    colors="$(tput colors 2>/dev/null || printf '8')"
    [[ "$colors" =~ ^[0-9]+$ ]] || colors=8

    if ((colors >= 256)); then
      COLOR_MODE=256
      RESET=$'\033[0m'
      BOLD=$'\033[1m'
      DIM=$'\033[2m'
      RED=$'\033[38;5;203m'
      GREEN=$'\033[38;5;114m'
      YELLOW=$'\033[38;5;221m'
      BLUE=$'\033[38;5;75m'
      MAGENTA=$'\033[38;5;176m'
      CYAN=$'\033[38;5;80m'
      WHITE=$'\033[38;5;255m'
      GREY=$'\033[38;5;245m'
      ORANGE=$'\033[38;5;209m'
    elif ((colors >= 8)); then
      COLOR_MODE=8
      RESET=$'\033[0m'
      BOLD=$'\033[1m'
      DIM=$'\033[2m'
      RED=$'\033[31m'
      GREEN=$'\033[32m'
      YELLOW=$'\033[33m'
      BLUE=$'\033[34m'
      MAGENTA=$'\033[35m'
      CYAN=$'\033[36m'
      WHITE=$'\033[97m'
      GREY=$'\033[90m'
      ORANGE=$'\033[33m'
    fi
  fi

  if [[ "$UNICODE" -eq 1 && "$COLOR_MODE" -ne 0 ]]; then
    SYM_INFO="◆"
    SYM_OK="✔"
    SYM_WARN="▲"
    SYM_ERR="✖"
    SYM_ASK="?"
    SYM_ARROW="▸"
  else
    SYM_INFO="*>"
    SYM_OK="[ok]"
    SYM_WARN="[warn]"
    SYM_ERR="[error]"
    SYM_ASK="??"
    SYM_ARROW=">"
  fi
}

term_width() {
  local cols="${COLUMNS:-0}"
  if [[ ! "$cols" =~ ^[0-9]+$ || "$cols" -le 0 ]]; then
    cols="$(tput cols 2>/dev/null || printf '0')"
  fi
  [[ "$cols" =~ ^[0-9]+$ ]] || cols=0
  if ((cols < 46)); then
    cols=46
  fi
  if ((cols > 78)); then
    cols=78
  fi
  printf '%s' "$cols"
}

have() { command -v "$1" >/dev/null 2>&1; }

trap 'err "Command failed at line ${LINENO}."' ERR

info() { printf '%s%s%s %s\n' "${BOLD}${CYAN}" "$SYM_INFO" "$RESET" "$*"; }
ok() { printf '%s%s%s %s\n' "${BOLD}${GREEN}" "$SYM_OK" "$RESET" "$*"; }
warn() { printf '%s%s%s %s\n' "${BOLD}${YELLOW}" "$SYM_WARN" "$RESET" "$*" >&2; }
err() { printf '%s%s%s %s\n' "${BOLD}${RED}" "$SYM_ERR" "$RESET" "$*" >&2; }
die() {
  err "$*"
  exit 1
}

rule() {
  local width char line="" i
  width="$(term_width)"
  char="-"
  [[ "$UNICODE" -eq 1 ]] && char="─"
  for ((i = 0; i < width; i++)); do
    line+="$char"
  done
  printf '%s%s%s\n' "$GREY" "$line" "$RESET"
}
hr() { rule; }

banner() {
  local domain i col
  domain="$(get_env CADDY_DOMAIN)"
  printf '\n'

  if [[ "$UNICODE" -eq 1 && "$COLOR_MODE" -ne 0 ]] && (($(term_width) >= 58)); then
    for i in "${!LOGO[@]}"; do
      if [[ "$COLOR_MODE" -eq 256 ]]; then
        col="${LOGO_SHADES[$((i % ${#LOGO_SHADES[@]}))]}"
        printf '\033[38;5;%sm  %s\033[0m\n' "$col" "${LOGO[$i]}"
      else
        printf '%s  %s%s\n' "${BOLD}${ORANGE}" "${LOGO[$i]}" "$RESET"
      fi
    done
  else
    printf '  %s%s%s\n' "${BOLD}${ORANGE}" "$APP_TITLE" "$RESET"
  fi

  printf '  %sVPS CLI UI  %s %sUbuntu / Debian%s\n\n' "$DIM" "$SYM_ARROW" "$DIM" "$RESET"
  rule
  printf '  %s%-9s%s %s\n' "$GREY" "Project" "$RESET" "$ROOT_DIR"
  if [[ -n "$domain" ]]; then
    printf '  %s%-9s%s %s%s%s\n' "$GREY" "Domain" "$RESET" "${BOLD}${CYAN}" "$domain" "$RESET"
  else
    printf '  %s%-9s%s %s\n' "$GREY" "Domain" "$RESET" "${YELLOW}<not configured>${RESET}"
  fi
  rule
}
init_colors

confirm() {
  local prompt="$1" default="${2:-n}" answer
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    return 0
  fi
  if [[ ! -t 0 ]]; then
    [[ "$default" == "y" ]]
    return
  fi
  read -r -p "$(printf '%s%s%s %s ' "${BOLD}${YELLOW}" "$SYM_ASK" "$RESET" "$prompt")" answer || true
  answer="${answer:-$default}"
  [[ "$answer" =~ ^[Yy]$ ]]
}

press_enter() {
  [[ -t 0 ]] || return 0
  printf '%sPress Enter to continue...%s' "$DIM" "$RESET"
  read -r _ || true
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
    printf '%s.%s' "$DIM" "$RESET"
    sleep 3
  done
  printf '\n'
  warn "Panel did not report healthy within ${timeout}s."
  return 1
}

print_access() {
  local domain
  domain="$(get_env CADDY_DOMAIN)"
  printf '\n'
  rule
  printf '  %s%-9s%s %shttps://%s%s\n' "$GREY" "Panel URL" "$RESET" "${BOLD}${CYAN}" "${domain:-$DEFAULT_DOMAIN}" "$RESET"
  if [[ -n "$GENERATED_PASSWORD" ]]; then
    printf '  %s%-9s%s %s%s%s %s(generated)%s\n' "$GREY" "Password" "$RESET" "${BOLD}${YELLOW}" "$GENERATED_PASSWORD" "$RESET" "$DIM" "$RESET"
  else
    printf '  %s%-9s%s %sAPP_PASSWORD%s in .env\n' "$GREY" "Password" "$RESET" "$BOLD" "$RESET"
  fi
  printf '  %s%-9s%s sudo bash %s logs\n' "$GREY" "Logs" "$RESET" "$SELF"
  rule
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
  printf '  %s%-9s%s %shttps://%s%s\n' "$GREY" "Panel URL" "$RESET" "${BOLD}${CYAN}" "$(get_env CADDY_DOMAIN)" "$RESET"
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

help_row() { printf '  %s%-16s%s %s\n' "$ORANGE" "$1" "$RESET" "$2"; }
help_section() { printf '\n  %s%s%s\n' "${BOLD}${GREY}" "$1" "$RESET"; }

show_help() {
  printf '\n  %s%s%s  %s%s%s\n' "$BOLD" "$APP_TITLE" "$RESET" "$DIM" "$SYM_ARROW VPS CLI UI (Ubuntu/Debian)" "$RESET"
  rule
  printf '  %s%-9s%s %s\n' "$GREY" "Usage" "$RESET" "sudo bash scripts/cliui.sh [command] [options]"

  help_section "COMMANDS"
  help_row "(none)" "Open the interactive menu"
  help_row "install" "Install Docker, create .env, build and start"
  help_row "uninstall" "Stop and remove containers (--purge: also volumes, images, .env)"
  help_row "run" "Start the panel"
  help_row "stop" "Stop the panel"
  help_row "restart" "Recreate containers with the current .env"
  help_row "status" "Show container and health status"
  help_row "logs" "Follow container logs (--no-follow to print once)"
  help_row "cf-setup" "Run scripts/cf-setup.mjs (D1 + Worker + Routing)"
  help_row "update" "git pull, rebuild, and restart"
  help_row "help" "Show this help"

  help_section "OPTIONS"
  help_row "--domain <name>" "Domain for Caddy/HTTPS (install)"
  help_row "--yes, -y" "Non-interactive, answer yes"
  help_row "--purge" "Also remove data volumes, images, and .env (uninstall)"
  help_row "--no-edit" "Do not open the .env editor (install)"
  help_row "--no-follow" "Print logs once instead of following"

  help_section "EXAMPLES"
  printf '  %s%s%s sudo bash scripts/cliui.sh install --domain mail.example.com\n' "$DIM" "$SYM_ARROW" "$RESET"
  printf '  %s%s%s sudo bash scripts/cliui.sh uninstall --purge --yes\n' "$DIM" "$SYM_ARROW" "$RESET"
  printf '  %s%s%s sudo bash scripts/cliui.sh logs --no-follow\n' "$DIM" "$SYM_ARROW" "$RESET"
  printf '\n'
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

menu_group() { printf '\n  %s%s%s\n' "${BOLD}${GREY}" "$1" "$RESET"; }
menu_row() { printf '    %s%2s%s  %s\n' "${BOLD}${ORANGE}" "$1" "$RESET" "$2"; }

main_menu() {
  local choice
  while true; do
    clear 2>/dev/null || true
    banner
    menu_group "SETUP"
    menu_row 1 "Install / setup"
    menu_row 7 "Cloudflare setup (D1 + Worker + Routing)"
    menu_group "OPERATIONS"
    menu_row 2 "Run (start)"
    menu_row 3 "Stop"
    menu_row 4 "Restart"
    menu_row 5 "Status"
    menu_row 6 "Logs (follow)"
    menu_group "MAINTENANCE"
    menu_row 8 "Update (git pull + rebuild)"
    menu_row 9 "Uninstall"
    menu_row 0 "Exit"
    printf '\n'
    rule
    if ! read -r -p "$(printf '%s%s%s Select an option: ' "${BOLD}${CYAN}" "$SYM_ARROW" "$RESET")" choice; then
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
