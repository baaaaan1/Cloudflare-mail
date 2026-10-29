# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-10-29

### Changed

- Authentication is password-only: `APP_PASSWORD` (or legacy `ADMIN_PASSWORD`) signs an
  HMAC-SHA256 session cookie with a 7-day expiry. The signing secret comes from
  `AUTH_SECRET` or is generated once and persisted to `DATA_DIR/auth-secret.txt`.
- The React/Vite SPA in `ui/` is the primary frontend. The server serves `ui/dist` and
  falls back to the legacy `public/` app when no build exists.
- REST API keys are managed from the panel (`/api/keys`). Keys use the `cfm_` prefix,
  are shown once, and only their SHA-256 hashes are stored in `DATA_DIR/api-keys.json`
  (mode 0600). Supported scopes: `rules:*`, `destinations:*`, `inbox:*`,
  `domains:read`, `config:*`, `keys:*`, and `*`.
- Requests are authorized by either a cookie session (admin) or a scoped API key.
  A resource/action scope map gates panel routes for API-key callers.
- Optional Cloudflare Turnstile captcha on the login form (`TURNSTILE_ENABLED`).
- Generated addresses are stored in D1 and pruned after 7 days.
- Documentation consolidated under `docs/`.
- Login requests are capped at 5 attempts per minute per IP; 5 failed attempts trigger
  a 15-minute lockout that doubles on repeat offences up to 24 hours.

### Removed

- Better Auth integration in favor of `lib/auth.js`.
- TOTP/2FA and MongoDB credential storage. `PASSWORD_HASH`, `PASSWORD_SALT`, and
  `POST /api/setup-password` are no longer used.
- Starfield background and glassmorphism styling from the legacy UI.

## [1.1.0] - 2026-08-25

### Security

- Session IDs stored hashed (SHA-256) in memory; raw IDs are never kept
- Sliding session expiry: 24h TTL plus a 30-minute idle timeout, with periodic cleanup
- Session-bound CSRF token required on all mutating requests (cookie sessions)
- Per-IP brute-force lockout: 5 failed logins trigger a 15-minute temporary block
- Optional `ADMIN_API_TOKEN` for `Authorization: Bearer <token>` / `X-API-Key` API auth
- `scripts/generate-password.js` to generate `PASSWORD_HASH` / `PASSWORD_SALT` for `.env`
- Added `Strict-Transport-Security`, `Cross-Origin-Opener-Policy`, and
  `Cross-Origin-Resource-Policy` headers
- `/api/config` exposes and can set an admin API token

### Docker

- Panel container runs as an unprivileged user (UID 1000) with `no-new-privileges:true`
  and `init: true`
- `.env` bind-mount ownership handled by `install_vps.sh` so settings save from the UI
- Added `docker-compose.dokploy.yml` for Dokploy deployments (no Caddy, no host ports,
  environment configured in Dokploy)

### Changed

- `/api/session` returns real auth state (fixes stale session on reload)
- `/api/config` reports `has_admin_api_token`

## [1.0.0] - 2025-07-24

### Features

#### Email Management

- Email Routing management (create, update, delete rules)
- Destination management (email forwarding addresses)
- Catch-all email routing configuration
- Worker integration for custom email processing

#### Inbox System

- Cloudflare Worker for receiving emails
- D1 database integration for email storage
- Email viewing and management in the panel
- Email deletion with API support

#### Security

- Password authentication with salted hash (scrypt)
- Session management with HttpOnly cookies
- Rate limiting on login (10 attempts per 5 minutes)
- CSP, HSTS, and X-Frame-Options headers
- Secure environment variable handling

#### UI/UX

- Responsive design
- Dark mode support
- Theme persistence (localStorage)
- Mobile-friendly interface

#### Diagnostics

- Cloudflare API connectivity check
- Permission verification
- Setup guide for API tokens

#### API

- RESTful API endpoints
- Authentication middleware
- CORS support
- Error handling

### Deployment

#### Docker

- Dockerfile with Node.js 22 Alpine
- Docker Compose with Caddy reverse proxy
- Automatic HTTPS via Caddy
- Health check endpoints

#### VPS Scripts

- `install_vps.sh` - Automated VPS setup
- `deploy_vps.sh` - Deployment automation
- Docker Engine + Compose installation
- Systemd service support

### Documentation

- Comprehensive README with badges
- API reference documentation
- Configuration reference
- Contributing guidelines (`docs/CONTRIBUTING.md`)
- Security policy (`docs/SECURITY.md`)
- Worker setup guide

### Dependencies

- Express.js 4.19.2
- Axios 1.7.2
- dotenv 16.4.5
- postal-mime 2.7.1
- nodemon 3.1.11 (dev)

### Project Structure

- Modular file organization
- Separate worker directory
- Public assets for the frontend
- Scripts for deployment

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 2.0.0 | 2026-10-29 | React workspace UI, password auth, scoped API keys, Cloudflare provisioning, hardened deployment |
| 1.1.0 | 2026-08-25 | Login/session hardening, CSRF, brute-force lockout, API token auth, Dokploy deploy |
| 1.0.0 | 2025-07-24 | Initial release |
