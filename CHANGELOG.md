# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-07-24

### 🚀 Features

#### Email Management
- Email Routing management (create, update, delete rules)
- Destination management (email forwarding addresses)
- Catch-All email routing configuration
- Worker integration for custom email processing

#### Inbox System
- Cloudflare Worker for receiving emails
- D1 database integration for email storage
- Email viewing and management in panel
- Email deletion with API support

#### Security
- Password authentication with salted hash (scrypt)
- Session management with HttpOnly cookies
- Rate limiting on login (10 attempts per 5 minutes)
- CSP, HSTS, X-Frame-Options headers
- Secure environment variable handling

#### UI/UX
- Modern, responsive design
- Dark mode support
- Star animation background
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

### 🐳 Deployment

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

### 📚 Documentation
- Comprehensive README with badges
- API reference documentation
- Configuration reference
- Contributing guidelines (CONTRIBUTING.md)
- Security policy (SECURITY.md)
- Worker setup guide

### 🔧 Dependencies
- Express.js 4.19.2
- Axios 1.7.2
- dotenv 16.4.5
- postal-mime 2.7.1
- nodemon 3.1.11 (dev)

### 📦 Project Structure
- Modular file organization
- Separate worker directory
- Public assets for frontend
- Scripts for deployment

---

## [1.1.0] - 2026-08-25

### 🔒 Security
- Session IDs are stored hashed (SHA-256) in memory; raw IDs are never kept
- Sliding session expiry: 24h TTL plus 30 min idle timeout, with periodic cleanup
- Session-bound CSRF token required on all mutating requests (cookie sessions)
- Per-IP brute-force lockout: 5 failed logins → 15 min temporary block
- Optional `ADMIN_API_TOKEN` for `Authorization: Bearer <token>` / `X-API-Key` API auth
- `scripts/generate-password.js` to generate `PASSWORD_HASH` / `PASSWORD_SALT` for `.env`
- Added `Strict-Transport-Security`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy` headers
- `/api/config` now exposes and can set an admin API token

### 🐳 Docker
- Panel container runs as unprivileged user (UID 1000) with `no-new-privileges:true` and `init: true`
- `.env` bind mount ownership handled by `install_vps.sh` so settings save from the UI
- Added `docker-compose.dokploy.yml` for Dokploy (self-hosted) deployments (no Caddy, no host ports, env via Dokploy Environment)

### 🧩 Changed
- `/api/session` returns real auth state (fixes stale session on reload)
- `/api/config` reports `has_admin_api_token`

## [Unreleased]

### 🔒 Security
- `PASSWORD` env var: set a plain login password and `PASSWORD_SALT`/`PASSWORD_HASH` are generated automatically at startup (ideal for Dokploy/Compose deploys; explicit hash+salt still take precedence)
- TOTP 2FA: optional two-factor auth via authenticator apps (`TOTP_SECRET` env or enroll from Settings), survives restarts when stored in environment
- `/api/totp/setup`, `/api/totp/activate`, `/api/totp/disable` endpoints for enrollment

### Planned Features
- [ ] Email filtering rules
- [ ] Bulk destination management
- [ ] Email analytics
- [ ] Webhook notifications
- [ ] Multi-user support
- [ ] Export/Import settings

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.1.0 | 2026-08-25 | Login/session hardening, CSRF, brute-force lockout, API token auth, Dokploy deploy |
| 1.0.0 | 2025-07-24 | Initial release |