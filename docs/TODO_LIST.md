# TODO List

Current status and planned work for Cloudflare Email Panel.

## Completed

### Core

- [x] Cloudflare Email Routing rule management (create, update, delete)
- [x] Destination management
- [x] Catch-all routing configuration
- [x] Worker routing support
- [x] Inbox backed by Cloudflare D1 + Worker
- [x] Email viewing and deletion
- [x] Generated addresses with 7-day retention
- [x] Diagnostics endpoint for token/permission checks

### Authentication and security

- [x] Password login with timing-safe comparison (`APP_PASSWORD` / `ADMIN_PASSWORD`)
- [x] Stateless HMAC-SHA256 session cookies (7-day expiry)
- [x] Stable signing secret persisted in `DATA_DIR/auth-secret.txt`
- [x] Per-IP login rate limit (5/minute) and escalating lockout (up to 24 hours)
- [x] Optional Cloudflare Turnstile on login
- [x] Scoped API keys with SHA-256 hashed storage (`/api/keys`)
- [x] Resource/action scope enforcement for API-key callers
- [x] Security headers (CSP, HSTS in production, COOP, CORP, and others)
- [x] Audit log lines for login and API-key events

### Frontend

- [x] React + TypeScript + Vite SPA in `ui/`
- [x] Overview, rules, addresses, inbox, settings, and API docs pages
- [x] Dark mode and responsive layout
- [x] Legacy `public/` frontend kept as a fallback

### Deployment and docs

- [x] Docker image with non-root user and health checks
- [x] Docker Compose stack with Caddy and automatic HTTPS
- [x] Dokploy compose file
- [x] VPS install and deploy scripts
- [x] One-command Cloudflare setup (`npm run cf:setup`)
- [x] Documentation consolidated under `docs/`
- [x] Changelog, contributing, and security docs synced with the current code
- [x] Removed unused dependencies (`better-auth`, `@better-auth/api-key`,
      `@better-auth/infra`, `telegraf`)
- [x] Updated stale Dokploy deployment comments
- [x] Added a screenshot to the README (stored in `docs/assets/`)

## Next

### Testing and CI

- [ ] Add automated tests for `lib/auth.js` (sign/verify, expiry, timing-safe compare)
- [ ] Add automated tests for `lib/apiKeys.js` (create, verify, revoke, scope validation)
- [ ] Add API tests for scope enforcement and config validation
- [ ] Add a GitHub Actions workflow for UI lint, typecheck, and build
- [ ] Add linting for `server.js` and `lib/`

### Reliability

- [ ] Optional shared rate-limit/session store for multi-instance deployments
- [ ] Graceful handling of a missing or read-only `DATA_DIR`
- [ ] Pagination for inbox recipients and generated addresses
- [ ] Health check that reports D1/Worker status separately

### Planned features

- [ ] Email filtering rules
- [ ] Bulk destination management
- [ ] Email analytics
- [ ] Webhook notifications
- [ ] Multi-user support with roles
- [ ] Export/import settings
