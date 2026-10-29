# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in Cloudflare
Email Panel, please report it responsibly.

### DO NOT

- **Do NOT** open a public GitHub issue
- **Do NOT** disclose the vulnerability publicly until a fix is available

### How to Report

1. Open a private advisory at
   <https://github.com/baaaaan1/Cloudflare-mail/security/advisories/new>.
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
3. Allow reasonable time for a response and a fix before public disclosure.

### What to Expect

- **Acknowledgment**: within 48 hours
- **Assessment**: severity and impact evaluation
- **Fix**: coordinated disclosure once a patch is available
- **Credit**: acknowledgement in the release notes (unless you prefer anonymity)

## Security Measures

### Authentication

- Single-password login using `APP_PASSWORD` (or legacy `ADMIN_PASSWORD`) with a
  timing-safe comparison
- Sessions are stateless HMAC-SHA256 signed cookies (`cf_panel_session`), HttpOnly and
  SameSite=Lax, with a 7-day expiry. The cookie is marked `Secure` when the request is
  served over HTTPS
- The session signing secret comes from `AUTH_SECRET` (or `BETTER_AUTH_SECRET`) or is
  generated once and persisted to `DATA_DIR/auth-secret.txt`
- Optional Cloudflare Turnstile captcha on the login form (`TURNSTILE_ENABLED` with
  `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY`)
- Brute-force protection: 5 failed attempts per IP trigger a 15-minute lockout that
  doubles on repeat offences up to 24 hours. Login attempts are capped at 5 per minute
  per IP and failures add artificial latency
- Scoped API keys (`Authorization: Bearer cfm_...` or `X-API-Key`) for scripted and
  remote access
- The panel is password-only. TOTP/2FA is not supported in the current release

### HTTP Security Headers

The application sets the following headers on every response:

```
Content-Security-Policy: default-src 'self'; script-src 'self' https://challenges.cloudflare.com; ...
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

`Strict-Transport-Security` is only sent when `NODE_ENV=production`.

### API Security

- All panel API routes require a session cookie or a valid scoped API key
- API keys are random 192-bit secrets with the `cfm_` prefix. Only SHA-256 hashes are
  stored, in `DATA_DIR/api-keys.json` (mode 0600); the plaintext key is shown once on
  creation
- Each key is limited to the scopes granted at creation (`rules:*`, `destinations:*`,
  `inbox:*`, `domains:read`, `config:*`, `keys:*`, or `*`)
- Non-admin keys cannot create keys with scopes they do not hold
- Revocation takes effect on the next request
- CORS is enabled for API-key callers; cookies are never sent cross-origin
- Input validation and sanitization on configuration endpoints
- No sensitive data in error messages

### Data Protection

- `.env` contains sensitive credentials
- `.env` is gitignored and never committed
- `DATA_DIR` contains the session signing secret (`auth-secret.txt`) and hashed API keys
  (`api-keys.json`). Persist it with a Docker volume and keep it out of version control

### Docker Security

- Runs as a non-root user (UID 1000) in the container
- `no-new-privileges:true` and `init: true` via Docker Compose
- Minimal Alpine Linux base image
- No unnecessary packages installed
- Read-only Caddyfile mount

## Best Practices for Deployment

### 1. API Token Permissions

Create a Cloudflare API token with the minimum required permissions:

- **Zone** -> Email Routing -> Edit
- **Zone** -> Zone -> Read
- **Account** -> Workers Scripts -> Edit (if using Workers)
- **Account** -> D1 -> Edit (if using the Inbox)

### 2. Network Security

- Use Cloudflare SSL/TLS Full (Strict) mode
- Restrict the VPS firewall to ports 80 and 443 only
- Consider Cloudflare Access for additional protection
- Use an IP allowlist if the panel is for team use only

### 3. Environment Variables

Keep these secure:

```env
CLOUDFLARE_API_TOKEN=your_api_token
CLOUDFLARE_ACCOUNT_ID=your_account_id
CLOUDFLARE_D1_DATABASE_ID=your_d1_database_id
APP_PASSWORD=your-strong-password
AUTH_SECRET=your_random_secret
```

Set `AUTH_SECRET` explicitly when `DATA_DIR` is not persisted; otherwise a lost
`auth-secret.txt` invalidates all existing sessions on restart.

### 4. Regular Updates

- Keep Node.js updated to the latest LTS
- Keep Docker images updated
- Monitor Cloudflare API changes
- Update dependencies regularly (`npm audit`)

## Security Checklist for Production

- [ ] API token has minimum required permissions
- [ ] `.env` file permissions set to 600
- [ ] `DATA_DIR` persisted with a Docker volume and backed up
- [ ] Firewall only allows ports 80 and 443
- [ ] Cloudflare SSL/TLS mode set to Full (Strict)
- [ ] Strong `APP_PASSWORD` configured
- [ ] Panel accessed only via HTTPS
- [ ] Regular backups of `.env` and the D1 database
- [ ] Monitor access logs for suspicious activity

## Known Security Considerations

### Stateless Sessions

Sessions are signed cookies, not server-side records. Changing `APP_PASSWORD` does not
invalidate sessions that are already issued; rotate the signing secret (or delete
`DATA_DIR/auth-secret.txt`) to sign everyone out.

### Rate Limiting

Rate limiting and lockouts are per-IP and in-memory. They reset on restart and are not
shared between instances. For distributed deployments, use a shared store such as Redis.

### Single Admin

The panel supports one password-authenticated admin. Per-user accounts and roles are not
available; use scoped API keys for limited integrations.

## Updates and Notifications

- Security fixes will be released as patch versions
- Subscribe to GitHub releases for notifications
- Check this `SECURITY.md` for updated guidance
