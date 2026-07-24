# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in Cloudflare Email Panel, please report it responsibly.

### DO NOT

- **Do NOT** open a public GitHub issue
- **Do NOT** disclose the vulnerability publicly until a fix is available

### How to Report

1. **Email**: Send details to [your-security-email@example.com]
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
3. **Allow time**: Give us reasonable time to respond and fix the issue

### What to Expect

- **Acknowledgment**: We'll acknowledge receipt within 48 hours
- **Assessment**: We'll evaluate the severity and impact
- **Fix**: We'll work on a fix and coordinate disclosure
- **Credit**: We'll credit you in the release notes (unless you prefer anonymity)

## Security Measures

### Authentication

- Password-only authentication with salted hash (scrypt)
- Secure session management with HttpOnly cookies
- Rate limiting on login attempts (10 attempts per 5 minutes)
- Session timeout (24 hours)

### HTTP Security Headers

The application sets the following headers:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; ...
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### API Security

- All API routes require authentication (except login, logout, auth-status)
- Rate limiting on sensitive endpoints
- Input validation and sanitization
- No sensitive data in error messages

### Data Protection

- `.env` file contains sensitive credentials
- `.env` is gitignored and never committed
- Passwords are hashed with scrypt (64-byte key)
- Random salt generated per installation

### Docker Security

- Non-root process inside container
- Minimal Alpine Linux base image
- No unnecessary packages installed
- Read-only Caddyfile mount

## Best Practices for Deployment

### 1. API Token Permissions

Create a Cloudflare API token with minimum required permissions:

- **Zone** → Email Routing → Edit
- **Zone** → Zone → Read
- **Account** → Workers Scripts → Edit (if using Workers)
- **Account** → D1 → Edit (if using Inbox)

### 2. Network Security

- Use Cloudflare's SSL/TLS Full (Strict) mode
- Restrict VPS firewall to ports 80 and 443 only
- Consider using Cloudflare Access for additional protection
- Use IP allowlist if the panel is for team use only

### 3. Environment Variables

Keep these secure:

```env
CLOUDFLARE_API_TOKEN=your_api_token
CLOUDFLARE_ACCOUNT_ID=your_account_id
PASSWORD_HASH=your_password_hash
PASSWORD_SALT=your_password_salt
```

### 4. Regular Updates

- Keep Node.js updated to latest LTS
- Keep Docker images updated
- Monitor Cloudflare API changes
- Update dependencies regularly (`npm audit`)

## Security Checklist for Production

- [ ] API token has minimum required permissions
- [ ] `.env` file permissions set to 600
- [ ] Firewall only allows ports 80 and 443
- [ ] Cloudflare SSL/TLS mode set to Full (Strict)
- [ ] Strong password configured (8+ characters)
- [ ] Panel accessed only via HTTPS
- [ ] Regular backups of `.env` and D1 database
- [ ] Monitor access logs for suspicious activity

## Known Security Considerations

### Session Storage

Sessions are stored in memory (not persistent across restarts). This is acceptable for single-server deployments but consider external session storage for high-availability setups.

### Rate Limiting

Rate limiting is per-IP and in-memory. For distributed deployments, consider using Redis or similar.

## Updates and Notifications

- Security fixes will be released as patch versions
- Subscribe to GitHub releases for notifications
- Check this SECURITY.md for updated guidance

---

Thank you for helping keep Cloudflare Email Panel and its users safe! 🔒