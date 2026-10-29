# Contributing to Cloudflare Email Panel

Thank you for your interest in contributing. This document explains how to report
issues, propose features, set up the project, and submit changes.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Security](#security)

## Code of Conduct

Please be respectful and inclusive in all interactions. Contributors are expected to:

- Use welcoming and inclusive language
- Respect differing viewpoints and experiences
- Accept constructive criticism gracefully
- Focus on what is best for the project and its users

## How to Contribute

### Reporting Bugs

Check existing issues before opening a new one. A useful bug report includes:

1. **Clear title** - summarize the issue concisely
2. **Steps to reproduce** - how to trigger the problem
3. **Expected behavior** - what should happen
4. **Actual behavior** - what happens instead
5. **Environment**:
   - Operating system
   - Node.js version
   - Browser (if applicable)
   - Docker version (if applicable)

### Suggesting Features

Feature requests are welcome. Include:

1. **Clear description** - what the feature does
2. **Use case** - why it is useful
3. **Possible implementation** - optional ideas or alternatives

### Contributing Code

1. **Fork** the repository
2. **Clone** your fork locally
3. **Create a branch** for your change
4. **Make changes** following the coding standards
5. **Test** the change locally
6. **Commit** with a clear message
7. **Push** to your fork
8. **Open a Pull Request**

## Development Setup

### Prerequisites

- Node.js 22 or higher
- npm
- Git
- Cloudflare account (for testing)
- Wrangler (only when deploying the Worker manually)

### Local Development

```bash
# Fork and clone the repo
git clone https://github.com/YOUR_USERNAME/Cloudflare-mail.git
cd Cloudflare-mail

# Install server and UI dependencies
npm ci
npm --prefix ui ci

# Copy the environment template
cp .env.example .env
```

Edit `.env` and set at least:

```env
APP_PASSWORD=your-strong-password
CLOUDFLARE_API_TOKEN=your_api_token
CLOUDFLARE_ACCOUNT_ID=your_account_id
```

Optional, for the Inbox feature:

```env
CLOUDFLARE_D1_DATABASE_ID=your_d1_database_id
```

Start both the API and the Vite dev server:

```bash
npm run dev
```

- API: `http://localhost:3000` (nodemon, hot reload)
- SPA: `http://localhost:5173` (Vite proxies `/api`, `/health`, and `/healthz` to the API)

To run only one side:

```bash
npm run dev:server
npm run dev:ui
```

### Building the Frontend

```bash
npm run build        # builds the React SPA into ui/dist
npm run build:css    # rebuilds public/styles.css for the legacy UI
```

The server serves `ui/dist` when it exists and falls back to `public/` otherwise.

## Project Structure

```
├── server.js                 # Express API server (main entry)
├── lib/
│   ├── auth.js               # Password login + HMAC session cookies
│   └── apiKeys.js            # Scoped API key store (hashed at rest)
├── ui/                       # React + TypeScript + Vite SPA
│   ├── src/pages/            # Overview, rules, addresses, inbox, settings, API docs
│   ├── src/components/       # App shell and shared components
│   └── src/lib/              # API client, types, helpers
├── public/                   # Legacy vanilla JS frontend (fallback)
├── src/tailwind.css          # Tailwind source for the legacy UI
├── worker/
│   ├── src/index.js          # Inbox Cloudflare Worker
│   ├── schema.sql            # D1 schema (emails, generated_addresses)
│   └── wrangler.toml.example
├── scripts/
│   ├── cliui.sh              # VPS CLI UI: install, run, stop, uninstall, update
│   ├── install_vps.sh        # Wrapper: cliui.sh install
│   ├── uninstall_vps.sh      # Wrapper: cliui.sh uninstall
│   ├── run_vps.sh            # Wrapper: cliui.sh run
│   ├── stop_vps.sh           # Wrapper: cliui.sh stop
│   ├── deploy_vps.sh         # App/Worker deployment helper
│   ├── cf-setup.mjs          # D1 + Worker + Email Routing provisioning
│   └── start-tunnel.bat      # Local server + tunnel helper (Windows)
├── docs/                     # Changelog, contributing, security, TODO
├── docker-compose.yml        # Production stack (panel + Caddy)
├── docker-compose.dokploy.yml# Dokploy deployment
├── Dockerfile
└── Caddyfile
```

## Testing

There is currently no automated test suite. Before opening a PR, verify the change
manually and run the UI checks.

### Manual Checklist

1. **Authentication**
   - Login with `APP_PASSWORD`
   - Logout clears the session
   - Invalid password is rejected and increments the lockout counter

2. **Panel operations**
   - List, create, and delete destinations
   - List, create, update, and delete rules
   - Catch-all configuration
   - Inbox listing and message deletion (when D1 is configured)

3. **API keys**
   - Create a key and confirm it is shown once
   - Call an API route with `Authorization: Bearer cfm_...`
   - Confirm a key without the required scope gets `403`
   - Revoke a key and confirm the next request gets `401`

4. **UI**
   - Check the change in Chrome, Firefox, Safari, and Edge
   - Verify light and dark modes
   - Verify the layout on mobile widths

### API Smoke Test

```bash
# Login and store the session cookie
curl -c cookies.txt -H "Content-Type: application/json" \
  -d '{"password":"your-password"}' \
  http://localhost:3000/api/auth/login

# Check auth state
curl -b cookies.txt http://localhost:3000/api/auth-status

# Health endpoints
curl http://localhost:3000/healthz
curl http://localhost:3000/health
```

### Frontend Checks

```bash
cd ui
npm run typecheck
npm run lint
npm run build
```

## Pull Request Process

### Before You Start

- Check existing issues and PRs to avoid duplicates
- For large changes, open an issue first to discuss the approach

### Creating Your PR

- Use a descriptive title
- Reference related issues (e.g. "Fixes #42")
- Describe what changed and why
- Include screenshots for UI changes

### PR Requirements

- [ ] Code follows the project style
- [ ] Changes have been tested locally
- [ ] UI typecheck, lint, and build pass (if the UI changed)
- [ ] Documentation updated (if applicable)
- [ ] No new console errors or warnings
- [ ] Commit messages are clear and descriptive

### Review Process

- Maintainers review the PR
- You may be asked to make changes
- Once approved, the PR is merged

## Coding Standards

### JavaScript / TypeScript

- Use modern ES syntax
- Use `const` by default, `let` only when reassignment is needed
- Avoid `var`
- Use meaningful names
- Comment only complex logic
- Keep functions focused and small
- Follow the existing style in `server.js`, `lib/`, and `ui/src/`

### Example

```javascript
// Good
async function fetchDestinations() {
  try {
    const response = await cf.get('/email/routing/addresses');
    return response.data.result;
  } catch (error) {
    console.error('Failed to fetch destinations:', error);
    throw error;
  }
}

// Bad
async function fd() {
  const r = await cf.get('/email/routing/addresses');
  return r.data.result;
}
```

### React and CSS

- Prefer function components and hooks
- Reuse the existing components and utilities in `ui/src`
- Follow the shadcn/ui and Tailwind conventions already in the project
- Ensure responsive behavior and dark-mode support

### Git Commits

Use clear, descriptive messages:

```bash
# Good
git commit -m "Add rate limiting to login endpoint"
git commit -m "Fix pagination for email destinations"
git commit -m "Update README with API documentation"

# Bad
git commit -m "fix"
git commit -m "update"
git commit -m "changes"
```

## Security

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Use the private advisory form:
<https://github.com/baaaaan1/Cloudflare-mail/security/advisories/new>

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

Allow time for a fix before any public disclosure. See
[`SECURITY.md`](SECURITY.md) for the full policy.

### Handling Secrets

- Never commit `.env`, `DATA_DIR`, API keys, or Cloudflare tokens
- Do not log credentials or session cookies
- Use placeholders in documentation and examples

## Questions

1. Check the existing documentation in `README.md` and `docs/`
2. Search existing issues
3. Open an issue for clarification
