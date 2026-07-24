# Contributing to Cloudflare Email Panel

Thank you for your interest in contributing! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)

## Code of Conduct

Please be respectful and inclusive in all interactions. We expect contributors to:

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Accept constructive criticism gracefully
- Focus on what is best for the community

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates.

When filing a bug report, include:

1. **Clear title** - Summarize the issue concisely
2. **Steps to reproduce** - List steps to replicate the problem
3. **Expected behavior** - What you expected to happen
4. **Actual behavior** - What actually happened
5. **Environment details**:
   - Operating system
   - Node.js version
   - Browser (if applicable)
   - Docker version (if using Docker)

### Suggesting Features

Feature requests are welcome! Please include:

1. **Clear description** - Explain the feature's purpose
2. **Use case** - Why this feature would be useful
3. **Possible implementation** - If you have ideas on how to implement it

### Contributing Code

1. **Fork** the repository
2. **Clone** your fork locally
3. **Create a branch** for your feature/fix
4. **Make changes** following our coding standards
5. **Test** your changes thoroughly
6. **Commit** with clear messages
7. **Push** to your fork
8. **Submit a Pull Request**

## Development Setup

### Prerequisites

- Node.js 22 or higher
- npm
- Git
- Cloudflare account (for testing)

### Local Development

```bash
# Fork and clone the repo
git clone https://github.com/YOUR_USERNAME/Cloudflare-mail.git
cd Cloudflare-mail

# Install dependencies
npm ci

# Copy environment template
cp .env.example .env

# Edit .env with your Cloudflare credentials
# At minimum, you need:
# - CLOUDFLARE_API_TOKEN
# - CLOUDFLARE_ACCOUNT_ID

# Start development server
npm run dev
```

The server starts with hot-reload at `http://localhost:3000`.

### Project Structure

```
├── server.js              # Express API server (main entry)
├── public/                # Frontend files
│   ├── index.html         # Main HTML
│   ├── main.js            # Frontend logic
│   ├── styles.css         # Styles
│   ├── bgStars.js         # Background animation
│   └── theme-init.js      # Theme initialization
├── worker/                # Cloudflare Worker
│   ├── src/index.js       # Worker code
│   ├── schema.sql         # D1 database schema
│   └── wrangler.toml.example
├── scripts/               # Deployment scripts
├── docker-compose.yml     # Docker stack
├── Dockerfile             # Container build
└── Caddyfile              # Reverse proxy config
```

## Pull Request Process

### 1. Before You Start

- Check existing issues and PRs to avoid duplicates
- For large changes, open an issue first to discuss the approach

### 2. Creating Your PR

- Use a descriptive title
- Reference related issues (e.g., "Fixes #42")
- Provide a clear description of changes
- Include screenshots for UI changes

### 3. PR Requirements

- [ ] Code follows project style guidelines
- [ ] Changes have been tested locally
- [ ] Documentation updated (if applicable)
- [ ] No console errors or warnings
- [ ] Commit messages are clear and descriptive

### 4. Review Process

- Maintainers will review your PR
- You may be asked to make changes
- Once approved, your PR will be merged

## Coding Standards

### JavaScript Style

- Use modern ES6+ syntax
- Use `const` by default, `let` when reassignment is needed
- Avoid `var`
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and small

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

### HTML/CSS

- Use semantic HTML elements
- Follow BEM naming convention for CSS classes
- Ensure responsive design
- Test in multiple browsers

### Git Commits

Use clear, descriptive commit messages:

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

## Testing

### Manual Testing

Before submitting a PR, test:

1. **Authentication flow**
   - Password setup
   - Login/logout
   - Session persistence

2. **CRUD operations**
   - Create/read/update/delete destinations
   - Create/read/update/delete rules
   - Inbox operations (if configured)

3. **Edge cases**
   - Empty states
   - Error handling
   - Rate limiting

4. **Browser compatibility**
   - Chrome
   - Firefox
   - Safari
   - Edge

### API Testing

Use curl or Postman to test API endpoints:

```bash
# Test health endpoint
curl http://localhost:3000/healthz

# Test auth status
curl http://localhost:3000/api/auth-status
```

## Security

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead, please email security concerns directly to the maintainer.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

Allow time for a fix before any public disclosure.

## Questions?

If you have questions about contributing:

1. Check existing documentation
2. Search existing issues
3. Open a new issue for clarification

Thank you for contributing! 🎉