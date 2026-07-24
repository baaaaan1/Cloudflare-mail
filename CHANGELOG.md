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

## [Unreleased]

### Planned Features
- [ ] Email filtering rules
- [ ] Bulk destination management
- [ ] Email analytics
- [ ] Webhook notifications
- [ ] Multi-user support
- [ ] Export/Import settings
- [ ] Two-factor authentication

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2025-07-24 | Initial release |