# Cloudflare Email Panel

[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-22+-green.svg)](https://nodejs.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![Cloudflare](https://img.shields.io/badge/Cloudflare-Required-orange.svg)](https://www.cloudflare.com/)

Self-hosted panel to manage Cloudflare Email Routing, destinations, rules, and inbox (via D1). Production uses Docker, Caddy, and automatic HTTPS.

## Screenshot

![Cloudflare Email Panel](screenshots/cfmail.jpg)

## Features

- **Email Routing Management** - Create, update, and delete forwarding rules
- **Destinations** - Manage email destinations (forwarding addresses)
- **Inbox System** - Store incoming emails using Cloudflare D1 + Worker
- **Catch-All Rules** - Configure catch-all email routing
- **Worker Integration** - Route emails to Cloudflare Workers
- **Password Protection** - Secure your panel with password authentication
- **Diagnostics** - Check Cloudflare API connectivity and permissions
- **Dark Mode** - Beautiful dark theme with responsive design
- **Security First** - CSP, HSTS, rate limiting, and more

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Your VPS                               │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐     ┌─────────────────────────────────────┐   │
│  │  Caddy  │────▶│        Cloudflare Email Panel        │   │
│  │ (HTTPS) │     │            (Node.js)                 │   │
│  └─────────┘     └─────────────────────────────────────┘   │
│   :80, :443                    :3000                        │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   Cloudflare                                 │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │Email Routing │  │   Workers   │  │    D1 Database      │ │
│  │   (Rules)   │  │  (Inbox)    │  │   (Email Storage)   │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- **VPS**: Ubuntu or Debian with root access
- **Cloudflare Account**: With Email Routing enabled
- **Domain**: Added to Cloudflare with DNS pointing to your VPS
- **Firewall**: Ports 80 and 443 open
- **SSL/TLS Mode**: Full (strict) in Cloudflare

## Quick Start (Docker)

### 1. Clone the repository

```bash
git clone https://github.com/baaaaan1/Cloudflare-mail.git
cd Cloudflare-mail
```

### 2. Run the installer

```bash
sudo bash scripts/install_vps.sh
```

The installer will:
- Install Docker Engine + Compose (if not present)
- Create `.env` from template
- Prompt for your domain
- Open `.env` for editing
- Build and start the containers

### 3. Configure credentials

Edit `.env` with your Cloudflare credentials:

```env
PORT=3000
CADDY_DOMAIN=your-domain.com
CLOUDFLARE_API_TOKEN=your_api_token
CLOUDFLARE_ACCOUNT_ID=your_account_id
CLOUDFLARE_D1_DATABASE_ID=your_d1_database_id
PASSWORD_HASH=
PASSWORD_SALT=
```

### 4. Set up password

1. Open your panel at `https://your-domain.com`
2. You'll see the setup screen
3. Enter your desired password (minimum 8 characters)
4. The password hash will be saved to `.env`

### 5. Access your panel

```
https://your-domain.com
```

## Manual Installation (without Docker)

### 1. Install Node.js 22+

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### 2. Clone and install dependencies

```bash
git clone https://github.com/baaaaan1/Cloudflare-mail.git
cd Cloudflare-mail
npm ci
```

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env with your credentials
```

### 4. Start the server

```bash
npm start
```

The panel will be available at `http://localhost:3000`.

## Configuration Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Server port (default: 3000) |
| `CADDY_DOMAIN` | Yes | Your domain (e.g., `mail.example.com`) |
| `CLOUDFLARE_API_TOKEN` | Yes | Cloudflare API token with required permissions |
| `CLOUDFLARE_ACCOUNT_ID` | Yes | Your Cloudflare account ID |
| `CLOUDFLARE_D1_DATABASE_ID` | No | D1 database ID (required for inbox feature) |
| `PASSWORD_HASH` | No | Password hash (set via panel setup) |
| `PASSWORD_SALT` | No | Password salt (set via panel setup) |

### Cloudflare API Token Permissions

Create a custom API token with these permissions:

- **Zone** → Email Routing → Edit
- **Zone** → Zone → Read
- **Account** → Workers Scripts → Edit (if using Workers)
- **Account** → D1 → Edit (if using Inbox)

## API Reference

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth-status` | GET | Check authentication status |
| `/api/login` | POST | Login with password |
| `/api/logout` | POST | Logout |
| `/api/setup-password` | POST | Initial password setup |

### Destinations

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/destinations` | GET | List all destinations |
| `/api/destinations` | POST | Create new destination |
| `/api/destinations/:id` | DELETE | Delete destination |

### Rules

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/rules` | GET | List rules (requires `zoneId`) |
| `/api/rules` | POST | Create new rule |
| `/api/rules/:id` | PUT | Update rule |
| `/api/rules/:id` | DELETE | Delete rule |

### Inbox

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/inbox/summary` | GET | Get inbox summary by recipient |
| `/api/inbox` | GET | List emails (supports `limit`, `offset`, `recipient`) |
| `/api/inbox/:id` | GET | Get email details |
| `/api/inbox/:id` | DELETE | Delete email |
| `/api/inbox/init` | POST | Initialize D1 database |

### Configuration

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/config` | GET | Get current config |
| `/api/config` | POST | Update config |
| `/api/diagnostics` | GET | Check API connectivity |

### Health

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/healthz` | GET | Liveness check |
| `/health` | GET | Health check with API verification |

## Worker Setup (Inbox)

The Worker stores incoming emails in D1 for viewing in the panel.

### 1. Create D1 Database

```bash
npx wrangler d1 create email-db
```

Note the `database_id` and add it to `.env`.

### 2. Configure Worker

```bash
cp worker/wrangler.toml.example worker/wrangler.toml
```

Edit `worker/wrangler.toml` and set `database_id`.

### 3. Deploy Worker

```bash
npm run deploy:worker
```

Or from VPS:

```bash
bash scripts/deploy_vps.sh --deploy-worker
```

### 4. Setup Email Routing

In Cloudflare Dashboard → Email Routing:
1. Add a catch-all rule or specific rule
2. Set action to "Send to Worker"
3. Select `inbox-worker`

## Development

### Local Development

```bash
cp .env.example .env
npm ci
npm run dev
```

The server will start with hot-reload at `http://localhost:3000`.

### Project Structure

```
├── server.js              # Express API server
├── public/                # Frontend (vanilla JS)
│   ├── index.html
│   ├── main.js
│   ├── styles.css
│   └── ...
├── worker/                # Cloudflare Worker
│   ├── src/index.js
│   ├── schema.sql
│   └── wrangler.toml.example
├── scripts/
│   ├── install_vps.sh     # AIO installer
│   └── deploy_vps.sh      # Deploy script
├── docker-compose.yml     # Production stack
├── Dockerfile             # Node.js container
├── Caddyfile              # Reverse proxy config
└── .env.example           # Environment template
```

### Available Scripts

```bash
npm start          # Start production server
npm run dev        # Start development server with hot-reload
npm run deploy:worker  # Deploy Cloudflare Worker
```

## Security

- **Password Authentication** - Secure your panel with a password
- **Rate Limiting** - Protection against brute-force attacks
- **CSP Headers** - Content Security Policy to prevent XSS
- **HSTS** - HTTP Strict Transport Security
- **Secure Cookies** - HttpOnly, SameSite=Strict
- **No Sensitive Data in Git** - `.env` and credentials are gitignored

### Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

1. **DO NOT** open a public GitHub issue
2. Email security concerns to: [your-email@example.com]
3. Allow time for a fix before public disclosure

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Cloudflare](https://www.cloudflare.com/) for Email Routing, Workers, and D1
- [Caddy](https://caddyserver.com/) for automatic HTTPS
- [Express.js](https://expressjs.com/) for the web framework
- [PostalMime](https://github.com/nicktomlin/postal-mime) for email parsing

## Support

- **Documentation**: Read this README
- **Issues**: [GitHub Issues](https://github.com/baaaaan1/Cloudflare-mail/issues)
- **Discussions**: [GitHub Discussions](https://github.com/baaaaan1/Cloudflare-mail/discussions)

---

Made with ☕ by [baaaaan1](https://github.com/baaaaan1)
