# Vaultwarden API Proxy

A secure, lightweight Go API that acts as a proxy between your local apps and Vaultwarden (self-hosted Bitwarden server). Use it as a replacement for `.env` files in development and production environments.

## Features

- **Secure**: API key authentication, IP whitelisting, constant-time comparison, no sensitive logging
- **Lightweight**: ~15MB Docker image, minimal resource usage
- **Fast**: Built-in caching with configurable TTL
- **Simple**: Clean architecture, easy to deploy and maintain
- **Production-ready**: Rate limiting, health checks, graceful shutdown, security headers
- **IP Whitelisting**: Restrict access by IP/CIDR with optional GitHub Actions support

## Architecture

```
┌─────────────┐     HTTPS + API Key     ┌──────────────────┐
│  Your App   │ ───────────────────────> │ Vaultwarden API  │
└─────────────┘                          │     Proxy        │
                                         └──────────────────┘
                                                  │
                                                  │ Vaultwarden API
                                                  ▼
                                         ┌──────────────────┐
                                         │  Vaultwarden     │
                                         │    Server        │
                                         └──────────────────┘
```

## Project Structure

```
.
├── cmd/
│   └── api/
│       └── main.go              # Application entry point
├── internal/
│   ├── auth/
│   │   └── middleware.go        # API key authentication
│   ├── config/
│   │   └── config.go           # Configuration management
│   ├── handlers/
│   │   └── handlers.go         # HTTP handlers
│   ├── ipwhitelist/
│   │   └── ipwhitelist.go      # IP-based access control
│   ├── validators/
│   │   └── validators.go       # Input validation
│   └── vaultwarden/
│       ├── client.go           # Vaultwarden client
│       ├── client_cli.go       # CLI-based secret retrieval
│       └── init.go             # Bitwarden CLI initialization
├── pkg/
│   └── logger/
│       └── logger.go           # Secure logging
├── .env.example                # Environment variables template
├── .gitignore                  # Git ignore rules
├── Dockerfile                  # Multi-stage Docker build
├── docker-compose.yml          # Docker Compose configuration
├── go.mod                      # Go module definition
├── go.sum                      # Go module checksums
├── Makefile                    # Build automation
└── README.md                   # This file
```

## Quick Start

### Prerequisites

- Go 1.25+ (for local development)
- Docker & Docker Compose (for containerized deployment)
- Vaultwarden instance with API access

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/turbootzz/vaultwarden-api.git
   cd vaultwarden-api
   ```

2. **Create environment file**
   ```bash
   cp .env.example .env
   ```

3. **Configure your `.env` file**
   ```bash
   # Generate a strong API key
   make generate-api-key

   # Edit .env and add:
   # - API_KEY (generated above)
   # - VAULTWARDEN_URL (your Vaultwarden instance URL)
   # - VAULTWARDEN_CLIENT_ID, VAULTWARDEN_CLIENT_SECRET, VAULTWARDEN_PASSWORD
   #   (from Vaultwarden Account Settings → Security → Keys → View API Key)
   # - ALLOWED_IPS (your IP address or CIDR range for security)
   ```

4. **Run the application**
   ```bash
   make run
   ```

### Docker Deployment

1. **Build the Docker image**
   ```bash
   make docker-build
   ```

2. **Run with Docker Compose**
   ```bash
   make docker-compose-up
   ```

## API Endpoints

### Health Check
```bash
curl http://localhost:8080/health
```
**Response:**
```json
{
  "status": "ok",
  "service": "vaultwarden-api"
}
```

### Get Secret
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:8080/secret/DATABASE_URL
```
**Response:**
```json
{
  "name": "DATABASE_URL",
  "value": "postgresql://user:pass@localhost:5432/db"
}
```

### Refresh Cache
```bash
curl -X POST \
     -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:8080/refresh
```
**Response:**
```json
{
  "status": "ok",
  "message": "cache cleared successfully"
}
```

## Configuration

All configuration is done via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `API_PORT` | No | `8080` | Port the API listens on |
| `ENVIRONMENT` | No | `development` | Environment (development/production) |
| `API_KEY` | **Yes** | - | API key for authentication (min 32 chars) |
| `VAULTWARDEN_URL` | **Yes** | - | Vaultwarden instance URL |
| `VAULTWARDEN_CLIENT_ID` | **Yes*** | - | Vaultwarden API client ID |
| `VAULTWARDEN_CLIENT_SECRET` | **Yes*** | - | Vaultwarden API client secret |
| `VAULTWARDEN_PASSWORD` | **Yes*** | - | Your Vaultwarden master password |
| `VAULTWARDEN_ACCESS_TOKEN` | **Yes*** | - | Alternative: pre-generated session token |
| `ALLOWED_IPS` | No | - | Comma-separated IPs/CIDRs to whitelist |
| `ENABLE_GITHUB_IP_RANGES` | No | `false` | Allow GitHub Actions IPs (updates every 24h) |
| `TRUSTED_PROXY_IP` | No | `localhost` | Trusted reverse proxy IPs/CIDRs |
| `CORS_ALLOWED_ORIGINS` | No | `localhost:3000` | CORS allowed origins |
| `CACHE_TTL` | No | `5m` | Cache duration (0 to disable) |
| `READ_TIMEOUT` | No | `10s` | HTTP read timeout |
| `WRITE_TIMEOUT` | No | `10s` | HTTP write timeout |
| `DEBUG` | No | `false` | Enable debug logging |

**\*Note:** Either use `VAULTWARDEN_CLIENT_ID` + `VAULTWARDEN_CLIENT_SECRET` + `VAULTWARDEN_PASSWORD` (recommended) OR `VAULTWARDEN_ACCESS_TOKEN` (will expire).

## Getting Vaultwarden API Credentials

### Recommended Method: API Key Authentication

1. **Get API Credentials from Vaultwarden Web UI**:
   - Log into your Vaultwarden instance
   - Go to **Account Settings** → **Security** → **Keys**
   - Click **View API Key**
   - You'll see:
     - `client_id` (starts with `user.`)
     - `client_secret` (long random string)
   - Add these to your `.env` as `VAULTWARDEN_CLIENT_ID` and `VAULTWARDEN_CLIENT_SECRET`
   - Add your master password as `VAULTWARDEN_PASSWORD`

2. **Benefits**:
   - ✅ Bypasses 2FA
   - ✅ Automatically logs in on startup
   - ✅ Never expires
   - ✅ More secure than session tokens

### Alternative Method: Session Token

1. **Generate a session token manually**:
   ```bash
   # Login and unlock your vault
   bw config server https://vault.yourdomain.com
   bw login
   SESSION_TOKEN=$(bw unlock --raw)
   echo $SESSION_TOKEN
   ```

2. **Add to `.env`**:
   ```bash
   VAULTWARDEN_ACCESS_TOKEN=your-session-token-here
   ```

3. **Limitations**:
   - ⚠️ Tokens expire after inactivity
   - ⚠️ Requires manual regeneration
   - ⚠️ Not recommended for production

## IP Whitelisting

The API supports IP-based access control for enhanced security.

### Configuration

**Allow specific IPs:**
```bash
ALLOWED_IPS=203.0.113.50
```

**Allow multiple IPs:**
```bash
ALLOWED_IPS=203.0.113.50,198.51.100.25
```

**Allow CIDR ranges:**
```bash
ALLOWED_IPS=192.168.1.0/24
```

**Mix IPs and CIDRs:**
```bash
ALLOWED_IPS=203.0.113.50,192.168.1.0/24,10.0.0.0/8
```

**Enable GitHub Actions (optional):**
```bash
ENABLE_GITHUB_IP_RANGES=true
```
This automatically whitelists all GitHub Actions IP ranges and updates them every 24 hours.

### Trusted Proxies

If you're running behind a reverse proxy (Nginx Proxy Manager, Traefik, Cloudflare), configure trusted proxies:

**Single proxy IP:**
```bash
TRUSTED_PROXY_IP=172.18.0.5
```

**Docker network range:**
```bash
TRUSTED_PROXY_IP=172.16.0.0/12
```

**Multiple proxies:**
```bash
TRUSTED_PROXY_IP=172.18.0.5,192.168.1.10
```

**Important Notes:**
- Invalid IPs/CIDRs are logged and ignored
- Duplicates are automatically removed
- The API extracts real client IPs from `X-Forwarded-For` header
- If no whitelist is configured, all IPs are allowed (not recommended for production)

## Deployment Guide

### Deploy to Portainer

1. **Prepare your environment**
   - Ensure Vaultwarden is accessible from the Portainer host
   - Have your API credentials ready

2. **Create a new Stack in Portainer**
   - Navigate to Stacks → Add Stack
   - Name it `vaultwarden-api`
   - Paste the contents of `docker-compose.yml`

3. **Set environment variables in Portainer**
   - Click "Add environment variable"
   - Add all required variables (see Configuration table)
   - **RECOMMENDED**: Add `ALLOWED_IPS` with your IP address
   - **IMPORTANT**: Never hardcode secrets in the stack file

4. **Deploy the stack**
   - Click "Deploy the stack"
   - Monitor logs for any errors

5. **Set up reverse proxy**
   - Use Nginx Proxy Manager, Traefik, or similar
   - Configure HTTPS with Let's Encrypt
   - Point to `vaultwarden-api:8080`

### Deploy Behind Nginx Proxy Manager

1. **Add a new Proxy Host**
   - Domain: `api.yourdomain.com`
   - Forward to: `vaultwarden-api:8080`
   - Enable "Block Common Exploits"
   - Enable "Websockets Support"

2. **Configure SSL**
   - Request a new SSL certificate (Let's Encrypt)
   - Force SSL
   - Enable HTTP/2

3. **Add custom headers** (optional)
   ```
   X-Real-IP $remote_addr
   X-Forwarded-For $proxy_add_x_forwarded_for
   X-Forwarded-Proto $scheme
   ```

## Security Best Practices

### For Public Repositories

- ✅ Use `.env.example` (committed) for documentation
- ✅ Add `.env` to `.gitignore` (already done)
- ✅ Never commit actual credentials
- ✅ Use Portainer's environment variable feature
- ✅ Rotate API keys regularly
- ✅ Use strong, randomly generated API keys

### For Private Repositories

- ✅ Still use `.env.example` for documentation
- ✅ Still never commit `.env` files
- ✅ Use secret managers (e.g., Docker secrets, Vault)
- ✅ Implement additional authentication if needed
- ✅ Monitor access logs

### Production Deployment

1. **Always use HTTPS** via reverse proxy
2. **Enable IP whitelisting** - Set `ALLOWED_IPS` to your trusted IPs/networks
3. **Configure trusted proxies** - Set `TRUSTED_PROXY_IP` to your reverse proxy range
4. **Restrict CORS** to specific domains via `CORS_ALLOWED_ORIGINS`
5. **Set ENVIRONMENT=production** to hide detailed error messages
6. **Use API key authentication** (not session tokens) for reliability
7. **Enable rate limiting** (already configured: 30 req/min)
8. **Use read-only filesystem** (already in docker-compose)
9. **Run as non-root user** (already in Dockerfile)
10. **Monitor logs** for suspicious activity and blocked IPs
11. **Use Docker secrets** instead of environment variables when possible
12. **Regular security updates** (rebuild images monthly)
13. **Enable DEBUG=false** in production (default)

## Usage Examples

### From a Shell Script
```bash
#!/bin/bash

API_KEY="your-api-key"
API_URL="https://api.yourdomain.com"

# Fetch database URL
DB_URL=$(curl -s -H "Authorization: Bearer $API_KEY" \
  "$API_URL/secret/DATABASE_URL" | jq -r '.value')

echo "Database URL: $DB_URL"
```

### From Python
```python
import requests

API_KEY = "your-api-key"
API_URL = "https://api.yourdomain.com"

def get_secret(name):
    headers = {"Authorization": f"Bearer {API_KEY}"}
    response = requests.get(f"{API_URL}/secret/{name}", headers=headers)
    return response.json()["value"]

# Usage
db_url = get_secret("DATABASE_URL")
print(f"Database URL: {db_url}")
```

### From Node.js
```javascript
const axios = require('axios');

const API_KEY = 'your-api-key';
const API_URL = 'https://api.yourdomain.com';

async function getSecret(name) {
  const response = await axios.get(`${API_URL}/secret/${name}`, {
    headers: { 'Authorization': `Bearer ${API_KEY}` }
  });
  return response.data.value;
}

// Usage
(async () => {
  const dbUrl = await getSecret('DATABASE_URL');
  console.log(`Database URL: ${dbUrl}`);
})();
```

## Makefile Commands

```bash
make help              # Show available commands
make build             # Build the binary
make run              # Run locally (requires .env)
make dev              # Run with hot reload
make test             # Run tests
make clean            # Clean build artifacts
make docker-build     # Build Docker image
make docker-run       # Run Docker container
make docker-push      # Push to Docker Hub
make generate-api-key # Generate a random API key
```

## Troubleshooting

### "Failed to load configuration: API_KEY is required"
- Make sure you have a `.env` file in the project root
- Copy `.env.example` to `.env` and fill in all required values

### "Secret not found"
- Verify the secret name matches exactly (case-sensitive)
- Check that your Vaultwarden token has access to the vault
- Use the Vaultwarden web UI to confirm the secret exists

### "Vaultwarden api returned status 401"
- Your credentials are invalid or expired
- For API key method: Check `VAULTWARDEN_CLIENT_ID`, `VAULTWARDEN_CLIENT_SECRET`, `VAULTWARDEN_PASSWORD`
- For session token: Generate a new `VAULTWARDEN_ACCESS_TOKEN`

### "IP blocked (not whitelisted)"
- Your IP is not in the `ALLOWED_IPS` list
- Check your current public IP: `curl ifconfig.me`
- Add your IP to `ALLOWED_IPS` in `.env` or Portainer
- If behind a proxy, ensure `TRUSTED_PROXY_IP` is set correctly
- Enable `DEBUG=true` to see which IP is being detected

### "Failed to initialize Bitwarden CLI"
- Ensure Bitwarden CLI is installed in the Docker container (already done)
- Check that `VAULTWARDEN_URL` is accessible from the container
- Verify your master password is correct
- Check logs for specific error messages

### Docker build fails
- Ensure you have the latest Go version in Dockerfile
- Run `go mod tidy` before building
- Check for network issues when downloading dependencies

## Recent Enhancements

- ✅ **IP Whitelisting** - CIDR support, GitHub Actions IPs, automatic validation
- ✅ **CLI Authentication** - Bitwarden CLI integration with API key support
- ✅ **Trusted Proxies** - Proper client IP detection behind reverse proxies
- ✅ **Input Validation** - Secure secret name validation
- ✅ **Debug Logging** - Optional debug mode for troubleshooting

## Future Enhancements

- [ ] Support for multiple Vaultwarden instances
- [ ] JWT-based authentication (in addition to API keys)
- [ ] Token rotation mechanism
- [ ] Metrics and monitoring (Prometheus)
- [ ] Support for secret versioning
- [ ] Webhook notifications for secret changes
- [ ] Redis-based distributed cache
- [ ] Rate limiting per API key
- [ ] Audit logging
- [ ] GraphQL API

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Disclaimer

This is a security-sensitive tool. Please:
- Review the code before deploying to production
- Keep your API keys and tokens secure
- Monitor access logs regularly
- Report security issues privately



---

**Made by Thijs Herman**