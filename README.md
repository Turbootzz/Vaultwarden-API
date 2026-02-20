# 🔐 Vaultwarden API

> **Stop using `.env` files.** Fetch secrets directly from your self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden) instance at runtime.

A lightweight, production-ready Go API that acts as a secrets bridge between your apps and Vaultwarden. No more scattered `.env` files, no more accidentally committed credentials.

## ✨ Highlights

- **🚀 Zero external dependencies** — Pure Go binary, no Node.js, no Bitwarden CLI
- **🔒 Native Bitwarden crypto** — AES-256-CBC + HMAC-SHA256, PBKDF2/Argon2id key derivation
- **♻️ Auto token refresh** — Never worry about expired sessions again
- **📦 ~15MB Docker image** — Alpine-based, runs as non-root
- **🛡️ Defense in depth** — API key auth, IP whitelisting, rate limiting, security headers
- **⚡ Background vault sync** — Secrets always up-to-date (configurable interval)
- **🏭 Production-ready** — Health checks, graceful shutdown, structured logging

## Architecture

```
┌─────────────┐    HTTPS + API Key    ┌──────────────────────┐    Native Go    ┌──────────────┐
│  Your App   │ ────────────────────> │  Vaultwarden API     │ ──────────────> │  Vaultwarden │
│  (any lang) │ <──────────────────── │  (Go, ~15MB image)   │ <────────────── │  Server      │
└─────────────┘    JSON response      │                      │  Encrypted API  └──────────────┘
                                      │  • Auto token refresh│
                                      │  • Background sync   │
                                      │  • In-memory cache   │
                                      │  • IP whitelisting   │
                                      └──────────────────────┘
```

**How it works under the hood:**
1. Authenticates with Vaultwarden using your master password (same as the web vault)
2. Derives encryption keys using PBKDF2-SHA256 or Argon2id (server-negotiated)
3. Decrypts your vault items in-memory using AES-256-CBC
4. Serves secrets via a simple REST API with API key authentication
5. Periodically re-syncs the vault and auto-refreshes auth tokens

## Quick Start

### 1. Pull and run with Docker

```bash
docker run -d \
  --name vaultwarden-api \
  -p 8080:8080 \
  -e VAULTWARDEN_URL=https://vault.yourdomain.com \
  -e VAULTWARDEN_EMAIL=you@example.com \
  -e VAULTWARDEN_PASSWORD=your-master-password \
  -e API_KEY=$(openssl rand -base64 32) \
  ghcr.io/turbootzz/vaultwarden-api:latest
```

### 2. Fetch a secret

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:8080/secret/DATABASE_URL
```

```json
{
  "name": "DATABASE_URL",
  "value": "postgresql://user:pass@db:5432/myapp"
}
```

That's it. Your app reads secrets from the API instead of `.env` files.

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | No | Health check |
| `GET` | `/secret/:name` | API Key | Fetch a secret by name |
| `POST` | `/refresh` | API Key | Force vault re-sync |

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VAULTWARDEN_URL` | **Yes** | — | Your Vaultwarden instance URL |
| `VAULTWARDEN_EMAIL` | **Yes** | — | Your Vaultwarden email |
| `VAULTWARDEN_PASSWORD` | **Yes** | — | Your master password |
| `API_KEY` | **Yes** | — | API key for this service (min 32 chars) |
| `ALLOWED_IPS` | No | (all) | Comma-separated IPs/CIDRs to whitelist |
| `ENABLE_GITHUB_IP_RANGES` | No | `false` | Auto-whitelist GitHub Actions IPs |
| `SYNC_INTERVAL` | No | `5m` | How often to re-sync the vault |
| `CACHE_TTL` | No | `5m` | Secret cache duration |
| `TRUSTED_PROXY_IP` | No | `localhost` | Trusted reverse proxy IPs |
| `ENVIRONMENT` | No | `development` | Set to `production` to hide errors |
| `DEBUG` | No | `false` | Enable debug logging |

## Docker Compose

```yaml
services:
  vaultwarden-api:
    image: ghcr.io/turbootzz/vaultwarden-api:latest
    container_name: vaultwarden-api
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      - VAULTWARDEN_URL=${VAULTWARDEN_URL}
      - VAULTWARDEN_EMAIL=${VAULTWARDEN_EMAIL}
      - VAULTWARDEN_PASSWORD=${VAULTWARDEN_PASSWORD}
      - API_KEY=${API_KEY}
      - ENVIRONMENT=production
      - ALLOWED_IPS=${ALLOWED_IPS}
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 128M
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:8080/health"]
      interval: 30s
      timeout: 3s
      retries: 3
```

## Usage Examples

### Shell / CI Pipeline
```bash
DB_URL=$(curl -sf -H "Authorization: Bearer $API_KEY" \
  https://api.yourdomain.com/secret/DATABASE_URL | jq -r '.value')
```

### Python
```python
import requests

def get_secret(name):
    r = requests.get(f"https://api.yourdomain.com/secret/{name}",
                     headers={"Authorization": f"Bearer {API_KEY}"})
    return r.json()["value"]

db_url = get_secret("DATABASE_URL")
```

### Node.js
```javascript
const res = await fetch(`https://api.yourdomain.com/secret/DATABASE_URL`, {
  headers: { Authorization: `Bearer ${API_KEY}` },
});
const { value } = await res.json();
```

### Go
```go
req, _ := http.NewRequest("GET", "https://api.yourdomain.com/secret/DATABASE_URL", nil)
req.Header.Set("Authorization", "Bearer "+apiKey)
resp, _ := http.DefaultClient.Do(req)
```

### GitHub Actions
```yaml
- name: Fetch secrets
  run: |
    export DB_URL=$(curl -sf -H "Authorization: Bearer ${{ secrets.VAULT_API_KEY }}" \
      https://api.yourdomain.com/secret/DATABASE_URL | jq -r '.value')
```

## Security

- **API key authentication** with constant-time comparison (timing-attack resistant)
- **IP whitelisting** with CIDR support + optional GitHub Actions IP auto-import
- **Rate limiting** (30 requests/minute per IP)
- **Read-only filesystem** in Docker (only `/tmp` writable)
- **Non-root user** in container
- **No capabilities** (`cap_drop: ALL`)
- **Security headers** via Helmet middleware
- **No secret names in production logs** (only at debug level)
- Secrets are **decrypted in-memory only** — never written to disk

## Project Structure

```
├── cmd/api/main.go                    # Entry point
├── internal/
│   ├── auth/middleware.go             # API key authentication
│   ├── config/config.go              # Configuration
│   ├── handlers/handlers.go          # HTTP handlers
│   ├── ipwhitelist/ipwhitelist.go    # IP access control
│   ├── validators/validators.go      # Input validation
│   └── vaultwarden/
│       ├── api_client.go             # Native HTTP client for Vaultwarden
│       ├── crypto.go                 # Bitwarden-compatible encryption
│       ├── crypto_test.go            # Crypto unit tests
│       ├── client.go                 # Secret lookup + caching
│       └── init.go                   # Initialization with retry
├── pkg/logger/logger.go              # Structured logging
├── Dockerfile                        # Multi-stage build (~15MB image)
├── docker-compose.yml                # Production-ready compose
└── go.mod
```

## Building from Source

```bash
# Build
go build -o vaultwarden-api ./cmd/api

# Test
go test ./...

# Docker
docker build -t vaultwarden-api .
```

## How Secrets are Matched

When you request `/secret/DATABASE_URL`, the API:

1. **Exact match** (case-insensitive) against vault item names
2. **Partial match** if no exact match is found
3. Returns the most relevant value: password → custom field → notes

This means you can name your Vaultwarden items naturally (e.g., "Database URL") and fetch them with any casing.

## Contributing

Contributions welcome! Fork → branch → PR.

## License

MIT — see [LICENSE](LICENSE)

---

**Built by [Thijs Herman](https://github.com/Turbootzz)** — because `.env` files are so 2020.
