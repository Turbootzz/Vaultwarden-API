# Vaultwarden API Proxy

A secure, lightweight Go API that acts as a proxy between your local apps and Vaultwarden (self-hosted Bitwarden server). Use it as a replacement for `.env` files in development and production environments.

## Features

- **Secure**: API key authentication, HTTPS-ready, constant-time comparison, no sensitive logging
- **Lightweight**: ~15MB Docker image, minimal resource usage
- **Fast**: Built-in caching with configurable TTL
- **Simple**: Clean architecture, easy to deploy and maintain
- **Production-ready**: Rate limiting, health checks, graceful shutdown, security headers

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
│   └── vaultwarden/
│       └── client.go           # Vaultwarden API client
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
   # - VAULTWARDEN_ACCESS_TOKEN (from Vaultwarden settings)
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
| `API_KEY` | **Yes** | - | API key for authentication |
| `VAULTWARDEN_URL` | **Yes** | - | Vaultwarden instance URL |
| `VAULTWARDEN_ACCESS_TOKEN` | **Yes** | - | Vaultwarden API access token |
| `CACHE_TTL` | No | `5m` | Cache duration (0 to disable) |
| `READ_TIMEOUT` | No | `10s` | HTTP read timeout |
| `WRITE_TIMEOUT` | No | `10s` | HTTP write timeout |

## Getting Vaultwarden Access Token

There are several ways to get an access token for Vaultwarden:

1. **Via Web UI** (if available):
   - Log into Vaultwarden
   - Go to Settings → Security
   - Generate a new API Key

2. **Via CLI** (for self-hosted):
   - Use the Vaultwarden CLI or API to generate a token
   - Refer to Vaultwarden documentation for your specific version

3. **Via Personal Access Token**:
   - Some Vaultwarden versions support personal access tokens
   - Check your instance's API documentation

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
2. **Restrict CORS** to specific domains (edit `main.go`)
3. **Set ENVIRONMENT=production** in `.env`
4. **Enable rate limiting** (already configured)
5. **Use read-only filesystem** (already in docker-compose)
6. **Run as non-root user** (already in Dockerfile)
7. **Monitor logs** for suspicious activity
8. **Implement IP whitelisting** if possible
9. **Use Docker secrets** instead of environment variables
10. **Regular security updates** (rebuild images monthly)

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
- Your `VAULTWARDEN_ACCESS_TOKEN` is invalid or expired
- Generate a new token from Vaultwarden settings

### Docker build fails
- Ensure you have the latest Go version in Dockerfile
- Run `go mod tidy` before building
- Check for network issues when downloading dependencies

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

## Support

For issues and questions:
- Open an issue on GitHub
- Check existing issues for solutions
- Provide detailed error messages and logs

---

**Built with ❤️ using Go and Fiber**
