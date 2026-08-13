# 🔐 Vaultwarden API

> **Stop using `.env` files.** Fetch secrets directly from your self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden) instance at runtime.

A lightweight, production-ready Go API that acts as a secrets bridge between your apps and Vaultwarden. No more scattered `.env` files, no more accidentally committed credentials.

## ✨ Highlights

- **🚀 Zero external dependencies** — Pure Go binary, no Node.js, no Bitwarden CLI
- **🔒 Native Bitwarden crypto** — AES-256-CBC + HMAC-SHA256, PBKDF2/Argon2id key derivation
- **♻️ Auto token refresh** — Never worry about expired sessions again; if the session is invalidated server-side (restart, token revocation), the service automatically performs a full re-login instead of serving a stale cache
- **📦 ~20MB Docker image** — Alpine-based, runs as non-root
- **🛡️ Defense in depth** — API key auth, IP whitelisting, rate limiting, security headers
- **⚡ Background vault sync** — Secrets always up-to-date (configurable interval)
- **🏭 Production-ready** — Health checks, graceful shutdown, structured logging

## Architecture

```
┌─────────────┐    HTTPS + API Key    ┌──────────────────────┐    Native Go    ┌──────────────┐
│  Your App   │ ────────────────────> │  Vaultwarden API     │ ──────────────> │  Vaultwarden │
│  (any lang) │ <──────────────────── │  (Go, ~20MB image)   │ <────────────── │  Server      │
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

## Setting Up Your Secrets in Vaultwarden

The API reads regular Vaultwarden/Bitwarden vault items. No special format needed — just create login items like you normally would.

### Recommended: Create a dedicated user

For security, **don't use your personal Vaultwarden account** (which has all your passwords). Instead:

1. Create a new user in Vaultwarden (e.g., `secrets@yourdomain.com`)
2. Log in as that user and add only the secrets your apps need
3. Point this API at that dedicated account

This way, the API only has access to the secrets you explicitly add — not your entire password vault.

### How to store secrets

Create a login item in Vaultwarden for each secret:

| Field | What to put |
|-------|-------------|
| **Name** | The key you'll use in the API (e.g., `DATABASE_URL`) |
| **Password** | The secret value |

That's it. When you call `GET /secret/DATABASE_URL`, the API finds the item named "DATABASE_URL" and returns the password field.

You can also use **custom fields** or **notes** — the API returns the most relevant value: password → custom fields → notes.

> **Tip:** Name your items exactly like you'd name environment variables. It makes the mental mapping easy: `DATABASE_URL` in Vaultwarden = `DATABASE_URL` in your app.

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
| `API_KEY` | Yes\* | — | Single full-access key for this service (min 32 chars) |
| `API_KEYS` | Yes\* | — | Inline JSON array of scoped keys (see [Scoped API keys](#scoped-api-keys)) |
| `API_KEYS_FILE` | Yes\* | — | Path to a JSON file of scoped keys; takes precedence over `API_KEYS` |
| `VAULTWARDEN_CLIENT_ID` | No | — | API key client ID (bypasses 2FA — see below) |
| `VAULTWARDEN_CLIENT_SECRET` | No | — | API key client secret (bypasses 2FA — see below) |
| `API_PORT` | No | `8080` | Port the API listens on |
| `ALLOWED_IPS` | No | (all) | Comma-separated IPs/CIDRs to whitelist |
| `ENABLE_GITHUB_IP_RANGES` | No | `false` | Auto-whitelist GitHub Actions IPs |
| `SYNC_INTERVAL` | No | `5m` | How often to re-sync the vault |
| `STRICT_SECRET_MATCH` | No | `false` | Require an exact name match; `true` returns 404 instead of falling back to a partial match |
| `RATE_LIMIT_MAX` | No | `30` | Max requests per window, per IP |
| `RATE_LIMIT_WINDOW` | No | `1m` | Rate-limit window duration |
| `READ_TIMEOUT` | No | `10s` | HTTP server read timeout |
| `WRITE_TIMEOUT` | No | `10s` | HTTP server write timeout |
| `CORS_ALLOWED_ORIGINS` | No | `http://localhost:3000` | Comma-separated origins allowed by CORS |
| `TRUSTED_PROXY_IP` | No | `127.0.0.1,::1` | Extra trusted reverse proxy IPs/CIDRs (comma-separated); loopback is always trusted. See [Client IP behind a proxy](#client-ip-behind-a-proxy) |
| `TRUSTED_PROXY_PRESET` | No | — | Comma-separated provider presets whose ranges are added to the trusted set. Only `cloudflare` today. **Not needed for a normal Cloudflare deployment** — that works out of the box; see [Behind a CDN](#behind-a-cdn-cloudflare). An unknown name aborts startup |
| `ENVIRONMENT` | No | `development` | Set to `production` to hide errors |
| `DEBUG` | No | `false` | Enable debug logging |

\* At least one of `API_KEY`, `API_KEYS`, or `API_KEYS_FILE` is required.

### Scoped API keys

`API_KEY` is a single, full-access key — any holder can read every secret the account
can decrypt. For least-privilege, per-consumer access, define multiple keys with
`API_KEYS` (inline JSON) or `API_KEYS_FILE` (a JSON file, ideal as a mounted Docker
secret). Each key is scoped to allowed organizations and/or collections, and is
individually revocable (remove it from the config and re-deploy).

```json
[
  {
    "name": "dev-team",
    "key": "<32+ character secret>",
    "organizations": ["MyOrg"],
    "collections": ["Secrets - DEV"]
  }
]
```

- **Scope is enforced server-side**, regardless of the `organization_*` / `collection_*`
  query filters. A scoped key can only ever read secrets within its scope — the query
  filters can narrow within scope but never widen beyond it.
- **A key with no `organizations` and no `collections` is unscoped** (full access),
  same as the legacy `API_KEY`. `API_KEY` keeps working alongside scoped keys.
- **Matching:** a secret is in scope when its organization is in the key's allowed
  organizations (if any) **and** it belongs to at least one allowed collection (if any).
  Consequently, an org-scoped key **cannot read personal / no-org items**.
- **Refs may be names or UUIDs.** UUIDs are recommended: name matching is
  case-insensitive, silently stops matching if the org/collection is renamed, and a
  duplicate name binds to the lowest matching UUID. Unresolvable refs **fail closed**
  (the key matches nothing), including the brief window before the first vault sync.

`API_KEYS_FILE` takes precedence over `API_KEYS` when both are set.

### 2FA / Two-Step Login

If your Vaultwarden account has 2FA enabled, password login will be blocked. You need to use API key login instead:

1. Log in to your Vaultwarden web vault
2. Go to **Settings → Security → Keys** → **View API key**
3. Set `VAULTWARDEN_CLIENT_ID` and `VAULTWARDEN_CLIENT_SECRET` in your environment
4. The `VAULTWARDEN_PASSWORD` is still required — it's used for decryption, not authentication

With API key credentials set, the service uses `client_credentials` grant which bypasses 2FA entirely.

## Docker Compose

### Standalone

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

### Alongside your existing Vaultwarden

Already running Vaultwarden in Docker? Add the API to the same stack:

```yaml
services:
  vaultwarden:
    image: vaultwarden/server:latest
    # ... your existing vaultwarden config ...

  vaultwarden-api:
    image: ghcr.io/turbootzz/vaultwarden-api:latest
    container_name: vaultwarden-api
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      - VAULTWARDEN_URL=http://vaultwarden:80  # Internal Docker network
      - VAULTWARDEN_EMAIL=${VAULTWARDEN_EMAIL}
      - VAULTWARDEN_PASSWORD=${VAULTWARDEN_PASSWORD}
      - API_KEY=${API_KEY}
      - ENVIRONMENT=production
    depends_on:
      - vaultwarden
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
```

> **Note:** When both containers are in the same Docker network, use `http://vaultwarden:80` as the URL (internal Docker DNS). No need to expose Vaultwarden's port to the host.

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
- **Per-key scoping** — multiple revocable keys, each restricted server-side to specific organizations/collections ([Scoped API keys](#scoped-api-keys))
- **IP whitelisting** with CIDR support + optional GitHub Actions IP auto-import. Whitelisting **fails closed**: once `ALLOWED_IPS` or `ENABLE_GITHUB_IP_RANGES` is set, a whitelist that ends up empty (a failed GitHub range fetch, say) denies every request rather than reverting to allow-all
- **KDF parameters from the server are bounded both ways** — the prelogin response chooses how the master key is derived, and the password hash sent back to the server is derived from it, so a server answering with a token iteration count would receive a hash it could brute-force offline. Values below the floors official clients enforce are rejected, and absurd ones are refused rather than allowed to exhaust the process
- **No unauthenticated cipher downgrade** — a type 0 (no-MAC) cipher string is refused under a key that carries a MAC key, so integrity protection cannot be stripped by relabelling the cipher string
- **Rate limiting** (configurable via `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW`, default 30/min per IP; whitelisted IPs are exempt)
- **Read-only filesystem** in Docker (only `/tmp` writable)
- **Non-root user** in container
- **No capabilities** (`cap_drop: ALL`)
- **Security headers** via Helmet middleware
- **Spoof-resistant client IP** — see [Client IP behind a proxy](#client-ip-behind-a-proxy)
- **No caching or compression of secret responses** — `GET /secret/:name` answers carry `Cache-Control: no-store` and are excluded from response compression, so a secret is neither storable by an intermediary nor measurable through compressed length
- **No secret values in logs** — secret values are never written to logs at any level; vault items are referenced by UUID
- **Secret names can appear in request-path logs** — several default-level paths log the requested URL or name for `GET /api/secret/:name`: the blocked-IP warning from the IP whitelist, the error handler's log for unmatched routes, and the failed-lookup warning below. Values are still never logged
- **A 404 tells the caller nothing; the log tells you everything** — see [Diagnosing a failed secret lookup](#diagnosing-a-failed-secret-lookup)
- Secrets are **decrypted in-memory only** — never written to disk

### Diagnosing a failed secret lookup

`GET /secret/:name` answers **exactly the same 404 for every failure** — same body,
same headers — whether the secret does not exist, sits outside the calling key's
[scope](#scoped-api-keys), or is excluded by the request's own filters. That
uniformity is the point: telling "no such secret" apart from "exists but not
yours" is how a scoped key would enumerate the vault a name at a time.

The lookup scans every cached item on the failure path regardless of outcome —
no early exit on a hit — so the dominant work does not vary with the answer.
That is a deliberate property, not a constant-time guarantee: the log write that
follows is synchronous and its length varies by cause, so a caller able to
measure the origin precisely enough, past network jitter and a blocking log
sink, is not provably unable to distinguish them. Treat the API key, not the
opaque 404, as the boundary that matters.

The server's log is under no such constraint, and is where the reason goes:

```text
WARN: Secret lookup failed for "JWT_SECRET" (key "hearth", IP 31.201.224.107):
      no item by that name anywhere in the vault; 259 of 259 items were visible to this key
```

The tail names the cause:

| Log says | Meaning | Fix |
|---|---|---|
| `no item by that name anywhere` | the secret really is absent | add it to the vault, or correct the name |
| `N item(s) by that name exist but are outside this key's scope` | it exists, this key may not see it | widen the key's `organizations` / `collections`, or use a different key |
| `left none of the N cached items visible` | the key's scope *or* the request's own `organization_*` / `collection_*` / `folder_*` query filters match nothing in the vault | check both: the key's scope, and any filter the caller sent |
| `STRICT_SECRET_MATCH rejects partial matches` | only a partial name match exists | use the exact name, or unset `STRICT_SECRET_MATCH` |
| `the vault cache is empty` | the first sync has not completed | check the Vaultwarden connection |

A scope that does not resolve at all is refused one step earlier, before any
lookup happens, and says so:

```text
WARN: Secret lookup denied for "JWT_SECRET" (key "hearth", IP 31.201.224.107):
      none of this key's 1 scoped collection(s) resolve against the 11 known to the vault;
      check the key config for a typo or a rename
```

Scope refs are matched against the last sync, so this is a typo in the key's
`organizations` / `collections`, or an org or collection renamed in the vault
since. Using UUIDs rather than names avoids the rename half of that.

A failed lookup is logged at **warning**, not error: a caller asking for a secret
that is not there is ordinary 404 traffic, and one misconfigured client retrying
would otherwise bury real faults. Errors of any other kind stay at error level.

### Client IP behind a proxy

`ALLOWED_IPS` and the rate limiter act on the client address, so how that address
is derived is itself a security control.

The socket peer is authoritative unless it is a trusted proxy — loopback, plus
anything in `TRUSTED_PROXY_IP`. Only for a trusted peer is `X-Forwarded-For`
consulted, and it is read **right to left**: the first entry that is not a
trusted proxy is the client. That direction is what makes it unspoofable. A
proxy running the standard `proxy_set_header X-Forwarded-For
$proxy_add_x_forwarded_for;` *appends* the address it saw, so everything to the
left of that entry is client-written and ignored. Prepending
`X-Forwarded-For: <whitelisted-ip>` to a request does not get it past the
whitelist.

The chain is read from the raw header block rather than the parsed header table,
because fasthttp merges HTTP/1.1 chunked *request trailers* into that table and
a trailer value lands after every genuine header — the one position the
right-to-left walk trusts. Without that, a client behind a proxy that forwards
trailers (HAProxy and Envoy do; nginx does not) could smuggle its chosen address
past the whitelist in the trailer section of a chunked request.

Three consequences worth knowing:

- **Every hop between the client and this service must be trusted.** The walk stops
  at the first untrusted entry and *returns* it, so one unlisted hop — a second
  reverse proxy, a sidecar — becomes the address `ALLOWED_IPS` is judged against,
  and no whitelist entry will ever match it. Known CDN edges are the exception:
  they are recognised and resolved automatically, see
  [Behind a CDN](#behind-a-cdn-cloudflare).
- **Set `TRUSTED_PROXY_IP` to your proxies, and only your proxies.** Anything that can
  connect from a trusted address *is* a proxy as far as this service can tell,
  and can therefore claim any client address. A broad range like `172.16.0.0/12`
  hands that power to every container on the bridge network.
- **Loopback is always trusted**, so any process on the same host can assert a
  client address. This is what makes the documented `127.0.0.1:8080` compose
  binding work with a same-host proxy; if you expose the service some other way,
  scope the port accordingly.

#### Behind a CDN (Cloudflare)

With Cloudflare in front (orange-cloud DNS → your reverse proxy → this service),
the chain arriving here is:

```text
X-Forwarded-For: <real client>, <cloudflare edge>
```

Cloudflare sets the header to the visitor address, and your own proxy appends the
address *it* saw — the edge. Edge addresses rotate per request and can never be
whitelisted, so a walk that stops there denies every request whatever
`ALLOWED_IPS` says. That was the failure reported in
[#40](https://github.com/Turbootzz/vaultwarden-api/issues/40).

**This is handled automatically — no configuration needed.** Cloudflare's
[published ranges](https://www.cloudflare.com/ips/) are embedded in the binary, and
when the walk lands on an address inside them the answer is taken from
`CF-Connecting-IP` instead. A CDN edge address is never a real client, so treating
it as the answer is always wrong; the edge sets that header itself and overwrites
any the visitor sent, which makes it the one value a visitor behind the edge cannot
choose. A weekly CI job flags drift in the embedded ranges; refresh with
`make update-cloudflare-ips`.

Recognising a provider is **not** the same as trusting it. The ranges are not added
to the trusted-proxy set, so a request coming *from* one is still just a client. The
header is read only when a trusted hop put the CDN address there — a client that
prepends a Cloudflare address to `X-Forwarded-For` never has it reached, because the
walk stops at the address your own proxy appended.

##### When you still need `TRUSTED_PROXY_PRESET`

Only when `CF-Connecting-IP` cannot reach this service — a proxy in between strips
it, or sends it twice. The denial log says so explicitly:

```text
resolved 172.71.99.34, peer 172.27.0.1, xff=[31.201.224.107 172.71.99.34] (cloudflare edge in the chain but no usable client-IP header)
```

```env
TRUSTED_PROXY_PRESET=cloudflare
TRUSTED_PROXY_IP=172.18.0.5        # your reverse proxy, as before
```

That additionally trusts the edge ranges as proxies, so the walk skips past them to
the entry Cloudflare appended. It is the weaker mechanism of the two: the walk
*skips* trusted entries, so a visitor whose own address is inside those ranges — one
Cloudflare zone proxying to another — has its prepended entries reached and
believed. Prefer fixing the stripped header.

For a provider with no preset, list its ranges in `TRUSTED_PROXY_IP` by hand, with
the same caveat.

**The residual trade-off:** anything connecting from a trusted range can still
assert a client address. Trusting a CDN's ranges is only safe while the CDN is the
sole way to reach the origin — an attacker who can reach your origin directly
bypasses the edge and its header entirely. Bound it with
[authenticated origin pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/)
or a [tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/),
plus a firewall that drops everything else.

Alternatives, if you would rather not trust the edge ranges: grey-cloud the
hostname so Cloudflare stops proxying it, or give LAN clients a split-horizon DNS
record that reaches the reverse proxy directly (that proxy must still be trusted).

#### Diagnosing a denied request

A blocked request logs the whole resolution, not just the verdict:

```text
WARN: IP blocked (not whitelisted) on GET /secret/db: resolved 172.70.1.1, peer 172.18.0.5, xff=[192.168.1.81 172.70.1.1]
```

`resolved` is the address judged against `ALLOWED_IPS`, `peer` is the socket
address, and `xff` is the forwarded chain. If `resolved` is an address you never
configured and it appears in `xff`, an untrusted hop terminated the walk — add
that hop to `TRUSTED_PROXY_IP` (or the matching preset). Only the last eight chain
entries are shown, since the client controls how many it prepends.

Two more markers appear when a preset is in play. `resolved 192.168.1.81 via
cloudflare` means the answer came from the provider's client-IP header rather than
the chain. `(cloudflare edge in the chain but no usable client-IP header)` means
the request came through the edge but `CF-Connecting-IP` was absent or duplicated,
so the weaker chain walk was used — check that nothing between the edge and this
service strips the header.

## Project Structure

```
├── cmd/api/main.go                    # Entry point
├── internal/
│   ├── auth/middleware.go             # API key authentication
│   ├── config/config.go              # Configuration
│   ├── handlers/handlers.go          # HTTP handlers
│   ├── ipwhitelist/ipwhitelist.go    # IP access control
│   ├── realip/realip.go              # Proxy-aware client IP resolution
│   ├── realip/presets.go             # Provider trusted-proxy range presets
│   ├── validators/validators.go      # Input validation
│   └── vaultwarden/
│       ├── api_client.go             # Native HTTP client for Vaultwarden
│       ├── crypto.go                 # Bitwarden-compatible encryption
│       ├── crypto_test.go            # Crypto unit tests
│       ├── client.go                 # Secret lookup + caching
│       └── init.go                   # Initialization with retry
├── pkg/logger/logger.go              # Structured logging
├── Dockerfile                        # Multi-stage build (~20MB image)
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

**Trashed items are never served.** Items in the Vaultwarden trash (soft-deleted) are skipped during sync, so deleting an item removes it from the API on the next sync or `POST /refresh`. Restoring it from the trash brings it back the same way.

**Colliding names**: When several items match, the one with the lowest cipher UUID wins, and the API logs a warning naming it. The choice is stable — the same request always returns the same secret — but it is arbitrary, so treat the warning as a prompt to disambiguate. Split colliding items across organizations, collections, or folders, then pass the ID or name of that grouping as a filter.

**Strict matching**: Set `STRICT_SECRET_MATCH=true` to turn off the partial-match fallback. A name that matches no item exactly then returns 404 rather than the nearest substring hit — worth it if you would rather a consumer fail loudly than silently receive a different secret after a rename. Exact matching stays case-insensitive.
Examples:
- `GET /secret/DATABASE_URL?organization_name=Organization1`
- `GET /secret/DATABASE_URL?organization_id=<organization_uuid>`
- `GET /secret/DATABASE_URL?collection_name=Project1`
- `GET /secret/DATABASE_URL?collection_id=<collection_uuid>`
- `GET /secret/DATABASE_URL?folder_name=Deployments`
- `GET /secret/DATABASE_URL?folder_id=<folder_uuid>`

You can combine the filters for even more fine-grained filtering, as such:
- `GET /secret/DATABASE_URL?organization_name=Organization1&collection_name=Project1`
However, for each dimension (organization | collection | folder) you can only filter on one value. Additionally, specifying the name and the ID are mutually exclusive; you cannot specify both at the same time.

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `prelogin failed (HTTP 502)` | Can't reach Vaultwarden | Check `VAULTWARDEN_URL` — is it reachable from the container? |
| `Two factor required` | Account has 2FA enabled | Set `VAULTWARDEN_CLIENT_ID` and `VAULTWARDEN_CLIENT_SECRET` (see [2FA section](#2fa--two-step-login)) |
| `MAC verification failed` | Wrong password or org-owned items | Normal for individual items shared via organizations — they use a different key. If *every* item fails, see the row below |
| `sync decrypted 0 of N ciphers (M failures), refusing to replace cache` | No usable decryption key for any item — wrong master password, or every item is org-owned and the org key can't be decrypted | Check `VAULTWARDEN_PASSWORD` and that at least one item is decryptable. Rather than serve an empty vault, the service keeps the last good cache — and refuses to start if this happens on the first sync |
| `missing authorization header` | No Bearer token in request | Add `-H "Authorization: Bearer YOUR_API_KEY"` to your request |
| `secret not found` | Item name doesn't match, the item is in the trash, or it's out of the key's scope | **The server log says which** — see [Diagnosing a failed secret lookup](#diagnosing-a-failed-secret-lookup). The response is identical for every cause by design |
| Container exits immediately | Missing required env vars | Ensure `VAULTWARDEN_URL`, `VAULTWARDEN_EMAIL`, `VAULTWARDEN_PASSWORD`, and one of `API_KEY` / `API_KEYS` / `API_KEYS_FILE` are set |
| `Background sync failed N times in a row, cache is stale` | Vaultwarden unreachable, or the account credentials are no longer valid | Individual sync failures log a warning; after 3 consecutive failures they escalate to an error. Secrets keep being served from the last successful sync — check `VAULTWARDEN_URL` connectivity and your credentials |

**Debug mode:** Set `DEBUG=true` to see detailed logs (sync results, token refreshes, per-item decrypt failures by UUID). Debug logging itself adds no secret names or values — it references vault items by UUID — but it is verbose, so don't use it in production. Secret values are never logged at any level; secret *names* can appear at default level in blocked-request warnings, routing-error logs, and the failed-lookup warning (see [Diagnosing a failed secret lookup](#diagnosing-a-failed-secret-lookup) and [Security](#security)).

## Contributing

Contributions welcome! Fork → branch → PR.

## License

MIT — see [LICENSE](LICENSE)

---

**Built by [Thijs Herman](https://github.com/Turbootzz)** — because `.env` files are so 2020.
