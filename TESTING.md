# Testing Guide

This guide provides step-by-step instructions for testing CrabTrap.

## Prerequisites

- Go 1.27.3 or later
- Docker (for PostgreSQL)
- OpenSSL
- curl
- jq (optional, for pretty JSON output)

## Setup

### 1. Start the Database

```bash
make db-up
```

This starts a PostgreSQL container and runs migrations.

### 2. Build the Gateway

```bash
make build
```

### 3. Generate CA Certificate

```bash
make gen-certs
# or
./scripts/generate-certs.sh
```

This creates:
- `certs/ca.key` - CA private key
- `certs/ca.crt` - CA certificate

### 4. Install CA Certificate (Optional)

**macOS:**
```bash
make install-ca
# or
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain certs/ca.crt
```

**Linux:**
```bash
sudo cp certs/ca.crt /usr/local/share/ca-certificates/openclaw-gateway.crt
sudo update-ca-certificates
```

**For Node.js applications (alternative to system install):**
```bash
export NODE_EXTRA_CA_CERTS=$(pwd)/certs/ca.crt
```

## Running Unit Tests

```bash
# Run all tests (requires Docker for PostgreSQL)
make test

# This runs make lint followed by go test -race -p 1 ./...
```

## Manual Testing

### Start the Gateway

```bash
make dev
```

This starts the database, backend, and frontend dev server.

You should see:
```
...
Database connected
Migrations applied
Starting admin API on port 8081
Starting CrabTrap on port 8080
Approval timeout: 30s
Cache TTL: 5m0s
Cache max uses: 5
```

### Create a Test User

```bash
# Create an admin user with a gateway auth token
DATABASE_URL=postgres://crabtrap:secret@localhost:$(docker compose port postgres 5432 | cut -d: -f2)/crabtrap \
  ./gateway create-admin-user testuser
```

This prints a `web_token` for the admin UI. You also need to create a gateway auth token for proxy access via the admin API or directly in PostgreSQL.

### Test Requests

**Test 1: GET request (evaluated by LLM judge in `llm` mode)**

```bash
curl -x http://gat_YOUR_TOKEN:@localhost:8080 \
  --cacert certs/ca.crt \
  https://httpbin.org/get
```

In `passthrough` mode, this completes immediately. In `llm` mode, the LLM judge evaluates and approves/denies.

**Test 2: POST request (evaluated by LLM judge)**

```bash
curl -x http://gat_YOUR_TOKEN:@localhost:8080 \
  --cacert certs/ca.crt \
  -X POST https://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

**Test 3: Health check**

```bash
curl http://localhost:8081/admin/health | jq '.'
```

### Testing with Passthrough Mode

For quick testing without LLM evaluation, set `approval.mode: passthrough` in your config. All requests will be auto-approved and audit-logged.

## Testing with Real Applications

### Node.js

```bash
export HTTP_PROXY=http://gat_YOUR_TOKEN:@localhost:8080
export HTTPS_PROXY=http://gat_YOUR_TOKEN:@localhost:8080
export NODE_EXTRA_CA_CERTS=$(pwd)/certs/ca.crt

node your-app.js
```

### Python

```python
import os
import requests

os.environ['HTTP_PROXY'] = 'http://gat_YOUR_TOKEN:@localhost:8080'
os.environ['HTTPS_PROXY'] = 'http://gat_YOUR_TOKEN:@localhost:8080'
os.environ['REQUESTS_CA_BUNDLE'] = './certs/ca.crt'

response = requests.get('https://httpbin.org/get')
print(response.json())
```

## Verification Checklist

- [ ] Gateway starts successfully with database connection
- [ ] Admin API responds on port 8081 (`/admin/health`)
- [ ] Requests are evaluated by LLM judge (in `llm` mode)
- [ ] Requests pass through immediately (in `passthrough` mode)
- [ ] Denied requests return 403
- [ ] Audit logs are written correctly
- [ ] Web UI loads at http://localhost:8081 (or http://localhost:3000 in dev mode)
- [ ] Graceful shutdown works (Ctrl+C)
- [ ] Debug logging works when `log_level: debug` is set

## Troubleshooting

### Certificate Errors

```bash
# Verify CA cert is installed (macOS)
security find-certificate -c "CrabTrap CA"

# Verify CA cert is readable
openssl x509 -in certs/ca.crt -text -noout

# Re-install CA cert
make fix-trust
```

### Connection Refused

```bash
# Check if gateway is running
curl http://localhost:8081/admin/health

# Check if port is in use
lsof -i :8080
lsof -i :8081
```

### Enable Debug Logging

Set `log_level: debug` in your config to see full request/response details:

```yaml
log_level: debug
```

### Database Issues

```bash
# Reset the database
make db-reset

# Check database connection
docker compose ps
```

## Performance Benchmarks

Expected performance (approximate):

- **Passthrough mode**: ~100-200ms (same as direct connection)
- **LLM mode**: Adds LLM evaluation latency (typically 1-5s depending on model)
- **Throughput**: 1000+ req/s in passthrough mode
- **Memory usage**: ~50MB base

## Reporting Issues

If you encounter issues:
1. Check the gateway logs (stderr for operational, stdout for audit JSON)
2. Check the health endpoint: `curl http://localhost:8081/admin/health`
3. Enable debug logging (`log_level: debug`)
4. Report with reproduction steps
