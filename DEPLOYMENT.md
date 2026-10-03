# Deployment Guide

## Docker / Podman

### Pre-built Image

```bash
docker pull ghcr.io/antoniolago/vaultwarden-masterless:main
```

### Build Locally

```bash
docker build -t vaultwarden-masterless .
```

### Run with Docker

```bash
docker run -d \
  --name masterless \
  -p 8484:8484 \
  -v ./data:/data \
  -e VAULTWARDEN_URL=http://vaultwarden:80 \
  -e VAULTWARDEN_RSA_PUBLIC_KEY_FILE=/data/vw_rsa_key.pub.pem \
  -e USER_KEYS_URL=https://vault.example.com/user-keys \
  -e PROXY_ENABLED=true \
  -e ROTATION_INTERVAL_HOURS=720 \
  vaultwarden-masterless
```

### Docker Compose (Production)

Minimal production compose — assumes you already have Vaultwarden and an SSO provider running:

```yaml
services:
  masterless:
    image: ghcr.io/antoniolago/vaultwarden-masterless:main
    restart: unless-stopped
    ports:
      - "8484:8484"
    volumes:
      - ./data:/data
      - ./keys:/keys:ro
    environment:
      HOST: "0.0.0.0"
      PORT: "8484"
      VAULTWARDEN_URL: "http://vaultwarden:80"
      VAULTWARDEN_RSA_PUBLIC_KEY_FILE: "/keys/vw_rsa_key.pub.pem"
      RSA_PRIVATE_KEY_FILE: "/keys/rsa_private.pem"
      RSA_PUBLIC_KEY_FILE: "/keys/rsa_public.pem"
      DATABASE_PATH: "/data/masterless.sqlite"
      PROXY_ENABLED: "true"
      USER_KEYS_URL: "https://vault.example.com/user-keys"
      ROTATION_INTERVAL_HOURS: "720"
      LOG_LEVEL: "info"
```

### Docker Compose (Full Test Stack)

A complete test environment with Vaultwarden, vaultwarden-masterless, and Pocket-ID is in `deploy/`:

```bash
cd deploy
cp .env.example .env
chmod +x setup.sh
./setup.sh
podman-compose up --build   # or: docker compose up --build
```

See [DEV.md](./DEV.md) for test stack details and first-time setup instructions.

## Kubernetes

Example manifests are in `k8s/`. See [k8s/README.md](./k8s/README.md) for full instructions.

### Quick overview

```
Internet → Ingress → vw-masterless (Service:8484) → Pod (masterless)
                                                         ↓ proxy
                                                     vaultwarden (Service:80)
```

```bash
# Generate keys
./scripts/generate-keys.sh ./keys

# Edit manifests (set your image, domain, URLs)
# Then apply:
kubectl apply -f k8s/
```

### Important notes

- **Single replica only** — SQLite doesn't support concurrent writers. Use `strategy: Recreate`.
- RSA keys are mounted as **Kubernetes Secrets** (volumes, not env vars).
- The pod runs as **non-root** (UID 1000) with a read-only root filesystem.
- Consider [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) or an external secret manager for production.

## Reverse Proxy (Nginx / Caddy / Traefik)

vaultwarden-masterless should be the **only entry point** for clients. Your reverse proxy should point to it, not to Vaultwarden directly.

### Nginx example

```nginx
server {
    listen 443 ssl;
    server_name vault.example.com;

    ssl_certificate     /etc/ssl/vault.crt;
    ssl_certificate_key /etc/ssl/vault.key;

    location / {
        proxy_pass http://127.0.0.1:8484;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Caddy example

```
vault.example.com {
    reverse_proxy 127.0.0.1:8484
}
```

With this setup, `USER_KEYS_URL` would be `https://vault.example.com/user-keys`.

## Configuration Reference

See the main [README.md](./README.md#configuration-reference) for all environment variables.

### Key production settings

| Variable | Recommended |
|---|---|
| `LOG_LEVEL` | `info` or `warn` |
| `ROTATION_INTERVAL_HOURS` | `720` (30 days) or `168` (weekly) |
| `PROXY_ENABLED` | `true` |
| `USER_KEYS_URL` | Your public HTTPS URL + `/user-keys` |

## Backup & Recovery

### What to back up

1. **SQLite database** (`DATABASE_PATH`) — contains encrypted user keys and the wrapped secret
2. **RSA private key** (`RSA_PRIVATE_KEY_FILE`) — required to decrypt the wrapping secret

If you lose the RSA private key, **all stored user keys are unrecoverable**. Back it up securely and separately from the database.

### Recovery

1. Restore the database file and RSA keys to their configured paths
2. Start vaultwarden-masterless — it will recover the wrapping secret from the database using the RSA key
3. All user keys will be accessible immediately
