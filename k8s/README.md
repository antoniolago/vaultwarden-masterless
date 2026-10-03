# Kubernetes Deployment — Vaultwarden Masterless

Example manifests to deploy vaultwarden-masterless in proxy mode on Kubernetes.

## Architecture

```
Internet → Ingress → vw-masterless (Service:8484) → Pod (masterless)
                                                         ↓ proxy
                                                     vaultwarden (Service:80)
```

Clients connect via Ingress. vaultwarden-masterless proxies all traffic to
Vaultwarden (running as a separate Deployment/Service in the same namespace)
and patches API responses to enable passwordless login.

## Prerequisites

1. A running Vaultwarden Deployment + Service (e.g. `vaultwarden:80`)
2. An SSO/OIDC provider (e.g. Pocket-ID, Keycloak, Authentik)
3. RSA keys for at-rest encryption (see below)
4. Vaultwarden's RSA public key (`rsa_key.pub.pem` from its data volume)

## Files

| File | What |
|---|---|
| `namespace.yaml` | Creates the `vaultwarden` namespace |
| `configmap.yaml` | Non-sensitive configuration (URLs, paths, flags) |
| `secret.yaml` | RSA keys for encryption and JWT verification |
| `pvc.yaml` | Persistent storage for the SQLite database |
| `deployment.yaml` | The vaultwarden-masterless pod |
| `service.yaml` | ClusterIP service exposing port 8484 |
| `ingress.yaml` | Ingress rule (adjust for your controller) |

## Quick Start

### 1. Generate RSA keys

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out rsa_private.pem
openssl pkey -in rsa_private.pem -pubout -out rsa_public.pem

# Copy Vaultwarden's public key from its data volume
kubectl cp vaultwarden/<vw-pod>:/data/rsa_key.pub.pem ./rsa_key.pub.pem
```

### 2. Edit the manifests

- **`secret.yaml`**: Paste your RSA keys
- **`configmap.yaml`**: Set `VAULTWARDEN_URL`, `USER_KEYS_URL`
- **`deployment.yaml`**: Set your container image
- **`ingress.yaml`**: Set your domain and TLS config

### 3. Apply

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
```

Or all at once:

```bash
kubectl apply -f k8s/
```

### 4. Verify

```bash
kubectl -n vaultwarden get pods
kubectl -n vaultwarden logs deploy/vw-masterless
curl https://vault.example.com/alive
```

## Notes

- The Deployment uses `strategy: Recreate` because SQLite doesn't support
  concurrent writers. Do **not** scale to more than 1 replica.
- If you need horizontal scaling, switch to PostgreSQL (requires code changes).
- The pod runs as non-root (UID 1000) with a read-only root filesystem.
- Secrets are mounted as volumes, not environment variables, for RSA keys.
- Consider using [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets)
  or an external secret manager for production.
