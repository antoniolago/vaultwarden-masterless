<div align="center">
  
  # Vaultwarden Masterless

  [![Experimental](https://img.shields.io/badge/status-experimental-orange?style=for-the-badge)](#-experimental--read-this-first)
  [![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue?style=for-the-badge)](./LICENSE)
  [![CI](https://github.com/antoniolago/vaultwarden-masterless/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/antoniolago/vaultwarden-masterless/actions/workflows/ci-cd.yml)
  [![Forgejo](https://img.shields.io/badge/forgejo-mirror-%23FB923C.svg?style=for-the-badge&logo=forgejo&logoColor=white)](https://git.lag0.com.br/antoniolago/vaultwarden-masterless)
</div>

**Remove the master password from Vaultwarden.** Users log in via SSO — their vault encryption keys are managed server-side so they never need to remember (or even have) a master password.

## ⚠️ Experimental — read this first

This project is **experimental** and is published for **test instances, evaluation and
feedback**. Do not point it at a production vault you cannot afford to lose.

- It is a **reverse proxy that rewrites Vaultwarden API responses** on the SSO / Key Connector
  path. Vaultwarden changes that path between releases, and Bitwarden owns the clients: a
  client update can break passwordless login without anything changing here. That is why
  `/version` and [COMPATIBILITY.md](./COMPATIBILITY.md) exist — pin versions and check them.
- **Passwordless means the server holds the keys.** The vault key is stored server-side
  (encrypted at rest under this proxy's own RSA key). If you lose the proxy's data volume and
  RSA keys, the vault is **not recoverable** — there is no master password to fall back on.
- Start with a **new, throwaway Vaultwarden instance**. Do not convert an existing vault
  in place: items created before the switch are encrypted under the old key and stay
  undecryptable (see [Troubleshooting](#troubleshooting)).
- The **mobile apps** need one device-local setting after the first login (a PIN or
  biometrics) or they log themselves out —
  see [Mobile clients](#mobile-clients--one-setting-after-the-first-login).

Only tested version combinations are supported: see [COMPATIBILITY.md](./COMPATIBILITY.md).
Not affiliated with Bitwarden Inc. or the Vaultwarden project. Security reports:
[SECURITY.md](./SECURITY.md).

## How It Works

Normally, Vaultwarden derives a user's vault encryption key from their master password. This project replaces that:

1. Users authenticate via **SSO** (configured in Vaultwarden)
2. On first login, the client generates an encryption key and **stores it** in vaultwarden-masterless
3. On subsequent logins, the client **retrieves the key** from vaultwarden-masterless to decrypt the vault
4. No master password is ever needed

vaultwarden-masterless runs as a **reverse proxy** in front of your existing, **unmodified** Vaultwarden. It intercepts API responses and injects flags that tell clients to use server-side key storage instead of a master password.

```
 ┌─────────────┐                ┌──────────────────────┐               ┌──────────────┐
 │   Clients   │──all traffic──▶│  vaultwarden-        │──proxy───────▶│  Vaultwarden  │
 │ (web/apps)  │◀──patched──────│  masterless          │◀──────────────│  (unmodified) │
 └─────────────┘    JSON        │                      │               └──────┬───────┘
                                │  /user-keys ● local  │                      │
                                │  /alive     ● local  │                   SSO via
                                └────────┬─────────────┘             ┌────────┴───────┐
                                    ┌────▼─────┐                     │  OIDC / SSO    │
                                    │ SQLite   │                     │  Provider      │
                                    │ (enc DB) │                     └────────────────┘
                                    └──────────┘
```

## Prerequisites

- A running **Vaultwarden** instance with **SSO enabled** (`SSO_ENABLED=true`), it's recommended to create a new separate instance and import your DB, it's safer.
- An **OIDC/SSO provider** (Pocket-ID, Authentik, Keycloak, etc.)
- Vaultwarden's **RSA public key** file (found in Vaultwarden's `data/` directory as `rsa_key.pub.pem`)


## Integration with Existing Vaultwarden (NOT RECOMMENDED!)

### Step 1 — Generate RSA keys for vaultwarden-masterless

```bash
./scripts/generate-keys.sh ./data
```

This creates `rsa_private.pem` and `rsa_public.pem` in `./data/`. These are **separate** from Vaultwarden's own RSA keys — they protect the stored vault keys at rest.

### Step 2 — Copy Vaultwarden's RSA public key

vaultwarden-masterless needs Vaultwarden's RSA public key to verify JWT tokens issued during login:

```bash
cp /path/to/vaultwarden/data/rsa_key.pub.pem ./data/vw_rsa_key.pub.pem
```

### Step 3 — Configure

```bash
cp .env.template .env
```

Edit `.env` — the two critical settings are:

```bash
# Where your Vaultwarden is running (vaultwarden-masterless proxies to it)
VAULTWARDEN_URL=https://vaultwarden.internal:8080

# The public URL of the /user-keys endpoint.
# The proxy strips the /user-keys suffix before injecting it into API responses
# (the Bitwarden client appends /user-keys automatically).
# This MUST be reachable from the browser/app.
USER_KEYS_URL=https://vault.example.com/user-keys
```

| Setup | `USER_KEYS_URL` value |
|---|---|
| vaultwarden-masterless is your public entry point | `https://vault.example.com/user-keys` |
| Behind a reverse proxy on a subpath | `https://example.com/vault/user-keys` |
| Local development | `http://localhost:8484/user-keys` |

If `USER_KEYS_URL` is empty, the proxy still works but **passwordless flags are not injected** — clients will behave as if key storage is not available.

### Step 4 — Run

```bash
cargo build --release
./target/release/vaultwarden-masterless
```

### Step 5 — Point clients at vaultwarden-masterless

Change your DNS/reverse-proxy so that clients connect to **vaultwarden-masterless** instead of directly to Vaultwarden. Everything else is transparent — vaultwarden-masterless proxies all traffic and patches the necessary responses.


## Helm Chart (One-Command Deployment)

The chart bundles vaultwarden-masterless + Vaultwarden + Keycloak into a single,
self-contained SSO-ready stack. Zero external dependencies — just a Kubernetes
cluster and a domain.

### OCI Artifacts

The chart and the image are published by CI to **GHCR** (public — use these):

```bash
# Helm chart
helm pull oci://ghcr.io/antoniolago/charts/vaultwarden-masterless --version 0.4.2

# Container image (tag `main` = latest build of the default branch;
# `sha-<short>` pins an exact commit)
docker pull ghcr.io/antoniolago/vaultwarden-masterless:main
```

<details>
<summary>The maintainer's own instances pull from a private Harbor mirror instead</summary>

Charts live in the `charts` project and images in `library`:

```bash
helm pull oci://harbor.lag0.com.br/charts/vaultwarden-masterless --version 0.4.2
docker pull harbor.lag0.com.br/library/vaultwarden-masterless:<tag>
```

</details>

### Quick Start (Bundled Stack)

```bash
helm install demo oci://ghcr.io/antoniolago/charts/vaultwarden-masterless \
  --version 0.4.2 \
  --namespace vaultwarden-masterless-demo \
  --create-namespace \
  --set fullnameOverride=demo \
  --set image.tag=main \
  --set config.userKeysUrl=https://vault.example.com/user-keys \
  --set vaultwarden.enabled=true \
  --set vaultwarden.domain=https://vault.example.com \
  --set vaultwarden.sso.authority=https://keycloak.example.com/realms/demo \
  --set vaultwarden.sso.clientSecret.value=my-vw-client-secret \
  --set keycloak.enabled=true \
  --set keycloak.hostname=https://keycloak.example.com \
  --set keycloak.adminPassword.value=admin \
  --set keycloak.setup.clientSecret.value=my-vw-client-secret \
  --set keycloak.setup.demoUser.password.value=demo
```

After install (~2 minutes for Keycloak setup), log in at `https://vault.example.com`:

| Field | Value |
|-------|-------|
| Email | `demo@demo.masterless.example` |
| SSO user | `demo` |
| SSO password | `demo` (change via `keycloak.setup.demoUser.password`) |

### Helm Values Reference

| Value | Description | Default |
|-------|-------------|---------|
| `image.repository` | Masterless proxy image | `ghcr.io/antoniolago/vaultwarden-masterless` |
| `image.tag` | Image tag (`main` = latest build of the default branch; `sha-<short>` pins a commit) | `"main"` |
| `config.userKeysUrl` | Public URL of `/user-keys` | `""` |
| `config.logLevel` | Log level | `"info"` |
| `config.syntheticOrgName` | Org name injected for Key Connector | `""` |
| `config.syntheticOrgIdentifier` | Org identifier | `""` |
| `config.compatVwVersion` | Vaultwarden version covered by CI (`/version`) | `"1.37.3"` |
| `config.compatKcVersion` | Tested Keycloak version for `/version` | `"26.3.4"` |
| `config.compatClients` | JSON of tested client versions | See `values.yaml` |
| `config.compatStatusUrl` | URL of the compatibility matrix | GitHub `COMPATIBILITY.md` |
| `config.compatLastTested` | ISO date of last compat test | `"2026-09-18"` |
| `persistence.enabled` | PVC for SQLite database | `true` |
| `persistence.storageClass` | Storage class | `""` |
| `persistence.size` | PVC size | `1Gi` |
| `rsaKeys.existingSecret` | Secret with `rsa_private.pem` + `rsa_public.pem` | `""` (auto-generated) |
| `vaultwarden.enabled` | Deploy bundled Vaultwarden | `false` |
| `vaultwarden.image.tag` | VW image tag | `"1.37.3"` |
| `vaultwarden.domain` | Public VW URL | required if enabled |
| `vaultwarden.sso.clientId` | OIDC client ID | `"vaultwarden"` |
| `vaultwarden.sso.clientSecret.value` | OIDC client secret (plain) | `""` |
| `vaultwarden.sso.clientSecret.existingSecret` | K8s secret ref instead of plain | `""` |
| `vaultwarden.sso.authority` | OIDC issuer URL | required |
| `vaultwarden.signupsAllowed` | Allow new signups | `"true"` |
| `vaultwarden.ssoOnly` | SSO-only mode (no master password) | `"false"` |
| `keycloak.enabled` | Deploy bundled Keycloak | `false` |
| `keycloak.adminPassword.value` | KC admin password | `"admin"` |
| `keycloak.adminPassword.existingSecret` | K8s secret ref | `""` |
| `keycloak.hostname` | Public KC URL | required if enabled |
| `keycloak.hostnameBackchannelDynamic` | Derive KC backchannel URLs from the incoming request | `"true"` |
| `keycloak.setup.realm` | OIDC realm to create | `"demo"` |
| `keycloak.setup.clientId` | OIDC client to create | `"vaultwarden"` |
| `keycloak.setup.clientSecret.value` | Client secret (plain) | `""` |
| `keycloak.setup.demoUser.username` | Demo user login | `"demo"` |
| `keycloak.setup.demoUser.password.value` | Demo user password | `""` |

### Integrating with an Existing Vaultwarden

If you already have Vaultwarden running, set `vaultwarden.enabled=false` and
point masterless at it:

```bash
helm install masterless oci://ghcr.io/antoniolago/charts/vaultwarden-masterless \
  --version 0.4.2 \
  --namespace vaultwarden \
  --set config.vaultwardenUrl=http://vaultwarden:80 \
  --set config.userKeysUrl=https://vault.example.com/user-keys \
  --set vaultwarden.enabled=false \
  --set vaultwardenRsaPublicKey.existingSecret=vw-rsa-pub-key \
  --set image.tag=main
```

### Mobile clients — one setting after the first login

A passwordless account has no master password to unlock with, and the Bitwarden apps **log
themselves out** when an account has neither a master password nor a PIN/biometrics
(`if (!activeAccount.hasManualUnlockMechanism) logout()` in the Android app's
`VaultUnlockViewModel`). The symptom is "I have to log in again every time I restart the app",
with the server looking perfectly healthy.

After the first SSO login, on each device:

1. **Settings → Account security → Unlock options** → enable **Unlock with PIN code** (works
   everywhere) and/or **Unlock with biometrics**.
2. On the same screen, make sure **Vault timeout**'s action is **Lock**, not *Log out*.

The first step is what stops the logouts; it cannot be set from the server — the unlock
mechanism is device-local state. The proxy warns in its log when it sees a device authenticating
repeatedly, which is the signature of this condition.

### Version Compatibility

Every instance exposes `GET /version` with both the version it was **tested
against** and the Vaultwarden it can see **actually running** (`status`: `match`
| `newer` | `older` | `unreachable`):

```bash
curl https://vault.example.com/version
```

```json
{
  "version": "0.2.0",
  "build": "sha-1a2b3c4d",
  "compatibility": {
    "vaultwarden": "1.37.3",
    "vaultwarden_detected": "1.37.3",
    "status": "match",
    "keycloak": "26.3.4",
    "clients": {
      "web": "2024.x - 2026.x",
      "desktop": "2024.x - 2026.x",
      "browser_extension": "2024.x - 2026.x",
      "mobile": "untested"
    },
    "last_tested": "2026-09-18",
    "status_url": "https://github.com/antoniolago/vaultwarden-masterless/blob/main/COMPATIBILITY.md"
  },
  "alive": true
}
```

See [COMPATIBILITY.md](./COMPATIBILITY.md) for the full compatibility matrix and
breakage risks when Bitwarden clients update.


## Configuration Reference

See [`.env.template`](./.env.template) for all options.

| Variable | Description | Default |
|---|---|---|
| `VAULTWARDEN_URL` | Internal URL of your Vaultwarden instance | *required* |
| `VAULTWARDEN_RSA_PUBLIC_KEY_FILE` | Path to Vaultwarden's RSA public key (for JWT verification) | *required* |
| `USER_KEYS_URL` | Public URL of `/user-keys` endpoint (proxy strips `/user-keys` suffix before injecting into client responses) | *(empty — disables passwordless)* |
| `HOST` | Bind address | `127.0.0.1` |
| `PORT` | Bind port | `8484` |
| `DATABASE_PATH` | SQLite database file | `./data/masterless.sqlite` |
| `RSA_PRIVATE_KEY_FILE` | RSA private key (protects stored keys) | `./data/rsa_private.pem` |
| `RSA_PUBLIC_KEY_FILE` | RSA public key | `./data/rsa_public.pem` |
| `PROXY_ENABLED` | Enable reverse proxy mode | `true` |
| `ROTATION_INTERVAL_HOURS` | Auto-rotate wrapping secret every N hours (0 = disabled) | `0` |
| `LOG_LEVEL` | Log level (trace/debug/info/warn/error) | `info` |

## Encryption & Key Rotation

User vault keys are encrypted at rest using three layers:

1. **AES-256-GCM** encrypts each user's key using a 256-bit **wrapping secret**
2. The wrapping secret is protected by **RSA-OAEP-SHA256** and stored in the database
3. The **RSA private key** lives on the filesystem (extendable to HSM/KMS)

### Automatic wrapping secret rotation

Set `ROTATION_INTERVAL_HOURS` to enable automatic rotation. On each rotation:

1. All user keys are decrypted with the **old** wrapping secret
2. A **new** wrapping secret is generated
3. All keys are re-encrypted with the new secret
4. The new secret is RSA-wrapped and stored
5. Everything is committed in a **single atomic database transaction**

**If any step fails, the database is left completely unchanged.** No data is ever lost.

Rotation is checked on startup and then hourly by a background task. Example:

```bash
ROTATION_INTERVAL_HOURS=720   # rotate every 30 days
```

### RSA key rotation

The RSA key pair protects the wrapping secret. To rotate RSA keys, you currently need to:

1. Keep the old private key available
2. Decrypt the wrapping secret with the old key
3. Re-encrypt it with the new key

This is handled automatically by the wrapping secret rotation — as long as the current RSA key can decrypt the existing wrapping secret, rotation will re-wrap it.

## Security Considerations

- **RSA private key** — Protect it. If compromised, an attacker can decrypt all stored vault keys.
- **Database** — Contains encrypted vault keys. Back it up securely.
- **Network** — Always use TLS. vaultwarden-masterless should not be exposed without HTTPS.
- **Trust model** — With passwordless mode, the server operator can theoretically decrypt user vaults. This is an intentional trade-off for organizations that prefer SSO-only authentication.

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/alive` | None | Health check |
| GET | `/version` | None | Version + compatibility matrix |
| GET | `/user-keys` | Bearer JWT | Retrieve user's encryption key |
| POST | `/user-keys` | Bearer JWT | Store user's key (first-time enrollment) |
| PUT | `/user-keys` | Bearer JWT | Update user's key |
| DELETE | `/user-keys` | Bearer JWT | Remove user's key |
| `*` | `/**` | Passthrough | Proxied to Vaultwarden (when proxy enabled) |

## Troubleshooting

### "You need to verify your email with your provider before you can log in"

Vaultwarden's SSO flow (`src/api/identity.rs:244-258`) checks the `email_verified` claim from the OIDC provider. There are TWO distinct cases:

| `email_verified` claim | Vaultwarden behavior | Fix |
|---|---|---|
| `None` (missing) | Blocked unless `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION=true` | Set env var |
| `Some(false)` | **Always blocked** — no env var bypasses this | Add `email_verified: true` claim in your OIDC provider |

**For Pocket-ID:** Pocket-ID does not include `email_verified` in its OIDC tokens by default. To fix, add a **custom claim** in the Pocket-ID admin panel:

1. Open the Pocket-ID admin panel (`https://<your-pocket-id-host>/admin/users`)
2. Select the user → Custom Claims → Add
3. Key: `email_verified`, Value: `true`
4. Save and restart Pocket-ID

Or via SQLite directly:
```sql
INSERT INTO custom_claims (id, created_at, key, value, user_id)
VALUES ('<uuid>', <unix_ts>, 'email_verified', 'true', '<user_uuid>');
```

**For other OIDC providers:** Check if your provider includes `email_verified` in the ID token or userinfo response. If it's missing, set `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION=true`. If it's explicitly `false`, add the claim as `true` in your provider's claim mapping.

## Further Reading

- **[DEV.md](./DEV.md)** — Local development, building, testing, test environment setup
- **[DEPLOYMENT.md](./DEPLOYMENT.md)** — Docker, Kubernetes, and production deployment
- **[VAULTWARDEN_PATCHES.md](./VAULTWARDEN_PATCHES.md)** — Details on which API responses are patched and why
- **[COMPATIBILITY.md](./COMPATIBILITY.md)** — Tested Vaultwarden / Keycloak / client versions
- **[SECURITY.md](./SECURITY.md)** — Experimental status and how to report a vulnerability

## License

AGPL-3.0-or-later. See [LICENSE](./LICENSE).
