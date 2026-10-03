# AGENTS.md — AI Agent Guide for vaultwarden-masterless

## What This Project Is

A Rust reverse proxy that sits in front of an **unmodified** Vaultwarden instance. It removes the need for a master password by intercepting API responses and injecting flags that tell Bitwarden clients to use server-side key storage (Key Connector) via SSO.

```
Clients ──▶ vaultwarden-masterless (proxy) ──▶ Vaultwarden (stock, unmodified)
                    │                                    │
              /user-keys (local)                    SSO via OIDC
              /alive (local)
                    │
               SQLite (encrypted)
```

Users authenticate via SSO. On first login the client generates an encryption key and POSTs it to `/user-keys`. On subsequent logins it GETs the key to decrypt the vault. No master password ever needed.

## Repository Layout

```
src/
├── main.rs       # Entry point, actix-web server, TLS, background rotation task
├── config.rs     # Environment variable loading (Config struct, from_env)
├── api.rs        # /alive and /user-keys HTTP handlers (GET/POST/PUT/DELETE)
├── auth.rs       # JWT validation against Vaultwarden's RSA public key
├── crypto.rs     # AES-256-GCM + RSA key management, wrapping secret rotation
├── db.rs         # SQLite operations (rusqlite), atomic rotation transaction
├── errors.rs     # AppError enum + actix ResponseError impl
├── models.rs     # Data structures (StoredKeyEntry, payloads, AuthenticatedUser)
├── proxy.rs      # Reverse proxy + API response patching (the core logic)
└── lib.rs        # Re-exports all modules for integration tests

tests/
└── integration_tests.rs  # Full HTTP flow tests with in-memory SQLite

e2e-tests/                # Playwright browser tests (Firefox)
├── tests/
│   ├── sso_login.spec.ts      # SSO flow: create account, login, lock/unlock
│   ├── sso_proxy.spec.ts      # Proxy response patching verification
│   ├── security.spec.ts       # Security tests
│   └── security_extended.spec.ts
├── docker-compose.e2e.yml     # Full stack: Keycloak + VW + Masterless
├── global-setup.ts            # RSA key generation, container builds
├── global-utils.ts            # Start/stop/wait helpers
└── run-e2e-tests.sh           # Single entry point

charts/vaultwarden-masterless/  # Helm chart (published to Harbor `charts` OCI)
├── Chart.yaml
├── values.yaml
└── templates/                  # 18 templates including bundled VW + Keycloak

deploy/                         # Docker Compose test stack (VW + Pocket-ID)
k8s/                            # Raw K8s manifests (alternative to Helm)
scripts/
├── generate-keys.sh            # RSA key pair generation
└── generate-tls-cert.sh        # Self-signed TLS cert generation

.forgejo/workflows/ci-cd.yml   # Primary CI: tests → e2e → image+chart publish
.github/workflows/ci-cd.yml    # Mirror for a future public GitHub repo (GHCR, multi-arch)
```

## Tech Stack

| Component | Technology |
|---|---|
| Language | Rust (edition 2021, requires 1.88+) |
| Web framework | actix-web 4 |
| Database | SQLite via rusqlite (bundled, no system install) |
| Crypto | aes-gcm 0.10, rsa 0.9, sha2 |
| JWT | jsonwebtoken 9 |
| HTTP client | reqwest 0.12 (for proxying to VW) |
| Config | dotenvy (`.env` files) |
| Logging | tracing + tracing-subscriber |
| Rate limiting | actix-governor |
| TLS | rustls 0.20 |
| Error handling | thiserror + anyhow |
| E2E tests | Playwright (Bun/TypeScript, Firefox) |

## Architecture Concepts

### Proxy Response Patching (proxy.rs — the most important file)

The proxy intercepts specific VW API responses and injects passwordless flags. **No VW source modification needed.** Key patched endpoints:

| Endpoint | What's injected |
|---|---|
| `/identity/connect/token` | `KeyConnectorOption` with base URL, `HasMasterPassword: false` |
| `/api/accounts/profile` | `usesKeyConnector: true`, org flags |
| `/api/sync` | Profile flags + `userDecryption.keyConnectorUnlock` |
| `/api/organizations/*` | `useKeyConnector`, `keyConnectorEnabled`, `keyConnectorUrl` |

Two endpoints are **synthesized** (they don't exist in stock VW):
- `/api/accounts/key-connector/confirmation-details/{id}` — stub response for enrollment
- `/api/accounts/set-key-connector-key` — translated to VW's `POST /api/accounts/keys`

### Synthetic Organization Injection

When a user has **no organizations**, the client's `findManagingOrganization()` fails silently. The proxy injects a synthetic org with Key Connector flags so the enrollment/unlock flow works.

**Critical detail**: The synthetic org uses `status: 1` (Accepted), NOT `status: 2` (Confirmed). Confirmed members are expected to have a non-null encrypted org key. Newer Bitwarden WASM clients pass `org.key` directly to `decapsulateKeyUnsigned` without a null check, crashing with:
```
TypeError: can't access property "length", e is null
    decapsulate_key_unsigned bitwarden_wasm_internal_bg.js
```
Using `status: 1` (Accepted) tells the client no org key exists yet, skipping decryption.

### Encryption Layers (crypto.rs)

1. **AES-256-GCM** encrypts each user's vault key with a 256-bit wrapping secret
2. The wrapping secret is **RSA-OAEP-SHA256** wrapped and stored in SQLite
3. The RSA private key lives on the filesystem

Sealed format: `nonce (12 bytes) || ciphertext`

### Key Rotation (crypto.rs + db.rs)

Controlled by `ROTATION_INTERVAL_HOURS`. On rotation:
1. Decrypt all keys with old secret
2. Generate new secret
3. Re-encrypt all keys
4. RSA-wrap new secret
5. Verify RSA roundtrip
6. Atomic DB transaction (all-or-nothing)

### JWT Authentication (auth.rs)

Validates Bearer tokens against VW's RSA public key. Accepts issuers:
- `{VAULTWARDEN_URL}` and `{VAULTWARDEN_URL}|login`
- `{DOMAIN}` and `{DOMAIN}|login` (when DOMAIN differs from internal URL)

Only allows `amr` methods: `Application`, `external`, `sso`.

## Key Configuration Variables

| Variable | Purpose | Default |
|---|---|---|
| `VAULTWARDEN_URL` | Internal VW URL (proxy target) | **required** |
| `VAULTWARDEN_RSA_PUBLIC_KEY_FILE` | VW's RSA public key for JWT verification | **required** |
| `USER_KEYS_URL` | Public URL of `/user-keys` (injected into responses) | empty = no passwordless |
| `PROXY_ENABLED` | Enable reverse proxy mode | `true` |
| `DOMAIN` | Public URL for JWT issuer validation (when VW_URL is internal) | unset |
| `ROTATION_INTERVAL_HOURS` | Auto-rotate wrapping secret (0 = disabled) | `0` |
| `SYNTHETIC_ORG_NAME` | Display name for injected org | `Vaultwarden Masterless` |
| `SYNTHETIC_ORG_IDENTIFIER` | Identifier for injected org | `vaultwarden-masterless` |

**Important**: `USER_KEYS_URL` gets its `/user-keys` suffix stripped before injection as `KeyConnectorUrl`. The Bitwarden client appends `/user-keys` itself.

## Development Commands

```bash
# Build
cargo build --release

# Run all tests (unit + integration)
cargo test

# Run with visible output
cargo test -- --nocapture

# Run only unit tests
cargo test --lib

# Run only integration tests
cargo test --test integration_tests

# Run E2E tests (requires Docker/Podman + Bun)
cd e2e-tests && ./run-e2e-tests.sh

# Generate RSA keys
./scripts/generate-keys.sh ./data
```

## Code Conventions

- **No `KC_` prefixes** — all legacy naming has been removed
- Error types: `AppError` / `AppResult` (thiserror-based)
- Crypto naming: `seal_vault_key` / `unseal_vault_key`, `wrap_with_rsa` / `unwrap_with_rsa`
- All names are clean-room, license-proof — no overlap with Bitwarden proprietary code
- JSON field names match Bitwarden client expectations exactly (PascalCase in API, camelCase in some contexts)
- Database uses `Mutex<Connection>` — single-writer SQLite; **single replica only**

## Testing Strategy

| Layer | Location | What's tested |
|---|---|---|
| Unit | `src/*.rs` `#[cfg(test)]` blocks | Crypto roundtrips, RSA wrap/unwrap, DB CRUD, proxy patching, JWT auth, rotation |
| Integration | `tests/integration_tests.rs` | Full HTTP request/response flow, auth rejection, user isolation, idempotent enrollment |
| E2E | `e2e-tests/tests/*.spec.ts` | Real browser SSO flow with Keycloak, proxy patching in live responses, security tests |

## CI/CD Pipeline

Two workflows run the same gates against the same code; they differ only in where the
artifacts land.

Forgejo (`.forgejo/workflows/ci-cd.yml`) — publishes to the maintainer's Harbor mirror:
1. **tests** — `cargo test --all`
2. **smoke** — browserless end-to-end check of the passwordless flow (**release gate**)
3. **e2e-tests** — Playwright with Firefox, Docker compose stack (2 shards), signal only
4. **vw-compat** — nightly E2E matrix over the Vaultwarden versions in COMPATIBILITY.md
5. **docker-publish** — image to Harbor `library` (`needs: [tests, smoke]`)
6. **helm-publish** — chart to Harbor `charts`

`.github/workflows/ci-cd.yml` runs on the **public GitHub repo**
(`antoniolago/vaultwarden-masterless`) and publishes to **GHCR** instead: same `unit-tests`
+ `smoke` gates, multi-arch image build, `docker-publish` (`needs: [docker-build, smoke]`),
`helm-lint` and `helm-publish`; the Playwright suites and the nightly `vw-compat` matrix run
as signals. Keep the two in step when a gate changes.

### Registry layout (do not mix these up)

Two registries are in play — the **public** one (GHCR, what the chart defaults to and what
the README tells users) and the maintainer's private mirror (Harbor, what the
`lag0-fleet-manifests` HelmReleases pin explicitly):

| Artifact | Public (GHCR) | Maintainer mirror (Harbor) |
|---|---|---|
| Helm chart | `oci://ghcr.io/antoniolago/charts/vaultwarden-masterless` | `oci://harbor.lag0.com.br/charts/vaultwarden-masterless` |
| Container image | `ghcr.io/antoniolago/vaultwarden-masterless:<tag>` | `harbor.lag0.com.br/library/vaultwarden-masterless:<tag>` |

Harbor's `charts` project holds charts and `library` holds images; pushing a chart to
`library` (or an image to `charts`) breaks that contract.

Image tags: CI pushes `main` (rolling, the default-branch tip) and `sha-<8 chars>` (pins a
commit). There is **no tag equal to the crate version** — do not leave `image.tag` empty,
or the chart would try to pull `appVersion` and fail.

## Helm Chart

Published to `oci://ghcr.io/antoniolago/charts/vaultwarden-masterless` (public) and
mirrored to Harbor (chart) with the image in `ghcr.io/antoniolago/vaultwarden-masterless`.
Supports:

- **Standalone mode**: Deploy masterless alongside an existing VW
- **Bundled VW** (`vaultwarden.enabled: true`): Auto-deploys stock VW, generates RSA keys, wires SSO config
- **Bundled Keycloak** (`keycloak.enabled: true`): Deploys Keycloak + setup Job (creates realm, OIDC client, demo user)

RSA keys are auto-generated via a Job on first install if not provided.

## Production Deployment (lag0-fleet-manifests)

The demo environment is deployed via Flux CD in the `lag0-fleet-manifests` repo:

```
lag0-fleet-manifests/
└── vaultwarden-masterless-demo-ton/
    ├── helm.yaml              # HelmRelease: chart from Harbor OCI registry
    ├── kustomization.yaml     # Flux kustomization
    ├── virtualservices.yaml   # Istio VirtualServices (proxy + keycloak)
    ├── ingress-ts.yaml        # Tailscale LoadBalancer services
    └── namespace.yaml
```

- **Cluster**: "ton" (home cluster)
- **Ingress**: Istio gateway → masterless service:8484
- **DNS**: `vaultwarden-masterless-demo.lag0.com.br` (masterless), `vaultwarden-masterless-demo-kc.lag0.com.br` (keycloak)
- **Secrets**: `vaultwarden-masterless-secrets` and `vaultwarden-masterless-demo-keycloak-secrets` (external)
- **Image**: Harbor mirror `harbor.lag0.com.br/library/vaultwarden-masterless`
- **Chart**: OCI from `harbor.lag0.com.br/charts`

Vaultwarden itself for the main environment is in `lag0-fleet-manifests/vaultwarden-ton/`.

## Known Issues & Gotchas

### Bitwarden WASM Client Null Key Crash (RESOLVED)

Newer Bitwarden web vault versions (2025+) include a WASM crypto module (`bitwarden_wasm_internal_bg.js`) that calls `decapsulateKeyUnsigned` on organization keys without null-checking. The proxy previously injected a synthetic organization (with `key: null`) for users with no real orgs, to satisfy `findManagingOrganization()`. However, the client's `setOrgKeys()` stores ALL org keys regardless of status, and `cipherDecryptionKeys$()` iterates them all — crashing on the null key:
```
TypeError: can't access property "length", e is null
```
**Fix**: Removed synthetic org injection entirely. The SSO enrollment flow is driven by `KeyConnectorOption` in the login token response, and the unlock flow uses `keyConnectorUnlock` in the sync `userDecryption` object — neither depends on `findManagingOrganization()`. The `status: 1` (Accepted) workaround was insufficient because `setOrgKeys()` doesn't check status.

### WebSocket Notifications

Vaultwarden uses SignalR WebSockets for push notifications (`/notifications/hub`). The masterless proxy forwards these but does **not** handle WebSocket upgrade specially — it's a plain HTTP proxy. WebSocket failures appear in the console but are non-fatal (the client falls back to polling).

### USER_KEYS_URL Suffix Stripping

The `KeyConnectorUrl` injected into responses must be the **base URL** (e.g. `https://vault.example.com`), not the full `/user-keys` path. The Bitwarden client appends `/user-keys` automatically. If misconfigured, the client calls `.../user-keys/user-keys` which 404s and logs the user out.

### Single Replica Constraint

SQLite doesn't support concurrent writers. Kubernetes deployments must use `strategy: Recreate` and `replicas: 1`.

### DOMAIN vs VAULTWARDEN_URL

When VW is behind a reverse proxy, its JWT tokens use the public DOMAIN as the issuer, not the internal URL. Set the `DOMAIN` env var to the public URL so JWT validation doesn't reject tokens.
