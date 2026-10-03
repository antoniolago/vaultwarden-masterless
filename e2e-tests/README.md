# Vaultwarden Masterless — End-to-End Tests

Browser-based E2E tests validating the complete SSO authentication flow through the Masterless proxy, using the **exact same Playwright pattern** as Vaultwarden's own test suite.

## Architecture

All services use `network_mode: "host"` — everything runs on `localhost` with different ports. No Docker DNS issues, no nginx, no certificates needed.

```
Browser (Playwright, Firefox)
    │
    ├── http://localhost:8443  →  Masterless proxy  →  Vaultwarden (:8000)
    │                                                       │
    └── http://localhost:8080  →  Keycloak (OIDC)  ←────────┘
                                   (auto-configured via kcadm.sh)
```

**Keycloak** is used as the OIDC provider (not Pocket-ID) because:
- It has `kcadm.sh` for fully automated setup — no manual UI interaction
- Vaultwarden's own Playwright tests use Keycloak — proven to work
- OIDC is a standard — if SSO works with Keycloak, the flow is correct

## Quick Start

```bash
cd e2e-tests
./run-e2e-tests.sh
```

That's it. The script:
1. Checks prerequisites (docker, bun, node, openssl)
2. Installs deps + Playwright browser
3. Delegates to `bunx playwright test` which:
   - **global-setup**: Generates RSA keys, builds containers
   - **sso-setup**: Starts Keycloak, auto-creates realm + OIDC client + test user
   - **sso_login.spec.ts**: Full SSO login flow through masterless proxy
   - **sso_proxy.spec.ts**: Verifies proxy response patching (KeyConnectorOption)
   - **sso-teardown**: Stops all services

## Options

```bash
./run-e2e-tests.sh --keep      # Keep services running after tests
./run-e2e-tests.sh --headed    # Visible browser
./run-e2e-tests.sh --debug     # Playwright debug mode
./run-e2e-tests.sh --ui        # Playwright UI mode
```

## Ports Used

| Port | Service |
|------|---------|
| 8000 | Vaultwarden (direct, not exposed to users) |
| 8080 | Keycloak (OIDC provider) |
| 8443 | Masterless proxy (client entry point) |

## Test Files

| File | What it tests |
|------|--------------|
| `tests/sso_login.spec.ts` | Account creation via SSO, SSO login, non-SSO login, SSO-only mode, `/alive`, `/user-keys` auth, new device key migration |
| `tests/sso_proxy.spec.ts` | Proxy patches `/identity/connect/token` with `KeyConnectorOption`, patches `/api/accounts/profile`, patches `/api/sync` |
| `tests/proxy_response_patching.spec.ts` | All proxy-patched endpoints: `HasMasterPassword: false`, UK_enc injection for returning users, org flags, sync `keyConnectorUnlock`, confirmation-details stub, `/alive` vs direct VW |
| `tests/key_connector_flow.spec.ts` | `/user-keys` auth for all methods, response headers, `set-key-connector-key` endpoint, `confirmation-details` stub, full SSO enrollment/retrieval flow, multi-device key protection |
| `tests/security.spec.ts` | JWT forgery attacks, auth requirements, info leakage, container security (SEC-2 through SEC-9) |
| `tests/security_extended.spec.ts` | HTTP method restrictions, header injection, oversized payloads, rate limiting, token validation (SEC-10 through SEC-27) |
| `tests/vault_items.spec.ts` | Full vault CRUD: create, edit, delete, secure notes, search, special characters, lock/unlock, survival across re-login |
| `tests/vault_inspect_form.spec.ts` | Debugging test for DOM form inspection (not a production test) |

See [E2E_TEST_COVERAGE.md](./E2E_TEST_COVERAGE.md) for the full coverage matrix mapping every behavior to its tests.

## How It Works

### Key Generation (`global-setup.ts`)
- Generates 2048-bit RSA keys for VW JWT signing → `data/vw/rsa_key.pem`
- Generates 2048-bit RSA keys for masterless encryption → `data/keys/rsa_private.pem`
- Copies VW public key for masterless JWT verification → `data/keys/vw_rsa_key.pub.pem`
- Builds Masterless + KeycloakSetup Docker images

### Keycloak Setup (`compose/keycloak/setup.sh`)
- Waits for Keycloak to start
- Creates "test" realm via `kcadm.sh`
- Creates OIDC client `warden` with redirect URIs for `http://localhost:8443/*`
- Creates test user `test` / `test`
- Creates "dummy" realm as a sentinel (setup complete when this exists)

### Container Lifecycle (`global-utils.ts`)
- `startVaultAndMasterless()` — starts VW (port 8000) + Masterless (port 8443), waits for both
- `stopVaultAndMasterless()` — stops both
- VW uses `I_REALLY_WANT_VOLATILE_STORAGE=true` (in-memory SQLite, fresh per run)
- VW RSA key is pre-generated and bind-mounted to `/data/`

### SSO Flow (`tests/setups/sso.ts`)
Exact same selectors as VW's own Playwright tests:
1. Fill `.vw-email-sso` input with test email
2. Click "Use single sign-on"
3. Fill Keycloak username/password, click "Sign In"
4. First login: set master password → "Create account"
5. Subsequent login: enter master password → "Unlock"

## Troubleshooting

```bash
# View service logs
docker compose --profile e2e --env-file test.env logs Masterless
docker compose --profile keycloak --env-file test.env logs Keycloak

# Check what's running
docker ps --filter name=e2e_

# Manual test run with verbose output
bunx playwright test --reporter=list

# Stop everything
docker compose --profile e2e --profile keycloak --env-file test.env down
```

## Directory Structure

```
e2e-tests/
├── compose/keycloak/        # Keycloak setup container
│   ├── Dockerfile
│   └── setup.sh             # kcadm.sh automation
├── tests/
│   ├── setups/
│   │   ├── sso-setup.ts     # Start Keycloak (Playwright project dep)
│   │   ├── sso-teardown.ts  # Stop everything
│   │   └── sso.ts           # logNewUser / logUser helpers
│   ├── sso_login.spec.ts    # SSO login flow tests
│   └── sso_proxy.spec.ts    # Proxy patching tests
├── docker-compose.e2e.yml   # All services (host network)
├── test.env                 # All configuration
├── global-setup.ts          # Key generation + container builds
├── global-utils.ts          # Start/stop/wait helpers
├── playwright.config.ts     # Projects: sso-setup → sso-e2e → sso-teardown
├── package.json
├── run-e2e-tests.sh         # Single command entry point
└── README.md
```
