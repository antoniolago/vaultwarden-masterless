# vaultwarden-masterless — Compatibility Matrix

> **Last updated:** 2026-09-18
> **Live status:** `GET /version` on any running instance
> **Project status:** 🧪 **experimental** — see the notice in [README.md](./README.md) and
> [SECURITY.md](./SECURITY.md). Releases are for test instances and evaluation.

This document tracks which versions of Vaultwarden, Keycloak, and Bitwarden
clients have been tested with vaultwarden-masterless.

Bitwarden Inc. owns the client code and may change the SSO / Key Connector flow
in a way that breaks vaultwarden-masterless without notice. Vaultwarden itself
also moves: **its SSO implementation changed in 1.36.0 and again in 1.37.0**, so
the version you run matters for this project more than for a plain Vaultwarden
deployment.

**Pin your Vaultwarden version**, and let `GET /version` tell you when what you
run has drifted from what was tested.

## Tested Versions

| Component | Tested Version(s) | Status |
|-----------|-------------------|--------|
| **Vaultwarden** | 1.37.3 | ✅ Tested |
| **Keycloak** | 26.3.4 | ✅ Tested |
| **vaultwarden-masterless** | 0.2.0 | ✅ Current |

### Minimum recommended Vaultwarden

**1.36.0 or newer.** 1.36.0 shipped security fixes that land squarely on the
flow this project depends on:

- SSO Login CSRF — GHSA-pfp2-jhgq-6hg5, GHSA-w6h6-8r66-hcv7
- SSO existing-user binding — GHSA-j4j8-gpvj-7fqr, GHSA-6x5c-84vm-5j56
- User / Organization enumeration — GHSA-hxqh-ff5p-wfr3

1.37.0 added more (icon-endpoint SSRF, cross-organization cipher access,
organization policy bypass on directory import, unauthenticated WebSocket
flooding DoS, cross-organization secret sharing, organization import
authorization, organization data enumeration via the Manager role). If your
Vaultwarden predates these, upgrade before running passwordless SSO — the whole
point of this project is that the SSO path is trustworthy.

## Bitwarden Clients

| Client | Version Range | Status | Notes |
|--------|--------------|--------|-------|
| **Web vault** (Firefox) | 2024.x – 2026.x | ✅ Tested | SSO → Key Connector enrollment → vault decrypt |
| **Desktop** (Linux, RPM) | 2024.x – 2026.x | ✅ Tested | SSO with browser redirect. Requires D-Bus for `xdg-open`. |
| **Desktop** (Linux, sandbox) | 2024.x – 2026.x | ⚠️ Works | `HOME=/tmp/bw-sandbox bitwarden-desktop` isolates data dir. |
| **Browser extension** (Firefox) | 2024.x – 2026.x | ✅ Tested | Standard SSO flow |
| **Mobile** (Android) | 2026.x | ⚠️ Works — one client-side step required | Log in with SSO, then enable *Unlock with Biometrics* (or a PIN) when the app offers "Set up unlock". A Key Connector account with no manual unlock mechanism is **logged out by the app itself** on the next start — `VaultUnlockViewModel` calls `logout()` when `hasManualUnlockMechanism` is false, and that flag is `hasMasterPassword \|\| isBiometricsEnabled` (or a PIN) — which is the "I have to log in again every time I restart" report. The session/refresh/key-retrieval path is covered by the browserless smoke. |

> Client/server coupling: Vaultwarden 1.37.2 and later require Bitwarden clients
> **2026.8.0+**. An older client against a newer server can fail before
> vaultwarden-masterless is ever involved — check Vaultwarden's own release notes
> before blaming the proxy.

## Runtime Detection (added in 0.2.0)

`GET /version` reports two different things, which used to be conflated:

| Field | Meaning |
|-------|---------|
| `compatibility.vaultwarden` | The version this build was **tested against** (`COMPAT_VW_VERSION`) |
| `compatibility.vaultwarden_detected` | The version **actually running**, read from Vaultwarden at runtime |
| `compatibility.status` | Verdict: `match` \| `newer` \| `older` \| `unreachable` \| `unknown` |

The proxy asks Vaultwarden (`GET /api/version`, falling back to `/api/config`) at
startup, retrying every 60s while it is unreachable, then re-checking every 6
hours so a long-running pod notices an upgrade underneath it.

- `match` — running exactly what CI tested. Nothing to do.
- `newer` — **you are on untested territory.** The proxy logs a `warn` at
  startup. Run the E2E suite against that version (see below) or roll back.
- `older` — you are behind the tested version. Check the security section above.
- `unreachable` — Vaultwarden could not be reached by the proxy. Fix connectivity;
  nothing can be said about compatibility.

Detection is best-effort: it never blocks startup and never fails `/version`.

## What Breaks When Versions Change

### Vaultwarden side

The proxy patches these API responses; a shape change in any of them is the
failure mode.

| Endpoint | What masterless does | Risk |
|----------|---------------------|------|
| `POST /identity/connect/token` | Injects `KeyConnectorOption`, `HasMasterPassword: false` | **Medium** — field renames break login |
| `GET /api/accounts/profile` | Injects `usesKeyConnector: true`, synthetic org | **Medium** — client may reject unknown orgs |
| `GET /api/sync` | Injects `keyConnectorUnlock` | **Low** — extra field is usually ignored |
| `GET /api/organizations/*` | Injects `keyConnectorEnabled`, `keyConnectorUrl` | **Medium** — org shape changes break parsing |
| `POST /api/accounts/set-key-connector-key` | Synthetic endpoint (not in stock VW) | **High** — client may change payload format |
| `GET /api/accounts/key-connector/confirmation-details/*` | Synthetic endpoint (stub) | **Low** — simple stub, rarely changes |
| `POST /api/accounts/convert-to-key-connector` | Synthetic endpoint (stub) | **Low** — simple stub |

Two rules keep the rewriting from touching sessions it should not:

- **Only non-password grants are rewritten.** `POST /identity/connect/token` with
  `grant_type=password` is passed through untouched: answering `HasMasterPassword: false`
  plus a `KeyConnectorOption` there tells the client to skip the password the account really
  has, and offers a connector flow the user never enrolled in. `authorization_code` (the SSO
  callback) and `refresh_token` keep the configured behaviour. The grant type is the only
  signal that distinguishes the two on every Vaultwarden build — nothing in the response
  does (a session's `amr` is not a reliable marker).
- **A connector the server already advertises wins.** If a login response already carries
  `UserDecryptionOptions.KeyConnectorOption`, it is left exactly as it is; overwriting the
  URL would silently point clients at a different connector than the one that server ships.
| `POST /api/accounts/key` | Synthetic endpoint (stores key) | **High** — client may change key format |
| `GET/POST /user-keys` | Local endpoint (key storage) | **Low** — our own API |

### Client side

What the proxy injects must match what the Bitwarden clients expect. These are
the fields to re-check when a client release breaks SSO:

| Injected field | Where | Breaks when |
|----------------|-------|-------------|
| `KeyConnectorOption` | token response | Client stops treating it as the SSO key-connector trigger |
| `HasMasterPassword: false` | token + profile | Client starts requiring a master password anyway |
| `usesKeyConnector: true` | profile | Client looks for the flag somewhere else |
| `keyConnectorUnlock` | sync | SDK unlock flow changes shape |
| Synthetic org with `status: 1` | profile + sync | Client starts requiring a real org key — newer WASM clients crash without the null check (`decapsulateKeyUnsigned`) |

## Testing a New Version

E2E runs against a configurable Vaultwarden tag, so testing a new release is one
variable:

```bash
# Full stack (Keycloak + Vaultwarden + masterless) on a specific VW version
cd e2e-tests
VW_TAG=1.37.3 ./run-e2e-tests.sh
```

CI runs this against the versions in the compatibility matrix
(`.forgejo/workflows/ci-cd.yml`, job `vw-compat`), plus a nightly run against
Vaultwarden's `testing` tag with `continue-on-error` so upstream breakage is
visible without blocking this repo.

When a new version passes:

1. Bump `vaultwarden.image.tag` and `config.compatVwVersion` in
   `charts/vaultwarden-masterless/values.yaml`
2. Bump the pins in `e2e-tests/docker-compose.e2e.yml`, `deploy/docker-compose.yml`
   and the `COMPAT_*` defaults in `Dockerfile` / `src/config.rs`
3. Update the tables above and `COMPAT_LAST_TESTED`

## Recovery When an Upgrade Breaks Things

1. **Check `GET /version`** — is `status` something other than `match`?
2. **Pin Vaultwarden back** to the tested version (`vaultwarden.image.tag`)
3. **Pin Bitwarden clients** — don't auto-update if you rely on SSO
4. **Read the proxy logs** — `Client connected: type=X, name=Y` shows which
   clients are connecting; the startup banner shows the detected Vaultwarden
5. **Roll back** the client, or upgrade vaultwarden-masterless

## Version Endpoint

Every vaultwarden-masterless instance exposes `GET /version`:

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
      "mobile": "2026.x (biometrics or PIN must be enabled in the app)"
    },
    "last_tested": "2026-09-18",
    "status_url": "https://github.com/antoniolago/vaultwarden-masterless/blob/main/COMPATIBILITY.md"
  },
  "alive": true
}
```

The response also carries the header `X-Vaultwarden-Masterless-Version: 0.2.0`.
