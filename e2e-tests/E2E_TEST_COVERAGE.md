# E2E Test Coverage Matrix

This document maps every core behavior of vaultwarden-masterless to the tests that verify it.

## Test Layer Overview

| Layer | Location | What's Tested |
|---|---|---|
| Unit | `src/*.rs` `#[cfg(test)]` blocks | Crypto, DB, JWT auth, proxy patching, response header logic |
| Integration | `tests/integration_tests.rs` | Full HTTP request/response flow, auth, CRUD, overwrite protection, user isolation |
| E2E | `e2e-tests/tests/*.spec.ts` | Full browser SSO flow, proxy patching in live responses, security headers, vault operations |

---

## Core Behavior → Test Coverage Map

### Proxy Response Patching (proxy.rs)

The most critical function — intercepting VW API responses and injecting passwordless flags.

| Behavior | Source | Unit Test | Integration Test | E2E Test |
|---|---|---|---|---|
| `/identity/connect/token` → inject `KeyConnectorOption` + `KeyConnectorUrl` | `patch_login_response` | ✅ `test_patch_login_response` | — | ✅ `PROXY-1a` in `proxy_response_patching.spec.ts` |
| `/identity/connect/token` → set `HasMasterPassword: false` | `patch_login_response` | ✅ (verified in unit test) | — | ✅ `PROXY-1b` in `proxy_response_patching.spec.ts` |
| `/identity/connect/token` → inject `Key` (UK_enc) for returning users | `patch_login_response` | ✅ (verified in unit test) | — | ✅ `PROXY-1c` in `proxy_response_patching.spec.ts` |
| `/api/accounts/profile` → set `usesKeyConnector: true` | `patch_profile_response` | ✅ `test_patch_profile_response` | — | ✅ `PROXY-2a` in `proxy_response_patching.spec.ts` |
| `/api/accounts/profile` → patch org `useKeyConnector`, `keyConnectorEnabled`, `keyConnectorUrl` | `patch_single_org` | ✅ `test_patch_org_response`, `test_synthetic_org_not_injected_when_orgs_exist` | — | ✅ `PROXY-2b` in `proxy_response_patching.spec.ts` |
| `/api/sync` → set `usesKeyConnector: true` on profile | `patch_sync_response` | ✅ `test_patch_sync_response` | — | ✅ `PROXY-3a` in `proxy_response_patching.spec.ts` |
| `/api/sync` → inject `keyConnectorUnlock` in `userDecryption` | `patch_sync_response` | ✅ (verified in unit test) | — | ✅ `PROXY-3b` in `proxy_response_patching.spec.ts` |
| `/api/organizations/*` → patch org flags | `patch_org_response` | ✅ `test_patch_org_response` | — | ⚠️ Not tested in E2E (requires a real org) |
| `/api/accounts/key-connector/confirmation-details/{id}` → stub response | `proxy_handler` | — | — | ✅ `KC-3` in `key_connector_flow.spec.ts` |
| `/api/accounts/set-key-connector-key` → translate to VW + store key | `handle_set_key_connector_key` | — | ✅ `test_proxy_set_key_connector_key_*` | ✅ `KC-4a/b/c` in `key_connector_flow.spec.ts` |
| `/api/accounts/key` → store symmetric key (overwrite protection) | `handle_set_user_key` | — | ✅ `test_proxy_accounts_key_*` | ✅ via `KC-4c` in `key_connector_flow.spec.ts` |
| `KeyConnectorUrl` suffix stripping (`/user-keys` removed) | `proxy_handler` line 107-109 | ✅ `test_key_connector_url_derivation` | — | ✅ (verified indirectly via `PROXY-1a`) |
| Non-JSON responses pass through unmodified | `patch_*` functions | ✅ `test_patch_non_json_passthrough` | — | ✅ (web vault HTML served through proxy) |
| Empty orgs remain empty (no synthetic injection) | `patch_org_array` | ✅ `test_empty_orgs_remain_empty`, `test_empty_orgs_remain_empty_in_sync` | — | ✅ (verified via `PROXY-2b` for new users) |

### `/user-keys` API Endpoints (api.rs)

| Behavior | Unit Test | Integration Test | E2E Test |
|---|---|---|---|
| `GET /alive` returns `{ alive: true, now }` | ✅ `test_alive_endpoint` | — | ✅ `PROXY-5a` |
| `GET /user-keys` returns 401 without auth | ✅ (implicit) | ✅ `test_get_without_auth_returns_401` | ✅ `KC-1a` |
| `GET /user-keys` returns 404 for nonexistent user | — | ✅ `test_get_nonexistent_key_returns_404` | — |
| `GET /user-keys` returns stored key for valid user | — | ✅ `test_full_enrollment_flow` | ✅ `KC-5` (via browser) |
| `POST /user-keys` enrolls new key | — | ✅ `test_full_enrollment_flow` | ✅ `KC-5` (via browser) |
| `POST /user-keys` idempotent (no overwrite) | — | ✅ `test_duplicate_enrollment_is_idempotent`, `test_post_different_key_preserves_original` | ✅ `KC-6` (via browser) |
| `PUT /user-keys` updates key | — | ✅ `test_put_updates_key` | — |
| `PUT /user-keys` returns 404 for nonexistent user | — | ✅ `test_put_nonexistent_returns_404` | — |
| `DELETE /user-keys` removes key | — | ✅ `test_delete_key`, `test_delete_nonexistent_returns_404` | — |
| Cross-user isolation | — | ✅ `test_different_users_isolated` | ✅ `SEC-21` (basic: unauth returns 401) |
| Cache-Control headers on responses | — | — | ✅ `KC-2a`, `SEC-11a` |
| X-Content-Type-Options headers | — | — | ✅ `KC-2a` (via 401 response check) |
| Rate limiting on `/user-keys` | — | — | ✅ `SEC-9` |
| `/alive` not rate-limited | — | — | ✅ `SEC-24` |

### Authentication (auth.rs)

| Behavior | Unit Test | Integration Test | E2E Test |
|---|---|---|---|
| Valid JWT with correct issuer accepted | ✅ `test_valid_jwt_extraction` | — | ✅ (all SSO login tests) |
| Missing auth header rejected | ✅ `test_missing_auth_header` | — | ✅ `KC-1a` |
| Expired token rejected | ✅ `test_expired_token` | — | — |
| Wrong signing key rejected | ✅ (implicit) | ✅ `test_wrong_signing_key_rejected` | ✅ `SEC-2a` |
| HS256 algorithm confusion rejected | — | — | ✅ `SEC-2b` |
| `alg:none` rejected | — | — | ✅ `SEC-2c` |
| SQL injection via auth header | — | — | ✅ `SEC-8` |
| Empty Bearer token rejected | — | — | ✅ `SEC-16a` |
| Non-Bearer auth scheme rejected | — | — | ✅ `SEC-16b` |
| Extremely long token | — | — | ✅ `SEC-16c` |

### Encryption (crypto.rs)

| Behavior | Unit Test | Integration Test | E2E Test |
|---|---|---|---|
| AES-256-GCM encrypt/decrypt roundtrip | ✅ `test_encrypt_decrypt_roundtrip` | ✅ (via full enrollment flow) | ✅ (vault items persist) |
| RSA wrap/unwrap roundtrip | ✅ `test_rsa_wrap_unwrap_roundtrip` | — | — |
| Tampered sealed data detected | ✅ `test_unseal_tampered_data` | — | — |
| Too-short sealed data rejected | ✅ `test_unseal_too_short_data` | — | — |
| Key rotation preserves all user keys | ✅ `test_rotation_preserves_all_user_keys` | — | — |
| Double rotation preserves keys | ✅ `test_double_rotation_preserves_keys` | — | — |
| Rotation with zero keys succeeds | ✅ `test_rotation_with_zero_keys` | — | — |
| New keys work after rotation | ✅ `test_new_keys_work_after_rotation` | — | — |
| Rotation records timestamp | ✅ `test_rotation_records_timestamp` | — | — |

### SSO Login Flow (browser)

| Behavior | E2E Test |
|---|---|
| First-time SSO login (account creation) | ✅ `sso_login.spec.ts` — "Account creation using SSO" |
| Returning SSO login (key retrieval) | ✅ `sso_login.spec.ts` — "SSO login" |
| Non-SSO login page renders | ✅ `sso_login.spec.ts` — "Non SSO login page renders" |
| SSO-only mode hides master password | ✅ `sso_login.spec.ts` — "SSO-only mode hides master password option" |
| New device login retrieves key | ✅ `sso_login.spec.ts` — "SSO login on new device" |
| Key Connector enrollment + retrieval flow | ✅ `KC-5`, `KC-6` in `key_connector_flow.spec.ts` |

### Vault Operations (browser)

| Behavior | E2E Test |
|---|---|
| Create and save login item | ✅ `vault_items.spec.ts` — "Create and save a login item" |
| Items survive page reload | ✅ `vault_items.spec.ts` — "Create and save a login item" (step) |
| Item survives logout/relogin | ✅ `vault_items.spec.ts` — "Vault item survives logout and re-login" |
| Edit and save vault item | ✅ `vault_items.spec.ts` — "Edit vault item" |
| Delete vault item | ✅ `vault_items.spec.ts` — "Delete vault item" |
| Create secure note | ✅ `vault_items.spec.ts` — "Vault encryption works through proxy" |
| Encryption works through proxy | ✅ `vault_items.spec.ts` — "Vault encryption works through proxy" |
| Vault search finds items | ✅ `vault_items.spec.ts` — "Vault search finds items" |
| Special characters in vault items | ✅ `vault_items.spec.ts` — "Vault items with special characters" |
| Lock/unlock preserves access | ✅ `vault_items.spec.ts` — "Lock/unlock vault" |

### Security (browser)

| Test ID | Description | File |
|---|---|---|
| SEC-2a/b/c | JWT forgery attacks (invalid sig, HS256, alg:none) | `security.spec.ts` |
| SEC-3 | All /user-keys methods require auth | `security.spec.ts` |
| SEC-4 | Error responses don't leak internal URLs | `security.spec.ts` |
| SEC-5 | Container runs as non-root | `security.spec.ts` |
| SEC-6 | SQLite DB not world-readable | `security.spec.ts` |
| SEC-7 | Path traversal blocked | `security.spec.ts` |
| SEC-8 | SQL injection via auth header | `security.spec.ts` |
| SEC-9 | Rate limiting on /user-keys | `security.spec.ts` |
| SEC-10 | Admin panel URL encoding bypass | `security_extended.spec.ts` ⚠️ commented out — feature not implemented |
| SEC-11a/b | Cache and server headers | `security_extended.spec.ts` |
| SEC-12 | HTTP method restrictions | `security_extended.spec.ts` |
| SEC-13a/b | Host header injection / SSRF | `security_extended.spec.ts` |
| SEC-14 | Oversized request body | `security_extended.spec.ts` |
| SEC-15 | Error responses don't leak infra | `security_extended.spec.ts` |
| SEC-16a/b/c/d | Token validation edge cases | `security_extended.spec.ts` |
| SEC-17a/b/c | POST /user-keys input validation | `security_extended.spec.ts` |
| SEC-18a/b | set-key-connector-key validation | `security_extended.spec.ts` |
| SEC-19 | Proxy doesn't follow redirects | `security_extended.spec.ts` |
| SEC-20 | TLS enforcement | `security_extended.spec.ts` |
| SEC-21 | Cross-user key isolation (basic) | `security_extended.spec.ts` |
| SEC-22 | Duplicate headers | `security_extended.spec.ts` |
| SEC-23 | Cookie security | `security_extended.spec.ts` |
| SEC-24 | /alive not rate-limited | `security_extended.spec.ts` |
| SEC-25 | Upgrade header doesn't bypass | `security_extended.spec.ts` |
| SEC-26 | Container minimal capabilities | `security_extended.spec.ts` |
| SEC-27 | Sensitive files not exposed | `security_extended.spec.ts` |

---

## Known Gaps

1. **SEC-1 (admin panel blocking)**: Commented out — the proxy has a TODO comment (`proxy.rs` line 24) but no implementation. Tests are commented out accordingly.

2. **Organization response patching** (`/api/organizations/*`): Tested in unit tests but requires a real org in VW for E2E. Currently not achievable without org provisioning in the test environment.

3. **PUT/DELETE /user-keys**: Tested in integration tests only. E2E browser tests don't exercise these endpoints directly — the Bitwarden client only uses GET/POST.

4. **Key rotation**: Tested in unit tests only (crypto.rs). E2E testing would require restarting the service mid-test with `ROTATION_INTERVAL_HOURS` set, which is complex to orchestrate.

5. **`/api/accounts/key` full flow**: The proxy intercepts this and stores the key locally. Integration tests cover overwrite protection, but E2E browser testing relies on SSO client flow which uses `/user-keys` directly.

---

## Playwright Project Structure

| Project | Test Match | Dependencies | Purpose |
|---|---|---|---|
| `sso-setup` | `tests/setups/sso-setup.ts` | — | Start Keycloak, create realm/client/user |
| `sso-e2e` | `tests/sso_*.spec.ts` | `sso-setup` | SSO login + proxy verification |
| `security` | `tests/security*.spec.ts` | `sso-setup` | Security hardening tests |
| `vault-e2e` | `tests/{e2e_vault,vault_items}*.spec.ts` | `sso-setup` | Vault CRUD operations |
| `proxy-patching` | `tests/proxy_response_patching.spec.ts` | `sso-setup` | All proxy-patched endpoint verification |
| `key-connector-flow` | `tests/key_connector_flow.spec.ts` | `sso-setup` | Key Connector enrollment/retrieval flow |
| `sso-teardown` | `tests/setups/sso-teardown.ts` | — | Stop all services |