# Vaultwarden API Response Patching

> **Note**: This document is a reference for how vaultwarden-masterless patches
> Vaultwarden API responses. **No Vaultwarden source modifications are needed** —
> vaultwarden-masterless runs as a reverse proxy and intercepts responses on the fly.

## How It Works

vaultwarden-masterless sits between clients and an unmodified Vaultwarden instance.
It intercepts specific API responses and injects fields that tell clients to use
passwordless (SSO-only) login with server-side key storage.

## Patched Endpoints

### 1. `/identity/connect/token` (Login Response)

Adds `KeyConnectorOption` to `UserDecryptionOptions` and sets `HasMasterPassword`
to `false` so the client uses Key Connector instead of prompting for a master password:

```json
"UserDecryptionOptions": {
    "HasMasterPassword": false,
    "KeyConnectorOption": {
        "KeyConnectorUrl": "<BASE_URL>",
        "Object": "keyConnectorUserDecryptionOption"
    }
}
```

**Important**: `KeyConnectorUrl` is the **base URL** (e.g. `https://vault.example.com`),
not the full `/user-keys` endpoint. The Bitwarden client automatically appends `/user-keys`
when calling the Key Connector API (`api.service.ts: keyConnectorUrl + "/user-keys"`).
The proxy strips `/user-keys` from the `USER_KEYS_URL` config before injecting it.

Setting `HasMasterPassword: false` is critical — the Bitwarden client's SSO login
strategy only calls `setMasterKeyFromKeyConnector()` when this is `false`, and the
lock screen only hides the master password prompt when this is `false`.

### 2. `/api/accounts/profile` (User Profile)

Sets the user-level flag:

```json
"usesKeyConnector": true
```

Also patches all organization objects in the response (see below).

### 3. `/api/sync` (Full Sync)

Patches `profile.usesKeyConnector` and all organizations inside the sync payload.
Also injects `keyConnectorUnlock` into the `userDecryption` object for newer clients:

```json
"userDecryption": {
    "masterPasswordUnlock": null,
    "keyConnectorUnlock": {
        "keyConnectorUrl": "<BASE_URL>"
    }
}
```

(Same base URL derivation — `/user-keys` is stripped from `USER_KEYS_URL`.)

### 4. `/api/organizations/*` (Organization Details)

Sets per-organization flags:

```json
"useKeyConnector": true,
"keyConnectorEnabled": true,
"keyConnectorUrl": "<BASE_URL>",
"usesKeyConnector": true
```

### 5. `/api/accounts/key-connector/confirmation-details/{identifier}` (Stub)

This endpoint doesn't exist in stock Vaultwarden — it's a Bitwarden Server
feature. During the SSO enrollment flow, the client calls this to confirm
the Key Connector domain before proceeding with key enrollment. The proxy
returns a stub response so the client proceeds:

```json
{
  "Object": "keyConnectorConfirmationDetails",
  "OrganizationName": "Vaultwarden Masterless"
}
```

### 6. `/api/accounts/set-key-connector-key` (Translated)

This endpoint doesn't exist in stock Vaultwarden either. The client sends
the user's encryption keys here during SSO enrollment. The proxy translates
the request for stock Vaultwarden compatibility:

- `POST /api/accounts/keys` — stores the user's asymmetric key pair in Vaultwarden
- `POST /api/accounts/key` — stores the wrapped symmetric user key in vaultwarden-masterless

Stock Vaultwarden (current versions) does **not** implement `POST /api/accounts/key`.
The proxy now **intercepts this call** and stores the wrapped symmetric key in
`vaultwarden-masterless`'s database (`/user-keys`). This is critical — without
the symmetric key, the client cannot decrypt the vault on subsequent logins and
fails with `decapsulate_key_unsigned` errors.

### 7. `/api/accounts/key` (New — Intercepted)

**This is a Bitwarden Server endpoint that stock Vaultwarden doesn't implement.**

During Key Connector enrollment, the client calls `POST /api/accounts/key` to
persist the wrapped symmetric vault encryption key. The proxy intercepts this
and stores the key in vaultwarden-masterless's SQLite database, encrypted with
the AES wrapping secret.

Request body format:
```json
{
  "key": "<base64-encoded wrapped symmetric key>"
}
```

The proxy:
1. Authenticates the request using the JWT bearer token
2. Extracts the `key` field
3. Encrypts it with AES-256-GCM using the wrapping secret
4. RSA-wraps the secret and stores everything in SQLite

**Without this handler, the symmetric key was never persisted**, causing the
client to fail with `Cannot read properties of null (reading 'length')` in
`decapsulate_key_unsigned`.

### 8. Synthetic Organization Injection (Empty Org Arrays)

When Vaultwarden returns an empty `organizations` array (the user is not a member
of any organization), the proxy injects a **synthetic organization** with all
Key Connector flags enabled. Without this, the Bitwarden client's Key Connector
flow silently fails because:

- `findManagingOrganization()` requires at least one org with `keyConnectorEnabled: true`
- The enrollment and unlock flows check for a managing organization
- `convertAccountRequired$` depends on finding a qualifying org

The synthetic org uses:
- `type: 2` (User) — passes `findManagingOrganization()` which rejects Owner (0) and Admin (1)
- `status: 2` (Confirmed)
- `keyConnectorEnabled: true`, `ssoEnabled: true`, `useKeyConnector: true`
- A nil UUID (`00000000-0000-0000-0000-000000000000`) as the org ID

If the user already has real organizations, those are patched with Key Connector
flags instead (no synthetic injection).

## Field Reference

| Field | Type | Where | Purpose |
|---|---|---|---|
| `HasMasterPassword` | bool | login response | Set to `false` — tells client to use Key Connector instead of master password |
| `usesKeyConnector` | bool | profile, org members | Tells client this user uses server-side key storage |
| `useKeyConnector` | bool | organizations | Enables the feature for the organization |
| `keyConnectorEnabled` | bool | organizations | Marks the feature as active |
| `keyConnectorUrl` | string | organizations | URL where the client fetches/stores encryption keys |
| `KeyConnectorOption` | object | login response | Provides the key storage URL to the client on login |

## Security Note

When passwordless login is enabled, users' vault encryption keys are stored server-side.
This shifts the trust model: the service operator can theoretically decrypt user vaults.
This is an intentional trade-off for organizations that prefer SSO-only authentication.
