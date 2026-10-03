# Fix: Key Connector Items Not Loading After SSO Login

## Problem Statement

After signing in with Keycloak SSO, users are redirected to the vault but:
- No items load
- Refreshing sends them back to the login page
- Console error: `TypeError: Cannot read properties of null (reading 'length')` at `decapsulate_key_unsigned`

## Root Cause

The Bitwarden client's Key Connector flow requires **two** pieces of data to be stored during first-time SSO enrollment:

1. **Asymmetric key pair** (public + encrypted private key) → stored in Vaultwarden ✅
2. **Wrapped symmetric vault encryption key** ("Key" or "akey") → **was NOT being stored** ❌

The `set-key-connector-key` handler in the proxy was **intentionally skipping** the symmetric key storage with this comment:
> "Stock Vaultwarden has no /api/accounts/key endpoint. Keep the value in masterless (/user-keys) and only persist account keys in VW."

**BUT** the code was only logging this, not actually storing the key! The symmetric key was simply discarded, leaving the user unable to decrypt their vault on subsequent logins.

## Solution

### 1. Added `POST /api/accounts/key` handler (`src/proxy.rs`)

New handler `handle_set_user_key()` that:
- Authenticates the request using JWT bearer token
- Extracts the `key` field from request body
- Encrypts it with AES-256-GCM using the wrapping secret
- Stores it in vaultwarden-masterless SQLite database

### 2. Modified `handle_set_key_connector_key()` 

Now calls `handle_set_user_key()` when a `key` field is present in the request body, ensuring the symmetric key is actually persisted.

### 3. Added diagnostic logging

Both handlers now log detailed information about the request:
- Whether keys are present
- Which fields are in the request body
- User ID for the stored key
- Success/failure status

## Files Changed

| File | Changes |
|------|---------|
| `src/proxy.rs` | +90 lines (new handler, logging, modified flow) |
| `VAULTWARDEN_PATCHES.md` | Updated documentation for new endpoint |
| `DEBUG_KEY_CONNECTOR.md` | New troubleshooting guide |
| `TEST_ACCOUNT_KEY_HANDLER.md` | New test procedures |

## How to Test

### Quick Test (existing deployment)
1. Set `LOG_LEVEL=debug` in vaultwarden-masterless
2. Create a **new** user via SSO (don't use existing users)
3. Watch logs for:
   ```
   set-key-connector-key: received request with keys=true, user_key=true
   set-user-key: successfully stored symmetric key for user <UUID>
   ```
4. User should now see their vault items

### Full Test (build & deploy new version)
1. Build: `cargo build --release`
2. Deploy the new binary
3. Create a fresh test user
4. Complete SSO login + Key Connector enrollment
5. Verify vault loads without errors
6. Logout and login again — should work without `decapsulate_key_unsigned` errors

## Important Notes

### Existing Users

Users who were created **before** this fix may still have the problem because:
- They never went through Key Connector enrollment
- Their `private_key` is `null` in Vaultwarden
- No symmetric key exists in vaultwarden-masterless

**Fix**: These users need to either:
- Delete their account and recreate via SSO (easiest)
- OR temporarily enable master password, set one, then migrate back to Key Connector

### Database Migration

No database migration needed — the new handler uses the existing `user_keys` table schema.

### Backward Compatibility

The fix is fully backward compatible:
- Existing users with keys are unaffected
- The new handler only activates when `POST /api/accounts/key` is called
- The proxy still handles `set-key-connector-key` the same way for asymmetric keys

## Technical Details

### Request Flow (First-Time SSO User)

```
1. User logs in via Keycloak SSO
   ↓
2. Vaultwarden returns token with AccountKeys: null
   ↓
3. Proxy patches response: HasMasterPassword=false, KeyConnectorOption added
   ↓
4. Client detects Key Connector flow needed
   ↓
5. Client generates asymmetric key pair + symmetric vault key
   ↓
6. Client calls POST /api/accounts/set-key-connector-key
   {
     "keys": { "encryptedPrivateKey": "...", "publicKey": "..." },
     "key": "<wrapped symmetric key>"
   }
   ↓
7. Proxy intercepts:
   a) Forwards "keys" → POST /api/accounts/keys (Vaultwarden) ✅
   b) Stores "key" → handle_set_user_key() → SQLite ✅ [NEW!]
   ↓
8. Client proceeds to vault — items load successfully ✅
```

### Subsequent Login Flow

```
1. User logs in via SSO
   ↓
2. Client calls GET /user-keys (from KeyConnectorUrl)
   ↓
3. Proxy retrieves encrypted key from SQLite
   ↓
4. Proxy decrypts with wrapping secret and returns key
   ↓
5. Client decrypts vault items successfully ✅
```

## Debugging Checklist

If the problem persists after deploying this fix:

- [ ] Check logs for `set-user-key` messages
- [ ] Verify user has `private_key` and `public_key` in Vaultwarden database
- [ ] Verify user has entry in vaultwarden-masterless `user_keys` table  
- [ ] Check browser Network tab for `POST /api/accounts/set-key-connector-key` response
- [ ] Check browser Network tab for `GET /user-keys` response
- [ ] Ensure `USER_KEYS_URL` is correctly configured and reachable from browser
- [ ] Review DEBUG_KEY_CONNECTOR.md for detailed troubleshooting steps
