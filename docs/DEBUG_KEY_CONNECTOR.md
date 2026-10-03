# Debug: Key Connector - Items not loading after SSO login

## Problem
After signing in with Keycloak SSO, you're redirected to vault but:
- No items load
- On refresh, you're sent back to the login page
- Console shows: `TypeError: Cannot read properties of null (reading 'length')` in `decapsulate_key_unsigned`

## Root Cause Analysis

This error occurs when the Bitwarden client tries to decrypt the vault encryption key using the user's private key, but the **private key is null**.

### Why does this happen?

When a user logs in via SSO for the first time with vaultwarden-masterless:

1. **Initial SSO Login**: Vaultwarden returns `AccountKeys: null` (user has no asymmetric keys yet)
2. **Key Connector Flow**: Client detects `HasMasterPassword: false` and initiates Key Connector enrollment
3. **Client generates keys** and calls `POST /api/accounts/set-key-connector-key`
4. **Proxy intercepts** and:
   - Forwards asymmetric keys to Vaultwarden's `POST /api/accounts/keys`
   - Stores symmetric key in vaultwarden-masterless's database

If any step fails, the user ends up with:
- `private_key = null` in Vaultwarden
- No symmetric key stored in vaultwarden-masterless
- Client crashes on `decapsulate_key_unsigned`

## Possible Scenarios

### Scenario 1: User created BEFORE vaultwarden-masterless was configured

If the user account was created via SSO **before** vaultwarden-masterless was deployed:
- The user never went through Key Connector enrollment
- No asymmetric keys exist in Vaultwarden
- No symmetric key exists in vaultwarden-masterless

**Solution**: The user needs to **delete their account** and recreate it, OR:
1. Enable master password login temporarily
2. Set a master password
3. Then migrate to Key Connector

### Scenario 2: First-time SSO login (fresh user)

This should work correctly with the proxy fix. The logs will show:
```
set-key-connector-key: received request with keys=true, user_key=true
set-key-connector-key: stored asymmetric keys in VW
set-user-key: successfully stored symmetric key for user <UUID>
```

### Scenario 3: Key storage failed

If the proxy couldn't store the keys, check logs for errors like:
- `set-key-connector-key: VW POST /api/accounts/keys returned 4xx`
- `set-user-key: failed to store key in database`

## Diagnostic Steps

### 1. Check vaultwarden-masterless logs

Set `LOG_LEVEL=debug` in your environment and look for:
```
set-key-connector-key: received request with keys=...
set-user-key: user=...
```

### 2. Check if user has keys in Vaultwarden

Query your Vaultwarden database:
```sql
SELECT uuid, email, private_key IS NOT NULL as has_keys, public_key IS NOT NULL as has_pub_key
FROM users 
WHERE email = 'user@example.com';
```

### 3. Check if user has keys in vaultwarden-masterless

Query the masterless database:
```sql
SELECT user_id, encrypted_key IS NOT NULL as has_encrypted_key, created_at
FROM user_keys 
WHERE user_id = '<USER_UUID>';
```

### 4. Check browser Network tab

Look for these API calls during login:
1. `POST /identity/connect/token` - Initial SSO token exchange
2. `POST /api/accounts/set-key-connector-key` - Key enrollment (should happen on first login)
3. `GET /user-keys` - Key retrieval (on subsequent logins)

Check the **request body** of #2 - it should contain:
```json
{
  "keys": {
    "encryptedPrivateKey": "...",
    "publicKey": "..."
  },
  "key": "..."
}
```

## Quick Fix for Existing Users

If the user was created before vaultwarden-masterless:

### Option A: Delete and recreate user (easiest)
1. Delete the user from Vaultwarden admin panel
2. User logs in via SSO again (creates fresh account with Key Connector)

### Option B: Manual migration (advanced)
1. Enable master password in Vaultwarden config temporarily
2. User sets a master password via web vault
3. Disable master password again
4. User logs in via SSO - should trigger Key Connector flow

## What the Proxy Fix Does

The fix adds a handler for `POST /api/accounts/key` which:
1. Authenticates the request using the JWT token
2. Extracts the wrapped symmetric key from the request body
3. Encrypts it with our AES wrapping secret
4. Stores it in the vaultwarden-masterless SQLite database

This ensures that when the Bitwarden client calls `set-key-connector-key`, **both** the asymmetric keys (stored in Vaultwarden) AND the symmetric key (stored in masterless) are persisted.

## Testing the Fix

After deploying the updated proxy:

1. **Create a fresh test user** (don't use existing users)
2. Log in via Keycloak SSO
3. Watch the logs for the key enrollment flow
4. The client should successfully enroll keys and proceed to the vault

If it still fails, the logs will tell us exactly where the flow breaks.
