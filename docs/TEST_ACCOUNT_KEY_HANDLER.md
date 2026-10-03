# Test: POST /api/accounts/key handler

## Manual Test (requires running vaultwarden-masterless)

### Prerequisites
1. vaultwarden-masterless running with `LOG_LEVEL=debug`
2. Vaultwarden instance behind it
3. Test user account created via SSO

### Test Steps

#### 1. Test unauthenticated request (should fail)
```bash
curl -X POST http://localhost:8484/api/accounts/key \
  -H "Content-Type: application/json" \
  -d '{"key": "test-key"}'
```
**Expected**: 401 Unauthorized

#### 2. Test with valid SSO token
First, get a token from `/identity/connect/token`, then:
```bash
curl -X POST http://localhost:8484/api/accounts/key \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"key": "dGVzdC1rZXk="}'
```
**Expected**: 200 OK

#### 3. Verify key was stored
Query the SQLite database:
```bash
sqlite3 ./data/masterless.sqlite "SELECT user_id, encrypted_key IS NOT NULL FROM user_keys;"
```
**Expected**: User ID present with encrypted_key = 1

#### 4. Verify subsequent login works
1. Logout from web vault
2. Login again via SSO
3. Check browser console for errors
4. **Expected**: No `decapsulate_key_unsigned` errors, vault loads successfully

#### 5. Check logs
```bash
# Should see these in vaultwarden-masterless logs:
set-user-key: user=<UUID>, key_field_present=true
set-user-key: successfully stored symmetric key for user <UUID>
```

## Integration Test (requires test infrastructure)

TODO: Add Playwright test to e2e-tests/ that:
1. Creates fresh SSO user
2. Completes Key Connector enrollment
3. Verifies keys are stored
4. Logs out and back in
5. Confirms vault loads without errors
