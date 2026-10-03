#!/bin/bash
##############################################################################
# Keycloak setup for E2E tests
#
# Creates:
#   - A "test" realm
#   - An OIDC client "warden" with redirect URIs for the masterless proxy
#   - A test user
#   - A "dummy" realm as a sentinel to signal setup completion
##############################################################################

# Keycloak binaries are already in PATH in the official image
export PATH=/opt/keycloak/bin:$PATH

# Wait for Keycloak to accept TCP connections (no curl in this image)
while ! (echo > /dev/tcp/${KC_HTTP_HOST}/${KC_HTTP_PORT}) 2>/dev/null; do
    echo "Waiting for Keycloak TCP on ${KC_HTTP_HOST}:${KC_HTTP_PORT}... (will retry in 2s)"
    sleep 2
done

# Now wait for the HTTP endpoint to be ready via kcadm.sh
READY=0
while [[ "$READY" != "1" ]] ; do
    echo "Waiting for Keycloak HTTP... (will retry in 2s)"
    sleep 2
    if kcadm.sh config credentials \
        --server "http://${KC_HTTP_HOST}:${KC_HTTP_PORT}" \
        --realm master \
        --user "$KEYCLOAK_ADMIN" \
        --password "$KEYCLOAK_ADMIN_PASSWORD" \
        --client admin-cli 2>/dev/null; then
        READY=1
    fi
done

# Check if setup was already done (dummy realm exists)
#
# The sentinel realm is dropped and recreated on every run instead of being
# used as a "skip everything" shortcut: the shortcut left a stale realm/client
# behind whenever this script changed (e.g. a client created by a Keycloak whose
# default for direct access grants differed), and the suite then failed for
# reasons unrelated to the code under test. Reconciling every run is cheap and
# means the readiness wait on $DUMMY_REALM in the tests only succeeds after THIS
# run finished configuring the realm.
if kcadm.sh get "realms/$DUMMY_REALM" --fields realm 2>/dev/null | grep -q "$DUMMY_REALM"; then
    echo "Dropping sentinel realm $DUMMY_REALM to re-run the setup"
    kcadm.sh delete "realms/$DUMMY_REALM" || true
fi

set -e

echo "=== Configuring Keycloak ==="

kcadm.sh config credentials \
    --server "http://${KC_HTTP_HOST}:${KC_HTTP_PORT}" \
    --realm master \
    --user "$KEYCLOAK_ADMIN" \
    --password "$KEYCLOAK_ADMIN_PASSWORD" \
    --client admin-cli

realm_exists() {
    local realm="$1"
    kcadm.sh get "realms/${realm}" --fields realm >/dev/null 2>&1
}

client_id_by_clientid() {
    local realm="$1"
    local client_id="$2"
    kcadm.sh get clients -r "$realm" -q clientId="$client_id" --fields id,clientId 2>/dev/null \
        | grep '"id"' | head -n 1 | sed -E 's/.*"id" *: *"([^"]+)".*/\1/'
}

user_id_by_username() {
    local realm="$1"
    local username="$2"
    kcadm.sh get users -r "$realm" -q username="$username" --fields id,username 2>/dev/null \
        | grep '"id"' | head -n 1 | sed -E 's/.*"id" *: *"([^"]+)".*/\1/'
}

# Create test realm
echo "Creating realm: $TEST_REALM"
# Session lifetime, mirroring the chart's own realm settings. For SSO logins Vaultwarden hands
# the client the IdP's refresh token, so Keycloak's defaults (SSO Session Idle 30 minutes, Max
# 10 hours) would log every client out half an hour after it is closed — the fixture has to
# match production or the smoke's session-lifetime assertion fails for the wrong reason.
SSO_IDLE=2592000   # 30 days
SSO_MAX=2592000    # 30 days

if realm_exists "$TEST_REALM"; then
    echo "Realm $TEST_REALM already exists — ensuring session timeouts"
    kcadm.sh update "realms/$TEST_REALM" \
        -s "ssoSessionIdleTimeout=$SSO_IDLE" \
        -s "ssoSessionMaxLifespan=$SSO_MAX"
else
    kcadm.sh create realms \
        -s realm="$TEST_REALM" \
        -s enabled=true \
        -s "accessTokenLifespan=600" \
        -s "ssoSessionIdleTimeout=$SSO_IDLE" \
        -s "ssoSessionMaxLifespan=$SSO_MAX"
fi

# Create OIDC client — redirect URIs include both VW direct and masterless proxy (over HTTPS)
#
# Direct access grants (ROPC) are OFF, exactly as in the chart's own Keycloak
# setup (charts/*/templates/keycloak-setup-configmap.yaml): the only way into a
# vault is the browser SSO flow, so the fixture realm must not be more
# permissive than what ships. Keycloak 26 already defaults to false for clients
# created through the admin API, but this is a security boundary, and relying on
# a default that has changed between Keycloak versions is how the suite ended up
# disagreeing with the chart in the first place.
echo "Creating OIDC client: $SSO_CLIENT_ID"
CLIENT_ID=$(client_id_by_clientid "$TEST_REALM" "$SSO_CLIENT_ID")
if [[ -n "$CLIENT_ID" ]]; then
    echo "OIDC client $SSO_CLIENT_ID already exists; updating settings"
    kcadm.sh update "clients/$CLIENT_ID" -r "$TEST_REALM" \
        -s "secret=$SSO_CLIENT_SECRET" \
        -s "redirectUris=[\"$DOMAIN/*\", \"http://localhost:${ROCKET_PORT:-8000}/*\"]" \
        -s standardFlowEnabled=true \
        -s directAccessGrantsEnabled=false \
        -s serviceAccountsEnabled=false
else
    kcadm.sh create clients -r "$TEST_REALM" \
        -s "clientId=$SSO_CLIENT_ID" \
        -s "secret=$SSO_CLIENT_SECRET" \
        -s "redirectUris=[\"$DOMAIN/*\", \"http://localhost:${ROCKET_PORT:-8000}/*\"]" \
        -s standardFlowEnabled=true \
        -s directAccessGrantsEnabled=false \
        -s serviceAccountsEnabled=false \
        -i
fi

# Create test user
echo "Creating user: $TEST_USER"
TEST_USER_ID=$(user_id_by_username "$TEST_REALM" "$TEST_USER")
if [[ -n "$TEST_USER_ID" ]]; then
    echo "User $TEST_USER already exists; updating profile"
    kcadm.sh update "users/$TEST_USER_ID" -r "$TEST_REALM" \
        -s "firstName=$TEST_USER" \
        -s "lastName=$TEST_USER" \
        -s "email=$TEST_USER_MAIL" \
        -s emailVerified=true \
        -s enabled=true
else
    TEST_USER_ID=$(kcadm.sh create users -r "$TEST_REALM" \
        -s "username=$TEST_USER" \
        -s "firstName=$TEST_USER" \
        -s "lastName=$TEST_USER" \
        -s "email=$TEST_USER_MAIL" \
        -s emailVerified=true \
        -s enabled=true \
        -i)
fi
kcadm.sh update "users/$TEST_USER_ID/reset-password" -r "$TEST_REALM" \
    -s type=password \
    -s "value=$TEST_USER_PASSWORD" \
    -n

# Dummy realm to signal setup completion
echo "Creating sentinel realm: $DUMMY_REALM"
if realm_exists "$DUMMY_REALM"; then
    echo "Sentinel realm $DUMMY_REALM already exists"
else
    kcadm.sh create realms -s realm="$DUMMY_REALM" -s enabled=true -s "accessTokenLifespan=600"
fi

echo "=== Keycloak setup complete ==="
