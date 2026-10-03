#!/usr/bin/env node
/**
 * Browserless smoke test of the passwordless SSO flow.
 *
 * Why this exists: the SSO/Key Connector path is the product, and the only end-to-end
 * check we had needed a browser — which the CI runner cannot drive reliably. This walks the
 * very same protocol the web vault walks, with plain HTTP and no JavaScript:
 *
 *   prevalidate (ssoToken) → /identity/connect/authorize (PKCE S256) → Keycloak login form
 *   → oidc-signin → sso-connector callback (code, state) → /identity/connect/token
 *   → /api/sync
 *
 * and then asserts what the product promises about those responses:
 *   - the token response carries UserDecryptionOptions.KeyConnectorOption (the proxy's job)
 *     and HasMasterPassword: false
 *   - /api/sync carries userDecryption.keyConnectorUnlock and profile.usesKeyConnector
 *
 * Exit code 0 = the flow works end to end; 1 = it does not, with the reason on stderr.
 *
 * Configuration (env):
 *   SMOKE_BASE    e.g. https://vaultwarden-masterless-demo.lag0.com.br   (required)
 *   SMOKE_KC      e.g. https://vaultwarden-masterless-demo-kc.lag0.com.br (required)
 *   SMOKE_REALM   Keycloak realm                          (default: demo)
 *   SMOKE_USER    Keycloak username to log in with        (required)
 *   SMOKE_PASS    Keycloak password                       (required)
 *   SMOKE_ORG     SSO organization identifier / domain hint (required)
 *   SMOKE_TIMEOUT per-request timeout in ms               (default: 20000)
 *   SMOKE_ENROLL  set to 1 to enrol a throwaway key first — only for targets whose account
 *                 is disposable (the CI stack). On a live account a re-enrolment would
 *                 overwrite the key the vault is encrypted with, so this stays off there.
 */

import { createHash, randomUUID, randomBytes } from 'node:crypto';

const BASE = (process.env.SMOKE_BASE || '').replace(/\/+$/, '');
const KC = (process.env.SMOKE_KC || '').replace(/\/+$/, '');
const REALM = process.env.SMOKE_REALM || 'demo';
const USER = process.env.SMOKE_USER;
const PASS = process.env.SMOKE_PASS;
const ORG = process.env.SMOKE_ORG;
const TIMEOUT = Number(process.env.SMOKE_TIMEOUT || 20_000);
// Floor for the refresh token's lifetime. For SSO logins Vaultwarden adopts the IdP's refresh
// token, so a short IdP session logs every client out — assert it here instead of discovering
// it on someone's phone.
const MIN_REFRESH_DAYS = Number(process.env.SMOKE_MIN_REFRESH_DAYS || 7);
const REDIRECT_URI = `${BASE}/sso-connector.html`;
const ENROLL = process.env.SMOKE_ENROLL === '1';
// Vaultwarden refuses API calls that arrive without a client version, and the mobile apps
// identify themselves as device type 10 (SDK/web) / their own type; send both like a client.
const CLIENT_VERSION = process.env.SMOKE_CLIENT_VERSION || '2025.6.0';

for (const [name, value] of Object.entries({ SMOKE_BASE: BASE, SMOKE_KC: KC, SMOKE_USER: USER, SMOKE_PASS: PASS, SMOKE_ORG: ORG })) {
    if (!value) {
        console.error(`smoke: ${name} is required`);
        process.exit(2);
    }
}

const fail = (step, detail) => {
    console.error(`smoke: FAILED at ${step}\n  ${detail}`);
    process.exit(1);
};

// --- a cookie jar, because fetch() does not keep one -------------------------
const jar = new Map();
function absorbCookies(res) {
    const raw = typeof res.headers.getSetCookie === 'function'
        ? res.headers.getSetCookie()
        : [res.headers.get('set-cookie')].filter(Boolean);
    for (const line of raw) {
        const [pair] = line.split(';');
        const idx = pair.indexOf('=');
        if (idx > 0) jar.set(pair.slice(0, idx).trim(), pair.slice(idx + 1).trim());
    }
}
function cookieHeader() {
    return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
}

async function request(method, url, { body, headers = {}, follow = 'manual' } = {}) {
    const res = await fetch(url, {
        method,
        redirect: follow,
        headers: {
            'user-agent': 'vaultwarden-masterless-smoke/1.0',
            'bitwarden-client-version': CLIENT_VERSION,
            'device-type': '10',
            ...(jar.size ? { cookie: cookieHeader() } : {}),
            ...headers,
        },
        body,
        signal: AbortSignal.timeout(TIMEOUT),
    });
    absorbCookies(res);
    return res;
}

function report(fields) {
    console.log(JSON.stringify({ ok: true, base: BASE, idp: KC, ...fields }));
}

const b64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/**
 * POST a token request to the proxy. Vaultwarden's token endpoint accepts only a form body
 * (JSON answers 415), and the mobile apps post form-encoded first and fall back on the other
 * shape — do the same, so the smoke reproduces real client traffic instead of provoking 415s.
 */
async function postToken(payload) {
    let res = await request('POST', `${BASE}/identity/connect/token`, {
        body: new URLSearchParams(payload).toString(),
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    if (res.status === 415) {
        res = await request('POST', `${BASE}/identity/connect/token`, {
            body: JSON.stringify(payload),
            headers: { 'content-type': 'application/json' },
        });
    }
    return res;
}

async function main() {
    const steps = [];

    // 1. prevalidate → the ssoToken the authorize call expects ------------------
    const pre = await request('GET', `${BASE}/identity/sso/prevalidate?domainHint=${encodeURIComponent(ORG)}`);
    if (!pre.ok) fail('prevalidate', `HTTP ${pre.status} from ${pre.url}`);
    const { token: ssoToken } = await pre.json().catch(() => ({}));
    if (!ssoToken) fail('prevalidate', 'no ssoToken in the response');
    steps.push('prevalidate');

    // 2. authorize with our own PKCE pair --------------------------------------
    const verifier = b64url(randomBytes(32));
    const challenge = b64url(createHash('sha256').update(verifier).digest());
    const state = `${b64url(randomBytes(32))}_identifier=${ORG}`;
    const authorize = new URL(`${BASE}/identity/connect/authorize`);
    for (const [k, v] of Object.entries({
        client_id: 'web',
        redirect_uri: REDIRECT_URI,
        response_type: 'code',
        scope: 'api offline_access',
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        response_mode: 'query',
        domain_hint: ORG,
        ssoToken,
    })) authorize.searchParams.set(k, v);

    const authRes = await request('GET', authorize.toString());
    const kcLocation = authRes.headers.get('location');
    if (!kcLocation) fail('authorize', `expected a redirect to the IdP, got HTTP ${authRes.status}`);
    if (!kcLocation.startsWith(KC)) {
        fail('authorize', `redirected to ${kcLocation.slice(0, 120)} instead of the expected IdP ${KC}`);
    }
    steps.push('authorize');

    // 3. Keycloak login form ---------------------------------------------------
    const loginPage = await request('GET', kcLocation);
    if (!loginPage.ok) fail('keycloak-login-page', `HTTP ${loginPage.status}`);
    const html = await loginPage.text();
    const action = html.match(/<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"/i)?.[1]
        ?? html.match(/<form[^>]+action="([^"]+)"[^>]*>/i)?.[1];
    if (!action) fail('keycloak-login-page', 'could not find the login form action');
    const formAction = action.replace(/&amp;/g, '&');

    const form = new URLSearchParams();
    for (const [, name, value] of html.matchAll(/<input[^>]+name="([^"]+)"[^>]*value="([^"]*)"[^>]*>/gi)) {
        if (/^(username|password|credentialId)$/.test(name)) continue;
        form.set(name, value.replace(/&amp;/g, '&'));
    }
    form.set('username', USER);
    form.set('password', PASS);
    form.set('credentialId', '');

    const loginPost = await request('POST', formAction, {
        body: form.toString(),
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    if (loginPost.status >= 400) {
        fail('keycloak-login', `HTTP ${loginPost.status} — check SMOKE_USER/SMOKE_PASS`);
    }
    steps.push('keycloak-login');

    // 4. follow the redirect chain until the callback carries the code ----------
    let next = loginPost.headers.get('location');
    let code = null;
    let returnedState = null;
    for (let hop = 0; hop < 6 && next; hop += 1) {
        const url = new URL(next, KC);
        if (url.pathname.endsWith('/sso-connector.html') && url.searchParams.get('code')) {
            code = url.searchParams.get('code');
            returnedState = url.searchParams.get('state');
            break;
        }
        const res = await request('GET', url.toString());
        if (res.status >= 400) fail('callback-chain', `HTTP ${res.status} from ${url.pathname}`);
        next = res.headers.get('location');
    }
    if (!code) fail('callback-chain', `never reached the SSO callback with a code (last redirect: ${next ?? 'none'})`);
    if (returnedState !== state) {
        fail('callback-chain', `state came back changed:\n  sent: ${state.slice(0, 40)}…\n  got:  ${String(returnedState).slice(0, 40)}…`);
    }
    steps.push('callback');

    // 5. exchange the code (this is where the proxy rewrites the response) ------
    const tokenPayload = {
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        redirect_uri: REDIRECT_URI,
        client_id: 'web',
        deviceType: 10,
        deviceName: 'browserless-smoke',
        deviceIdentifier: randomUUID(),
        scope: 'api offline_access',
    };
    const tokenRes = await postToken(tokenPayload);
    if (!tokenRes.ok) {
        fail('token-exchange', `HTTP ${tokenRes.status}: ${(await tokenRes.text()).slice(0, 300)}`);
    }
    const token = await tokenRes.json();
    const udo = token.UserDecryptionOptions || {};
    const problems = [];
    if (!udo.KeyConnectorOption) problems.push('no UserDecryptionOptions.KeyConnectorOption');
    if (udo.HasMasterPassword !== false) problems.push(`HasMasterPassword is ${JSON.stringify(udo.HasMasterPassword)}, expected false`);
    if (!token.access_token) problems.push('no access_token');
    if (problems.length) fail('token-exchange (passwordless flags)', problems.join('; '));
    steps.push('token-exchange');

    // The session lifetime, checked on every run: this is the number that decides whether a
    // client that comes back later is still logged in.
    const claimsOf = (jwt) => {
        try {
            return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url').toString('utf8'));
        } catch { return {}; }
    };
    const refreshClaims = claimsOf(token.refresh_token);
    const refreshIssued = refreshClaims.iat ?? refreshClaims.nbf;
    const refreshTtlDays = refreshIssued && refreshClaims.exp
        ? (refreshClaims.exp - refreshIssued) / 86400
        : null;
    if (refreshTtlDays === null) {
        fail('session lifetime', 'could not read the refresh token claims');
    }
    if (refreshTtlDays < MIN_REFRESH_DAYS) {
        fail(
            'session lifetime',
            `the refresh token lives ${refreshTtlDays.toFixed(2)} days (minimum ${MIN_REFRESH_DAYS}). ` +
            'For SSO logins the client inherits the IdP\'s session, so this logs users out — ' +
            'check the IdP realm/client session settings; see COMPATIBILITY.md.',
        );
    }
    steps.push('session-lifetime');

    // Surface the session lifetimes (timings only — never the tokens themselves). A client
    // that comes back later than the refresh token's exp is logged out, so this is the number
    // that decides how often a user has to log in again.
    if (process.env.SMOKE_DEBUG_TOKENS === '1') {
        const timing = (jwt) => {
            try {
                const [, payload] = String(jwt).split('.');
                const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
                const issued = claims.iat ?? claims.nbf;
                if (!issued || !claims.exp) {
                    return { segments: String(jwt).split('.').length, claim_keys: Object.keys(claims) };
                }
                return {
                    iat: new Date(issued * 1000).toISOString(),
                    exp: new Date(claims.exp * 1000).toISOString(),
                    ttl_minutes: Math.round((claims.exp - issued) / 60),
                    ttl_days: Number(((claims.exp - issued) / 86400).toFixed(2)),
                };
            } catch (error) {
                return `unreadable: ${String(error).slice(0, 60)}`;
            }
        };
        console.error('smoke: lifetimes ' + JSON.stringify({
            access: timing(token.access_token),
            refresh: timing(token.refresh_token),
            response_expires_in: token.expires_in,
            response_scope: token.scope,
        }));
    }

    // 6. sync must advertise the connector unlock ------------------------------
    const syncRes = await request('GET', `${BASE}/api/sync`, {
        headers: { authorization: `Bearer ${token.access_token}` },
    });
    if (!syncRes.ok) fail('sync', `HTTP ${syncRes.status}`);
    const sync = await syncRes.json();
    const syncProblems = [];
    if (!sync?.userDecryption?.keyConnectorUnlock) syncProblems.push('no userDecryption.keyConnectorUnlock');
    if (sync?.profile?.usesKeyConnector !== true) syncProblems.push(`profile.usesKeyConnector is ${JSON.stringify(sync?.profile?.usesKeyConnector)}`);
    if (syncProblems.length) fail('sync (passwordless flags)', syncProblems.join('; '));
    steps.push('sync');

    // 7. Enrol a throwaway key, the way a real client does on first login. Gated: on a live
    //    account this would overwrite the key the user's vault is encrypted with.
    // standard base64 (not url-safe): the connector decodes with the STANDARD alphabet
    const SMOKE_KEY = randomBytes(64).toString('base64');
    if (ENROLL) {
        const enrollRes = await request('POST', `${BASE}/user-keys`, {
            body: JSON.stringify({ key: SMOKE_KEY }),
            headers: { 'content-type': 'application/json', authorization: `Bearer ${token.access_token}` },
        });
        if (!enrollRes.ok) {
            fail('enroll', `POST /user-keys returned HTTP ${enrollRes.status}: ${(await enrollRes.text()).slice(0, 200)}`);
        }
        steps.push('enroll');
    }

    // The client logs out when the security stamp it has stored disagrees with the server
    // (password change / session revocation). Surface both places it comes from so a mismatch is
    // visible instead of being blamed on the app.
    const decodeClaims = (jwt) => {
        try {
            return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url').toString('utf8'));
        } catch { return {}; }
    };
    const tokenClaims = decodeClaims(token.access_token);
    console.error('smoke: security stamp ' + JSON.stringify({
        token_sstamp: String(tokenClaims.sstamp ?? '').slice(0, 12) + '…',
        sync_stamp: String(sync?.profile?.securityStamp ?? '').slice(0, 12) + '…',
        equal: tokenClaims.sstamp != null && tokenClaims.sstamp === sync?.profile?.securityStamp,
    }));

    // 8. The session must survive a token refresh. This is what the mobile apps do when the
    //    user reopens them: they refresh the access token and then ask the connector for the
    //    user key. If the refreshed session cannot retrieve its key, the app has no way back
    //    into the vault and shows the login screen again — the "log in on every restart"
    //    symptom. The client is the same device throughout, as a real app would be.
    const deviceId = tokenPayload.deviceIdentifier;
    const refreshRes = await postToken({
        grant_type: 'refresh_token',
        refresh_token: token.refresh_token,
        client_id: 'web',
        deviceType: 10,
        deviceName: 'browserless-smoke',
        deviceIdentifier: deviceId,
    });
    if (!refreshRes.ok) {
        fail('refresh', `HTTP ${refreshRes.status}: ${(await refreshRes.text()).slice(0, 300)}`);
    }
    const refreshed = await refreshRes.json();
    if (!refreshed.access_token) fail('refresh', 'no access_token in the refreshed response');
    const refreshedProblems = [];
    if (!refreshed.UserDecryptionOptions?.KeyConnectorOption) refreshedProblems.push('no KeyConnectorOption after refresh');
    if (refreshed.UserDecryptionOptions?.HasMasterPassword !== false) refreshedProblems.push('HasMasterPassword is not false after refresh');
    if (refreshedProblems.length) fail('refresh (passwordless flags)', refreshedProblems.join('; '));
    steps.push('refresh');

    // 8. …and the refreshed session must still be able to fetch its key from the connector.
    const keyRes = await request('GET', `${BASE}/user-keys`, {
        headers: { authorization: `Bearer ${refreshed.access_token}` },
    });
    if (keyRes.status === 404 && !ENROLL) {
        steps.push('key-retrieval-after-refresh (skipped: no key enrolled on this account)');
        report({ steps });
        return;
    }
    if (!keyRes.ok) {
        fail('key-retrieval after refresh', `GET /user-keys returned HTTP ${keyRes.status}: ${(await keyRes.text()).slice(0, 200)}`);
    }
    const keyBody = await keyRes.json().catch(() => ({}));
    const gotKey = keyBody?.key ?? keyBody?.Key;
    if (!gotKey) {
        fail('key-retrieval after refresh', `the connector answered without a key: ${JSON.stringify(keyBody).slice(0, 200)}`);
    }
    if (ENROLL && gotKey !== SMOKE_KEY) {
        fail('key-retrieval after refresh', 'the connector returned a different key than the one enrolled');
    }
    steps.push('key-retrieval-after-refresh');

    report({
        steps,
        keyConnectorUrl: udo.KeyConnectorOption.KeyConnectorUrl,
        hasKey: typeof token.Key === 'string',
        cipherCount: Array.isArray(sync.ciphers) ? sync.ciphers.length : null,
    });
}

main().catch((error) => fail('unexpected', String(error?.stack ?? error)));
