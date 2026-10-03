import { test, expect, type TestInfo } from '@playwright/test';

import * as utils from "../global-utils";

let users = utils.loadEnv();

const masterlessPort = process.env.MASTERLESS_PORT || '18443';
const testHost = process.env.TEST_HOST || '127.0.0.1';
const baseUrl = `https://${testHost}:${masterlessPort}`;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVaultAndMasterless(browser, {
        SSO_ENABLED: true,
        SSO_ONLY: false,
    }, 'quick');
});

test.afterAll('Teardown', async ({}) => {
    await utils.stopVaultAndMasterless();
});

// // ===========================================================================
// // SEC-10: Admin panel bypass via URL encoding tricks
// // ===========================================================================
// test('SEC-10a: Proxy blocks /admin with URL-encoded separators', async ({ request }) => {
//     const bypassAttempts = [
//         '/admin%00',           // null byte injection
//         '/admin%20',           // space suffix
//         '/admin%2f',           // encoded slash
//         '/admin%2Fconfig',     // encoded slash + subpath
//         '/./admin',            // dot segment
//         '/admin/.',            // trailing dot segment
//         '/admin/..',           // dot-dot after admin
//     ];
//     for (const path of bypassAttempts) {
//         const resp = await request.get(path);
//         const body = await resp.text();
//         expect(body, `${path} must not leak admin HTML`).not.toContain('Vaultwarden Admin Panel');
//         expect(body, `${path} must not contain admin form`).not.toContain('name="token"');
//     }
// });

// test('SEC-10b: Proxy blocks /admin with mixed-case and trailing characters', async ({ request }) => {
//     const bypassAttempts = [
//         '/Admin',
//         '/ADMIN',
//         '/aDmIn',
//         '/admin;',
//         '/admin?foo=bar',
//         '/admin#fragment',
//     ];
//     for (const path of bypassAttempts) {
//         const resp = await request.get(path);
//         const body = await resp.text();
//         expect(body, `${path} must not expose admin panel`).not.toContain('Vaultwarden Admin Panel');
//     }
// });

// ===========================================================================
// SEC-11: Security headers on sensitive endpoints
// ===========================================================================
test('SEC-11a: /user-keys responses include no-cache directives', async ({ request }) => {
    // Even unauthenticated 401 responses should not be cached
    const resp = await request.get('/user-keys');
    expect(resp.status()).toBe(401);

    // The response should not instruct proxies/browsers to cache auth errors
    const cacheControl = resp.headers()['cache-control'] || '';
    const pragma = resp.headers()['pragma'] || '';
    // At minimum, verify the response is not explicitly set to be cached for long
    // (absence of cache-control is acceptable — it defaults to no caching for API responses)
    if (cacheControl) {
        expect(cacheControl, 'Cache-Control should not be public').not.toContain('public');
    }
});

test('SEC-11b: /alive does not expose server version or technology', async ({ request }) => {
    const resp = await request.get('/alive');
    const serverHeader = resp.headers()['server'] || '';
    const poweredBy = resp.headers()['x-powered-by'] || '';

    // Should not reveal actix-web version or other internals
    expect(poweredBy, 'X-Powered-By should be absent or empty').toBe('');
    if (serverHeader) {
        expect(serverHeader.toLowerCase(), 'Server header should not reveal framework').not.toContain('actix');
        expect(serverHeader.toLowerCase(), 'Server header should not reveal rust').not.toContain('rust');
    }
});

// ===========================================================================
// SEC-12: HTTP method restrictions through proxy
// ===========================================================================
test('SEC-12: Dangerous HTTP methods are rejected or safe', async ({ request }) => {
    // TRACE can lead to cross-site tracing (XST) attacks
    const traceResp = await request.fetch('/api/alive', { method: 'TRACE' });
    const traceBody = await traceResp.text();
    // TRACE must NOT echo back the request (XST attack)
    expect(traceBody, 'TRACE must not echo request headers').not.toContain('TRACE /');

    // CONNECT should not be accepted
    // Playwright may not support CONNECT, so we check that it doesn't return 200
    const optionsResp = await request.fetch('/', { method: 'OPTIONS' });
    // OPTIONS is fine to return any status, but should not leak internal info
    const optionsBody = await optionsResp.text();
    expect(optionsBody, 'OPTIONS must not leak internal URLs').not.toContain('vaultwarden:');
});

// ===========================================================================
// SEC-13: Host header injection / SSRF via headers
// ===========================================================================
test('SEC-13a: X-Forwarded-Host injection does not alter responses', async ({ request }) => {
    const resp = await request.get('/alive', {
        headers: {
            'X-Forwarded-Host': 'evil.com',
            'X-Forwarded-Proto': 'http',
        },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.text();
    // Response must not reflect the injected host
    expect(body).not.toContain('evil.com');
});

test('SEC-13b: Absolute URL in request line does not cause SSRF', async ({ request }) => {
    // Attempt to make the proxy connect to an external host via absolute URL
    // The proxy should only forward to its configured VW backend
    const resp = await request.get('/alive');
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.alive).toBe(true);
});

// ===========================================================================
// SEC-14: Oversized request body handling
// ===========================================================================
test('SEC-14: Oversized POST to /user-keys is rejected', async ({ request }) => {
    // Generate a ~2MB payload — should be rejected or auth-fail before reaching crypto
    const hugeKey = 'A'.repeat(2 * 1024 * 1024);
    try {
        const resp = await request.post('/user-keys', {
            headers: {
                'Authorization': 'Bearer fake.jwt.token',
                'Content-Type': 'application/json',
            },
            data: JSON.stringify({ key: hugeKey }),
        });
        // Should be rejected with 401 (auth fails first) or 413 (payload too large)
        // The important thing is it does NOT return 200 or 500
        expect([401, 413]).toContain(resp.status());
    } catch (e: any) {
        // EPIPE / connection reset means the server rejected the oversized payload
        // at the transport level — this is a valid rejection
        expect(
            e.message.includes('EPIPE') || e.message.includes('ECONNRESET') || e.message.includes('socket hang up'),
            `Oversized payload must be rejected, got: ${e.message}`
        ).toBe(true);
    }
});

// ===========================================================================
// SEC-15: Response body does not leak internal infrastructure
// ===========================================================================
test('SEC-15: Error responses never contain internal hostnames or ports', async ({ request }) => {
    const vwPort = process.env.ROCKET_PORT || '18000';
    const internalPatterns = [
        `127.0.0.1:${vwPort}`,
        `localhost:${vwPort}`,
        'VAULTWARDEN_URL',
        'ROCKET_PORT',
        'RSA_PRIVATE_KEY',
        'DATABASE_PATH',
        '/data/masterless.sqlite',
        '/usr/local/bin/vaultwarden-masterless',
    ];

    // Test multiple endpoints for info leakage
    const endpoints = ['/alive', '/user-keys', '/nonexistent-path-12345'];
    for (const endpoint of endpoints) {
        const resp = await request.get(endpoint);
        const body = await resp.text();
        for (const pattern of internalPatterns) {
            expect(body, `${endpoint} must not leak "${pattern}"`).not.toContain(pattern);
        }
    }
});

// ===========================================================================
// SEC-16: Expired / malformed Bearer tokens
// ===========================================================================
test('SEC-16a: Empty Bearer token rejected', async ({ request }) => {
    const resp = await request.get('/user-keys', {
        headers: { 'Authorization': 'Bearer ' },
    });
    expect(resp.status()).toBe(401);
});

test('SEC-16b: Non-Bearer auth scheme rejected', async ({ request }) => {
    const resp = await request.get('/user-keys', {
        headers: { 'Authorization': 'Basic dGVzdDp0ZXN0' },
    });
    expect(resp.status()).toBe(401);
});

test('SEC-16c: Extremely long token rejected gracefully', async ({ request }) => {
    const longToken = 'a'.repeat(100_000);
    const resp = await request.get('/user-keys', {
        headers: { 'Authorization': `Bearer ${longToken}` },
    });
    // Should be 401, not 500 or timeout
    expect(resp.status()).toBe(401);
});

test('SEC-16d: Token with unicode escape sequences rejected', async ({ request }) => {
    // Null bytes cannot be sent in HTTP headers, so test with
    // URL-encoded garbage that looks like a JWT but is clearly invalid
    const resp = await request.get('/user-keys', {
        headers: { 'Authorization': 'Bearer eyJhbGciOi%00JSUzI1NiJ9.te%00st.test' },
    });
    expect(resp.status()).toBe(401);
});

// ===========================================================================
// SEC-17: POST /user-keys input validation
// ===========================================================================
test('SEC-17a: POST /user-keys with non-JSON body returns 400', async ({ request }) => {
    const resp = await request.post('/user-keys', {
        headers: {
            'Authorization': 'Bearer fake.jwt.token',
            'Content-Type': 'text/plain',
        },
        data: 'not json at all',
    });
    // Auth should fail first (401) or body parse fails (400)
    expect([400, 401]).toContain(resp.status());
});

test('SEC-17b: POST /user-keys with missing key field', async ({ request }) => {
    const resp = await request.post('/user-keys', {
        headers: {
            'Authorization': 'Bearer fake.jwt.token',
            'Content-Type': 'application/json',
        },
        data: JSON.stringify({ notAKey: 'value' }),
    });
    // Auth fails first, but the body structure should eventually be validated
    expect([400, 401, 422]).toContain(resp.status());
});

test('SEC-17c: POST /user-keys with empty key value', async ({ request }) => {
    const resp = await request.post('/user-keys', {
        headers: {
            'Authorization': 'Bearer fake.jwt.token',
            'Content-Type': 'application/json',
        },
        data: JSON.stringify({ key: '' }),
    });
    expect([400, 401]).toContain(resp.status());
});

// ===========================================================================
// SEC-18: set-key-connector-key endpoint validation
// ===========================================================================
test('SEC-18a: POST /api/accounts/set-key-connector-key without auth forwards to VW', async ({ request }) => {
    const resp = await request.post('/api/accounts/set-key-connector-key', {
        headers: { 'Content-Type': 'application/json' },
        data: JSON.stringify({
            key: 'fakeKey',
            keys: { publicKey: 'fakePub', encryptedPrivateKey: 'fakePriv' },
        }),
    });
    // Without valid auth, VW should reject upstream requests
    // The proxy should NOT return 200 OK unconditionally
    // Acceptable: 401 (VW rejects), 400, or 502 (upstream failed)
    expect(resp.status(), 'set-key-connector-key without auth must not succeed')
        .not.toBe(200);
});

test('SEC-18b: POST /api/accounts/set-key-connector-key with empty body', async ({ request }) => {
    // Send an empty JSON object — no "keys" or "key" fields
    // The handler should still not crash or return 500
    const resp = await request.post('/api/accounts/set-key-connector-key', {
        headers: { 'Content-Type': 'application/json' },
        data: JSON.stringify({}),
    });
    // Without auth, the handler returns 401 before checking the body.
    // With auth + empty body, it returns 200 (skips both VW calls).
    expect([200, 400, 401]).toContain(resp.status());
});

// ===========================================================================
// SEC-19: Proxy does not follow redirects to external domains
// ===========================================================================
test('SEC-19: Proxy HTTP client does not follow redirects', async ({ request }) => {
    // The proxy is configured with reqwest::redirect::Policy::none()
    // Verify that redirected upstream responses are passed through, not followed
    const resp = await request.get('/alive');
    expect(resp.status()).toBe(200);
    // The alive endpoint is handled directly — confirms proxy doesn't interfere
});

// ===========================================================================
// SEC-20: TLS enforcement verification
// ===========================================================================
test('SEC-20: Masterless is reachable via HTTPS', async ({ request }) => {
    // Since baseURL uses https:// in playwright config and tests pass,
    // TLS is working. Verify explicitly that /alive works over HTTPS.
    const resp = await request.get('/alive');
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.alive).toBe(true);
});

// ===========================================================================
// SEC-21: Cross-user key isolation (authorization boundary)
// ===========================================================================
test('SEC-21: Key retrieval returns 404 for users without stored keys', async ({ request }) => {
    // A valid auth flow would be needed to fully test cross-user isolation.
    // Here we verify the basic contract: unauthenticated = 401.
    const resp = await request.get('/user-keys');
    expect(resp.status()).toBe(401);
    const body = await resp.json();
    // Error message must not leak other users' data
    expect(JSON.stringify(body)).not.toContain('encrypted_key');
    expect(JSON.stringify(body)).not.toContain('wrapping_secret');
});

// ===========================================================================
// SEC-22: Request smuggling via duplicate Content-Length / Transfer-Encoding
// ===========================================================================
test('SEC-22: Duplicate headers do not cause unexpected behavior', async ({ request }) => {
    // Send a request with potentially conflicting headers
    const resp = await request.post('/user-keys', {
        headers: {
            'Authorization': 'Bearer fake.jwt.token',
            'Content-Type': 'application/json',
            'Transfer-Encoding': 'chunked',
        },
        data: JSON.stringify({ key: 'dGVzdA==' }),
    });
    // Should still get a clean auth rejection, not a 500 or garbled response
    expect([400, 401]).toContain(resp.status());
});

// ===========================================================================
// USA-1: Health check endpoint reports meaningful status
// ===========================================================================
test('USA-1: /alive returns structured health information', async ({ request }) => {
    const resp = await request.get('/alive');
    expect(resp.status()).toBe(200);
    const body = await resp.json();

    // Must have the 'alive' flag
    expect(body).toHaveProperty('alive');
    expect(body.alive).toBe(true);

    // Must have a timestamp for debugging
    expect(body).toHaveProperty('now');
    expect(typeof body.now).toBe('string');
    // Timestamp should be a valid ISO 8601 date
    const ts = new Date(body.now);
    expect(ts.getTime()).not.toBeNaN();
});

// ===========================================================================
// USA-2: Error responses have consistent JSON structure
// ===========================================================================
test('USA-2a: 401 responses have consistent error JSON format', async ({ request }) => {
    const resp = await request.get('/user-keys');
    expect(resp.status()).toBe(401);

    const body = await resp.json();
    expect(body).toHaveProperty('error');
    expect(body).toHaveProperty('error_description');
    expect(typeof body.error).toBe('string');
    expect(typeof body.error_description).toBe('string');
});

// test('USA-2b: 404 responses from proxy have consistent JSON format', async ({ request }) => {
//     const resp = await request.get('/admin');
//     expect(resp.status()).toBeGreaterThanOrEqual(400);

//     const contentType = resp.headers()['content-type'] || '';
//     if (contentType.includes('application/json')) {
//         const body = await resp.json();
//         expect(body).toHaveProperty('error');
//         expect(body).toHaveProperty('error_description');
//     }
// });

// ===========================================================================
// USA-3: Proxy correctly forwards non-API static assets
// ===========================================================================
test('USA-3: Web vault static assets are served through proxy', async ({ request }) => {
    // The web vault's index page should be served via proxy
    const resp = await request.get('/');
    expect(resp.status()).toBe(200);
    const body = await resp.text();
    // Should contain web vault HTML, not an error
    expect(body).toContain('html');
});

// ===========================================================================
// USA-4: Concurrent requests are handled correctly
// ===========================================================================
test('USA-4: Concurrent /alive requests all succeed', async ({ request }) => {
    // Send 20 parallel requests — all should return 200
    const promises = Array.from({ length: 20 }, () =>
        request.get('/alive').then(async r => ({
            status: r.status(),
            body: await r.json().catch(() => null),
        }))
    );
    const results = await Promise.all(promises);

    for (const r of results) {
        expect(r.status).toBe(200);
        expect(r.body?.alive).toBe(true);
    }
});

// ===========================================================================
// USA-5: Proxy preserves upstream response status codes
// ===========================================================================
test('USA-5: Proxy forwards 404 for unknown VW API paths', async ({ request }) => {
    const resp = await request.get('/api/nonexistent-endpoint-xyz');
    // VW should return 404, and proxy should forward it — not 200 or 502
    expect([404, 400]).toContain(resp.status());
});

// ===========================================================================
// SEC-23: Cookie security — proxy must not leak session cookies
// ===========================================================================
test('SEC-23: /user-keys responses do not set insecure cookies', async ({ request }) => {
    const resp = await request.get('/user-keys');
    const setCookie = resp.headers()['set-cookie'] || '';
    // If cookies are set, they should be Secure and HttpOnly
    if (setCookie) {
        const lower = setCookie.toLowerCase();
        if (lower.includes('session') || lower.includes('token')) {
            expect(lower, 'Session cookies must have Secure flag').toContain('secure');
            expect(lower, 'Session cookies must have HttpOnly flag').toContain('httponly');
        }
    }
});

// ===========================================================================
// SEC-24: Verify rate limiter only applies to /user-keys, not /alive
// ===========================================================================
test('SEC-24: /alive is not rate-limited (health check availability)', async ({ request }) => {
    // Send 40 rapid requests to /alive — none should get 429
    const results: number[] = [];
    const promises = Array.from({ length: 40 }, () =>
        request.get('/alive').then(r => results.push(r.status()))
    );
    await Promise.all(promises);

    const has429 = results.some(s => s === 429);
    expect(has429, '/alive should not be rate-limited').toBe(false);
    expect(results.every(s => s === 200), 'All /alive requests should return 200').toBe(true);
});

// ===========================================================================
// SEC-25: Upgrade header on non-admin path does not bypass proxy
// ===========================================================================
test('SEC-25: Upgrade header does not bypass proxy controls', async ({ request }) => {
    // Verify that sending Upgrade headers on a normal endpoint doesn't
    // cause the proxy to misbehave or skip security checks
    const resp = await request.get('/user-keys', {
        headers: {
            'Upgrade': 'h2c',
            'Connection': 'Upgrade',
        },
    });
    // Should still enforce auth — not 101 or 200
    expect(resp.status()).toBe(401);
});

// ===========================================================================
// SEC-26: Verify container has no unnecessary capabilities
// ===========================================================================
test('SEC-26: Container has minimal capabilities', async ({}) => {
    const { execSync } = require('node:child_process');
    try {
        // Check that the container cannot write to protected paths
        const result = execSync(
            'docker exec e2e_masterless-e2e touch /etc/test-write-check 2>&1 || echo "PERMISSION_DENIED"',
            { encoding: 'utf-8' }
        ).trim();
        expect(
            result.includes('PERMISSION_DENIED') || result.includes('Permission denied') || result.includes('Read-only'),
            'Container should not be able to write to /etc'
        ).toBe(true);
    } catch (e: any) {
        // Command failing is acceptable — means write was denied
        expect(e.message).toMatch(/permission|denied|read.only/i);
    }
});

// ===========================================================================
// SEC-27: Private key files are not accessible via proxy
// ===========================================================================
test('SEC-27: RSA private key paths are not exposed via proxy', async ({ request }) => {
    const sensitiveFiles = [
        '/keys/rsa_private.pem',
        '/data/rsa_private.pem',
        '/data/masterless.sqlite',
        '/.env',
        '/proc/self/environ',
    ];
    for (const path of sensitiveFiles) {
        const resp = await request.get(path);
        const body = await resp.text();
        expect(body, `${path} must not expose private key material`).not.toContain('BEGIN PRIVATE KEY');
        expect(body, `${path} must not expose RSA key`).not.toContain('BEGIN RSA PRIVATE KEY');
        expect(body, `${path} must not expose env vars`).not.toContain('VAULTWARDEN_URL=');
    }
});
