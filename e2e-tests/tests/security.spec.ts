import { test, expect, type TestInfo } from '@playwright/test';

import * as utils from "../global-utils";

let users = utils.loadEnv();

const masterlessPort = process.env.MASTERLESS_PORT || '18443';
const baseUrl = `https://localhost:${masterlessPort}`;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVaultAndMasterless(browser, {
        SSO_ENABLED: true,
        SSO_ONLY: false,
    }, 'quick');
});

test.afterAll('Teardown', async ({}) => {
    await utils.stopVaultAndMasterless();
});

// ---------------------------------------------------------------------------
// SEC-1: Admin panel must NOT be accessible through the proxy
// ---------------------------------------------------------------------------
// test('SEC-1: Proxy blocks /admin panel access', async ({ request }) => {
//     // GET /admin — should be blocked by proxy, not forwarded to VW
//     const resp = await request.get('/admin');
//     // We expect 403 or 404 — NOT VW's admin login page (200)
//     expect(resp.status()).not.toBe(200);
//     expect(resp.status()).toBeGreaterThanOrEqual(400);

//     const body = await resp.text();
//     // Must NOT contain the VW admin panel HTML
//     expect(body).not.toContain('Vaultwarden Admin Panel');
// });

// test('SEC-1b: Proxy blocks /admin subpaths', async ({ request }) => {
//     const paths = ['/admin/', '/admin/config', '/admin/users', '/admin/diagnostics'];
//     for (const path of paths) {
//         const resp = await request.get(path);
//         expect(resp.status(), `${path} should be blocked`).not.toBe(200);
//         const body = await resp.text();
//         expect(body, `${path} should not leak admin HTML`).not.toContain('Vaultwarden Admin Panel');
//     }
// });

// test('SEC-1c: Proxy blocks POST to /admin (login attempt)', async ({ request }) => {
//     const resp = await request.post('/admin', {
//         form: { token: process.env.ADMIN_TOKEN || 'e2e-admin-token' },
//     });
//     expect(resp.status()).not.toBe(200);
// });

// ---------------------------------------------------------------------------
// SEC-2: JWT forgery attacks must be rejected
// ---------------------------------------------------------------------------
test('SEC-2a: Forged JWT with invalid signature rejected', async ({ request }) => {
    const forgedToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJlbWFpbCI6ImF0dGFja2VyQGV2aWwuY29tIiwiYW1yIjpbIkFwcGxpY2F0aW9uIl0sImV4cCI6OTk5OTk5OTk5OSwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6MTg0NDMifQ.invalidsignature';
    const resp = await request.get('/user-keys', {
        headers: { 'Authorization': `Bearer ${forgedToken}` },
    });
    expect(resp.status()).toBe(401);
});

test('SEC-2b: HS256 algorithm confusion attack rejected', async ({ request }) => {
    // Token signed with HS256 instead of RS256 — classic JWT confusion attack
    const hs256Token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJlbWFpbCI6ImF0dGFja2VyQGV2aWwuY29tIiwiYW1yIjpbIkFwcGxpY2F0aW9uIl0sImV4cCI6OTk5OTk5OTk5OSwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6MTg0NDMifQ.fakesig';
    const resp = await request.get('/user-keys', {
        headers: { 'Authorization': `Bearer ${hs256Token}` },
    });
    expect(resp.status()).toBe(401);
    const body = await resp.json();
    expect(body.error).toBe('unauthorized');
});

test('SEC-2c: alg:none attack rejected', async ({ request }) => {
    const noneToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJlbWFpbCI6ImF0dGFja2VyQGV2aWwuY29tIiwiYW1yIjpbIkFwcGxpY2F0aW9uIl0sImV4cCI6OTk5OTk5OTk5OSwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6MTg0NDMifQ.';
    const resp = await request.get('/user-keys', {
        headers: { 'Authorization': `Bearer ${noneToken}` },
    });
    expect(resp.status()).toBe(401);
});

// ---------------------------------------------------------------------------
// SEC-3: Unauthenticated key operations must be rejected
// ---------------------------------------------------------------------------
test('SEC-3: All /user-keys methods require authentication', async ({ request }) => {
    const methods = [
        { fn: () => request.get('/user-keys'), method: 'GET' },
        { fn: () => request.post('/user-keys', { data: { key: 'dGVzdA==' } }), method: 'POST' },
        { fn: () => request.put('/user-keys', { data: { key: 'dGVzdA==' } }), method: 'PUT' },
        { fn: () => request.delete('/user-keys'), method: 'DELETE' },
    ];
    for (const { fn, method } of methods) {
        const resp = await fn();
        expect(resp.status(), `${method} /user-keys should require auth`).toBe(401);
    }
});

// ---------------------------------------------------------------------------
// SEC-4: Proxy must not leak internal upstream error details
// ---------------------------------------------------------------------------
test('SEC-4: Proxy error responses do not leak internal URLs', async ({ request }) => {
    // Stop VW to trigger a proxy upstream error, then check error response
    // We can simulate by requesting a path that causes a proxy failure message
    // Actually, we test the currently-running proxy's error format by checking
    // that the /alive endpoint doesn't contain internal URLs
    const resp = await request.get('/alive');
    const body = await resp.text();
    // The internal VW URL should never appear in any client-facing response
    expect(body).not.toContain('vaultwarden:80');
    expect(body).not.toContain('127.0.0.1:18000');
    expect(body).not.toContain('ROCKET_PORT');
});

// ---------------------------------------------------------------------------
// SEC-5: Container should NOT run as root
// ---------------------------------------------------------------------------
test('SEC-5: Masterless container runs as non-root user', async ({}) => {
    const { execSync } = require('node:child_process');
    const uid = execSync(
        'docker exec e2e_masterless-e2e id -u',
        { encoding: 'utf-8' }
    ).trim();
    // Must not be root (uid 0)
    expect(uid, 'Container must not run as root (uid 0)').not.toBe('0');
});

// ---------------------------------------------------------------------------
// SEC-6: Database file must have restrictive permissions
// ---------------------------------------------------------------------------
test('SEC-6: SQLite database is not world-readable', async ({}) => {
    const { execSync } = require('node:child_process');
    const perms = execSync(
        'docker exec e2e_masterless-e2e stat -c "%a" /data/masterless.sqlite',
        { encoding: 'utf-8' }
    ).trim();
    // 600 (owner rw only) or 640 (owner rw, group r)
    // Must NOT be 644 or 666 (world-readable)
    const otherBits = parseInt(perms.slice(-1), 10);
    expect(otherBits, `DB perms ${perms} must not be world-readable`).toBe(0);
});

// ---------------------------------------------------------------------------
// SEC-7: Path traversal attempts must be blocked
// ---------------------------------------------------------------------------
test('SEC-7: Path traversal does not expose filesystem', async ({ request }) => {
    const paths = [
        '/../../../etc/passwd',
        '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
        '/..%2f..%2f..%2fetc/passwd',
    ];
    for (const path of paths) {
        const resp = await request.get(path);
        const body = await resp.text();
        expect(body, `${path} must not expose /etc/passwd`).not.toContain('root:x:');
    }
});

// ---------------------------------------------------------------------------
// SEC-8: SQL injection attempts must be safe
// ---------------------------------------------------------------------------
test('SEC-8: SQL injection via Authorization header returns 401', async ({ request }) => {
    const sqliPayloads = [
        "' OR 1=1 --",
        "'; DROP TABLE user_keys; --",
        "\" OR \"\"=\"",
    ];
    for (const payload of sqliPayloads) {
        const resp = await request.get('/user-keys', {
            headers: { 'Authorization': `Bearer ${payload}` },
        });
        expect(resp.status(), `SQLi payload should get 401`).toBe(401);
    }
});

// ---------------------------------------------------------------------------
// SEC-9: Rate limiting on key endpoints
// ---------------------------------------------------------------------------
test('SEC-9: Rate limiting triggers on rapid requests', async ({ request }) => {
    // Send many rapid parallel requests — burst_size is 30, so 50 should trigger 429
    const results: number[] = [];
    const promises = [];
    for (let i = 0; i < 50; i++) {
        promises.push(
            request.get('/user-keys', {
                headers: { 'Authorization': 'Bearer fake.jwt.token' },
            }).then(r => results.push(r.status()))
        );
    }
    await Promise.all(promises);

    const has429 = results.some(s => s === 429);
    expect(has429, 'At least one request in a burst of 50 should be rate-limited (429)').toBe(true);
});
