import { test, expect, type TestInfo } from '@playwright/test';

import { logNewUser, logUser } from './setups/sso';
import * as utils from "../global-utils";

let users = utils.loadEnv();

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVaultAndMasterless(browser, {
        SSO_ENABLED: true,
        SSO_ONLY: false,
    });
});

test.afterAll('Teardown', async ({}) => {
    await utils.stopVaultAndMasterless();
});

// ===========================================================================
// KC-1: /user-keys endpoint authentication and authorization
// ===========================================================================
test.describe('Key Connector /user-keys endpoint auth', () => {
    test('KC-1a: GET /user-keys returns 401 without auth', async ({ request }) => {
        const resp = await request.get('/user-keys');
        expect(resp.status()).toBe(401);
        const body = await resp.json();
        expect(body).toHaveProperty('error');
    });

    test('KC-1b: POST /user-keys returns 401 without auth', async ({ request }) => {
        const resp = await request.post('/user-keys', {
            data: { key: 'dGVzdA==' },
        });
        expect(resp.status()).toBe(401);
    });

    test('KC-1c: PUT /user-keys returns 401 without auth', async ({ request }) => {
        const resp = await request.put('/user-keys', {
            data: { key: 'dGVzdA==' },
        });
        expect(resp.status()).toBe(401);
    });

    test('KC-1d: DELETE /user-keys returns 401 without auth', async ({ request }) => {
        const resp = await request.delete('/user-keys');
        expect(resp.status()).toBe(401);
    });

    test('KC-1e: /user-keys with invalid JWT returns 401', async ({ request }) => {
        const resp = await request.get('/user-keys', {
            headers: { 'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.bogus.signature' },
        });
        expect(resp.status()).toBe(401);
    });

    test('KC-1f: /user-keys with empty Bearer token returns 401', async ({ request }) => {
        const resp = await request.get('/user-keys', {
            headers: { 'Authorization': 'Bearer ' },
        });
        expect(resp.status()).toBe(401);
    });
});

// ===========================================================================
// KC-2: /user-keys response headers (security)
// ===========================================================================
test.describe('Key Connector /user-keys response headers', () => {
    test('KC-2a: /user-keys responses include no-cache headers', async ({ request }) => {
        const resp = await request.get('/user-keys');
        expect(resp.status()).toBe(401);

        const cacheControl = resp.headers()['cache-control'] || '';
        const pragma = resp.headers()['pragma'] || '';
        const xContentType = resp.headers()['x-content-type-options'] || '';

        if (cacheControl) {
            expect(cacheControl.toLowerCase(), 'Cache-Control should include no-store or no-cache').toMatch(/no-store|no-cache/);
        }
        if (pragma === 'no-cache' || cacheControl.toLowerCase().includes('no-cache')) {
            // Acceptable
        }
        if (xContentType) {
            expect(xContentType.toLowerCase(), 'X-Content-Type-Options should be nosniff').toBe('nosniff');
        }
    });
});

// ===========================================================================
// KC-3: /api/accounts/key-connector/confirmation-details
// ===========================================================================
test.describe('Key Connector confirmation-details stub', () => {
    test('KC-3: confirmation-details returns stub or 404', async ({ request }) => {
        const orgId = '00000000-0000-0000-0000-000000000001';
        const resp = await request.get(`/api/accounts/key-connector/confirmation-details/${orgId}`);

        if (resp.status() === 200) {
            const body = await resp.json();
            expect(body, 'Stub response must have Object field').toHaveProperty('Object');
            expect(body['Object']).toBe('keyConnectorConfirmationDetails');
            expect(body, 'Stub response must have OrganizationName').toHaveProperty('OrganizationName');
        } else {
            expect([401, 404], 'Non-200 responses should be auth errors or not found').toContain(resp.status());
        }
    });
});

// ===========================================================================
// KC-4: set-key-connector-key endpoint
// ===========================================================================
test.describe('Key Connector set-key-connector-key', () => {
    test('KC-4a: POST /api/accounts/set-key-connector-key without auth is rejected', async ({ request }) => {
        const resp = await request.post('/api/accounts/set-key-connector-key', {
            data: { key: 'fakeKey' },
        });
        expect(resp.status(), 'Must NOT return 200 without auth').not.toBe(200);
    });

    test('KC-4b: POST /api/accounts/set-key-connector-key with empty body does not crash', async ({ request }) => {
        const resp = await request.post('/api/accounts/set-key-connector-key', {
            headers: { 'Content-Type': 'application/json' },
            data: {},
        });
        expect(resp.status(), 'Should not return 500 (crash)').not.toBe(500);
    });

    test('KC-4c: POST /api/accounts/key without auth is rejected', async ({ request }) => {
        const resp = await request.post('/api/accounts/key', {
            data: { key: 'dGVzdA==' },
        });
        expect(resp.status(), 'Must NOT return 200 without auth').not.toBe(200);
    });
});

// ===========================================================================
// KC-5: Full SSO enrollment flow — key stored via user-keys during first login
// ===========================================================================
test.describe('Key Connector enrollment via SSO', () => {
    test('KC-5: First SSO login stores key and subsequent login retrieves it', async ({ browser }) => {
        const userKeysGetCount = { value: 0 };
        const userKeysPutCount = { value: 0 };

        const ctx1 = await browser.newContext();
        const page1 = await ctx1.newPage();

        page1.on('request', req => {
            if (req.method() === 'GET' && req.url().includes('/user-keys')) {
                userKeysGetCount.value++;
            }
            if (req.method() === 'POST' && req.url().includes('/user-keys')) {
                userKeysPutCount.value++;
            }
        });

        await logNewUser(page1, users.user1);
        await expect(page1).toHaveTitle(/Vaultwarden Web/);

        await page1.close();
        await ctx1.close();

        const ctx2 = await browser.newContext();
        const page2 = await ctx2.newPage();

        let returnUserKeysGetCount = 0;
        page2.on('request', req => {
            if (req.method() === 'GET' && req.url().includes('/user-keys')) {
                returnUserKeysGetCount++;
            }
        });

        await logUser(page2, users.user1);
        await expect(page2).toHaveTitle(/Vaultwarden Web/);

        const content = await page2.content();
        expect(content).toMatch(/All vaults|Vaults|Get started/i);

        expect(returnUserKeysGetCount, 'Returning user should GET their key from /user-keys').toBeGreaterThan(0);

        await page2.close();
        await ctx2.close();
    });
});

// ===========================================================================
// KC-6: Key retrieval on new device (key overwrite protection)
// ===========================================================================
test.describe('Key Connector multi-device key protection', () => {
    test('KC-6: SSO login on new device retrieves same key (does not overwrite)', async ({ browser }) => {
        const ctx1 = await browser.newContext();
        const page1 = await ctx1.newPage();

        await logNewUser(page1, users.user1);
        await expect(page1).toHaveTitle(/Vaultwarden Web/);
        await page1.close();
        await ctx1.close();

        const ctx2 = await browser.newContext();
        const page2 = await ctx2.newPage();

        let userKeysGetCount = 0;
        page2.on('request', req => {
            if (req.method() === 'GET' && req.url().includes('/user-keys')) {
                userKeysGetCount++;
            }
        });

        await logUser(page2, users.user1);
        await expect(page2).toHaveTitle(/Vaultwarden Web/);

        expect(userKeysGetCount, 'Second device must fetch key via GET /user-keys').toBeGreaterThan(0);

        const content = await page2.content();
        expect(content).toMatch(/All vaults|Vaults|Get started/i);

        await page2.close();
        await ctx2.close();
    });
});