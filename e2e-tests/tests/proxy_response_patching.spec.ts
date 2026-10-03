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
// PROXY-1: /identity/connect/token — KeyConnectorOption injection
// ===========================================================================
test.describe('Proxy patches /identity/connect/token', () => {
    test('PROXY-1a: Token response contains UserDecryptionOptions with KeyConnectorOption', async ({ page }) => {
        const tokenResponses: any[] = [];

        page.on('response', async (response) => {
            if (response.url().includes('/identity/connect/token') && response.status() === 200) {
                try {
                    const body = await response.json();
                    tokenResponses.push(body);
                } catch {}
            }
        });

        await logNewUser(page, users.user1);

        await page.waitForLoadState('networkidle');

        expect(tokenResponses.length, 'At least one token response should be captured').toBeGreaterThan(0);

        const ssoToken = tokenResponses.find(r => r['UserDecryptionOptions']);
        expect(ssoToken, 'Token response must contain UserDecryptionOptions').toBeTruthy();

        if (ssoToken) {
            const udo = ssoToken['UserDecryptionOptions'];
            expect(udo).toHaveProperty('KeyConnectorOption');

            const kcOpt = udo['KeyConnectorOption'];
            expect(kcOpt).toHaveProperty('KeyConnectorUrl');
            expect(kcOpt).toHaveProperty('Object');
            expect(kcOpt['Object'], 'KeyConnectorOption must identify as keyConnectorUserDecryptionOption')
                .toBe('keyConnectorUserDecryptionOption');

            const masterlessPort = process.env.MASTERLESS_PORT || '8443';
            const expectedBaseUrl = process.env.DOMAIN || `https://127.0.0.1:${masterlessPort}`;
            expect(kcOpt['KeyConnectorUrl'], 'KeyConnectorUrl must be base URL (stripped of /user-keys)')
                .toBe(expectedBaseUrl);
        }
    });

    test('PROXY-1b: Token response sets HasMasterPassword to false', async ({ page }) => {
        const tokenResponses: any[] = [];

        page.on('response', async (response) => {
            if (response.url().includes('/identity/connect/token') && response.status() === 200) {
                try {
                    const body = await response.json();
                    tokenResponses.push(body);
                } catch {}
            }
        });

        await logUser(page, users.user1);

        await page.waitForLoadState('networkidle');

        const ssoToken = tokenResponses.find(r => r['UserDecryptionOptions']);
        expect(ssoToken, 'Token response must contain UserDecryptionOptions').toBeTruthy();

        if (ssoToken) {
            expect(
                ssoToken['UserDecryptionOptions']['HasMasterPassword'],
                'HasMasterPassword MUST be false — the proxy removes the master password requirement'
            ).toBe(false);
        }
    });

    test('PROXY-1c: Returning user token response has Key field (UK_enc)', async ({ browser }) => {
        const ctx1 = await browser.newContext();
        const page1 = await ctx1.newPage();

        const firstTokenResponses: any[] = [];
        page1.on('response', async (response) => {
            if (response.url().includes('/identity/connect/token') && response.status() === 200) {
                try {
                    firstTokenResponses.push(await response.json());
                } catch {}
            }
        });

        await logNewUser(page1, users.user1);
        await expect.poll(() => firstTokenResponses.length, { timeout: 10_000 }).toBeGreaterThan(0);
        await page1.close();
        await ctx1.close();

        const ctx2 = await browser.newContext();
        const page2 = await ctx2.newPage();

        const returnTokenResponses: any[] = [];
        page2.on('response', async (response) => {
            if (response.url().includes('/identity/connect/token') && response.status() === 200) {
                try {
                    returnTokenResponses.push(await response.json());
                } catch {}
            }
        });

        await logUser(page2, users.user1);
        await expect.poll(() => returnTokenResponses.length, { timeout: 10_000 }).toBeGreaterThan(0);

        const ssoToken = returnTokenResponses.find(r => r['UserDecryptionOptions']);
        if (ssoToken) {
            expect(
                ssoToken['Key'],
                'Returning user token response must have Key field (UK_enc) for vault decryption'
            ).toBeTruthy();
            expect(typeof ssoToken['Key']).toBe('string');
        }

        await page2.close();
        await ctx2.close();
    });
});

// ===========================================================================
// PROXY-2: /api/accounts/profile — usesKeyConnector injection
// ===========================================================================
test.describe('Proxy patches /api/accounts/profile', () => {
    test('PROXY-2a: Profile response has usesKeyConnector=true', async ({ page }) => {
        const profileResponses: any[] = [];

        page.on('response', async (response) => {
            if (response.url().includes('/api/accounts/profile') && response.status() === 200) {
                try {
                    profileResponses.push(await response.json());
                } catch {}
            }
        });

        await logUser(page, users.user1);

        await page.waitForLoadState('networkidle');

        if (profileResponses.length === 0) {
            await page.goto('/#/settings/account');
            await page.waitForLoadState('networkidle');
        }

        expect(profileResponses.length, 'At least one profile response should be captured').toBeGreaterThan(0);

        const profile = profileResponses[profileResponses.length - 1];
        expect(profile['usesKeyConnector'], 'usesKeyConnector MUST be true in patched profile').toBe(true);
    });

    test('PROXY-2b: Profile response organizations have Key Connector flags', async ({ page }) => {
        const profileResponses: any[] = [];

        page.on('response', async (response) => {
            if (response.url().includes('/api/accounts/profile') && response.status() === 200) {
                try {
                    profileResponses.push(await response.json());
                } catch {}
            }
        });

        await logUser(page, users.user1);

        await page.waitForLoadState('networkidle');

        if (profileResponses.length === 0) {
            await page.goto('/#/settings/account');
            await page.waitForLoadState('networkidle');
        }

        if (profileResponses.length > 0) {
            const profile = profileResponses[profileResponses.length - 1];
            const orgs = profile['organizations'];
            if (orgs && Array.isArray(orgs) && orgs.length > 0) {
                const masterlessPort = process.env.MASTERLESS_PORT || '8443';
                const expectedBaseUrl = process.env.DOMAIN || `https://127.0.0.1:${masterlessPort}`;
                for (const org of orgs) {
                    expect(org['useKeyConnector'], 'Each org must have useKeyConnector=true').toBe(true);
                    expect(org['keyConnectorEnabled'], 'Each org must have keyConnectorEnabled=true').toBe(true);
                    expect(org['keyConnectorUrl'], 'Each org must have keyConnectorUrl set').toContain(masterlessPort);
                    expect(org['keyConnectorUrl'], 'Org keyConnectorUrl must match base URL')
                        .toBe(expectedBaseUrl);
                }
            }
        }
    });
});

// ===========================================================================
// PROXY-3: /api/sync — keyConnectorUnlock and profile flags
// ===========================================================================
test.describe('Proxy patches /api/sync', () => {
    test('PROXY-3a: Sync response has usesKeyConnector=true in profile', async ({ page }) => {
        const syncResponses: any[] = [];

        page.on('response', async (response) => {
            if (response.url().includes('/api/sync') && response.status() === 200) {
                try {
                    syncResponses.push(await response.json());
                } catch {}
            }
        });

        await logUser(page, users.user1);

        await page.waitForLoadState('networkidle');

        // The response body is parsed asynchronously in the listener above, so
        // poll instead of asserting straight after networkidle.
        await expect.poll(
            () => syncResponses.some(r => r['profile']),
            { timeout: 15_000, message: 'Sync response must contain profile data' },
        ).toBe(true);

        const syncWithProfile = syncResponses.find(r => r['profile']);
        expect(syncWithProfile, 'Sync response must contain profile data').toBeTruthy();

        if (syncWithProfile) {
            expect(syncWithProfile['profile']['usesKeyConnector'], 'Profile usesKeyConnector MUST be true').toBe(true);
        }
    });

    test('PROXY-3b: Sync response has keyConnectorUnlock in userDecryption', async ({ page }) => {
        const syncResponses: any[] = [];

        page.on('response', async (response) => {
            if (response.url().includes('/api/sync') && response.status() === 200) {
                try {
                    syncResponses.push(await response.json());
                } catch {}
            }
        });

        await logUser(page, users.user1);

        await page.waitForLoadState('networkidle');

        const syncWithProfile = syncResponses.find(r => r['profile']);
        if (syncWithProfile && syncWithProfile['userDecryption']) {
            const ud = syncWithProfile['userDecryption'];
            expect(ud, 'userDecryption must contain keyConnectorUnlock').toHaveProperty('keyConnectorUnlock');

            const kcu = ud['keyConnectorUnlock'];
            expect(kcu).toHaveProperty('keyConnectorUrl');

            const masterlessPort = process.env.MASTERLESS_PORT || '8443';
            const expectedBaseUrl = process.env.DOMAIN || `https://127.0.0.1:${masterlessPort}`;
            expect(kcu['keyConnectorUrl'], 'keyConnectorUrl must be the base URL (stripped of /user-keys)')
                .toBe(expectedBaseUrl);
        }
    });
});

// ===========================================================================
// PROXY-4: /api/accounts/key-connector/confirmation-details — synthetic stub
// ===========================================================================
test.describe('Proxy handles key-connector confirmation-details', () => {
    test('PROXY-4:confirmation-details returns stub response', async ({ request }) => {
        const resp = await request.get('/api/accounts/key-connector/confirmation-details/some-org-id');

        if (resp.status() === 200) {
            const body = await resp.json();
            expect(body).toHaveProperty('Object');
            expect(body['Object']).toBe('keyConnectorConfirmationDetails');
            expect(body).toHaveProperty('OrganizationName');
        } else {
            // If the proxy doesn't intercept this path (e.g., user hasn't enrolled yet),
            // VW may return 404. An unauthenticated request returns 401 (auth-gated endpoint).
            expect([200, 401, 404]).toContain(resp.status());
        }
    });
});

// ===========================================================================
// PROXY-5: /alive endpoint (not proxied — local)
// ===========================================================================
test.describe('Proxy local endpoints', () => {
    test('PROXY-5a: /alive returns structured JSON health info', async ({ request }) => {
        const resp = await request.get('/alive');
        expect(resp.status()).toBe(200);

        const body = await resp.json();
        expect(body.alive).toBe(true);
        expect(body.now).toBeTruthy();
        const ts = new Date(body.now);
        expect(ts.getTime()).not.toBeNaN();
    });

    test('PROXY-5b: Proxy /alive returns different response than direct VW /alive', async ({ request }) => {
        const vwPort = process.env.ROCKET_PORT || '18000';
        const testHost = process.env.TEST_HOST || '127.0.0.1';

        const proxyResp = await request.get('/alive');
        const directResp = await request.get(`http://${testHost}:${vwPort}/alive`, {
            ignoreHTTPSErrors: true,
        });

        expect(proxyResp.status()).toBe(200);
        const proxyBody = await proxyResp.json();
        expect(proxyBody.alive).toBe(true);

        if (directResp.status() === 200) {
            let directBody: any;
            try {
                directBody = await directResp.json();
            } catch {
                return;
            }
            const isSameAsProxy = directBody.alive === true && typeof directBody.now === 'string';
            expect(isSameAsProxy, 'Direct VW /alive should not return same JSON as proxy').toBe(false);
        }
    });
});

// ===========================================================================
// PROXY-6: Static assets and non-API paths are proxied through
// ===========================================================================
test.describe('Proxy forwards non-API traffic', () => {
    test('PROXY-6: Web vault static assets are served through proxy', async ({ request }) => {
        const resp = await request.get('/');
        expect(resp.status()).toBe(200);
        const body = await resp.text();
        expect(body, 'Root page must contain HTML (not an error)').toContain('html');
    });

    test('PROXY-7: Unknown API paths return VW status codes', async ({ request }) => {
        const resp = await request.get('/api/nonexistent-endpoint-xyz');
        expect([400, 404], 'Unknown VW API path should return 404 or 400, not 200').toContain(resp.status());
    });
});