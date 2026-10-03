import { test, expect } from '@playwright/test';

import { logNewUser, logUser } from './setups/sso';
import * as utils from "../global-utils";

let users = utils.loadEnv();

test.beforeAll('Setup', async ({ browser }) => {
    await utils.startVaultAndMasterless(browser, {
        SSO_ENABLED: true,
        SSO_ONLY: false,
    });
});

test.afterAll('Teardown', async ({}) => {
    await utils.stopVaultAndMasterless();
});

// ===========================================================================
// ATTEST-1: Token Response Attestation
// ===========================================================================
test.describe('ATTEST-1: Token response attestation', () => {
    test('ATTEST-1a: Token response contains UserDecryptionOptions with KeyConnectorOption', async ({ page, browser }) => {
        const context = await browser.newContext();
        const apiPage = await context.newPage();

        const tokenData = await utils.getVaultwardenToken(apiPage, users.user1);
        expect(tokenData, 'Must capture at least one token response').toBeTruthy();
        if (!tokenData) return;

        expect(tokenData['UserDecryptionOptions']).toBeTruthy();
        const udo = tokenData['UserDecryptionOptions'];
        expect(udo['HasMasterPassword'], 'HasMasterPassword MUST be false').toBe(false);
        expect(udo).toHaveProperty('KeyConnectorOption');

        const kcOpt = udo['KeyConnectorOption'];
        expect(kcOpt).toHaveProperty('KeyConnectorUrl');
        const expectedBaseUrl = process.env.DOMAIN || 'https://127.0.0.1:8443';
        expect(kcOpt['KeyConnectorUrl'], 'KeyConnectorUrl must be base URL (stripped of /user-keys)')
            .toBe(expectedBaseUrl);
        expect(kcOpt).toHaveProperty('Object');
        expect(kcOpt['Object'], 'KeyConnectorOption must identify as keyConnectorUserDecryptionOption')
            .toBe('keyConnectorUserDecryptionOption');

        await context.close();
    });
});

// ===========================================================================
// ATTEST-2: Profile Response Attestation
// ===========================================================================
test.describe('ATTEST-2: Profile response attestation', () => {
    test('ATTEST-2: Profile response has usesKeyConnector=true', async ({ page, browser }) => {
        // Use Keycloak direct token grant to get a VW access token
        const ctx = await browser.newContext();
        const apiPage = await ctx.newPage();

        const tokenData = await utils.getVaultwardenToken(apiPage, users.user1);
        expect(tokenData, 'Must have valid token response').toBeTruthy();
        if (!tokenData) return;

        const accessToken = tokenData.access_token;
        expect(accessToken, 'Must have access token').toBeTruthy();

        // Direct API call to profile endpoint through the proxy
        const profileResp = await apiPage.request.get('/api/accounts/profile', {
            headers: { 'Authorization': `Bearer ${accessToken}` },
            ignoreHTTPSErrors: true,
        });
        expect(profileResp.status(), 'Profile endpoint must return 200').toBe(200);

        const profile = await profileResp.json();
        expect(profile['usesKeyConnector'], 'usesKeyConnector MUST be true in patched profile').toBe(true);

        // Also verify org flags if orgs exist
        const orgs = profile['organizations'];
        if (orgs && Array.isArray(orgs) && orgs.length > 0) {
            for (const org of orgs) {
                expect(org['useKeyConnector'], 'Org useKeyConnector must be true').toBe(true);
                expect(org['keyConnectorEnabled'], 'Org keyConnectorEnabled must be true').toBe(true);
            }
        }

        await ctx.close();
    });
});

// ===========================================================================
// ATTEST-3: Sync Response Attestation
// ===========================================================================
test.describe('ATTEST-3: Sync response attestation', () => {
    test('ATTEST-3: Sync response has keyConnectorUnlock and profile flags', async ({ page, browser }) => {
        const ctx = await browser.newContext();
        const apiPage = await ctx.newPage();

        const tokenData = await utils.getVaultwardenToken(apiPage, users.user1);
        expect(tokenData, 'Must have valid token response').toBeTruthy();
        if (!tokenData) return;

        const accessToken = tokenData.access_token;

        // Direct API call to sync endpoint
        const syncResp = await apiPage.request.get('/api/sync', {
            headers: { 'Authorization': `Bearer ${accessToken}` },
            ignoreHTTPSErrors: true,
        });
        expect(syncResp.status(), 'Sync endpoint must return 200').toBe(200);

        const sync = await syncResp.json();
        expect(sync['profile']).toBeTruthy();
        expect(sync['profile']['usesKeyConnector'], 'Profile usesKeyConnector MUST be true').toBe(true);

        if (sync['userDecryption']) {
            const ud = sync['userDecryption'];
            expect(ud).toHaveProperty('keyConnectorUnlock');

            const kcu = ud['keyConnectorUnlock'];
            expect(kcu).toHaveProperty('keyConnectorUrl');
            const expectedBaseUrl = process.env.DOMAIN || 'https://127.0.0.1:8443';
            expect(kcu['keyConnectorUrl'], 'keyConnectorUrl must be the base URL').toBe(expectedBaseUrl);
        }

        await ctx.close();
    });
});

// ===========================================================================
// ATTEST-4: Full Enrollment + Retrieve Cycle
// ===========================================================================
test.describe('ATTEST-4: Full enrollment + retrieve cycle', () => {
    test('ATTEST-4: Key is enrolled via SSO and retrievable via /user-keys API', async ({ page, browser }) => {
        const ctx = await browser.newContext();
        const apiPage = await ctx.newPage();

        // Get Vaultwarden access token via API
        const tokenData = await utils.getVaultwardenToken(apiPage, users.user1);
        expect(tokenData, 'Must have captured a valid token response').toBeTruthy();
        if (!tokenData) return;

        const accessToken = tokenData.access_token;
        expect(accessToken, 'Must have captured a valid access token').toBeTruthy();

        // Retrieve the key via GET /user-keys using the bearer token
        const getResp = await apiPage.request.get('/user-keys', {
            headers: { 'Authorization': `Bearer ${accessToken}` },
            ignoreHTTPSErrors: true,
        });

        expect(getResp.status(), 'GET /user-keys must return 200 for authenticated user').toBe(200);

        const body = await getResp.json();
        expect(body, 'Response must contain Key field').toHaveProperty('Key');

        const key = body['Key'];
        expect(key, 'Key must be a truthy value').toBeTruthy();
        expect(typeof key, 'Key must be a string').toBe('string');
        expect(key.length, 'Key must be non-empty').toBeGreaterThan(0);

        // The key is the user's vault encryption key, base64-encoded by the client
        const base64Like = /^[A-Za-z0-9+/=._-]+$/;
        expect(key, 'Key must be base64-encoded').toMatch(base64Like);

        await ctx.close();
    });
});

// ===========================================================================
// ATTEST-5: Vault Item Survives Re-login (Key-Overwrite Regression)
// ===========================================================================
test.describe('ATTEST-5: Vault item survives re-login (key-overwrite regression)', () => {
    test('ATTEST-5: Create item → logout → login → verify → repeat 3 times', async ({ page, browser }) => {
        const itemName = `SurvivalAttest-${Date.now()}`;
        const vaultUsername = 'survival@test.com';
        const vaultPassword = 'SurvivalPass999!';

        // ── Cycle 1: Login, create item, verify, logout ──
        await test.step('Cycle 1: Login and create vault item', async () => {
            await logUser(page, users.user1);
            await expect(page).toHaveTitle(/Vaultwarden Web/);

            // Create a login item
            await utils.clickAddItem(page);
            await utils.clickLoginItem(page);
            // Wait for the add-item form to fully render
            await page.waitForTimeout(1_000);

            await page.getByLabel(/Item name/i).fill(itemName);
            await page.getByLabel(/^Username$/i).fill(vaultUsername);
            await page.getByLabel(/^Password$/i).first().fill(vaultPassword);
            await page.getByRole('button', { name: /^Save$/i }).click();
            await page.waitForLoadState('networkidle');

            // Verify item appears in vault
            await utils.expectItemListed(page, itemName);
        });

        await test.step('Cycle 1: Logout', async () => {
            await utils.cleanLanding(page);
            await expect(page.getByRole('button', { name: /Use single sign-on/i }))
                .toBeVisible({ timeout: 20_000 });
        });

        // ── Cycle 2: Re-login, verify item, logout ──
        await test.step('Cycle 2: Re-login and verify item is accessible', async () => {
            await logUser(page, users.user1);
            await expect(page).toHaveTitle(/Vaultwarden Web/);

            // Item must still exist (key was NOT overwritten)
            await utils.expectItemListed(page, itemName);

            // Open item and verify content is decryptable
            await utils.openVaultItem(page, itemName);
            await expect(page.getByTestId('login-username')).toHaveValue(vaultUsername);
        });

        await test.step('Cycle 2: Logout', async () => {
            await utils.cleanLanding(page);
            await expect(page.getByRole('button', { name: /Use single sign-on/i }))
                .toBeVisible({ timeout: 20_000 });
        });

        // ── Cycle 3: Third login, verify item still intact ──
        await test.step('Cycle 3: Third login and verify item still exists', async () => {
            await logUser(page, users.user1);
            await expect(page).toHaveTitle(/Vaultwarden Web/);

            // Item must still exist after a third login
            await utils.expectItemListed(page, itemName);

            // Open item and verify content is still decryptable
            await utils.openVaultItem(page, itemName);
            await expect(page.getByTestId('login-username')).toHaveValue(vaultUsername);
        });
    });
});
