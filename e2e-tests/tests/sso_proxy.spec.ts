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

test.describe('Proxy patches /identity/connect/token', () => {
    test('Token response contains UserDecryptionOptions with KeyConnectorOption', async ({ page }) => {
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

            const masterlessPort = process.env.MASTERLESS_PORT || '8443';
            expect(kcOpt['KeyConnectorUrl']).toContain(masterlessPort);
        }
    });

    test('Token response sets HasMasterPassword to false', async ({ page }) => {
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

    test('Returning user token response has Key field (UK_enc)', async ({ browser }) => {
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
