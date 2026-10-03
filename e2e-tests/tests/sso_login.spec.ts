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
    utils.stopVaultAndMasterless();
});

test('Account creation using SSO (via masterless proxy)', async ({ page }) => {
    await logNewUser(page, users.user1);
});

test('SSO login (via masterless proxy)', async ({ page }) => {
    // Capture key API responses during returning user flow
    const apiLogs: string[] = [];
    page.on('response', async (response) => {
        const url = response.url();
        if (url.match(/\.(js|css|png|svg|woff2?|ico|map|ttf|eot)(\?|$)/)) return;
        const status = response.status();
        let snippet = '';
        try {
            const text = await response.text();
            snippet = text.substring(0, 200);
        } catch {}
        apiLogs.push(`${status} ${url} | ${snippet}`);
    });

    page.on('console', msg => {
        if (msg.type() === 'error') {
            apiLogs.push(`CONSOLE_ERROR: ${msg.text()}`);
        }
    });

    try {
        await logUser(page, users.user1);
    } catch (e) {
        // Dump diagnostics on failure
        console.log('=== RETURNING USER FLOW DIAGNOSTICS ===');
        console.log(`Final URL: ${page.url()}`);
        for (const log of apiLogs) {
            console.log(`  ${log}`);
        }
        throw e;
    }
});

test('Non SSO login page renders through proxy', async ({ page }) => {
    // Landing page — verify the "Other" (master password) button is visible
    // when SSO_ONLY=false, even though key connector users can't use it
    await page.goto('/');
    await expect(page.getByRole('button', { name: 'Other' })).toBeVisible();
    await expect(page.getByRole('button', { name: /Use single sign-on/ })).toBeVisible();
});

test('SSO-only mode hides master password option', async ({ page, browser }, testInfo: TestInfo) => {
    await utils.stopVaultAndMasterless(true);
    await utils.startVaultAndMasterless(browser, {
        SSO_ENABLED: true,
        SSO_ONLY: true,
    }, true);

    // Landing page
    await page.goto('/');
    await expect(page).toHaveTitle(/Vaultwarden Web/, { timeout: 30_000 });

    // SSO login is available
    await expect(page.getByRole('button', { name: /Use single sign-on/ })).toHaveCount(1, { timeout: 20_000 });

    // No "Other" button for master password
    await expect(page.getByRole('button', { name: 'Other' })).toHaveCount(0);
});

test('Masterless /alive endpoint works', async ({ request }) => {
    const resp = await request.get('/alive');
    expect(resp.status()).toBe(200);

    const body = await resp.json();
    expect(body.alive).toBe(true);
    expect(body.now).toBeTruthy();
});

test('Masterless /user-keys returns 401 without auth', async ({ request }) => {
    const resp = await request.get('/user-keys');
    expect(resp.status()).toBe(401);
});

test('SSO login on new device migrates/overwrites key and unlocks vault (works after fix)', async ({ browser }, testInfo) => {
    const ctx1 = await browser.newContext();
    const page1 = await ctx1.newPage();
    await logNewUser(page1, users.user1);
    await expect(page1).toHaveTitle(/Vaultwarden Web/);
    await page1.close();
    await ctx1.close();

    const ctx2 = await browser.newContext();
    const page2 = await ctx2.newPage();
    const apiLogs: string[] = [];
    let userKeysGetCount = 0;

    page2.on('request', req => {
        if (req.method() === 'GET' && req.url().includes('/user-keys')) {
            userKeysGetCount += 1;
        }
    });
    page2.on('console', msg => {
        if (msg.type() === 'error') apiLogs.push(`CONSOLE_ERROR: ${msg.text()}`);
    });

    try {
        await logUser(page2, users.user1);
    } catch (e) {
        console.log('=== MIGRATION FLOW DIAGNOSTICS ===');
        for (const log of apiLogs) console.log(log);
        throw e;
    }

    expect(userKeysGetCount).toBeGreaterThan(0);

    await expect(page2).toHaveTitle(/Vaultwarden Web/);
    const content = await page2.content();
    expect(content).toMatch(/All vaults|Vaults|Get started/i);

    await page2.close();
    await ctx2.close();
});

test('Masterless /user-keys returns 401 with invalid token', async ({ request }) => {
    const resp = await request.get('/user-keys', {
        headers: { 'Authorization': 'Bearer invalid.jwt.token' },
    });
    expect(resp.status()).toBe(401);
});
