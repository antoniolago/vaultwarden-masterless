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

test.afterAll('Teardown', async () => {
    await utils.stopVaultAndMasterless();
});

// ===========================================================================
// DECRYPT-1: Login token Key field format is valid EncString (not raw master key)
// ===========================================================================
test('DECRYPT-1: Login token Key field has valid EncString format', async ({ browser }) => {
    // Fresh context for first-time enrollment
    const ctx1 = await browser.newContext();
    const page1 = await ctx1.newPage();

    const tokenResponses: any[] = [];
    page1.on('response', async (response) => {
        if (response.url().includes('/identity/connect/token') && response.status() === 200) {
            try {
                tokenResponses.push(await response.json());
            } catch {}
        }
    });

    await logNewUser(page1, users.user1);
    await expect.poll(() => tokenResponses.length, { timeout: 15_000 }).toBeGreaterThan(0);
    await page1.close();
    await ctx1.close();

    // Fresh context for returning user — Key field should be present
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
    await expect.poll(() => returnTokenResponses.length, { timeout: 15_000 }).toBeGreaterThan(0);

    const ssoToken = returnTokenResponses.find(r => r['UserDecryptionOptions']);
    expect(ssoToken, 'Returning user token response must contain UserDecryptionOptions').toBeTruthy();

    if (ssoToken) {
        // Verify Key field exists for returning users
        expect(ssoToken['Key'], 'Returning user must have Key field for vault decryption').toBeTruthy();

        const keyStr = ssoToken['Key'] as string;
        expect(typeof keyStr).toBe('string');

        // === EncString format verification ===
        // Format: {encType}.{iv}|{ciphertext}|{mac}  (e.g. "2.abc123==|def456==|ghi789==")
        // encType is typically 2 (AesCbc256_HmacSha256_B64) for Bitwarden
        // A raw 32-byte master key would be ~44 base64 chars with no dots
        // (toMatch takes no message argument — the expectation text lives in comments)
        expect(keyStr, 'Key MUST be EncString format, NOT raw base64 master key').toMatch(/^\d+\./);

        const parts = keyStr.split('.');
        expect(parts.length).toBeGreaterThanOrEqual(2);

        // encType must be a valid integer
        const encType = parseInt(parts[0], 10);
        expect(Number.isInteger(encType) && encType >= 0).toBe(true);

        // The part after the dot should contain pipes separating IV|ciphertext|MAC
        const encPayload = parts.slice(1).join('.');
        expect(encPayload, 'EncString payload must contain pipe-separated segments (IV|ciphertext|MAC)')
            .toMatch(/\|/);

        // Verify UserDecryptionOptions.KeyConnectorOption has proper KeyConnectorUrl
        const udo = ssoToken['UserDecryptionOptions'];
        expect(udo).toHaveProperty('KeyConnectorOption');
        const kcOpt = udo['KeyConnectorOption'];
        expect(kcOpt).toHaveProperty('KeyConnectorUrl');
        expect(kcOpt['KeyConnectorUrl']).toBeTruthy();

        // Verify HasMasterPassword is false (proxy removes master password requirement)
        expect(udo['HasMasterPassword']).toBe(false);
    }

    await page2.close();
    await ctx2.close();
});

// ===========================================================================
// DECRYPT-2: Vault data survives logout and re-login (proves decrypt chain)
// ===========================================================================
test('DECRYPT-2: Vault data survives logout and re-login', async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();

    const itemName = `DecryptChainItem-${Date.now()}`;
    const itemUsername = `decrypt-test-${Date.now()}@example.com`;
    const itemPassword = `DecryptPass-${Date.now()}`;

    await test.step('Create account via SSO and save a vault item', async () => {
        await logNewUser(page, users.user1);
        await expect(page).toHaveTitle(/Vaultwarden Web/);

        // Create a login item with unique content
        await utils.clickAddItem(page);
        await utils.clickLoginItem(page);
        await page.getByLabel(/Item name/i).fill(itemName);
        await page.getByLabel(/^Username$/i).fill(itemUsername);
        await page.getByLabel(/^Password$/i).first().fill(itemPassword);
        await page.getByRole('button', { name: /^Save$/i }).click();
        await page.waitForLoadState('networkidle');
        await utils.expectItemListed(page, itemName);
    });

    await test.step('Logout', async () => {
        await utils.cleanLanding(page);
        await expect(page.getByRole('button', { name: /Use single sign-on/i })).toBeVisible({ timeout: 20_000 });
    });

    await test.step('Re-login via SSO', async () => {
        await logUser(page, users.user1);
        await expect(page).toHaveTitle(/Vaultwarden Web/);
    });

    await test.step('Verify item survived — proves decryption chain works', async () => {
        // Item name should be visible in the list (requires successful decryption)
        await utils.expectItemListed(page, itemName);

        // Open the item and verify its sensitive content
        await utils.openVaultItem(page, itemName);

        // Username must survive decryption
        await expect(page.getByTestId('login-username')).toHaveValue(itemUsername, { timeout: 10_000 });
    });

    await page.close();
    await ctx.close();
});

// ===========================================================================
// DECRYPT-3: GET /user-keys is called during returning user login
// ===========================================================================
test('DECRYPT-3: GET /user-keys is called during returning user login', async ({ browser }) => {
    // First: enroll the user
    const enrollCtx = await browser.newContext();
    const enrollPage = await enrollCtx.newPage();
    await logNewUser(enrollPage, users.user1);
    await expect(enrollPage).toHaveTitle(/Vaultwarden Web/);
    await enrollPage.close();
    await enrollCtx.close();

    // Second: returning login while tracking /user-keys GET requests
    const ctx = await browser.newContext();
    const page = await ctx.newPage();

    let userKeysGetCount = 0;
    page.on('request', req => {
        if (req.method() === 'GET' && req.url().includes('/user-keys')) {
            userKeysGetCount += 1;
        }
    });

    await logUser(page, users.user1);

    // The client must fetch the key from the proxy to decrypt the vault
    expect(userKeysGetCount, 'Client must fetch /user-keys during returning login').toBeGreaterThan(0);

    // Verify vault page loads correctly (decryption succeeded)
    await expect(page).toHaveTitle(/Vaultwarden Web/);

    // Navigate to vault and verify it renders
    await page.goto('/#/vault', { waitUntil: 'domcontentloaded' });
    await page.waitForLoadState('networkidle');

    // The vault should render items or show "Get started" / empty state
    // Either way, the page loads without errors — proving decryption worked
    const content = await page.content();
    const hasVaultContent = content.match(/All vaults|Vaults|Get started|item-name/i);
    expect(hasVaultContent, 'Vault page must render content after key retrieval').toBeTruthy();

    await page.close();
    await ctx.close();
});
