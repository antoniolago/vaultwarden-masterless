import { test, expect } from '@playwright/test';
import { logNewUser, logUser } from './setups/sso';
import * as utils from '../global-utils';

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

test('Create item → logout → login → verify → edit → logout → login → verify updated', async ({ page }) => {
    const itemName = `LifecycleItem-${Date.now()}`;
    const originalUsername = 'lifecycle-user@test.com';
    const originalPassword = 'OriginalPass123!';
    const updatedUsername = 'lifecycle-user-updated@test.com';
    const updatedPassword = 'UpdatedPass456!';

    await test.step('Create account via SSO', async () => {
        await logNewUser(page, users.user1);
        await expect(page).toHaveTitle(/Vaultwarden Web/);
    });

    await test.step('Create login item with username and password', async () => {
        await utils.clickAddItem(page);
        await utils.clickLoginItem(page);
        await page.getByLabel(/Item name/i).fill(itemName);
        await page.getByLabel(/^Username$/i).fill(originalUsername);
        await page.getByLabel(/^Password$/i).first().fill(originalPassword);
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

    await test.step('Navigate to vault and find the item', async () => {
        await utils.expectItemListed(page, itemName);
    });

    await test.step('Open item and verify original content', async () => {
        await utils.openVaultItem(page, itemName);
        await expect(page.getByTestId('login-username')).toHaveValue(originalUsername);
    });

    await test.step('Edit username and password', async () => {
        await page.getByRole('button', { name: /^Edit$/i }).first().click();
        await page.waitForLoadState('networkidle');

        const usernameField = page.getByLabel(/^Username$/i);
        await usernameField.fill('');
        await usernameField.fill(updatedUsername);

        const passwordField = page.getByLabel(/^Password$/i).first();
        await passwordField.fill('');
        await passwordField.fill(updatedPassword);

        await page.getByRole('button', { name: /^Save$/i }).click();
        await page.waitForLoadState('networkidle');
    });

    await test.step('Logout after editing', async () => {
        await utils.cleanLanding(page);
        await expect(page.getByRole('button', { name: /Use single sign-on/i })).toBeVisible({ timeout: 20_000 });
    });

    await test.step('Re-login via SSO after edit', async () => {
        await logUser(page, users.user1);
        await expect(page).toHaveTitle(/Vaultwarden Web/);
    });

    await test.step('Navigate to vault and find the updated item', async () => {
        await utils.expectItemListed(page, itemName);
    });

    await test.step('Open item and verify updated content persisted', async () => {
        await utils.openVaultItem(page, itemName);
        await expect(page.getByTestId('login-username')).toHaveValue(updatedUsername);
    });
});
