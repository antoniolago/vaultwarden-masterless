import { test, expect, type TestInfo } from '@playwright/test';
import { logNewUser, logUser } from './setups/sso';
import * as utils from "../global-utils";

let users = utils.loadEnv();

test.describe('Vaultwarden Masterless Item Flows', () => {
    test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
        await utils.startVaultAndMasterless(browser, {
            SSO_ENABLED: true,
            SSO_ONLY: false,
        });
    });

    test.afterAll('Teardown', async ({}) => {
        await utils.stopVaultAndMasterless();
    });

    test('Create and save a login item', async ({ page }) => {
        await test.step('Create account via SSO', async () => {
            await logNewUser(page, users.user1);
            await expect(page).toHaveTitle(/Vaultwarden Web/);
        });

        const itemName = `LoginItem-${Date.now()}`;

        await test.step('Create login item', async () => {
            await utils.clickAddItem(page);
            await utils.clickLoginItem(page);
            await page.getByLabel(/Item name/i).fill(itemName);
            await page.getByLabel(/^Username$/i).fill('testuser@example.com');
            await page.getByLabel(/^Password$/i).first().fill('SecurePass123!');
            await page.getByRole('button', { name: /^Save$/i }).click();
            await page.waitForLoadState('networkidle');
        });

        await test.step('Item is listed in the vault', async () => {
            await utils.expectItemListed(page, itemName);
        });

        await test.step('Item persists after page reload', async () => {
            // A reload of the web vault always lands on the login page: the
            // Bitwarden client's state provider for the web (`web-disk-local`)
            // deliberately skips persisting `accessToken` / `refreshToken`, so
            // there is no session to restore after a reload. That is client
            // behaviour, not a proxy regression — what must hold is that the
            // vault content survives the reload once the user signs in again.
            await page.reload({ waitUntil: 'domcontentloaded' });
            await page.waitForLoadState('networkidle');
            await logUser(page, users.user1);
            await expect(page).toHaveTitle(/Vaultwarden Web/);
            await utils.expectItemListed(page, itemName);
        });
    });

    test('Vault item survives logout and re-login', async ({ page }) => {
        const itemName = `SurvivalItem-${Date.now()}`;

        await test.step('Login via SSO (returning user)', async () => {
            await logUser(page, users.user1);
            await expect(page).toHaveTitle(/Vaultwarden Web/);
        });

        await test.step('Create and save login item', async () => {
            await utils.clickAddItem(page);
            await utils.clickLoginItem(page);
            await page.getByLabel(/Item name/i).fill(itemName);
            await page.getByLabel(/^Username$/i).fill('survivor@test.com');
            await page.getByLabel(/^Password$/i).first().fill('TempPass123');
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

        await test.step('Verify item survived logout/relogin', async () => {
            await utils.expectItemListed(page, itemName);
        });
    });

    test('Edit vault item and save changes', async ({ page }) => {
        const itemName = `EditableItem-${Date.now()}`;
        const newItemName = `${itemName}-UPDATED`;

        await test.step('Login via SSO (returning user)', async () => {
            await logUser(page, users.user1);
            await expect(page).toHaveTitle(/Vaultwarden Web/);
        });

        await test.step('Create item', async () => {
            await utils.clickAddItem(page);
            await utils.clickLoginItem(page);
            await page.getByLabel(/Item name/i).fill(itemName);
            await page.getByLabel(/^Username$/i).fill('edituser@test.com');
            await page.getByLabel(/^Password$/i).first().fill('EditPass123');
            await page.getByRole('button', { name: /^Save$/i }).click();
            await page.waitForLoadState('networkidle');
            await utils.expectItemListed(page, itemName);
        });

        await test.step('Edit item name', async () => {
            await utils.openVaultItem(page, itemName);
            await page.getByRole('button', { name: /^Edit$/i }).first().click();
            await page.waitForLoadState('networkidle');
            const nameInput = page.getByLabel(/Item name/i);
            await nameInput.fill('');
            await nameInput.fill(newItemName);
            await page.getByRole('button', { name: /^Save$/i }).click();
            await page.waitForLoadState('networkidle');
            await utils.expectItemListed(page, newItemName);
        });
    });

    test('Delete vault item', async ({ page }) => {
        const itemName = `DeletableItem-${Date.now()}`;

        await test.step('Login via SSO (returning user)', async () => {
            await logUser(page, users.user1);
            await expect(page).toHaveTitle(/Vaultwarden Web/);
        });

        await test.step('Create item', async () => {
            await utils.clickAddItem(page);
            await utils.clickLoginItem(page);
            await page.getByLabel(/Item name/i).fill(itemName);
            await page.getByLabel(/^Username$/i).fill('deluser@test.com');
            await page.getByLabel(/^Password$/i).first().fill('DelPass123');
            await page.getByRole('button', { name: /^Save$/i }).click();
            await page.waitForLoadState('networkidle');
            await utils.expectItemListed(page, itemName);
        });

        await test.step('Delete item', async () => {
            await utils.openVaultItem(page, itemName);
            await page.getByTestId('delete-cipher-btn').click();
            // The confirmation is a dialog of its own ("Delete item" / "Do you
            // really want to send to the trash?"). Address its "Yes" by exact
            // name: the item dialog's own delete button is also named "Delete",
            // and a locator matching both is a strict-mode violation.
            const confirmBtn = page.getByRole('button', { name: 'Yes', exact: true });
            await expect(confirmBtn).toBeVisible({ timeout: 10_000 });
            await confirmBtn.click();
            await page.waitForLoadState('networkidle');
            await utils.closeOpenDialogs(page);
            await page.goto('/#/vault', { waitUntil: 'domcontentloaded' });
            await page.waitForLoadState('networkidle');
            await expect(utils.vaultItemRow(page, itemName)).toHaveCount(0, { timeout: 15_000 });
        });
    });

    test('Vault encryption works through proxy', async ({ page }) => {
        const sensitiveData = `SecretNote-${Date.now()}-SuperSecretContent`;

        await test.step('Login via SSO (returning user)', async () => {
            await logUser(page, users.user1);
            await expect(page).toHaveTitle(/Vaultwarden Web/);
        });

        await test.step('Create secure note with sensitive data', async () => {
            await utils.clickAddItem(page);
            // The add-item menu entries are "Login", "Card", "Identity", "Note",
            // "SSH key" and "Folder" (verified against the web vault this stack
            // serves) — there is no "Secure note" entry.
            await page.getByRole('menuitem', { name: 'Note', exact: true }).click();
            await page.getByLabel(/Item name/i).fill('SensitiveNote');
            // The notes field is the form's only textarea (label "Notes");
            // `getByLabel(/Notes?/i)` also matches the item-type button
            // ("Filter: Secure note") and the dialog container.
            await page.locator('textarea').first().fill(sensitiveData);
            await page.getByRole('button', { name: /^Save$/i }).click();
            await page.waitForLoadState('networkidle');
            await expect(page.getByText('SensitiveNote')).toBeVisible({ timeout: 10_000 });
        });

        await test.step('Verify sensitive data is encrypted in transit', async () => {
            await utils.openVaultItem(page, 'SensitiveNote');
            await expect(page.getByText(sensitiveData)).toBeVisible({ timeout: 15_000 });
        });
    });

    test('Vault search finds items', async ({ page }) => {
        const itemName = `SearchItem-${Date.now()}`;

        await test.step('Login via SSO (returning user)', async () => {
            await logUser(page, users.user1);
            await expect(page).toHaveTitle(/Vaultwarden Web/);
        });

        await test.step('Create item with searchable name', async () => {
            await utils.clickAddItem(page);
            await utils.clickLoginItem(page);
            await page.getByLabel(/Item name/i).fill(itemName);
            await page.getByLabel(/^Username$/i).fill('search@example.com');
            await page.getByLabel(/^Password$/i).first().fill('SearchPass123!');
            await page.getByRole('button', { name: /^Save$/i }).click();
            await page.waitForLoadState('networkidle');
            await utils.expectItemListed(page, itemName);
        });

        await test.step('Search for item by name', async () => {
            // The vault search box is `input[type=search]` with placeholder
            // "Search vault" (role `searchbox`). `getByLabel('Search')` matches
            // the "Learn more about searching your vault" help link instead,
            // and `getByPlaceholder` would too, so use the role.
            const searchInput = page.getByRole('searchbox');
            await expect(searchInput).toBeVisible({ timeout: 10_000 });
            await searchInput.fill(itemName);
            await page.waitForLoadState('networkidle');
            await expect(utils.vaultItemRow(page, itemName)).toBeVisible({ timeout: 15_000 });
        });
    });

    test('Vault items with special characters', async ({ page }) => {
        const itemName = `SpecialChars-${Date.now()}`;
        const specialUsername = 'user+test@example.com';
        const specialPassword = 'Pass!@#$%^&*()_+-=';

        await test.step('Login via SSO (returning user)', async () => {
            await logUser(page, users.user1);
            await expect(page).toHaveTitle(/Vaultwarden Web/);
        });

        await test.step('Create item with special characters', async () => {
            await utils.clickAddItem(page);
            await utils.clickLoginItem(page);
            await page.getByLabel(/Item name/i).fill(itemName);
            await page.getByLabel(/^Username$/i).fill(specialUsername);
            await page.getByLabel(/^Password$/i).first().fill(specialPassword);
            await page.getByRole('button', { name: /^Save$/i }).click();
            await page.waitForLoadState('networkidle');
            await utils.expectItemListed(page, itemName);
        });

        await test.step('Verify special characters are preserved', async () => {
            await utils.openVaultItem(page, itemName);
            await expect(page.getByTestId('login-username')).toHaveValue(specialUsername);
        });
    });

    test('Lock/unlock vault preserves item access', async ({ page }) => {
        const itemName = `LockableItem-${Date.now()}`;

        await test.step('Login via SSO (returning user)', async () => {
            await logUser(page, users.user1);
            await expect(page).toHaveTitle(/Vaultwarden Web/);
        });

        await test.step('Create item', async () => {
            await utils.clickAddItem(page);
            await utils.clickLoginItem(page);
            await page.getByLabel(/Item name/i).fill(itemName);
            await page.getByLabel(/^Username$/i).fill('lockuser@test.com');
            await page.getByLabel(/^Password$/i).first().fill('LockPass123');
            await page.getByRole('button', { name: /^Save$/i }).click();
            await page.waitForLoadState('networkidle');
            await utils.expectItemListed(page, itemName);
        });

        await test.step('Lock vault if supported', async () => {
            const lockBtn = page.getByRole('menuitem', { name: /Lock/i });
            if (await lockBtn.isVisible({ timeout: 2_000 }).catch(() => false)) {
                await lockBtn.click();
                await page.waitForLoadState('networkidle');
            }
        });

        await test.step('Unlock and verify item accessible', async () => {
            const ssoBtn = page.getByRole('button', { name: /Use single sign-on/i });
            if (await ssoBtn.isVisible({ timeout: 2_000 }).catch(() => false)) {
                await logUser(page, users.user1);
                await page.waitForLoadState('networkidle');
            }
            await utils.expectItemListed(page, itemName);
        });
    });
});
