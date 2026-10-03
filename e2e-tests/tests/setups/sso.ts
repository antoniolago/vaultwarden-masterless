import { type Page } from '@playwright/test';

import * as utils from '../../global-utils';

/**
 * The SSO login flow itself lives in global-utils (`utils.ssoLogin`) so that
 * helpers needing an authenticated page can use it without a circular import.
 * These wrappers keep the specs' imports stable.
 */
export async function ssoLogin(
    page: Page,
    user: { email: string, name: string, password: string },
) {
    await utils.ssoLogin(page, user);
}

export async function logNewUser(page: Page, user: { email: string, name: string, password: string }) {
    console.log(`[logNewUser] Starting first-time SSO login for ${user.email}`);
    await ssoLogin(page, user);
}

export async function logUser(page: Page, user: { email: string, name: string, password: string }) {
    console.log(`[logUser] Starting returning user SSO login for ${user.email}`);
    await ssoLogin(page, user);
}
