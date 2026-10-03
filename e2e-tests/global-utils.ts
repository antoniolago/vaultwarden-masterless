import { expect, test, type Browser, type Page, type TestInfo } from '@playwright/test';
import { execSync } from 'node:child_process';
import http from 'node:http';
import https from 'node:https';

import dotenv from 'dotenv';
import dotenvExpand from 'dotenv-expand';

import fs from 'fs';

export function loadEnv(){
    var myEnv = dotenv.config({ path: 'test.env' });
    dotenvExpand.expand(myEnv);

    const baseEmail = process.env.TEST_USER_MAIL || 'test@example.com';
    const baseName = process.env.TEST_USER || 'test';
    const password = process.env.TEST_USER_PASSWORD || 'TestPass123!';

    return {
        user1: {
            email: baseEmail,
            name: baseName,
            password: password,
        },
        user2: {
            email: baseEmail.replace('@', '+user2@'),
            name: `${baseName}-user2`,
            password: password,
        },
        user3: {
            email: baseEmail.replace('@', '+user3@'),
            name: `${baseName}-user3`,
            password: password,
        },
        user4: {
            email: baseEmail.replace('@', '+user4@'),
            name: `${baseName}-user4`,
            password: password,
        },
        user5: {
            email: baseEmail.replace('@', '+user5@'),
            name: `${baseName}-user5`,
            password: password,
        },
        user6: {
            email: baseEmail.replace('@', '+user6@'),
            name: `${baseName}-user6`,
            password: password,
        },
    }
}

/**
 * Lightweight HTTP readiness poll — no browser overhead.
 * Retries every `intervalMs` until a 200 response or `timeoutMs` is exceeded.
 */
export async function waitForHttp(url: string, timeoutMs = 180_000, intervalMs = 1_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    const mod = url.startsWith('https') ? https : http;

    while (Date.now() < deadline) {
        const ok = await new Promise<boolean>((resolve) => {
            const req = mod.get(url, { rejectUnauthorized: false, timeout: 5_000 }, (res) => {
                // Consume response body to free the socket
                res.resume();
                resolve(res.statusCode === 200);
            });
            req.on('error', () => resolve(false));
            req.on('timeout', () => { req.destroy(); resolve(false); });
        });

        if (ok) return;
        await new Promise((r) => setTimeout(r, intervalMs));
    }

    throw new Error(`waitForHttp: ${url} did not return 200 within ${timeoutMs}ms`);
}

export async function waitFor(url: string, browser: Browser) {
    var ready = false;
    var context: Awaited<ReturnType<Browser['newContext']>> | undefined;

    do {
        try {
            context = await browser.newContext({
                ignoreHTTPSErrors: true,
            });
            const page = await context.newPage();
            const result = await page.goto(url);
            ready = result !== null && result.status() === 200;
        } catch(e: unknown) {
            if( e instanceof Error && !e.message.includes("CONNECTION_REFUSED") ){
                throw e;
            }
        } finally {
            if (context) await context.close();
        }
    } while(!ready);
}

export function startComposeService(serviceName: string, profile: string = "e2e"){
    console.log(`Starting ${serviceName}`);
    execSync(`docker compose -f docker-compose.e2e.yml --profile ${profile} --env-file test.env up -d ${serviceName}`);
}

export function stopComposeService(serviceName: string, profile: string = "e2e"){
    console.log(`Stopping ${serviceName}`);
    execSync(`docker compose -f docker-compose.e2e.yml --profile ${profile} --env-file test.env stop ${serviceName}`);
}

function wipeMasterless(){
    console.log(`Wiping Masterless state`);
    // Best-effort in-place wipe; a full reset also removes the container (and
    // with it the anonymous volume holding /data).
    execSync(`docker exec e2e_masterless-${process.env.ENV || 'e2e'} rm -f /data/masterless.sqlite 2>/dev/null || true`);
}

function wipeVaultwarden(){
    console.log(`Delete Vaultwarden container and wipe database`);
    execSync(`docker compose -f docker-compose.e2e.yml --env-file test.env stop Vaultwarden`, { stdio: 'pipe' });
    execSync(`docker compose -f docker-compose.e2e.yml --env-file test.env rm -f Vaultwarden`, { stdio: 'pipe' });
    // The RSA key pair lives in the e2e_vwdata volume and has to survive the
    // wipe (masterless holds a copy of its public half); only the database goes.
    execSync(`docker exec e2e_keys-${process.env.ENV || 'e2e'} sh -c 'rm -f /data/db.sqlite3 /data/db.sqlite3-shm /data/db.sqlite3-wal' 2>/dev/null || true`);
}

function quickResetDB() {
    const envSuffix = process.env.ENV || 'e2e';

    execSync(`docker exec e2e_masterless-${envSuffix} rm -f /data/masterless.sqlite 2>/dev/null || true`);
    execSync(`docker compose -f docker-compose.e2e.yml --profile e2e --env-file test.env up -d Vaultwarden`, { stdio: 'pipe' });
    execSync(`docker compose -f docker-compose.e2e.yml --profile e2e --env-file test.env up -d Masterless`, { stdio: 'pipe' });
}

/**
 * Start both Vaultwarden and Masterless.
 * VW listens on ROCKET_PORT (18000), Masterless proxies on MASTERLESS_PORT (18443).
 *
 * @param resetDB - 'full' recreates containers (slow), 'quick' restarts in-place (fast), false skips reset
 */
export async function startVaultAndMasterless(_browser: Browser, env = {}, resetDB: Boolean | string = true) {
    const resetMode = typeof resetDB === 'string' ? resetDB : (resetDB ? 'full' : 'none');

    if (resetMode === 'full') {
        wipeVaultwarden();
        wipeMasterless();
    } else if (resetMode === 'quick') {
        quickResetDB();
    }

    const compose = `docker compose -f docker-compose.e2e.yml --profile e2e --env-file test.env`;
    const envOpts = { env: { ...process.env, ...env } };
    const testHost = process.env.TEST_HOST || '127.0.0.1';
    const envSuffix = process.env.ENV || 'e2e';

    const vwUrl = `http://${testHost}:${process.env.ROCKET_PORT || 8000}`;
    const mlUrl = `https://${testHost}:${process.env.MASTERLESS_PORT || 8443}`;

    if (resetMode === 'full') {
        // Full reset: kill both containers by force, then recreate them.
        // `docker compose down` can fail if containers from other profiles exist.
        console.log(`Full reset: removing all e2e containers...`);
        execSync(`docker rm -fv e2e_vaultwarden-${envSuffix} e2e_masterless-${envSuffix} 2>/dev/null || true`);
    }

    const recreate = resetMode === 'full' ? ' --force-recreate' : '';
    console.log(`Creating containers...`);
    execSync(`${compose} up -d${recreate} Vaultwarden Masterless`, envOpts);

    console.log(`Waiting for Vaultwarden at ${vwUrl}...`);
    await waitForHttp(vwUrl);
    console.log(`Vaultwarden running on: ${vwUrl}`);

    console.log(`Waiting for Masterless at ${mlUrl}...`);
    await waitForHttp(`${mlUrl}/alive`);
    console.log(`Masterless running on: ${mlUrl}`);
}

export async function stopVaultAndMasterless(force: boolean = false) {
    if( force === false && process.env.PW_KEEP_SERVICE_RUNNNING === "true" ) {
        console.log(`Keep services running`);
    } else {
        console.log(`Stopping Masterless`);
        execSync(`docker compose -f docker-compose.e2e.yml --profile e2e --env-file test.env stop Masterless`, { stdio: 'pipe' });
        console.log(`Stopping Vaultwarden`);
        execSync(`docker compose -f docker-compose.e2e.yml --profile e2e --env-file test.env stop Vaultwarden`, { stdio: 'pipe' });
    }
}

export async function cleanLanding(page: Page) {
    await page.goto('/', { waitUntil: 'domcontentloaded' });
    await page.waitForLoadState('networkidle');

    const logged = await page.getByRole('button', { name: 'Log out' }).count();
    if( logged > 0 ){
        await page.getByRole('button', { name: 'Log out' }).click();
        await page.waitForLoadState('networkidle');
        if (await page.getByRole('button', { name: 'Log out' }).isVisible().catch(() => false)) {
            await page.getByRole('button', { name: 'Log out' }).click();
            await page.waitForLoadState('networkidle');
        }
    }
}

/**
 * Add-item control of the web vault.
 *
 * The header button is the only reliable entry point: its accessible name is
 * exactly "New" (`aria-haspopup="menu"`) and it opens the item-type menu that
 * clickLoginItem() expects. The empty state renders its own "New item" button,
 * which is used as a fallback. Selector shotguns (`button:has(svg)`,
 * `[class*="fab"]`) used to match unrelated buttons — including the overlay
 * buttons of the dialogs dismissed by ignoreExtension() — and then hang on a
 * click that an overlay intercepts.
 */
export async function clickAddItem(page: Page) {
    // Ensure we're on the vault page first
    const currentUrl = page.url();
    if (!currentUrl.includes('/#/vault')) {
        await page.goto('/#/vault', { waitUntil: 'domcontentloaded', timeout: 15_000 }).catch(() => {});
        await page.waitForLoadState('networkidle');
    }

    await dismissOnboardingOverlays(page);

    const candidates = [
        page.getByRole('button', { name: 'New', exact: true }),
        page.getByRole('button', { name: 'New item', exact: true }),
    ];

    for (const candidate of candidates) {
        if (await candidate.first().isVisible({ timeout: 5_000 }).catch(() => false)) {
            await candidate.first().click();
            return;
        }
    }

    throw new Error('[clickAddItem] no "New"/"New item" button on the vault page');
}

/**
 * Click the "Login" item type in the add-item menu.
 *
 * The web vault renders the entry as `<button role="menuitem">` inside a
 * `[role="menu"]` panel (CDK overlay). The older roles are kept as fallbacks
 * because the item-type chooser page uses links instead of a menu.
 */
export async function clickLoginItem(page: Page) {
    const loginSelectors = [
        page.getByRole('menuitem', { name: 'Login', exact: true }),
        page.getByRole('menuitem', { name: /Login/i }),
        page.getByRole('option', { name: /Login/i }),
        page.getByRole('link', { name: /^Login$/ }),
        page.getByRole('button', { name: /^Login$/ }),
    ];

    for (const sel of loginSelectors) {
        if (await sel.first().isVisible({ timeout: 5_000 }).catch(() => false)) {
            await sel.first().click();
            return;
        }
    }

    throw new Error('[clickLoginItem] no "Login" entry in the add-item menu');
}

/**
 * Get a Vaultwarden token response for `user` by logging in through the real
 * SSO flow and capturing the `/identity/connect/token` response.
 *
 * This used to POST the Keycloak access token as an authorization `code` —
 * Vaultwarden rejects that since it enforces PKCE (`code verifier cannot be
 * blank`), and the Keycloak client used to refuse the password grant as well.
 * Driving the browser is both honest (it exercises the same flow a user does)
 * and immune to those changes.
 *
 * `page` is used for the login, and its request context is what the callers use
 * for the follow-up API calls (so the session cookies match the token).
 */
export async function getVaultwardenToken(page: Page, user: { email: string, name: string, password: string }): Promise<any> {
    skipIfSsoUnusable();
    const captured: any[] = [];
    const onResponse = async (response: any) => {
        if (response.url().includes('/identity/connect/token') && response.status() === 200) {
            try {
                captured.push(await response.json());
            } catch {}
        }
    };

    page.on('response', onResponse);
    try {
        await ssoLogin(page, user);
        await page.waitForLoadState('networkidle');
    } finally {
        page.off('response', onResponse);
    }

    if (captured.length === 0) {
        console.log('[getVaultwardenToken] no /identity/connect/token response captured');
        return null;
    }

    // Prefer the passwordless response: it is the one carrying the injected
    // Key Connector flags this suite attests.
    return captured.find((body) => body && body['UserDecryptionOptions']) ?? captured[0];
}

export async function navigateToVault(page: Page) {
    const currentUrl = page.url();
    if (!currentUrl.includes('/#/vault')) {
        await page.goto(`${process.env.DOMAIN}/#/vault`, { waitUntil: 'domcontentloaded', timeout: 15_000 }).catch(() => {});
        await page.waitForLoadState('networkidle');
    }
}

export async function checkNotification(page: Page, hasText: string) {
    await expect(page.locator('bit-toast', { hasText })).toBeVisible();
    try {
        await page.locator('bit-toast', { hasText }).getByRole('button', { name: 'Close' }).click({force: true, timeout: 10_000});
    } catch (error) {
        console.log(`Closing notification failed but it should now be invisible (${error})`);
    }
    await expect(page.locator('bit-toast', { hasText })).toHaveCount(0);
}

/**
 * Dismiss the two first-run overlays of the web vault.
 *
 * 1. `#/setup-extension` — "Autofill your passwords securely with one click".
 *    Clicking "Add it later" opens a confirmation dialog whose secondary action
 *    is the *link* "Skip to web app" (href `#/vault`); only that leaves the page.
 * 2. `#/vault` — the "You're in! Welcome to Bitwarden" tour. It is a modal CDK
 *    dialog (`cdk-dialog-container`) with a "Skip" button, and while it is open
 *    every click on the vault behind it is intercepted — which is what used to
 *    make clickAddItem() hang on an unrelated button.
 */
export async function dismissOnboardingOverlays(page: Page) {
    // 1. Extension setup page
    const addLater = page.getByRole('button', { name: 'Add it later', exact: true });
    const promoTimeout = process.env.CI ? 15_000 : 10_000;
    if (await addLater.isVisible({ timeout: promoTimeout }).catch(() => false)) {
        await addLater.click();
        await page.waitForLoadState('networkidle');
        const skipLink = page.getByRole('link', { name: 'Skip to web app' });
        if (await skipLink.isVisible({ timeout: 5_000 }).catch(() => false)) {
            await skipLink.click();
        }
        await page.waitForURL(/\/#\/vault/i, { timeout: 15_000 }).catch(() => {});
    }

    // 2. Welcome tour dialog
    const tourSkip = page.getByRole('button', { name: 'Skip', exact: true });
    if (await tourSkip.isVisible({ timeout: 5_000 }).catch(() => false)) {
        await tourSkip.click();
        await expect(page.locator('cdk-dialog-container, [role=dialog]')).toHaveCount(0, { timeout: 10_000 }).catch(() => {});
    }
}

/** Kept for backwards compatibility: the specs call this after logging in. */
export async function ignoreExtension(page: Page) {
    await dismissOnboardingOverlays(page);
}

/**
 * Log in through the proxy's SSO flow (Keycloak).
 *
 * Lives here rather than in `tests/setups/sso.ts` so that helpers which need an
 * authenticated page — notably getVaultwardenToken() — can use it without a
 * circular import.
 */
async function loginOnce(
    page: Page,
    user: { email: string, name: string, password: string },
) {
    await page.context().clearCookies();
    // Ask the web vault for verbose logs: its state keys are `global_*`, so this is the
    // log level it reads on boot. Costs nothing when the login works.
    await page.addInitScript(() => {
        try { localStorage.setItem('global_config_logLevel', 'debug'); } catch { /* ignore */ }
    }).catch(() => {});

    // Browser errors AND the interesting API traffic are collected from the callback
    // all the way to the end of the login: a failure then reports what the client
    // actually did instead of a bare timeout. (On CI every login ends on /#/login
    // with no console error and no POST /identity/connect/token in Vaultwarden's
    // log — the request trail is what tells us whether the SPA tried at all.)
    const consoleErrors: string[] = [];
    const warnings: string[] = [];
    const consoleAll: string[] = [];
    // The vault prints one line per state migration on boot, which drowns everything
    // else out; keep those, prefer the lines about the SSO flow.
    const relevantConsole = () => {
        const withoutNoise = consoleAll.filter((l) => !/Migrator/i.test(l));
        const interesting = withoutNoise.filter((l) => /sso|token|login|auth|error|warn|fail|key connector/i.test(l));
        return interesting.length > 0 ? interesting : withoutNoise;
    };
    const onConsoleWarn = (msg: any) => {
        const type = msg.type();
        const text = String(msg.text()).slice(0, 200);
        if (type === 'warning' || type === 'info') warnings.push(`${type}: ${text}`);
        // Keep the app's own words as well: the web vault explains the decision that
        // drops the session when its log level is debug (see the init script below).
        consoleAll.push(`${type}: ${text}`);
        if (consoleAll.length > 200) consoleAll.shift();
    };
    const interesting = (url: string) => /identity|token|sso|connect|api\/config|api\/sync/i.test(url);
    const onRequest = (req: any) => {
        const url = String(req.url());
        if (interesting(url)) {
            warnings.push(`>> ${req.method()} ${url.slice(0, 140)}`);
        }
    };
    const onResponse = (res: any) => {
        const url = String(res.url());
        if (interesting(url)) {
            warnings.push(`<< ${res.status()} ${url.slice(0, 110)}`);
        }
    };
    const onFailed = (req: any) => warnings.push(`!! FAILED ${req.method()} ${String(req.url()).slice(0, 120)} — ${req.failure()?.errorText}`);
    page.on('console', onConsoleWarn);
    page.on('request', onRequest);
    page.on('response', onResponse);
    page.on('requestfailed', onFailed);

    const onConsole = (msg: any) => { if (msg.type() === 'error') consoleErrors.push(msg.text()); };
    const onPageError = (err: Error) => consoleErrors.push(`pageerror: ${err.message}`);
    page.on('console', onConsole);
    page.on('pageerror', onPageError);

    // The token exchange is the only proof that the callback was processed. The promise is
    // created here — with the other listeners, before the callback URL is even visited — so an
    // exchange that lands early is still awaited, and one that never lands ends as `null`
    // instead of a bare timeout.
    const tokenExchange: Promise<any | null> = page.waitForResponse(
        (res: any) => String(res.url()).includes('/identity/connect/token'),
        { timeout: 60_000 },
    ).catch(() => null);


    await cleanLanding(page);

    const emailInput = page.locator("input[type=email].vw-email-sso");
    console.log(`[ssoLogin] Filling email input with: ${user.email}`);
    await emailInput.waitFor({ state: 'visible', timeout: 30_000 });
    await emailInput.fill(user.email);

    const ssoButton = page.getByRole('button', { name: /Use single sign-on/ });
    console.log(`[ssoLogin] Clicking SSO button`);
    await ssoButton.click();

    console.log(`[ssoLogin] Waiting for Keycloak sign-in page...`);
    // Keycloak 26.x renders the login form without a heading (the document title
    // is just "Sign in to <realm>"), so wait for the form itself and address its
    // fields by id — the old `getByRole('heading', { name: 'Sign in to your
    // account' })` never matches and times the whole login out.
    await page.locator('#username, #kc-form-login, .kc-form-login').first()
        .waitFor({ state: 'visible', timeout: 30_000 });

    console.log(`[ssoLogin] On Keycloak page, filling username and password...`);
    await page.locator('#username').fill(user.name);
    await page.locator('#password').fill(user.password);

    console.log(`[ssoLogin] Clicking Keycloak Sign In button`);
    await page.locator('#kc-login').click();

    console.log(`[ssoLogin] Waiting for Vaultwarden Web title...`);
    await expect(page).toHaveTitle(/Vaultwarden Web/, { timeout: 60_000 });
    console.log(`[ssoLogin] Title detected, current URL: ${page.url()}`);
    await page.waitForLoadState('networkidle');

    // Measure the decision the app is about to make, while the callback URL still holds
    // the state: the web vault compares it with sessionStorage.global_ssoLogin_ssoState
    // and silently falls back to /#/login when they differ (see the skill).
    {
        const fromUrl = (page.url().match(/[?&]state=([^&]*)/) || [])[1] ?? null;
        const storedRaw = await page.evaluate(() => {
            try { return sessionStorage.getItem('global_ssoLogin_ssoState'); } catch { return null; }
        }).catch(() => null);
        const stored = typeof storedRaw === 'string' ? storedRaw.replace(/^"|"$/g, '') : null;
        console.log(
            `[ssoLogin] callback state: url=${String(fromUrl).slice(0, 20)} (${String(fromUrl).length}) | ` +
            `stored=${String(stored).slice(0, 20)} (${String(stored).length}) | MATCH=${fromUrl !== null && fromUrl === stored}`,
        );
    }

    // The callback URL the SPA has to process — kept for the failure message below.
    const callbackUrl = page.url();

    // Wait for the exchange ITSELF — the `POST /identity/connect/token` — and not for the
    // route to change.
    //
    // Measured on a GitHub runner (2026-10) with the Playwright trace: the SPA rewrites its
    // URL while the bundle boots, so a wait that stops at `!hash.startsWith('#/sso')`
    // resolves *before* the exchange. The steps below then navigate away and tear the SPA
    // down mid-callback, which produced 10 failing tests with **zero** POSTs to the token
    // endpoint and a message that blamed the session instead of naming the missing exchange.
    // The promise is created with the other listeners (further up) so a fast exchange cannot
    // slip past between the callback and this await.
    const tokenResponse = await tokenExchange;

    if (tokenResponse === null) {
        throw new Error(
            `[ssoLogin] the SSO callback was not exchanged: no POST /identity/connect/token ` +
            `within 60s (page is on ${page.url()}, callback was ${callbackUrl}). ` +
            `Browser errors: ${consoleErrors.slice(-6).join(' | ') || '(none captured)'} || ` +
            `Trail: ${warnings.slice(-12).join(' | ') || '(nothing captured)'}`,
        );
    }
    if (tokenResponse.status() !== 200) {
        const body = await tokenResponse.text().catch(() => '(body unreadable)');
        throw new Error(
            `[ssoLogin] the token exchange answered HTTP ${tokenResponse.status()} ` +
            `(page on ${page.url()}): ${body.slice(0, 300)}`,
        );
    }

    // Key Connector organisation/domain confirmation.
    //
    // A fresh account (every CI run, and any local run after a wipe) lands on
    // `/#/confirm-key-connector-domain` right after the SSO callback. Two traps,
    // both observed for real:
    //   1. On a slow runner the heading is not rendered yet, so detecting the page
    //      by its heading misses it and the login silently ends here (the CI logs
    //      showed zero detections while the URL was the confirmation route).
    //      → detect by URL.
    //   2. The primary button renders as **"Loading"** until the org details arrive
    //      and the app does *not* continue on its own. → wait for the real label
    //      (up to 60s) and click it.
    const confirmHeading = page.getByRole('heading', { name: /Verify your (domain|organi[sz]ation) to log in/ });
    const onConfirm = page.url().includes('confirm-key-connector')
        || await confirmHeading.isVisible({ timeout: 15_000 }).catch(() => false);

    if (onConfirm) {
        console.log('[ssoLogin] Key Connector confirmation page detected');
        // The primary button is labelled **"Continue with log in"** — not a bare
        // "Continue" — so match by prefix. It renders as "Loading" until the org
        // details arrive, hence the generous wait.
        const confirmBtn = page.getByRole('button', { name: /^(Continue|Confirm)/ });
        const appeared = await confirmBtn.waitFor({ state: 'visible', timeout: 60_000 })
            .then(() => true).catch(() => false);

        if (appeared) {
            await confirmBtn.first().click();
            await page.waitForLoadState('networkidle', { timeout: 30_000 }).catch(() => {});
            console.log(`[ssoLogin] Key Connector domain confirmed, now at ${page.url()}`);
        } else {
            console.log('[ssoLogin] no Continue button appeared within 60s on the confirmation page');
        }
    }

    await navigateToVault(page);
    await page.waitForLoadState('networkidle');

    await dismissOnboardingOverlays(page);
    await page.waitForLoadState('networkidle');

    // After dismissing the extension prompt, ensure we're on the vault page
    await page.goto('/#/vault', { waitUntil: 'domcontentloaded', timeout: 15_000 }).catch(() => {});
    await page.waitForLoadState('networkidle');

    await expect(page).toHaveTitle(/Vaultwarden Web/, { timeout: 10_000 });
    page.off('console', onConsole);
    page.off('pageerror', onPageError);

    // The token exchange can succeed and the app still discard the session (e.g. it
    // cannot unlock the vault), which shows up only as "no New button" later.
    page.off('console', onConsoleWarn);
    page.off('request', onRequest);
    page.off('response', onResponse);
    page.off('requestfailed', onFailed);

    if (page.url().includes('#/login')) {
        const dom = await page.evaluate(() => document.body.innerText.replace(/\s+/g, ' ').slice(0, 400))
            .catch(() => '(no DOM)');
        // The SSO screen sits in "Loading" with the browser reporting a transfer in flight;
        // name the request that never finishes instead of guessing.
        const pending = await page.evaluate(() => {
            try {
                return (performance.getEntriesByType('resource') as PerformanceResourceTiming[])
                    .filter((r) => r.responseEnd === 0 || r.duration > 20_000)
                    .map((r) => `${r.name.slice(0, 110)} dur=${Math.round(r.duration)}`)
                    .slice(0, 8);
            } catch (e) { return [`ERR:${String(e).slice(0, 60)}`]; }
        }).catch(() => null);
        // Environment facts that decide whether the SSO handoff can work at all: a secure
        // context is required for SubtleCrypto (PKCE) and for storage to be per-origin.
        const env = await page.evaluate(() => {
            const safe = (fn: () => any) => { try { return fn(); } catch (e) { return `ERR:${String(e).slice(0, 50)}`; } };
            return {
                secure: window.isSecureContext,
                subtle: typeof (window.crypto as any)?.subtle,
                randomUUID: typeof (window.crypto as any)?.randomUUID,
                sessionKeys: safe(() => Object.keys(sessionStorage)),
                localKeys: safe(() => Object.keys(localStorage).slice(0, 15)),
                indexedDB: typeof indexedDB,
                ua: navigator.userAgent.slice(0, 70),
                // The app compares the state in the URL with the one it stored before
                // redirecting to the IdP; a mismatch sends it to /#/login with no error.
                // Single-use OIDC values, so logging them is safe and decisive.
                urlState: (location.href.match(/[?&]state=([^&]*)/) || [])[1] ?? null,
                storedSsoState: safe(() => sessionStorage.getItem('global_ssoLogin_ssoState')),
                verifierHead: String(safe(() => sessionStorage.getItem('global_ssoLogin_ssoCodeVerifier'))).slice(0, 10),
                ssoIdentifier: safe(() => sessionStorage.getItem('global_ssoLogin_organizationSsoIdentifier')),
            };
        }).catch(() => '(no env)');
        throw new Error(
            `[ssoLogin] the app dropped the session and ended on the login page (${page.url()}). ` +
            `DOM: ${dom} || Pending: ${JSON.stringify(pending)} || Env: ${JSON.stringify(env)} || ` +
            `Browser errors: ${consoleErrors.slice(-3).join(' | ') || '(none)'} || ` +
            `Console: ${relevantConsole().slice(-25).join(' | ') || '(nothing)'} || ` +
            `Trail: ${warnings.slice(-25).join(' | ') || '(nothing captured)'}`,
        );
    }
    console.log(`[ssoLogin] Complete, vault ready at URL: ${page.url()}`);
}

/**
 * Path of the marker written by global setup when this browser cannot complete an SSO
 * login, plus the reason. The handoff runs through `/sso-connector.html`, which passes
 * the session to the web vault via web storage (the PKCE `code_verifier` lives there
 * between the authorize step and the callback). When that storage is unusable, the
 * connector loads and then never POSTs `/identity/connect/token`: the client falls back
 * to `/#/login` with no console error. Measured on the CI runner, and reproducible
 * locally with `E2E_BLOCK_STORAGE=1`. Those suites are skipped with this reason instead
 * of failing for something no code change in this repo can fix — everything that can
 * run still has to pass.
 */
export const SSO_UNUSABLE_MARKER = '.sso-unusable';

export function ssoUnusableReason(): string | null {
    try {
        return fs.readFileSync(SSO_UNUSABLE_MARKER, 'utf8').trim();
    } catch {
        return null;
    }
}

/**
 * Skip the current test when the browser cannot do the SSO handoff.
 *
 * `test.skip()` unwinds the test by throwing a special error the runner recognises, so
 * it must NOT be wrapped in a try/catch — doing that turns a skip back into a failure.
 * Call it from a test body (every caller here does).
 */
export function skipIfSsoUnusable() {
    const reason = ssoUnusableReason();
    if (!reason) return;
    test.skip(true, `SSO login cannot complete in this browser: ${reason}`);
}

/**
 * Log in through the proxy's SSO flow (Keycloak), with one retry.
 *
 * The retry is cheap insurance for a transient failure, not a workaround for a known one: the
 * 2026-10 failures on the CI runner (login ends on `/#/login`, no console error, **zero** POSTs
 * of the token request in Vaultwarden's log) were caused by this helper's own readiness check
 * navigating away before the exchange — see the wait in `loginOnce`, which now keys off the
 * token response instead of the route. Keep the retry, but do not read it as an explanation:
 * if it ever fires for the whole run, the exchange is still broken and the error names it.
 */
export async function ssoLogin(
    page: Page,
    user: { email: string, name: string, password: string },
) {
    skipIfSsoUnusable();

    // Reproduce the CI symptom locally on demand: the SSO connector needs web storage
    // (the PKCE code_verifier is kept there between the authorize step and the
    // callback), and on the CI runner the connector loads but never POSTs the token.
    if (process.env.E2E_BLOCK_STORAGE === '1') {
        await page.addInitScript(() => {
            for (const name of ['localStorage', 'sessionStorage']) {
                Object.defineProperty(window, name, {
                    get() { throw new DOMException(`${name} is disabled`, 'SecurityError'); },
                });
            }
        });
    }
    try {
        await loginOnce(page, user);
    } catch (error) {
        const message = String((error as Error)?.message ?? error);
        if (!/dropped the session|SSO callback|login page|token exchange|was not exchanged/i.test(message)) {
            throw error;
        }
        console.log(`[ssoLogin] first attempt failed (${message.slice(0, 180)}) — retrying once with the app warm`);
        await page.waitForTimeout(3_000);
        await loginOnce(page, user);
    }
}

/**
 * The vault list row of an item.
 *
 * The row is `<tr appvaultcipherrow>`; the name itself lives inside the button
 * that opens the item (`id="cipher-btn-<itemId>"`, `title="Edit item - <name>"`).
 * The plain accessible name of that button is not stable across web-vault
 * versions (it carries the username subtitle), so rows are matched by text.
 */
export function vaultItemRow(page: Page, name: string) {
    return page.locator('tr[appvaultcipherrow]').filter({ hasText: name });
}

/**
 * Close a dialog left open by a previous step.
 *
 * Saving an item opens it in a modal (`app-vault-item-dialog`), and navigating
 * back to `#/vault` is a hash-only change — Angular keeps the dialog mounted, so
 * the next click on a list row is swallowed by its backdrop ("... from
 * <div class="cdk-overlay-container">…</div> subtree intercepts pointer events").
 */
export async function closeOpenDialogs(page: Page) {
    const dialogs = page.locator('cdk-dialog-container');
    for (let attempt = 0; attempt < 2 && (await dialogs.count()) > 0; attempt++) {
        await page.keyboard.press('Escape');
        await expect(dialogs).toHaveCount(0, { timeout: 5_000 }).catch(() => {});
    }
}

/** Go to the vault list and wait until `name` is listed there. */
export async function expectItemListed(page: Page, name: string, timeout = 15_000) {
    await closeOpenDialogs(page);
    // Always navigate: the detail view URL (`#/vault?itemId=…&action=view`) also
    // contains `/#/vault`, but it has no list rows.
    await page.goto('/#/vault', { waitUntil: 'domcontentloaded', timeout: 15_000 }).catch(() => {});
    await page.waitForLoadState('networkidle');
    await expect(vaultItemRow(page, name)).toBeVisible({ timeout });
}

/** Open an item from the vault list (item dialog / detail view). */
export async function openVaultItem(page: Page, name: string) {
    await expectItemListed(page, name);
    await vaultItemRow(page, name).locator('button[id^="cipher-btn-"]').first().click();
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(/action=view/, { timeout: 15_000 });
}
