import { test } from '@playwright/test';

const { execSync } = require('node:child_process');
const utils = require('../../global-utils');

utils.loadEnv();

// Keycloak startup + realm setup can take 2-3 minutes in CI.
// The default 120s test timeout is too tight — use 180s here.
test.setTimeout(180_000);

test.beforeAll('Setup', async () => {
    console.log("Starting Keycloak");
    execSync(`docker compose -f docker-compose.e2e.yml --profile keycloak --env-file test.env up -d`, { stdio: 'inherit' });
});

test('Keycloak is up', async () => {
    console.log(`TEST_HOST=${process.env.TEST_HOST}`);
    console.log(`Waiting for SSO_AUTHORITY: ${process.env.SSO_AUTHORITY}`);
    console.log(`Waiting for DUMMY_AUTHORITY: ${process.env.DUMMY_AUTHORITY}`);

    // Use lightweight HTTP polling instead of browser contexts.
    // This avoids spinning up heavy Playwright browser pages just to check
    // if an HTTP endpoint returns 200, which adds overhead and can itself
    // time out under CI resource pressure.
    // Poll both endpoints in parallel so total wall time is
    // max(sso, dummy) instead of sso + dummy.
    await Promise.all([
        utils.waitForHttp(process.env.SSO_AUTHORITY!, 170_000),
        // Dummy authority is created at the end of the setup
        utils.waitForHttp(process.env.DUMMY_AUTHORITY!, 170_000),
    ]);
    console.log(`Keycloak running on: ${process.env.SSO_AUTHORITY}`);

    // Verify OIDC configuration — ensures KeycloakSetup actually created realm/client/user
    // If this fails, the SSO tests will fail with a clear error instead of timing out mysteriously.
    console.log(`Verifying OIDC realm configuration...`);
    // SSO_AUTHORITY = http://HOST:PORT/realms/TEST_REALM
    // We strip the realm path to get the base Keycloak URL, then use the master realm
    const keycloakBase = process.env.SSO_AUTHORITY!.replace(/\/realms\/[^/]+$/, '');
    const realmBase = `${keycloakBase}/realms/master`;
    const oidcUrl = `${realmBase}/.well-known/openid-configuration`;

    const verifyOidc = (url: string): Promise<void> => {
        return new Promise((resolve, reject) => {
            const mod = url.startsWith('https') ? require('https') : require('http');
            const req = mod.get(url, { rejectUnauthorized: false, timeout: 30_000 }, (res: any) => {
                let data = '';
                res.on('data', (chunk: string) => { data += chunk; });
                res.on('end', () => {
                    if (res.statusCode !== 200) {
                        return reject(new Error(`OIDC config at ${url} returned ${res.statusCode}`));
                    }
                    try {
                        const config = JSON.parse(data);
                        if (!config.issuer) {
                            return reject(new Error(`OIDC config at ${url} missing 'issuer' field`));
                        }
                        console.log(`OIDC realm verified — issuer: ${config.issuer}`);
                        resolve();
                    } catch (e) {
                        reject(new Error(`OIDC config at ${url} is not valid JSON: ${e}`));
                    }
                });
            });
            req.on('error', (e: Error) => reject(e));
            req.on('timeout', () => { req.destroy(); reject(new Error(`OIDC config at ${url} timed out`)); });
        });
    };

    await verifyOidc(oidcUrl);
    console.log(`Keycloak realm & OIDC client verified`);
});
