import { defineConfig } from '@playwright/test';

const utils = require('./global-utils');

utils.loadEnv();

export default defineConfig({
    testDir: './.',
    fullyParallel: false,
    forbidOnly: !!process.env.CI,
    retries: 0,

    // Workers are pinned to 1 on purpose.
    //
    // ⚠️ PORT CONFLICT: every test project shares the same Vaultwarden (:18000)
    // and Masterless (:18443) containers via `network_mode: "host"`, and each
    // project's `beforeAll` hook calls `startVaultAndMasterless()`, which
    // *removes and recreates* those containers. Two projects running at the same
    // time therefore destroy each other's stack: the second one hits
    // "container is marked for removal and cannot be started" (or the first one
    // loses its database mid-login) and a whole project fails for reasons that
    // have nothing to do with the code under test.
    //
    // For wall-time reduction, use CI-level sharding instead (see the CI
    // workflow): each shard gets its own runner, and therefore its own ports.
    //   Job 1:  --project=sso-e2e --project=security --project=vault-e2e
    //   Job 2:  --project=proxy-patching --project=key-connector-flow
    //           --project=item-lifecycle --project=attest
    workers: 1,

    reporter: 'html',

    timeout: 300 * 1000,
    expect: { timeout: 20_000 },

    use: {
        actionTimeout: 20 * 1000,
        navigationTimeout: 20 * 1000,
        baseURL: process.env.DOMAIN,
        browserName: 'firefox',
        locale: 'en-GB',
        timezoneId: 'Europe/London',
        trace: 'on',
        viewport: { width: 1080, height: 720 },
        video: 'on',
        ignoreHTTPSErrors: true,
    },

    projects: [
        {
            name: 'sso-setup',
            testMatch: 'tests/setups/sso-setup.ts',
        },
        {
            name: 'sso-e2e',
            testMatch: 'tests/sso_*.spec.ts',
            dependencies: ['sso-setup'],
            teardown: 'sso-teardown',
        },
        {
            name: 'security',
            testMatch: 'tests/security*.spec.ts',
            dependencies: ['sso-setup'],
            teardown: 'sso-teardown',
        },
        {
            name: 'vault-e2e',
            testMatch: 'tests/vault_items*.spec.ts',
            dependencies: ['sso-setup'],
            teardown: 'sso-teardown',
        },
        {
            name: 'proxy-patching',
            testMatch: 'tests/proxy_response_patching.spec.ts',
            dependencies: ['sso-setup'],
            teardown: 'sso-teardown',
        },
        {
            name: 'key-connector-flow',
            testMatch: 'tests/key_connector_flow.spec.ts',
            dependencies: ['sso-setup'],
            teardown: 'sso-teardown',
        },
        {
            name: 'item-lifecycle',
            testMatch: 'tests/item_lifecycle.spec.ts',
            dependencies: ['sso-setup'],
            teardown: 'sso-teardown',
        },
        {
            name: 'attest',
            testMatch: 'tests/attest_*.spec.ts',
            dependencies: ['sso-setup'],
            teardown: 'sso-teardown',
        },
        {
            name: 'sso-teardown',
            testMatch: 'tests/setups/sso-teardown.ts',
        },
    ],

    globalSetup: require.resolve('./global-setup'),
});
