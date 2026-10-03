import { type FullConfig } from '@playwright/test';
import { execSync } from 'node:child_process';
import fs from 'fs';

const utils = require('./global-utils');

utils.loadEnv();

async function globalSetup(config: FullConfig) {
    console.log('=== Global Setup: Generating keys & building containers ===');

    // Create data directories
    execSync('mkdir -p data/vw data/keys data/masterless', { stdio: 'inherit' });
    // Ensure test-results and artifacts/traces directory exists for Playwright
    execSync('mkdir -p e2e-tests/test-results/traces', { stdio: 'inherit' });

    // Generate Vaultwarden's signing key pair.
    //
    // Vaultwarden loads an existing /data/rsa_key.pem and *never* writes the
    // public half to disk, so there is nothing to extract from the container at
    // runtime. Generating the pair here and seeding the private key into
    // Vaultwarden's data folder is what keeps the key masterless verifies
    // identical to the key Vaultwarden actually signs with.
    if (!fs.existsSync('data/vw/rsa_key.pem')) {
        console.log('Generating Vaultwarden RSA key pair...');
        execSync('openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out data/vw/rsa_key.pem 2>/dev/null');
        execSync('openssl pkey -in data/vw/rsa_key.pem -pubout -out data/vw/rsa_key.pub.pem 2>/dev/null');
        console.log('  VW keys written to data/vw/');
    }
    execSync('cp data/vw/rsa_key.pub.pem data/keys/vw_rsa_key.pub.pem');

    // Generate masterless RSA key pair (used for at-rest encryption)
    if (!fs.existsSync('data/keys/rsa_private.pem')) {
        console.log('Generating Masterless RSA key pair...');
        execSync('openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out data/keys/rsa_private.pem 2>/dev/null');
        execSync('openssl pkey -in data/keys/rsa_private.pem -pubout -out data/keys/rsa_public.pem 2>/dev/null');
        console.log('  Masterless keys written to data/keys/');
    }

    // Generate self-signed TLS certificate for Masterless HTTPS
    // Always regenerate — TEST_HOST may differ between local and CI runs
    const testHost = process.env.TEST_HOST || '127.0.0.1';
    console.log(`Generating self-signed TLS certificate (TEST_HOST=${testHost})...`);
    const sanEntries = `DNS:localhost,IP:127.0.0.1,IP:${testHost}`;
    execSync(
        `openssl req -x509 -newkey rsa:2048 -keyout data/keys/tls.key -out data/keys/tls.crt ` +
        `-days 730 -nodes -subj "/CN=localhost" ` +
        `-addext "subjectAltName=${sanEntries}" 2>/dev/null`
    );
    console.log('  TLS cert written to data/keys/tls.{crt,key}');

    // Vaultwarden's public key lives in the generated pair above.

    // The CI job container runs as root, so `docker cp` seeds the keys volume with
    // root-owned 0600 files and masterless (uid 1000) cannot read them:
    //   Error: Cannot read RSA private key at /keys/rsa_private.pem: Permission denied
    // The volume holds throwaway test material, so make it world-readable.
    execSync('chmod 644 data/keys/* data/vw/rsa_key.pem data/vw/rsa_key.pub.pem 2>/dev/null || true', { stdio: 'inherit' });

    // --- Browser capability probe -------------------------------------------------
    // The SSO handoff goes through /sso-connector.html, which passes the session to
    // the web vault via web storage. When the runner's browser cannot persist web
    // storage, every SSO login dies on /#/login without a single POST to
    // /identity/connect/token (measured on CI; reproducible locally with
    // E2E_BLOCK_STORAGE=1). Measure it once and leave a marker so the suites skip with
    // a reason instead of failing for the environment.
    const marker = '.sso-unusable';
    try {
        const { firefox } = require('playwright');
        const http = require('node:http');
        const server = http.createServer((_req: any, res: any) => {
            res.writeHead(200, { 'content-type': 'text/html' });
            res.end('<!doctype html><title>probe</title>ok');
        });
        await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
        const port = (server.address() as any).port;
        const probeBrowser = await firefox.launch();
        const probePage = await probeBrowser.newPage({ ignoreHTTPSErrors: true });
        // E2E_BLOCK_STORAGE emulates the runner's broken storage so the skip path can be
        // exercised locally in one command.
        if (process.env.E2E_BLOCK_STORAGE === '1') {
            await probePage.addInitScript(() => {
                for (const name of ['localStorage', 'sessionStorage']) {
                    Object.defineProperty(window, name, {
                        get() { throw new DOMException(`${name} is disabled`, 'SecurityError'); },
                    });
                }
            });
        }
        await probePage.goto(`http://127.0.0.1:${port}/`);
        const wrote = await probePage.evaluate(() => {
            try {
                localStorage.setItem('probe', '1');
                sessionStorage.setItem('probe', '1');
                return localStorage.getItem('probe') === '1' && sessionStorage.getItem('probe') === '1';
            } catch { return false; }
        });
        await probePage.reload();
        const survivedReload = await probePage.evaluate(() => {
            try { return localStorage.getItem('probe'); } catch { return null; }
        });
        await probeBrowser.close();
        server.close();

        if (wrote && survivedReload === '1') {
            console.log('  browser storage: usable');
            fs.rmSync(marker, { force: true });
        } else {
            const reason = `web storage did not survive a reload (write=${wrote}, afterReload=${String(survivedReload)})`;
            console.log(`  browser storage: UNUSABLE — ${reason}`);
            console.log('  → SSO-dependent suites will be skipped; see the E2E notes in the skill');
            fs.writeFileSync(marker, reason);
        }
    } catch (error) {
        // A probe error is NOT evidence that storage is unusable: leave the marker
        // absent so the suites run and fail loudly on their own.
        console.log(`  browser storage: probe could not run (${error}) — not marking the suites as skipped`);
    }

    // Clean masterless DB for fresh state
    execSync('rm -f data/masterless/masterless.sqlite');

    // Load the keys into the named volume the masterless container mounts.
    // A host bind mount would arrive empty on a docker-in-docker runner, where
    // the daemon resolves the source path in its own filesystem; `docker cp` is
    // client-side and therefore daemon-agnostic.
    const envSuffix = process.env.ENV || 'e2e';
    console.log('Loading keys into the e2e_keys volume...');
    // Build the proxy image explicitly: the compose services no longer depend on
    // the build-only MasterlessPrebuild service (depending on it made compose
    // create a container for it, which collided with the previous run).
    execSync(`docker compose -f docker-compose.e2e.yml --profile e2e --env-file test.env build MasterlessPrebuild`, { stdio: 'inherit' });
    execSync(`docker compose -f docker-compose.e2e.yml --profile e2e --env-file test.env up -d KeysVolume`, { stdio: 'inherit' });
    execSync(`docker cp data/keys/. e2e_keys-${envSuffix}:/keys/`, { stdio: 'inherit' });
    // Seed Vaultwarden's data folder so it signs with the key masterless trusts
    execSync(`docker cp data/vw/rsa_key.pem e2e_keys-${envSuffix}:/data/rsa_key.pem`, { stdio: 'inherit' });

    // Build KeycloakSetup container (Masterless image is pre-built by CI or `docker compose build`)
    console.log('Building KeycloakSetup container...');
    execSync(
        `docker compose -f docker-compose.e2e.yml --profile keycloak --env-file test.env build KeycloakSetup`,
        { env: { ...process.env, DOCKER_BUILDKIT: '1' }, stdio: 'inherit' }
    );

    console.log('=== Global Setup complete ===');
}

export default globalSetup;
