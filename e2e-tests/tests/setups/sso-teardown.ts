import { test } from '@playwright/test';

const { execSync } = require('node:child_process');
const utils = require('../../global-utils');

utils.loadEnv();

test('Teardown', async () => {
    if( process.env.PW_KEEP_SERVICE_RUNNNING === "true" ) {
        console.log("Keep services running");
    } else {
        console.log("Stopping Keycloak");
        execSync(`docker compose -f docker-compose.e2e.yml --profile keycloak --env-file test.env stop Keycloak`, { stdio: 'pipe' });
        console.log("Stopping Vaultwarden");
        execSync(`docker compose -f docker-compose.e2e.yml --profile e2e --env-file test.env stop Vaultwarden`, { stdio: 'pipe' });
        console.log("Stopping Masterless");
        execSync(`docker compose -f docker-compose.e2e.yml --profile e2e --env-file test.env stop Masterless`, { stdio: 'pipe' });
    }
});
