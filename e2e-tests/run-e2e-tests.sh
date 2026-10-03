#!/bin/bash
###############################################################################
# run-e2e-tests.sh — Single command to run the complete E2E test suite
#
# Follows Vaultwarden's own Playwright testing pattern:
#   - network_mode: "host" (all services on localhost)
#   - Keycloak + kcadm.sh for automated OIDC setup
#   - Pre-generated RSA keys (no external setup.sh dependency)
#   - Playwright manages container lifecycle
#
# Usage:
#   cd e2e-tests
#   ./run-e2e-tests.sh
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Parse arguments
KEEP=""
EXTRA_ARGS=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --keep)
            KEEP="PW_KEEP_SERVICE_RUNNNING=true"
            shift
            ;;
        --headed|--debug|--ui)
            EXTRA_ARGS="$EXTRA_ARGS $1"
            shift
            ;;
        --project)
            EXTRA_ARGS="$EXTRA_ARGS --project $2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --keep      Keep all services running after tests"
            echo "  --headed    Run tests with visible browser"
            echo "  --debug     Run tests in Playwright debug mode"
            echo "  --ui        Open Playwright UI mode"
            echo "  --project X Run only Playwright project X"
            echo ""
            echo "Ports used (must be free):"
            echo "  8000  Vaultwarden"
            echo "  8080  Keycloak"
            echo "  8443  Masterless proxy"
            exit 0
            ;;
        *)
            EXTRA_ARGS="$EXTRA_ARGS $1"
            shift
            ;;
    esac
done

echo "======================================================================"
echo "  Vaultwarden Masterless — E2E Test Suite"
echo "======================================================================"
echo ""

# ============================================================================
# Step 1: Check prerequisites
# ============================================================================
echo "=== Step 1: Checking prerequisites ==="

if ! command -v docker &>/dev/null; then
    echo "  ERROR: docker not found"
    exit 1
fi
echo "  docker: $(docker --version | head -1)"

if ! docker compose version &>/dev/null 2>&1; then
    echo "  ERROR: docker compose not found"
    exit 1
fi
echo "  docker compose: $(docker compose version --short 2>/dev/null || echo 'ok')"

if ! command -v node &>/dev/null; then
    echo "  ERROR: node not found (need Node.js 18+)"
    exit 1
fi
echo "  node: $(node --version)"

if ! command -v bun &>/dev/null; then
    echo "  ERROR: bun not found (install: curl -fsSL https://bun.sh/install | bash)"
    exit 1
fi
echo "  bun: $(bun --version)"

if ! command -v openssl &>/dev/null; then
    echo "  ERROR: openssl not found"
    exit 1
fi
echo "  openssl: ok"

# ============================================================================
# Step 2: Install dependencies
# ============================================================================
echo ""
echo "=== Step 2: Installing dependencies ==="
if [ ! -d "node_modules" ] || [ "package.json" -nt "node_modules" ]; then
    bun install
else
    echo "  Dependencies up to date"
fi

# Install Playwright browser (firefox only, matching VW's tests)
bunx playwright install firefox 2>/dev/null || bunx playwright install

# ============================================================================
# Step 3: Build Masterless container image
# ============================================================================
echo ""
echo "=== Step 3: Building Masterless container ==="
docker compose -f docker-compose.e2e.yml --profile e2e --env-file test.env build MasterlessPrebuild

# ============================================================================
# Step 4: Run Playwright (handles everything else)
# ============================================================================
echo ""
echo "=== Step 4: Running tests ==="
echo ""
echo "Playwright will:"
echo "  1. Generate RSA keys (global-setup)"
echo "  2. Build KeycloakSetup container"
echo "  3. Start Keycloak, configure OIDC client (sso-setup)"
echo "  4. Start Vaultwarden + Masterless per test"
echo "  5. Run SSO flow + proxy tests"
echo "  6. Tear down services (sso-teardown)"
echo ""

set +e
env $KEEP bunx playwright test $EXTRA_ARGS
TEST_EXIT_CODE=$?
set -e

# ============================================================================
# Results
# ============================================================================
echo ""
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "=== ALL TESTS PASSED ==="
else
    echo "=== SOME TESTS FAILED ==="
    echo ""
    echo "View report:  bunx playwright show-report"
    echo "View traces:  bunx playwright show-trace test-results/*/trace.zip"
fi

echo ""
echo "Artifacts: playwright-report/  test-results/"

exit $TEST_EXIT_CODE
