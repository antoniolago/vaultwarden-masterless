#!/usr/bin/env bash
# Run the browserless SSO smoke test against a live instance.
#
# usage: run-against.sh <demo|prod>
#
# `demo` uses the throwaway demo user: its password is read from the cluster secret at
# runtime and never printed. `prod` authenticates through a real IdP with real accounts, so
# it only checks what is reachable without credentials (health + the compatibility report).
set -uo pipefail

TARGET="${1:?usage: run-against.sh <demo|prod>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K=("kubectl" "--context" "${KUBE_CONTEXT:-admin@ton-cluster}")

case "$TARGET" in
  demo)
    export SMOKE_BASE="https://vaultwarden-masterless-demo.lag0.com.br"
    export SMOKE_KC="https://vaultwarden-masterless-demo-kc.lag0.com.br"
    export SMOKE_REALM="demo"
    export SMOKE_USER="demo"
    NS=vaultwarden-masterless-demo
    SECRET=vaultwarden-masterless-demo-keycloak-secrets
    KEY=DEMO_USER_PASSWORD
    ;;
  prod)
    BASE="https://vw2.lag0.com.br"
    echo "smoke: prod has no disposable SSO user — checking reachability only"
    rc=0
    for path in /alive /version; do
      status="$(curl -s -o /dev/null -w '%{http_code}' -m 20 "$BASE$path")"
      printf '  %-9s %s\n' "$path" "$status"
      [ "$status" = "200" ] || rc=1
    done
    curl -s -m 20 "$BASE/version" | python3 -c '
import sys, json
d = json.load(sys.stdin)
c = d["compatibility"]
print("  build {} | tested {} | detected {} | {} | alive={}".format(
    d["build"], c["vaultwarden"], c.get("vaultwarden_detected"), c.get("status"), d["alive"]))
sys.exit(0 if c.get("status") == "match" else 1)
' || rc=1
    exit "$rc"
    ;;
  *)
    echo "unknown target: $TARGET" >&2
    exit 2
    ;;
esac

export SMOKE_ORG="${SMOKE_ORG:-00000000-01DC-01DC-01DC-000000000000}"
SMOKE_PASS="$("${K[@]}" get secret -n "$NS" "$SECRET" -o jsonpath="{.data.$KEY}" 2>/dev/null | base64 -d)"
if [ -z "$SMOKE_PASS" ]; then
  echo "smoke: could not read $KEY from $NS/$SECRET" >&2
  exit 2
fi
export SMOKE_PASS

echo "smoke: target=$TARGET base=$SMOKE_BASE user=$SMOKE_USER"
node "$HERE/sso-smoke.mjs"
