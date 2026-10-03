# Development Guide

## Requirements

- **Rust 1.88+** (uses edition 2021, but dependencies require 1.88+ features)
- **SQLite** (bundled via `rusqlite`, no system install needed)

## Building

```bash
cargo build --release
```

The binary is at `./target/release/vaultwarden-masterless`.

## Running Tests

```bash
# All tests (unit + integration)
cargo test

# With output visible
cargo test -- --nocapture

# Only unit tests
cargo test --lib

# Only integration tests
cargo test --test integration_tests
```

The test suite includes:
- **Unit tests** — crypto seal/unseal, RSA wrap/unwrap, DB CRUD, proxy response patching, JWT auth, wrapping secret rotation (multi-user, double rotation, timestamp recording, post-rotation enrollment)
- **Integration tests** — full HTTP request/response flow for all `/user-keys` endpoints, auth rejection, user isolation

## Project Structure

```
src/
├── main.rs       # Entry point, server setup, background rotation task
├── config.rs     # Environment variable loading
├── api.rs        # /alive and /user-keys HTTP handlers
├── auth.rs       # JWT validation against Vaultwarden's RSA public key
├── crypto.rs     # AES-256-GCM + RSA key management, wrapping secret rotation
├── db.rs         # SQLite operations, atomic rotation transaction
├── errors.rs     # AppError / AppResult types
├── models.rs     # Data structures (StoredKeyEntry, payloads, AuthenticatedUser)
└── proxy.rs      # Reverse proxy + API response patching
tests/
└── integration_tests.rs   # End-to-end HTTP tests with in-memory DB
```

## Local Test Environment (Docker/Podman)

A full stack is provided in `deploy/` with Vaultwarden, vaultwarden-masterless, and Pocket-ID (OIDC provider).

### Setup

```bash
cd deploy
cp .env.example .env
chmod +x setup.sh
./setup.sh                    # Generates keys, bootstraps Vaultwarden
podman-compose up --build     # or: docker compose up --build
```

### Services

| Service | URL | Purpose |
|---|---|---|
| **Vaultwarden** (via masterless proxy) | http://localhost:8443 | Where clients connect |
| **Pocket-ID** (OIDC admin) | http://localhost:3100 | Create OIDC clients, manage users |

### First-time setup after starting the stack

1. Open **Pocket-ID** at http://localhost:3100, create an admin account
2. Create an OIDC client:
   - **Client ID**: `vaultwarden`
   - **Redirect URI**: `http://localhost:8443/identity/connect/oidc-signin`
   - Copy the client secret → update `OIDC_CLIENT_SECRET` in `deploy/.env`
3. Restart: `podman-compose down && podman-compose up --build`
4. Open http://localhost:8443 → Create account → Try SSO login

## Environment Variables for Development

Copy `.env.template` to `.env` and adjust:

```bash
cp .env.template .env
```

For local development without a real Vaultwarden, you can set `PROXY_ENABLED=false` to run only the `/user-keys` API endpoints (useful for unit-testing the key storage independently).

## Key Generation

```bash
chmod +x scripts/generate-keys.sh
./scripts/generate-keys.sh ./data
```

Creates `rsa_private.pem` and `rsa_public.pem` in the specified directory.

## Code Style

- No `KC_` prefixes — all legacy naming has been removed
- Error types: `AppError` / `AppResult`
- Crypto naming: `seal_vault_key` / `unseal_vault_key`, `wrap_with_rsa` / `unwrap_with_rsa`
- All names are clean-room, license-proof — no overlap with Bitwarden proprietary code
