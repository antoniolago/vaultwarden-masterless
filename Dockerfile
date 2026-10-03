# Multi-stage build for vaultwarden-masterless
#
# Stage 1 builds only Cargo dependencies using a dummy main.rs.
# We strip the dummy binary but keep compiled dependency artifacts
# so stage 2 only recompiles the application itself.
#
# BuildKit cache mounts (--mount=type=cache) persist cargo registry
# and target artifacts across builds. The binary must be copied out
# of the mount before the RUN step ends, otherwise it's unreachable
# by later COPY --from= commands.

# --- Dependencies (cached layer) ---
FROM rust:1.88-bookworm AS deps

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    rm -rf src target/release/deps/vaultwarden_masterless* target/release/vaultwarden-masterless*

# --- Build ---
FROM deps AS builder

COPY src/ src/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp /app/target/release/vaultwarden-masterless /app/vaultwarden-masterless

# --- Runtime ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates openssl libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/vaultwarden-masterless /usr/local/bin/

RUN groupadd -r masterless && useradd -r -g masterless -u 1000 masterless \
    && mkdir -p /data \
    && chown masterless:masterless /data
VOLUME /data

ENV HOST=0.0.0.0
ENV PORT=8484
ENV DATABASE_PATH=/data/masterless.sqlite
ENV RSA_PRIVATE_KEY_FILE=/data/rsa_private.pem
ENV RSA_PUBLIC_KEY_FILE=/data/rsa_public.pem
ENV VAULTWARDEN_RSA_PUBLIC_KEY_FILE=/data/vw_rsa_key.pub.pem
ENV BUILD_SHA=dev
ENV COMPAT_VW_VERSION=1.37.3
ENV COMPAT_KC_VERSION=26.3.4
ENV COMPAT_CLIENTS={"web":"2024.x - 2026.x","desktop":"2024.x - 2026.x","browser_extension":"2024.x - 2026.x","mobile":"untested"}
ENV COMPAT_LAST_TESTED=2026-09-18

EXPOSE 8484

USER masterless
ENTRYPOINT ["vaultwarden-masterless"]
