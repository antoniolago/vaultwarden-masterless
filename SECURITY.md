# Security Policy

## Project status: experimental

vaultwarden-masterless is **experimental**. It is published so it can be evaluated and
tested against throwaway instances — it has **not** been audited, and it is not
recommended for a production vault holding data you cannot afford to lose.

## Threat model — read this before deploying

This project **removes the master password**, and that changes the security model on
purpose:

- The user's vault key is stored **server-side**, encrypted at rest in the proxy's SQLite
  database under its own RSA key pair. A master password normally means the server never
  holds material that can decrypt the vault; here it does.
- **Losing that data is unrecoverable.** If the proxy's data volume (`masterless.sqlite`)
  or its RSA keys (`rsa_private.pem`) are lost, the stored vault keys are gone and there is
  no master-password fallback. Back up both, together, or do not use this.
- An attacker who has both the database and the RSA private key can decrypt the stored
  vault keys. Protect the volume and the secret as you would the vault itself.
- The proxy **rewrites Vaultwarden API responses** and **strips the
  `Content-Security-Policy` header** on the pages it serves (the web vault needs inline
  scripts). It also terminates or forwards TLS depending on your deployment. Review
  `src/proxy.rs` before trusting it in front of anything that matters.
- SSO is the only authentication path and is delegated to your OIDC provider. A
  misconfigured provider (for example one that lets anyone obtain a token for an existing
  user) becomes a vault compromise. Configure the provider strictly.

These are design consequences, not bugs — but they are the reason this is experimental.

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than opening a public issue:

- Preferred: GitHub private vulnerability reporting —
  <https://github.com/antoniolago/vaultwarden-masterless/security/advisories/new>
- Alternative: open an issue asking for a private contact channel, **without** the details.

Please include the version (`GET /version`), the Vaultwarden and OIDC-provider versions,
and a minimal reproduction.

There is no bug bounty. This is a spare-time project: expect an acknowledgement when it is
possible, and a fix when one is warranted.

## Supported versions

Only the current `main` and the version combination listed as tested in
[COMPATIBILITY.md](./COMPATIBILITY.md) are supported. Older releases are not maintained.
