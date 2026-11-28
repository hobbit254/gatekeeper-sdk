# Changelog

## Unreleased

- `gk.public` and `gk.signed_in` middleware and `GatekeeperAssert::everyRouteGuarded()`: a test that fails when a route has no Gatekeeper guard (ADR-0149).
- `Principal::$actorMode`: support sessions are `read` or `write`; in read mode `permissions` keeps only read permissions (ADR-0146).
- `verifyApproval()` and `spendApproval()`: a second person approves one action, spent once (ADR-0145).
- `Principal::canAmount()`, `limits` and `currency`: amount limits from the role map, with an organization's overrides (ADR-0143).
- Security: `web-token/jwt-library` 4.2.4 → 4.2.8, which fixes 11 advisories published on 2026-11-08 (JWE key-size checks, RSA-OAEP, ECDH-ES and parsing costs). It's used only to decrypt encrypted ID tokens and userinfo.

## 0.1.0

- First public release.
