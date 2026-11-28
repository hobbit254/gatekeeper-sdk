# Changelog

## Unreleased

- `supportSession()`, `mountSupportBanner()` and `client.supportSession()` in the browser entry: the support-session banner for product UIs (ADR-0159).
- `gk.fastify()`, `recordFastifyRoutes(app)` and `assertEveryFastifyRouteGuarded(app)`: Fastify hooks carrying the guard marks, and the route test for Fastify (ADR-0153).
- `publicRoute()`, `signedIn()` and `assertEveryRouteGuarded(app)`: a test that fails when an Express route has no Gatekeeper guard; `requirePermission` and `requirePermissionOn` carry their mark (ADR-0149).
- `principal.actorMode`: support sessions are `read` or `write`; in read mode `permissions` keeps only read permissions (ADR-0146).
- `verifyApproval()` and `spendApproval()`, and `approveWithPin()` on the shared device: a second person approves one action, spent once (ADR-0145).
- `createSharedDevice()`: claim a shared device and sign staff in with a PIN, with `renewPinSession` and `pinSignOut`; every request signed by the device's key (ADR-0144).
- `principal.canAmount()`, `limits` and `currency`: amount limits from the role map, with an organization's overrides (ADR-0143).

## 0.1.0

- First public release.
