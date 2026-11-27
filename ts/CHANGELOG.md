# Changelog

## Unreleased

- `verifyApproval()` and `spendApproval()`, and `approveWithPin()` on the shared device: a second person approves one action, spent once (ADR-0145).
- `createSharedDevice()`: claim a shared device and sign staff in with a PIN, with `renewPinSession` and `pinSignOut`; every request signed by the device's key (ADR-0144).
- `principal.canAmount()`, `limits` and `currency`: amount limits from the role map, with an organization's overrides (ADR-0143).

## 0.1.0

- First public release.
