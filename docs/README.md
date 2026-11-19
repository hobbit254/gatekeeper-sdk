# Integrating with Gatekeeper

Gatekeeper signs your users in, keeps their sessions, and tells your apps who they are and what they may do. Your apps send users to Gatekeeper's sign-in pages (or use your own screens), get standard OAuth 2.0 and OpenID Connect tokens back, and your APIs check those tokens with an SDK.

## Your tenant

Everything belongs to a **tenant**: your users, apps, roles and settings. Its **issuer** is the address your apps and SDKs are configured with:

```text
https://auth.<domain>/t/<tenant>
```

It's your dashboard's address without the trailing `/admin`, and each app's **Connect** panel on the dashboard's **Clients** page shows it. Standard discovery works from it: `<issuer>/.well-known/openid-configuration` and `<issuer>/.well-known/jwks.json`.

## The guide

| Page | Read it when you want to |
| --- | --- |
| [Getting started](getting-started.md) | register an app, install an SDK and sign a first user in |
| [Signing users in](signing-in.md) | sign in from a browser, a mobile app or your own screens; DPoP; push approval |
| [Protecting an API](protecting-an-api.md) | check tokens, permissions, recent second factors, API keys and plans |
| [Machine-to-machine](machine-to-machine.md) | call APIs from a service with no user |
| [Webhooks](webhooks.md) | react to account changes: the events, their payloads and the signature |
| [The admin API](admin-api.md) | manage users, roles and apps from code; the permissions manifest |
| [Enterprise SSO and SCIM](enterprise.md) | let a company's people sign in with their own identity provider |
| [Tenant policies](tenant-policies.md) | choose sign-in methods, terms and consent, passkey rules, compliance packs |

## SDKs

| SDK | Install |
| --- | --- |
| Go | `go get github.com/hobbit254/gatekeeper-sdk/go` |
| TypeScript (Node 22+ and browsers) | `npm install @hobbit254/gatekeeper-sdk` |
| PHP / Laravel (PHP 8.3+) | `composer require hobbit254/gatekeeper-laravel` |
| Dart (Dart 3.5+) | `dart pub add gatekeeper_sdk` |
| Flutter | `flutter pub add gatekeeper_flutter` |

The Go, TypeScript and PHP SDKs protect APIs. The TypeScript, Dart and Flutter SDKs sign users in. Without an SDK, any OpenID Connect library works for signing in, and any JOSE library can check tokens against the JWKS.

## Conventions

- **Errors** are RFC 9457 problem documents: `type` (for example `/errors/captcha-required`), `title`, `detail`, and sometimes extra fields named on the page that uses them.
- **Times** are RFC 3339 in UTC; **ids** are UUIDs unless a page says otherwise.
- The samples marked as whole files are compiled against the SDKs whenever they change, so they stay correct. Shorter fragments show one call in context.
