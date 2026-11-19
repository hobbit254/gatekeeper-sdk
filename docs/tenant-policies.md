# Tenant policies

Settings a tenant admin chooses for every app in the tenant, mostly on the dashboard's **Security policy** page or with `PUT /v1/admin/tenant/policy`. This page covers the ones that change what your apps see or must handle.

## Sign-in methods and sessions

- **Methods** (`allowed_methods`): passwords, one-time codes by email or SMS, passkeys, and Google, Apple or Microsoft. Codes by USSD dialing (`otp_ussd`) are available where your Gatekeeper operator has set them up.
- **Second factor:** off, optional or required for everyone.
- **Passwords:** minimum length, and whether known-breached passwords are refused.
- **Sessions:** how long until idle users, and all users, sign in again.
- **Lockout:** how many failed attempts lock an account, and for how long.

### Google, Apple and Microsoft

Each provider needs your own app registration with it, saved with `PUT /v1/admin/tenant/identity-providers/{provider}` or on the dashboard. For Microsoft:
1. **Register an app** in Microsoft Entra for "Accounts in any organizational directory and personal Microsoft accounts". Add the redirect URI `https://auth.<domain>/t/<tenant>/oauth2/callback/microsoft` and create a client secret.
2. **Work accounts:** in the app registration's token configuration, add the optional claim `xms_edov` to the ID token. Without it, Gatekeeper can't tell that the directory owns the email's domain, and work accounts are refused with "the provider has not verified this email address". Personal accounts work without it.
3. **Turn it on:** `PUT /v1/admin/tenant/identity-providers/microsoft {client_id, client_secret, enabled: true}`, then add `microsoft` to `allowed_methods`.

For native mobile sign-in with these providers, see [Signing users in](signing-in.md#headless-sign-in).

### Codes by dialing (USSD)

Where available, add `otp_ussd` to `allowed_methods`, and the hosted pages offer "Get a code by dialing".
- **Your own forms:** send `code_channel: "ussd"` on `POST /v1/auth/register`, or `channel: "ussd"` on `/v1/auth/identity/change` and headless `/code`. Tell the person to dial the code in `dial` from that phone, then post the code as usual.
- **Headless MFA:** `mfa_required` with `factor: "ussd"` and `dial` means the code is waiting; post it to `/mfa`.

## Terms and privacy policy

- **Publishing:** publish each new version on the Security policy page or with `POST /v1/admin/tenant/legal-documents`: its URL, a label, and the SHA-256 of the text. Keep old versions online, because users' records point to them.
- **Accepting:** users accept the current versions at their next sign-in, before your app gets its code. Headless apps see `terms_required`; show the links, then post `/v1/auth/headless/terms`.
- **Your own sign-up form:** if it shows the documents, send `accept_terms: true` to `POST /v1/auth/register`. Otherwise the first sign-in asks.

## Optional purposes

Purposes such as marketing email are defined on the same page.
- Users switch them on and off on the hosted account page (`/account/privacy`) or through `/v1/me/consents`.
- Listen for the `consent.granted` and `consent.withdrawn` webhooks (see [Webhooks](webhooks.md)) and stop as soon as a withdrawal arrives.
- Never send for a purpose the user hasn't granted.

## Partner apps and consent

- **Third-party by default:** clients created through the admin API or the dashboard are third-party unless they're marked first-party.
- **The consent screen:** the first time a third-party client asks for a user, the user sees its name and the scopes, and allows or denies. A denial reaches the client as `access_denied`; `prompt=none` without a grant gets `consent_required`.
- **Removing access:** users remove an app's access on `/account/privacy` or with `DELETE /v1/me/grants/{client_id}`. This also ends that client's refresh tokens for them.

## Your own sign-up form

Apps that call `POST /v1/auth/register` themselves (mobile apps, custom sign-up pages) must handle what the hosted page handles:
- **`400` with `type: /errors/captcha-required` and a `site_key`:** while sign-ups score as risky, or while the tenant's code sends are under attack. Show Cloudflare Turnstile with that site key, then resend the same request with `captcha_token`.
- **`403 signup-refused`:** show a plain "we can't create this account".
- **`signup.risky` webhook:** subscribe to it to hold or review new accounts that scored high but were let through, for example after a solved CAPTCHA.

## Risk and trusted networks

Sign-ins are scored from signals such as a new device, a new country, a hosting network or impossible travel. High scores ask for a second factor (`step_up`), and the highest are blocked. The `login.anomalous` signal reaches the audit log, and a new device sends the `login.new_device` webhook.
- **The Risk page:** adjust the thresholds and weights, list extra hosting or VPN networks by AS number, and exempt your own VPN or cloud desktops so staff on them aren't flagged. Exemptions apply to every user, so keep them to networks you run.
- **Border towns:** a never-seen country within 300 km of a user's usual places doesn't count as new.
- **Impersonation from a risky network** needs the admin's second factor within 5 minutes, and is refused outright in the block band.

## Passkey rules

- **Device-bound passkeys:** `PUT /v1/admin/tenant/policy {passkey: {require_device_bound: true}}` refuses passkeys that may sync (iCloud Keychain, Google Password Manager). Users whose only passkey is synced must sign in another way and add a security key or a platform-bound passkey.
- **Authenticator models** (`passkey.authenticators`): the Policy page picks models by name from the FIDO Metadata Service.
  - **Allow mode** accepts only passkeys whose model is proven by attestation and listed. Synced passkeys, and every passkey registered before the policy, are unattested, so they stop working. Check the passkey list on each user's page ("allowed") before turning it on.
  - **Deny mode** refuses listed models when attestation identifies them, and accepts the rest.
  - **Either mode** refuses models FIDO reports as revoked or compromised.

## Incidents and bulk responses

Tenant admins can act on many accounts at once from the dashboard's **Incidents** page or the admin API.
- **What your app sees:** affected users' sessions end (a refresh fails with `invalid_grant`, and the revocation feed refuses their access tokens), forced resets work as they do one at a time, and personal API keys stop. Subscribe to `response.finished` if you cache sessions or permissions yourself.
- **Client secrets:** `rotate_clients` cuts a client's secret with no overlap. Issue a new one with `POST /v1/admin/clients/{id}/rotate-secret` (shown once) and deploy it. Until then the client can't get tokens.
- **Evidence:** an incident's report is a signed ZIP in the compliance-pack format below.

## Compliance packs

Turn on `compliance.monthly_pack` in the policy. Each month's signed pack, with a PDF summary, is then stored on the 1st. List and download packs from `/v1/admin/compliance/packs` or the dashboard's **Compliance** page.

A pack holds:
- CSVs of the period's sign-ins, admin actions, deletions and exports;
- `summary.pdf`;
- `manifest.json`, listing every file with its SHA-256;
- `manifest.jws`, an ES256 signature over the manifest by a key in your tenant's JWKS (`typ: gk-compliance+jws`).

Verify the signature against `<issuer>/.well-known/jwks.json`, then each file's hash.
