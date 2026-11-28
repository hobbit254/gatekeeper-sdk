# Signing users in

There are two ways in:
- **Redirect.** Your app sends users to Gatekeeper's hosted sign-in pages and gets them back with an authorization code (OAuth 2.0 with PKCE). This is the default, and the only way for partners' apps.
- **Headless.** Your own first-party app shows its own screens and calls Gatekeeper's JSON API.

Both end with the same tokens: an access token for your APIs, an ID token describing the user, and with `offline_access` a refresh token.

## Browser apps

```ts
import { createBrowserClient } from "@hobbit254/gatekeeper-sdk/browser";
const auth = createBrowserClient({ issuer, clientId: "shop-web", redirectUri: `${location.origin}/callback`, scope: "openid profile offline_access" });
await auth.loginWithRedirect();                       // on "Sign in"
const user = await auth.handleRedirectCallback();     // on /callback: state, code exchange, ID token (nonce) checked
const token = await auth.getAccessToken();            // refreshed 30 s before expiry, one refresh at a time
await auth.logout({ returnTo: location.origin });
```

- **Token storage:** tokens live in memory only. After a reload, call `loginWithRedirect({ prompt: "none" })` to get them back silently while the session lives.
- **Errors:** an `AuthorizeError` carries `access_denied`, `consent_required` or `interaction_required`.
- **An organization's sign-in:** `loginWithRedirect({ organization: "acme" })` sends members of an organization with SSO to their identity provider (see [Enterprise SSO and SCIM](enterprise.md)).
- **Other parameters:** `prompt`, `uiLocales`, and `extra` for `acr_values`, `max_age` and `login_hint`.

## Mobile apps

Flutter apps use `gatekeeper_flutter` (see [Getting started](getting-started.md#2-sign-users-in)):
- **`GatekeeperAuth`:** `restore()`, `signIn()`, `stepUp(maxAge)` and `signOut(postLogoutRedirect: …)` run through the system browser.
- **Auth state:** `AuthState` is `SignedOut`, `SignedIn` or `StepUpNeeded`, and `GatekeeperScope` puts it in reach of your widgets.
- **`guard()`:** wraps an API call and turns a step-up challenge into `StepUpNeeded`.
- **The redirect:** register your app's custom-scheme redirect, and its post-logout redirect, on the client.

Other Dart apps use `gatekeeper_sdk` directly:
- `authorizationRequest` builds the PKCE request (with `acr_values`, `max_age` and `ui_locales`), and `handleRedirect` finishes it.
- `refresh` is single-flight, so concurrent calls share one refresh.
- `authorizedClient()` is an HTTP client that adds the token and throws `StepUpRequired` on a step-up challenge.
- `logoutUrl` ends the session.
- Your app opens the browser (for example with `flutter_web_auth_2`) and stores tokens (for example with `flutter_secure_storage`) behind the `TokenStore` interface.

## Headless sign-in

A first-party app can sign users in with its own screens instead of the hosted pages:
1. A tenant admin turns on **headless login** for the app's client: on the dashboard's Clients page, or `PATCH /v1/admin/clients/{id}` with `headless_login: true`.
2. The app makes its PKCE pair as for `/oauth2/authorize`, then calls `POST /v1/auth/headless/start` with those parameters.
3. It signs the user in with one of the `methods` the answer lists:
   - **Password:** post it to `/password`.
   - **Code:** send one with `/code`, then post it to `/code/verify`.
   - **Passkey:** call `/passkey/begin`, pass `options` to the platform passkey API, and post the result to `/passkey`.
   - **Google, Apple or Microsoft:** sign in with the provider's native SDK, setting its nonce to `provider_nonce`, and post the ID token to `/social`.
4. On `mfa_required` it asks for the second factor and posts it to `/mfa`. When the answer says `passkey: true`, it can instead call `/mfa/passkey/begin` and post the assertion to `/mfa`.
5. On `terms_required` it shows the listed documents and posts `/terms` (see [Tenant policies](tenant-policies.md#terms-and-privacy-policy)).
6. On `complete` it exchanges `code` at `/oauth2/token` with the verifier. Everything after that (refresh, DPoP, logout) is as for the redirect.

The TypeScript SDK runs those steps for you:

```ts compile
import { HeadlessProblem, startHeadless } from "@hobbit254/gatekeeper-sdk/headless";

export async function signIn(email: string, password: string, askForCode: () => Promise<string>) {
  const h = await startHeadless({
    issuer: "https://auth.example.com/t/acme",
    clientId: "shop-app",
    redirectUri: "com.example.shop:/signed-in",
    scope: "openid profile offline_access",
  });
  try {
    let r = await h.password(email, password);
    if (r.status === "mfa_required") r = await h.mfa(await askForCode());
    if (r.status === "terms_required") r = await h.acceptTerms(); // after showing r.documents
    if (r.status !== "complete") throw new Error(`sign-in stopped at ${r.status}`);
    return r.tokens;
  } catch (e) {
    if (e instanceof HeadlessProblem && e.type === "locked") {
      throw new Error(`locked; try again in ${e.retryAfter ?? 60} s`);
    }
    throw e;
  }
}
```

In Dart, call `await gatekeeper.startHeadless()`. Steps return `Complete`, `MfaRequired`, `TermsRequired`, `LinkRequired` or `CodeSent`, and problems throw `HeadlessProblem`. `Complete` has already saved the tokens in the `TokenStore`, so `accessToken()` and `refresh()` work as after a browser sign-in.

**Problems** carry the hosted page's meaning:
- **`captcha-required`:** show Cloudflare Turnstile with `site_key` and resend with `captcha_token`.
- **`locked`:** honour `Retry-After`.
- **`mfa-enrollment-required`:** send the user to the hosted pages, which enrol a second factor.
- **`link-required`:** the email already has an account. Ask the user to sign in to it with another method in the same flow, and the provider is connected once they do.

**Native provider setup:**
- **Client ids:** add your app's provider client ids to the tenant's provider settings as `native_client_ids`: the Android and iOS OAuth client ids for Google, the bundle id for Apple, the app registration id for Microsoft. A token issued to anything else is refused.
- **The nonce:** the provider's SDK must put `provider_nonce` in the token's `nonce`. Google's Credential Manager and Sign in with Apple let you set it. MSAL picks its own nonce, so Microsoft apps use an OIDC library that lets them set it, such as AppAuth.
- **Passkeys in native apps:** ask your Gatekeeper operator to register your app (iOS: Team ID and bundle id; Android: package name and signing-certificate SHA-256). Gatekeeper then serves `/.well-known/apple-app-site-association` and `/.well-known/assetlinks.json`, and your app declares the relying-party domain as `webcredentials:` (iOS) or through its asset statements (Android).

**Never** turn headless login on for a partner's app: it would see your users' passwords.

## Step-up: asking for a recent second factor

Some actions need a second factor from the last few minutes. An API asks for one by answering `401` with an RFC 9470 challenge (see [Protecting an API](protecting-an-api.md#step-up)):

```text
WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age="300", acr_values="mfa"
```

Run authorize again with `max_age=300&acr_values=mfa` (browser: `loginWithRedirect({ extra: { max_age: "300", acr_values: "mfa" } })`; Flutter: `auth.stepUp(300)`), then retry the call.

Gatekeeper's own account calls use the same challenge. Adding or removing a passkey (`/v1/auth/webauthn/register/*`, `DELETE /v1/me/passkeys/{id}`) and connecting or disconnecting a provider (`POST`/`DELETE /v1/me/identities`) answer `401` with `max_age="300"` when the sign-in is older than 5 minutes. Re-run authorize with `max_age=300`, without `acr_values`, and retry.

## DPoP: tokens bound to a device

A stolen bearer token works anywhere. A client flagged `dpop_bound_access_tokens` instead gets tokens bound to a key on the device (RFC 9449), and every use needs a fresh proof signed with that key. Use it for mobile apps, whose refresh tokens last 90 days on devices that get lost.

- **Flutter apps:** pass a `DpopSigner` backed by the iOS Secure Enclave or Android Keystore to `Gatekeeper(..., dpop: signer)`. The SDK adds a proof to every token request and API call and sends `Authorization: DPoP <token>`.
- **Browser apps:** `createBrowserClient({..., dpop: true})` makes a non-extractable P-256 key in IndexedDB (`gatekeeper-dpop`) and binds sign-in and refreshes to it. Call your APIs with `auth.fetchWithDPoP(url, init)`. Logout deletes the key.
- **Code binding:** the Dart and TypeScript SDKs send `dpop_jkt` at authorize and headless start, so a stolen code is useless without the key. A public client flagged for DPoP must send it.
- **Nonces:** a tenant can require server nonces (`PUT /v1/admin/tenant/policy {dpop_nonce: true}`). Every SDK that makes proofs remembers the latest `DPoP-Nonce` and retries once on `use_dpop_nonce`. Turn it on once your apps run current SDKs.
- **Clocks:** keep device clocks within 60 seconds of real time; proofs outside that window are refused.

APIs need no change: the SDK middleware checks the proof when a token is bound (see [Protecting an API](protecting-an-api.md#dpop-bound-tokens)).

## Push approval on the user's phone

Users can approve a sign-in on their phone by tapping the number the sign-in page shows. Gatekeeper never contacts FCM or APNs; your backend wakes your app.
1. **Turn it on:** `PUT /v1/admin/tenant/policy` with `mfa_push: {enabled: true}`, or the checkbox on the dashboard's Security policy page.
2. **Enrol in the app:** create a P-256 key in the Keychain or Android Keystore, wrap it in a signer (64-byte r‖s signatures), and call `PushApprover(...).enrol(accessToken, "Pixel 9")` (Dart) or `createPushApprover({issuer, signer}).enrol(token, name)` (TypeScript) right after the user signs in. Store the returned approver id with the key.
3. **Relay the push:** subscribe a webhook to `mfa.push_requested`, verify it, read the user id from it (`event.PushRequested()` in Go, `Webhook::pushRequested()` in PHP; see [Webhooks](webhooks.md)) and send a silent push to that user's devices.
4. **Answer in the app:** on the push, or whenever the app opens, call `pending()`. Show the client, device, country and the three numbers, then `approve(id, number)` with the one the user taps, or `deny(id, reported: true)` for "that wasn't me".

- The right number is never sent to the phone, and a wrong pick denies the push, so blind taps don't sign anyone in.
- Without a relay, users can still open the app and approve. A push lasts 2 minutes.
- Headless sign-in doesn't offer push yet.

## Shared devices: signing staff in with a PIN

Tills and terminals that staff share can sign people in with a 4–6 digit PIN instead of a full sign-in. A PIN works only on a device the organization registered, which signs every request with its own key.
1. **Turn it on:** `PUT /v1/admin/tenant/policy` with `pin: {sign_in: true, session_max_sec: 28800}` (15 minutes to 12 hours; 8 hours by default).
2. **Mark what a till may do:** give `pin_sign_in: true` to the roles staff may use there, in the manifest or on an organization's own role (see [Organization roles](admin-api.md#organization-roles)). A PIN session's token carries only those roles, and checks for it weigh only them. A role with a sensitive permission, a `tenant_only` group, `*:*` or a limited permission without `approves` can't be marked.
3. **Register the device:** an org admin registers it on the dashboard's Devices page and gets a one-time code, valid 10 minutes.
4. **Claim it in the app:** create a P-256 key that can't be exported (WebCrypto, Keychain or Keystore) and redeem the code. With the TypeScript SDK:

```ts
import { createSharedDevice, cryptoKeySigner, generatePushKey } from "@hobbit254/gatekeeper-sdk";

const keys = await generatePushKey(); // keep it, with the device id
const till = createSharedDevice({ issuer: "https://auth.example.com/t/acme", signer: cryptoKeySigner(keys) });
await till.claim("K7QM-2XRP");
const session = await till.pinSignIn(userId, pin); // session.access_token, session.sid
```

5. **People set their PIN** on their account's security page, or with `PUT /v1/me/pin {pin}` after a sign-in in the last 5 minutes.
6. **Keep the session alive:** a PIN access token lasts 15 minutes and there's no refresh token. Call `renewPinSession(sid)` while someone is using the till. After 15 idle minutes, or at `session_max_sec`, the session ends and they type their PIN again. `pinSignOut(sid)` ends it at once.

- **Errors:** every refusal is a `DeviceError`. `401` never says whether the device, the signature or the PIN was wrong. `423` is `pin-locked` (5 wrong in a row, for 15 minutes; `retryAfter` in seconds) or `pin-held` (10 wrong; an org admin must unlock it, and the user is emailed).
- **What a PIN can't do:** `amr` is `pin`, `hwk`, never `mfa`, so step-up always refuses it. Account changes from a PIN session are refused (`403`).
- **Revoking:** revoking a device, or registering it again, signs everyone on it out at once.
- **Dart and Flutter:** `SharedDevice` in `gatekeeper_sdk` has the same calls: `claim`, `pinSignIn`, `renewPinSession`, `pinSignOut` and `approveWithPin`. Give it a signer backed by the platform keystore (Android Keystore, Secure Enclave), as for push approvers. Refusals are a `DeviceException` with `status`, `code` and `retryAfter`.
- **The hosted till:** for a web till, embed Gatekeeper's page instead of building the screens: `<iframe src="https://auth.example.com/t/acme/till?client_id=pos&origin=https://pos.example.com">`. It claims the device with a key the page makes and can't export, shows who has a PIN, takes the PIN, and posts `{type: "gatekeeper:pin-session", access_token, sid, expires_in, user_id}` to your page. Post `{type: "gatekeeper:approve", approval_id}` to it for a manager's approval; it shows the amber prompt and answers `{type: "gatekeeper:approval", approval_token}`, or `gatekeeper:approval-cancelled`. Only your client's redirect-URI origins can frame it or hear from it.
- **Not yet:** signing in while offline.

## Signing out

- **Browser:** `auth.logout({ returnTo })` ends the Gatekeeper session and returns to `returnTo`, which must be one of the client's post-logout redirect URIs.
- **Any app:** send the user to `<issuer>/oauth2/logout` with `id_token_hint` and `post_logout_redirect_uri`.
- **What else ends:** for a user who came through their company's SSO, signing out also signs them out at the identity provider (see [Enterprise SSO and SCIM](enterprise.md#day-to-day)).

Access tokens stay valid until they expire. Your APIs reject them sooner if they check the denylist or the revocation feed (see [Protecting an API](protecting-an-api.md#ended-sessions)).
