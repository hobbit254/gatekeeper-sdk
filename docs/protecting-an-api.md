# Protecting an API

Your API receives `Authorization: Bearer <access token>` (or `DPoP <token>` with a proof). The Go, TypeScript and PHP SDKs check it and hand you a **principal**: who the user is, their roles and permissions, how they signed in, and when.

## Verifying tokens

Access tokens are JWTs signed with the tenant's keys (ES256), published at `<issuer>/.well-known/jwks.json`. The SDKs check, on every request:
- the signature, against the key named by `kid` (the key set is cached and refetched on an unknown `kid`);
- `iss` is your issuer, and `aud` contains your API's audience;
- `exp`, with up to 60 seconds of clock skew;
- `typ` is `at+jwt`, so an ID token can't be passed off as an access token;
- the session isn't ended, when you give the SDK a denylist or the revocation feed (see [Ended sessions](#ended-sessions)).

A failure answers `401`. Configure the SDK with your issuer, your API's audience, and the client id and secret whose role map turns roles into permissions:

| | Go | TypeScript | Laravel |
| --- | --- | --- | --- |
| Configure | `gk.New(gk.Config{Issuer, Audience, ClientID, ClientSecret})` | `createGatekeeper({issuer, audience, clientId, clientSecret})` | `GATEKEEPER_*` in `.env` (`config/gatekeeper.php`) |
| Check requests | `auth.Middleware()` | `gk.express()` | middleware `gatekeeper` |
| The principal | `gk.FromContext(ctx)` | `getPrincipal(req)` | `GatekeeperAuthenticate::principal($request)` |
| Check a token yourself | `auth.Verify(ctx, raw)` | `gk.verify(raw)` | `app(Gatekeeper::class)->verify($raw)` |

The principal carries `Sub` (the user id), `TenantID`, `OrgID` (the organization the user signed in to, if any), `ClientID`, `Roles`, `Permissions`, `Scopes`, `AMR` (how they signed in: `pwd`, `otp`, `mfa`, `hwk`, `fed`, …), `AuthTime` and `SID` (the session). Names are the same in each SDK, in its own casing.

## Permissions and roles

Permissions are strings such as `report:read`. Your app declares them, and the roles that hold them, in a permissions manifest (see [The admin API](admin-api.md#the-permissions-manifest)). Admins grant roles to users, tenant-wide or within an organization.

A token carries the user's roles and a role-map version (`rv`). The SDK fetches your client's role map once, turns roles into permissions locally, and refetches when a token's `rv` is newer. So a role change applies at the user's next token, without a call per request.

An organization can also define its own roles ([Organization roles](admin-api.md#organization-roles)). A token in that organization carries them as `org/<name>`, with the organization's role-map version, `orv`. When a token holds one, the SDK fetches that organization's map (`role-map?org=<slug>`) and caches it until a token carries a newer `rv` or `orv`. An `org/` role never counts outside its organization.

| | Go | TypeScript | Laravel |
| --- | --- | --- | --- |
| Guard a route | `gk.RequirePermission("report:read")` | `requirePermission("report:read")` | `gk.can:report:read` |
| Check in code | `p.Can("report:read")` | `p.permissions.includes(...)` | `$principal->can('report:read')` |

Wildcards work in roles: `report:*` holds every `report:` permission.

## Check every route is guarded

The commonest authorization bug is a route nobody guarded. Mark every route, and add a test that fails when one isn't:
- **Guarded:** `RequirePermission`, `RequirePermissionOn` or `RequireStepUp`.
- **Deliberately open:** `Public()`.
- **Any signed-in user:** `SignedIn()`, which also answers `401` without a principal.

The test reads the marks and never calls a route. It lists every unmarked route and, given your manifest's keys, the permissions no route guards (some are checked in code; `FailOnUnused` makes that a failure too).

```go
func TestEveryRouteGuarded(t *testing.T) {
	mux := gktest.NewMux() // records what you register; an http.ServeMux can't list its routes
	register(mux)
	gktest.AssertEveryRouteGuarded(t, mux.Routes(), gktest.Options{Permissions: []string{"report:read"}})
}
```

| | Go | TypeScript (Express 4 and 5) | Laravel |
| --- | --- | --- | --- |
| Open on purpose | `gk.Public()` | `publicRoute()` | middleware `gk.public` |
| Any signed-in user | `gk.SignedIn()` | `signedIn()` | middleware `gk.signed_in` |
| The test | `gktest.AssertEveryRouteGuarded(t, routes, opts)` | `assertEveryRouteGuarded(app, {permissions})` | `GatekeeperAssert::everyRouteGuarded(Route::getRoutes())` |
| Routes from | `gktest.NewMux()`, or a `[]gktest.Route` (chi's `chi.Walk` gives the fields) | the app's router, nested routers included | Laravel's route list |

In Go, put the Gatekeeper guards outside your other middleware, or have that middleware implement `Unwrap() http.Handler`, so the test can see through it.

## Amount limits

Some actions are fine up to an amount: a cashier refunds up to KES 2,000, and above that a manager must approve. Mark the permission `limit: amount` in the manifest, and give each role its limits in minor units (cents):

```yaml
permissions:
  - key: refund:create
    limit: amount
roles:
  cashier:
    groups: {refunds: full}
    limits: {refund:create: {alone: 200000, approves: 0}}   # KES 2,000.00
```

- **`alone`** is how much the holder does without approval; **`approves`** is how much they may approve for someone else. A missing value is no limit; `0` is none at all.
- **A role that gives the permission with no limit set is unlimited.** Across a user's roles the most generous value wins.
- **A direct allow without a limit** needs approval for any amount.
- **Organizations** can override a tenant role's limits for themselves, and their own roles carry their own (see [Organization roles](admin-api.md#organization-roles)). In an organization, the SDKs fetch its role map when your client has limited permissions, and cache it by `orv`.
- **The currency** is the organization's `currency`, else the tenant's `settings.currency`.

| | Go | TypeScript | Laravel |
| --- | --- | --- | --- |
| Check in code | `p.CanAmount("refund:create", 250000)` | `p.canAmount("refund:create", 250000)` | `$principal->canAmount('refund:create', 250000)` |
| The answer | `gk.AmountAllow`, `gk.AmountApprovalRequired` or `gk.AmountDeny` | `"allow"`, `"approval_required"` or `"deny"` | `Principal::AMOUNT_ALLOW`, `..._APPROVAL_REQUIRED`, `..._DENY` |
| The limit | `p.Limits["refund:create"]`, `p.Currency` | `p.limits?.["refund:create"]`, `p.currency` | `$principal->limits['refund:create']`, `$principal->currency` |

The SDK sees only the token's roles. For the authoritative answer, direct grants included, send the amount to the server: `POST /v1/authz/check {"permission": "refund:create", "amount": 250000}` answers `decision` (`allow`, `approval_required` or `deny`) and `limit {alone, approves, currency}`. Above `alone`, `allow` is `false`, so code that reads only `allow` never lets the amount through. Decisions above `alone` are audited.

## Second-person approval

Above `alone`, or for a permission that always needs a second person, Gatekeeper can collect one approval for one action and hand you a token you spend once. Mark a permission that needs approval whatever the amount (a void, a price override) with `requires_approval: true` in the manifest.

1. **Ask:** when a check answers `approval_required` (or `allow` for a `requires_approval` permission), your backend calls `POST /v1/approvals {"permission": "refund:create", "resource": "sale:42", "amount": 250000, "summary": "Refund of a broken kettle"}` with the requester's token. You get `approval_id`; it waits 2 minutes. Any other answer is `409 approval-not-needed`.
2. **Tell approvers:** subscribe to the `approval.requested` webhook, which carries the ids and the amount, never the summary.
3. **Approve:**
   - **on the shared device,** the approver enters their PIN: `device.approveWithPin(approvalId, approverId, pin)` in the TypeScript device signer. Wrong PINs count toward their lockout, and a sensitive permission is never approved by PIN;
   - **on their own device,** with a second factor in the last 5 minutes: `POST /v1/approvals/{id}/approve` (or `/deny`) with their token. `GET /v1/approvals/{id}` shows them the summary.
   The approver must be another active member holding the permission in the same organization, with `approves` covering the amount.
4. **Get the token:** the device's approve call answers with `approval_token`, and the requester's `GET /v1/approvals/{id}` returns it once granted. It's valid for 2 minutes.
5. **Spend it last,** in the commit path of the action, with the requester's token or your client's client-credentials token. Everything must match: permission, resource, amount, client and requester. A second spend is refused.

| | Go | TypeScript | Laravel |
| --- | --- | --- | --- |
| Read it (no spend) | `sdk.VerifyApproval(ctx, raw, p)` | `gk.verifyApproval(raw, p)` | `$gk->verifyApproval($raw, $principal)` |
| Spend it once | `sdk.SpendApproval(ctx, token, raw, "refund:create", "sale:42", &amount)` | `gk.spendApproval(token, raw, "refund:create", "sale:42", 250000)` | `$gk->spendApproval($token, $raw, 'refund:create', 'sale:42', 250000)` |
| Already spent or expired | `gk.ErrApprovalClosed` | `ApprovalError` with `code: "closed"` | `ApprovalException` with `reason` `closed` |
| Doesn't match | `gk.ErrApprovalMismatch` | `ApprovalError` with `code: "mismatch"` | `ApprovalException` with `reason` `mismatch` |

The approval token is an ES256 JWS with `typ: approval+jwt`, signed by the keys in the tenant's JWKS: `aud` is the requester's client, `jti` the approval id, `sub` the approver, `req` the requester, and `perm`, `res`, `amt`, `cur`, `org` and `method` (`pin` or `mfa`) say what was approved and how.

## Step-up

Some actions need a second factor from the last few minutes. `RequireStepUp(5*time.Minute)` (Go), `requireStepUp(300)` (TypeScript) and `gk.stepup:300` (Laravel) refuse a user whose last second factor is older, with `401` and an RFC 9470 challenge:

```text
WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age="300", acr_values="mfa"
```

The app re-runs sign-in with those parameters and retries (see [Signing users in](signing-in.md#step-up-asking-for-a-recent-second-factor)).

A permission can require one too: `sensitive: true` in the manifest asks for a second factor within the tenant's step-up window (10 minutes by default), and `step_up: 120` gives it its own window in seconds. The permission guards then answer the same challenge when it's stale. Machine principals (client credentials, API keys) are never asked; step-up guards refuse them.

```go compile
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	gk "github.com/hobbit254/gatekeeper-sdk/go"
)

func main() {
	issuer := "https://auth.example.com/t/acme"
	secret := os.Getenv("GATEKEEPER_CLIENT_SECRET")

	// The revocation feed refuses tokens from ended sessions within seconds.
	feed := gk.NewRevocationFeed(gk.FeedConfig{Issuer: issuer, ClientID: "billing-api", ClientSecret: secret})
	go feed.Run(context.Background())
	auth := gk.New(gk.Config{Issuer: issuer, Audience: "billing-api", ClientID: "billing-api", ClientSecret: secret}).WithDenylist(feed)

	refund := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := gk.FromContext(r.Context())
		if !p.HasFeature("refunds") { // the customer's plan doesn't include it
			http.Error(w, "upgrade to issue refunds", http.StatusPaymentRequired)
			return
		}
		if p.Actor != "" {
			log.Printf("%s refunding as %s", p.Actor, p.Sub) // an admin is impersonating this user
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux := http.NewServeMux()
	mux.Handle("POST /refunds", gk.RequirePermission("billing:refund")(gk.RequireStepUp(5*time.Minute)(refund)))
	srv := &http.Server{Addr: ":8080", Handler: auth.Middleware()(mux), ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
```

## Ended sessions

An access token stays valid until it expires (10 minutes by default) even after the user signs out, an admin suspends them, or a breach response ends their sessions. To refuse it sooner:

- **The revocation feed:** `gk.NewRevocationFeed(...)`, `createRevocationFeed({issuer, clientId, clientSecret})`, or PHP's `RevocationFeed` (polled every 5 seconds) keeps the tenant's ended sessions in memory from a stream. Give your client the `revocations:read` scope. If the feed hears nothing for 60 seconds, every token is refused until it catches up, so an outage fails closed.
- **A denylist of your own:** any function `(sid, jti) → denied` works: `WithDenylist` in Go, `denylist` in TypeScript, a bound `Gatekeeper\DenylistChecker` in Laravel.

Refresh tokens from an ended session stop at once: the next refresh answers `invalid_grant`.

## API keys

Users and service accounts can create personal API keys (`gk_live_…`) for scripts. The SDKs accept `Authorization: Bearer gk_live_…` like a token:
- they introspect it with your client's credentials and cache the answer for 60 seconds (10 seconds when inactive);
- the principal has `APIKey` set, `OwnerType` `user` or `service_account`, and no `AMR`, so step-up guards refuse it;
- if Gatekeeper can't be reached, the key is refused.

## Plans and features

A tenant can attach a customer's plan and paid features to its users' tokens, tenant-wide or per organization. `Principal.Entitlements` (`entitlements`, `$entitlements`) carries `plan` and `features`, and `HasFeature` (`hasFeature`, `hasFeature()`) gates a feature. They change at the user's next token or refresh, up to the access token's lifetime; cut off at once through your own billing system when that matters. The `entitlements.updated` webhook tells you when they change.

## Impersonation

A tenant admin can act as a user for support, when the client allows it. Every support session has a reason, and it's **read-only unless the admin asked for write**:
- **The token** carries `Actor` (`actor`), the admin's id, `ImpersonationEndsAt`, and `ActorMode` (`actorMode`, `$actorMode`): `read` or `write`.
- **In read mode,** the SDK keeps only read permissions: those in a group's `read` set, or ending in `:read`. `Can`, `RequirePermission` and `CanAmount` refuse the rest, and `/v1/authz/check` answers `deny` with `matched_by: "impersonation_read_only"`. Name read-only actions `…:read`, or put them in a group's `read` set.
- **Write mode** needs a tenant owner, or a role in the policy's `impersonation_write_roles`, with a second factor in the last 5 minutes.
- **The organization is told:** its owners and admins are emailed who, why, the mode and when it ends, and they can end the session from the dashboard.

Show a banner while `Actor` is set ("Support is viewing as … · read-only · ends in N min · Stop"), wire Stop to `POST /v1/auth/impersonation/stop`, and record `Actor` and `ActorMode` in your own audit trail.

## DPoP-bound tokens

The SDK middleware checks DPoP proofs whenever a token is bound to a key (see [Signing users in](signing-in.md#dpop-tokens-bound-to-a-device)); there's nothing to turn on. Behind a proxy, set your public URL (`Config.PublicURL`, `publicUrl`, `$publicUrl`) so the proof's URL matches what the app signed.

Without an SDK, call `<issuer>/oauth2/introspect` with the token, `dpop_proof`, `htm` and `htu`, and treat `active: false` as a refusal.

## Resource relationships

Permissions say what someone may do in general; relationships say which records ("editor of campaign 42 because manager of the organization that owns it"). When the tenant turns on relationship checks:

1. **Describe the model** in an `fga` block of your permissions manifest, and apply it.
2. **Write relationships** with a service account whose role holds `fga:write`: `POST /v1/authz/relations {writes: [{user: "user:<id>", relation: "editor", object: "campaign:42"}]}`. Your app owns its resource relationships: when a resource is deleted, send its `deletes` in the same flow. Gatekeeper adds each user's organization memberships itself.
3. **Check:** `auth.CanOn(ctx, token, "campaign:update", "campaign:42")` (`canOn`, `canOn()`), `CanOnEach` for a page of rows, or guard a route with `RequirePermissionOn` (`requirePermissionOn`, Laravel `gk.can_on:campaign:update,campaign`). Each check asks Gatekeeper, with the user's own token.
4. **List pages:** `POST /v1/authz/list-objects {permission, type}` answers `{all: true}` (show everything) or the ids to show. Treat `truncated` as "more than 1,000", and `503` as an error, never as "nothing".
5. **Who can access a record:** `POST /v1/authz/list-users {permission, resource}`, with the `authz:list-users` scope or the user's own token in a share dialog. Show `users` by name, and `roles` as "everyone holding these roles".

**Organization-wide access:** define `admin: [user]` or `role_<role>: [user]` on `org` in the model and use them (`define can_archive: editor or admin from owner_org`). Gatekeeper sends who holds them, so don't write those yourself.

**Users with DPoP-bound tokens** can't have their token forwarded. Allow `authz:check` on your confidential client and configure its secret: the guards then check those users with your client's credentials, and `CanOnFor(ctx, userID, …)` (`canOnFor`, `canOnFor()`) does the same in jobs. Gatekeeper answers only for users with a live sign-in through your client.

The dashboard's **Relationships** page shows the model, tests checks, and answers "who can access".

## Encrypted ID tokens

For tenants who want names and emails readable only by the client they're for:
1. **Register a key:** generate an EC P-256 (or RSA 2048+) key pair for the client, and keep the private key in the client's secret store or the device keystore. Give Gatekeeper the public key: `PATCH /v1/admin/clients/{id}` with `encryption {jwks | jwks_uri, id_token_encrypted_response_alg: "ECDH-ES+A256KW", userinfo_encrypted_response_alg?}`.
2. **Read tokens with the SDKs:**
   - Go: `Config.DecryptionKey` with `VerifyIDToken` / `UserInfo`;
   - TypeScript: `decryptionKey` on `createBrowserClient`, or `verifyIdToken(raw, {decryptionKey})`;
   - PHP: the `Config` `decryptionKey` with `verifyIdToken()` / `userInfo()`;
   - Dart: an `IdTokenDecrypter` backed by the keystore.
3. **Rotate:** with a `jwks_uri`, publish the new key at least an hour before retiring the old one; Gatekeeper caches the set for an hour.
