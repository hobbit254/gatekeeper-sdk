# Machine-to-machine

A service with no user (a nightly job, a back office, one API calling another) signs in as itself with the OAuth 2.0 client-credentials grant.

## Service accounts

A **service account** is a client of type `m2m` with a service user behind it, so it can hold roles like a person. Create one on the dashboard's **Clients and API keys** page, or with the admin API: `POST /v1/admin/service-accounts {name, audiences}` returns `client_id: "svc-<name>"` and its secret, shown once.

Grant it roles as for any user (`POST /v1/admin/users/{id}/roles`), using the service user's id from the answer. Give it only the permissions it needs. To let it call the admin API too (to sync a manifest from CI, or provision users from a back office), give it admin scopes (see [The admin API](admin-api.md#service-accounts)).

## Getting a token

`POST <issuer>/oauth2/token` with `grant_type=client_credentials`, the client's id and secret (HTTP Basic or form fields), and optionally `audience` and `scope`. The answer is an access token with `sub` set to the client id, the service account's roles, and `aud` set to the requested audience (or all of the client's). There is no refresh token and no ID token: ask again when it expires.

The SDKs cache the token until a minute before it expires, and concurrent callers share one request:

```go compile
package main

import (
	"context"
	"log"
	"os"

	gk "github.com/hobbit254/gatekeeper-sdk/go"
)

func main() {
	ctx := context.Background()
	issuer := "https://auth.example.com/t/acme"
	creds := &gk.ClientCredentials{
		TokenURL:     issuer + "/oauth2/token",
		ClientID:     "svc-reports",
		ClientSecret: os.Getenv("GATEKEEPER_CLIENT_SECRET"),
		Audience:     "shop-api",
	}
	token, err := creds.Token(ctx) // cached; call it before each request
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("call shop-api with: Authorization: Bearer %.12s…", token)
}
```

In TypeScript, `createClientCredentials({tokenUrl, clientId, clientSecret, audience})` and `await creds.token()`; in PHP, `new Gatekeeper\ClientCredentials($tokenUrl, $id, $secret, $scope, $audience, $cache)` and `->token()`.

The API receiving the token checks it like any other (see [Protecting an API](protecting-an-api.md)). Its principal is a machine: `Sub` is the client id, and step-up guards refuse it, since a service has no second factor.

## Binding a service's tokens to a key

Flag the m2m client `dpop_bound_access_tokens` and give the helper a key. Each token request then carries a proof, and the token works only with proofs from that key:
- **Go:** `gk.ClientCredentials{..., DPoPKey: signer}`, then `cc.Proof(method, url, token)` for each call;
- **TypeScript:** `createClientCredentials({..., dpopKey: await generateDPoPKey()})` and `cc.proof(...)`;
- **PHP:** `(new ClientCredentials(...))->withDPoPKey($pem)` and `->proof(...)`.

Send `Authorization: DPoP <token>` with the proof in a `DPoP` header.

## API keys for scripts

For a script or a partner's integration that can't do OAuth, a tenant admin can issue a personal **API key** to a user or a service account: `POST /v1/admin/api-keys {owner_id, name, scopes, expires_in_days?}`, shown once, revoked with `DELETE /v1/admin/api-keys/{id}`. Keys look like `gk_live_…` and are sent as a bearer token; the SDKs accept them (see [Protecting an API](protecting-an-api.md#api-keys)). Prefer client credentials for your own services: their tokens expire on their own.

## Checking on a user's behalf

A job sometimes needs to know whether a particular user may act on a record, with no token from that user. Allow `authz:check` on your confidential client, then:
- call `CanOnFor(ctx, userID, permission, resource)` (`canOnFor`, `canOnFor()`) for relationship checks (see [Protecting an API](protecting-an-api.md#resource-relationships));
- or call `POST /v1/authz/check {permission, user_id}` with your client-credentials token.

Gatekeeper answers only for users with a live sign-in through your client; otherwise `403 user-not-served`.

## Support access (impersonation)

A support tool can act as a user, for a tenant admin who has just used their second factor:
- **Allow it on the client:** `PATCH /v1/admin/clients/{id} {allow_impersonation: true}`. It isn't available for m2m clients.
- **Start it:** `POST /v1/admin/users/{id}/impersonate {client_id}` with the admin's token returns a short access token for that user, valid for at most an hour. It has `act` set and no `amr`, so step-up guards refuse it.
- **Show and stop it:** your app shows the banner and stops it (see [Protecting an API](protecting-an-api.md#impersonation)).
