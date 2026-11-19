# Getting started

From nothing to a user signed in to your app and calling your API. The dashboard's **Guide** walks through the same steps, and its **Overview** checklist ticks each one when it's done.

## 1. Register your app

An app that signs users in, or an API that checks their tokens, is a **client**. On the dashboard open **Clients and API keys → Register an app**:

- **Type:** `public` for browser and mobile apps, which can't keep a secret; `confidential` for a server that can; `m2m` for a service with no user (see [Machine-to-machine](machine-to-machine.md)).
- **Redirect URIs:** where users may be sent back after signing in, exactly as your app will ask for them, for example `https://shop.example.com/callback`. Mobile apps use their own scheme, such as `com.example.shop:/callback`.
- **API audiences:** the identifiers of the APIs this app calls with its users' tokens, for example `shop-api`. Your API checks for it.
- **First-party:** tick it for your own apps. They skip the consent screen and may use headless sign-in. Leave it off for partners' apps (see [Tenant policies](tenant-policies.md#partner-apps-and-consent)).

A confidential client's secret is shown once. Put it in your secret manager straight away. The client's **Connect** panel then shows the issuer, the client id, and the code below with your values filled in.

The same can be done with the admin API (`POST /v1/admin/clients`); see [The admin API](admin-api.md).

## 2. Sign users in

A browser app, in TypeScript. Users go to Gatekeeper's sign-in page and come back to your redirect URI:

```ts compile
import { createBrowserClient } from "@hobbit254/gatekeeper-sdk/browser";

export const auth = createBrowserClient({
  issuer: "https://auth.example.com/t/acme",
  clientId: "shop-web",
  redirectUri: "https://shop.example.com/callback",
  scope: "openid profile email offline_access",
});

// On your "Sign in" button.
export const signIn = () => auth.loginWithRedirect();

// On the page at the redirect URI: checks the response and returns the user's claims.
export const onCallback = () => auth.handleRedirectCallback();

// Calls your API with the user's access token, refreshed before it expires.
export const callApi = async (url: string) =>
  fetch(url, { headers: { Authorization: `Bearer ${await auth.getAccessToken()}` } });
```

A Flutter app signs in through the system browser and keeps tokens in the Keychain or Android Keystore:

```dart compile
import 'package:gatekeeper_flutter/gatekeeper_flutter.dart';

final gatekeeper = Gatekeeper(
  GatekeeperConfig(
    issuer: 'https://auth.example.com/t/acme',
    clientId: 'shop-app',
    redirectUri: Uri.parse('com.example.shop:/callback'),
  ),
  store: SecureTokenStore(issuer: 'https://auth.example.com/t/acme', clientId: 'shop-app'),
);

final auth = GatekeeperAuth(gatekeeper);

// At start-up, then on your "Sign in" button.
Future<void> restore() => auth.restore();
Future<bool> signIn() => auth.signIn();
```

More ways to sign in, including your own screens, are in [Signing users in](signing-in.md).

## 3. Protect your API

Your API checks each request's bearer token: its signature against the tenant's keys, the issuer, your audience, expiry, and whether the session was ended. The SDKs do all of it and give you the user. In Go:

```go compile
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	gk "github.com/hobbit254/gatekeeper-sdk/go"
)

func main() {
	auth := gk.New(gk.Config{
		Issuer:       "https://auth.example.com/t/acme",
		Audience:     "shop-api",
		ClientID:     "shop-api",
		ClientSecret: os.Getenv("GATEKEEPER_CLIENT_SECRET"),
	})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		p, _ := gk.FromContext(r.Context())
		_, _ = w.Write([]byte(p.Sub))
	})
	mux.Handle("GET /reports", gk.RequirePermission("report:read")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[]"))
	})))
	srv := &http.Server{Addr: ":8080", Handler: auth.Middleware()(mux), ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
```

In Laravel, after `composer require hobbit254/gatekeeper-laravel`, set `GATEKEEPER_ISSUER`, `GATEKEEPER_AUDIENCE`, `GATEKEEPER_CLIENT_ID` and `GATEKEEPER_CLIENT_SECRET` in `.env`, then:

```php compile
<?php

use Gatekeeper\Laravel\GatekeeperAuthenticate;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::middleware('gatekeeper')->get('/me', fn (Request $request) => [
    'sub' => GatekeeperAuthenticate::principal($request)?->sub,
]);

Route::middleware(['gatekeeper', 'gk.can:report:read'])->get('/reports', fn () => []);
```

The client id and secret let the SDK fetch your app's role map, which turns the roles in a token into permissions. Permissions, step-up and the rest are in [Protecting an API](protecting-an-api.md).

## 4. Try it

Sign in to **your app** (not the dashboard) as any user. If nothing happens, the dashboard's **Audit log** shows each attempt and why it failed. The usual cause is a redirect URI that differs by a slash or a scheme.

## The examples

[`examples/browser-app`](../examples/browser-app) (TypeScript, Vite) signs users in and calls [`examples/go-api`](../examples/go-api), which checks tokens and a permission. Each runs against any tenant from a few environment variables, listed at the top of its files.

## Keep in your own database

Store Gatekeeper's user id (the token's `sub`) as a foreign key on your own user or customer rows, with a cached copy of the display fields if you show them (`display_name`, `avatar_url`, `locale`, `timezone`). Everything about what a person does in your product stays in your tables. Refresh the cached fields from the `user.updated` webhook (see [Webhooks](webhooks.md)).

Your app never writes to Gatekeeper directly: users change their profile through `PATCH /v1/me` or the hosted account pages, and your back office changes roles through [the admin API](admin-api.md).
