# Webhooks

Gatekeeper posts signed events to your HTTPS endpoint when something changes: a user is created, a role is granted, a session ends. Use them to keep your copy of a user's display fields fresh, to react to suspensions and deletions, and to relay push approvals.

## Setting one up

On the dashboard's **Webhooks** page, or `POST /v1/admin/webhooks {url, description?, events?}`:
- **The URL** must be `https` on a public address. It's checked again on every connection, so a name that later points somewhere private is refused.
- **`events`** filters what you get: exact types such as `user.deleted`, or prefixes such as `user.*`. Leave it out to get everything.
- **The secret** (`whsec_…`) is shown once, in the answer. Keep it in your secret manager.

`PATCH /v1/admin/webhooks/{id}` changes the URL, filter or `enabled`; the dashboard can send a `webhook.test` event and shows recent deliveries.

## Delivery

Each event is an HTTPS `POST` of a CloudEvents 1.0 JSON body:

```json
{
  "specversion": "1.0",
  "type": "user.updated",
  "source": "https://auth.example.com/t/acme",
  "id": "01JC5X7Q9A2B3C4D5E6F7G8H9J",
  "time": "2026-11-09T14:02:11Z",
  "subject": "0192f3a1-7c2e-7d3a-9b1f-3a4c5d6e7f80",
  "datacontenttype": "application/json",
  "data": {
    "user_id": "0192f3a1-7c2e-7d3a-9b1f-3a4c5d6e7f80",
    "tenant_id": "0192f3a1-0000-7000-8000-000000000001",
    "tenant": "acme",
    "status": "active",
    "changed": ["display_name", "locale"],
    "display_name": "Amina Wanjiru",
    "avatar_url": null,
    "locale": "sw-KE",
    "timezone": "Africa/Nairobi"
  }
}
```

- **Headers:** `X-Gatekeeper-Signature` (below), `X-Gatekeeper-Delivery` (the same on every retry of one delivery) and `X-Gatekeeper-Event` (the type).
- **At least once:** the same event can arrive twice, so deduplicate on the CloudEvent `id`. Events about one user arrive in order.
- **Success** is any `2xx` within 10 seconds. Redirects aren't followed.
- **Retries** at 1, 5, 30, 120 and 600 seconds, then the delivery is marked failed.
- **Disabling:** after 50 failed attempts in a row the endpoint is disabled. The tenant's owners get an email and a `webhook.disabled` event. Re-enabling resets the count, but events from while it was off aren't resent.

## Checking the signature

```text
X-Gatekeeper-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, t + "." + body)>
```

Compute the HMAC over the raw body exactly as received, compare in constant time, and reject a `t` more than 5 minutes from now. The Go and PHP SDKs do all of it:

```go compile
package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	gk "github.com/hobbit254/gatekeeper-sdk/go"
)

func main() {
	secret := os.Getenv("GATEKEEPER_WEBHOOK_SECRET")
	http.HandleFunc("POST /gatekeeper/events", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		ev, err := gk.VerifyWebhook(secret, r.Header.Get("X-Gatekeeper-Signature"), body, time.Now())
		if errors.Is(err, gk.ErrWebhookSignature) {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		switch ev.Type {
		case "user.deleted":
			var d struct {
				UserID string `json:"user_id"`
			}
			_ = json.Unmarshal(ev.Data, &d)
			log.Printf("anonymise our copy of %s (event %s)", d.UserID, ev.ID)
		case "mfa.push_requested":
			if p, ok := ev.PushRequested(); ok {
				log.Printf("wake %s's devices for challenge %s", p.UserID, p.ChallengeID)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Addr: ":8080", ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
```

```php compile
<?php

use Gatekeeper\Webhook;
use Gatekeeper\WebhookSignatureException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('/gatekeeper/events', function (Request $request) {
    try {
        $event = Webhook::verify(
            (string) env('GATEKEEPER_WEBHOOK_SECRET'),
            (string) $request->header('X-Gatekeeper-Signature'),
            $request->getContent(),
        );
    } catch (WebhookSignatureException) {
        return response('bad signature', 401);
    }
    if ($event['type'] === 'user.deleted') {
        // Anonymise or delete your copy of $event['data']['user_id'].
    }
    return response()->noContent();
});
```

## Events

Every event's `data` carries `tenant_id` and `tenant` (the slug). User events also carry `user_id`, `status`, and `changed` when fields changed.

| Type | When | `data` highlights |
| --- | --- | --- |
| `user.created` | an account is created (sign-up, invitation, import, SCIM) | display fields |
| `user.updated` | profile or status changes; unsuspending is `changed: ["status"]` | `changed`, display fields |
| `user.suspended` | an admin suspends the account | |
| `user.deleted` | deletion starts its grace period (30 days by default) | |
| `user.restored` | a deletion is undone during the grace period | |
| `identity.verified` | an email or phone is verified | |
| `identity.changed` | the email or phone changes | |
| `identity.linked` | a Google, Apple or Microsoft account is connected | |
| `consent.granted` | the user switches an optional purpose on | `purpose` |
| `consent.withdrawn` | the user switches it off: stop at once | `purpose` |
| `data_export.ready` | a copy of the user's data is ready for them | `export_id` |
| `session.created` | a sign-in starts a session | `session_id`, `client_id`, `amr`, device, country |
| `session.revoked` | a session ends | `session_id`, reason |
| `login.succeeded` | a sign-in succeeds | `amr`, device, country; `amr: ["pin","hwk"]` and `device_id` for a PIN on a shared device |
| `login.failed` | a sign-in fails | reason; `amr: ["pin"]` and `device_id` for a PIN |
| `device.registered`, `device.revoked` | an organization registers (or registers again) or revokes a shared device | `device_id`, `org_id`, `name` |
| `pin.set`, `pin.removed`, `pin.held`, `pin.unlocked` | a user's PIN for shared devices changes; `pin.held` after 10 wrong tries | `user_id` |
| `login.new_device` | a sign-in from a device the user hasn't used | `session_id`, `device`, `ip`, `country`, `at` |
| `token.revoked` | a session's tokens are revoked | `sid` |
| `refresh.reuse_detected` | a used refresh token came back: the family is revoked | `family_id` |
| `mfa.push_requested` | a sign-in waits for push approval | `challenge_id`, `expires_at` |
| `signup.risky` | a sign-up scored high but was let through | `score`, `signals`, `outcome` |
| `role.assigned`, `role.revoked` | a role is granted or removed | `role_id`, `org_id`, `rv` |
| `role.updated` | a role, its permissions, its limits or the manifest change | `rv`; for an organization's own role or an organization's limits, `org_id` and `orv` instead, with `change: limits` for limits (ADR-0142, ADR-0143) |
| `permission.granted`, `permission.revoked` | a direct permission grant changes | `org_id`, `rv` |
| `org.created`, `org.updated`, `org.deleted` | organizations change | `org_id`, `slug`, `name` |
| `membership.added`, `membership.removed` | someone joins or leaves an organization | `org_id` |
| `entitlements.updated` | a plan or features change | `scope` (`tenant` or `org`), `org_id`, `entitlements` |
| `access.requested`, `access.approved`, `access.rejected`, `access.cancelled`, `access.lapsed`, `access.expired` | an access request or a protected grant moves | `request_id`, `kind`, `status`, role or permission, `org_id` |
| `incident.opened`, `incident.closed` | a tenant admin opens or closes an incident | `incident_id`, `severity` |
| `response.started`, `response.finished` | a bulk response (sessions ended, resets forced) runs | `response_id`, `actions`, `processed`, `failed` |
| `key.rotated`, `key.revoked` | the tenant's signing keys change | `kid` |
| `webhook.test` | you asked for a test delivery | |
| `webhook.disabled` | an endpoint was disabled after failures | |

Events never carry passwords, codes, the push number, incident notes or reasons for access decisions.

## Using them

- **Your copy of users:** upsert the display fields on `user.created` and `user.updated`.
- **Deletions:** on `user.deleted`, anonymise or delete your copy within your own retention policy. A deletion can be undone during the grace period, and `user.restored` follows. Either wait out the grace period before deleting, or re-create your copy on `user.restored`.
- **Consent:** never send for a purpose the user hasn't granted, and stop as soon as `consent.withdrawn` arrives (see [Tenant policies](tenant-policies.md#optional-purposes)).
- **Caching sessions or permissions yourself:** drop them on `session.revoked`, `token.revoked`, `role.*` and `response.finished`.
- **Push approval:** relay `mfa.push_requested` to the user's devices (see [Signing users in](signing-in.md#push-approval-on-the-users-phone)).
