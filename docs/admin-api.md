# The admin API

Everything on the dashboard is also an API under `<issuer>/v1/admin`: users, roles, apps, organizations, webhooks, policies, the audit log. Use it from an internal back-office tool or a script. The Go, TypeScript and PHP SDKs include typed clients generated from its OpenAPI description ([`admin-openapi.json`](../admin-openapi.json)).

## Tokens

Admin calls carry a tenant admin's own access token, as the dashboard does:
- **Who:** a person holding the `owner` or `admin` role, tenant-wide.
- **The token:** it has the `tenant:admin` scope and the `gatekeeper-admin-api` audience.
- **A recent second factor:** the admin must have used one within the last 10 minutes. Otherwise the call answers `401` with a step-up challenge (`max_age="600"`); sign in again with it (see [Signing users in](signing-in.md#step-up-asking-for-a-recent-second-factor)).

**From your own tool:**
1. Register a first-party client for it, allowed the `tenant:admin` scope and with `gatekeeper-admin-api` as its only API audience.
2. Sign the admin in with `scope=openid tenant:admin`. With no `audience` asked for, the token gets the client's audiences.

Gatekeeper grants `tenant:admin` only to people who hold an admin role.

**Organization admins** get `org:admin` instead. It reaches only their organization's members, invitations, SSO, domains, SCIM tokens and access requests.

**Not yet:** service accounts and API keys can't call the admin API.

## The generated clients

```ts compile
import { createBrowserClient } from "@hobbit254/gatekeeper-sdk/browser";
import { createAdminClient } from "@hobbit254/gatekeeper-sdk/admin";

const issuer = "https://auth.example.com/t/acme";

// The back-office tool signs its admin in for the admin API.
export const auth = createBrowserClient({
  issuer,
  clientId: "backoffice",
  redirectUri: "https://backoffice.example.com/callback",
  scope: "openid tenant:admin",
});
export const signIn = () => auth.loginWithRedirect({ extra: { acr_values: "mfa" } });

const admin = createAdminClient({ issuer, token: () => auth.getAccessToken() });

// Suspends every active user with an email at a domain (one page of users).
export async function suspendDomain(emailDomain: string) {
  const { data, error } = await admin.GET("/v1/admin/users", { params: { query: { status: "active" } } });
  if (error) throw new Error(`listing users: ${JSON.stringify(error)}`);
  for (const u of data?.items ?? []) {
    if (u.email?.endsWith(`@${emailDomain}`)) {
      await admin.POST("/v1/admin/users/{id}/suspend", { params: { path: { id: u.id } } });
    }
  }
}
```

- **Go:** `admin.New(issuer, tokenFunc)` returns a client with a `…WithResponse` method per operation, such as `AdminListClientsWithResponse(ctx, nil)`.
- **PHP:** `Gatekeeper\AdminClient::make($issuer, fn () => $token)` returns the generated `DefaultApi`, for example `->adminListClients()`.

Errors are problem documents (`type`, `title`, `detail`). Lists page with `limit` and `cursor`; pass the answer's `next_cursor` back until it's `null`.

## What's there

| Area | Paths (under `/v1/admin`) |
| --- | --- |
| Users | `/users`, `/users/{id}`, `…/suspend`, `…/roles`, `…/permissions`, `…/revoke-sessions`, `…/reset-mfa`, `/users/import`, `/invitations`, `/sessions` |
| Roles and permissions | `/roles`, `/permissions`, `/permissions/sync` |
| Apps | `/clients`, `/clients/{id}/rotate-secret`, `/service-accounts`, `/api-keys` |
| Organizations | `/orgs`, `/orgs/{id}/members`, `…/sso`, `…/domains`, `…/scim-tokens` |
| Policy | `/tenant`, `/tenant/policy`, `/tenant/identity-providers/{provider}`, `/tenant/legal-documents` |
| Events and evidence | `/webhooks`, `/audit-events`, `/compliance/packs`, `/incidents` |

[`admin-openapi.json`](../admin-openapi.json) has every operation, its parameters and answers.

## The permissions manifest

Your app declares its permissions, and the roles that hold them, in a YAML file kept in its own repository:

```yaml
client: shop-api
version: 3
permissions:
  - key: report:read
    description: View reports
  - key: report:export
    description: Export reports to CSV
  - key: refund:issue
    description: Refund an order
    step_up: 120 # a second factor within 2 minutes for this one
  - key: user:impersonate
    description: Act as a customer for support
    sensitive: true # a second factor within the tenant's window
roles:
  viewer: [report:read]
  manager: [report:*, refund:issue]
```

- **Keys** are `resource:action`. Wildcards (`report:*`) are allowed in roles only, and they also cover permissions added later.
- **`sensitive: true`** asks for a second factor within the tenant's step-up window. **`step_up: <seconds>`** (60–86400) sets one permission's own window.
- **Bump `version`** with each change.
- **Removing a permission** that a role or a direct grant still uses fails, so remove the grant first.
- **Reserved roles:** `owner` can't be redefined, and only `owner` and `admin` may hold `*:*`.

Apply it on the dashboard's **Roles and permissions** page (choose the client and the file, **Preview**, then **Apply**), or with `PUT /v1/admin/permissions/sync?client_id=shop-api&dry_run=true` and the YAML as the body. The dry run lists what would be added, changed or removed. A role change reaches users at their next token (see [Protecting an API](protecting-an-api.md#permissions-and-roles)).

An `fga` block in the same file describes resource relationships (see [Protecting an API](protecting-an-api.md#resource-relationships)).
