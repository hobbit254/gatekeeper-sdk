# The admin API

Everything on the dashboard is also an API under `<issuer>/v1/admin`: users, roles, apps, organizations, webhooks, policies, the audit log. Use it from an internal back-office tool or a script. The Go, TypeScript and PHP SDKs include typed clients generated from its OpenAPI description ([`admin-openapi.json`](../admin-openapi.json)).

## Tokens

Admin calls carry either a tenant admin's own token or a service account's token with admin scopes ([below](#service-accounts)).

**A person's token**, as the dashboard uses:
- **Who:** a person holding the `owner` or `admin` role, tenant-wide.
- **The token:** it has the `tenant:admin` scope and the `gatekeeper-admin-api` audience.
- **A recent second factor:** the admin must have used one within the last 10 minutes. Otherwise the call answers `401` with a step-up challenge (`max_age="600"`); sign in again with it (see [Signing users in](signing-in.md#step-up-asking-for-a-recent-second-factor)).

**From your own tool:**
1. Register a first-party client for it, allowed the `tenant:admin` scope and with `gatekeeper-admin-api` as its only API audience.
2. Sign the admin in with `scope=openid tenant:admin`. With no `audience` asked for, the token gets the client's audiences.

Gatekeeper grants `tenant:admin` only to people who hold an admin role.

**Organization admins** get `org:admin` instead. It reaches only their organization's members, invitations, SSO, domains, SCIM tokens and access requests.

**API keys** can't call the admin API.

## Service accounts

A service account (see [Machine-to-machine](machine-to-machine.md#service-accounts)) can call the admin API within **admin scopes** that a tenant admin gives it, one by one. Each opens a fixed set of routes:

| Scope | Lets it |
| --- | --- |
| `admin:permissions` | sync the permissions manifest (dry run included) and read roles and permissions |
| `admin:users.read` | list and read users, invitations and sessions |
| `admin:users.write` | create, edit, suspend and unsuspend users; import users from a CSV file; end sessions, a user's or by id; send and withdraw invitations |
| `admin:roles` | grant and revoke roles and permissions on users |
| `admin:orgs` | manage organizations, their members, and their plans and features |
| `admin:audit.read` | read and export the audit log |
| `admin:consent` | add, change and remove consent purposes |

**What stays with people:**
- **Any other route** answers `403`, whatever scopes the account holds: apps and secrets, service accounts, API keys, the tenant's policy and providers, terms and privacy versions, webhooks, impersonation, MFA and password resets, deleting users or organizations, SSO, domains and SCIM, incidents and compliance packs.
- **Owners and admins:** a service account can never edit, suspend, end the sessions of, or change the roles of a tenant owner or admin.
- **Admin roles:** it can never grant or revoke `owner`, `admin` or `*:*`, by any route.
- **Imports and session revocation:**
  - In a CSV import it starts, a row granting `owner` or `admin`, or naming an existing owner or admin, fails with its own error. The other rows go through, and a dry run (`dry_run=true`) shows the same outcomes.
  - A revocation by id that includes an owner's or admin's session is refused whole: `403`, and nothing ends.

**Giving it scopes:** tick them under **Admin access** on the dashboard's **Clients and API keys** page, or send `admin_scopes` to `POST /v1/admin/service-accounts`. `allowed_scopes` on `PATCH /v1/admin/clients/{client_id}` changes them later. The `gatekeeper-admin-api` audience comes and goes with them. A change applies from the account's next token.

**Using them:** ask for the scopes in the client-credentials request (`scope=admin:permissions`). No second factor is asked of a machine, so keep the secret in your CI's or platform's secret store, and give each job only the scopes it needs. Every call is in the audit log as `service account svc-…`. Suspending the service account's user, or deleting the account, stops its tokens at once.

Syncing the manifest from CI:

```go compile
package main

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"os"

	gk "github.com/hobbit254/gatekeeper-sdk/go"
	"github.com/hobbit254/gatekeeper-sdk/go/admin"
)

func main() {
	ctx := context.Background()
	issuer := os.Getenv("GATEKEEPER_ISSUER") // https://auth.example.com/t/acme
	creds := &gk.ClientCredentials{
		TokenURL:     issuer + "/oauth2/token",
		ClientID:     "svc-ci",
		ClientSecret: os.Getenv("GATEKEEPER_CLIENT_SECRET"),
		Scope:        "admin:permissions",
		Audience:     "gatekeeper-admin-api",
	}
	c, err := admin.New(issuer, creds.Token)
	if err != nil {
		log.Fatal(err)
	}
	manifest, err := os.ReadFile("permissions.yaml")
	if err != nil {
		log.Fatal(err)
	}
	dryRun := os.Getenv("DRY_RUN") == "true" // preview on pull requests, apply on main
	resp, err := c.AdminSyncPermissionsWithBodyWithResponse(ctx, &admin.AdminSyncPermissionsParams{ClientId: "shop-api", DryRun: &dryRun},
		"application/yaml", bytes.NewReader(manifest))
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode() != http.StatusOK {
		log.Fatalf("sync refused: %d %s", resp.StatusCode(), resp.Body)
	}
	log.Printf("%s", resp.Body) // what was (or would be) added, changed and removed
}
```

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
| Organizations | `/orgs`, `/orgs/{id}/members`, `…/roles`, `…/sso`, `…/domains`, `…/scim-tokens` |
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

### Permission groups

Group your permissions into a few named jobs, so admins build roles from words like "Reports" or "Refunds" instead of keys. A role then holds a group at `read` or `full`:

```yaml
groups:
  - key: reports
    label: {en: Reports, sw: Ripoti}
    description: {en: View and export reports}
    read: [report:read]
    full: [report:*]
  - key: refunds
    label: {en: Refunds, sw: Marejesho}
    full: [refund:issue]
roles:
  viewer: [report:read]       # a plain list still works
  clerk:
    groups: {reports: read}
  manager:
    groups: {reports: full, refunds: full}
    permissions: [user:impersonate]
```

- **Levels:** `read` gives the group's `read` permissions; `full` gives both lists. You say what "read" means; nothing is inferred.
- **Labels and descriptions** are in English (`en`, required) and Swahili (`sw`), shown on the dashboard's role editor.
- **A change to a group** reaches every role that holds it, including roles admins built on the dashboard, at their next token. Your SDK and tokens don't change: the role map still lists each role's permissions.
- **`tenant_only: true`** keeps a group for the tenant's own admins: a role holding it is never granted by an organization's admins.
- **Removing a group** that a dashboard-built role still holds fails; take it away from that role first.
- **The dry run** lists group changes and the permissions no group gives.
- **`/v1/authz/check`** names the group that allowed a permission in its `group` field.

`GET /v1/admin/permission-groups?client_id=shop-api` lists the groups with what each level gives; a service account with `admin:permissions` may read it.

### Organization roles

An organization's admins can build their own roles, such as a "Senior cashier" for one shop, from the groups they hold. Mark the roles they may start from with `template: true`:

```yaml
roles:
  cashier:
    template: true
    groups: {sales: read}
```

- **Templates hold groups only**, and never a `tenant_only` group or a system role; the sync refuses anything else.
- **A copy is independent.** A later change to the template doesn't reach it, but a change to a *group* does.
- **Guard rails, on the server:** an org admin gives a group only at a level they hold, can't edit or retire a role holding a group they lack, and never gives a `tenant_only` group. At most 50 roles per organization; names never clash with a tenant role.
- **Names:** tokens, grants and the role map call them `org/<name>`. Grant one with `POST /v1/admin/users/{id}/roles {"role": "org/senior-cashier", "org_id": "acme"}`; it applies only in that organization.

| Call | What it does |
| --- | --- |
| `GET /v1/admin/orgs/{id}/roles` | The organization's roles, the templates, and each group with the highest level the caller may give (`max`, and `reason`: `not_held` or `tenant_only`) |
| `POST /v1/admin/orgs/{id}/roles` | `{name, description?, copy_from?, groups?}`; with `copy_from` and no `groups`, the template's groups are copied |
| `PATCH /v1/admin/orgs/{id}/roles/{role_id}` | Rename it, or change its description or groups; it reaches everyone holding it at once |
| `DELETE /v1/admin/orgs/{id}/roles/{role_id}` | Retire it; its grants go with it |

**Amount limits** ([Amount limits](protecting-an-api.md#amount-limits)): an org role carries `limits` (`{"refund:create": {"alone": 200000, "approves": 0}}`), copied from the template on a copy. An organization can override a tenant role's limits for itself. An org admin gives a limit only up to their own in the organization, and a permission given with no limit is unlimited, so they must state one. They can't edit, override or grant a role whose limits are above theirs. `GET /v1/admin/orgs/{id}/roles` lists the limited permissions they hold with their own limits (`limited`), and the tenant roles' limits with the organization's overrides (`tenant_roles`).

| Call | What it does |
| --- | --- |
| `PUT /v1/admin/orgs/{id}/roles/{role_id}/limits` | `{limits}`: for a tenant role, the organization's override, used in its scope; for its own role, its limits. `{}` clears them |
| `PATCH /v1/admin/orgs/{id}` | `{currency: "KES"}` sets the organization's currency (tenant admins only); `""` uses the tenant's `settings.currency` |
| `POST /v1/admin/users/{id}/permissions` | `{permission, effect: "allow", limit: {alone, approves}}`: a direct allow's limit; without one it needs approval for any amount |

Each change sends `role.updated` with `org_id` and the organization's new `orv` (see [Webhooks](webhooks.md)). Org admins reach these for their own organization; tenant admins for any.
