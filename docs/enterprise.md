# Enterprise SSO and SCIM

When your customers are companies, their people can sign in with the company's identity provider (Okta, Entra ID, Google Workspace, ADFS, or any SAML 2.0 or OpenID Connect provider), and the provider can create and remove their accounts.

Each customer company is an **organization** in your tenant. Nothing changes for your app: it keeps sending users to `/oauth2/authorize`, optionally with `organization=<slug>` to go straight to that company's sign-in. Tokens from SSO carry `amr ["fed", "sso"]` (plus `mfa` when the connection trusts the provider's MFA) and the organization in `org`.

## Setting up a company

On the dashboard, the organization's page does all of this. The API calls are shown alongside, under `/v1/admin`.

1. **Our addresses first.** Start a connection with `PUT /orgs/{id}/sso {protocol: "saml", enabled: false}` and none of the provider's details. It saves a draft and returns `sp`: the addresses the company's provider needs (ACS URL, entity id, SLO URL, metadata URL, or the OIDC redirect URI). Later `PUT`s keep them.
2. **The domain.** Add the company's email domain (`POST /orgs/{id}/domains`), have them publish the returned TXT record, then verify it (`POST /orgs/{id}/domains/{domain_id}/verify`). DNS changes can take up to an hour.
3. **The connection.**
   - **SAML:**
     - At the provider, create an app with ACS URL `sp.acs_url`, entity id (audience) `sp.entity_id`, and SLO URL `sp.slo_url` (HTTP-POST).
     - Use a persistent id or the email as the NameID, sign the assertions, and send the attributes `email`, `firstName` and `lastName` (or name yours in `attributes`).
     - Give the provider our metadata at `sp.metadata_url`. It carries our certificate, so the provider can check our signed requests and encrypt its assertions.
     - Send us the provider's metadata URL as `metadata_url`, refreshed daily so certificate rollovers need nothing from you, or paste its metadata as `metadata_xml`.
   - **OIDC:** register `sp.redirect_uri` at the provider and send its `issuer`, `client_id` and `client_secret`.

   Then turn it on: `PUT /orgs/{id}/sso {protocol, enabled: true}`. `{protocol, enabled}` alone turns a connection off or on without resending its details.
4. **Optional, required SSO:** `PATCH /orgs/{id} {require_sso: true}` stops members on the verified domains signing in any other way, and ends their sessions that didn't come through SSO. Keep a tenant admin outside the domain in case the provider is down.
5. **Optional, the provider's MFA:** `trust_idp_mfa: true` lets a provider sign-in with MFA count as Gatekeeper's second factor. Only turn it on for a provider that enforces MFA.
6. **Provisioning:** create a SCIM token (`POST /orgs/{id}/scim-tokens`) and give the provider the base URL `https://auth.<domain>/t/<tenant>/scim/v2` with that token. Push users and groups, then map each group to roles: on the organization's page under **Groups from your identity provider**, or with `PUT /orgs/{id}/scim-groups/{group_id}/roles`. A group can map the tenant's roles and the organization's own (`org/<name>`). Renaming or retiring an organization role updates the groups that map it.

Organization admins can do all of this for their own organization (see [The admin API](admin-api.md#tokens)). On the dashboard they also invite people by email, see each member's email and roles, and change those roles, offered only the roles they may grant.

- **Activity:** they see their organization's own activity: sign-ins into it, invitations, membership and role changes, SCIM and SSO changes, and their admins' actions (`GET /orgs/{id}/audit-events`). Nothing from other organizations appears there.
- **Sign-in logo:** they upload the organization's logo (`PUT /orgs/{id}/logo`, PNG, at most 100 KB). Sign-in pages opened with `organization=<slug>` then show that logo and the organization's name.

## Day to day

- **Logout:** signing out of your app (`/oauth2/logout`) also signs the user out at the provider. A logout at the provider ends their Gatekeeper sessions: only those from the provider session it names, or all of them. Providers may use HTTP-POST or HTTP-Redirect for logout requests and answers.
- **Certificates and domains:** the tenant's owners and the organization's admins are emailed 14 and 3 days before a provider certificate expires. A domain whose TXT record is missing for 3 days in a row stops being verified, with the same emails.
- **SCIM filters and sorting:** list calls accept RFC 7644's whole filter grammar on names, emails, dates and the enterprise attributes, and `sortBy`/`sortOrder`. Incremental syncs can ask for `meta.lastModified gt "…"`.
- **`/Me`:** self-service tools can read and rename the signed-in user at `/scim/v2/Me` with a Gatekeeper access token that has the `scim:me` scope. Allow that scope on the client first.
- **Enterprise attributes and bulk:** the provider's enterprise extension (department, manager, …) is kept per organization, and large imports can use `/Bulk`.
- **Group companies:** each regional organization can verify its own subdomain (`eu.acme.com`) under the parent's (`acme.com`). An email belongs to the organization with the longest verified match, and required SSO follows it.
- **Microsoft accounts:** a work account whose domain belongs to an organization that requires SSO is sent to that organization's SSO, not signed in through "Continue with Microsoft".

## Not supported yet

- IdP-initiated SAML sign-in. Use a bookmark app at the provider that opens your app.
- SCIM `/.search`, `attributes` / `excludedAttributes`, and ETags.
