# Gatekeeper SDKs

Client libraries and example apps for Gatekeeper, a multi-tenant sign-in and access service. Your Gatekeeper dashboard's **Connect** panel shows each snippet with your tenant's issuer and client id filled in.

**Start with the [integration guide](docs/README.md):** getting started, signing users in, protecting an API, machine-to-machine, webhooks, the admin API, enterprise SSO and SCIM, and tenant policies.

| SDK | Install | Folder |
| --- | --- | --- |
| Go | `go get github.com/hobbit254/gatekeeper-sdk/go` | [`go/`](go) |
| TypeScript (Node 22+, browsers) | `npm install @hobbit254/gatekeeper-sdk` | [`ts/`](ts) |
| PHP / Laravel (PHP 8.3+) | `composer require hobbit254/gatekeeper-laravel` | [`php/`](php) |
| Dart (Dart 3.5+) | `dart pub add gatekeeper_sdk` | [`dart/`](dart) |
| Flutter | `flutter pub add gatekeeper_flutter` | [`flutter/`](flutter) |

Each SDK verifies access tokens against your tenant's keys, resolves roles and permissions, and guards routes; the TypeScript, Dart and Flutter SDKs also sign users in. The Go, TypeScript and PHP SDKs include a typed admin client generated from [`admin-openapi.json`](admin-openapi.json).

## Examples

Copy one and set a few environment variables; each file's header lists them.

- [`examples/browser-app`](examples/browser-app): a browser app (TypeScript, Vite) that signs users in by redirect and calls an API.
- [`examples/go-api`](examples/go-api): the API it calls, checking tokens and a permission with the Go SDK.

## Versions

Versions are `0.x`: an API may still change between minor versions. Each package is released from its own tag (`go/v0.1.0`, `ts/v0.1.0`, `php/v0.1.0`, `dart/v0.1.0`, `flutter/v0.1.0`). The PHP package is published from the read-only [hobbit254/gatekeeper-laravel](https://github.com/hobbit254/gatekeeper-laravel), which the release copies from `php/`; send changes here.

## Development

Every SDK passes the same contract vectors in [`contract/vectors.json`](contract/vectors.json), regenerated with `cd go && go run ./internal/contractgen > ../contract/vectors.json`.

**Test data only:** the keys, tokens, API keys (`gk_live_…`) and secrets in `contract/` and in the tests were made for those tests and protect nothing.

- Go: `cd go && go test ./...` (a `go.work` links the examples to this module)
- TypeScript: `npm ci && npm test -w ts` (npm workspaces link the examples to this package)
- PHP: `cd php && composer install && vendor/bin/phpunit`
- Dart: `cd dart && dart pub get && dart test`
- Flutter: `cd flutter && flutter pub get && flutter test` (`pubspec_overrides.yaml` uses `../dart`)

The admin clients are generated from the Gatekeeper server's OpenAPI document; changes to them come from there.

Before a pull request, the same checks CI runs:
- `go run ./tools/guidecheck check docs` checks the guide's pages, links and anchors.
- `tools/guidecheck/compile.sh go|ts|php|dart` compiles the guide's samples against the SDKs.
- `tools/release-dry-run.sh npm|dart|flutter|php|go` rehearses each package's release without publishing.

## Licence

[Apache-2.0](LICENSE)
