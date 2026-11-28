#!/usr/bin/env bash
# Rehearses every package's release without publishing anything (ADR-0135):
#   tools/release-dry-run.sh npm|dart|flutter|php|go|gkgin
# Run from the repository root. npm needs `npm ci`; php needs full git history.
set -euo pipefail
fail() { echo "release dry run: $*" >&2; exit 1; }

case "${1:?usage: release-dry-run.sh npm|dart|flutter|php|go|gkgin}" in
npm)
  npm run build -w ts >/dev/null
  npm pack --dry-run --json -w ts 2>/dev/null | node -e '
    const out = JSON.parse(require("fs").readFileSync(0, "utf8"));
    const files = (Array.isArray(out) ? out[0] : Object.values(out)[0]).files.map((f) => f.path); // npm 10 vs 11
    const need = ["package.json", "README.md", "LICENSE", "dist/index.js", "dist/index.d.ts", "dist/browser.js", "dist/headless.js", "dist/admin/index.js"];
    const missing = need.filter((f) => !files.includes(f));
    const stray = files.filter((f) => /^(src|test|node_modules)\//.test(f));
    if (missing.length || stray.length) { console.error("missing:", missing, "should not ship:", stray); process.exit(1); }
    console.log(`npm: ${files.length} files, as expected`);'
  ;;
dart)
  (cd dart && dart pub get >/dev/null && dart pub publish --dry-run)
  ;;
flutter)
  if ! curl -fsS https://pub.dev/api/packages/gatekeeper_sdk >/dev/null 2>&1; then
    echo "::notice::flutter: skipped until gatekeeper_sdk is on pub.dev (its version dependency can't resolve yet)"
    exit 0
  fi
  tmp=$(mktemp -d) && cp -R flutter/. "$tmp/" && rm -f "$tmp/pubspec_overrides.yaml"
  (cd "$tmp" && flutter pub get >/dev/null && dart pub publish --dry-run)
  ;;
php)
  (cd php && composer validate --no-check-publish --no-interaction)
  branch="release-dry-run-php-$$"
  git subtree split --prefix=php -b "$branch" >/dev/null 2>&1
  trap 'git branch -D "$branch" >/dev/null 2>&1' EXIT
  root=$(git ls-tree --name-only "$branch")
  for f in composer.json src LICENSE README.md; do grep -qx "$f" <<<"$root" || fail "php: the split repository's root has no $f"; done
  name=$(git show "$branch:composer.json" | sed -n 's/.*"name": *"\([^"]*\)".*/\1/p' | head -1)
  [ "$name" = "hobbit254/gatekeeper-laravel" ] || fail "php: the split's composer.json is named $name"
  echo "php: Packagist would read hobbit254/gatekeeper-laravel at the split's root"
  ;;
go)
  (cd go && GOWORK=off go build ./... && GOWORK=off go vet ./...)
  want=$(sed -n 's#^require github.com/hobbit254/gatekeeper-sdk/go \(v[^ ]*\)$#\1#p' examples/go-api/go.mod)
  have=$(sed -n 's#^replace github.com/hobbit254/gatekeeper-sdk/go \(v[^ ]*\) => ./go$#\1#p' go.work)
  [ -n "$want" ] && [ "$want" = "$have" ] || fail "go: the example requires $want but go.work replaces $have"
  # A copied example, against a clean copy of the module at the version it names.
  tmp=$(mktemp -d) && cp -R examples/go-api "$tmp/app" && cp -R go "$tmp/module"
  (cd "$tmp/app" && go mod edit -replace "github.com/hobbit254/gatekeeper-sdk/go@$want=../module" \
    && GOWORK=off GOFLAGS=-mod=mod go build -o /dev/null .)
  echo "go: the module and a copied example build without go.work ($want)"
  ;;
gkgin)
  # gkgin is its own module (ADR-0153), released after the core version it requires (ADR-0156).
  want=$(sed -n 's#^[[:space:]]*github.com/hobbit254/gatekeeper-sdk/go \(v[^ ]*\)$#\1#p' go/gkgin/go.mod)
  have=$(sed -n 's#^replace github.com/hobbit254/gatekeeper-sdk/go \(v[^ ]*\) => ./go$#\1#p' go.work)
  [ -n "$want" ] && [ "$want" = "$have" ] || fail "gkgin: go/gkgin/go.mod requires $want but go.work replaces $have"
  tmp=$(mktemp -d) && cp -R go/gkgin "$tmp/gkgin" && cp -R go "$tmp/module" && rm -rf "$tmp/module/gkgin"
  (cd "$tmp/gkgin" && go mod edit -replace "github.com/hobbit254/gatekeeper-sdk/go@$want=../module" \
    && GOWORK=off GOFLAGS=-mod=mod go vet ./... && GOWORK=off GOFLAGS=-mod=mod go test ./... >/dev/null)
  echo "gkgin: a copy builds and passes its tests without go.work, against the core module at $want"
  ;;
*) fail "unknown package $1" ;;
esac
