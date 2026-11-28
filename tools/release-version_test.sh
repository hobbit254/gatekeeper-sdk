#!/usr/bin/env bash
# Tests tools/release-version.sh against a throwaway clone (ADR-0156):
#   tools/release-version_test.sh
set -euo pipefail
root=$(git rev-parse --show-toplevel)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git clone -q "$root" "$tmp/repo"
cp "$root/tools/release-version.sh" "$tmp/repo/tools/release-version.sh" # the copy under test, even if uncommitted
cd "$tmp/repo"
git tag -l | xargs -r git tag -d >/dev/null # start from no tags

failures=0
ok() { # ok <tag> <want>
  local got
  if got=$(tools/release-version.sh "$1" 2>&1) && [ "$got" = "$2" ]; then echo "ok    $1 -> $got"
  else echo "FAIL  $1: want \"$2\", got \"$got\""; failures=$((failures + 1)); fi
}
refused() { # refused <tag> <part of the message>
  local got
  if got=$(tools/release-version.sh "$1" 2>&1); then echo "FAIL  $1: accepted ($got)"; failures=$((failures + 1))
  elif grep -qF "$2" <<<"$got"; then echo "ok    $1 refused"
  else echo "FAIL  $1: refused without \"$2\": $got"; failures=$((failures + 1)); fi
}

ts=$(jq -r .version ts/package.json)
dart=$(sed -n 's/^version: //p' dart/pubspec.yaml)
core=$(sed -n 's#^[[:space:]]*github.com/hobbit254/gatekeeper-sdk/go \(v[^ ]*\)$#\1#p' go/gkgin/go.mod)

ok "go/v1.2.3" "go 1.2.3"
ok "php/v0.4.0" "php 0.4.0"
ok "ts/v$ts" "ts $ts"
ok "dart/v$dart" "dart $dart"
refused "ts/v99.0.0" "is at $ts"
refused "go/vbanana" "isn't a semantic version"
refused "go/v1.2" "isn't a semantic version"
refused "rust/v1.0.0" "unknown package"
refused "v1.0.0" "not a release tag"
refused "go/gkgin/v0.1.0" "release the core module first"
git tag "go/$core"
ok "go/gkgin/v0.1.0" "gkgin 0.1.0"
refused "go/gkgin/v0.1" "isn't a semantic version"

[ "$failures" -eq 0 ] || { echo "$failures failure(s)"; exit 1; }
echo "release-version: all cases pass"
