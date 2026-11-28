#!/usr/bin/env bash
# Prints "<package> <version>" for a release tag, or fails when the tag can't
# be released (ADR-0135, ADR-0156):
#   tools/release-version.sh ts/v0.2.0
# The version must match the package's manifest; Go and Packagist take it from
# the tag. A gkgin tag needs the core version gkgin requires to be tagged first.
# Run from the repository root, with its tags fetched.
set -euo pipefail
fail() { echo "::error::$*" >&2; exit 1; }
ref="${1:?usage: release-version.sh <tag>}"

case "$ref" in
  go/gkgin/v*) pkg=gkgin; ver="${ref#go/gkgin/v}" ;; # a nested module's tags carry its path
  */v*) pkg="${ref%%/*}"; ver="${ref#*/v}" ;;
  *) fail "not a release tag: $ref" ;;
esac
[[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || fail "$ref: $ver isn't a semantic version"

case "$pkg" in
  ts) have=$(jq -r .version ts/package.json) ;;
  dart|flutter) have=$(sed -n 's/^version: //p' "$pkg/pubspec.yaml") ;;
  go|php) have="$ver" ;;
  gkgin)
    have="$ver"
    core=$(sed -n 's#^[[:space:]]*github.com/hobbit254/gatekeeper-sdk/go \(v[^ ]*\)$#\1#p' go/gkgin/go.mod)
    [ -n "$core" ] || fail "go/gkgin/go.mod doesn't require github.com/hobbit254/gatekeeper-sdk/go"
    git rev-parse -q --verify "refs/tags/go/$core" >/dev/null ||
      fail "gkgin requires github.com/hobbit254/gatekeeper-sdk/go $core, which has no go/$core tag: release the core module first"
    ;;
  *) fail "unknown package $pkg in $ref" ;;
esac
[ "$have" = "$ver" ] || fail "tag $ref but $pkg is at $have"
echo "$pkg $ver"
