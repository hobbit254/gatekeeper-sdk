#!/usr/bin/env bash
# Compiles the guide's whole-file samples for one language against the SDKs in
# this checkout (ADR-0135): tools/guidecheck/compile.sh go|ts|php|dart
# Run from the repository root; ts needs `npm ci` first, dart needs Flutter.
set -euo pipefail
lang=${1:?usage: compile.sh go|ts|php|dart}
root=$(pwd)
out="$root/.samples/$lang"
rm -rf "$out" && mkdir -p "$out"
go run ./tools/guidecheck samples docs "$lang" "$out" >/dev/null

case "$lang" in
go)
  cp go/go.sum "$out/"
  printf 'module samples\n\ngo 1.26.0\n\nrequire github.com/hobbit254/gatekeeper-sdk/go v0.1.0\n\nreplace github.com/hobbit254/gatekeeper-sdk/go => %s/go\n' "$root" >"$out/go.mod"
  (cd "$out" && GOWORK=off GOFLAGS=-mod=mod go vet ./...)
  ;;
ts)
  npm run build -w ts >/dev/null
  echo '{"type":"module"}' >"$out/package.json"
  files=$(cd "$out" && ls ./*.ts | sed 's/.*/"&"/' | paste -sd, -)
  cat >"$out/tsconfig.json" <<EOF
{"compilerOptions":{"target":"ES2022","module":"NodeNext","moduleResolution":"NodeNext","strict":true,"noEmit":true,
"skipLibCheck":true,"lib":["ES2022","DOM"],"types":["node"],"typeRoots":["$root/node_modules/@types"]},"files":[$files]}
EOF
  npx tsc -p "$out/tsconfig.json"
  ;;
php)
  for f in "$out"/*.php; do php -l "$f" >/dev/null; done
  ;;
dart)
  mkdir -p "$out/lib" && mv "$out"/*.dart "$out/lib/"
  cat >"$out/pubspec.yaml" <<EOF
name: guide_samples
publish_to: none
environment:
  sdk: ">=3.8.0 <4.0.0"
dependencies:
  flutter:
    sdk: flutter
  gatekeeper_flutter:
    path: $root/flutter
  gatekeeper_sdk:
    path: $root/dart
dependency_overrides:
  gatekeeper_sdk:
    path: $root/dart
EOF
  (cd "$out" && flutter pub get >/dev/null && flutter analyze --no-fatal-infos .)
  ;;
esac
echo "the guide's $lang samples compile"
