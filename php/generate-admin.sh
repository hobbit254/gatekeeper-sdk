#!/bin/sh
# Generates the PHP admin client into $1/lib from sdk/admin-openapi.json with
# the pinned openapi-generator image (FR-D13, ADR-0088). Run from the repo root.
set -eu
out=$(cd "$1" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/sdk:/sdk:ro" -v "$tmp:/out" openapitools/openapi-generator-cli:v7.10.0 generate \
  -i /sdk/admin-openapi.json -g php -o /out --skip-validate-spec \
  --additional-properties=invokerPackage='Gatekeeper\Admin',srcBasePath=lib,variableNamingConvention=snake_case,hideGenerationTimestamp=true \
  --global-property apiTests=false,modelTests=false,apiDocs=false,modelDocs=false >/dev/null
rm -rf "$out/lib"
cp -R "$tmp/lib" "$out/lib"
