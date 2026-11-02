#!/usr/bin/env bash
# Writes the release images into chart/netcheck/values.yaml, changing only the
# repository, tag and digest lines of the image and probeImage blocks (comments
# and formatting are kept). Then renders the chart and checks both references.
#
# Usage: pin-images.sh VERSION APP_REPO APP_DIGEST PROBE_REPO PROBE_DIGEST
set -euo pipefail

version="$1" app_repo="$2" app_digest="$3" probe_repo="$4" probe_digest="$5"
values="$(dirname "$0")/../../chart/netcheck/values.yaml"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid version: ${version}" >&2; exit 1; }
for v in "$app_repo" "$probe_repo"; do
  [ -n "$v" ] || { echo "empty image repository" >&2; exit 1; }
done
for d in "$app_digest" "$probe_digest"; do
  [[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "invalid image digest: ${d}" >&2; exit 1; }
done

awk -v ver="$version" -v ar="$app_repo" -v ad="$app_digest" -v pr="$probe_repo" -v pd="$probe_digest" '
  /^[A-Za-z]/ { block = $1 }
  block == "image:" && /^  repository:/ { print "  repository: " ar; n++; next }
  block == "image:" && /^  tag:/ { print "  tag: \"" ver "\""; n++; next }
  block == "image:" && /^  digest:/ { print "  digest: \"" ad "\""; n++; next }
  block == "probeImage:" && /^  repository:/ { print "  repository: " pr; n++; next }
  block == "probeImage:" && /^  tag:/ { print "  tag: \"" ver "\""; n++; next }
  block == "probeImage:" && /^  digest:/ { print "  digest: \"" pd "\""; n++; next }
  { print }
  END { if (n != 6) { print "expected 6 image lines in values.yaml, found " n > "/dev/stderr"; exit 1 } }
' "$values" > "$values.tmp"
mv "$values.tmp" "$values"

rendered="$(helm template netcheck "$(dirname "$values")" --set httpRoute.enabled=false)"
for ref in "${app_repo}:${version}@${app_digest}" "${probe_repo}:${version}@${probe_digest}"; do
  grep -qF "$ref" <<< "$rendered" || { echo "the rendered chart does not use ${ref}" >&2; exit 1; }
done
echo "pinned ${app_repo}:${version}@${app_digest} and ${probe_repo}:${version}@${probe_digest}"
