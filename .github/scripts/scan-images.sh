#!/usr/bin/env bash
# Scans release images with Grype before they are pinned in the release pull
# request. Fails when an image has a High or Critical vulnerability that
# already has a fix, so the release cannot be merged until the base image or
# the dependency is updated.
#
# Grype runs in its own container (pinned by digest) with no access to the
# workflow's tokens or files. Accepted risks can be listed in .grype.yaml
# (https://github.com/anchore/grype#specifying-matches-to-ignore).
#
# Usage: scan-images.sh IMAGE@DIGEST...
set -euo pipefail

GRYPE="anchore/grype:v0.121.0@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea"
PLATFORMS=(linux/amd64 linux/arm64)
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

mount=() config=()
if [ -f .grype.yaml ]; then
  mount=(-v "${PWD}/.grype.yaml:/grype.yaml:ro") config=(-c /grype.yaml)
fi

failed=0
echo "## Vulnerability scan (Grype, High and Critical with a fix)" >> "${SUMMARY}"
for image in "$@"; do
  for platform in "${PLATFORMS[@]}"; do
    out="$(docker run --rm "${mount[@]}" "${GRYPE}" "registry:${image}" "${config[@]}" --platform "${platform}" \
      --only-fixed --fail-on high -o table 2>&1)" && status=passed || status=failed
    [ "${status}" = failed ] && failed=1
    { echo; echo "### ${image%%@*} (${platform}): ${status}"; echo; echo '```'; echo "${out}"; echo '```'; } >> "${SUMMARY}"
    echo "${image%%@*} (${platform}): ${status}"
    [ "${status}" = failed ] && echo "${out}"
  done
done

if [ "${failed}" = 1 ]; then
  echo "::error::the release images have fixable High or Critical vulnerabilities; see the job summary"
  exit 1
fi
