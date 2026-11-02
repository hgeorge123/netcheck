#!/usr/bin/env bash
# Sets the "release/images" commit status on the release pull request. Make it
# a required check on main so the pull request cannot be merged before its
# images are built and pinned.
#
# Usage: release-status.sh SHA pending|success|failure|error DESCRIPTION
# Needs GH_TOKEN and GH_REPO.
set -euo pipefail

sha="$1" state="$2" description="${3:0:140}"
gh api --silent -X POST "repos/${GH_REPO:?}/statuses/${sha}" \
  -f state="${state}" -f context="release/images" -f description="${description}" \
  -f target_url="${GITHUB_SERVER_URL:-https://github.com}/${GH_REPO}/actions/runs/${GITHUB_RUN_ID:-}"
echo "release/images: ${state} on ${sha:0:7} (${description})"
