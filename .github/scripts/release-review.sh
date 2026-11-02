#!/usr/bin/env bash
# Keeps the release pull request in draft while its images are built, so
# neither a merge nor an automatic Copilot review sees the version bump
# without the pinned images.
#
# Usage: release-review.sh draft|ready PR_NUMBER
#   draft  turns the pull request back into a draft (images being rebuilt)
#   ready  marks a draft ready for review and requests a Copilot review of
#          the pinned state; the request needs REVIEW_TOKEN, a token of a
#          user with Copilot code review (RELEASE_PLEASE_TOKEN), and is
#          skipped without it
# Needs GH_TOKEN and GH_REPO.
set -euo pipefail

action="$1" pr="$2"
copilot="copilot-pull-request-reviewer[bot]"
is_draft="$(gh pr view "${pr}" --json isDraft --jq .isDraft)"

case "${action}" in
  draft)
    [ "${is_draft}" = true ] || gh pr ready "${pr}" --undo
    ;;
  ready)
    # Only on the draft -> ready transition: one review per pinned build.
    if [ "${is_draft}" = false ]; then
      echo "#${pr} is already ready for review"
      exit 0
    fi
    gh pr ready "${pr}"
    if [ -z "${REVIEW_TOKEN:-}" ]; then
      echo "no REVIEW_TOKEN: Copilot review not requested"
      exit 0
    fi
    requested() {
      GH_TOKEN="${REVIEW_TOKEN}" gh api "repos/${GH_REPO}/pulls/${pr}/requested_reviewers" \
        --jq '[.users[].login] | index("'"${copilot}"'") != null'
    }
    if [ "$(requested)" = true ]; then
      echo "Copilot review already requested"
    elif GH_TOKEN="${REVIEW_TOKEN}" gh api --silent -X POST "repos/${GH_REPO}/pulls/${pr}/requested_reviewers" \
        -f "reviewers[]=${copilot}" && [ "$(requested)" = true ]; then
      echo "Copilot review requested on #${pr}"
    else
      # Never fail the release for this: the images are already pinned.
      echo "::warning::could not request a Copilot review on #${pr}; request it from the pull request page"
    fi
    ;;
  *)
    echo "usage: $0 draft|ready PR_NUMBER" >&2
    exit 2
    ;;
esac
