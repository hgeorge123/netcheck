# Sourced by the release jobs: sets the image repositories of a release and
# exports them to the following steps. Each job computes them itself because
# GitHub drops job outputs that contain a secret value (the Docker Hub user).
#
# Needs REGISTRY; DOCKERHUB_USERNAME is optional.
#   APP_REPO / PROBE_REPO    repository the published chart points to
#   APP_REPOS / PROBE_REPOS  every repository the images are pushed to

APP_REPOS="${REGISTRY:?}/netcheck"
PROBE_REPOS="${REGISTRY}/netcheck-probe"
APP_REPO="${APP_REPOS}"
PROBE_REPO="${PROBE_REPOS}"
# The published chart points to Docker Hub when it is configured.
if [ -n "${DOCKERHUB_USERNAME:-}" ]; then
  APP_REPO="docker.io/${DOCKERHUB_USERNAME}/netcheck"
  PROBE_REPO="docker.io/${DOCKERHUB_USERNAME}/netcheck-probe"
  APP_REPOS="${APP_REPOS} ${APP_REPO}"
  PROBE_REPOS="${PROBE_REPOS} ${PROBE_REPO}"
fi
{
  echo "APP_REPO=${APP_REPO}"
  echo "PROBE_REPO=${PROBE_REPO}"
  echo "APP_REPOS=${APP_REPOS}"
  echo "PROBE_REPOS=${PROBE_REPOS}"
} >> "${GITHUB_ENV:-/dev/null}"
