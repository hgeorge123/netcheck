#!/usr/bin/env bash
# Builds the netcheck-cli release binaries into OUT_DIR. Used by the release
# workflow, by CI and by `make cli`.
#
#   tools/build-cli.sh VERSION OUT_DIR      (TARGETS="os/arch ..." to limit)
#
# Windows binaries carry a version resource, the NetCheck icon and an
# application manifest (go-winres, pinned below) and keep their symbols:
# stripped Go executables without that metadata are often flagged by
# antivirus machine-learning heuristics. The release workflow then signs them
# with Authenticode when signing is configured. Other targets are stripped.
set -euo pipefail

VERSION="${1:?usage: build-cli.sh VERSION OUT_DIR}"
OUT="${2:?usage: build-cli.sh VERSION OUT_DIR}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GO="${GO:-go}"
GO_WINRES="github.com/tc-hib/go-winres@v0.3.3"
TARGETS="${TARGETS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64}"

# Windows versions are four numbers: 1.2.3 -> 1.2.3.0 (pre-releases keep the
# numeric part; anything else, such as "dev", is 0.0.0.0).
numeric="$(printf '%s' "${VERSION}" | sed -E 's/^v//; s/[-+].*$//')"
[[ "${numeric}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || numeric=0.0.0

mkdir -p "${OUT}"
OUT="$(cd "${OUT}" && pwd)"
CLI="${ROOT}/cmd/netcheck-cli"
cleanup() { rm -f "${CLI}"/rsrc_windows_*.syso; }
trap cleanup EXIT

cd "${ROOT}"
for target in ${TARGETS}; do
  os="${target%/*}" arch="${target#*/}" ext="" ldflags="-X main.version=${VERSION}"
  if [ "${os}" = windows ]; then
    ext=".exe"
    # Resources from cmd/netcheck-cli/winres/winres.json; go build links
    # rsrc_windows_<arch>.syso into the Windows build only.
    (cd "${CLI}" && "${GO}" run "${GO_WINRES}" make --in winres/winres.json --arch "${arch}" --out rsrc \
      --product-version "${numeric}.0" --file-version "${numeric}.0")
  else
    ldflags="-s -w ${ldflags}"
  fi
  CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" "${GO}" build -trimpath -ldflags "${ldflags}" \
    -o "${OUT}/netcheck-cli_${VERSION}_${os}_${arch}${ext}" ./cmd/netcheck-cli
  cleanup
done
