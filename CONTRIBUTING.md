# Contributing to NetCheck

Thanks for your interest in NetCheck! Bug reports, documentation fixes, new
diagnostics and UI improvements are all welcome.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Security problems must be reported privately, see [SECURITY.md](SECURITY.md).

## Ways to contribute

- **Report a bug** or **request a feature** with the issue templates.
- **Improve the docs**: if something in [docs/](docs/) was unclear while you
  installed or used NetCheck, a pull request is the best way to fix it.
- **Send code**: for anything bigger than a small fix, open an issue first so we
  can agree on the approach before you spend time on it.

## Repository layout

| Path | Contents |
|---|---|
| `cmd/netcheck` | API server, web UI host and probe controller (one binary) |
| `cmd/probe` | The probe that runs inside the short-lived Job (static Go binary, no shell) |
| `internal/` | Go packages: `api`, `auth`, `config`, `diagnostics`, `k8s`, `probes`, `scheduler`, `store` |
| `web/` | React + TypeScript UI built with the Cloudscape Design System |
| `chart/netcheck` | Helm chart, the only supported way to deploy |
| `test/integration` | End-to-end tests against a local kind + Calico cluster |
| `docs/` | User, administration, installation and design documentation |

## Development environment

You need:

- Go 1.27
- Node.js 24
- Helm 3.14+ or 4.x (chart checks)
- Docker and [kind](https://kind.sigs.k8s.io/) (only for the integration lab)

```bash
make web-install   # npm ci in web/
make test          # Go unit tests (with -race) and frontend tests (Vitest)
make lint          # gofmt, go vet, ESLint and TypeScript type checks
make helm-lint     # helm lint, rendering and the "must fail" chart cases
```

> Run Go commands with explicit package paths (`./cmd/... ./internal/...`), not
> `./...`: `web/node_modules` can contain unrelated Go code.

### Running the UI and API locally

```bash
export NETCHECK_BOOTSTRAP_ADMIN_PASSWORD='choose-a-local-password'
make run-local     # http://127.0.0.1:8080, user "admin"
```

Without a cluster every test ends as an *infrastructure error*: NetCheck never
fakes connectivity results. For real tests use the lab below. For frontend work
you can also run `npm run dev` in `web/` (Vite proxies `/api` to port 8080).

### Integration lab (kind + Calico)

The lab is a local kind cluster with Calico, so NetworkPolicies are really
enforced, plus sample namespaces with different policies:

```bash
make lab-up        # kind cluster, Calico, local registry and fixtures
make lab-deploy    # build the images and install the chart by digest
kubectl --context kind-netcheck-lab -n netcheck port-forward svc/netcheck 8080:8080
NETCHECK_URL=http://127.0.0.1:8080 make test-integration
make lab-down      # remove everything
```

See [test/integration/README.md](test/integration/README.md) for what the
fixtures and the tests cover.

### Documentation screenshots

The images in `docs/images/` come from the real interface. With the lab running
behind its Gateway (`make lab-gateway lab-deploy` and a port-forward of the
Gateway to 8443), regenerate them with:

```bash
make docs-screenshots
```

It creates demo users in the lab, walks the user and administrator guides and
restores the destination policy at the end.

## Coding guidelines

- **Security first.** The probe never runs a shell or arbitrary commands, never
  gets a Kubernetes token or cloud credentials, and every destination is checked
  against the destination policy before any packet is sent. Changes that weaken
  any of this need a design discussion first ([docs/security.md](docs/security.md)).
- **Never invent results.** If something cannot be measured, report it as such
  (for example an infrastructure error), do not guess.
- **Go:** `gofmt`, small packages, errors wrapped with context, table tests.
- **TypeScript:** strict mode, Cloudscape components, no `dangerouslySetInnerHTML`.
- **UI text:** every string goes through `web/src/i18n`. Add each new key to
  both `en.ts` (default) and `es.ts`; the type checker fails if one is missing.
- **Helm chart:** new values need a comment in `values.yaml`; anything that can
  break a cluster should fail early in `_helpers.tpl` with a clear message, with
  a case in `chart/check.sh`.
- **Tests:** add unit tests next to the code you change. Changes that touch
  Kubernetes behavior should also extend `test/integration`.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Keep pull requests focused; split unrelated changes.
3. Make sure `make lint test helm-lint` passes.
4. Update the documentation when behavior changes. Do not edit `CHANGELOG.md`:
   it is generated from the pull request titles.
5. Describe *what* and *why* in the pull request; screenshots help for UI changes.

Pull requests are squash-merged, and the **pull request title** becomes the commit
message. It must follow [Conventional Commits](https://www.conventionalcommits.org/)
(a check enforces it), because it decides the next version and the changelog entry:

| Title | Effect on the next release |
|---|---|
| `feat: add UDP checks` | New minor version, listed under *Features* |
| `fix(probe): report the node IP for firewall tickets` | New patch version, listed under *Bug Fixes* |
| `feat!: rename the destinations values` (or a `BREAKING CHANGE:` footer) | Breaking change (minor while the version is 0.x) |
| `docs:`, `perf:`, `deps:`, `revert:` | Listed in the changelog |
| `chore:`, `ci:`, `test:`, `refactor:`, `build:` | Not listed |

## Releases

Releases are automated with [release-please](https://github.com/googleapis/release-please)
in the [release workflow](.github/workflows/release.yml):

1. Every merge to `main` updates an open **release pull request** with the next
   version (in `chart/netcheck/Chart.yaml`, `version.txt` and the install
   commands of the docs) and the new `CHANGELOG.md` entry.
2. A maintainer reviews and merges it when a release is due. That creates the
   `vX.Y.Z` tag and the GitHub release, so `main` always carries the latest
   released version.
3. The workflow then builds the multi-architecture images, pushes them to
   `ghcr.io/hgeorge123` (and Docker Hub, see below) with an SBOM and build
   provenance, signs them with Sigstore, writes their digests into the published
   chart, pushes and signs the chart (`oci://ghcr.io/hgeorge123/charts/netcheck`)
   and adds every digest to the release notes.

Nobody creates tags or edits versions by hand.

Repository settings the workflow needs:

- **Settings → Actions → General → Workflow permissions:** allow GitHub Actions
  to create and approve pull requests.
- **Docker Hub (optional):** the Actions secrets `DOCKERHUB_USERNAME` and
  `DOCKERHUB_TOKEN` (a personal access token with read and write access). Both
  registries receive the same build, so the digests are identical. Without these
  secrets the published chart points to GHCR.
- **`RELEASE_PLEASE_TOKEN` (optional):** a fine-grained token with contents and
  pull requests write access. GitHub does not run CI on pull requests opened with
  the default `GITHUB_TOKEN`, so set it to get checks on the release pull request.

## License

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
