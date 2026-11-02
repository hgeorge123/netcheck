# Review guidelines for NetCheck

NetCheck runs short-lived probe Jobs in other teams' namespaces and sends traffic to destinations that users choose.
Review every change with that in mind: a small mistake can turn it into an SSRF proxy or a privilege escalation.
The design is described in `docs/security.md` and `docs/architecture.md`.

## Report as high severity

- The probe (`cmd/probe`, `internal/probes`) running a shell, an external command or user-controlled data: it must
  implement checks with Go primitives and send only fixed packets (UDP: empty datagram, DNS query or NTP request).
- A destination reached without passing the destination policy first, or a resolved IP that is not checked
  (DNS rebinding). Cloud metadata, the API server, loopback and link-local must stay denied.
- The probe Pod template (`internal/k8s/jobs.go`) gaining privileges, capabilities, host access, volumes, a
  ServiceAccount token, `env.valueFrom`/`envFrom`, or anything the admission policies in `chart/netcheck/templates`
  would reject. Template and policies must change together.
- RBAC granting `pods/create`, `pods/exec`, `secrets`, RBAC objects or NetworkPolicy writes to the controller.
- Passwords, session tokens or secrets in logs, audit events, API responses or URLs; authorization not checked in
  the backend; mutating endpoints without the CSRF checks.
- Results that are invented or inferred instead of measured. Anything not measured must be reported as such.

## Also check

- Tests next to the changed code (Go table tests, Vitest). Kubernetes behavior changes should extend
  `test/integration`; chart failures need a case in `chart/check.sh`.
- Every new UI string in both `web/src/i18n/en.ts` and `web/src/i18n/es.ts`. UI built with Cloudscape components, no
  `dangerouslySetInnerHTML`.
- New Helm values documented in `values.yaml`; unsafe combinations failing early in `_helpers.tpl`.
- Documentation in `docs/` updated when behavior changes. `CHANGELOG.md` is generated: it must not be edited by hand.
- Pull request titles follow Conventional Commits: they become the changelog entry.

## Release pull requests

Pull requests titled `chore: release X.Y.Z` (branch `release-please--branches--main--components--netcheck`) are
generated. Their first commit only bumps versions and the changelog; a second commit,
`chore: pin the X.Y.Z images in the chart values`, adds the image tags and digests to `chart/netcheck/values.yaml`
after the release workflow builds them. The required `release/images` check stays pending until then. Review these
pull requests on their latest commit: before the pin commit the values still show the previous release by design.
On the latest commit, check that `Chart.yaml`, `version.txt`, `.release-please-manifest.json`, the documentation
commands and both image tags in `values.yaml` show the same version, and that both images have a `sha256:` digest.
