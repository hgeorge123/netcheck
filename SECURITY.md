# Security Policy

NetCheck runs inside Kubernetes clusters with permission to create Jobs in other
namespaces, so we take security reports seriously.

## Supported versions

Security fixes are released for the latest minor version. Please upgrade to the
latest release before reporting an issue.

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/hgeorge123/netcheck/security/advisories/new)
("Report a vulnerability" in the Security tab). Include:

- the NetCheck version (Administration > System and versions, or the image digest),
- the Kubernetes version and CNI,
- the steps to reproduce and the impact you observed.

You should receive an answer within 7 days. Once the issue is confirmed we will
prepare a fix, publish a release and a security advisory, and credit you unless
you prefer to stay anonymous.

## Scope

In scope, among others:

- escaping the probe sandbox (running anything other than the fixed checks,
  privilege escalation, reading Secrets or service account tokens);
- bypassing the destination policy or the platform protections (cloud metadata,
  Kubernetes API server);
- bypassing namespace authorization, the admission policies or RBAC limits;
- authentication or session flaws in the web UI and API.

Out of scope: findings that require cluster-admin access to begin with, and
denial of service through the documented rate limits.

## Hardening recommendations

See [docs/security.md](docs/security.md) for the security model and the
recommended production settings (HTTPS-only exposure, IMDSv2 with hop limit 1 on
the nodes, digest-pinned images, and changing the initial admin password right
after installing).
