# NetCheck documentation

| Guide | Contents |
|---|---|
| [features.md](features.md) | Every feature, with a link to how to use it |
| [install.md](install.md) | Step-by-step installation on any Kubernetes cluster, installing with Argo CD, upgrades and a local kind laboratory |
| [install-eks.md](install-eks.md) | Step-by-step installation on Amazon EKS |
| [install-aks.md](install-aks.md) | Step-by-step installation on Azure Kubernetes Service (AKS) |
| [user-guide.md](user-guide.md) | Creating tests, firewall ticket mode and reading the results |
| [admin-guide.md](admin-guide.md) | What gets deployed, users, namespaces, destination policy, certificate authorities, proxies, check types, data retention, operations and troubleshooting |
| [sso.md](sso.md) | Single sign-on with an OIDC provider or with GitHub, GitLab, LDAP and SAML through Dex; access rules |
| [cli.md](cli.md) | API tokens and `netcheck-cli` to run tests from pipelines |
| [security.md](security.md) | Security model and residual risks |
| [architecture.md](architecture.md) | Components, life of a test and design choices |

Screenshots live in [images/](images) and are generated from the real interface with `make docs-screenshots`
(see [CONTRIBUTING.md](../CONTRIBUTING.md)).
