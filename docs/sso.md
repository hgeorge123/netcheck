# Single sign-on (SSO)

With single sign-on, people sign in to NetCheck with the account of your organization instead of a NetCheck password.
NetCheck speaks **OpenID Connect (OIDC)**, so it works directly with Microsoft Entra ID, Okta, Keycloak, Google, Auth0
and any other OIDC provider. For **GitHub**, **GitLab**, **LDAP** or **SAML**, the chart can deploy **Dex** next to
NetCheck, the same way Argo CD does: Dex signs people in with those services and hands NetCheck a standard OIDC
identity with their groups.

Local NetCheck accounts keep working alongside SSO, including the `admin` account created at installation, which is
your way in if the identity provider is down.

## Contents

1. [How it works](#1-how-it-works)
2. [GitHub, LDAP and others through the bundled Dex](#2-github-ldap-and-others-through-the-bundled-dex)
3. [An OIDC provider (Entra ID, Okta, Keycloak, Google…)](#3-an-oidc-provider-entra-id-okta-keycloak-google)
4. [Access rules: who gets what](#4-access-rules-who-gets-what)
5. [Day-to-day](#5-day-to-day)
6. [Troubleshooting](#6-troubleshooting)
7. [Reference: values](#7-reference-values)

## 1. How it works

```
Browser ──► NetCheck "Sign in with GitHub" ──► Dex ──► GitHub (login, organizations and teams)
   ▲                                              │
   └──── NetCheck session ◄── ID token (user, groups) ◄─┘
```

1. The sign-in page shows **Sign in with &lt;provider&gt;** next to the username and password form.
2. The provider (or Dex) authenticates the person and sends NetCheck an ID token with their username and groups.
   NetCheck checks it (issuer, audience, signature, expiry, a one-time nonce and PKCE).
3. NetCheck evaluates the **access rules** (section 4). If at least one matches, it opens a normal NetCheck session
   with the role and namespaces of the matching rules; otherwise the person sees *no access rule grants you access*.
4. The account is created at the first sign-in and listed in **Administration → Users** as **SSO**. It has no
   NetCheck password: it can only sign in through the provider.

Permissions come only from the access rules, which you write **before** anyone signs in. They are recomputed at every
sign-in and whenever you change a rule, so adding someone to a group of the provider is enough to give them access
the next time they sign in.

## 2. GitHub, LDAP and others through the bundled Dex

You need a host name for NetCheck (the one of your Ingress or HTTPRoute). The examples use
`netcheck.example.com`. Sections 2.1 to 2.4 set up GitHub (organization `my-org`); 2.5 is LDAP or Active Directory, and
2.6 the other Dex connectors. The values of 2.3 (what the chart does with Dex) and the first rules of 2.4 apply to all
of them.

### 2.1 Create a GitHub OAuth App

In GitHub, open **your organization → Settings → Developer settings → OAuth Apps → New OAuth App** (an organization
owner can do it; a personal OAuth App works too):

| Field | Value |
|---|---|
| Application name | `NetCheck` |
| Homepage URL | `https://netcheck.example.com` |
| Authorization callback URL | `https://netcheck.example.com/dex/callback` |

Register it, copy the **Client ID**, and use **Generate a new client secret** to get the secret.

### 2.2 Store the credentials in a Secret

```bash
kubectl -n netcheck create secret generic netcheck-github \
  --from-literal=GITHUB_CLIENT_ID='<client id>' \
  --from-literal=GITHUB_CLIENT_SECRET='<client secret>'
```

The keys become environment variables of Dex; the connector configuration refers to them as `$GITHUB_CLIENT_ID` and
`$GITHUB_CLIENT_SECRET`, so no secret ends up in your values file.

### 2.3 Values

Add to your values file:

```yaml
auth:
  oidc:
    enabled: true
    providerName: GitHub            # button: "Sign in with GitHub"
    usernameClaim: preferred_username   # the GitHub login (e.g. octocat); "email" uses the primary e-mail
dex:
  enabled: true
  envSecret: netcheck-github
  connectors:
    - type: github
      id: github
      name: GitHub
      config:
        clientID: $GITHUB_CLIENT_ID
        clientSecret: $GITHUB_CLIENT_SECRET
        redirectURI: https://netcheck.example.com/dex/callback
        orgs:
          - name: my-org            # only members of my-org can sign in
        teamNameField: slug         # groups like "my-org:payments-team"
```

What the chart does with it:

- Deploys Dex (one small Pod, non-root, read-only file system, no Kubernetes token) and serves it at
  `https://netcheck.example.com/dex` through the **same** Ingress or HTTPRoute: no new DNS name or certificate.
- Creates the Secret `netcheck-oidc` with a random client secret shared by NetCheck and Dex (created once, kept on
  upgrades).
- Sets the issuer to `https://<first host>/dex` and the redirect URI to
  `https://<first host>/api/v1/auth/oidc/callback`. NetCheck reaches Dex inside the cluster for the token exchange.

Apply it with your usual `helm upgrade` (or `helmfile apply`). With the AWS Load Balancer Controller the ALB gets a
`/dex` rule in a minute or two.

> `networkPolicy.enabled` does not cover the bundled Dex yet: the chart refuses the combination. Use an external
> provider (section 3) if you need that policy.

### 2.4 Create the first rules and sign in

Before anyone can sign in with GitHub there must be at least one access rule:

1. Sign in with the local `admin` account.
2. Open **Administration → Access rules → Create rule**, for example *Group* `my-org:platform-team` → role
   **Administrator**, and *Group* `my-org:payments-team` → role **User**, namespaces `payments`.
3. Sign out and use **Sign in with GitHub**. The first time, GitHub asks to authorize the OAuth App for `my-org`.

Section 4 explains the rules in detail.

### 2.5 LDAP or Active Directory

The bundled Dex has an LDAP connector, the same one Argo CD uses. People click **Sign in with LDAP**, type their
directory username and password in a Dex page, and come back to NetCheck with the groups they belong to. NetCheck never
sees the password.

**Bind account.** Dex searches the directory with a read-only service account. Store its password in a Secret:

```bash
kubectl -n netcheck create secret generic netcheck-ldap --from-literal=LDAP_BIND_PW='<bind password>'
```

**Certificate authority.** For LDAPS (port 636, recommended) Dex must trust the certificate of the directory. The
chart does not mount extra files into Dex, so the CA goes inline, base64-encoded:

```bash
base64 -w0 corporate-ca.pem    # paste the output as rootCAData
```

**Values** (OpenLDAP-style directory):

```yaml
auth:
  oidc:
    enabled: true
    providerName: LDAP                    # button: "Sign in with LDAP"
    usernameClaim: preferred_username     # the uid; "email" uses the mail attribute
dex:
  enabled: true
  envSecret: netcheck-ldap
  connectors:
    - type: ldap
      id: ldap
      name: LDAP
      config:
        host: ldap.example.com:636
        rootCAData: <base64 of the CA>
        bindDN: cn=svc-netcheck,ou=services,dc=example,dc=com
        bindPW: $LDAP_BIND_PW
        usernamePrompt: Corporate username
        userSearch:
          baseDN: ou=people,dc=example,dc=com
          filter: "(objectClass=inetOrgPerson)"
          username: uid
          idAttr: uid
          emailAttr: mail
          nameAttr: cn
          preferredUsernameAttr: uid
        groupSearch:
          baseDN: ou=groups,dc=example,dc=com
          filter: "(objectClass=groupOfNames)"
          userMatchers:
            - userAttr: DN
              groupAttr: member
          nameAttr: cn                    # the group name your access rules use
```

For **Active Directory**, change the searches:

| Setting | Active Directory value |
|---|---|
| `bindDN` | The service account, e.g. `CN=svc-netcheck,OU=Service Accounts,DC=corp,DC=example` or `svc-netcheck@corp.example` |
| `userSearch.filter` | `(objectClass=person)` |
| `userSearch.username`, `idAttr`, `preferredUsernameAttr` | `sAMAccountName` (use `userPrincipalName` for `idAttr` if you prefer) |
| `groupSearch.filter` | `(objectClass=group)` |
| `groupSearch.userMatchers` | `userAttr: DN`, `groupAttr: member` |

Dex only sees **direct** group membership: a user in a group nested inside `netcheck-users` does not match a rule for
`netcheck-users`. Write rules for the groups people are direct members of.

**Coming from Argo CD.** Copy the `ldap` connector of the `dex.config` in `argocd-cm` into `dex.connectors` and make
two changes: the bind password becomes `$LDAP_BIND_PW` (Argo CD uses `$dex.ldap.bindPW` from `argocd-secret`), and a
CA file given with `rootCA:` (a path) becomes `rootCAData:` (the base64 content). Avoid `insecureSkipVerify: true`.

**Network.** The Dex Pod runs in the NetCheck namespace and must reach the directory (389 or 636). If the directory
only accepts some source addresses, allow the Pod or node addresses of the cluster.

Then sign in as the local `admin` and create access rules with the group names (`cn`) of your directory (section 4).
If someone cannot sign in, the Dex log says why (`kubectl -n netcheck logs deploy/netcheck-dex`): unknown user, wrong
password or a failed search; once Dex accepts the person, the NetCheck audit event `auth.login` lists the username and
groups NetCheck received.

This setup is tested in the local laboratory against OpenLDAP over LDAPS
(`LAB_SSO=ldap bash test/integration/lab.sh deploy`, see [test/integration/README.md](../test/integration/README.md)).

### 2.6 GitLab, SAML and others

Any [Dex connector](https://dexidp.io/docs/connectors/) works the same way: list it in `dex.connectors`, put its
secrets in the `dex.envSecret` Secret and refer to them as `$VARIABLE`. The groups that Dex sends depend on the
connector (GitLab groups, SAML attributes) and are what your access rules match.

## 3. An OIDC provider (Entra ID, Okta, Keycloak, Google…)

### 3.1 Register NetCheck at the provider

Create a web application / OIDC client with:

| Setting | Value |
|---|---|
| Redirect (callback) URI | `https://netcheck.example.com/api/v1/auth/oidc/callback` |
| Grant type | Authorization code (NetCheck also uses PKCE) |
| Scopes | `openid`, `profile`, `email` and, if the provider has it, `groups` |
| Groups | Include a `groups` claim in the **ID token** if you want group rules |

Provider notes:

| Provider | Issuer URL | Username claim | Groups |
|---|---|---|---|
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` | `preferred_username` (the UPN) | Add the *groups* optional claim; rules then use the group **object IDs** |
| Okta | `https://<org>.okta.com/oauth2/default` | `email` | Add a `groups` claim to the authorization server |
| Keycloak | `https://<keycloak>/realms/<realm>` | `preferred_username` or `email` | Add a *Group Membership* mapper named `groups` |
| Google | `https://accounts.google.com` | `email` | Not available: use user rules or "any authenticated user" |

### 3.2 Values

```bash
kubectl -n netcheck create secret generic netcheck-oidc --from-literal=client-secret='<client secret>'
```

```yaml
auth:
  oidc:
    enabled: true
    providerName: Microsoft
    issuerUrl: https://login.microsoftonline.com/<tenant-id>/v2.0
    clientId: <application (client) id>
    existingSecret: netcheck-oidc
    usernameClaim: preferred_username
```

NetCheck reads the provider endpoints from `<issuerUrl>/.well-known/openid-configuration`, so the NetCheck Pod must
reach the issuer over HTTPS (allow it if you use `networkPolicy.enabled` or an egress proxy). Then create the access
rules as in section 2.4.

## 4. Access rules: who gets what

**Administration → Access rules** lists the rules. Each one says *who* it applies to and *what* it grants:

| Applies to | Matches | Example |
|---|---|---|
| **Group** | Members of a group sent by the provider (not case-sensitive) | `my-org:payments-team`, an Entra group object ID |
| **User** | One username, as the provider sends it (not case-sensitive) | `octocat`, `ana@example.com` |
| **Any authenticated user** | Everybody the provider signs in | Read access to a sandbox namespace for the whole company |

And grants a role (**User**, **Administrator** or a custom role, [admin guide §21](admin-guide.md#21-roles)),
namespaces (a list or **all namespaces**, including future ones) and optionally the NetCheck namespace, exactly like a
local user.

How they combine:

- A person gets **every** rule that matches, each with its own namespaces: in each namespace they have the permissions
  of the rules given for that namespace only (a custom role given for `orders` never applies to `payments`). An
  administrator rule makes them administrator everywhere.
- An administrator can also add an SSO account to a local group ([admin guide §22](admin-guide.md#22-groups)) once it
  has signed in; the group's role adds up the same way.
- **No matching rule, no access.** Without any rule nobody can sign in with SSO, so you decide explicitly whether
  "anyone in the company" gets in (rule *Any authenticated user*) or only some groups.
- Changes apply **at once** to existing SSO accounts, using the groups of their last sign-in. If a change leaves an
  account without any rule, its sessions and API tokens are revoked.
- Group membership changes at the provider apply at the next sign-in.

Every rule change is recorded in the audit log (`access_rule.create`, `access_rule.update`, `access_rule.delete`).

## 5. Day-to-day

- **Users list:** SSO accounts show **SSO** in the *Sign-in* column. Editing one shows its groups and only allows
  enabling or disabling it: its role and namespaces belong to the rules. A disabled account cannot sign in even if a
  rule matches.
- **Passwords:** SSO accounts have none, so *Reset password* and *Change password* do not apply.
- **Names:** an SSO username cannot reuse the name of a local account; the person sees *your username already belongs
  to a local NetCheck account* until an administrator renames or deletes that account.
- **Emergency access:** the local `admin` account (and the recovery procedure of the
  [admin guide](admin-guide.md), Part III §5) works even when the provider or Dex is down.
- **API tokens** created by SSO users act with their current permissions and are revoked if they lose access.

## 6. Troubleshooting

| What the person sees | Likely cause | What to do |
|---|---|---|
| The provider shows *redirect URI mismatch* | The callback registered at the provider is not exactly the one NetCheck sends | GitHub with Dex: `https://<host>/dex/callback`. Other providers: `https://<host>/api/v1/auth/oidc/callback` |
| *No access rule grants you access* | No rule matches the username or groups | Check the audit event `auth.login` (reason `no access rule`): it lists the username and groups NetCheck received. Fix the rule |
| *Single sign-on could not be completed* | Issuer, client secret, clock or token problem | The NetCheck log has a `sso sign-in failed` line with the reason (`kubectl -n netcheck logs deploy/netcheck`) |
| *The single sign-on provider cannot be reached* | NetCheck cannot reach the issuer (DNS, egress, proxy) | Test from the NetCheck Pod network; with Dex check `kubectl -n netcheck get pods -l app.kubernetes.io/name=netcheck-dex` and its log |
| Groups are empty | The provider does not put groups in the ID token | Configure the groups claim (section 3.1) or set `auth.oidc.groupsClaim` to the claim it uses |
| `/dex` returns 404 at the ALB | The Ingress was rendered without Dex, or the ALB is still updating | `kubectl -n netcheck get ingress netcheck -o yaml` must have a `/dex` path |

## 7. Reference: values

| Value | Default | Meaning |
|---|---|---|
| `auth.oidc.enabled` | `false` | Turns SSO on |
| `auth.oidc.providerName` | `SSO` | Button label: "Sign in with &lt;providerName&gt;" |
| `auth.oidc.issuerUrl` | with Dex: `https://<first host>/dex` | Must match the `iss` of the ID tokens |
| `auth.oidc.clientId` | `netcheck` | Client ID at the provider |
| `auth.oidc.existingSecret` / `secretKey` | `""` / `client-secret` | Secret with the client secret. Empty: the chart creates `netcheck-oidc` from `clientSecret`, or a random value for Dex. With Argo CD or `helm template` use `existingSecret`: the random value would change on every sync ([install.md §14](install.md#14-installing-with-argo-cd)) |
| `auth.oidc.redirectUrl` | `https://<first host>/api/v1/auth/oidc/callback` | Callback registered at the provider |
| `auth.oidc.scopes` | `[openid, profile, email, groups]` | Requested scopes |
| `auth.oidc.usernameClaim` | `email` | `email`, `preferred_username`, `sub` or `name`. With `email`, an address the provider marks as unverified is refused |
| `auth.oidc.groupsClaim` | `groups` | Claim with the groups |
| `dex.enabled` | `false` | Deploys Dex at `/dex` on the same host |
| `dex.connectors` | `[]` | Dex connectors (GitHub, GitLab, LDAP, SAML…) |
| `dex.envSecret` | `""` | Secret whose keys become environment variables of Dex |
| `dex.image.*` | pinned by digest | Dex image |
