# User guide

NetCheck checks network connectivity **from a Kubernetes namespace**. It answers questions such as "from the
`payments` namespace, can I reach `10.20.30.40` on port 443?" without installing anything in your applications: for
each test it creates a short-lived Pod (the *probe*) in the namespace you choose, measures, and deletes it.

## 1. What you can do

With the **User** role you can:

- Sign in with a NetCheck account or, if your organization enabled it, with single sign-on; choose the interface
  language (English or Spanish) and change your password.
- Run **DNS**, **TCP connection**, **UDP**, **HTTP**, **HTTPS**, **ping** and **traceroute** checks from the namespaces an
  administrator assigned to you.
- Produce, in one click, the **troubleshooting output for a firewall ticket** (date, hostname, ping, traceroute,
  telnet and curl) as a single block ready to paste.
- See each result with an indicative diagnosis, the technical output and an equivalent command to reproduce it by
  hand.
- Browse the dashboard and the history of your own tests. Each user sees only the tests they started, from the web or
  with their API tokens; administrators see every test.
- See where the traffic stops (**Path**) and **what is missing** for it to flow: nothing, a suggested NetworkPolicy or
  a ready-to-send request for the firewall team.
- Run tests from pipelines with an **API token** and `netcheck-cli`.
- Send TCP, HTTP and HTTPS checks through an HTTP proxy: a shared one of your administrators or one of your own
  (**My proxies**, which only you see and use).

You cannot:

- Run tests from namespaces you were not assigned, or towards destinations or ports the destination policy does not
  allow.
- Use system namespaces (`kube-system`, `kube-public`, `kube-node-lease`, `default`) or the namespace where NetCheck
  is installed (unless an administrator explicitly allows it for your account).
- Create, change or delete users, or change your own namespaces (ask an administrator).
- Run arbitrary commands, scan networks or change NetworkPolicies: NetCheck only **observes**.

## 2. Access

### 2.1 Signing in and language

Open the NetCheck address your platform team gave you (for example `https://netcheck.example.com`). The interface
is **in English by default**, whatever your browser language is.

![Sign-in page](images/user-01-sign-in.png)

To work in Spanish, pick **Español** in the **Language** selector in the top-right corner. The choice is **saved in your
account** when you sign in, so NetCheck opens in Spanish in any browser from then on.

- A wrong username or password shows a generic message that does not say which one failed.
- After **5 failed attempts** in a row the account is locked for **15 minutes**. Wait, or ask an administrator to
  unlock it.
- **Forgot your password?** Ask an administrator to reset it. You will get a temporary password.

**Single sign-on.** If your organization enabled it, the page also shows **Sign in with &lt;provider&gt;** (for example
*Sign in with GitHub*). Use it with the account of your organization: you have no NetCheck password and skip the
password change below. What you can do depends on the *access rules* your administrators defined for your groups; if no
rule matches you, the page says so and you need to ask a NetCheck administrator for access.

### 2.2 First sign-in: mandatory password change

The first time, or after an administrator resets your password, you sign in with a **temporary** password and
NetCheck asks you to change it before anything else.

![Mandatory password change](images/user-02-change-password.png)

- The new password needs **at least 12 characters** and cannot be your username.
- A long, easy-to-remember phrase ("coffee-at-eight-without-sugar") is stronger than a short word with symbols.

### 2.3 Page layout

NetCheck follows the layout of the AWS console:

- **Top bar:** logo, **preferences** button (gear) and your name, with the user menu.
- **Side navigation:** **Dashboard**, **Create test**, **Test history**, **My proxies** and **My API tokens**
  (administrators also see **Administration**). It can be collapsed with the arrow.
- **Breadcrumbs** above the title of each page.
- **Help panel** (the "i" icon on the right or the **Info** link): a summary of how to read the results.

### 2.4 User menu, preferences and sign out

The menu with your name opens **Preferences**, **Change password** (not shown for single sign-on accounts), **API
tokens** (section 8), **My proxies** (your own proxies, section 4.2.2) and **Sign out**. **API tokens** and **My
proxies** are also in the side navigation. Its description shows your username, your role and the NetCheck version.

![User menu](images/user-20-user-menu.png)

**Preferences** sets the interface language (English / Español). It is saved in your account when you click **Save**.

![Preferences](images/user-21-preferences.png)

Sessions expire after **60 minutes without activity** and, in any case, after **12 hours**. When that happens
NetCheck returns to the sign-in page.

## 3. Dashboard

The **Dashboard** is the home page. For your tests of the last 24 hours (administrators: everyone's) it shows how many
passed, had connectivity failures or infrastructure errors; the checks by method; the namespaces you can test from; and
your most recent tests.

![Dashboard](images/user-03-dashboard.png)

## 4. Creating a test

Click **Create test** in the side navigation (or on the dashboard). Only the check types your administrators left
enabled are offered; **Run again** of an older test leaves out the ones disabled since then and says so.

![Create test](images/user-04-create-test.png)

### 4.1 Source and destination

- **Source namespace:** only your assigned namespaces are listed. The test runs **from** that namespace, with its
  NetworkPolicies, its DNS and its network.

  ![Assigned namespaces](images/user-05-assigned-namespaces.png)

- **Destination:** **only** an IP address (IPv4 or IPv6) or a DNS name (for example
  `api.payments.svc.cluster.local`). URLs, ports and paths are not accepted in this field: the port and the path are set
  **in each check**.

### 4.2 Checks

Select one or more cards (or **Select all**). They run one after another in a single Pod.

| Check | What it verifies | Port | Equivalent to |
|---|---|---|---|
| **DNS resolution** | The name resolves from the source Pod (A/AAAA and CNAME). Needs a name, not an IP | — | `getent ahosts` |
| **TCP connection** | A TCP connection to the port can be established | **Required, no default** | `nc -z` / `telnet` |
| **UDP** | A UDP service answers: a generic port, a DNS server or an NTP server (see 4.2.1) | Generic: **required**; DNS **53**, NTP **123** | `nc -u`, `dig`, `ntpdate -q` |
| **HTTP** | A web service answers GET or HEAD over plain HTTP | **80** by default, editable | `curl http://…` |
| **HTTPS** | The same over TLS, verifying the certificate | **443** by default, editable | `curl https://…` |
| **Ping (ICMP)** | The destination answers ICMP echo requests | — | `ping -c N` |
| **Traceroute (ICMP)** | The hops (routers) towards the destination | — | `traceroute -I` |

![Default ports: TCP empty, HTTP 80 and HTTPS 443](images/user-06-default-ports.png)

**Check settings** (shown when a card is selected):

- **TCP:** port (required).
- **UDP:** what to test (generic port, DNS server or NTP server) and the port.
- **HTTP / HTTPS:** port, method (GET or HEAD) and path (for example `/health`). Redirects are not followed: you see
  the 3xx code and its target.
- **HTTPS → Ignore certificate errors:** by default an invalid certificate stops the request and the result says
  exactly why (expired, another name, untrusted authority, self-signed). With this option the request goes on, so you
  can check the application behind it; the result is a **warning** that still lists every certificate problem, like
  `curl --insecure`.
- **TCP / HTTP / HTTPS → Connection** (when you or your administrators have proxies): **Direct** (default) tests the
  path from the Pod; **Through proxy …** sends the check through that proxy: a tunnel for TCP and HTTPS, like
  `curl --proxy` or `nc -X connect`, and a forwarded request for HTTP, like `curl -x`. The list shows **My proxies**
  first and then the **Shared** ones. Use it when your applications reach the destination through the proxy. A success
  proves the path through the proxy, not the direct one; the proxy resolves the name, so the result shows the proxy's
  IP and its answer instead of the destination IP.
- **My proxies** (side navigation or user menu): your own proxies, which only you can see and use. Add the name,
  host and port, and, if the proxy inspects TLS, its certificate authority (PEM), which is trusted only for your HTTPS
  checks through that proxy. If an administrator opens one of your tests, they only see that it went through a
  personal proxy, not which one.
- **DNS:** address family (IPv4 and IPv6, IPv4 only or IPv6 only).
- **Ping:** number of echo requests (1–10, one per second).
- **Traceroute:** maximum hops (1–30, at most one second per hop).
- **Advanced → Timeout per check:** for DNS, TCP, UDP, HTTP and HTTPS; 5 s by default, 10 s maximum.

#### 4.2.1 UDP

UDP has no handshake: the probe sends a datagram and the destination may or may not answer. That is why NetCheck only
offers what can actually be tested over UDP:

| Mode | What is sent | Conclusive result |
|---|---|---|
| **Generic port** | Empty datagrams (up to three) | A reply means **open**; an ICMP "port unreachable" means **closed** (the host was reached). **No reply is inconclusive**: many services ignore unexpected datagrams and firewalls drop them silently |
| **DNS server** | A standard DNS query | Any DNS answer, even an error code such as REFUSED, proves the server is reachable |
| **NTP server** | A time request | The answer shows the server stratum, its reference and the clock offset of the probe |

The content of the datagrams is fixed: you cannot send your own data. Prefer the DNS or NTP mode whenever the service
is one of them; use the generic mode for other services, keeping in mind that silence does not prove a block.

![UDP check in DNS server mode, port 53 by default](images/user-23-udp-modes.png)

The result shows the mode, the datagrams sent, the reply time and, in the DNS and NTP modes, what the server answered:

![UDP result against the cluster DNS server](images/user-24-udp-result.png)

Ping and traceroute work **without privileges**: the probe needs neither `NET_RAW` nor root. They use Linux *ping
sockets*, enabled only inside the probe Pod.

#### 4.2.2 Through a proxy

**My proxies → Add proxy** (side navigation or user menu) registers a proxy of your own: a name, the host and the
port, and, only if the proxy inspects TLS, its certificate authority. Nobody else can see or use it.

![Adding a personal proxy](images/user-25-add-personal-proxy.png)

![My proxies](images/user-26-my-proxies.png)

In a TCP, HTTP or HTTPS check, **Connection** offers **Direct** (the default), your proxies under **My proxies** and
the ones your administrators share under **Shared**. A proxy with its own authority is tagged *with CA*.

![Choosing the connection of an HTTP check](images/user-27-proxy-selector.png)

The result names the proxy, its IP and its answer: for HTTP, whether the proxy forwarded the request or answered it
itself. The destination IP is not shown, because the proxy, not the Pod, resolved the name.

![HTTP check through a personal proxy](images/user-28-result-through-proxy.png)

### 4.3 Firewall ticket troubleshooting

When you open a firewall ticket you are often asked for the output of `date`, `hostname`, `ping`, `traceroute`,
`telnet` and `curl` against the destination and port, all together. In **Create test → Test type** choose **Firewall
ticket troubleshooting**: you only enter the source namespace, the **destination** (IP or FQDN) and the **port**.

![Firewall ticket form](images/user-07-firewall-form.png)

- **curl protocol:** automatic by port (443 and 8443 → HTTPS, anything else → HTTP), or choose HTTP or HTTPS.
- A single Pod runs `ping -c 4`, `traceroute` (20 hops), `telnet <port>` and `curl -v` against `/`, plus `date` and
  `hostname`.

When it finishes, the result shows a **Firewall ticket report** block: **one output** with every command, with **Copy
report** and **Download .txt** buttons to attach it to the ticket.

![Firewall ticket report](images/user-08-firewall-report.png)

How to read the report:

- The header states that the NetCheck **probe** ran the checks: each block reproduces the usual command output
  (`PING …`, `traceroute to …`, `Trying … Connected to …`, `curl -v`) with **measured** values. Nothing is
  invented: what the probe does not measure (the ping TTL or the full HTTP response headers, for example) is left out.
- **Source of the tests:** cluster, namespace, name and IP of the **probe Pod**, and name and IP of the **node
  (server)** it ran on, taken from the Kubernetes API. **IP seen by the firewall:** traffic to destinations outside
  the VPC or cluster network usually leaves with the **node IP** (SNAT); inside the VPC, with the **Pod IP**. Request
  the rule for the right one.
- There is no `ifconfig`: the probe has no access to the server interfaces (by design), and the Pod's own `ifconfig`
  would not show the server IP. The node IP is in the source block.
- `hostname` shows the probe Pod name; the server name is in the source block.
- Ping and traceroute to a **Kubernetes Service** (cluster IP) get no answer: Services do not reply to ICMP. That is
  expected; for the ticket, `telnet` and `curl` to the port are what matters.

### 4.4 Request preview and running the test

Expand **Request preview** to see exactly what will be sent, then click **Run test**.

![Complete form](images/user-09-request-preview.png)

The server performs the final validation. If the destination or the port is not allowed by the destination policy
(managed by administrators), or it is a protected destination such as the cloud metadata service, the test is rejected
**without sending any traffic** and the message gives the exact reason:

![Denied destination](images/user-10-denied-destination.png)

## 5. Reading the result

The result page refreshes by itself while the probe works (usually 5 to 30 seconds; ping and traceroute take longer).
**Run again** opens the form filled in with the same values and **Copy JSON** copies the full result.

![Successful result](images/user-11-result-succeeded.png)

### 5.1 Overall status

| Status | Meaning |
|---|---|
| Queued / Running | The probe is being created or is measuring |
| **All checks passed** | Every check succeeded |
| **Connectivity failures** | At least one network check failed (refused, timed out, DNS, no ICMP reply…) |
| **Infrastructure error** | NetCheck could not run the probe (permissions, quota, image…). **It is not a network result**: tell your platform team. When the namespace quota is full, the message names the quota and how much is missing |

The **Details** block also shows the **probe Pod IP** and the **node** the measurement came from.

### 5.2 Interpreting each check

| Result | What it means | What it does **not** mean |
|---|---|---|
| TCP **Succeeded** | There is a TCP path from that namespace to that port | That the application works |
| TCP **Connection refused** | The packet arrived and something answered "no" (nothing listens on the port, or the Service has no endpoints) | A NetworkPolicy block |
| UDP **reply** | A UDP service answered on that port | That the application is healthy |
| UDP **port closed** | The datagram reached the host and nothing listens on that port | A network block |
| UDP **no reply** | Inconclusive: open but silent, or filtered | A block: many UDP services never answer unexpected datagrams |
| TCP **Timed out** | No answer. It can be a NetworkPolicy (source or destination), a Security Group, a NACL, routing, or the destination being down | Proof that a NetworkPolicy blocks it |
| DNS **NXDOMAIN** | The name does not exist for that resolver | A network problem |
| DNS **Timed out** | The resolver could not be reached (a policy blocking port 53?) | — |
| HTTP/HTTPS **200–299** | The service answered fine | — |
| HTTP/HTTPS **401/403/404/5xx** | **There is connectivity**; the problem is in the application. Shown as a warning, not as a network failure | A network problem |
| TLS **certificate not valid** | It connected, but the certificate failed; the detail says which problem: expired or not yet valid, issued for another name, signed by an authority the probe does not trust, or self-signed | A network block |
| HTTPS **Trusted through** an authority *configured in NetCheck* | The certificate is valid, but only thanks to an authority added in NetCheck: by your administrators (corporate PKI or a firewall that decrypts TLS, [admin guide §18](admin-guide.md#18-certificate-authorities)) or in the proxy the check went through | That other clients trust it: they need the same authority installed |
| HTTPS answered, **certificate errors ignored** (warning) | You chose *Ignore certificate errors*: the network and the application answer, but the certificate has the problems listed | That clients will accept it: anything that verifies certificates still rejects it |
| Through a proxy: **proxy could not be reached** | The block is between the Pod and the proxy (NetworkPolicy, firewall or wrong address); the destination was never tried | A block towards the destination |
| Through a proxy: **proxy refused the tunnel** (403) / **requires authentication** (407) | The proxy answered: its policy denies that destination or port (many proxies only allow port 443), or it only accepts authenticated clients | A network block: ask the proxy team |
| Through a proxy: **proxy could not reach the destination** (502/503/504) or **did not answer in time** | The Pod reaches the proxy; the problem is beyond it | That the Pod-to-proxy path is blocked |
| Ping **no reply** | No echo reply arrived | That TCP is blocked: ICMP is often filtered while TCP works |
| Ping **partial loss** | Some requests got no reply; the host is reachable | — |
| Traceroute **incomplete** | The destination was not reached; hops shown as `*` did not answer | Packet loss: many routers and policies do not answer ICMP |
| **Destination denied** | The NetCheck policy does not allow that destination; no traffic was sent | A network result |

### 5.3 Ping and traceroute

The **ping** detail shows packets sent and received, the loss percentage, the minimum, average and maximum RTT, and
the answer to each request. The **traceroute** detail lists each hop with its address and RTT.

![Successful ping from a namespace without policies](images/user-12-ping.png)

![Traceroute hops](images/user-13-traceroute.png)

An important example: from a namespace whose NetworkPolicies only allow DNS and TCP 8080, **TCP to port 8080 works**
but **ping gets no reply**. A failed ping therefore does not prove that your application cannot connect: always check
with TCP or HTTP(S) on the real port.

![Ping filtered while TCP works](images/user-14-ping-filtered.png)

### 5.4 Fidelity notice

The result belongs to the **probe Pod**, whose labels, ServiceAccount and IP differ from your application's. The
fidelity notice tells you how representative it is:

- **Namespace-wide policies (likely):** every egress policy in the namespace uses `podSelector: {}`, so it applies to
  the probe and to your application alike.
- **Some policies use specific selectors:** a policy only applies to Pods with certain labels. Your application may get
  different rules than the probe (in the example, `allow-echo-legacy-only` only applies to `app=legacy`).
- **No native egress NetworkPolicies visible** or **Fidelity unknown.**

Other layers may always exist and are not visible here: Security Groups for Pods, `ClusterNetworkPolicy`, policies on
the destination side and firewalls.

![Blocked result with fidelity notice](images/user-15-result-blocked.png)

### 5.5 Check details

Select a row of the **Checks** table to see its details below, in these tabs:

- **Summary:** diagnosis, resolved IPs, IP and port used, IPs denied by policy, HTTP status, TLS version, certificate,
  and connect / TLS / first-byte timings (or the ping and traceroute tables).
- **Output:** the probe's technical trace.
- **Equivalent command:** an approximate command (`getent`, `nc`, `curl`, `ping` or `traceroute`) to reproduce the
  check by hand, with a **Copy** button. The probe does not run it: it uses its own network primitives.
- **JSON:** the complete result, to attach to an incident.

![HTTP check detail](images/user-16-check-detail.png)

![Equivalent command](images/user-17-equivalent-command.png)

A timeout caused by a NetworkPolicy that blocks egress:

![Timeout detail](images/user-18-timeout-detail.png)

### 5.6 Path

The **Path** panel draws where the traffic goes and where it stops, with measured values only: the probe Pod and its
node (from the Kubernetes API), the hops of the traceroute if the test included one, and the destination with the
result of every check. Without a traceroute the middle is shown as *Path not measured*; silent hops are grouped, and
the last hop that answered is marked when the traceroute did not reach the destination. The hops come from ICMP:
TCP and UDP can take another path, and many networks (an AWS VPC, for example) do not answer the traceroute.

### 5.7 What is missing

Every finished test ends with a **What is missing** panel that always states what has to change, if anything:

| Situation | What the panel says |
|---|---|
| Every check got an answer | **Nothing is missing.** No NetworkPolicy or firewall change is needed. Errors that come with an answer (connection refused, TLS, HTTP status) come from the destination |
| Checks got no answer and egress NetworkPolicies of the namespace apply to the probe | **A NetworkPolicy change is probably needed**, with a suggested egress NetworkPolicy (YAML) built from the measured IPs, ports and protocols, plus the cluster DNS rule when name resolution timed out. Narrow its `podSelector` to your application before applying it |
| Checks got no answer and no egress NetworkPolicy applies to the probe | **No NetworkPolicy change is needed**: the block is most likely outside the cluster |

In both blocked cases the **Firewall request** tab has a ready-to-copy text for the firewall team: source namespace,
Pod and node IPs (the firewall sees one of them depending on SNAT), the destinations and ports that got no answer with
their times, and what does work from the same Pod. NetCheck never applies the policy or changes anything: it tells
whoever owns the change what to do. ICMP cannot be allowed with a NetworkPolicy, so it is listed as a comment.

## 6. Test history

**Test history** lists the tests you started, from the web or with your API tokens, newest first, with filters by
namespace and status. Other users' tests are private: they do not appear, and their links answer "not found", even in
a namespace you share. Administrators see every test. Click the
date to open the full result. The gear icon of the table sets the page size and the visible columns (remembered in
your browser).

![Test history](images/user-19-history.png)

Technical output is kept for 15 days and the rest of the data for 45 days (or whatever your administrators configured).

## 7. Changing your password

User menu → **Change password**. Enter the current password and the new one twice. Saving signs out your other
sessions in other browsers.

![Change password](images/user-22-change-password.png)

## 8. API tokens and the command line

To run tests from a CI/CD pipeline or a terminal, create an **API token** in **My API tokens** (side navigation, or
**user menu → API tokens**) **→ Create token**. Give it a name and an expiry (30 to 365 days); it is shown
**once**, so copy it into the secrets of your pipeline. The token acts as you, with your namespaces and the
destination policy, but it can only run and read tests.
Revoke it from the same page when it is no longer needed.

Use it with `netcheck-cli`, which runs the test, waits for the result and exits with `0` (passed), `1`
(connectivity failures), `2` (the test could not run) or `3` (usage or API error):

```bash
export NETCHECK_URL=https://netcheck.example.com
export NETCHECK_TOKEN=nck_...
netcheck-cli run -n payments -t db.corp.example -c dns -c tcp:5432
```

The [CLI guide](cli.md) explains how to download it, every check and pipeline examples.

## 9. FAQ

**I cannot see the namespace I need.** Ask an administrator to assign it to you or, if it was excluded, to include it
again in **Administration → Namespaces**. If you have "All namespaces" and the namespace is new, it can take up to a
minute to appear. System namespaces (`kube-system`, `default`…) are never available, and the NetCheck namespace only
if an administrator enables it for your account.

**"Not allowed by the NetCheck destination policy".** By default you can test any name, IP and port (for example
`www.google.com`), except a few destinations protected for security reasons: the cloud metadata service
(`169.254.169.254`), the Kubernetes API server, loopback (`127.0.0.1`) and link-local addresses. It is also rejected if
an administrator restricted destinations in **Administration → Destination policy** (ask them to add it; the change is
immediate). The message gives the exact reason and no traffic was sent.

**Why does TCP have no default port?** To avoid testing, by mistake, a port that is not your service's. HTTP and HTTPS
default to 80 and 443 because those are the standard ports, but you can change them.

**Ping fails but my application works.** That is normal: ICMP is often filtered (NetworkPolicies, Security Groups,
firewalls) while TCP is allowed. Test with TCP or HTTP(S) on the real port.

**My application cannot reach a destination, but NetCheck says "Succeeded".** The probe may get different rules than
your application (check the fidelity notice): Security Groups for Pods, policies with selectors, service meshes or
sidecars. Share the result with your platform team.

**I got "Infrastructure error".** It is not a problem with your network. Copy the test ID and the message and send
them to your platform team.

**"Too many sign-in attempts".** Wait one minute and try again.

**The firewall team asks for the server's `ifconfig`.** NetCheck cannot show it: the probe is a Pod without access to
the server interfaces, by design. The firewall ticket report includes the real node (server) and Pod IPs taken from
Kubernetes and explains which one the firewall will see. If the firewall team insists on the server's `ifconfig`, ask
your platform team.

**Can I test UDP?** Yes, with the **UDP** check: as a generic port, a DNS server or an NTP server (see 4.2.1). Only the
DNS and NTP modes, or a service that answers, give a certain result: silence over UDP is inconclusive.
