//go:build integration

// Package integration exercises a deployed NetCheck against a laboratory
// cluster whose CNI enforces NetworkPolicy (kind + Calico, see lab.sh).
//
// Environment:
//
//	NETCHECK_URL     API base URL (default http://127.0.0.1:8080, via port-forward)
//	NETCHECK_CONTEXT kube context (default kind-netcheck-lab)
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	echoTarget     = "echo.nc-target.svc.cluster.local"
	controllerUser = "system:serviceaccount:netcheck:netcheck-controller"
	sessionCookie  = "netcheck_session"
)

func baseURL() string {
	if u := os.Getenv("NETCHECK_URL"); u != "" {
		return strings.TrimSuffix(u, "/")
	}
	return "http://127.0.0.1:8080"
}

// client keeps the session cookie by hand: Go's cookie jar never sends
// Secure cookies over plain HTTP (the port-forward), browsers do for 127.0.0.1.
type client struct {
	t       *testing.T
	session string
}

func (c *client) do(method, path, body string) (int, []byte) {
	c.t.Helper()
	req, _ := http.NewRequest(method, baseURL()+path, bytes.NewBufferString(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.session != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.session})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v (is the port-forward running?)", method, path, err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie {
			c.session = ck.Value
		}
	}
	return resp.StatusCode, buf.Bytes()
}

func login(t *testing.T, user, pass string) *client {
	t.Helper()
	c := &client{t: t}
	code, body := c.do("POST", "/api/v1/auth/login", fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass))
	if code != http.StatusOK || c.session == "" {
		t.Fatalf("login %s: %d %s", user, code, body)
	}
	return c
}

func kubeClient(t *testing.T, impersonate string) *kubernetes.Clientset {
	t.Helper()
	ctxName := os.Getenv("NETCHECK_CONTEXT")
	if ctxName == "" {
		ctxName = "kind-netcheck-lab"
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{CurrentContext: ctxName}).ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg.Host, "127.0.0.1") && !strings.Contains(cfg.Host, "localhost") {
		t.Fatalf("refusing to run against non-local cluster %s", cfg.Host)
	}
	cfg.Impersonate.UserName = impersonate
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// admin logs in with NETCHECK_ADMIN_PASSWORD or, when unset, the bootstrap
// password read from the chart Secret (valid until the admin changes it).
func admin(t *testing.T) *client {
	t.Helper()
	if p := os.Getenv("NETCHECK_ADMIN_PASSWORD"); p != "" {
		return login(t, "admin", p)
	}
	s, err := kubeClient(t, "").CoreV1().Secrets("netcheck").Get(context.Background(), "netcheck-bootstrap-admin", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("bootstrap secret: %v", err)
	}
	return login(t, "admin", string(s.Data["password"]))
}

func randSuffix() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// newUser creates a user and returns a client that already replaced the
// temporary password.
func newUser(t *testing.T, a *client, body string) *client {
	t.Helper()
	var in map[string]any
	json.Unmarshal([]byte(body), &in)
	user, _ := in["username"].(string)
	code, resp := a.do("POST", "/api/v1/admin/users", body)
	if code != http.StatusCreated {
		t.Fatalf("create user: %d %s", code, resp)
	}
	var created struct{ ID string }
	json.Unmarshal(resp, &created)
	t.Cleanup(func() { a.do("DELETE", "/api/v1/admin/users/"+created.ID, "") })
	c := login(t, user, in["password"].(string))
	if code, resp := c.do("GET", "/api/v1/namespaces", ""); code != http.StatusForbidden {
		t.Fatalf("temporary password must block the API: %d %s", code, resp)
	}
	if code, resp := c.do("POST", "/api/v1/auth/password", fmt.Sprintf(`{"currentPassword":%q,"newPassword":"integration-final-pass"}`, in["password"])); code != http.StatusNoContent {
		t.Fatalf("change password: %d %s", code, resp)
	}
	return c
}

type check struct {
	Method   string `json:"method"`
	Status   string `json:"status"`
	Category string `json:"category"`
	PodIP    string `json:"podIp"`
	NodeName string `json:"nodeName"`
	NodeIP   string `json:"nodeIp"`
	PodName  string `json:"podName"`
	Result   struct {
		Port int `json:"port"`
		HTTP *struct {
			StatusCode int `json:"statusCode"`
		} `json:"http"`
		Ping *struct {
			Transmitted int `json:"transmitted"`
			Received    int `json:"received"`
		} `json:"ping"`
		Traceroute *struct {
			Reached bool `json:"reached"`
			Hops    []struct {
				TTL     int    `json:"ttl"`
				Address string `json:"address"`
			} `json:"hops"`
		} `json:"traceroute"`
	} `json:"result"`
}

type runDetail struct {
	ID           string  `json:"id"`
	Status       string  `json:"status"`
	ErrorMessage string  `json:"errorMessage"`
	Checks       []check `json:"checks"`
	Fidelity     struct {
		Level string `json:"level"`
	} `json:"fidelity"`
}

// echoChecks is DNS + TCP + HTTP against the echo Service (per-check ports).
const echoChecks = `[{"method":"dns"},{"method":"tcp","port":8080},{"method":"http","port":8080,"http":{"method":"GET","path":"/hostname"}}]`

func runAndWait(t *testing.T, c *client, namespace string) runDetail {
	t.Helper()
	return runChecks(t, c, namespace, echoTarget, echoChecks)
}

func runChecks(t *testing.T, c *client, namespace, target, checks string) runDetail {
	t.Helper()
	body := fmt.Sprintf(`{"namespace":%q,"target":%q,"checks":%s}`, namespace, target, checks)
	code, resp := c.do("POST", "/api/v1/runs", body)
	if code != http.StatusAccepted {
		t.Fatalf("create run in %s: %d %s", namespace, code, resp)
	}
	var out struct{ ID string }
	json.Unmarshal(resp, &out)
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		_, b := c.do("GET", "/api/v1/runs/"+out.ID, "")
		var d runDetail
		json.Unmarshal(b, &d)
		if d.Status != "queued" && d.Status != "running" {
			t.Logf("%s run %s: status=%s fidelity=%s", namespace, out.ID, d.Status, d.Fidelity.Level)
			return d
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("run %s did not finish", out.ID)
	return runDetail{}
}

func byMethod(d runDetail, m string) check {
	for _, c := range d.Checks {
		if c.Method == m {
			return c
		}
	}
	return check{}
}

// TestSameDestinationAllowedAndDenied is the main acceptance test: the same
// destination must be reachable from nc-allow and blocked from nc-deny.
func TestSameDestinationAllowedAndDenied(t *testing.T) {
	a := admin(t)
	allow := runAndWait(t, a, "nc-allow")
	deny := runAndWait(t, a, "nc-deny")

	if allow.Status != "succeeded" {
		t.Errorf("nc-allow: status %s (%s)", allow.Status, allow.ErrorMessage)
	}
	if c := byMethod(allow, "http"); c.Result.HTTP == nil || c.Result.HTTP.StatusCode != 200 {
		t.Errorf("nc-allow: expected HTTP 200, got %+v", c)
	}
	if allow.Fidelity.Level != "namespace-wide-likely" {
		t.Errorf("nc-allow fidelity = %s", allow.Fidelity.Level)
	}
	if deny.Status != "failed" {
		t.Errorf("nc-deny: status %s (%s)", deny.Status, deny.ErrorMessage)
	}
	if c := byMethod(deny, "dns"); c.Status != "succeeded" {
		t.Errorf("nc-deny: DNS should be allowed by policy, got %+v", c)
	}
	if c := byMethod(deny, "tcp"); c.Status != "timed_out" || c.Category != "timeout" {
		t.Errorf("nc-deny: expected TCP timeout, got %+v", c)
	}
	if deny.Fidelity.Level != "specific-selectors-detected" {
		t.Errorf("nc-deny fidelity = %s", deny.Fidelity.Level)
	}
	for _, d := range []runDetail{allow, deny} {
		if c := byMethod(d, "tcp"); c.PodIP == "" || c.NodeName == "" {
			t.Errorf("run %s: source pod evidence missing: %+v", d.ID, c)
		}
	}
}

func TestDestinationPolicyAndExcludedNamespaces(t *testing.T) {
	a := admin(t)
	// The policy is open (any host, IP and port) but platform protections stay:
	// cloud metadata and the API server are always denied.
	for _, target := range []string{"169.254.169.254", "10.96.0.1"} {
		if code, b := a.do("POST", "/api/v1/runs", fmt.Sprintf(`{"namespace":"nc-allow","target":%q,"checks":[{"method":"tcp","port":443}]}`, target)); code != http.StatusForbidden {
			t.Errorf("protected destination %s: %d %s", target, code, b)
		}
	}
	// A name that resolves to the API server is blocked inside the probe (DNS rebinding defence).
	if d := runChecks(t, a, "nc-open", "kubernetes.default.svc.cluster.local", `[{"method":"tcp","port":443}]`); byMethod(d, "tcp").Category != "destination_denied" {
		t.Errorf("API server by name must be denied in the probe: %+v", d)
	}
	// Any other destination and port is accepted (TEST-NET-1: documentation range, no real host).
	if code, b := a.do("POST", "/api/v1/runs", `{"namespace":"nc-open","target":"192.0.2.10","checks":[{"method":"tcp","port":5432}]}`); code != http.StatusAccepted {
		t.Errorf("open policy rejected 192.0.2.10:5432: %d %s", code, b)
	}
	for _, ns := range []string{"kube-system", "default", "netcheck", "nc-target"} {
		if code, b := a.do("POST", "/api/v1/runs", fmt.Sprintf(`{"namespace":%q,"target":"10.96.0.10","checks":[{"method":"tcp","port":8080}]}`, ns)); code != http.StatusForbidden {
			t.Errorf("excluded namespace %s accepted: %d %s", ns, code, b)
		}
	}
}

func TestUserRestrictedToAssignedNamespaces(t *testing.T) {
	a := admin(t)
	name := "itest-" + randSuffix()
	u := newUser(t, a, fmt.Sprintf(`{"username":%q,"role":"user","password":"temporary-pass-123","namespaces":["nc-allow"]}`, name))
	if code, _ := u.do("GET", "/api/v1/admin/users", ""); code != http.StatusForbidden {
		t.Errorf("user reached admin API: %d", code)
	}
	if code, b := u.do("POST", "/api/v1/runs", `{"namespace":"nc-deny","target":"10.96.0.10","checks":[{"method":"tcp","port":8080}]}`); code != http.StatusForbidden {
		t.Errorf("user ran outside its namespaces: %d %s", code, b)
	}
	if d := runAndWait(t, u, "nc-allow"); d.Status != "succeeded" {
		t.Errorf("user run in nc-allow: %+v", d)
	}
}

func TestAllNamespacesIncludesNewNamespaces(t *testing.T) {
	ctx := context.Background()
	kc := kubeClient(t, "")
	a := admin(t)
	u := newUser(t, a, fmt.Sprintf(`{"username":%q,"role":"user","password":"temporary-pass-123","allNamespaces":true}`, "itest-all-"+randSuffix()))

	ns := "nc-dyn-" + randSuffix()
	_, err := kc.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns,
		Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kc.CoreV1().Namespaces().Delete(context.Background(), ns, metav1.DeleteOptions{}) })

	deadline := time.Now().Add(90 * time.Second) // namespace list is cached for 30s
	for {
		_, b := u.do("GET", "/api/v1/namespaces", "")
		if strings.Contains(string(b), `"`+ns+`"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("namespace %s created after the user never became available: %s", ns, b)
		}
		time.Sleep(3 * time.Second)
	}
	if d := runAndWait(t, u, ns); d.Status != "succeeded" {
		t.Errorf("run in new namespace: %+v", d)
	}
	sa, err := kc.CoreV1().ServiceAccounts(ns).Get(ctx, "netcheck-probe", metav1.GetOptions{})
	if err != nil || sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
		t.Errorf("probe ServiceAccount not created safely on demand: %+v %v", sa, err)
	}
}

// TestControllerIdentityCannotEscalate impersonates the controller
// ServiceAccount: RBAC and both ValidatingAdmissionPolicies must stop the
// escalation paths described in docs/security.md.
func TestControllerIdentityCannotEscalate(t *testing.T) {
	ctx := context.Background()
	sa := kubeClient(t, controllerUser)
	f := false
	malicious := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "evil-", Labels: map[string]string{"app.kubernetes.io/managed-by": "netcheck-controller"}},
		Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever, HostNetwork: true, AutomountServiceAccountToken: &f, ServiceAccountName: "netcheck-probe",
			Containers: []corev1.Container{{Name: "x", Image: "busybox", Command: []string{"sh", "-c", "id"}}},
		}}},
	}
	for _, ns := range []string{"nc-allow", "kube-system"} {
		if _, err := sa.BatchV1().Jobs(ns).Create(ctx, malicious, metav1.CreateOptions{}); err == nil {
			t.Errorf("malicious Job accepted in %s", ns)
		} else {
			t.Logf("malicious job in %s rejected: %v", ns, err)
		}
	}
	bad := map[string]*corev1.ServiceAccount{
		"other name": {ObjectMeta: metav1.ObjectMeta{Name: "admin-sa"}, AutomountServiceAccountToken: &f},
		"irsa": {ObjectMeta: metav1.ObjectMeta{Name: "netcheck-probe", Annotations: map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::1:role/x"}},
			AutomountServiceAccountToken: &f},
		"automount": {ObjectMeta: metav1.ObjectMeta{Name: "netcheck-probe"}},
	}
	for name, obj := range bad {
		if _, err := sa.CoreV1().ServiceAccounts("nc-deny").Create(ctx, obj, metav1.CreateOptions{}); err == nil {
			t.Errorf("ServiceAccount %q accepted", name)
		}
	}
	if _, err := sa.CoreV1().ServiceAccounts("kube-system").Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "netcheck-probe"},
		AutomountServiceAccountToken: &f}, metav1.CreateOptions{}); err == nil {
		t.Error("ServiceAccount accepted in kube-system")
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{GenerateName: "evil-"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "x", Image: "busybox"}}}}
	if _, err := sa.CoreV1().Pods("nc-allow").Create(ctx, pod, metav1.CreateOptions{}); !apierrors.IsForbidden(err) {
		t.Errorf("pods/create must be forbidden, got %v", err)
	}
	if _, err := sa.CoreV1().Secrets("nc-allow").List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
		t.Errorf("secrets/list must be forbidden, got %v", err)
	}
	if _, err := sa.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
		t.Errorf("RBAC read must be forbidden, got %v", err)
	}
}

func TestProbeJobsAreCleanedUp(t *testing.T) {
	kc := kubeClient(t, "")
	deadline := time.Now().Add(time.Minute)
	for {
		jobs, err := kc.BatchV1().Jobs("").List(context.Background(), metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=netcheck-controller"})
		if err != nil {
			t.Fatal(err)
		}
		if len(jobs.Items) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d probe Jobs still present", len(jobs.Items))
		}
		time.Sleep(3 * time.Second)
	}
}

// echoPodIP returns the IP of the echo Pod: ICMP is answered by Pods, not by
// ClusterIP Services.
func echoPodIP(t *testing.T) string {
	t.Helper()
	pods, err := kubeClient(t, "").CoreV1().Pods("nc-target").List(context.Background(), metav1.ListOptions{LabelSelector: "app=echo"})
	if err != nil || len(pods.Items) == 0 || pods.Items[0].Status.PodIP == "" {
		t.Fatalf("echo pod IP: %v", err)
	}
	return pods.Items[0].Status.PodIP
}

// TestICMPWithoutPrivileges runs ping and traceroute from the restricted
// probe (no NET_RAW): they work where policies allow ICMP and are reported as
// "no reply" where the namespace only allows DNS and TCP 8080.
func TestICMPWithoutPrivileges(t *testing.T) {
	a := admin(t)
	ip := echoPodIP(t)
	const icmp = `[{"method":"ping","ping":{"count":3}},{"method":"traceroute","traceroute":{"maxHops":8}}]`

	open := runChecks(t, a, "nc-open", ip, icmp)
	if p := byMethod(open, "ping"); p.Status != "succeeded" || p.Result.Ping == nil || p.Result.Ping.Received == 0 {
		t.Errorf("nc-open ping: %+v", p)
	}
	if tr := byMethod(open, "traceroute"); tr.Status != "succeeded" || tr.Result.Traceroute == nil || !tr.Result.Traceroute.Reached {
		t.Errorf("nc-open traceroute: %+v", tr)
	} else {
		t.Logf("nc-open traceroute hops: %+v", tr.Result.Traceroute.Hops)
	}

	allow := runChecks(t, a, "nc-allow", ip, `[{"method":"ping","ping":{"count":2}},{"method":"tcp","port":8080}]`)
	if p := byMethod(allow, "ping"); p.Status == "succeeded" || p.Category != "icmp_no_reply" {
		t.Errorf("nc-allow ping should be dropped by the egress policy: %+v", p)
	}
	if c := byMethod(allow, "tcp"); c.Status != "succeeded" {
		t.Errorf("nc-allow TCP 8080 should work while ICMP is blocked: %+v", c)
	}
}

func TestPerCheckPortRules(t *testing.T) {
	a := admin(t)
	cases := map[string]string{
		"tcp without port": `[{"method":"tcp"}]`,
		"ping with port":   `[{"method":"ping","port":80}]`,
	}
	for name, checks := range cases {
		code, b := a.do("POST", "/api/v1/runs", fmt.Sprintf(`{"namespace":"nc-open","target":%q,"checks":%s}`, echoTarget, checks))
		if code != http.StatusBadRequest && code != http.StatusForbidden {
			t.Errorf("%s: accepted (%d %s)", name, code, b)
		}
	}
	d := runChecks(t, a, "nc-open", echoTarget, `[{"method":"http","port":8080,"http":{"path":"/hostname"}}]`)
	if c := byMethod(d, "http"); c.Result.Port != 8080 || c.Result.HTTP == nil || c.Result.HTTP.StatusCode != 200 {
		t.Errorf("HTTP on an explicit port: %+v", c)
	}
}

// TestNetcheckNamespaceOnlyWithCheckbox: the installation namespace and the
// system namespaces are never offered, unless a user has the explicit flag
// for the NetCheck namespace.
func TestNetcheckNamespaceOnlyWithCheckbox(t *testing.T) {
	a := admin(t)
	_, b := a.do("GET", "/api/v1/namespaces", "")
	for _, ns := range []string{"netcheck", "default", "kube-system", "kube-public", "kube-node-lease"} {
		if strings.Contains(string(b), `"`+ns+`"`) {
			t.Errorf("namespace %s offered to the admin: %s", ns, b)
		}
	}
	u := newUser(t, a, fmt.Sprintf(`{"username":%q,"role":"user","password":"temporary-pass-123","namespaces":["nc-open"],"allowNetcheckNamespace":true}`,
		"itest-own-"+randSuffix()))
	_, b = u.do("GET", "/api/v1/namespaces", "")
	if !strings.Contains(string(b), `"netcheck"`) {
		t.Fatalf("flagged user does not get the NetCheck namespace: %s", b)
	}
	if d := runChecks(t, u, "netcheck", echoTarget, `[{"method":"tcp","port":8080}]`); d.Status != "succeeded" {
		t.Errorf("run in the NetCheck namespace (no NetworkPolicy there): %+v", d)
	}
}

func TestPreferencesSessionsAndSystem(t *testing.T) {
	a := admin(t)
	if code, b := a.do("PUT", "/api/v1/me/preferences", `{"language":"es"}`); code != http.StatusOK {
		t.Fatalf("set language: %d %s", code, b)
	}
	t.Cleanup(func() { a.do("PUT", "/api/v1/me/preferences", `{"language":"en"}`) })
	if code, _ := a.do("PUT", "/api/v1/me/preferences", `{"language":"fr"}`); code != http.StatusBadRequest {
		t.Errorf("unsupported language accepted: %d", code)
	}
	var me struct{ Language, Version string }
	_, b := a.do("GET", "/api/v1/me", "")
	json.Unmarshal(b, &me)
	if me.Language != "es" {
		t.Errorf("language not stored: %s", b)
	}
	var sessions struct {
		ConnectedUsers int `json:"connectedUsers"`
		Items          []struct {
			Current bool `json:"current"`
		} `json:"items"`
	}
	_, b = a.do("GET", "/api/v1/admin/sessions", "")
	json.Unmarshal(b, &sessions)
	if sessions.ConnectedUsers < 1 || len(sessions.Items) < 1 {
		t.Errorf("sessions: %s", b)
	}
	var sys struct {
		Current struct{ Version, Image string } `json:"current"`
		History []json.RawMessage               `json:"history"`
	}
	_, b = a.do("GET", "/api/v1/admin/system", "")
	json.Unmarshal(b, &sys)
	if sys.Current.Version == "" || sys.Current.Version == "dev" || len(sys.History) == 0 || !strings.Contains(sys.Current.Image, "@sha256:") {
		t.Errorf("system info: %s", b)
	}
	t.Logf("running version %s (%d versions recorded), UI version %s", sys.Current.Version, len(sys.History), me.Version)
}

// TestDestinationPolicyEditedInTheWeb restricts the policy through the admin
// API, checks that the next run is denied without redeploying, and restores it.
func TestDestinationPolicyEditedInTheWeb(t *testing.T) {
	a := admin(t)
	code, original := a.do("GET", "/api/v1/admin/policy", "")
	if code != http.StatusOK {
		t.Fatalf("GET policy: %d %s", code, original)
	}
	var view struct {
		Policy json.RawMessage `json:"policy"`
	}
	json.Unmarshal(original, &view)
	t.Cleanup(func() { a.do("PUT", "/api/v1/admin/policy", string(view.Policy)) })

	restricted := `{"allowCidrs":["10.96.0.0/12"],"denyCidrs":[],"allowHostnameSuffixes":[".svc.cluster.local"],"allowPorts":[{"from":8080,"to":8080}]}`
	if code, b := a.do("PUT", "/api/v1/admin/policy", restricted); code != http.StatusOK {
		t.Fatalf("PUT restricted: %d %s", code, b)
	}
	if code, b := a.do("POST", "/api/v1/runs", `{"namespace":"nc-open","target":"192.0.2.10","checks":[{"method":"tcp","port":5432}]}`); code != http.StatusForbidden {
		t.Errorf("restricted policy accepted 192.0.2.10:5432: %d %s", code, b)
	}
	if d := runAndWait(t, a, "nc-allow"); d.Status != "succeeded" {
		t.Errorf("allowed destination after restricting: %+v", d)
	}
}

// TestFirewallTicketBundle runs the firewall-ticket bundle (ping, traceroute,
// telnet and curl against one port) and checks the source data the report
// needs: probe Pod name and IP, node name and IP (status.hostIP).
func TestFirewallTicketBundle(t *testing.T) {
	a := admin(t)
	body := fmt.Sprintf(`{"mode":"firewall","namespace":"nc-open","target":%q,"checks":[{"method":"ping","ping":{"count":4}},`+
		`{"method":"traceroute","traceroute":{"maxHops":20}},{"method":"tcp","port":8080},{"method":"http","port":8080,"http":{"method":"GET","path":"/"}}]}`, echoTarget)
	code, resp := a.do("POST", "/api/v1/runs", body)
	if code != http.StatusAccepted {
		t.Fatalf("create firewall run: %d %s", code, resp)
	}
	var out struct{ ID string }
	json.Unmarshal(resp, &out)
	var d runDetail
	for deadline := time.Now().Add(3 * time.Minute); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		_, b := a.do("GET", "/api/v1/runs/"+out.ID, "")
		json.Unmarshal(b, &d)
		if d.Status != "queued" && d.Status != "running" {
			break
		}
	}
	if len(d.Checks) != 4 {
		t.Fatalf("firewall run: %+v", d)
	}
	for _, m := range []string{"tcp", "http"} {
		if c := byMethod(d, m); c.Status != "succeeded" {
			t.Errorf("%s: %+v", m, c)
		}
	}
	c := byMethod(d, "tcp")
	if c.PodName == "" || c.PodIP == "" || c.NodeName == "" || c.NodeIP == "" {
		t.Errorf("source data for the report missing: %+v", c)
	}
	t.Logf("firewall run %s: pod %s (%s) on node %s (%s)", d.ID, c.PodName, c.PodIP, c.NodeName, c.NodeIP)
}

// TestNamespaceExcludedInTheWeb excludes a namespace through the admin API:
// it disappears and runs are refused immediately; Helm/system exclusions
// cannot be removed from the web.
func TestNamespaceExcludedInTheWeb(t *testing.T) {
	a := admin(t)
	t.Cleanup(func() { a.do("DELETE", "/api/v1/admin/namespace-exclusions/nc-open", "") })
	if code, b := a.do("POST", "/api/v1/admin/namespace-exclusions", `{"name":"nc-open","reason":"integration test"}`); code != http.StatusNoContent {
		t.Fatalf("exclude nc-open: %d %s", code, b)
	}
	if _, b := a.do("GET", "/api/v1/namespaces", ""); strings.Contains(string(b), `"nc-open"`) {
		t.Errorf("excluded namespace still offered: %s", b)
	}
	if code, b := a.do("POST", "/api/v1/runs", fmt.Sprintf(`{"namespace":"nc-open","target":%q,"checks":[{"method":"tcp","port":8080}]}`, echoTarget)); code != http.StatusForbidden {
		t.Errorf("run in excluded namespace: %d %s", code, b)
	}
	for _, ns := range []string{"nc-target", "kube-system", "netcheck"} {
		if code, _ := a.do("DELETE", "/api/v1/admin/namespace-exclusions/"+ns, ""); code != http.StatusConflict {
			t.Errorf("removing the %s exclusion from the web: %d", ns, code)
		}
	}
	if code, b := a.do("DELETE", "/api/v1/admin/namespace-exclusions/nc-open", ""); code != http.StatusNoContent {
		t.Fatalf("include nc-open: %d %s", code, b)
	}
	if d := runChecks(t, a, "nc-open", echoTarget, `[{"method":"tcp","port":8080}]`); d.Status != "succeeded" {
		t.Errorf("run after including again: %+v", d)
	}
}
