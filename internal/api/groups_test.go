package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/hgeorge123/netcheck/internal/auth"
)

// groupsFixture wires roles and groups like main does.
func groupsFixture(t *testing.T) *fixture {
	t.Helper()
	f := rolesFixture(t)
	groups, err := auth.LoadGroups(context.Background(), f.store)
	if err != nil {
		t.Fatal(err)
	}
	f.local.Groups = groups
	return f
}

func (f *fixture) createGroup(body string) string {
	f.t.Helper()
	rec := f.do(f.admin, "POST", "/api/v1/admin/groups", body)
	var v GroupView
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
		f.t.Fatalf("create group: %d %s", rec.Code, rec.Body)
	}
	return v.ID
}

func TestGroupMembersGetTheGroupRole(t *testing.T) {
	f := groupsFixture(t)
	bob := f.userID("bob")
	ping := f.createRole(`{"name":"Ping only","permissions":["check.ping"]}`)
	// Bob keeps his own role in payments and gets ping in secret through the group.
	gid := f.createGroup(`{"name":"On-call","role":"` + ping + `","namespaces":["secret"],"members":["` + bob + `"]}`)
	rec := f.do(f.user, "GET", "/api/v1/namespaces", "")
	if !strings.Contains(rec.Body.String(), `"name":"secret","canRun":true,"checks":["ping"]`) ||
		!strings.Contains(rec.Body.String(), `"name":"payments","canRun":true,"checks":["dns","tcp","udp","http","https","ping","traceroute"]`) {
		t.Errorf("namespaces with the group: %s", rec.Body)
	}
	if rec := f.do(f.admin, "GET", "/api/v1/admin/users/"+bob+"/permissions", ""); !strings.Contains(rec.Body.String(), `"source":"localgroup:On-call"`) {
		t.Errorf("permissions do not name the group: %s", rec.Body)
	}
	// The role is in use by the group; leaving the group removes the grant.
	if rec := f.do(f.admin, "DELETE", "/api/v1/admin/roles/"+ping, ""); rec.Code != http.StatusConflict {
		t.Errorf("delete role used by a group: %d", rec.Code)
	}
	if rec := f.do(f.admin, "PUT", "/api/v1/admin/groups/"+gid, `{"name":"On-call","role":"`+ping+`","namespaces":["secret"],"members":[]}`); rec.Code != http.StatusOK {
		t.Fatalf("empty group: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.user, "GET", "/api/v1/namespaces", ""); strings.Contains(rec.Body.String(), `"name":"secret"`) {
		t.Errorf("secret still granted after leaving the group: %s", rec.Body)
	}
	// Validation.
	for body, code := range map[string]string{
		`{"name":"","role":"user","namespaces":["payments"]}`:                       "group_name_invalid",
		`{"name":"x","role":"nope","namespaces":["payments"]}`:                      "role_invalid",
		`{"name":"x","role":"user","namespaces":["payments"],"members":["u-nope"]}`: "member_unknown",
		`{"name":"on-call","role":"user","namespaces":["payments"]}`:                "group_exists",
	} {
		if rec := f.do(f.admin, "POST", "/api/v1/admin/groups", body); rec.Code < 400 || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("%.50s: %d %s", body, rec.Code, rec.Body)
		}
	}
}

func TestAdminGroupKeepsAnAdministrator(t *testing.T) {
	f := groupsFixture(t)
	bob, admin := f.userID("bob"), f.userID("admin")
	// Bob becomes administrator through a group.
	gid := f.createGroup(`{"name":"Platform","role":"admin","members":["` + bob + `"]}`)
	if rec := f.do(f.user, "GET", "/api/v1/admin/users", ""); rec.Code != http.StatusOK {
		t.Fatalf("group admin cannot administer: %d", rec.Code)
	}
	// Nobody takes away their own administrator role through a group.
	if rec := f.do(f.user, "PUT", "/api/v1/admin/groups/"+gid, `{"name":"Platform","role":"admin","members":[]}`); rec.Code != http.StatusConflict || errCode(t, rec) != "self_admin" {
		t.Errorf("bob removes himself: %d %s", rec.Code, rec.Body)
	}
	// With bob admin through the group, the bootstrap admin can be demoted...
	if rec := f.do(f.user, "PUT", "/api/v1/admin/users/"+admin, `{"displayName":"Admin","role":"user","namespaces":["payments"]}`); rec.Code != http.StatusOK {
		t.Fatalf("demote the other admin: %d %s", rec.Code, rec.Body)
	}
	// ...and then the group can no longer lose its last admin, by any route.
	if rec := f.do(f.user, "DELETE", "/api/v1/admin/groups/"+gid, ""); rec.Code != http.StatusConflict {
		t.Errorf("delete the only admin group: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.user, "PUT", "/api/v1/admin/groups/"+gid, `{"name":"Platform","role":"user","namespaces":["payments"],"members":["`+bob+`"]}`); rec.Code != http.StatusConflict {
		t.Errorf("demote the only admin group: %d %s", rec.Code, rec.Body)
	}
}

func TestRunsGroupShowsTheTestsOfTheGroup(t *testing.T) {
	f := groupsFixture(t)
	bob := f.userID("bob")
	// carol shares a group with bob; dave does not.
	for _, u := range []string{"carol", "dave"} {
		rec := f.do(f.admin, "POST", "/api/v1/admin/users", `{"username":"`+u+`","role":"user","password":"`+userTemp+`","namespaces":["payments","secret"]}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", u, rec.Code, rec.Body)
		}
		s := f.login(u, userTemp, http.StatusOK)
		f.do(s, "POST", "/api/v1/auth/password", `{"currentPassword":"`+userTemp+`","newPassword":"`+userPass+`"}`)
		s = f.login(u, userPass, http.StatusOK)
		for _, ns := range []string{"payments", "secret"} {
			if rec := f.do(s, "POST", "/api/v1/runs", strings.Replace(validRun, "payments", ns, 1)); rec.Code != http.StatusAccepted {
				t.Fatalf("%s run in %s: %d %s", u, ns, rec.Code, rec.Body)
			}
			f.starter.lim.Release(ns)
		}
	}
	team := f.createRole(`{"name":"Team","permissions":["check.tcp","check.https","runs.group"]}`)
	f.setRole("bob", team, `["payments"]`)
	f.createGroup(`{"name":"Payments team","role":"user","namespaces":["payments"],"members":["` + bob + `","` + f.userID("carol") + `"]}`)
	rec := f.do(f.user, "GET", "/api/v1/runs", "")
	body := rec.Body.String()
	// carol's test in payments only: not her test in secret, nothing of dave.
	if rec.Code != http.StatusOK || strings.Count(body, `"actor":"carol"`) != 1 || strings.Contains(body, `"actor":"dave"`) || strings.Contains(body, `"namespace":"secret"`) {
		t.Errorf("group history: %d %s", rec.Code, body)
	}
}
