package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"siemlite/api"
	"siemlite/pkg/auth"
	"siemlite/pkg/entra/entratest"
)

// withLocalPort gives the server a local port, as main does by default.
func withLocalPort(d *api.Deps) { d.LocalAddr = "localhost:8444" }

// at sends a JSON request to base (the main or the local port).
func (e *env) at(base string, c *http.Client, method, path string, body, out any) (int, string) {
	e.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, base+path, r)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil {
		json.Unmarshal(raw, out)
	}
	var er struct{ Error string }
	json.Unmarshal(raw, &er)
	return resp.StatusCode, er.Error
}

func (e *env) loginAt(base string, c *http.Client, user, pw string) (int, string) {
	return e.at(base, c, "POST", "/api/v1/login", map[string]string{"username": user, "password": pw}, nil)
}

func TestAdminKeptToTheServer(t *testing.T) {
	e := newEnvWith(t, withLocalPort)
	main, local := e.srv.URL, e.local.URL
	e.user("admin", auth.RoleAdmin)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	before := e.client()
	if got, _ := e.loginAt(main, before, "admin", password); got != 200 {
		t.Fatalf("admin sign-in before = %d", got)
	}

	var v map[string]any
	if got, msg := e.at(main, root, "PUT", "/api/v1/system/signin", map[string]bool{"admin_local_only": true}, &v); got != 200 || v["admin_local_only"] != true || v["local_port"] != "8444" {
		t.Fatalf("turn on = %d %q %v", got, msg, v)
	}
	// The session made away from the server ends at once.
	if got, _ := e.at(main, before, "GET", "/api/v1/me", nil, nil); got != 401 {
		t.Errorf("admin's remote session survived = %d", got)
	}
	// Refused away from the server, whatever the password, without counting as
	// a guess (the address isn't locked out after many).
	for i := 0; i < 12; i++ {
		for _, name := range []string{"admin", "ADMIN", " admin "} {
			if got, msg := e.loginAt(main, e.client(), name, password); got != 403 || !strings.Contains(msg, "server itself") {
				t.Fatalf("%q remote sign-in = %d %q", name, got, msg)
			}
		}
		if got, _ := e.loginAt(main, e.client(), "admin", "wrong"); got != 403 {
			t.Fatalf("remote wrong password = %d", got)
		}
	}
	// On the local port it works, and that session works only there.
	c := e.client()
	if got, msg := e.loginAt(local, c, "admin", password); got != 200 {
		t.Fatalf("local sign-in = %d %q", got, msg)
	}
	if got, _ := e.at(local, c, "GET", "/api/v1/users", nil, nil); got != 200 {
		t.Errorf("admin on the local port = %d", got)
	}
	if got, _ := e.at(main, c, "GET", "/api/v1/users", nil, nil); got != 401 {
		t.Errorf("the local session worked on the main port = %d", got)
	}
	if got, _ := e.loginAt(local, e.client(), "admin", "wrong-password-x"); got != 401 {
		t.Errorf("wrong password locally = %d", got)
	}
	// Other admins are unaffected.
	if got, _ := e.at(main, root, "GET", "/api/v1/users", nil, nil); got != 200 {
		t.Errorf("another admin = %d", got)
	}
	var lv map[string]any
	e.at(local, c, "GET", "/api/v1/system/signin", nil, &lv)
	if lv["local"] != true || v["local"] != false {
		t.Errorf("local flag: local %v, main %v", lv["local"], v["local"])
	}
	// Off again: sign-in from anywhere.
	if got, _ := e.at(main, root, "PUT", "/api/v1/system/signin", map[string]bool{"admin_local_only": false}, nil); got != 200 {
		t.Fatal("turn off")
	}
	if got, _ := e.loginAt(main, e.client(), "admin", password); got != 200 {
		t.Errorf("after turning it off = %d", got)
	}
}

func TestSigninRestrictionsNeedALocalPort(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	for _, body := range []map[string]bool{{"admin_local_only": true}, {"entra_only": true}} {
		if got, msg := e.at(e.srv.URL, root, "PUT", "/api/v1/system/signin", body, nil); got != 400 || !strings.Contains(msg, "local port") {
			t.Errorf("%v = %d %q", body, got, msg)
		}
	}
	if got := e.call(e.client(), "GET", "/api/v1/system/signin", nil, nil, nil); got != 401 {
		t.Errorf("anonymous read = %d", got)
	}
	e.user("sam", auth.RoleStandard)
	sam := e.client()
	e.login(sam, "sam", password)
	if got := e.call(sam, "PUT", "/api/v1/system/signin", map[string]bool{"admin_local_only": true}, nil, nil); got != 403 {
		t.Errorf("standard user change = %d", got)
	}
}

func TestOnlyMicrosoftSignIn(t *testing.T) {
	e := newEnvWith(t, withLocalPort)
	main, local := e.srv.URL, e.local.URL
	e.user("root", auth.RoleAdmin)
	e.user("sam", auth.RoleStandard)
	root := e.client()
	e.login(root, "root", password)
	on := map[string]bool{"entra_only": true}

	if got, msg := e.at(main, root, "PUT", "/api/v1/system/signin", on, nil); got != 400 || !strings.Contains(msg, "Microsoft first") {
		t.Errorf("before Entra = %d %q", got, msg)
	}
	e.ms.Set(entratest.AccessGroup, annOID, true)
	if got := e.call(root, "PUT", "/api/v1/integrations/entra", entraForm(e), nil, nil); got != 200 {
		t.Fatalf("save Entra = %d", got)
	}
	// No way back in without the built-in admin.
	if got, msg := e.at(main, root, "PUT", "/api/v1/system/signin", on, nil); got != 400 || !strings.Contains(msg, "named admin") {
		t.Errorf("without an admin account = %d %q", got, msg)
	}
	e.user("admin", auth.RoleStandard)
	if got, _ := e.at(main, root, "PUT", "/api/v1/system/signin", on, nil); got != 400 {
		t.Errorf("admin account that isn't an Admin = %d", got)
	}
	e.repo.DeleteUser(t.Context(), "admin")
	e.user("admin", auth.RoleAdmin)

	sam := e.client()
	e.login(sam, "sam", password)
	var v map[string]any
	if got, msg := e.at(main, root, "PUT", "/api/v1/system/signin", on, &v); got != 200 {
		t.Fatalf("turn on = %d %q", got, msg)
	}
	enf, _ := v["enforced"].(map[string]any)
	if enf["passwords_off"] != true || enf["admin_local_only"] != true || v["admin_local_only"] != false {
		t.Errorf("enforced = %v", v)
	}
	// Password accounts are out, sessions included, and the refusal is the
	// same for a name that doesn't exist.
	if got := e.call(sam, "GET", "/api/v1/me", nil, nil, nil); got != 401 {
		t.Errorf("sam's session survived = %d", got)
	}
	if got := e.call(root, "GET", "/api/v1/users", nil, nil, nil); got != 401 {
		t.Errorf("root's session survived = %d", got)
	}
	for _, name := range []string{"sam", "root", "nobody-here"} {
		if got, msg := e.loginAt(main, e.client(), name, password); got != 403 || !strings.Contains(msg, "Microsoft") {
			t.Errorf("%s = %d %q", name, got, msg)
		}
		if got, _ := e.loginAt(local, e.client(), name, password); got != 403 {
			t.Errorf("%s on the local port = %d", name, got)
		}
	}
	// The built-in admin: only on the server.
	if got, _ := e.loginAt(main, e.client(), "admin", password); got != 403 {
		t.Errorf("admin remotely = %d", got)
	}
	adm := e.client()
	if got, _ := e.loginAt(local, adm, "admin", password); got != 200 {
		t.Fatalf("admin locally = %d", got)
	}
	// The sign-in page hides the password form, except on the local port.
	var p map[string]bool
	e.at(main, e.client(), "GET", "/api/v1/auth/providers", nil, &p)
	if !p["entra"] || p["password"] || p["local"] {
		t.Errorf("providers = %v", p)
	}
	e.at(local, e.client(), "GET", "/api/v1/auth/providers", nil, &p)
	if !p["password"] || !p["local"] {
		t.Errorf("local providers = %v", p)
	}
	// Microsoft sign-in still works.
	br := e.browser()
	authURL, state := e.startSSO(br)
	e.ms.Expect(authURL, annOID, "ann@example.com")
	e.get(br, "/api/v1/auth/entra/callback?code="+entratest.Code+"&state="+state)
	if got := e.call(br, "GET", "/api/v1/me", nil, nil, nil); got != 200 {
		t.Errorf("Microsoft account = %d", got)
	}

	// Switching Microsoft sign-in off brings passwords back...
	if got, _ := e.at(local, adm, "POST", "/api/v1/integrations/entra/enabled", map[string]bool{"enabled": false}, nil); got != 200 {
		t.Fatal("switch Entra off")
	}
	if got, _ := e.loginAt(main, e.client(), "sam", password); got != 200 {
		t.Errorf("sam with Entra off = %d", got)
	}
	if got, _ := e.loginAt(main, e.client(), "admin", password); got != 200 {
		t.Errorf("admin with Entra off = %d", got)
	}
	// ...and switching it on again takes them away.
	if got, _ := e.at(local, adm, "POST", "/api/v1/integrations/entra/enabled", map[string]bool{"enabled": true}, nil); got != 200 {
		t.Fatal("switch Entra on")
	}
	if got, _ := e.loginAt(main, e.client(), "sam", password); got != 403 {
		t.Errorf("sam with Entra back on = %d", got)
	}
	// Off from the local admin.
	if got, _ := e.at(local, adm, "PUT", "/api/v1/system/signin", map[string]bool{"entra_only": false}, nil); got != 200 {
		t.Fatal("turn off")
	}
	if got, _ := e.loginAt(main, e.client(), "sam", password); got != 200 {
		t.Errorf("sam after turning it off = %d", got)
	}
}

// TestPolicyFromStoredSettings: a change made outside the API (the command
// line, a restore) applies when the server refreshes.
func TestPolicyFromStoredSettings(t *testing.T) {
	e := newEnvWith(t, withLocalPort)
	e.user("admin", auth.RoleAdmin)
	if err := auth.SaveSigninSettings(t.Context(), e.repo, auth.SigninSettings{AdminLocalOnly: true}); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.loginAt(e.srv.URL, e.client(), "admin", password); got != 200 {
		t.Fatalf("before a refresh = %d", got)
	}
	e.api.RefreshSignin(t.Context())
	if got, _ := e.loginAt(e.srv.URL, e.client(), "admin", password); got != 403 {
		t.Errorf("after a refresh = %d", got)
	}
}
