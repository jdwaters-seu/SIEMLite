package api_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"siemlite/pkg/auth"
)

func TestChangeOwnPassword(t *testing.T) {
	e := newEnv(t)
	e.user("sam", auth.RoleStandard)
	me := e.client()
	if got := e.login(me, "sam", password); got.StatusCode != 200 {
		t.Fatalf("login = %d", got.StatusCode)
	}
	other := e.client() // the same person signed in elsewhere
	e.login(other, "sam", password)

	var info map[string]any
	if got := e.call(me, "GET", "/api/v1/me", nil, &info, nil); got != 200 || info["auth_provider"] != "local" {
		t.Fatalf("me = %d %v", got, info)
	}
	change := func(c *http.Client, cur, next string) (int, string) {
		var out map[string]string
		got := e.call(c, "POST", "/api/v1/me/password", map[string]string{"current_password": cur, "new_password": next}, &out, nil)
		return got, out["error"]
	}
	if got, msg := change(me, "not-my-password!", "a brand new passphrase"); got != 400 || !strings.Contains(msg, "current password is wrong") {
		t.Errorf("wrong current = %d %q", got, msg)
	}
	if got, msg := change(me, password, "short"); got != 400 || msg == "" {
		t.Errorf("too short = %d %q", got, msg)
	}
	if got, msg := change(me, password, password); got != 400 || !strings.Contains(msg, "different") {
		t.Errorf("unchanged = %d %q", got, msg)
	}
	if got, msg := change(me, password, "a brand new passphrase"); got != 200 {
		t.Fatalf("change = %d %q", got, msg)
	}
	// This session carries on; the other one ended.
	if got := e.call(me, "GET", "/api/v1/me", nil, nil, nil); got != 200 {
		t.Errorf("the changer was signed out = %d", got)
	}
	if got := e.call(other, "GET", "/api/v1/me", nil, nil, nil); got != 401 {
		t.Errorf("the other session survived = %d", got)
	}
	if got := e.login(e.client(), "sam", password); got.StatusCode != 401 {
		t.Errorf("old password still works = %d", got.StatusCode)
	}
	if got := e.login(e.client(), "sam", "a brand new passphrase"); got.StatusCode != 200 {
		t.Errorf("new password = %d", got.StatusCode)
	}
}

func TestChangeOwnPasswordLimits(t *testing.T) {
	e := newEnv(t)
	e.user("sam", auth.RoleStandard)
	me := e.client()
	e.login(me, "sam", password)
	var last int
	for i := 0; i < 12; i++ {
		last = e.call(me, "POST", "/api/v1/me/password", map[string]string{"current_password": "guess-" + string(rune('a'+i)) + "-xxxxxxxx", "new_password": "a brand new passphrase"}, nil, nil)
	}
	if last != 429 {
		t.Errorf("guessing the current password isn't limited: last = %d", last)
	}
	// Even the right password is refused while locked out.
	if got := e.call(me, "POST", "/api/v1/me/password", map[string]string{"current_password": password, "new_password": "a brand new passphrase"}, nil, nil); got != 429 {
		t.Errorf("right password during lockout = %d", got)
	}
	// Guesses made through a session don't lock the owner out of signing in.
	if got := e.login(e.client(), "sam", password); got.StatusCode != 200 {
		t.Errorf("sign-in after password-change guesses = %d", got.StatusCode)
	}
}

// TestFailedSignInsDontBlockAChange: someone failing to sign in as you
// doesn't stop you changing your password, and a request that changes
// nothing doesn't clear their failures.
func TestFailedSignInsDontBlockAChange(t *testing.T) {
	e := newEnv(t)
	e.user("sam", auth.RoleStandard)
	me := e.client()
	e.login(me, "sam", password)
	for i := 0; i < 10; i++ {
		e.login(e.client(), "sam", "wrong-password-"+string(rune('a'+i)))
	}
	if got := e.login(e.client(), "sam", password); got.StatusCode != 429 {
		t.Fatalf("sign-in limit didn't trip: %d", got.StatusCode)
	}
	if got := e.call(me, "POST", "/api/v1/me/password", map[string]string{"current_password": password, "new_password": password}, nil, nil); got != 400 {
		t.Errorf("unchanged password = %d", got)
	}
	if got := e.login(e.client(), "sam", password); got.StatusCode != 429 {
		t.Errorf("a no-op change cleared the sign-in limit: %d", got.StatusCode)
	}
	if got := e.call(me, "POST", "/api/v1/me/password", map[string]string{"current_password": password, "new_password": "a brand new passphrase"}, nil, nil); got != 200 {
		t.Errorf("change during a sign-in lockout = %d", got)
	}
}

func TestMicrosoftAccountHasNoPasswordToChange(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	id, err := e.repo.CreateExternalUser(ctx, "entra", "0000000a-0000-0000-0000-000000000001", "ann@example.com", "standard", 1)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := e.repo.GetUser(ctx, id)
	token, err := e.deps.Auth.StartSession(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	c := e.client()
	base, _ := url.Parse(e.srv.URL)
	c.Jar.SetCookies(base, []*http.Cookie{{Name: auth.CookieName, Value: token, Path: "/"}})
	var info map[string]any
	if got := e.call(c, "GET", "/api/v1/me", nil, &info, nil); got != 200 || info["auth_provider"] != "entra" {
		t.Fatalf("me = %d %v", got, info)
	}
	var out map[string]string
	if got := e.call(c, "POST", "/api/v1/me/password", map[string]string{"current_password": "x", "new_password": "a brand new passphrase"}, &out, nil); got != 400 || !strings.Contains(out["error"], "Microsoft") {
		t.Errorf("SSO change = %d %v", got, out)
	}
}
