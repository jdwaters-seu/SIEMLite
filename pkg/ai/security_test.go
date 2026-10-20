package ai

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// TestMaskerFindsEveryAddress: an address run together with other text, with
// leading zeros, or an email address without a dotted domain is still replaced.
func TestMaskerFindsEveryAddress(t *testing.T) {
	for _, real := range []string{"10.1.2.3", "010.001.002.003", "root@localhost", "svc_backup@bastion", "a.b@x.io"} {
		for _, line := range []string{
			"ip" + real + " seen", "src_" + real + "_x", real + "abc", "x=" + real, "[" + real + "]:443",
		} {
			m := newMasker(nil)
			out := m.mask(line)
			if strings.Contains(out, real) {
				t.Errorf("%q kept in %q", real, out)
			}
			if back := m.unmask(out); back != line {
				t.Errorf("unmask(%q) = %q, want %q", out, back, line)
			}
		}
	}
	m := newMasker(nil)
	if out := m.mask("version 1.2.3 build 300.1.1.1 at 2026-10-03T10:17:12.123Z took 1.5s ssh2"); !strings.Contains(out, "1.2.3 build 300.1.1.1 at 2026-10-03T10:17:12.123Z took 1.5s ssh2") {
		t.Errorf("things that aren't addresses were changed: %q", out)
	}
	// Host names (which can hold an address, as on EC2) and MAC addresses.
	line := "conn from ip-10-0-0-1.ec2.internal to bastion.corp.fisni.com via db01.lan mac AA:BB:CC:00:11:22 or aa-bb-cc-00-11-23 user svc@fisni.com"
	m = newMasker(nil)
	out := m.mask(line)
	for _, real := range []string{"ip-10-0-0-1", "ec2.internal", "fisni", "db01.lan", "AA:BB:CC:00:11:22", "aa-bb-cc-00-11-23"} {
		if strings.Contains(out, real) {
			t.Errorf("%q kept in %q", real, out)
		}
	}
	if back := m.unmask(out); back != line {
		t.Errorf("unmask = %q", back)
	}
	// Many distinct MAC addresses each get their own stand-in.
	m = newMasker(nil)
	var macs []string
	for i := 0; i < 600; i++ {
		macs = append(macs, fmt.Sprintf("02:00:00:00:%02x:%02x", i>>8, i&0xff))
	}
	all := strings.Join(macs, " ")
	if back := m.unmask(m.mask(all)); back != all {
		t.Error("MAC stand-ins collided")
	}
}

// TestOllamaClientDoesntFollowRedirects: an answer that redirects goes nowhere.
func TestOllamaClientDoesntFollowRedirects(t *testing.T) {
	hit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Write([]byte(`{"models":[{"name":"internal-secret"}]}`))
	}))
	defer target.Close()
	bounce := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer bounce.Close()
	models, err := newOllama(bounce.URL, "").models(context.Background())
	if err == nil || hit || len(models) != 0 {
		t.Errorf("followed a redirect: %v %v hit=%v", models, err, hit)
	}
	for _, a := range []string{"64:ff9b::a9fe:a9fe", "::ffff:169.254.169.254", "0.1.2.3", "fe80::1"} {
		if !forbiddenAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s allowed", a)
		}
	}
	for _, a := range []string{"127.0.0.1", "10.0.0.5", "172.18.0.3", "::1", "64:ff9b::a00:5"} {
		if forbiddenAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s refused", a)
		}
	}
}

// TestOllamaAddressIsChecked: the same check when saving, testing and
// connecting, and nothing the far end sends back is repeated.
func TestOllamaAddressIsChecked(t *testing.T) {
	for _, bad := range []string{"http://169.254.169.254", "http://169.254.169.254:80/", "http://[fe80::1]:11434", "http://[fd00:ec2::254]",
		"http://100.100.100.200", "file:///etc/passwd", "http://ollama:11434/latest/meta-data", "http://u:p@ollama:11434", "http://ollama:11434?x=1", "gopher://x"} {
		if CheckOllamaURL(bad) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	for _, good := range []string{"http://ollama:11434", "http://localhost:11434/", "https://10.0.0.5:11434", "http://[::1]:11434"} {
		if err := CheckOllamaURL(good); err != nil {
			t.Errorf("%s refused: %v", good, err)
		}
	}
	s, _ := newTestService(t, Defaults{})
	ctx := context.Background()
	if _, err := s.Test(ctx, Settings{Provider: ProviderLocal, OllamaURL: "http://169.254.169.254", LocalModel: "m"}, nil); err == nil {
		t.Error("Test went to a metadata address")
	} else if _, ok := err.(InputError); !ok {
		t.Errorf("Test error = %v", err)
	}
	if err := s.Save(ctx, Settings{Provider: ProviderLocal, OllamaURL: "http://169.254.169.254", LocalModel: "m"}, nil); err == nil {
		t.Error("saved a metadata address")
	}
	// Even a name that leads there is refused when connecting.
	if _, err := newOllama("http://169.254.169.254:1", "").models(ctx); err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Errorf("connecting to a link-local address = %v", err)
	}
	// Something that isn't Ollama: its answer isn't repeated.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" && r.URL.Query().Get("ok") == "" {
			w.WriteHeader(500)
			w.Write([]byte("TOP-SECRET-CREDENTIALS"))
			return
		}
		w.Write([]byte("<html>TOP-SECRET-CREDENTIALS</html>"))
	}))
	defer srv.Close()
	_, err := s.Test(ctx, Settings{Provider: ProviderLocal, OllamaURL: srv.URL, LocalModel: "m"}, nil)
	if err == nil || strings.Contains(err.Error(), "TOP-SECRET") {
		t.Errorf("error repeats the answer: %v", err)
	}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("TOP-SECRET-CREDENTIALS")) }))
	defer srv2.Close()
	if _, err := s.Test(ctx, Settings{Provider: ProviderLocal, OllamaURL: srv2.URL, LocalModel: "m"}, nil); err == nil || strings.Contains(err.Error(), "TOP-SECRET") {
		t.Errorf("a 200 that isn't Ollama: %v", err)
	}
}
