package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	if out := m.mask("version 1.2.3 build 300.1.1.1 at 10:17:12"); !strings.Contains(out, "1.2.3 build 300.1.1.1") {
		t.Errorf("things that aren't addresses were changed: %q", out)
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
