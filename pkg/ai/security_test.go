package ai

import (
	"context"
	"fmt"
	"io"
	"log/slog"
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

// recorder is a model that keeps everything it is sent and answers with a
// pattern built from the stand-ins it was shown.
type recorder struct{ sent []string }

func (r *recorder) chat(_ context.Context, msgs []map[string]string, _ any) (string, error) {
	for _, m := range msgs {
		r.sent = append(r.sent, m["content"])
	}
	return `{"pattern":"{message}","fields":{},"category":6,"severity":{"from":"auto"}}`, nil
}

// TestNothingLeaksThroughTheDraft: the draft SIEMLite writes from the real
// lines is sent too, so it must never hold part of an address. Lines that
// share a network, a domain, a vendor or a prefix are where it would.
func TestNothingLeaksThroughTheDraft(t *testing.T) {
	sets := [][]string{
		{"host=10.20.30.1:443 accepted", "host=10.20.30.9:80 accepted", "host=10.20.30.77:8080 accepted"},
		{"conn bastion1.corp.fisni.com ok", "conn bastion2.corp.fisni.com ok"},
		{"mail bob@fisni.com sent", "mail alice@fisni.com sent"},
		{"peer fd12:3456:789a::1 up", "peer fd12:3456:789a::2 up"},
		{"dev aa:bb:cc:00:11:22 joined", "dev aa:bb:cc:00:11:99 joined"},
		{"src=10.20.30.1 dst=10.20.31.2", "src=10.20.30.5 dst=10.20.31.9"},
		{`{"ip":"10.20.30.1","host":"db1.fisni.com"}`, `{"ip":"10.20.30.2","host":"db2.fisni.com"}`},
	}
	fragments := []string{"10.20.3", "20.30.", "fisni", "bastion", "fd12", "3456", "789a", "aa:bb:cc", "aa-bb-cc"}
	for _, lines := range sets {
		r := &recorder{}
		if _, err := suggest(context.Background(), newMasker(r), slogDiscard(), lines); err != nil {
			t.Fatal(err)
		}
		for _, sent := range r.sent {
			for _, f := range fragments {
				if strings.Contains(strings.ToLower(sent), f) {
					t.Errorf("lines %q: %q was sent in:\n%s", lines, f, sent)
				}
			}
		}
	}
}

func slogDiscard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestGuardStopsWhatMaskingMissed: whatever way a piece of an address got
// into the text, nothing is sent.
func TestGuardStopsWhatMaskingMissed(t *testing.T) {
	r := &recorder{}
	m := newMasker(r)
	m.mask("seen 10.20.30.1 and bastion1.corp.fisni.com") // replaced earlier in the conversation
	for _, text := range []string{
		"pattern host=10.20.30.{value}", // a network prefix
		"conn {name}.corp.fisni.com",    // a domain
		"mail {user}@fisni.com",         // a domain after a placeholder
	} {
		if !m.leaks(text) {
			t.Errorf("not caught: %q", text)
		}
	}
	for _, text := range []string{
		"took 30.1s, version 1.2.3, at 10:17:12, fields actor.ip and user.name",
		"from " + m.toFake["10.20.30.1"] + " to " + m.toFake["bastion1.corp.fisni.com"],
	} {
		if m.leaks(text) {
			t.Errorf("false alarm: %q", text)
		}
	}
	// Through chat: nothing reaches the model.
	_, err := m.chat(context.Background(), []map[string]string{{"role": "user", "content": "pattern host=10.20.30.{value}"}}, nil)
	if err == nil || len(r.sent) != 0 {
		t.Errorf("sent anyway: %v %q", err, r.sent)
	}
	// Two-part field names are left for the model to read.
	m = newMasker(nil)
	if out := m.mask(`{"actor.ip":"x","user.name":"y","db01.lan":"z"}`); !strings.Contains(out, "actor.ip") || !strings.Contains(out, "user.name") || strings.Contains(out, "db01.lan") {
		t.Errorf("field names = %q", out)
	}
}

// TestGuardLetsOrdinaryLogsThrough: everyday logs, full of addresses and
// names, can still be sent once masked.
func TestGuardLetsOrdinaryLogsThrough(t *testing.T) {
	for _, lines := range [][]string{
		{`203.0.113.7 - - [03/Oct/2026:10:17:12 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8.1"`,
			`198.51.100.23 - bob [03/Oct/2026:10:18:01 +0000] "POST /api/v1/login HTTP/2.0" 401 87 "https://siem.fisni.com/" "Mozilla/5.0"`},
		{"Oct  3 10:20:01 bastion sshd[812]: Failed password for root from 10.20.30.7 port 51234 ssh2",
			"Oct  3 10:20:05 bastion sshd[812]: Accepted publickey for alice from 10.20.30.8 port 40022 ssh2"},
		{"action=block src=10.20.30.1 dst=172.16.5.9 proto=tcp dport=445 rule=deny-smb host=fw01.corp.fisni.com",
			"action=allow src=10.20.30.2 dst=172.16.5.10 proto=udp dport=53 rule=dns host=fw01.corp.fisni.com"},
		{`{"actor":{"ip":"10.20.30.1","user.name":"bob@fisni.com"},"host":"db1.fisni.com","mac":"aa:bb:cc:00:11:22","v":"1.2.3"}`,
			`{"actor":{"ip":"10.20.30.2","user.name":"alice@fisni.com"},"host":"db2.fisni.com","mac":"aa:bb:cc:00:11:23","v":"1.2.3"}`},
		{`CORP\jdoe logged on to WS-0142.corp.fisni.com from fe80::1c2b:3cff:fe4d:5e6f%eth0`,
			`CORP\asmith logged on to WS-0177.corp.fisni.com from fe80::1c2b:3cff:fe4d:5e70%eth0`},
	} {
		r := &recorder{}
		if _, err := suggest(context.Background(), newMasker(r), slogDiscard(), lines); err != nil {
			t.Errorf("%q: %v", lines[0], err)
			continue
		}
		if len(r.sent) == 0 {
			t.Errorf("%q: nothing was sent", lines[0])
		}
	}
}

// TestRefusalIsReported: when the guard stops a request, the person is told,
// rather than given SIEMLite's own draft as if the model had looked.
func TestRefusalIsReported(t *testing.T) {
	r := &recorder{}
	m := newMasker(r)
	m.mask("10.20.30.1") // so the prefix counts as part of a real address
	_, err := suggest(context.Background(), m, slogDiscard(), []string{"x 10.20.30.{a} y", "x 10.20.30.{b} y"})
	if err != errCouldntMask || len(r.sent) != 0 {
		t.Errorf("err = %v, sent %d", err, len(r.sent))
	}
}
