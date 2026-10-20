package ai

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Before sample lines go to a cloud model, IP, email and MAC addresses and
// host names are replaced with stand-ins of the same kind (documentation
// addresses, example.com and example.net), the same value always by the same
// stand-in, so the lines keep their shape and a pattern still fits them. The model's answer is changed back
// before it is used, so a pattern that kept an address as literal text still
// matches the real lines.

var (
	// No word boundaries: an address run together with other text
	// (ip10.0.0.1, src_10.0.0.1) must still be found. Replacing too much is
	// harmless, since the answer is changed back; replacing too little leaks.
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*`)
	ipv4Re  = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
	// A run of hex digits and colons with at least two colons; only runs
	// that are whole IPv6 addresses are changed (not times or MAC addresses).
	ipv6Re = regexp.MustCompile(`(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}`)
	macRe  = regexp.MustCompile(`(?i)[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}`)
	// Dotted names whose last part is a word: host names, and things that look
	// like them (index.html, java.lang.String), which is harmless.
	hostRe = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,23}[a-z0-9]`)
)

type masker struct {
	next           chatter
	toFake, toReal map[string]string
	n4, n6, nEmail int
	nMAC, nHost    int
	seen           strings.Builder // everything sent, so a stand-in never equals a real value
}

func newMasker(next chatter) *masker {
	return &masker{next: next, toFake: map[string]string{}, toReal: map[string]string{}}
}

// chat masks every message (the model's own earlier answers come back
// unmasked from here, so they are masked again the same way) and unmasks the answer.
func (m *masker) chat(ctx context.Context, msgs []map[string]string, schema any) (string, error) {
	for _, msg := range msgs {
		m.seen.WriteString(msg["content"])
		m.seen.WriteByte('\n')
	}
	masked := make([]map[string]string, len(msgs))
	for i, msg := range msgs {
		c := map[string]string{}
		for k, v := range msg {
			c[k] = v
		}
		c["content"] = m.mask(c["content"])
		masked[i] = c
	}
	out, err := m.next.chat(ctx, masked, schema)
	if err != nil {
		return "", err
	}
	return m.unmask(out), nil
}

// unmask puts the real values back into text from the model, whole
// addresses only, so 192.0.2.1 never touches 192.0.2.15.
func (m *masker) unmask(s string) string {
	back := func(v string) string {
		if r, ok := m.toReal[v]; ok {
			return r
		}
		return v
	}
	s = emailRe.ReplaceAllStringFunc(s, back)
	s = ipv4Re.ReplaceAllStringFunc(s, back)
	s = ipv6Re.ReplaceAllStringFunc(s, back)
	s = macRe.ReplaceAllStringFunc(s, back)
	return hostRe.ReplaceAllStringFunc(s, back)
}

func (m *masker) mask(s string) string {
	s = emailRe.ReplaceAllStringFunc(s, func(e string) string {
		return m.fake(e, func() string { m.nEmail++; return fmt.Sprintf("user%d@example.com", m.nEmail) })
	})
	s = ipv4Re.ReplaceAllStringFunc(s, func(v string) string {
		if !octets(v) {
			return v
		}
		return m.fake(v, func() string {
			m.n4++
			nets := []string{"192.0.2", "198.51.100", "203.0.113"}
			return fmt.Sprintf("%s.%d", nets[(m.n4-1)/250%3], (m.n4-1)%250+1)
		})
	})
	s = ipv6Re.ReplaceAllStringFunc(s, func(v string) string {
		if a, err := netip.ParseAddr(v); err != nil || !a.Is6() {
			return v
		}
		return m.fake(v, func() string { m.n6++; return fmt.Sprintf("2001:db8::%x", m.n6) })
	})
	s = macRe.ReplaceAllStringFunc(s, func(v string) string {
		return m.fake(v, func() string {
			m.nMAC++
			return fmt.Sprintf("00:00:5e:%02x:%02x:%02x", 0x53+m.nMAC>>16&0xff, m.nMAC>>8&0xff, m.nMAC&0xff)
		})
	})
	s = hostRe.ReplaceAllStringFunc(s, func(v string) string {
		l := strings.ToLower(v)
		if m.toReal[v] != "" || strings.HasSuffix(l, "example.com") || strings.HasSuffix(l, "example.net") {
			return v // a stand-in, or inside one
		}
		return m.fake(v, func() string { m.nHost++; return fmt.Sprintf("host%d.example.net", m.nHost) })
	})
	return s
}

func (m *masker) fake(real string, next func() string) string {
	if f, ok := m.toFake[real]; ok {
		return f
	}
	seen := m.seen.String()
	f := next()
	for i := 0; i < 1000 && (strings.Contains(seen, f) || m.toReal[f] != ""); i++ {
		f = next()
	}
	m.toFake[real], m.toReal[f] = f, real
	return f
}

// octets reports whether s is four numbers of at most 255, leading zeros
// allowed (010.000.000.001 is still an address to a reader).
func octets(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n > 255 {
			return false
		}
	}
	return true
}
