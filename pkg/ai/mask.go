package ai

import (
	"context"
	"fmt"
	"strings"

	"siemlite/pkg/parser"
)

// Before sample lines go to a cloud model, IP, email and MAC addresses and
// host names are replaced with stand-ins of the same kind (documentation
// addresses, example.com and example.net), the same value always by the same
// stand-in, so the lines keep their shape and a pattern still fits them. The model's answer is changed back
// before it is used, so a pattern that kept an address as literal text still
// matches the real lines.

// The address patterns are parser's, which also keeps them whole in drafts.
var (
	emailRe = parser.EmailRe
	ipv4Re  = parser.IPv4Re
	ipv6Re  = parser.IPv6Re
	macRe   = parser.MACRe
	hostRe  = parser.HostRe
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
	// The reverse of mask's order.
	s = hostRe.ReplaceAllStringFunc(s, back)
	s = ipv6Re.ReplaceAllStringFunc(s, back)
	s = macRe.ReplaceAllStringFunc(s, back)
	s = ipv4Re.ReplaceAllStringFunc(s, back)
	return emailRe.ReplaceAllStringFunc(s, back)
}

func (m *masker) mask(s string) string {
	s = emailRe.ReplaceAllStringFunc(s, func(e string) string {
		return m.fake(e, func() string { m.nEmail++; return fmt.Sprintf("user%d@example.com", m.nEmail) })
	})
	s = ipv4Re.ReplaceAllStringFunc(s, func(v string) string {
		if !parser.IPv4Address(v) {
			return v
		}
		return m.fake(v, func() string { // 198.18.0.0/15, set aside for testing
			m.n4++
			return fmt.Sprintf("198.%d.%d.%d", 18+m.n4>>16&1, m.n4>>8&0xff, m.n4&0xff)
		})
	})
	s = macRe.ReplaceAllStringFunc(s, func(v string) string {
		return m.fake(v, func() string {
			m.nMAC++
			return fmt.Sprintf("00:00:5e:%02x:%02x:%02x", 0x53+m.nMAC>>16&0xff, m.nMAC>>8&0xff, m.nMAC&0xff)
		})
	})
	s = ipv6Re.ReplaceAllStringFunc(s, func(v string) string {
		if !parser.IPv6Address(v) {
			return v
		}
		return m.fake(v, func() string { m.n6++; return fmt.Sprintf("2001:db8::%x", m.n6) })
	})
	s = hostRe.ReplaceAllStringFunc(s, func(v string) string {
		l := strings.ToLower(v)
		if m.toReal[v] != "" || l == "example.com" || l == "example.net" || strings.HasSuffix(l, ".example.com") || strings.HasSuffix(l, ".example.net") {
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
	if m.toReal[real] != "" {
		return real // already a stand-in, from an earlier step
	}
	seen := m.seen.String()
	f := next()
	for i := 0; i < 1000 && (strings.Contains(seen, f) || m.toReal[f] != ""); i++ {
		f = next()
	}
	m.toFake[real], m.toReal[f] = f, real
	return f
}
