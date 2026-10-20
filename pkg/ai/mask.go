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
	// Last check, on exactly what is about to be sent.
	for _, c := range masked {
		if m.leaks(c["content"]) {
			return "", errCouldntMask
		}
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
		if !parser.HostName(v) {
			return v
		}
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

// errCouldntMask stops a request rather than send an address.
var errCouldntMask = InputError("Some addresses in these lines couldn't be hidden, so nothing was sent to the cloud. Remove them from the sample lines, or use a model on this server.")

// leaks reports whether text about to be sent still holds an address that
// isn't a stand-in, or a piece of a real address that was replaced (such as a
// network prefix or a domain left as literal text). It looks at the final
// text with the same patterns the draft uses, so it doesn't depend on how the
// text got that way.
func (m *masker) leaks(text string) bool {
	for _, sp := range parser.AddressSpans(text) {
		if !m.standIn(text[sp[0]:sp[1]]) {
			return true
		}
	}
	low := strings.ToLower(text)
	for real := range m.toFake {
		for _, f := range fragments(real) {
			if strings.Contains(low, f) {
				return true
			}
		}
	}
	return false
}

// standIn reports whether v is a stand-in, part of one, or the name it lives under.
func (m *masker) standIn(v string) bool {
	if m.toReal[v] != "" {
		return true
	}
	l := strings.ToLower(v)
	if l == "example.com" || l == "example.net" || strings.HasSuffix(l, ".example.com") || strings.HasSuffix(l, ".example.net") {
		return true
	}
	for f := range m.toReal {
		if strings.Contains(f, v) {
			return true
		}
	}
	return false
}

// fragments are the telling pieces of a real address: runs of at least three
// parts of an IPv4, IPv6 or MAC address, and pieces of a name that are host
// names themselves (fisni.com, corp.fisni.com), lowercased. Short or generic pieces are left
// out so ordinary numbers don't trip the check.
func fragments(real string) []string {
	l := strings.ToLower(real)
	if i := strings.LastIndex(l, "@"); i >= 0 {
		l = l[i+1:] // an email address: its domain
	}
	var sep string
	min := 3
	switch {
	case parser.IPv4Re.MatchString(l) && parser.IPv4Address(l):
		sep = "."
	case strings.Count(l, ":") >= 2:
		sep = ":"
	case strings.Count(l, "-") == 5 && len(l) == 17:
		sep = "-"
	default:
		sep, min = ".", 2
	}
	parts := strings.Split(l, sep)
	var out []string
	for n := min; n < len(parts); n++ {
		for i := 0; i+n <= len(parts); i++ {
			f := strings.Join(parts[i:i+n], sep)
			if len(strings.Trim(f, sep)) < 5 || generic[f] {
				continue
			}
			if sep == "." && min == 2 && !parser.HostName(f) {
				continue // user.name, from actor.user.name, is a field name, not part of a host
			}
			out = append(out, f)
		}
	}
	return out
}

// generic name pieces that say nothing about a network.
var generic = map[string]bool{"co.uk": true, "com.au": true, "co.jp": true, "co.nz": true, "com.br": true, "example.com": true, "example.net": true}
