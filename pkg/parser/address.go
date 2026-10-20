package parser

import (
	"net/netip"
	"regexp"
	"strings"
)

// Address-like text: IP, email and MAC addresses and host names. AI Parsers
// replaces these before sample lines go to a cloud model, and a draft
// pattern never cuts one in half, so literal text in a pattern holds either
// a whole address or none.
//
// There are no word boundaries: an address run together with other text
// (ip10.0.0.1, src_10.0.0.1) is still found. Finding too much is harmless.
var (
	EmailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*`)
	IPv4Re  = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
	// A run of hex digits and colons with at least two colons; IPv6Address
	// decides whether it is one (not a time).
	IPv6Re = regexp.MustCompile(`(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}`)
	MACRe  = regexp.MustCompile(`(?i)[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}`)
	// Dotted names whose last part is a word: host names, and everything that
	// looks like one (index.html, java.lang.String, actor.ip). There is no list
	// of top-level names to decide which are hosts: an internal one would slip
	// through, so all of them count.
	HostRe = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,23}[a-z0-9]`)
)

// IPv6Address reports whether a run IPv6Re found should be treated as an
// IPv6 address: a valid one, or anything with "::" or six or more groups
// (a mangled address is still sensitive). Times like 10:17:12 aren't.
func IPv6Address(v string) bool {
	if _, err := netip.ParseAddr(v); err == nil {
		return true
	}
	return strings.Contains(v, "::") || strings.Count(v, ":") >= 5
}

// IPv4Address reports whether a run IPv4Re found is four numbers of at most
// 255; leading zeros are allowed (010.000.000.001 is still an address to a reader).
func IPv4Address(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

// AddressSpans returns where address-like text is in s, as [start, end) pairs.
func AddressSpans(s string) [][2]int {
	var out [][2]int
	add := func(re *regexp.Regexp, ok func(string) bool) {
		for _, m := range re.FindAllStringIndex(s, -1) {
			if ok == nil || ok(s[m[0]:m[1]]) {
				out = append(out, [2]int{m[0], m[1]})
			}
		}
	}
	add(EmailRe, nil)
	add(IPv4Re, IPv4Address)
	add(IPv6Re, IPv6Address)
	add(MACRe, nil)
	add(HostRe, nil)
	return out
}

// keepAddressesWhole shrinks a common prefix and suffix so that neither ends
// inside an address in any of the words.
func keepAddressesWhole(col []string, pre, suf string) (string, string) {
	for changed := true; changed; {
		changed = false
		for _, w := range col {
			for _, sp := range AddressSpans(w) {
				if sp[0] < len(pre) && len(pre) < sp[1] {
					pre, changed = w[:sp[0]], true
				}
				if start := len(w) - len(suf); sp[0] < start && start < sp[1] {
					suf, changed = w[sp[1]:], true
				}
			}
		}
	}
	return pre, suf
}
