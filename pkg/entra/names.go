package entra

import (
	_ "embed"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"siemlite/pkg/storage"
)

// Display names come from Entra, where people can often change their own, so
// one is shown only if it can't pass for another account. The rules work on
// what a name looks like, not on its bytes, following Unicode's UTS #39: a
// fullwidth "ＡＤＭＩＮ", an "ad\u200bmin" with an invisible space, or an
// "аdmin" with a Cyrillic а are all "admin".

// CleanName tidies a display name for showing: compatibility forms unified
// (fullwidth letters become ordinary ones), invisible and control characters
// dropped, spaces collapsed, at most 128 characters.
func CleanName(s string) string {
	s = norm.NFKC.String(s)
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case unicode.In(r, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs, unicode.Zl, unicode.Zp) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r):
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 128 {
		s = strings.TrimSpace(string(r[:128]))
	}
	return s
}

// nameShape reports whether a cleaned name is made only of what names are
// made of (letters, accents, digits, spaces and . ' ’ - ,), has a letter, and
// is "highly restrictive" in the sense of Unicode's UTS #39: all its letters
// from one script, or from Latin with Han and Japanese kana, Han and
// Bopomofo, or Han and Hangul. Anything else (symbols, @, brackets of any
// kind, mixed alphabets) means the account's username is shown instead.
func nameShape(s string) bool {
	scripts := map[string]bool{}
	letters := false
	for _, r := range s {
		switch {
		case unicode.IsLetter(r):
			letters = true
			if sc := scriptOf(r); sc != "Common" && sc != "Inherited" {
				scripts[sc] = true
			}
		case unicode.IsMark(r), unicode.IsDigit(r), r == ' ', r == '.', r == '\'', r == '\u2019', r == '-', r == ',':
		default:
			return false
		}
	}
	if !letters {
		return false
	}
	if len(scripts) <= 1 {
		return true
	}
	for _, allowed := range [][]string{{"Latin", "Han", "Hiragana", "Katakana"}, {"Latin", "Han", "Bopomofo"}, {"Latin", "Han", "Hangul"}} {
		within := true
		for sc := range scripts {
			within = within && slices.Contains(allowed, sc)
		}
		if within {
			return true
		}
	}
	return false
}

// scriptOf names the Unicode script of r.
func scriptOf(r rune) string {
	for name, table := range unicode.Scripts {
		if unicode.Is(table, r) {
			return name
		}
	}
	return "Unknown"
}

var fold = cases.Fold()

// Unicode's list of characters that look alike (UTS #39 confusables.txt,
// version in the file), trimmed to its mappings.
//
//go:embed confusables.txt
var confusablesData string

var confusables = sync.OnceValue(func() map[rune]string {
	m := map[rune]string{}
	for _, line := range strings.Split(confusablesData, "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, ";")
		if len(f) < 2 {
			continue
		}
		src := []rune(hexRunes(f[0]))
		if len(src) != 1 {
			continue
		}
		m[src[0]] = hexRunes(f[1])
	}
	return m
})

// hexRunes turns "0072 006E" into "rn".
func hexRunes(s string) string {
	var b strings.Builder
	for _, h := range strings.Fields(s) {
		if v, err := strconv.ParseUint(h, 16, 32); err == nil {
			b.WriteRune(rune(v))
		}
	}
	return b.String()
}

// skeletons are what a name looks like, following UTS #39: compatibility
// forms unified, case folded and each character replaced by the one it is
// confusable with, then accents dropped and only letters and digits kept
// (with rn read as m and vv as w). Folding and mapping are done in both
// orders, since neither catches everything on its own (ADMIN only meets
// admin when case is folded first; capital Cherokee letters only meet Latin
// ones when they are mapped first). Two names whose skeletons meet could be
// mistaken for each other.
func skeletons(s string) []string {
	skelMu.Lock()
	if sk, ok := skelCache[s]; ok {
		skelMu.Unlock()
		return sk
	}
	skelMu.Unlock()
	sk := computeSkeletons(s)
	skelMu.Lock()
	if len(skelCache) >= 20000 { // names come and go; start over rather than grow
		clear(skelCache)
	}
	skelCache[s] = sk
	skelMu.Unlock()
	return sk
}

// The membership check compares every account with every other, so
// skeletons are remembered by name.
var (
	skelMu    sync.Mutex
	skelCache = map[string][]string{}
)

func computeSkeletons(s string) []string {
	s = norm.NFKC.String(s)
	foldFirst := fold.String(mapConfusables(norm.NFD.String(fold.String(s))))
	foldFirst = fold.String(mapConfusables(norm.NFD.String(foldFirst)))
	mapFirst := fold.String(mapConfusables(norm.NFD.String(s)))
	mapFirst = fold.String(mapConfusables(norm.NFD.String(mapFirst)))
	out := []string{lettersOnly(foldFirst)}
	if m := lettersOnly(mapFirst); m != out[0] {
		out = append(out, m)
	}
	return out
}

func lettersOnly(s string) string {
	var b strings.Builder
	for _, r := range norm.NFD.String(s) {
		if !unicode.IsMark(r) && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			b.WriteRune(r)
		}
	}
	return strings.ReplaceAll(strings.ReplaceAll(b.String(), "rn", "m"), "vv", "w")
}

// alike reports whether two names could be mistaken for each other.
func alike(a []string, b string) bool {
	for _, y := range skeletons(b) {
		if slices.Contains(a, y) {
			return true
		}
	}
	return false
}

// mapConfusables replaces each character with the one Unicode says it can be
// confused with, as UTS #39 does, and then with the extra lookalikes below.
func mapConfusables(s string) string {
	// The extras go first too: Unicode's list sends some of them elsewhere
	// (Cyrillic м to ʍ, п to Greek π) rather than to the Latin letter they
	// pass for.
	s = strings.Map(extra, s)
	m := confusables()
	var b strings.Builder
	for _, r := range s {
		if t, ok := m[r]; ok {
			b.WriteString(t)
		} else {
			b.WriteRune(r)
		}
	}
	return strings.Map(extra, b.String())
}

func extra(r rune) rune {
	if l, ok := extraLookalikes[r]; ok {
		return l
	}
	return r
}

// extraLookalikes are letters that pass for Latin ones in many fonts but
// aren't in Unicode's list. A false match only means the email is shown
// instead of the name, so the list leans towards matching.
var extraLookalikes = map[rune]rune{
	// Cyrillic
	'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'з': '3', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c',
	'т': 't', 'у': 'y', 'х': 'x', 'і': 'l', 'ї': 'l', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ԛ': 'q',
	'ԝ': 'w', 'ү': 'y', 'ь': 'b', 'ъ': 'b', 'п': 'n', 'г': 'r', 'и': 'u', 'л': 'n', 'ɡ': 'g',
	// Greek
	'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'l', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u',
	'χ': 'x', 'γ': 'y', 'μ': 'u', 'ω': 'w', 'σ': 'o', 'ς': 's', 'π': 'n',
	// Latin and digits easily mistaken
	'0': 'o', '1': 'l', 'i': 'l', 'ı': 'l', '|': 'l', 'ʍ': 'm',
}

// ShowableName is the display name to show for account u, or "" to show its
// username: the name must have a name's shape, and must not look like any
// other account's username or display name, or u's own username. all is every account (u among them).
func ShowableName(raw string, u storage.User, all []storage.User) string {
	name := CleanName(raw)
	if name == "" || !nameShape(name) {
		return ""
	}
	sk := skeletons(name)
	if slices.Contains(sk, "") || alike(sk, u.Username) {
		return ""
	}
	for _, o := range all {
		if o.ID == u.ID {
			continue
		}
		if alike(sk, o.Username) || (o.DisplayName != "" && alike(sk, o.DisplayName)) {
			return ""
		}
	}
	return name
}
