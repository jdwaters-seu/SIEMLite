package entra

import (
	"strings"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"siemlite/pkg/storage"
)

// Display names come from Entra, where people can often change their own, so
// one is shown only if it can't pass for another account. The rules work on
// what a name looks like, not on its bytes: a fullwidth "ＡＤＭＩＮ", an
// "ad\u200bmin" with an invisible space, or an "аdmin" with a Cyrillic а
// are all "admin".

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
// doesn't mix Latin, Greek and Cyrillic letters, the usual way to make one
// name look like another. Anything else (symbols, @, brackets of any kind)
// means the account's username is shown instead.
func nameShape(s string) bool {
	var latin, greek, cyrillic, letters bool
	for _, r := range s {
		switch {
		case unicode.IsLetter(r):
			letters = true
			latin = latin || unicode.Is(unicode.Latin, r)
			greek = greek || unicode.Is(unicode.Greek, r)
			cyrillic = cyrillic || unicode.Is(unicode.Cyrillic, r)
		case unicode.IsMark(r), unicode.IsDigit(r), r == ' ', r == '.', r == '\'', r == '’', r == '-', r == ',':
		default:
			return false
		}
	}
	mixed := 0
	for _, b := range []bool{latin, greek, cyrillic} {
		if b {
			mixed++
		}
	}
	return letters && mixed <= 1
}

var fold = cases.Fold()

// lookalike maps letters and digits that look like Latin ones to them.
var lookalike = map[rune]rune{
	// Cyrillic
	'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'з': '3', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c',
	'т': 't', 'у': 'y', 'х': 'x', 'і': 'i', 'ї': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ԛ': 'q',
	'ԝ': 'w', 'ү': 'y', 'ь': 'b', 'п': 'n', 'г': 'r', 'ɡ': 'g',
	// Greek
	'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u',
	'χ': 'x', 'γ': 'y', 'μ': 'u', 'ω': 'w', 'σ': 'o', 'ς': 's',
	// Digits and letters that are easily mistaken
	'0': 'o', '1': 'l', 'i': 'l', '|': 'l',
}

// skeleton is what a name looks like: folded case and width, no accents,
// lookalike letters made Latin, rn read as m, and only letters and digits.
// Two names with the same skeleton could be mistaken for each other.
func skeleton(s string) string {
	s = norm.NFD.String(fold.String(norm.NFKC.String(s)))
	var b strings.Builder
	for _, r := range s {
		if unicode.IsMark(r) {
			continue
		}
		for i := 0; i < 3; i++ { // і becomes i, then l
			l, ok := lookalike[r]
			if !ok {
				break
			}
			r = l
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return strings.ReplaceAll(strings.ReplaceAll(b.String(), "rn", "m"), "vv", "w")
}

// ShowableName is the display name to show for account u, or "" to show its
// username: the name must have a name's shape, and its skeleton must differ
// from every other account's username and display name, and from u's own
// username. all is every account (u among them).
func ShowableName(raw string, u storage.User, all []storage.User) string {
	name := CleanName(raw)
	if name == "" || !nameShape(name) {
		return ""
	}
	sk := skeleton(name)
	if sk == "" || sk == skeleton(u.Username) {
		return ""
	}
	for _, o := range all {
		if o.ID == u.ID {
			continue
		}
		if sk == skeleton(o.Username) || (o.DisplayName != "" && sk == skeleton(o.DisplayName)) {
			return ""
		}
	}
	return name
}
