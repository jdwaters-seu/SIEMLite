package entra

import (
	"testing"

	"siemlite/pkg/storage"
)

func TestShowableName(t *testing.T) {
	all := []storage.User{
		{ID: 1, Username: "admin"},
		{ID: 2, Username: "root"},
		{ID: 3, Username: "pat@example.com", DisplayName: "Pat Smith"},
		{ID: 4, Username: "cara@example.com"},
		{ID: 5, Username: "poe"},
		{ID: 6, Username: "dam"},
	}
	me := all[3]
	for raw, want := range map[string]string{
		// Real names are shown, tidied.
		"Cara Jones":              "Cara Jones",
		"  José   Ñúñez-O'Brien ": "José Ñúñez-O'Brien",
		"Сергей Иванов":           "Сергей Иванов", // all Cyrillic is a name
		"Smith, John Jr.":         "Smith, John Jr.",
		"Ｃａｒａ　Ｊｏｎｅｓ":              "Cara Jones", // fullwidth becomes ordinary
		"Cara\u200b Jones\u00ad":  "Cara Jones", // invisible characters go
		// Anything that could pass for another account is not.
		"ADMIN":                     "",
		"ＡＤＭＩＮ":                     "", // fullwidth
		"ad\u200bmin":               "", // zero-width space
		"аdmin":                     "", // Cyrillic а: mixed alphabets
		"\u0440\u043e\u0435":        "", // all Cyrillic р о е, looks like the user poe
		"Admİn":                     "", // dotted capital I
		"r00t":                      "", // digits for letters
		"Pat  Smith":                "", // another person's display name
		"pat smith":                 "",
		"Pаt Smith":                 "", // with a Cyrillic а
		"pat@example.com":           "", // an @ in any form
		"pat＠example.com":           "",
		"Justin (justin@fisni.com)": "",
		"Justin （justin）":           "",          // fullwidth brackets
		"Justin ❨justin❩":           "",          // ornamental brackets
		"cara@example.com":          "",          // its own username
		"Cara\u202eJones":           "CaraJones", // a direction override goes
		"<script>":                  "",
		"":                          "",
		"   ":                       "",
		"123":                       "", // no letters
	} {
		if got := ShowableName(raw, me, all); got != want {
			t.Errorf("ShowableName(%q) = %q, want %q", raw, got, want)
		}
	}
	// Scripts: one alphabet, or Latin with the usual Chinese, Japanese and
	// Korean combinations; nothing else mixed.
	for raw, want := range map[string]string{
		"Tanaka 田中":          "Tanaka 田中",
		"田中 たなか タナカ":         "田中 たなか タナカ",
		"김민수 Kim":            "김민수 Kim",
		"Ana Αλφα":           "",
		"\u0531rmen":         "", // Armenian Ա with Latin
		"\u13a0\u13aa\u13b7": "", // all Cherokee, looks like the user dam
	} {
		if got := ShowableName(raw, me, all); got != want {
			t.Errorf("ShowableName(%q) = %q, want %q", raw, got, want)
		}
	}
	// Someone keeps their own display name.
	if got := ShowableName("Pat Smith", all[2], all); got != "Pat Smith" {
		t.Errorf("own name = %q", got)
	}
}
