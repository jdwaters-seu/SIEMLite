package web

import (
	"regexp"
	"testing"
)

// TestUniqueIDs guards against two elements sharing an id: the page looks
// elements up by id, which finds only the first, so the second one's handlers
// end up on the wrong element.
func TestUniqueIDs(t *testing.T) {
	page, err := assets.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`\sid="([^"]+)"`).FindAllSubmatch(page, -1) {
		id := string(m[1])
		if seen[id] {
			t.Errorf("id %q is used more than once", id)
		}
		seen[id] = true
	}
	if len(seen) < 100 {
		t.Fatalf("found only %d ids; is the pattern still right?", len(seen))
	}
}
