package agents

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/integrations"
	"siemlite/pkg/storage"
)

func setup(t *testing.T) (*Service, *storage.Repository) {
	t.Helper()
	db, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(t.TempDir(), "a.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	repo := storage.NewRepository(db)
	return New(repo), repo
}

func TestTokenLifecycle(t *testing.T) {
	s, repo := setup(t)
	ctx := context.Background()

	tok, plain, err := s.Create(ctx, "  Claude  ", storage.AgentAnalyst, "root")
	if err != nil || tok.Name != "Claude" || !strings.HasPrefix(plain, "slmcp_") || len(plain) < 40 {
		t.Fatalf("create = %+v %q %v", tok, plain, err)
	}
	// Only a hash is stored: the token is nowhere in the database.
	all, _ := repo.ListAgentTokens(ctx)
	if len(all) != 1 || all[0].CreatedBy != "root" || all[0].LastUsedAt != nil {
		t.Fatalf("list = %+v", all)
	}
	if _, err := repo.FindAgentToken(ctx, plain); !errors.Is(err, storage.ErrAgentTokenNotFound) {
		t.Errorf("the token itself matched a hash: %v", err)
	}

	got, err := s.Authenticate(ctx, plain)
	if err != nil || got.ID != tok.ID || got.Level != storage.AgentAnalyst {
		t.Fatalf("authenticate = %+v %v", got, err)
	}
	for _, bad := range []string{"", "slmcp_", "slmcp_wrong", "slk_" + plain[len("slmcp_"):], plain + "x", strings.ToUpper(plain)} {
		if _, err := s.Authenticate(ctx, bad); !errors.Is(err, ErrBadToken) {
			t.Errorf("%q authenticated: %v", bad, err)
		}
	}

	// Use is recorded, but at most once a minute.
	now := time.Now()
	s.now = func() time.Time { return now }
	s.touched = map[int64]time.Time{}
	s.Authenticate(ctx, plain)
	first := lastUsed(t, repo, tok.ID)
	s.now = func() time.Time { return now.Add(10 * time.Second) }
	s.Authenticate(ctx, plain)
	if got := lastUsed(t, repo, tok.ID); got != first {
		t.Errorf("last used moved within a minute: %d -> %d", first, got)
	}
	s.now = func() time.Time { return now.Add(2 * time.Minute) }
	s.Authenticate(ctx, plain)
	if got := lastUsed(t, repo, tok.ID); got <= first {
		t.Errorf("last used didn't move after a minute: %d -> %d", first, got)
	}

	if _, err := s.Remove(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, plain); !errors.Is(err, ErrBadToken) {
		t.Errorf("a removed token still works: %v", err)
	}
	if _, err := s.Remove(ctx, tok.ID); !errors.Is(err, storage.ErrAgentTokenNotFound) {
		t.Errorf("removing twice = %v", err)
	}
}

func lastUsed(t *testing.T, repo *storage.Repository, id int64) int64 {
	t.Helper()
	all, _ := repo.ListAgentTokens(context.Background())
	for _, x := range all {
		if x.ID == id && x.LastUsedAt != nil {
			return *x.LastUsedAt
		}
	}
	return 0
}

func TestCreateValidates(t *testing.T) {
	s, _ := setup(t)
	ctx := context.Background()
	for name, tc := range map[string]struct{ name, level string }{
		"no name": {"   ", "read"}, "long name": {strings.Repeat("x", 61), "read"}, "control": {"a\nb", "read"},
		"no level": {"ok", ""}, "unknown level": {"ok", "owner"},
	} {
		_, _, err := s.Create(ctx, tc.name, tc.level, "root")
		var bad integrations.InputError
		if !errors.As(err, &bad) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := s.Create(ctx, "Reader", "read", "root"); err != nil {
		t.Fatal(err)
	}
	var bad integrations.InputError
	if _, _, err := s.Create(ctx, "reader", "admin", "root"); !errors.As(err, &bad) {
		t.Errorf("a duplicate name (any case) = %v", err)
	}
}

func TestIntegrationCard(t *testing.T) {
	s, _ := setup(t)
	ctx := context.Background()
	info := integrations.Describe(ctx, s)
	if info.State != integrations.StateNeedsSetup || info.ID != "mcp" {
		t.Errorf("no tokens: %+v", info)
	}
	s.Create(ctx, "a", "read", "root")
	s.Create(ctx, "b", "read", "root")
	s.Create(ctx, "c", "admin", "root")
	if info = integrations.Describe(ctx, s); info.State != integrations.StateOn || info.Summary != "3 tokens (2 read-only, 1 admin)" {
		t.Errorf("three tokens: %+v", info)
	}
	if err := s.SetEnabled(ctx, false); err != nil {
		t.Fatal(err)
	}
	if info = integrations.Describe(ctx, s); info.State != integrations.StateOff || info.Enabled {
		t.Errorf("switched off: %+v", info)
	}
	if on, _ := s.Enabled(ctx); on {
		t.Error("still enabled")
	}
	s.SetEnabled(ctx, true)
	if on, _ := s.Enabled(ctx); !on {
		t.Error("not enabled again")
	}
}
