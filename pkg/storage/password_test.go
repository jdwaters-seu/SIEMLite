package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// TestChangeOwnPasswordIsAllOrNothing: if the new session can't be stored,
// the password and the old sessions are left as they were.
func TestChangeOwnPasswordIsAllOrNothing(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewRepository(db)
	sam, _ := repo.CreateUser(ctx, "sam", "old-hash", "standard", 1)
	ann, _ := repo.CreateUser(ctx, "ann", "ann-hash", "standard", 1)
	if err := repo.CreateSession(ctx, "sam-session", sam, 1, 1<<50); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSession(ctx, "ann-session", ann, 1, 1<<50); err != nil {
		t.Fatal(err)
	}

	// A token hash that is already taken makes the last step fail.
	if err := repo.ChangeOwnPassword(ctx, sam, "new-hash", "ann-session", 2, 1<<50); err == nil {
		t.Fatal("a clashing session was stored")
	}
	if _, hash, _ := repo.GetUserWithHash(ctx, sam); hash != "old-hash" {
		t.Errorf("the password changed anyway: %q", hash)
	}
	if _, err := repo.FindSession(ctx, "sam-session", 3); err != nil {
		t.Errorf("the old session ended anyway: %v", err)
	}

	if err := repo.ChangeOwnPassword(ctx, sam, "new-hash", "sam-new", 2, 1<<50); err != nil {
		t.Fatal(err)
	}
	if _, hash, _ := repo.GetUserWithHash(ctx, sam); hash != "new-hash" {
		t.Errorf("hash = %q", hash)
	}
	if _, err := repo.FindSession(ctx, "sam-session", 3); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("the old session survived: %v", err)
	}
	if u, err := repo.FindSession(ctx, "sam-new", 3); err != nil || u.ID != sam {
		t.Errorf("new session = %+v %v", u, err)
	}
	if _, err := repo.FindSession(ctx, "ann-session", 3); err != nil {
		t.Errorf("another user's session ended: %v", err)
	}

	ext, _ := repo.CreateExternalUser(ctx, "entra", "oid-1", "eve@example.com", "standard", 1)
	if err := repo.ChangeOwnPassword(ctx, ext, "h", "eve-new", 2, 1<<50); !errors.Is(err, ErrExternalUser) {
		t.Errorf("external user: %v", err)
	}
	if err := repo.ChangeOwnPassword(ctx, 9999, "h", "nobody", 2, 1<<50); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("missing user: %v", err)
	}
}
