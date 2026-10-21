package ingest

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"siemlite/pkg/ocsf"
	"siemlite/pkg/storage"
)

func TestLateBursts(t *testing.T) {
	var l lateTracker
	t0 := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	old := t0.AddDate(0, -3, 0)
	// 49 from one source isn't a mass ingestion; 50 from another is.
	for i := 0; i < 49; i++ {
		if done := l.note(1, old, true, t0.Add(time.Duration(i)*time.Second)); len(done) != 0 {
			t.Fatal("reported mid-burst")
		}
	}
	for i := 0; i < 45; i++ {
		l.note(2, old.Add(time.Duration(i)*time.Hour), true, t0)
	}
	for i := 0; i < 5; i++ {
		l.note(2, old.AddDate(0, 0, -i), false, t0)
	}
	if done := l.sweep(t0.Add(30 * time.Second)); len(done) != 0 {
		t.Errorf("reported before going quiet: %+v", done)
	}
	done := l.sweep(t0.Add(2 * time.Minute))
	if len(done) != 1 || done[0].SourceID != 2 || done[0].Stored != 45 || done[0].Refused != 5 ||
		!done[0].Oldest.Equal(old.AddDate(0, 0, -4)) || !done[0].Newest.Equal(old.Add(44*time.Hour)) {
		t.Fatalf("done = %+v", done)
	}
	// A burst that never goes quiet is reported after lateMax, and counting starts again.
	start := t0.Add(time.Hour)
	var got []LateBatch
	for i := 0; i < 700; i++ {
		got = append(got, l.note(3, old, true, start.Add(time.Duration(i)*time.Second))...)
	}
	if len(got) != 1 || got[0].Stored != 600 {
		t.Errorf("long burst = %+v", got)
	}
}

// TestLateEventsAreStoredAndCounted: an event more than 30 days old is
// stored under its own date and counted; one older than the retention
// period is refused and counted; recent ones aren't counted. Changing the
// retention period applies at once.
func TestLateEventsAreStoredAndCounted(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var mu sync.Mutex
	var reports []LateBatch
	w := New(storage.NewRepository(db), Config{FlushInterval: 10 * time.Millisecond, MaxAge: 730 * 24 * time.Hour,
		OnLateBatch: func(b LateBatch) { mu.Lock(); reports = append(reports, b); mu.Unlock() }})
	defer w.Close()
	now := time.Now()
	submit := func(at time.Time) error {
		return w.SubmitWith(ctx, &ocsf.Event{Time: at.UnixMilli(), CategoryUID: 6, ClassUID: 6003, SeverityID: 2, RawData: "x"}, SubmitOptions{SourceID: 7})
	}
	for i := 0; i < 55; i++ {
		if err := submit(now.AddDate(0, 0, -40-i)); err != nil {
			t.Fatalf("a 40-day-old event was refused: %v", err)
		}
	}
	if err := submit(now.AddDate(-3, 0, 0)); err == nil {
		t.Error("a 3-year-old event was stored")
	}
	for i := 0; i < 100; i++ {
		submit(now.Add(-time.Duration(i) * time.Minute))
	}
	w.EndLateBursts()
	mu.Lock()
	if len(reports) != 1 || reports[0].SourceID != 7 || reports[0].Stored != 55 || reports[0].Refused != 1 {
		t.Errorf("reports = %+v", reports)
	}
	mu.Unlock()
	w.Drain(ctx)
	// Stored under their own days, with their own severity.
	if days := db.Days(); len(days) < 50 {
		t.Errorf("only %d day files: the late events weren't stored under their dates", len(days))
	}
	w.SetMaxAge(30 * 24 * time.Hour)
	if err := submit(now.AddDate(0, 0, -40)); err == nil {
		t.Error("after shortening the retention period, a 40-day-old event was stored")
	}
}
