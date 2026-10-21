package ingest

import (
	"sync"
	"time"
)

// Late events: events dated well before they arrive, such as a batch of old
// logs sent all at once. They are stored under their own date (as long as it
// is within the retention period) and keep their own severity, but many from
// one source in one go is worth knowing about, so it is reported once the
// burst is over.
const (
	// LateAfter is how old an event must be, when it arrives, to count as late.
	LateAfter = 30 * 24 * time.Hour
	// LateBurst is how many late events from one source make a mass ingestion.
	LateBurst = 50
	// A burst ends when a source sends no late events for lateQuiet, or after lateMax.
	lateQuiet = time.Minute
	lateMax   = 10 * time.Minute
)

// LateBatch is a burst of late events from one source.
type LateBatch struct {
	SourceID       int64
	Stored         int // within the retention period
	Refused        int // older than the retention period
	Oldest, Newest time.Time
	Start, End     time.Time // when they arrived
}

type lateTracker struct {
	mu     sync.Mutex
	bursts map[int64]*LateBatch
}

// note counts one late event; it returns the bursts that have ended.
func (l *lateTracker) note(source int64, t time.Time, stored bool, now time.Time) []LateBatch {
	l.mu.Lock()
	defer l.mu.Unlock()
	done := l.sweepLocked(now)
	if l.bursts == nil {
		l.bursts = map[int64]*LateBatch{}
	}
	b := l.bursts[source]
	if b == nil {
		b = &LateBatch{SourceID: source, Oldest: t, Newest: t, Start: now}
		l.bursts[source] = b
	}
	if stored {
		b.Stored++
	} else {
		b.Refused++
	}
	if t.Before(b.Oldest) {
		b.Oldest = t
	}
	if t.After(b.Newest) {
		b.Newest = t
	}
	b.End = now
	return done
}

// sweep returns the bursts that have ended by now.
func (l *lateTracker) sweep(now time.Time) []LateBatch {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sweepLocked(now)
}

func (l *lateTracker) sweepLocked(now time.Time) []LateBatch {
	var done []LateBatch
	for src, b := range l.bursts {
		if now.Sub(b.End) < lateQuiet && now.Sub(b.Start) < lateMax {
			continue
		}
		delete(l.bursts, src)
		if b.Stored+b.Refused >= LateBurst {
			done = append(done, *b)
		}
	}
	return done
}
