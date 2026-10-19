package auth

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestTakeIsAtomic: concurrent attempts can't get past the limit between
// being checked and being counted.
func TestTakeIsAtomic(t *testing.T) {
	l := newLoginLimiter(maxFailures)
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.take("7") {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != maxFailures {
		t.Errorf("%d attempts allowed, want %d", got, maxFailures)
	}
	l.reset("7")
	if !l.take("7") {
		t.Error("still blocked after a reset")
	}
}
