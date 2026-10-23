package httpapi

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLimiterConcurrentRequestsAndReset(t *testing.T) {
	l := &windowLimiter{limit: 10}
	now := time.Now()
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			if ok, _ := l.allow("same-ip", now); ok {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 10 {
		t.Fatalf("accepted %d, want 10", accepted.Load())
	}
	if ok, retry := l.allow("same-ip", now.Add(59*time.Second)); ok || retry != 1 {
		t.Fatalf("ok=%v retry=%d", ok, retry)
	}
	if ok, _ := l.allow("same-ip", now.Add(time.Minute)); !ok {
		t.Fatal("window did not reset")
	}
}

func TestLimiterBoundsMemory(t *testing.T) {
	l := &windowLimiter{limit: 2}
	now := time.Now()
	for i := range 10000 {
		if ok, _ := l.allow(fmt.Sprint(i), now); !ok {
			t.Fatalf("unexpected rejection at %d", i)
		}
	}
	if ok, _ := l.allow("new-client", now); ok {
		t.Fatal("new client should be rejected at capacity")
	}
	if ok, _ := l.allow("0", now); !ok {
		t.Fatal("existing client lost its quota")
	}
	if ok, _ := l.allow("new-client", now.Add(time.Minute)); !ok {
		t.Fatal("capacity did not reset")
	}
}
