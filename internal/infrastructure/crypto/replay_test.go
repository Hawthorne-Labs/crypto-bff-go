package crypto

import (
	"testing"
	"time"
)

func TestReplayProtectorFirstRequest(t *testing.T) {
	p := NewInMemoryReplayProtector(5*time.Minute, 1000)
	err := p.CheckAndMark("default", "enc:v1", "sess-1", "req-1")
	if err != nil {
		t.Fatalf("first request should succeed: %v", err)
	}
}

func TestReplayProtectorDetectsReplay(t *testing.T) {
	p := NewInMemoryReplayProtector(5*time.Minute, 1000)
	_ = p.CheckAndMark("default", "enc:v1", "sess-1", "req-1")
	err := p.CheckAndMark("default", "enc:v1", "sess-1", "req-1")
	if err == nil {
		t.Fatal("expected replay error on duplicate request")
	}
}

func TestReplayProtectorDifferentRequestIDs(t *testing.T) {
	p := NewInMemoryReplayProtector(5*time.Minute, 1000)
	_ = p.CheckAndMark("default", "enc:v1", "sess-1", "req-1")
	err := p.CheckAndMark("default", "enc:v1", "sess-1", "req-2")
	if err != nil {
		t.Fatalf("different request ID should succeed: %v", err)
	}
}

func TestReplayProtectorDifferentTenants(t *testing.T) {
	p := NewInMemoryReplayProtector(5*time.Minute, 1000)
	_ = p.CheckAndMark("tenant-a", "enc:v1", "sess-1", "req-1")
	err := p.CheckAndMark("tenant-b", "enc:v1", "sess-1", "req-1")
	if err != nil {
		t.Fatalf("same request ID in different tenant should succeed: %v", err)
	}
}

func TestReplayProtectorEvictsExpired(t *testing.T) {
	p := NewInMemoryReplayProtector(1*time.Millisecond, 1000)
	_ = p.CheckAndMark("default", "enc:v1", "sess-1", "req-1")
	time.Sleep(5 * time.Millisecond)
	err := p.CheckAndMark("default", "enc:v1", "sess-1", "req-1")
	if err != nil {
		t.Fatalf("expired entry should allow replay: %v", err)
	}
}

func TestReplayProtectorCapacityEviction(t *testing.T) {
	p := NewInMemoryReplayProtector(5*time.Minute, 3)
	for i := 0; i < 5; i++ {
		_ = p.CheckAndMark("default", "enc:v1", "sess-1", "req-"+string(rune('0'+i)))
	}
	err := p.CheckAndMark("default", "enc:v1", "sess-1", "req-new")
	if err != nil {
		t.Fatalf("should succeed after eviction: %v", err)
	}
}

func TestReplayProtectorDefaultCapacity(t *testing.T) {
	p := NewInMemoryReplayProtector(5*time.Minute, 0)
	if p.maxEntries != 200000 {
		t.Errorf("expected default capacity 200000, got %d", p.maxEntries)
	}
}
