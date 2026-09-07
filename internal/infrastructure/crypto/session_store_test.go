package crypto

import (
	"testing"
	"time"

	"github.com/Hawthorne-Labs/crypto-bff-go/internal/domain/fle"
)

func TestSessionStorePutAndGet(t *testing.T) {
	store := NewInMemorySessionStore(100)
	session := &fle.CryptoSession{
		SessionID:          "sess-1",
		TenantID:           "default",
		CryptoVersion:      "enc:v1",
		SessionKey:         make([]byte, 32),
		ExpiresAtMonotonic: time.Now().Add(5 * time.Minute),
		ExpiresAtEpoch:     time.Now().Add(5 * time.Minute),
	}
	if err := store.Put(session); err != nil {
		t.Fatalf("put failed: %v", err)
	}
	got, err := store.Get("default", "sess-1")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected session, got nil")
	}
	if got.SessionID != "sess-1" {
		t.Errorf("expected sess-1, got %s", got.SessionID)
	}
}

func TestSessionStoreGetMissing(t *testing.T) {
	store := NewInMemorySessionStore(100)
	got, err := store.Get("default", "nonexistent")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if got != nil {
		t.Error("expected nil for missing session")
	}
}

func TestSessionStoreGetExpired(t *testing.T) {
	store := NewInMemorySessionStore(100)
	session := &fle.CryptoSession{
		SessionID:          "sess-expired",
		TenantID:           "default",
		CryptoVersion:      "enc:v1",
		SessionKey:         make([]byte, 32),
		ExpiresAtMonotonic: time.Now().Add(-1 * time.Second),
		ExpiresAtEpoch:     time.Now().Add(-1 * time.Second),
	}
	if err := store.Put(session); err != nil {
		t.Fatalf("put failed: %v", err)
	}
	got, err := store.Get("default", "sess-expired")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if got != nil {
		t.Error("expected nil for expired session")
	}
}

func TestSessionStoreDelete(t *testing.T) {
	store := NewInMemorySessionStore(100)
	session := &fle.CryptoSession{
		SessionID:          "sess-del",
		TenantID:           "default",
		CryptoVersion:      "enc:v1",
		SessionKey:         make([]byte, 32),
		ExpiresAtMonotonic: time.Now().Add(5 * time.Minute),
		ExpiresAtEpoch:     time.Now().Add(5 * time.Minute),
	}
	_ = store.Put(session)
	_ = store.Delete("default", "sess-del")
	got, _ := store.Get("default", "sess-del")
	if got != nil {
		t.Error("expected nil after delete")
	}
}

func TestSessionStoreEviction(t *testing.T) {
	store := NewInMemorySessionStore(2)
	for i := 0; i < 3; i++ {
		_ = store.Put(&fle.CryptoSession{
			SessionID:          "sess-" + string(rune('a'+i)),
			TenantID:           "default",
			CryptoVersion:      "enc:v1",
			SessionKey:         make([]byte, 32),
			ExpiresAtMonotonic: time.Now().Add(5 * time.Minute),
			ExpiresAtEpoch:     time.Now().Add(5 * time.Minute),
		})
	}
	first, _ := store.Get("default", "sess-a")
	if first != nil {
		t.Error("expected sess-a to be evicted")
	}
	third, _ := store.Get("default", "sess-c")
	if third == nil {
		t.Error("expected sess-c to exist")
	}
}

func TestSessionStoreTenantIsolation(t *testing.T) {
	store := NewInMemorySessionStore(100)
	for _, tid := range []string{"tenant-a", "tenant-b"} {
		_ = store.Put(&fle.CryptoSession{
			SessionID:          "sess-shared",
			TenantID:           tid,
			CryptoVersion:      "enc:v1",
			SessionKey:         make([]byte, 32),
			ExpiresAtMonotonic: time.Now().Add(5 * time.Minute),
			ExpiresAtEpoch:     time.Now().Add(5 * time.Minute),
		})
	}
	a, _ := store.Get("tenant-a", "sess-shared")
	b, _ := store.Get("tenant-b", "sess-shared")
	if a == nil || b == nil {
		t.Fatal("both tenant sessions should exist")
	}
}

func TestSessionStoreOverwrite(t *testing.T) {
	store := NewInMemorySessionStore(100)
	_ = store.Put(&fle.CryptoSession{
		SessionID:          "sess-ow",
		TenantID:           "default",
		CryptoVersion:      "enc:v1",
		SessionKey:         []byte{1},
		ExpiresAtMonotonic: time.Now().Add(5 * time.Minute),
		ExpiresAtEpoch:     time.Now().Add(5 * time.Minute),
	})
	_ = store.Put(&fle.CryptoSession{
		SessionID:          "sess-ow",
		TenantID:           "default",
		CryptoVersion:      "enc:v1",
		SessionKey:         []byte{2},
		ExpiresAtMonotonic: time.Now().Add(5 * time.Minute),
		ExpiresAtEpoch:     time.Now().Add(5 * time.Minute),
	})
	got, _ := store.Get("default", "sess-ow")
	if got == nil {
		t.Fatal("expected session")
	}
	if got.SessionKey[0] != 2 {
		t.Errorf("expected overwritten key [2], got [%d]", got.SessionKey[0])
	}
}
