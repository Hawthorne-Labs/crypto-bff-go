package crypto

import (
	"sync"
	"time"

	"github.com/Hawthorne-Labs/crypto-bff-go/internal/domain/fle"
)

// SessionStore manages FLE sessions.
type SessionStore interface {
	Put(session *fle.CryptoSession) error
	Get(tenantID, sessionID string) (*fle.CryptoSession, error)
	Delete(tenantID, sessionID string) error
}

// InMemorySessionStore is a thread-safe in-memory session store with LRU eviction.
type InMemorySessionStore struct {
	entries    map[string]*fle.CryptoSession
	order      []string
	maxEntries int
	mu         sync.RWMutex
}

// NewInMemorySessionStore creates a store with the given capacity.
func NewInMemorySessionStore(maxEntries int) *InMemorySessionStore {
	if maxEntries <= 0 {
		maxEntries = 100000
	}
	return &InMemorySessionStore{
		entries:    make(map[string]*fle.CryptoSession),
		order:      make([]string, 0, maxEntries),
		maxEntries: maxEntries,
	}
}

func scopedKey(tenantID, sessionID string) string {
	return tenantID + "|" + sessionID
}

// Put stores a session.
func (s *InMemorySessionStore) Put(session *fle.CryptoSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := scopedKey(session.TenantID, session.SessionID)
	if _, exists := s.entries[key]; !exists {
		// Evict oldest if at capacity
		for len(s.entries) >= s.maxEntries && len(s.order) > 0 {
			oldest := s.order[0]
			s.order = s.order[1:]
			delete(s.entries, oldest)
		}
		s.order = append(s.order, key)
	}
	s.entries[key] = session
	return nil
}

// Get retrieves a session if it exists and hasn't expired.
func (s *InMemorySessionStore) Get(tenantID, sessionID string) (*fle.CryptoSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := scopedKey(tenantID, sessionID)
	session, exists := s.entries[key]
	if !exists {
		return nil, nil
	}
	if time.Now().After(session.ExpiresAtMonotonic) {
		return nil, nil
	}
	return session, nil
}

// Delete removes a session.
func (s *InMemorySessionStore) Delete(tenantID, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := scopedKey(tenantID, sessionID)
	delete(s.entries, key)
	// Note: order slice cleanup is deferred to eviction
	return nil
}
