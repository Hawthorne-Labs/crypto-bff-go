package crypto

import (
	"sync"
	"time"

	"github.com/Hawthorne-Labs/crypto-bff-go/internal/domain/fle"
)

// ReplayProtector prevents request replay attacks.
type ReplayProtector interface {
	CheckAndMark(tenantID, cryptoVersion, sessionID, requestID string) error
}

// InMemoryReplayProtector tracks request IDs with TTL-based expiration.
type InMemoryReplayProtector struct {
	entries    map[string]time.Time
	order      []string
	ttl        time.Duration
	maxEntries int
	mu         sync.Mutex
}

// NewInMemoryReplayProtector creates a protector with the given TTL and capacity.
func NewInMemoryReplayProtector(ttl time.Duration, maxEntries int) *InMemoryReplayProtector {
	if maxEntries <= 0 {
		maxEntries = 200000
	}
	return &InMemoryReplayProtector{
		entries:    make(map[string]time.Time),
		order:      make([]string, 0, maxEntries),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

func replayKey(tenantID, cryptoVersion, sessionID, requestID string) string {
	return tenantID + "|" + cryptoVersion + "|" + sessionID + "|" + requestID
}

// CheckAndMark verifies the request ID hasn't been seen and marks it.
func (p *InMemoryReplayProtector) CheckAndMark(tenantID, cryptoVersion, sessionID, requestID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	key := replayKey(tenantID, cryptoVersion, sessionID, requestID)

	// Evict expired entries
	for len(p.order) > 0 {
		oldestKey := p.order[0]
		if exp, exists := p.entries[oldestKey]; exists && exp.After(now) {
			break
		}
		delete(p.entries, oldestKey)
		p.order = p.order[1:]
	}

	// Check for replay
	if exp, exists := p.entries[key]; exists && exp.After(now) {
		return fle.ErrReplayDetected
	}

	// Evict if at capacity
	for len(p.entries) >= p.maxEntries && len(p.order) > 0 {
		oldest := p.order[0]
		p.order = p.order[1:]
		delete(p.entries, oldest)
	}

	p.entries[key] = now.Add(p.ttl)
	p.order = append(p.order, key)
	return nil
}
