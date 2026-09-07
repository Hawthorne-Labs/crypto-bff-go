package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
)

// KeyProvider provides X25519 keys for FLE operations.
type KeyProvider interface {
	PrivateKey(keyID string) (*ecdh.PrivateKey, error)
	PublicKeyB64URL(keyID string) (string, error)
}

// StaticKeyProvider holds a single static key pair (for local development).
type StaticKeyProvider struct {
	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey
	mu         sync.RWMutex
}

// NewStaticKeyProvider creates a provider with a pre-generated key pair.
func NewStaticKeyProvider(privKey *ecdh.PrivateKey) *StaticKeyProvider {
	return &StaticKeyProvider{
		privateKey: privKey,
		publicKey:  privKey.PublicKey(),
	}
}

// PrivateKey returns the private key.
func (p *StaticKeyProvider) PrivateKey(keyID string) (*ecdh.PrivateKey, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.privateKey, nil
}

// PublicKeyB64URL returns the public key as base64url.
func (p *StaticKeyProvider) PublicKeyB64URL(keyID string) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pubBytes := p.publicKey.Bytes()
	return base64.RawURLEncoding.EncodeToString(pubBytes), nil
}

// GenerateKeyPair generates a new X25519 key pair.
func GenerateKeyPair() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// PrivateKeyFromBytes parses a 32-byte X25519 private key.
func PrivateKeyFromBytes(raw []byte) (*ecdh.PrivateKey, error) {
	if len(raw) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(raw))
	}
	return ecdh.X25519().NewPrivateKey(raw)
}
