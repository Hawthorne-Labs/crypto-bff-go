// Package usecase implements FLE application services.
package usecase

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/Hawthorne-Labs/crypto-bff-go/internal/domain/fle"
	"github.com/Hawthorne-Labs/crypto-bff-go/internal/infrastructure/crypto"
	"golang.org/x/crypto/hkdf"
	"io"
	"crypto/sha256"
)

const (
	x25519PublicKeyBytes = 32
	sessionKeyBytes      = 32
)

// HandshakeService performs FLE handshake operations.
type HandshakeService struct {
	policyResolver *crypto.PolicyResolver
	keyProvider    crypto.KeyProvider
	sessionStore   crypto.SessionStore
}

// NewHandshakeService creates a new handshake service.
func NewHandshakeService(
	policyResolver *crypto.PolicyResolver,
	keyProvider crypto.KeyProvider,
	sessionStore crypto.SessionStore,
) *HandshakeService {
	return &HandshakeService{
		policyResolver: policyResolver,
		keyProvider:    keyProvider,
		sessionStore:   sessionStore,
	}
}

// Perform executes the handshake protocol.
func (s *HandshakeService) Perform(cryptoVersion, clientPublicKeyB64URL, tenantID string) (*fle.HandshakeResult, error) {
	if tenantID == "" {
		tenantID = "default"
	}

	policy, err := s.policyResolver.Resolve(cryptoVersion)
	if err != nil {
		return nil, err
	}

	// Decode and validate client public key
	clientPublicRaw, err := crypto.Base64URLDecode(clientPublicKeyB64URL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid client public key", fle.ErrHandshakePayloadInvalid)
	}
	if len(clientPublicRaw) != x25519PublicKeyBytes {
		return nil, fmt.Errorf("%w: client public key must be 32 bytes", fle.ErrHandshakePayloadInvalid)
	}

	clientPub, err := ecdh.X25519().NewPublicKey(clientPublicRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid client public key", fle.ErrHandshakePayloadInvalid)
	}

	// Get BFF private key
	bffPriv, err := s.keyProvider.PrivateKey(policy.KeyID)
	if err != nil {
		return nil, fmt.Errorf("get private key: %w", err)
	}
	bffPub := bffPriv.PublicKey()

	// Perform X25519 key exchange
	sharedSecret, err := bffPriv.ECDH(clientPub)
	if err != nil {
		return nil, fmt.Errorf("%w: key exchange failed", fle.ErrHandshakePayloadInvalid)
	}

	// Generate salt and derive session key
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	sessionKey, err := deriveSessionKey(sharedSecret, policy, tenantID, salt)
	if err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}

	// Create session
	sessionID := newSessionID(policy)
	now := time.Now()
	expiresEpoch := now.Add(time.Duration(policy.SessionTTLSeconds) * time.Second)
	expiresMonotonic := now.Add(time.Duration(policy.SessionTTLSeconds) * time.Second)

	session := &fle.CryptoSession{
		SessionID:          sessionID,
		TenantID:           tenantID,
		CryptoVersion:      policy.CryptoVersion,
		SessionKey:         sessionKey,
		ExpiresAtMonotonic: expiresMonotonic,
		ExpiresAtEpoch:     expiresEpoch,
	}

	if err := s.sessionStore.Put(session); err != nil {
		return nil, fmt.Errorf("store session: %w", err)
	}

	// Generate access token
	accessToken := generateAccessToken()

	return &fle.HandshakeResult{
		SessionID:             sessionID,
		TenantID:              tenantID,
		ExpiresAtEpoch:        expiresEpoch,
		ServerPublicKeyB64URL: crypto.Base64URLEncode(bffPub.Bytes()),
		SaltB64URL:            crypto.Base64URLEncode(salt),
		AccessToken:           accessToken,
	}, nil
}

func deriveSessionKey(sharedSecret []byte, policy *fle.CryptoPolicy, tenantID string, salt []byte) ([]byte, error) {
	scopedInfo := append(policy.KDFInfo, '|')
	scopedInfo = append(scopedInfo, []byte(tenantID)...)

	reader := hkdf.New(sha256.New, sharedSecret, salt, scopedInfo)
	key := make([]byte, sessionKeyBytes)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func newSessionID(policy *fle.CryptoPolicy) string {
	token := make([]byte, 18)
	rand.Read(token)
	return policy.CryptoVersion + "-" + crypto.Base64URLEncode(token)
}

func generateAccessToken() string {
	token := make([]byte, 32)
	rand.Read(token)
	return crypto.Base64URLEncode(token)
}
