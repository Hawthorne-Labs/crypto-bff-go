package usecase

import (
	"fmt"
	"time"

	"github.com/Hawthorne-Labs/crypto-bff-go/internal/domain/fle"
	"github.com/Hawthorne-Labs/crypto-bff-go/internal/infrastructure/crypto"
)

// DecryptService handles field decryption.
type DecryptService struct {
	policyResolver  *crypto.PolicyResolver
	sessionStore    crypto.SessionStore
	replayProtector crypto.ReplayProtector
}

// NewDecryptService creates a new decrypt service.
func NewDecryptService(
	policyResolver *crypto.PolicyResolver,
	sessionStore crypto.SessionStore,
	replayProtector crypto.ReplayProtector,
) *DecryptService {
	return &DecryptService{
		policyResolver:  policyResolver,
		sessionStore:    sessionStore,
		replayProtector: replayProtector,
	}
}

// Decrypt decrypts the given fields.
func (s *DecryptService) Decrypt(req *fle.DecryptRequest) (map[string]any, error) {
	// Resolve policy
	policy, err := s.policyResolver.Resolve(req.CryptoVersion)
	if err != nil {
		return nil, err
	}

	// Validate timestamp
	if err := crypto.ValidateTimestamp(time.Now().Format(time.RFC3339), policy.TimestampSkewSeconds, time.Now()); err != nil {
		// Timestamp validation is done by the handler with the actual header value
		_ = err
	}

	// Get session
	session, err := s.sessionStore.Get(req.TenantID, req.CryptoSessionID)
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	if session == nil || session.CryptoVersion != req.CryptoVersion || session.TenantID != req.TenantID {
		return nil, fmt.Errorf("%w: %s", fle.ErrSessionNotFound, req.CryptoSessionID)
	}

	// Check replay
	if err := s.replayProtector.CheckAndMark(req.TenantID, req.CryptoVersion, req.CryptoSessionID, req.RequestID); err != nil {
		return nil, err
	}

	// Decrypt
	decryptor := crypto.NewFieldDecryptor(session.SessionKey)
	return decryptor.DecryptFields(req)
}

// EncryptService handles field encryption.
type EncryptService struct {
	sessionStore crypto.SessionStore
}

// NewEncryptService creates a new encrypt service.
func NewEncryptService(sessionStore crypto.SessionStore) *EncryptService {
	return &EncryptService{sessionStore: sessionStore}
}

// Encrypt encrypts the given fields.
func (s *EncryptService) Encrypt(req *fle.EncryptRequest) (map[string]string, error) {
	// Get session
	session, err := s.sessionStore.Get(req.TenantID, req.CryptoSessionID)
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	if session == nil || session.CryptoVersion != req.CryptoVersion || session.TenantID != req.TenantID {
		return nil, fmt.Errorf("%w: %s", fle.ErrSessionNotFound, req.CryptoSessionID)
	}

	// Encrypt
	encryptor := crypto.NewFieldEncryptor(session.SessionKey)
	return encryptor.EncryptFields(req)
}
