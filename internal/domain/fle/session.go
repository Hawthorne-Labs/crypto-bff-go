package fle

import "time"

// CryptoSession represents an active FLE session.
type CryptoSession struct {
	SessionID          string
	TenantID           string
	CryptoVersion      string
	SessionKey         []byte
	ExpiresAtMonotonic time.Time
	ExpiresAtEpoch     time.Time
}

// HandshakeResult contains the data returned after a successful handshake.
type HandshakeResult struct {
	SessionID            string
	TenantID             string
	ExpiresAtEpoch       time.Time
	ServerPublicKeyB64URL string
	SaltB64URL           string
	AccessToken          string
}

// DecryptRequest contains the parameters for field decryption.
type DecryptRequest struct {
	Method          string
	Path            string
	Fields          map[string]string
	CryptoVersion   string
	CryptoSessionID string
	RequestID       string
	TenantID        string
}

// EncryptRequest contains the parameters for field encryption.
type EncryptRequest struct {
	Method          string
	Path            string
	Fields          map[string]any
	CryptoVersion   string
	CryptoSessionID string
	RequestID       string
	TenantID        string
}
