package fle

import "time"

// CryptoPolicy defines the cryptographic parameters for a version.
type CryptoPolicy struct {
	CryptoVersion        string
	Mode                 string
	KeyAgreement         string
	KDF                  string
	KDFInfo              []byte
	Cipher               string
	NonceSize            int
	TagSize              int
	Encoding             string
	AADStrategy          string
	KeyID                string
	SessionTTLSeconds    int
	TimestampSkewSeconds int
	Enabled              bool
	ExpiresAt            *time.Time
}

// DefaultPolicies returns the supported crypto policies.
func DefaultPolicies() []*CryptoPolicy {
	expires := time.Date(2027, 12, 31, 23, 59, 59, 0, time.UTC)
	return []*CryptoPolicy{
		{
			CryptoVersion:        "enc:v1",
			Mode:                 "schema-preserving-field-level",
			KeyAgreement:         "X25519",
			KDF:                  "HKDF-SHA256",
			KDFInfo:              []byte("sp-fle-v1/session"),
			Cipher:               "AES-256-GCM",
			NonceSize:            12,
			TagSize:              16,
			Encoding:             "base64url",
			AADStrategy:          "method:path:crypto_version:crypto_session_id:request_id:field_path",
			KeyID:                "internal-bff-x25519-active-key",
			SessionTTLSeconds:    300,
			TimestampSkewSeconds: 300,
			Enabled:              true,
			ExpiresAt:            &expires,
		},
	}
}
