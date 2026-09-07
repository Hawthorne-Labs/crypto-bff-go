// Package crypto implements FLE cryptographic operations.
package crypto

import (
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/Hawthorne-Labs/crypto-bff-go/internal/domain/fle"
)

const (
	NonceSize = 12
	TagSize   = 16
	MinValueBytes = NonceSize + TagSize
)

var b64urlCharset = regexp.MustCompile(`^[A-Za-z0-9_-]+=*$`)

// Base64URLEncode encodes bytes to base64url without padding.
func Base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Base64URLDecode decodes a base64url string (with or without padding).
func Base64URLDecode(value string) ([]byte, error) {
	if value == "" {
		return nil, fle.ErrInvalidEncryptedValue
	}
	if !b64urlCharset.MatchString(value) {
		return nil, fle.ErrInvalidEncryptedValue
	}
	// Add padding if needed
	padding := (4 - len(value)%4) % 4
	padded := value + string(make([]byte, padding))
	for i := len(value); i < len(padded); i++ {
		padded = padded[:i] + "=" + padded[i+1:]
	}
	return base64.RawURLEncoding.DecodeString(value)
}

// Pack combines nonce and ciphertext into a base64url-encoded string.
func Pack(nonce, ciphertextWithTag []byte) (string, error) {
	if len(nonce) != NonceSize {
		return "", fmt.Errorf("%w: nonce must be 12 bytes", fle.ErrInvalidEncryptedValue)
	}
	if len(ciphertextWithTag) < TagSize {
		return "", fmt.Errorf("%w: ciphertext too short for tag", fle.ErrInvalidEncryptedValue)
	}
	combined := make([]byte, len(nonce)+len(ciphertextWithTag))
	copy(combined, nonce)
	copy(combined[len(nonce):], ciphertextWithTag)
	return Base64URLEncode(combined), nil
}

// Unpack splits a base64url-encoded value into nonce and ciphertext.
func Unpack(value string) (nonce, ciphertextWithTag []byte, err error) {
	raw, err := Base64URLDecode(value)
	if err != nil {
		return nil, nil, err
	}
	if len(raw) < MinValueBytes {
		return nil, nil, fmt.Errorf("%w: encrypted value below minimum length", fle.ErrInvalidEncryptedValue)
	}
	nonce = make([]byte, NonceSize)
	copy(nonce, raw[:NonceSize])
	ciphertextWithTag = make([]byte, len(raw)-NonceSize)
	copy(ciphertextWithTag, raw[NonceSize:])
	return nonce, ciphertextWithTag, nil
}
