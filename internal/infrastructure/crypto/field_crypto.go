package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/Hawthorne-Labs/crypto-bff-go/internal/domain/fle"
)

// FieldEncryptor encrypts response fields with the session key.
type FieldEncryptor struct {
	sessionKey []byte
}

// NewFieldEncryptor creates an encryptor with the given session key.
func NewFieldEncryptor(sessionKey []byte) *FieldEncryptor {
	return &FieldEncryptor{sessionKey: sessionKey}
}

// EncryptFields encrypts the given fields and returns them as base64url strings.
func (e *FieldEncryptor) EncryptFields(req *fle.EncryptRequest) (map[string]string, error) {
	aead, err := newGCMFromKey(e.sessionKey)
	if err != nil {
		return nil, err
	}

	encrypted := make(map[string]string, len(req.Fields))
	for fieldPath, value := range req.Fields {
		nonce := make([]byte, NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("generate nonce: %w", err)
		}

		aad := BuildAAD(
			req.Method,
			req.Path,
			req.CryptoVersion,
			req.CryptoSessionID,
			req.RequestID,
			fieldPath,
			req.TenantID,
		)

		plaintext, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("marshal field %s: %w", fieldPath, err)
		}

		ciphertext := aead.Seal(nil, nonce, plaintext, aad)
		packed, err := Pack(nonce, ciphertext)
		if err != nil {
			return nil, fmt.Errorf("pack field %s: %w", fieldPath, err)
		}
		encrypted[fieldPath] = packed
	}
	return encrypted, nil
}

// FieldDecryptor decrypts request fields with the session key.
type FieldDecryptor struct {
	sessionKey []byte
}

// NewFieldDecryptor creates a decryptor with the given session key.
func NewFieldDecryptor(sessionKey []byte) *FieldDecryptor {
	return &FieldDecryptor{sessionKey: sessionKey}
}

// DecryptFields decrypts the given fields and returns them as parsed JSON.
func (d *FieldDecryptor) DecryptFields(req *fle.DecryptRequest) (map[string]any, error) {
	aead, err := newGCMFromKey(d.sessionKey)
	if err != nil {
		return nil, err
	}

	plaintext := make(map[string]any, len(req.Fields))
	for fieldPath, value := range req.Fields {
		nonce, ciphertext, err := Unpack(value)
		if err != nil {
			return nil, fmt.Errorf("%w: field %s", fle.ErrInvalidEncryptedValue, fieldPath)
		}

		aad := BuildAAD(
			req.Method,
			req.Path,
			req.CryptoVersion,
			req.CryptoSessionID,
			req.RequestID,
			fieldPath,
			req.TenantID,
		)

		plainBytes, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return nil, fmt.Errorf("%w: authentication failed for %s", fle.ErrDecryptionFailed, fieldPath)
		}

		var parsed any
		if err := json.Unmarshal(plainBytes, &parsed); err != nil {
			return nil, fmt.Errorf("%w: plaintext for %s is not canonical json", fle.ErrDecryptionFailed, fieldPath)
		}
		plaintext[fieldPath] = parsed
	}
	return plaintext, nil
}

func newGCMFromKey(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return aead, nil
}
