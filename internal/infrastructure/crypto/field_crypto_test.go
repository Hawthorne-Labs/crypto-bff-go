package crypto

import (
	"encoding/json"
	"testing"

	"github.com/Hawthorne-Labs/crypto-bff-go/internal/domain/fle"
)

func TestFieldEncryptDecryptRoundTrip(t *testing.T) {
	// Generate a 32-byte session key
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i)
	}

	encryptor := NewFieldEncryptor(sessionKey)
	decryptor := NewFieldDecryptor(sessionKey)

	// Test data
	original := map[string]any{
		"name":    "John Doe",
		"phone":   "+1234567890",
		"balance": 1500.50,
	}

	req := &fle.EncryptRequest{
		Method:          "POST",
		Path:            "/api/v1/test",
		Fields:          original,
		CryptoVersion:   "enc:v1",
		CryptoSessionID: "test-session-123",
		RequestID:       "req-456",
		TenantID:        "default",
	}

	// Encrypt
	encrypted, err := encryptor.EncryptFields(req)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	if len(encrypted) != len(original) {
		t.Fatalf("expected %d encrypted fields, got %d", len(original), len(encrypted))
	}

	// Verify encrypted values are different from original
	for key, val := range encrypted {
		origJSON, _ := json.Marshal(original[key])
		if val == string(origJSON) {
			t.Errorf("field %s was not encrypted", key)
		}
	}

	// Decrypt
	decryptReq := &fle.DecryptRequest{
		Method:          req.Method,
		Path:            req.Path,
		Fields:          encrypted,
		CryptoVersion:   req.CryptoVersion,
		CryptoSessionID: req.CryptoSessionID,
		RequestID:       req.RequestID,
		TenantID:        req.TenantID,
	}

	decrypted, err := decryptor.DecryptFields(decryptReq)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	// Verify round-trip
	for key, expected := range original {
		actual, ok := decrypted[key]
		if !ok {
			t.Errorf("missing decrypted field: %s", key)
			continue
		}
		// JSON numbers are float64
		expectedJSON, _ := json.Marshal(expected)
		actualJSON, _ := json.Marshal(actual)
		if string(expectedJSON) != string(actualJSON) {
			t.Errorf("field %s: expected %s, got %s", key, expectedJSON, actualJSON)
		}
	}
}

func TestFieldDecryptTampered(t *testing.T) {
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i)
	}

	encryptor := NewFieldEncryptor(sessionKey)
	decryptor := NewFieldDecryptor(sessionKey)

	req := &fle.EncryptRequest{
		Method:          "POST",
		Path:            "/api/v1/test",
		Fields:          map[string]any{"secret": "password123"},
		CryptoVersion:   "enc:v1",
		CryptoSessionID: "test-session",
		RequestID:       "req-1",
		TenantID:        "default",
	}

	encrypted, err := encryptor.EncryptFields(req)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Tamper with the encrypted value
	tampered := make(map[string]string)
	for k, v := range encrypted {
		// Flip a character
		if len(v) > 5 {
			tampered[k] = v[:5] + "X" + v[6:]
		} else {
			tampered[k] = "XXXXX"
		}
	}

	decryptReq := &fle.DecryptRequest{
		Method:          req.Method,
		Path:            req.Path,
		Fields:          tampered,
		CryptoVersion:   req.CryptoVersion,
		CryptoSessionID: req.CryptoSessionID,
		RequestID:       req.RequestID,
		TenantID:        req.TenantID,
	}

	_, err = decryptor.DecryptFields(decryptReq)
	if err == nil {
		t.Fatal("expected decryption to fail with tampered data")
	}
}

func TestBase64URLRoundTrip(t *testing.T) {
	tests := [][]byte{
		{0},
		{0, 1, 2, 3},
		make([]byte, 32),
		[]byte("hello world"),
	}

	for i, data := range tests {
		encoded := Base64URLEncode(data)
		decoded, err := Base64URLDecode(encoded)
		if err != nil {
			t.Errorf("test %d: decode failed: %v", i, err)
			continue
		}
		if len(data) == 0 && len(decoded) == 0 {
			continue
		}
		if string(decoded) != string(data) {
			t.Errorf("test %d: round-trip failed", i)
		}
	}
}

func TestPackUnpack(t *testing.T) {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	ciphertext := []byte("encrypted data with tag padding")

	packed, err := Pack(nonce, ciphertext)
	if err != nil {
		t.Fatalf("pack failed: %v", err)
	}

	unpackedNonce, unpackedCiphertext, err := Unpack(packed)
	if err != nil {
		t.Fatalf("unpack failed: %v", err)
	}

	if string(unpackedNonce) != string(nonce) {
		t.Error("nonce mismatch")
	}
	if string(unpackedCiphertext) != string(ciphertext) {
		t.Error("ciphertext mismatch")
	}
}
