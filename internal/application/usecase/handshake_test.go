package usecase

import (
	"testing"

	"github.com/Hawthorne-Labs/crypto-bff-go/internal/domain/fle"
	"github.com/Hawthorne-Labs/crypto-bff-go/internal/infrastructure/crypto"
)

func TestHandshakePerform(t *testing.T) {
	bffKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate bff key: %v", err)
	}

	keyProvider := crypto.NewStaticKeyProvider(bffKey)
	sessionStore := crypto.NewInMemorySessionStore(100)
	resolver := crypto.DefaultResolver()

	svc := NewHandshakeService(resolver, keyProvider, sessionStore)

	clientKey, _ := crypto.GenerateKeyPair()
	clientPubB64 := crypto.Base64URLEncode(clientKey.PublicKey().Bytes())

	result, err := svc.Perform("enc:v1", clientPubB64, "default")
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	if result.SessionID == "" {
		t.Error("expected non-empty session ID")
	}
	if result.TenantID != "default" {
		t.Errorf("expected tenant default, got %s", result.TenantID)
	}
	if result.ServerPublicKeyB64URL == "" {
		t.Error("expected non-empty server public key")
	}
	if result.SaltB64URL == "" {
		t.Error("expected non-empty salt")
	}
	if result.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if result.ExpiresAtEpoch.IsZero() {
		t.Error("expected non-zero expiry")
	}

	session, _ := sessionStore.Get("default", result.SessionID)
	if session == nil {
		t.Fatal("session should be stored after handshake")
	}
	if len(session.SessionKey) != 32 {
		t.Errorf("session key should be 32 bytes, got %d", len(session.SessionKey))
	}
}

func TestHandshakePerformDefaultTenant(t *testing.T) {
	bffKey, _ := crypto.GenerateKeyPair()
	keyProvider := crypto.NewStaticKeyProvider(bffKey)
	sessionStore := crypto.NewInMemorySessionStore(100)
	resolver := crypto.DefaultResolver()
	svc := NewHandshakeService(resolver, keyProvider, sessionStore)

	clientKey, _ := crypto.GenerateKeyPair()
	clientPubB64 := crypto.Base64URLEncode(clientKey.PublicKey().Bytes())

	result, err := svc.Perform("enc:v1", clientPubB64, "")
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if result.TenantID != "default" {
		t.Errorf("empty tenant should default to 'default', got %s", result.TenantID)
	}
}

func TestHandshakeInvalidVersion(t *testing.T) {
	bffKey, _ := crypto.GenerateKeyPair()
	keyProvider := crypto.NewStaticKeyProvider(bffKey)
	sessionStore := crypto.NewInMemorySessionStore(100)
	resolver := crypto.DefaultResolver()
	svc := NewHandshakeService(resolver, keyProvider, sessionStore)

	clientKey, _ := crypto.GenerateKeyPair()
	clientPubB64 := crypto.Base64URLEncode(clientKey.PublicKey().Bytes())

	_, err := svc.Perform("enc:v99", clientPubB64, "default")
	if err == nil {
		t.Fatal("expected error for unknown crypto version")
	}
}

func TestHandshakeInvalidClientKey(t *testing.T) {
	bffKey, _ := crypto.GenerateKeyPair()
	keyProvider := crypto.NewStaticKeyProvider(bffKey)
	sessionStore := crypto.NewInMemorySessionStore(100)
	resolver := crypto.DefaultResolver()
	svc := NewHandshakeService(resolver, keyProvider, sessionStore)

	_, err := svc.Perform("enc:v1", "not-valid-base64!!!", "default")
	if err == nil {
		t.Fatal("expected error for invalid client key")
	}
}

func TestHandshakeClientKeyWrongSize(t *testing.T) {
	bffKey, _ := crypto.GenerateKeyPair()
	keyProvider := crypto.NewStaticKeyProvider(bffKey)
	sessionStore := crypto.NewInMemorySessionStore(100)
	resolver := crypto.DefaultResolver()
	svc := NewHandshakeService(resolver, keyProvider, sessionStore)

	shortKey := crypto.Base64URLEncode(make([]byte, 16))
	_, err := svc.Perform("enc:v1", shortKey, "default")
	if err == nil {
		t.Fatal("expected error for 16-byte client key")
	}
}

func TestHandshakeToEncryptDecryptRoundTrip(t *testing.T) {
	bffKey, _ := crypto.GenerateKeyPair()
	keyProvider := crypto.NewStaticKeyProvider(bffKey)
	sessionStore := crypto.NewInMemorySessionStore(100)
	resolver := crypto.DefaultResolver()

	hsSvc := NewHandshakeService(resolver, keyProvider, sessionStore)

	clientKey, _ := crypto.GenerateKeyPair()
	clientPubB64 := crypto.Base64URLEncode(clientKey.PublicKey().Bytes())

	result, err := hsSvc.Perform("enc:v1", clientPubB64, "default")
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	session, _ := sessionStore.Get("default", result.SessionID)
	if session == nil {
		t.Fatal("session not found after handshake")
	}

	encryptor := crypto.NewFieldEncryptor(session.SessionKey)
	encFields, err := encryptor.EncryptFields(&fle.EncryptRequest{
		Method: "POST", Path: "/api/v1/test",
		Fields:        map[string]any{"name": "John"},
		CryptoVersion: "enc:v1", CryptoSessionID: result.SessionID,
		RequestID: "req-rt", TenantID: "default",
	})
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decryptor := crypto.NewFieldDecryptor(session.SessionKey)
	decrypted, err := decryptor.DecryptFields(&fle.DecryptRequest{
		Method: "POST", Path: "/api/v1/test",
		Fields:        encFields,
		CryptoVersion: "enc:v1", CryptoSessionID: result.SessionID,
		RequestID: "req-rt", TenantID: "default",
	})
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if decrypted["name"] != "John" {
		t.Errorf("expected name=John, got %v", decrypted["name"])
	}
}

func TestDecryptServiceReplayDetection(t *testing.T) {
	bffKey, _ := crypto.GenerateKeyPair()
	keyProvider := crypto.NewStaticKeyProvider(bffKey)
	sessionStore := crypto.NewInMemorySessionStore(100)
	replayProtector := crypto.NewInMemoryReplayProtector(300_000_000_000, 1000)
	resolver := crypto.DefaultResolver()

	hsSvc := NewHandshakeService(resolver, keyProvider, sessionStore)

	clientKey, _ := crypto.GenerateKeyPair()
	clientPubB64 := crypto.Base64URLEncode(clientKey.PublicKey().Bytes())

	result, _ := hsSvc.Perform("enc:v1", clientPubB64, "default")

	session, _ := sessionStore.Get("default", result.SessionID)
	if session == nil {
		t.Fatal("session not found")
	}

	encryptor := crypto.NewFieldEncryptor(session.SessionKey)
	encFields, _ := encryptor.EncryptFields(&fle.EncryptRequest{
		Method: "POST", Path: "/api/v1/test",
		Fields:        map[string]any{"secret": "value"},
		CryptoVersion: "enc:v1", CryptoSessionID: result.SessionID,
		RequestID: "req-replay", TenantID: "default",
	})

	decSvc := NewDecryptService(resolver, sessionStore, replayProtector)
	decryptReq := &fle.DecryptRequest{
		Method: "POST", Path: "/api/v1/test",
		Fields:        encFields,
		CryptoVersion: "enc:v1", CryptoSessionID: result.SessionID,
		RequestID: "req-replay", TenantID: "default",
	}

	_, err := decSvc.Decrypt(decryptReq)
	if err != nil {
		t.Fatalf("first decrypt should succeed: %v", err)
	}

	_, err = decSvc.Decrypt(decryptReq)
	if err == nil {
		t.Fatal("second decrypt with same request ID should fail (replay)")
	}
}

func TestEncryptServiceSessionNotFound(t *testing.T) {
	sessionStore := crypto.NewInMemorySessionStore(100)
	svc := NewEncryptService(sessionStore)

	req := &fle.EncryptRequest{
		Method:          "POST",
		Path:            "/api/v1/test",
		Fields:          map[string]any{"x": "y"},
		CryptoVersion:   "enc:v1",
		CryptoSessionID: "nonexistent",
		RequestID:       "req-1",
		TenantID:        "default",
	}

	_, err := svc.Encrypt(req)
	if err == nil {
		t.Fatal("expected error for missing session")
	}
}

func TestDecryptServiceSessionNotFound(t *testing.T) {
	resolver := crypto.DefaultResolver()
	sessionStore := crypto.NewInMemorySessionStore(100)
	replayProtector := crypto.NewInMemoryReplayProtector(300_000_000_000, 1000)
	svc := NewDecryptService(resolver, sessionStore, replayProtector)

	req := &fle.DecryptRequest{
		Method:          "POST",
		Path:            "/api/v1/test",
		Fields:          map[string]string{"x": "y"},
		CryptoVersion:   "enc:v1",
		CryptoSessionID: "nonexistent",
		RequestID:       "req-1",
		TenantID:        "default",
	}

	_, err := svc.Decrypt(req)
	if err == nil {
		t.Fatal("expected error for missing session")
	}
}
