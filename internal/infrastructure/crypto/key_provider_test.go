package crypto

import (
	"encoding/base64"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	key, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair failed: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	pub := key.PublicKey()
	if len(pub.Bytes()) != 32 {
		t.Errorf("X25519 public key should be 32 bytes, got %d", len(pub.Bytes()))
	}
}

func TestStaticKeyProvider(t *testing.T) {
	key, _ := GenerateKeyPair()
	provider := NewStaticKeyProvider(key)
	priv, err := provider.PrivateKey("any-id")
	if err != nil {
		t.Fatalf("private key failed: %v", err)
	}
	if priv == nil {
		t.Fatal("expected non-nil private key")
	}
	pubB64, err := provider.PublicKeyB64URL("any-id")
	if err != nil {
		t.Fatalf("public key b64 failed: %v", err)
	}
	pubRaw, err := base64.RawURLEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatalf("decode public key b64 failed: %v", err)
	}
	if len(pubRaw) != 32 {
		t.Errorf("decoded public key should be 32 bytes, got %d", len(pubRaw))
	}
}

func TestPrivateKeyFromBytesValid(t *testing.T) {
	key, _ := GenerateKeyPair()
	raw := key.Bytes()
	parsed, err := PrivateKeyFromBytes(raw)
	if err != nil {
		t.Fatalf("parse private key failed: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil parsed key")
	}
}

func TestPrivateKeyFromBytesInvalidLength(t *testing.T) {
	_, err := PrivateKeyFromBytes(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestGenerateKeyPairUniqueness(t *testing.T) {
	k1, _ := GenerateKeyPair()
	k2, _ := GenerateKeyPair()
	if string(k1.Bytes()) == string(k2.Bytes()) {
		t.Error("two generated keys should be different")
	}
}
