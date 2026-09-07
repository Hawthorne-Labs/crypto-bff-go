package crypto

import (
	"testing"

	"github.com/Hawthorne-Labs/crypto-bff-go/internal/domain/fle"
)

func TestPolicyResolverResolve(t *testing.T) {
	policies := fle.DefaultPolicies()
	resolver := NewPolicyResolver(policies)
	policy, err := resolver.Resolve("enc:v1")
	if err != nil {
		t.Fatalf("resolve enc:v1 failed: %v", err)
	}
	if policy.Cipher != "AES-256-GCM" {
		t.Errorf("expected AES-256-GCM, got %s", policy.Cipher)
	}
	if !policy.Enabled {
		t.Error("default policy should be enabled")
	}
}

func TestPolicyResolverUnknownVersion(t *testing.T) {
	resolver := DefaultResolver()
	_, err := resolver.Resolve("enc:v99")
	if err == nil {
		t.Fatal("expected error for unknown version")
	}
}

func TestPolicyResolverDisabledVersion(t *testing.T) {
	policies := []*fle.CryptoPolicy{
		{CryptoVersion: "enc:disabled", Enabled: false},
	}
	resolver := NewPolicyResolver(policies)
	_, err := resolver.Resolve("enc:disabled")
	if err == nil {
		t.Fatal("expected error for disabled version")
	}
}

func TestPolicyResolverAll(t *testing.T) {
	policies := fle.DefaultPolicies()
	resolver := NewPolicyResolver(policies)
	all := resolver.All()
	if len(all) != len(policies) {
		t.Errorf("expected %d policies, got %d", len(policies), len(all))
	}
}

func TestDefaultResolver(t *testing.T) {
	resolver := DefaultResolver()
	policy, err := resolver.Resolve("enc:v1")
	if err != nil {
		t.Fatalf("default resolver should resolve enc:v1: %v", err)
	}
	if policy.KeyAgreement != "X25519" {
		t.Errorf("expected X25519, got %s", policy.KeyAgreement)
	}
}
