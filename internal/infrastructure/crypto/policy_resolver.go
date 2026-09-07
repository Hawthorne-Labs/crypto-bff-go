package crypto

import (
	"fmt"

	"github.com/Hawthorne-Labs/crypto-bff-go/internal/domain/fle"
)

// PolicyResolver resolves crypto policies by version.
type PolicyResolver struct {
	policies map[string]*fle.CryptoPolicy
	ordered  []*fle.CryptoPolicy
}

// NewPolicyResolver creates a resolver from a list of policies.
func NewPolicyResolver(policies []*fle.CryptoPolicy) *PolicyResolver {
	m := make(map[string]*fle.CryptoPolicy, len(policies))
	for _, p := range policies {
		m[p.CryptoVersion] = p
	}
	return &PolicyResolver{policies: m, ordered: policies}
}

// Resolve returns the policy for the given version.
func (r *PolicyResolver) Resolve(cryptoVersion string) (*fle.CryptoPolicy, error) {
	policy, exists := r.policies[cryptoVersion]
	if !exists {
		return nil, fmt.Errorf("%w: %s", fle.ErrUnknownCryptoVersion, cryptoVersion)
	}
	if !policy.Enabled {
		return nil, fmt.Errorf("%w: %s", fle.ErrCryptoVersionDisabled, cryptoVersion)
	}
	return policy, nil
}

// All returns all policies.
func (r *PolicyResolver) All() []*fle.CryptoPolicy {
	return r.ordered
}

// DefaultResolver returns a resolver with default policies.
func DefaultResolver() *PolicyResolver {
	return NewPolicyResolver(fle.DefaultPolicies())
}
