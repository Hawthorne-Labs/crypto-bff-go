// Package config provides application configuration.
package config

import (
	"fmt"
	"os"
	"strconv"
)

// Settings holds all application configuration.
type Settings struct {
	Port                    int
	OTELServiceName         string
	SessionStoreMaxEntries  int
	ReplayTTLSeconds        int
	ReplayMaxEntries        int
	InternalJWTSecret       string
	InternalJWTAudience     string
	FLEPrivateKeyB64        string
	CryptoSessionTokenSecret string
	CryptoTenantDigestKey   string
}

// Load reads configuration from environment variables.
func Load() (*Settings, error) {
	port := 9000
	if v := os.Getenv("PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid PORT: %w", err)
		}
		port = p
	}

	sessionMax := 100000
	if v := os.Getenv("SESSION_STORE_MAX_ENTRIES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			sessionMax = n
		}
	}

	replayTTL := 300
	if v := os.Getenv("REPLAY_TTL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			replayTTL = n
		}
	}

	replayMax := 200000
	if v := os.Getenv("REPLAY_MAX_ENTRIES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			replayMax = n
		}
	}

	return &Settings{
		Port:                    port,
		OTELServiceName:         envOrDefault("OTEL_SERVICE_NAME", "crypto-bff"),
		SessionStoreMaxEntries:  sessionMax,
		ReplayTTLSeconds:        replayTTL,
		ReplayMaxEntries:        replayMax,
		InternalJWTSecret:       os.Getenv("INTERNAL_JWT_SECRET"),
		InternalJWTAudience:     envOrDefault("INTERNAL_JWT_AUDIENCE", "crypto-bff"),
		FLEPrivateKeyB64:        os.Getenv("FLE_PRIVATE_KEY_B64"),
		CryptoSessionTokenSecret: os.Getenv("CRYPTO_SESSION_TOKEN_SECRET"),
		CryptoTenantDigestKey:   os.Getenv("CRYPTO_TENANT_DIGEST_KEY"),
	}, nil
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
