// Package secrets loads runtime secrets from AWS Secrets Manager.
package secrets

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// fleKeysSecret is the JSON shape stored in Secrets Manager under
// hawthorne-prod/application/crypto-fle-keys.
type fleKeysSecret struct {
	ActivePrivateKey string `json:"active_private_key"`
	ActivePublicKey  string `json:"active_public_key"`
	ActiveKID        string `json:"active_kid"`
	Alg              string `json:"alg"`
	Status           string `json:"status"`
}

// LoadFLEPrivateKeyFromSecretsManager reads the active FLE private key from
// the Secrets Manager secret identified by secretARN. The secret is expected
// to be a JSON object with an "active_private_key" field containing the
// base64-encoded X25519 private key.
func LoadFLEPrivateKeyFromSecretsManager(ctx context.Context, secretARN string) (string, error) {
	if secretARN == "" {
		return "", fmt.Errorf("empty secret ARN")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("load AWS config: %w", err)
	}
	client := secretsmanager.NewFromConfig(cfg)
	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: &secretARN})
	if err != nil {
		return "", fmt.Errorf("get secret %s: %w", secretARN, err)
	}
	if out.SecretString == nil {
		return "", fmt.Errorf("secret %s has no string value", secretARN)
	}
	var keys fleKeysSecret
	if err := json.Unmarshal([]byte(*out.SecretString), &keys); err != nil {
		return "", fmt.Errorf("parse secret JSON: %w", err)
	}
	if keys.ActivePrivateKey == "" {
		return "", fmt.Errorf("secret %s has empty active_private_key", secretARN)
	}
	return keys.ActivePrivateKey, nil
}
