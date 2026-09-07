// Package fle defines the domain types for Field-Level Encryption.
package fle

import "errors"

// Sentinel errors for FLE operations.
var (
	ErrUnknownCryptoVersion    = errors.New("unknown crypto version")
	ErrCryptoVersionDisabled   = errors.New("crypto version disabled")
	ErrHandshakePayloadInvalid = errors.New("handshake payload invalid")
	ErrSessionNotFound         = errors.New("session not found")
	ErrSessionExpired          = errors.New("session expired")
	ErrTimestampOutOfWindow    = errors.New("timestamp out of window")
	ErrReplayDetected          = errors.New("replay detected")
	ErrInvalidEncryptedValue   = errors.New("invalid encrypted value")
	ErrDecryptionFailed        = errors.New("decryption failed")
)
