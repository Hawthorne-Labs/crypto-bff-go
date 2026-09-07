// Package handler provides HTTP handlers for the crypto BFF API.
package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/Hawthorne-Labs/crypto-bff-go/internal/application/usecase"
	"github.com/Hawthorne-Labs/crypto-bff-go/internal/domain/fle"
	"github.com/Hawthorne-Labs/crypto-bff-go/internal/infrastructure/crypto"
	"github.com/gin-gonic/gin"
)

// HandshakeHandler handles FLE handshake requests.
type HandshakeHandler struct {
	handshakeService *usecase.HandshakeService
}

// NewHandshakeHandler creates a new handshake handler.
func NewHandshakeHandler(hs *usecase.HandshakeService) *HandshakeHandler {
	return &HandshakeHandler{handshakeService: hs}
}

type handshakeRequest struct {
	ClientPublicKey string `json:"clientPublicKey" binding:"required"`
}

type handshakeResponse struct {
	CryptoSessionID string `json:"cryptoSessionId"`
	ExpiresAt       string `json:"expiresAt"`
}

type sessionHandshakeResponse struct {
	ServerPublicKey   string `json:"serverPublicKey"`
	Salt              string `json:"salt"`
	CryptoSessionID   string `json:"cryptoSessionId"`
	CryptoAccessToken string `json:"cryptoAccessToken"`
	ExpiresIn         int    `json:"expiresIn"`
}

// Handshake handles POST /api/v1/crypto/handshake
func (h *HandshakeHandler) Handshake(c *gin.Context) {
	cryptoVersion := c.GetHeader("Crypto-Version")
	if cryptoVersion == "" {
		c.JSON(http.StatusBadRequest, errorResponse("Crypto-Version header required"))
		return
	}
	tenantID := c.GetHeader("Crypto-Tenant-Id")
	if tenantID == "" {
		tenantID = "default"
	}

	var req handshakeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse("clientPublicKey missing"))
		return
	}

	result, err := h.handshakeService.Perform(cryptoVersion, req.ClientPublicKey, tenantID)
	if err != nil {
		handleHandshakeError(c, err)
		return
	}

	c.JSON(http.StatusCreated, handshakeResponse{
		CryptoSessionID: result.SessionID,
		ExpiresAt:       result.ExpiresAtEpoch.UTC().Format(time.RFC3339),
	})
}

// SessionHandshake handles POST /crypto/v1/sessions/:service_name
func (h *HandshakeHandler) SessionHandshake(c *gin.Context) {
	cryptoVersion := c.GetHeader("Crypto-Version")
	if cryptoVersion == "" {
		cryptoVersion = "enc:v1"
	}
	tenantID := c.GetHeader("Crypto-Tenant-Id")
	if tenantID == "" {
		tenantID = "default"
	}

	var req handshakeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse("clientPublicKey missing"))
		return
	}

	result, err := h.handshakeService.Perform(cryptoVersion, req.ClientPublicKey, tenantID)
	if err != nil {
		handleHandshakeError(c, err)
		return
	}

	expiresIn := int(time.Until(result.ExpiresAtEpoch).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}

	c.JSON(http.StatusCreated, sessionHandshakeResponse{
		ServerPublicKey:   result.ServerPublicKeyB64URL,
		Salt:              result.SaltB64URL,
		CryptoSessionID:   result.SessionID,
		CryptoAccessToken: result.AccessToken,
		ExpiresIn:         expiresIn,
	})
}

func handleHandshakeError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, fle.ErrUnknownCryptoVersion):
		c.JSON(http.StatusBadRequest, errorResponse("unknown crypto version"))
	case errors.Is(err, fle.ErrHandshakePayloadInvalid):
		c.JSON(http.StatusBadRequest, errorResponse("invalid handshake payload"))
	default:
		c.JSON(http.StatusInternalServerError, errorResponse("handshake failed"))
	}
}

// DecryptHandler handles field decryption requests.
type DecryptHandler struct {
	decryptService *usecase.DecryptService
	policyResolver *crypto.PolicyResolver
}

// NewDecryptHandler creates a new decrypt handler.
func NewDecryptHandler(ds *usecase.DecryptService, pr *crypto.PolicyResolver) *DecryptHandler {
	return &DecryptHandler{decryptService: ds, policyResolver: pr}
}

type decryptRequest struct {
	Method string            `json:"method" binding:"required,min=1,max=16"`
	Path   string            `json:"path" binding:"required,min=1,max=256"`
	Fields map[string]string `json:"fields" binding:"required,max=64"`
}

type decryptResponse struct {
	Plaintext map[string]any `json:"plaintext"`
}

// Decrypt handles POST /api/v1/crypto/decrypt-fields
func (h *DecryptHandler) Decrypt(c *gin.Context) {
	cryptoVersion := c.GetHeader("Crypto-Version")
	cryptoSessionID := c.GetHeader("Crypto-Session-Id")
	requestID := c.GetHeader("Crypto-Request-Id")
	timestamp := c.GetHeader("Crypto-Timestamp")
	tenantID := c.GetHeader("Crypto-Tenant-Id")
	if tenantID == "" {
		tenantID = "default"
	}

	// Validate required headers
	if cryptoVersion == "" || cryptoSessionID == "" || requestID == "" || timestamp == "" {
		c.JSON(http.StatusBadRequest, errorResponse("missing required crypto headers"))
		return
	}

	// Validate timestamp
	policy, err := h.policyResolver.Resolve(cryptoVersion)
	if err != nil {
		c.JSON(http.StatusBadRequest, errorResponse("unknown crypto version"))
		return
	}
	if err := crypto.ValidateTimestamp(timestamp, policy.TimestampSkewSeconds, time.Now()); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse("timestamp out of window"))
		return
	}

	var req decryptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse("invalid request body"))
		return
	}

	result, err := h.decryptService.Decrypt(&fle.DecryptRequest{
		Method:          req.Method,
		Path:            req.Path,
		Fields:          req.Fields,
		CryptoVersion:   cryptoVersion,
		CryptoSessionID: cryptoSessionID,
		RequestID:       requestID,
		TenantID:        tenantID,
	})
	if err != nil {
		handleDecryptError(c, err)
		return
	}

	c.JSON(http.StatusOK, decryptResponse{Plaintext: result})
}

func handleDecryptError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, fle.ErrSessionNotFound):
		c.JSON(http.StatusNotFound, errorResponse("session not found"))
	case errors.Is(err, fle.ErrReplayDetected):
		c.JSON(http.StatusBadRequest, errorResponse("replay detected"))
	case errors.Is(err, fle.ErrDecryptionFailed):
		c.JSON(http.StatusBadRequest, errorResponse("decryption failed"))
	case errors.Is(err, fle.ErrInvalidEncryptedValue):
		c.JSON(http.StatusBadRequest, errorResponse("invalid encrypted value"))
	case errors.Is(err, fle.ErrUnknownCryptoVersion):
		c.JSON(http.StatusBadRequest, errorResponse("unknown crypto version"))
	default:
		c.JSON(http.StatusInternalServerError, errorResponse("decryption failed"))
	}
}

// EncryptHandler handles field encryption requests.
type EncryptHandler struct {
	encryptService *usecase.EncryptService
}

// NewEncryptHandler creates a new encrypt handler.
func NewEncryptHandler(es *usecase.EncryptService) *EncryptHandler {
	return &EncryptHandler{encryptService: es}
}

type encryptRequest struct {
	Method string         `json:"method" binding:"required,min=1,max=16"`
	Path   string         `json:"path" binding:"required,min=1,max=256"`
	Fields map[string]any `json:"fields" binding:"required,max=64"`
}

type encryptResponse struct {
	Encrypted map[string]string `json:"encrypted"`
}

// Encrypt handles POST /api/v1/crypto/encrypt-fields
func (h *EncryptHandler) Encrypt(c *gin.Context) {
	cryptoVersion := c.GetHeader("Crypto-Version")
	cryptoSessionID := c.GetHeader("Crypto-Session-Id")
	requestID := c.GetHeader("Crypto-Request-Id")
	tenantID := c.GetHeader("Crypto-Tenant-Id")
	if tenantID == "" {
		tenantID = "default"
	}

	if cryptoVersion == "" || cryptoSessionID == "" || requestID == "" {
		c.JSON(http.StatusBadRequest, errorResponse("missing required crypto headers"))
		return
	}

	var req encryptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse("invalid request body"))
		return
	}

	result, err := h.encryptService.Encrypt(&fle.EncryptRequest{
		Method:          req.Method,
		Path:            req.Path,
		Fields:          req.Fields,
		CryptoVersion:   cryptoVersion,
		CryptoSessionID: cryptoSessionID,
		RequestID:       requestID,
		TenantID:        tenantID,
	})
	if err != nil {
		if errors.Is(err, fle.ErrSessionNotFound) {
			c.JSON(http.StatusNotFound, errorResponse("session not found"))
			return
		}
		c.JSON(http.StatusInternalServerError, errorResponse("encryption failed"))
		return
	}

	c.JSON(http.StatusOK, encryptResponse{Encrypted: result})
}

// DiscoveryHandler handles crypto discovery requests.
type DiscoveryHandler struct {
	policyResolver *crypto.PolicyResolver
	keyProvider    crypto.KeyProvider
}

// NewDiscoveryHandler creates a new discovery handler.
func NewDiscoveryHandler(pr *crypto.PolicyResolver, kp crypto.KeyProvider) *DiscoveryHandler {
	return &DiscoveryHandler{policyResolver: pr, keyProvider: kp}
}

type discoveryVersionEntry struct {
	CryptoVersion string  `json:"cryptoVersion"`
	PublicKey     string  `json:"publicKey"`
	Status        string  `json:"status"`
	ExpiresAt     *string `json:"expiresAt,omitempty"`
}

type discoveryResponse struct {
	Versions []discoveryVersionEntry `json:"versions"`
}

// Discovery handles GET /.well-known/app-crypto
func (h *DiscoveryHandler) Discovery(c *gin.Context) {
	policies := h.policyResolver.All()
	entries := make([]discoveryVersionEntry, 0, len(policies))

	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		pubKey, err := h.keyProvider.PublicKeyB64URL(policy.KeyID)
		if err != nil {
			continue
		}
		entry := discoveryVersionEntry{
			CryptoVersion: policy.CryptoVersion,
			PublicKey:     pubKey,
			Status:        "active",
		}
		if policy.ExpiresAt != nil {
			expires := policy.ExpiresAt.UTC().Format(time.RFC3339)
			entry.ExpiresAt = &expires
		}
		entries = append(entries, entry)
	}

	c.JSON(http.StatusOK, discoveryResponse{Versions: entries})
}

// Health handles GET /health
func Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func errorResponse(message string) gin.H {
	return gin.H{"error": gin.H{"message": message}}
}
