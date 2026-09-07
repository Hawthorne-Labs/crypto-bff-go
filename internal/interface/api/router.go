// Package api provides the HTTP router and server setup.
package api

import (
	"github.com/Hawthorne-Labs/crypto-bff-go/internal/application/usecase"
	"github.com/Hawthorne-Labs/crypto-bff-go/internal/infrastructure/config"
	"github.com/Hawthorne-Labs/crypto-bff-go/internal/infrastructure/crypto"
	"github.com/Hawthorne-Labs/crypto-bff-go/internal/interface/api/handler"
	"github.com/Hawthorne-Labs/crypto-bff-go/internal/interface/api/middleware"
	"github.com/gin-gonic/gin"
)

// NewRouter creates the HTTP router with all routes configured.
func NewRouter(
	settings *config.Settings,
	handshakeService *usecase.HandshakeService,
	decryptService *usecase.DecryptService,
	encryptService *usecase.EncryptService,
	policyResolver *crypto.PolicyResolver,
	keyProvider crypto.KeyProvider,
) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	// Global middleware
	r.Use(gin.Recovery())
	r.Use(middleware.SecurityHeaders())

	// Health check
	r.GET("/health", handler.Health)

	// Crypto discovery (public)
	discoveryHandler := handler.NewDiscoveryHandler(policyResolver, keyProvider)
	r.GET("/.well-known/app-crypto", discoveryHandler.Discovery)

	// Handshake endpoints (public - no auth required)
	handshakeHandler := handler.NewHandshakeHandler(handshakeService)
	r.POST("/api/v1/crypto/handshake", handshakeHandler.Handshake)
	r.POST("/crypto/v1/sessions/:service_name", handshakeHandler.SessionHandshake)

	// Decrypt/Encrypt endpoints (require internal JWT auth)
	protected := r.Group("/")
	if settings.InternalJWTSecret != "" {
		protected.Use(middleware.InternalJWTAuth(settings.InternalJWTSecret, settings.InternalJWTAudience))
	}

	decryptHandler := handler.NewDecryptHandler(decryptService, policyResolver)
	protected.POST("/api/v1/crypto/decrypt-fields", decryptHandler.Decrypt)

	encryptHandler := handler.NewEncryptHandler(encryptService)
	protected.POST("/api/v1/crypto/encrypt-fields", encryptHandler.Encrypt)

	return r
}
