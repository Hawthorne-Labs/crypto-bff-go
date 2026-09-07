// Package main is the entry point for the crypto BFF Go server.
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Hawthorne-Labs/crypto-bff-go/internal/application/usecase"
	"github.com/Hawthorne-Labs/crypto-bff-go/internal/infrastructure/config"
	"github.com/Hawthorne-Labs/crypto-bff-go/internal/infrastructure/crypto"
	"github.com/Hawthorne-Labs/crypto-bff-go/internal/interface/api"
)

func main() {
	// Load configuration
	settings, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Initialize key provider
	var keyProvider crypto.KeyProvider
	if settings.FLEPrivateKeyB64 != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(settings.FLEPrivateKeyB64)
		if err != nil {
			slog.Error("failed to decode FLE private key", slog.String("error", err.Error()))
			os.Exit(1)
		}
		privKey, err := crypto.PrivateKeyFromBytes(keyBytes)
		if err != nil {
			slog.Error("failed to parse FLE private key", slog.String("error", err.Error()))
			os.Exit(1)
		}
		keyProvider = crypto.NewStaticKeyProvider(privKey)
	} else {
		// Generate ephemeral key for development
		privKey, err := crypto.GenerateKeyPair()
		if err != nil {
			slog.Error("failed to generate key pair", slog.String("error", err.Error()))
			os.Exit(1)
		}
		keyProvider = crypto.NewStaticKeyProvider(privKey)
		slog.Warn("using ephemeral FLE key - set FLE_PRIVATE_KEY_B64 for production")
	}

	// Initialize stores
	sessionStore := crypto.NewInMemorySessionStore(settings.SessionStoreMaxEntries)
	replayProtector := crypto.NewInMemoryReplayProtector(
		time.Duration(settings.ReplayTTLSeconds)*time.Second,
		settings.ReplayMaxEntries,
	)

	// Initialize policy resolver
	policyResolver := crypto.DefaultResolver()

	// Initialize services
	handshakeService := usecase.NewHandshakeService(policyResolver, keyProvider, sessionStore)
	decryptService := usecase.NewDecryptService(policyResolver, sessionStore, replayProtector)
	encryptService := usecase.NewEncryptService(sessionStore)

	// Create router
	router := api.NewRouter(
		settings,
		handshakeService,
		decryptService,
		encryptService,
		policyResolver,
		keyProvider,
	)

	// Create HTTP server
	addr := fmt.Sprintf(":%d", settings.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	go func() {
		slog.Info("crypto-bff-go starting", slog.String("addr", addr), slog.String("service", settings.OTELServiceName))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", slog.String("error", err.Error()))
		os.Exit(1)
	}

	slog.Info("server stopped")
}
