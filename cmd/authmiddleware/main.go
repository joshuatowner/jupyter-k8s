// Package main provides the entry point for the authmiddleware service that
// handles JWT-based authentication and authorization for Jupyter-k8s workspaces.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/jupyter-ai-contrib/jupyter-k8s/internal/authmiddleware"
)

func main() {
	// Initialize logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Load configuration
	cfg, err := authmiddleware.NewConfig()
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	logger.Info("Configuration loaded", 
		"jwt_validation_type", cfg.JWTValidationType,
		"kms_key_id", cfg.KMSKeyId,
		"kms_region", cfg.KMSRegion)

	// Create JWT manager using builder pattern
	builder := authmiddleware.NewJWTManagerBuilder(cfg)

	// Add KMS client if using KMS validation
	if cfg.JWTValidationType == authmiddleware.JWTValidationKMS {
		logger.Info("Initializing KMS client for JWT validation", "region", cfg.KMSRegion)
		
		awsCfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(cfg.KMSRegion))
		if err != nil {
			logger.Error("Failed to load AWS config", "error", err)
			os.Exit(1)
		}
		
		kmsClient := kms.NewFromConfig(awsCfg)
		builder = builder.WithKMSClient(kmsClient)
		logger.Info("KMS client initialized successfully")
	}

	jwtManager, err := builder.Build()
	if err != nil {
		logger.Error("Failed to create JWT manager", "error", err)
		os.Exit(1)
	}

	logger.Info("JWT manager created successfully", "type", cfg.JWTValidationType)

	// Create cookie manager
	cookieManager, err := authmiddleware.NewCookieManager(cfg)
	if err != nil {
		logger.Error("Failed to create cookie manager", "error", err)
		os.Exit(1)
	}

	// Create and start server
	server := authmiddleware.NewServer(cfg, jwtManager, cookieManager, logger)
	logger.Info("Starting authentication middleware server", "port", cfg.Port)
	
	if err := server.Start(); err != nil {
		logger.Error("Server failed", "error", err)
		os.Exit(1)
	}
}
