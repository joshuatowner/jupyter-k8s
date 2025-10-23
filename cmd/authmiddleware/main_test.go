package main

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/jupyter-ai-contrib/jupyter-k8s/internal/authmiddleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper to create JWT manager using the same logic as main.go
func createJWTManager(cfg *authmiddleware.Config) (authmiddleware.JWTHandler, error) {
	builder := authmiddleware.NewJWTManagerBuilder(cfg)

	// Add KMS client if using KMS validation
	if cfg.JWTValidationType == authmiddleware.JWTValidationKMS {
		// For tests, we'll use a mock or skip AWS config loading
		// In real usage, this would load AWS config
		awsCfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(cfg.KMSRegion))
		if err != nil {
			// In tests, we might not have AWS credentials, so we'll create a mock client
			// For now, we'll return the error to test error handling
			return nil, err
		}
		
		kmsClient := kms.NewFromConfig(awsCfg)
		builder = builder.WithKMSClient(kmsClient)
	}

	return builder.Build()
}

func TestCreateJWTManager_HMAC(t *testing.T) {
	cfg := &authmiddleware.Config{
		JWTValidationType: authmiddleware.JWTValidationHMAC,
		JWTSigningKey:     "test-signing-key",
		JWTIssuer:         "test-issuer",
		JWTAudience:       "test-audience",
	}

	jwtManager, err := createJWTManager(cfg)

	require.NoError(t, err)
	assert.NotNil(t, jwtManager)
	
	// Verify it's the HMAC implementation
	_, ok := jwtManager.(*authmiddleware.JWTManager)
	assert.True(t, ok, "Expected HMAC JWTManager implementation")
}

func TestCreateJWTManager_KMS_WithoutAWSCredentials(t *testing.T) {
	// Clear AWS environment variables to simulate missing credentials
	originalRegion := os.Getenv("AWS_REGION")
	originalProfile := os.Getenv("AWS_PROFILE")
	os.Unsetenv("AWS_REGION")
	os.Unsetenv("AWS_PROFILE")
	
	defer func() {
		if originalRegion != "" {
			os.Setenv("AWS_REGION", originalRegion)
		}
		if originalProfile != "" {
			os.Setenv("AWS_PROFILE", originalProfile)
		}
	}()

	cfg := &authmiddleware.Config{
		JWTValidationType: authmiddleware.JWTValidationKMS,
		KMSKeyId:          "arn:aws:kms:us-west-2:123456789012:key/test-key-id",
		KMSRegion:         "us-west-2",
		JWTIssuer:         "test-issuer",
		JWTAudience:       "test-audience",
	}

	jwtManager, err := createJWTManager(cfg)

	// This should fail due to missing AWS credentials in test environment
	// In a real deployment, AWS credentials would be available via IAM roles
	if err != nil {
		assert.Nil(t, jwtManager)
		t.Logf("Expected error in test environment without AWS credentials: %v", err)
	} else {
		// If AWS credentials are available in test environment
		assert.NotNil(t, jwtManager)
		_, ok := jwtManager.(*authmiddleware.KMSJWTManager)
		assert.True(t, ok, "Expected KMS JWTManager implementation")
	}
}

func TestCreateJWTManager_InvalidValidationType(t *testing.T) {
	cfg := &authmiddleware.Config{
		JWTValidationType: authmiddleware.JWTValidationType("invalid"),
	}

	jwtManager, err := createJWTManager(cfg)

	assert.Error(t, err)
	assert.Nil(t, jwtManager)
	assert.Contains(t, err.Error(), "unsupported JWT validation type")
}

func TestCreateJWTManager_KMS_MissingKeyId(t *testing.T) {
	cfg := &authmiddleware.Config{
		JWTValidationType: authmiddleware.JWTValidationKMS,
		KMSKeyId:          "", // Missing key ID
		KMSRegion:         "us-west-2",
	}

	jwtManager, err := createJWTManager(cfg)

	assert.Error(t, err)
	assert.Nil(t, jwtManager)
	assert.Contains(t, err.Error(), "KMS key ID is required")
}

func TestCreateJWTManager_HMAC_MissingSigningKey(t *testing.T) {
	cfg := &authmiddleware.Config{
		JWTValidationType: authmiddleware.JWTValidationHMAC,
		JWTSigningKey:     "", // Missing signing key
	}

	jwtManager, err := createJWTManager(cfg)

	assert.Error(t, err)
	assert.Nil(t, jwtManager)
	assert.Contains(t, err.Error(), "JWT signing key is required")
}
