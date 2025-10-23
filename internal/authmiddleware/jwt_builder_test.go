package authmiddleware

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTManagerBuilder_HMAC(t *testing.T) {
	config := &Config{
		JWTValidationType: JWTValidationHMAC,
		JWTSigningKey:     "test-signing-key",
		JWTIssuer:         "test-issuer",
		JWTAudience:       "test-audience",
	}

	builder := NewJWTManagerBuilder(config)
	jwtManager, err := builder.Build()

	require.NoError(t, err)
	assert.NotNil(t, jwtManager)
	
	// Verify it's the HMAC implementation
	_, ok := jwtManager.(*JWTManager)
	assert.True(t, ok, "Expected HMAC JWTManager implementation")
}

func TestJWTManagerBuilder_HMAC_MissingSigningKey(t *testing.T) {
	config := &Config{
		JWTValidationType: JWTValidationHMAC,
		JWTSigningKey:     "", // Missing signing key
	}

	builder := NewJWTManagerBuilder(config)
	jwtManager, err := builder.Build()

	assert.Error(t, err)
	assert.Nil(t, jwtManager)
	assert.Contains(t, err.Error(), "JWT signing key is required")
}

func TestJWTManagerBuilder_KMS(t *testing.T) {
	config := &Config{
		JWTValidationType: JWTValidationKMS,
		KMSKeyId:          "arn:aws:kms:us-west-2:123456789012:key/test-key-id",
		KMSRegion:         "us-west-2",
		JWTIssuer:         "test-issuer",
		JWTAudience:       "test-audience",
	}

	// Create a mock KMS client (in real usage, this would be a real client)
	mockKMSClient := &kms.Client{}

	builder := NewJWTManagerBuilder(config)
	jwtManager, err := builder.WithKMSClient(mockKMSClient).Build()

	require.NoError(t, err)
	assert.NotNil(t, jwtManager)
	
	// Verify it's the KMS implementation
	_, ok := jwtManager.(*KMSJWTManager)
	assert.True(t, ok, "Expected KMS JWTManager implementation")
}

func TestJWTManagerBuilder_KMS_MissingKeyId(t *testing.T) {
	config := &Config{
		JWTValidationType: JWTValidationKMS,
		KMSKeyId:          "", // Missing key ID
	}

	mockKMSClient := &kms.Client{}
	builder := NewJWTManagerBuilder(config)
	jwtManager, err := builder.WithKMSClient(mockKMSClient).Build()

	assert.Error(t, err)
	assert.Nil(t, jwtManager)
	assert.Contains(t, err.Error(), "KMS key ID is required")
}

func TestJWTManagerBuilder_KMS_MissingClient(t *testing.T) {
	config := &Config{
		JWTValidationType: JWTValidationKMS,
		KMSKeyId:          "arn:aws:kms:us-west-2:123456789012:key/test-key-id",
	}

	builder := NewJWTManagerBuilder(config)
	jwtManager, err := builder.Build() // No KMS client provided

	assert.Error(t, err)
	assert.Nil(t, jwtManager)
	assert.Contains(t, err.Error(), "KMS client is required")
}

func TestJWTManagerBuilder_UnsupportedType(t *testing.T) {
	config := &Config{
		JWTValidationType: JWTValidationType("unsupported"),
	}

	builder := NewJWTManagerBuilder(config)
	jwtManager, err := builder.Build()

	assert.Error(t, err)
	assert.Nil(t, jwtManager)
	assert.Contains(t, err.Error(), "unsupported JWT validation type")
}

func TestJWTManagerBuilder_ChainedCalls(t *testing.T) {
	config := &Config{
		JWTValidationType: JWTValidationKMS,
		KMSKeyId:          "arn:aws:kms:us-west-2:123456789012:key/test-key-id",
		KMSRegion:         "us-west-2",
		JWTIssuer:         "test-issuer",
		JWTAudience:       "test-audience",
	}

	mockKMSClient := &kms.Client{}

	// Test method chaining
	jwtManager, err := NewJWTManagerBuilder(config).
		WithKMSClient(mockKMSClient).
		Build()

	require.NoError(t, err)
	assert.NotNil(t, jwtManager)
}
