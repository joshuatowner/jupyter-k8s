package authmiddleware

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// Config additions for JWT validation type
type JWTConfig struct {
	ValidationType JWTValidationType `json:"validation_type"`

	// HMAC settings
	SigningKey string `json:"signing_key"`

	// KMS settings
	KMSKeyId  string `json:"kms_key_id"`
	KMSRegion string `json:"kms_region"`
}

// JWTManagerBuilder creates the appropriate JWT manager based on validation type
type JWTManagerBuilder struct {
	config    *Config
	kmsClient *kms.Client
}

// NewJWTManagerBuilder creates a new builder
func NewJWTManagerBuilder(config *Config) *JWTManagerBuilder {
	return &JWTManagerBuilder{
		config: config,
	}
}

// WithKMSClient sets the KMS client for KMS-based validation
func (b *JWTManagerBuilder) WithKMSClient(client *kms.Client) *JWTManagerBuilder {
	b.kmsClient = client
	return b
}

// Build creates the appropriate JWT manager implementation
func (b *JWTManagerBuilder) Build() (JWTHandler, error) {
	switch b.config.JWTValidationType {
	case JWTValidationHMAC:
		if b.config.JWTSigningKey == "" {
			return nil, fmt.Errorf("JWT signing key is required for HMAC validation")
		}
		return NewJWTManager(b.config), nil

	case JWTValidationKMS:
		if b.config.KMSKeyId == "" {
			return nil, fmt.Errorf("KMS key ID is required for KMS validation")
		}
		if b.kmsClient == nil {
			return nil, fmt.Errorf("KMS client is required for KMS validation")
		}
		return NewKMSJWTManager(b.config, b.kmsClient, b.config.KMSKeyId), nil

	default:
		return nil, fmt.Errorf("unsupported JWT validation type: %s", b.config.JWTValidationType)
	}
}
