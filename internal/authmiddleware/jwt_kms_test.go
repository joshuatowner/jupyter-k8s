package authmiddleware

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// MockKMSClient implements a mock KMS client for testing
type MockKMSClient struct {
	dataKey       []byte
	encryptedKey  []byte
	decryptCalled bool
}

func (m *MockKMSClient) GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	return &kms.GenerateDataKeyOutput{
		Plaintext:      m.dataKey,
		CiphertextBlob: m.encryptedKey,
		KeyId:          params.KeyId,
	}, nil
}

func (m *MockKMSClient) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	m.decryptCalled = true
	return &kms.DecryptOutput{
		Plaintext: m.dataKey,
		KeyId:     aws.String("test-key-id"),
	}, nil
}

func TestKMSJWTManager_EnvelopeEncryption(t *testing.T) {
	// Create test config
	cfg := &Config{
		JWTIssuer:         "test-issuer",
		JWTAudience:       "test-audience",
		JWTExpiration:     30 * time.Minute,
		JWTRefreshWindow:  5 * time.Minute,
		JWTRefreshHorizon: 2 * time.Hour,
	}

	// Create mock KMS client
	mockKMS := &MockKMSClient{
		dataKey:      []byte("test-data-key-32-bytes-long-key"),
		encryptedKey: []byte("encrypted-data-key-blob"),
	}

	// Create KMS JWT manager
	manager := &KMSJWTManager{
		kmsClient:      mockKMS,
		keyId:          "test-key-id",
		issuer:         cfg.JWTIssuer,
		audience:       cfg.JWTAudience,
		expiration:     cfg.JWTExpiration,
		refreshWindow:  cfg.JWTRefreshWindow,
		refreshHorizon: cfg.JWTRefreshHorizon,
		keyCache:       make(map[string][]byte),
	}

	// Test data
	user := "test-user"
	groups := []string{"users", "admins"}
	path := "/workspaces/test-ns/test-workspace"
	domain := "example.com"
	tokenType := "access"

	// Generate token
	token, err := manager.GenerateToken(user, groups, path, domain, tokenType)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token == "" {
		t.Fatal("Generated token is empty")
	}

	// Validate token (should use cache, not call KMS decrypt)
	mockKMS.decryptCalled = false
	claims, err := manager.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	// Verify KMS decrypt was not called (cache hit)
	if mockKMS.decryptCalled {
		t.Error("Expected cache hit, but KMS decrypt was called")
	}

	// Verify claims
	if claims.User != user {
		t.Errorf("Expected user %q, got %q", user, claims.User)
	}

	if len(claims.Groups) != len(groups) {
		t.Errorf("Expected %d groups, got %d", len(groups), len(claims.Groups))
	}

	if claims.Path != path {
		t.Errorf("Expected path %q, got %q", path, claims.Path)
	}

	if claims.Domain != domain {
		t.Errorf("Expected domain %q, got %q", domain, claims.Domain)
	}

	if claims.TokenType != tokenType {
		t.Errorf("Expected token type %q, got %q", tokenType, claims.TokenType)
	}

	if claims.Issuer != cfg.JWTIssuer {
		t.Errorf("Expected issuer %q, got %q", cfg.JWTIssuer, claims.Issuer)
	}

	if len(claims.Audience) != 1 || claims.Audience[0] != cfg.JWTAudience {
		t.Errorf("Expected audience [%q], got %v", cfg.JWTAudience, claims.Audience)
	}
}

func TestKMSJWTManager_CacheMiss(t *testing.T) {
	// Create test config
	cfg := &Config{
		JWTIssuer:   "test-issuer",
		JWTAudience: "test-audience",
		JWTExpiration: 30 * time.Minute,
	}

	// Create mock KMS client
	mockKMS := &MockKMSClient{
		dataKey:      []byte("test-data-key-32-bytes-long-key"),
		encryptedKey: []byte("encrypted-data-key-blob"),
	}

	// Create KMS JWT manager
	manager := &KMSJWTManager{
		kmsClient: mockKMS,
		keyId:     "test-key-id",
		issuer:    cfg.JWTIssuer,
		audience:  cfg.JWTAudience,
		expiration: cfg.JWTExpiration,
		keyCache:  make(map[string][]byte),
	}

	// Generate token
	token, err := manager.GenerateToken("user", []string{"group"}, "/path", "domain", "type")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Clear cache to force KMS decrypt call
	manager.keyCache = make(map[string][]byte)
	mockKMS.decryptCalled = false

	// Validate token (should call KMS decrypt due to cache miss)
	_, err = manager.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	// Verify KMS decrypt was called (cache miss)
	if !mockKMS.decryptCalled {
		t.Error("Expected KMS decrypt to be called on cache miss")
	}
}

func TestKMSJWTManager_RefreshToken(t *testing.T) {
	// Create test config
	cfg := &Config{
		JWTIssuer:   "test-issuer",
		JWTAudience: "test-audience",
		JWTExpiration: 30 * time.Minute,
	}

	// Create mock KMS client
	mockKMS := &MockKMSClient{
		dataKey:      []byte("test-data-key-32-bytes-long-key"),
		encryptedKey: []byte("encrypted-data-key-blob"),
	}

	// Create KMS JWT manager
	manager := &KMSJWTManager{
		kmsClient: mockKMS,
		keyId:     "test-key-id",
		issuer:    cfg.JWTIssuer,
		audience:  cfg.JWTAudience,
		expiration: cfg.JWTExpiration,
		keyCache:  make(map[string][]byte),
	}

	// Create test claims
	claims := &Claims{
		User:      "test-user",
		Groups:    []string{"users"},
		Path:      "/workspaces/test/app",
		Domain:    "example.com",
		TokenType: "access",
	}

	// Refresh token
	newToken, err := manager.RefreshToken(claims)
	if err != nil {
		t.Fatalf("Failed to refresh token: %v", err)
	}

	if newToken == "" {
		t.Fatal("Refreshed token is empty")
	}

	// Validate refreshed token
	newClaims, err := manager.ValidateToken(newToken)
	if err != nil {
		t.Fatalf("Failed to validate refreshed token: %v", err)
	}

	// Verify claims are preserved
	if newClaims.User != claims.User {
		t.Errorf("Expected user %q, got %q", claims.User, newClaims.User)
	}
}
