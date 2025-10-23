package authmiddleware

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	jwt5 "github.com/golang-jwt/jwt/v5"
)

// KMSJWTManager handles JWT token creation and validation using AWS KMS envelope encryption
type KMSJWTManager struct {
	kmsClient      KMSClientInterface
	keyId          string
	issuer         string
	audience       string
	expiration     time.Duration
	refreshWindow  time.Duration
	refreshHorizon time.Duration
	keyCache       map[string][]byte // encrypted_key_hash -> plaintext_key
	cacheMutex     sync.RWMutex
}

// KMSClientInterface defines the interface we need for KMS operations
type KMSClientInterface interface {
	GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// NewKMSJWTManager creates a new KMSJWTManager
func NewKMSJWTManager(cfg *Config, kmsClient *kms.Client, keyId string) *KMSJWTManager {
	return &KMSJWTManager{
		kmsClient:      kmsClient,
		keyId:          keyId,
		issuer:         cfg.JWTIssuer,
		audience:       cfg.JWTAudience,
		expiration:     cfg.JWTExpiration,
		refreshWindow:  cfg.JWTRefreshWindow,
		refreshHorizon: cfg.JWTRefreshHorizon,
		keyCache:       make(map[string][]byte),
	}
}

// GenerateToken creates a new JWT token using KMS envelope encryption
func (m *KMSJWTManager) GenerateToken(user string, groups []string, path string, domain string, tokenType string) (string, error) {
	ctx := context.Background()
	now := time.Now().UTC()

	log.Printf("KMS: Starting token generation for user=%s, path=%s", user, path)

	// Generate data key for this token
	dataKeyInput := &kms.GenerateDataKeyInput{
		KeyId:   aws.String(m.keyId),
		KeySpec: "AES_256",
	}

	log.Printf("KMS: Calling GenerateDataKey with keyId=%s", m.keyId)
	dataKeyResult, err := m.kmsClient.GenerateDataKey(ctx, dataKeyInput)
	if err != nil {
		log.Printf("KMS: GenerateDataKey failed: %v", err)
		return "", fmt.Errorf("failed to generate data key: %w", err)
	}
	log.Printf("KMS: GenerateDataKey successful, got %d byte plaintext key and %d byte encrypted key", 
		len(dataKeyResult.Plaintext), len(dataKeyResult.CiphertextBlob))

	// Create claims
	claims := &Claims{
		RegisteredClaims: jwt5.RegisteredClaims{
			ExpiresAt: jwt5.NewNumericDate(now.Add(m.expiration)),
			IssuedAt:  jwt5.NewNumericDate(now),
			NotBefore: jwt5.NewNumericDate(now),
			Issuer:    m.issuer,
			Audience:  []string{m.audience},
			Subject:   user,
		},
		User:      user,
		Groups:    groups,
		Path:      path,
		Domain:    domain,
		TokenType: tokenType,
	}

	// TODO: Fix this weird mutation of the header - should use proper custom header struct
	// Create token with custom header containing encrypted data key
	token := jwt5.NewWithClaims(jwt5.SigningMethodHS256, claims)
	
	// Add encrypted data key to header (temporary approach)
	token.Header["edk"] = base64.URLEncoding.EncodeToString(dataKeyResult.CiphertextBlob)
	log.Printf("KMS: Added encrypted data key to JWT header (length=%d)", len(dataKeyResult.CiphertextBlob))

	// Sign with plaintext data key
	tokenString, err := token.SignedString(dataKeyResult.Plaintext)
	if err != nil {
		log.Printf("KMS: Token signing failed: %v", err)
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	// Cache the plaintext key
	keyHash := m.hashKey(dataKeyResult.CiphertextBlob)
	m.cacheMutex.Lock()
	m.keyCache[keyHash] = dataKeyResult.Plaintext
	m.cacheMutex.Unlock()
	log.Printf("KMS: Cached plaintext key with hash=%s, cache size=%d", keyHash[:8], len(m.keyCache))

	log.Printf("KMS: Token generation successful, token length=%d", len(tokenString))
	return tokenString, nil
}

// ValidateToken validates token using envelope decryption
func (m *KMSJWTManager) ValidateToken(tokenString string) (*Claims, error) {
	ctx := context.Background()
	log.Printf("KMS: Starting token validation, token length=%d", len(tokenString))

	// Parse token to extract header with encrypted data key
	token, err := jwt5.ParseWithClaims(tokenString, &Claims{}, func(token *jwt5.Token) (interface{}, error) {
		log.Printf("KMS: Parsing token, method=%v", token.Method)
		
		// Verify signing method
		if _, ok := token.Method.(*jwt5.SigningMethodHMAC); !ok {
			log.Printf("KMS: Unexpected signing method: %v", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Extract encrypted data key from header
		edkStr, ok := token.Header["edk"].(string)
		if !ok {
			log.Printf("KMS: Missing encrypted data key in header, header keys: %v", getHeaderKeys(token.Header))
			return nil, errors.New("missing encrypted data key in header")
		}
		log.Printf("KMS: Found encrypted data key in header, length=%d", len(edkStr))

		encryptedKey, err := base64.URLEncoding.DecodeString(edkStr)
		if err != nil {
			log.Printf("KMS: Failed to decode encrypted data key: %v", err)
			return nil, fmt.Errorf("invalid encrypted data key: %w", err)
		}
		log.Printf("KMS: Decoded encrypted data key, length=%d bytes", len(encryptedKey))

		// Try cache first
		keyHash := m.hashKey(encryptedKey)
		m.cacheMutex.RLock()
		plaintextKey, cached := m.keyCache[keyHash]
		m.cacheMutex.RUnlock()

		if cached {
			log.Printf("KMS: Cache hit for key hash=%s", keyHash[:8])
			return plaintextKey, nil
		}

		log.Printf("KMS: Cache miss for key hash=%s, calling KMS Decrypt", keyHash[:8])
		// Decrypt with KMS
		decryptInput := &kms.DecryptInput{
			CiphertextBlob: encryptedKey,
		}

		result, err := m.kmsClient.Decrypt(ctx, decryptInput)
		if err != nil {
			log.Printf("KMS: Decrypt failed: %v", err)
			return nil, fmt.Errorf("failed to decrypt data key: %w", err)
		}
		log.Printf("KMS: Decrypt successful, got %d byte plaintext key", len(result.Plaintext))

		// Cache the decrypted key
		m.cacheMutex.Lock()
		m.keyCache[keyHash] = result.Plaintext
		m.cacheMutex.Unlock()
		log.Printf("KMS: Cached decrypted key, cache size=%d", len(m.keyCache))

		return result.Plaintext, nil
	})

	if err != nil {
		log.Printf("KMS: Token parsing failed: %v", err)
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		log.Printf("KMS: Invalid claims type")
		return nil, ErrInvalidClaims
	}

	// Validate standard claims manually
	now := time.Now().UTC()
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(now) {
		log.Printf("KMS: Token expired at %v, current time %v", claims.ExpiresAt.Time, now)
		return nil, ErrTokenExpired
	}

	log.Printf("KMS: Token validation successful for user=%s, path=%s", claims.User, claims.Path)
	return claims, nil
}

// Helper function to get header keys for debugging
func getHeaderKeys(header map[string]interface{}) []string {
	keys := make([]string, 0, len(header))
	for k := range header {
		keys = append(keys, k)
	}
	return keys
}

// hashKey creates a hash of the encrypted key for cache indexing
func (m *KMSJWTManager) hashKey(encryptedKey []byte) string {
	hash := sha256.Sum256(encryptedKey)
	return base64.URLEncoding.EncodeToString(hash[:])
}

// RefreshToken creates a new token with the same claims but a new expiry time
func (m *KMSJWTManager) RefreshToken(claims *Claims) (string, error) {
	if claims == nil {
		return "", errors.New("claims cannot be nil")
	}

	return m.GenerateToken(claims.User, claims.Groups, claims.Path, claims.Domain, claims.TokenType)
}

// ShouldRefreshToken determines if a token should be refreshed
func (m *KMSJWTManager) ShouldRefreshToken(claims *Claims) bool {
	if claims == nil || claims.ExpiresAt == nil {
		return false
	}

	now := time.Now().UTC()
	expiryTime := claims.ExpiresAt.Time
	remainingTime := expiryTime.Sub(now)

	if remainingTime <= 0 {
		return false
	}

	if remainingTime > m.refreshWindow {
		return false
	}

	originalIssueTime := claims.IssuedAt.Time
	timeSinceOriginalIssuance := now.Sub(originalIssueTime)

	return timeSinceOriginalIssuance < m.refreshHorizon
}
