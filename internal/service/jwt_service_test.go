package service

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/guipguia/auth/internal/config"
)

func createTestJWTConfig() *config.JWTConfig {
	return &config.JWTConfig{
		Issuer:             "auth-test",
		AccessTokenSecret:  "test-access-secret-key-32-chars",
		RefreshTokenSecret: "test-refresh-secret-key-32-char",
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
	}
}

// Test: Generate and Parse Access Token
func TestJWTService_GenerateAccessToken(t *testing.T) {
	cfg := createTestJWTConfig()
	service := NewJWTService(cfg)

	userID := uuid.New()
	email := "test@example.com"
	extra := map[string]string{"role": "admin"}

	// Generate access token
	token, err := service.GenerateAccessToken(userID, email, extra)

	// Assert token generation
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Parse and validate token
	claims, err := service.ParseToken(token)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, userID.String(), claims.UserID)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, AccessToken, claims.Type)
	assert.Equal(t, "admin", claims.Extra["role"])
	assert.Equal(t, cfg.Issuer, claims.Issuer)
}

// Test: Generate and Parse Refresh Token
func TestJWTService_GenerateRefreshToken(t *testing.T) {
	cfg := createTestJWTConfig()
	service := NewJWTService(cfg)

	userID := uuid.New()
	email := "test@example.com"

	// Generate refresh token
	token, err := service.GenerateRefreshToken(userID, email)

	// Assert token generation
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Parse and validate token
	claims, err := service.ParseToken(token)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, userID.String(), claims.UserID)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, RefreshToken, claims.Type)
	assert.Equal(t, cfg.Issuer, claims.Issuer)
}

// Test: Validate Access Token with Correct Type
func TestJWTService_ValidateToken_CorrectType(t *testing.T) {
	cfg := createTestJWTConfig()
	service := NewJWTService(cfg)

	userID := uuid.New()
	email := "test@example.com"

	// Generate access token
	token, err := service.GenerateAccessToken(userID, email, nil)
	assert.NoError(t, err)

	// Validate with correct type
	claims, err := service.ValidateToken(token, AccessToken)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, AccessToken, claims.Type)
}

// Test: Validate Access Token with Wrong Type
func TestJWTService_ValidateToken_WrongType(t *testing.T) {
	cfg := createTestJWTConfig()
	service := NewJWTService(cfg)

	userID := uuid.New()
	email := "test@example.com"

	// Generate access token
	token, err := service.GenerateAccessToken(userID, email, nil)
	assert.NoError(t, err)

	// Validate with wrong type (expecting refresh)
	claims, err := service.ValidateToken(token, RefreshToken)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "invalid token type")
}

// Test: Parse Invalid Token
func TestJWTService_ParseToken_Invalid(t *testing.T) {
	cfg := createTestJWTConfig()
	service := NewJWTService(cfg)

	// Try to parse invalid token
	claims, err := service.ParseToken("invalid-token")
	assert.Error(t, err)
	assert.Nil(t, claims)
}

// Test: Parse Token with Wrong Secret
func TestJWTService_ParseToken_WrongSecret(t *testing.T) {
	cfg1 := createTestJWTConfig()
	service1 := NewJWTService(cfg1)

	userID := uuid.New()
	email := "test@example.com"

	// Generate token with first service
	token, err := service1.GenerateAccessToken(userID, email, nil)
	assert.NoError(t, err)

	// Try to parse with different secret
	cfg2 := createTestJWTConfig()
	cfg2.AccessTokenSecret = "different-secret-key-32-chars"
	service2 := NewJWTService(cfg2)

	claims, err := service2.ParseToken(token)
	assert.Error(t, err)
	assert.Nil(t, claims)
}

// Test: Token Expiration
func TestJWTService_TokenExpiration(t *testing.T) {
	cfg := createTestJWTConfig()
	cfg.AccessTokenExpiry = 1 * time.Millisecond // Very short expiry
	service := NewJWTService(cfg)

	userID := uuid.New()
	email := "test@example.com"

	// Generate token
	token, err := service.GenerateAccessToken(userID, email, nil)
	assert.NoError(t, err)

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	// Try to parse expired token
	claims, err := service.ParseToken(token)
	assert.Error(t, err)
	assert.Nil(t, claims)
}

// Test: Access and Refresh Tokens Use Different Secrets
func TestJWTService_DifferentSecrets(t *testing.T) {
	cfg := createTestJWTConfig()
	service := NewJWTService(cfg)

	userID := uuid.New()
	email := "test@example.com"

	// Generate access token
	accessToken, err := service.GenerateAccessToken(userID, email, nil)
	assert.NoError(t, err)

	// Generate refresh token
	refreshToken, err := service.GenerateRefreshToken(userID, email)
	assert.NoError(t, err)

	// Both should parse successfully
	accessClaims, err := service.ParseToken(accessToken)
	assert.NoError(t, err)
	assert.Equal(t, AccessToken, accessClaims.Type)

	refreshClaims, err := service.ParseToken(refreshToken)
	assert.NoError(t, err)
	assert.Equal(t, RefreshToken, refreshClaims.Type)
}
