package service

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/guipguia/auth/internal/config"
)

// TokenType represents the type of JWT token
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

// Claims represents JWT claims
type Claims struct {
	UserID string            `json:"user_id"`
	Email  string            `json:"email"`
	Type   TokenType         `json:"type"`
	Extra  map[string]string `json:"extra,omitempty"`
	jwt.RegisteredClaims
}

// JWTService handles JWT token operations
type JWTService interface {
	GenerateAccessToken(userID uuid.UUID, email string, extra map[string]string) (string, error)
	GenerateRefreshToken(userID uuid.UUID, email string) (string, error)
	ValidateToken(token string, tokenType TokenType) (*Claims, error)
	ParseToken(token string) (*Claims, error)
}

type jwtService struct {
	cfg *config.JWTConfig
}

// NewJWTService creates a new JWT service
func NewJWTService(cfg *config.JWTConfig) JWTService {
	return &jwtService{cfg: cfg}
}

// GenerateAccessToken generates an access token
func (s *jwtService) GenerateAccessToken(userID uuid.UUID, email string, extra map[string]string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID.String(),
		Email:  email,
		Type:   AccessToken,
		Extra:  extra,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.AccessTokenExpiry)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.AccessTokenSecret))
}

// GenerateRefreshToken generates a refresh token
func (s *jwtService) GenerateRefreshToken(userID uuid.UUID, email string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID.String(),
		Email:  email,
		Type:   RefreshToken,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.RefreshTokenExpiry)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.RefreshTokenSecret))
}

// ValidateToken validates a token and checks its type
func (s *jwtService) ValidateToken(tokenString string, tokenType TokenType) (*Claims, error) {
	claims, err := s.ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.Type != tokenType {
		return nil, fmt.Errorf("invalid token type: expected %s, got %s", tokenType, claims.Type)
	}

	return claims, nil
}

// ParseToken parses and validates a token
func (s *jwtService) ParseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get claims to determine token type
		claims, ok := token.Claims.(*Claims)
		if !ok {
			return nil, fmt.Errorf("invalid claims type")
		}

		// Return appropriate secret based on token type
		switch claims.Type {
		case AccessToken:
			return []byte(s.cfg.AccessTokenSecret), nil
		case RefreshToken:
			return []byte(s.cfg.RefreshTokenSecret), nil
		default:
			return nil, fmt.Errorf("unknown token type")
		}
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	return claims, nil
}
