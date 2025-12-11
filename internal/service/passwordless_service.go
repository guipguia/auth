package service

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/guipguia/auth/internal/domain"
	"github.com/guipguia/auth/internal/repository"
)

// PasswordlessService handles passwordless authentication operations
type PasswordlessService interface {
	GenerateToken(tenantID uuid.UUID, email string) (*domain.OTP, error)
	VerifyToken(tenantID uuid.UUID, token string) (*domain.OTP, error)
}

type passwordlessService struct {
	otpRepo     repository.OTPRepository
	tokenExpiry time.Duration
	tokenLength int
}

// NewPasswordlessService creates a new passwordless service
func NewPasswordlessService(otpRepo repository.OTPRepository) PasswordlessService {
	return &passwordlessService{
		otpRepo:     otpRepo,
		tokenExpiry: 15 * time.Minute, // Token expires in 15 minutes
		tokenLength: 32,
	}
}

// GenerateToken generates a passwordless login token
func (s *passwordlessService) GenerateToken(tenantID uuid.UUID, email string) (*domain.OTP, error) {
	// Generate secure random token
	token, err := s.generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Create OTP record with tenant ID
	otp := &domain.OTP{
		TenantID:  tenantID,
		Email:     email,
		Token:     token,
		Type:      domain.OTPTypePasswordless,
		ExpiresAt: time.Now().Add(s.tokenExpiry),
	}

	if err := s.otpRepo.Create(otp); err != nil {
		return nil, fmt.Errorf("failed to create passwordless token: %w", err)
	}

	return otp, nil
}

// VerifyToken verifies a passwordless login token
func (s *passwordlessService) VerifyToken(tenantID uuid.UUID, token string) (*domain.OTP, error) {
	otp, err := s.otpRepo.GetByToken(tenantID, token)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token: %w", err)
	}

	if otp.Type != domain.OTPTypePasswordless {
		return nil, fmt.Errorf("invalid token type")
	}

	if !otp.IsValid() {
		return nil, fmt.Errorf("token is invalid or expired")
	}

	// Mark token as used
	if err := s.otpRepo.MarkAsUsed(tenantID, otp.ID); err != nil {
		return nil, fmt.Errorf("failed to mark token as used: %w", err)
	}

	otp.MarkAsUsed()
	return otp, nil
}

// generateSecureToken generates a cryptographically secure random token
func (s *passwordlessService) generateSecureToken() (string, error) {
	bytes := make([]byte, s.tokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateEmailVerificationToken generates an email verification token
func GenerateEmailVerificationToken(tenantID uuid.UUID, email string, userID uuid.UUID, otpRepo repository.OTPRepository) (*domain.OTP, error) {
	// Generate secure random token
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(bytes)

	// Create OTP record with tenant ID
	otp := &domain.OTP{
		TenantID:  tenantID,
		UserID:    userID,
		Email:     email,
		Token:     token,
		Type:      domain.OTPTypeEmailVerification,
		ExpiresAt: time.Now().Add(24 * time.Hour), // Token expires in 24 hours
	}

	if err := otpRepo.Create(otp); err != nil {
		return nil, fmt.Errorf("failed to create email verification token: %w", err)
	}

	return otp, nil
}

// GeneratePasswordResetToken generates a password reset token
func GeneratePasswordResetToken(tenantID uuid.UUID, email string, userID uuid.UUID, otpRepo repository.OTPRepository) (*domain.OTP, error) {
	// Generate secure random token
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(bytes)

	// Create OTP record with tenant ID
	otp := &domain.OTP{
		TenantID:  tenantID,
		UserID:    userID,
		Email:     email,
		Token:     token,
		Type:      domain.OTPTypePasswordReset,
		ExpiresAt: time.Now().Add(1 * time.Hour), // Token expires in 1 hour
	}

	if err := otpRepo.Create(otp); err != nil {
		return nil, fmt.Errorf("failed to create password reset token: %w", err)
	}

	return otp, nil
}
