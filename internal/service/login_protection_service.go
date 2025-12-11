package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/guipguia/auth/internal/domain"
	"github.com/guipguia/auth/internal/repository"
)

// LoginProtectionConfig holds configuration for login protection
type LoginProtectionConfig struct {
	// Maximum failed login attempts before lockout
	MaxFailedAttempts int
	// Time window to count failed attempts
	FailedAttemptsWindow time.Duration
	// Lockout duration after max failed attempts
	LockoutDuration time.Duration
	// Progressive lockout multiplier for repeat offenders
	LockoutMultiplier float64
	// Maximum lockout duration
	MaxLockoutDuration time.Duration
	// IP-based rate limiting threshold
	IPRateLimitThreshold int
	// IP rate limit window
	IPRateLimitWindow time.Duration
}

// DefaultLoginProtectionConfig returns sensible default configuration
func DefaultLoginProtectionConfig() LoginProtectionConfig {
	return LoginProtectionConfig{
		MaxFailedAttempts:    5,
		FailedAttemptsWindow: 15 * time.Minute,
		LockoutDuration:      15 * time.Minute,
		LockoutMultiplier:    2.0,
		MaxLockoutDuration:   24 * time.Hour,
		IPRateLimitThreshold: 20,
		IPRateLimitWindow:    15 * time.Minute,
	}
}

// LoginProtectionService handles brute force protection and account lockout
type LoginProtectionService interface {
	// CheckLoginAllowed checks if login is allowed for the given email/IP
	CheckLoginAllowed(ctx context.Context, tenantID uuid.UUID, email, ipAddress string) error

	// RecordLoginAttempt records a login attempt (success or failure)
	RecordLoginAttempt(ctx context.Context, tenantID uuid.UUID, email, ipAddress string, userID *uuid.UUID, success bool, failureReason string) error

	// GetActiveLockout gets the active lockout for a user if any
	GetActiveLockout(ctx context.Context, tenantID, userID uuid.UUID) (*domain.AccountLockout, error)

	// UnlockAccount manually unlocks an account (admin action)
	UnlockAccount(ctx context.Context, tenantID, userID uuid.UUID, unlockedBy *uuid.UUID) error

	// CleanupExpired removes expired records
	CleanupExpired(ctx context.Context) error
}

type loginProtectionService struct {
	loginAttemptRepo repository.LoginAttemptRepository
	lockoutRepo      repository.AccountLockoutRepository
	userRepo         repository.UserRepository
	config           LoginProtectionConfig
}

// NewLoginProtectionService creates a new login protection service
func NewLoginProtectionService(
	loginAttemptRepo repository.LoginAttemptRepository,
	lockoutRepo repository.AccountLockoutRepository,
	userRepo repository.UserRepository,
	config LoginProtectionConfig,
) LoginProtectionService {
	return &loginProtectionService{
		loginAttemptRepo: loginAttemptRepo,
		lockoutRepo:      lockoutRepo,
		userRepo:         userRepo,
		config:           config,
	}
}

// CheckLoginAllowed checks if login is allowed for the given email/IP
func (s *loginProtectionService) CheckLoginAllowed(ctx context.Context, tenantID uuid.UUID, email, ipAddress string) error {
	// Check IP-based rate limiting first
	if ipAddress != "" {
		since := time.Now().Add(-s.config.IPRateLimitWindow)
		ipAttempts, err := s.loginAttemptRepo.CountFailedAttemptsByIP(tenantID, ipAddress, since)
		if err != nil {
			return fmt.Errorf("failed to check IP rate limit: %w", err)
		}

		if ipAttempts >= int64(s.config.IPRateLimitThreshold) {
			return fmt.Errorf("too many failed login attempts from this IP address, please try again later")
		}
	}

	// Check email-based rate limiting
	since := time.Now().Add(-s.config.FailedAttemptsWindow)
	emailAttempts, err := s.loginAttemptRepo.CountFailedAttempts(tenantID, email, since)
	if err != nil {
		return fmt.Errorf("failed to check email rate limit: %w", err)
	}

	if emailAttempts >= int64(s.config.MaxFailedAttempts) {
		return fmt.Errorf("account temporarily locked due to too many failed login attempts")
	}

	return nil
}

// RecordLoginAttempt records a login attempt (success or failure)
func (s *loginProtectionService) RecordLoginAttempt(ctx context.Context, tenantID uuid.UUID, email, ipAddress string, userID *uuid.UUID, success bool, failureReason string) error {
	// Create the login attempt record
	attempt := &domain.LoginAttempt{
		TenantID:    tenantID,
		Email:       email,
		IPAddress:   ipAddress,
		UserAgent:   UserAgentFromContext(ctx),
		Success:     success,
		FailReason:  failureReason,
		AttemptedAt: time.Now(),
	}
	if userID != nil {
		attempt.UserID = userID
	}

	if err := s.loginAttemptRepo.Create(attempt); err != nil {
		return fmt.Errorf("failed to record login attempt: %w", err)
	}

	// If successful login, reset failed login count for the user
	if success && userID != nil {
		if err := s.userRepo.ResetFailedLogin(tenantID, *userID); err != nil {
			// Log but don't fail
			log.Printf("[WARN] Failed to reset failed login count: %v", err)
		}
		return nil
	}

	// For failed attempts, increment the user's failed login count
	if !success && userID != nil {
		if err := s.userRepo.IncrementFailedLogin(tenantID, *userID); err != nil {
			log.Printf("[WARN] Failed to increment failed login count: %v", err)
		}

		// Check if we need to create a lockout
		since := time.Now().Add(-s.config.FailedAttemptsWindow)
		failedAttempts, err := s.loginAttemptRepo.CountFailedAttempts(tenantID, email, since)
		if err != nil {
			return nil // Don't fail the whole operation
		}

		if failedAttempts >= int64(s.config.MaxFailedAttempts) {
			if err := s.createLockout(ctx, tenantID, *userID, email); err != nil {
				log.Printf("[WARN] Failed to create lockout: %v", err)
			}
		}
	}

	return nil
}

// createLockout creates or extends a lockout for a user
func (s *loginProtectionService) createLockout(ctx context.Context, tenantID, userID uuid.UUID, email string) error {
	// Check for existing lockout to determine multiplier
	var lockoutDuration time.Duration
	existingLockout, err := s.lockoutRepo.GetByUserID(tenantID, userID)
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}

	if existingLockout != nil && existingLockout.UnlockedAt == nil {
		// Progressive lockout - increase duration
		lockoutDuration = time.Duration(float64(s.config.LockoutDuration) * s.config.LockoutMultiplier)
	} else {
		lockoutDuration = s.config.LockoutDuration
	}

	// Cap at max lockout duration
	if lockoutDuration > s.config.MaxLockoutDuration {
		lockoutDuration = s.config.MaxLockoutDuration
	}

	// Count failed attempts for lockout record
	since := time.Now().Add(-s.config.FailedAttemptsWindow)
	failedAttempts, _ := s.loginAttemptRepo.CountFailedAttempts(tenantID, email, since)

	// Create lockout record
	lockout := &domain.AccountLockout{
		TenantID:    tenantID,
		UserID:      userID,
		Email:       email,
		LockReason:  string(domain.LockReasonTooManyFailedAttempts),
		FailedCount: int(failedAttempts),
		LockedAt:    time.Now(),
		UnlocksAt:   time.Now().Add(lockoutDuration),
	}

	if err := s.lockoutRepo.Create(lockout); err != nil {
		return err
	}

	// Also lock the user account
	return s.userRepo.LockAccount(tenantID, userID, lockout.UnlocksAt)
}

// GetActiveLockout gets the active lockout for a user if any
func (s *loginProtectionService) GetActiveLockout(ctx context.Context, tenantID, userID uuid.UUID) (*domain.AccountLockout, error) {
	return s.lockoutRepo.GetActiveLockout(tenantID, userID)
}

// UnlockAccount manually unlocks an account (admin action)
func (s *loginProtectionService) UnlockAccount(ctx context.Context, tenantID, userID uuid.UUID, unlockedBy *uuid.UUID) error {
	// Unlock in lockout repository
	if err := s.lockoutRepo.Unlock(tenantID, userID, unlockedBy); err != nil {
		// Ignore if no lockout exists
		log.Printf("[DEBUG] No active lockout to unlock: %v", err)
	}

	// Unlock user account
	if err := s.userRepo.UnlockAccount(tenantID, userID); err != nil {
		return fmt.Errorf("failed to unlock user account: %w", err)
	}

	// Reset failed login count
	return s.userRepo.ResetFailedLogin(tenantID, userID)
}

// CleanupExpired removes expired records
func (s *loginProtectionService) CleanupExpired(ctx context.Context) error {
	// Delete old login attempts (older than 30 days)
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	if _, err := s.loginAttemptRepo.DeleteOlderThan(thirtyDaysAgo); err != nil {
		return fmt.Errorf("failed to delete old login attempts: %w", err)
	}

	// Delete expired lockouts
	if _, err := s.lockoutRepo.DeleteExpired(); err != nil {
		return fmt.Errorf("failed to delete expired lockouts: %w", err)
	}

	return nil
}
