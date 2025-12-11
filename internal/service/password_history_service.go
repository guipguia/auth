package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/guipguia/auth/internal/domain"
	"github.com/guipguia/auth/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// PasswordHistoryConfig holds configuration for password history
type PasswordHistoryConfig struct {
	// Number of previous passwords to check against
	HistoryCount int
	// Minimum days before password can be reused (0 = never)
	MinPasswordAgeDays int
}

// DefaultPasswordHistoryConfig returns sensible default configuration
func DefaultPasswordHistoryConfig() PasswordHistoryConfig {
	return PasswordHistoryConfig{
		HistoryCount:       12, // HIPAA/SOC2 typically require 12-24
		MinPasswordAgeDays: 0,  // No minimum age by default
	}
}

// PasswordHistoryService handles password history for compliance
type PasswordHistoryService interface {
	// CheckPasswordReuse checks if the password was used recently
	CheckPasswordReuse(ctx context.Context, tenantID, userID uuid.UUID, newPassword string) error

	// RecordPassword records a password in history
	RecordPassword(ctx context.Context, tenantID, userID uuid.UUID, passwordHash string) error

	// CleanupOldHistory removes old password history entries
	CleanupOldHistory(ctx context.Context, tenantID, userID uuid.UUID) error
}

type passwordHistoryService struct {
	historyRepo repository.PasswordHistoryRepository
	config      PasswordHistoryConfig
}

// NewPasswordHistoryService creates a new password history service
func NewPasswordHistoryService(
	historyRepo repository.PasswordHistoryRepository,
	config PasswordHistoryConfig,
) PasswordHistoryService {
	return &passwordHistoryService{
		historyRepo: historyRepo,
		config:      config,
	}
}

// CheckPasswordReuse checks if the password was used recently
func (s *passwordHistoryService) CheckPasswordReuse(ctx context.Context, tenantID, userID uuid.UUID, newPassword string) error {
	// Get recent password hashes
	history, err := s.historyRepo.GetRecent(tenantID, userID, s.config.HistoryCount)
	if err != nil {
		return fmt.Errorf("failed to get password history: %w", err)
	}

	// Check against each historical password
	for _, h := range history {
		if err := bcrypt.CompareHashAndPassword([]byte(h.PasswordHash), []byte(newPassword)); err == nil {
			return fmt.Errorf("password has been used recently, please choose a different password")
		}
	}

	return nil
}

// RecordPassword records a password in history
func (s *passwordHistoryService) RecordPassword(ctx context.Context, tenantID, userID uuid.UUID, passwordHash string) error {
	// Create history entry
	history := &domain.PasswordHistory{
		TenantID:     tenantID,
		UserID:       userID,
		PasswordHash: passwordHash,
	}

	if err := s.historyRepo.Create(history); err != nil {
		return fmt.Errorf("failed to record password history: %w", err)
	}

	// Cleanup old entries
	return s.CleanupOldHistory(ctx, tenantID, userID)
}

// CleanupOldHistory removes old password history entries
func (s *passwordHistoryService) CleanupOldHistory(ctx context.Context, tenantID, userID uuid.UUID) error {
	// Keep only the configured number of entries
	return s.historyRepo.DeleteOldest(tenantID, userID, s.config.HistoryCount)
}
