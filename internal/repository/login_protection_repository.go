package repository

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/guipguia/auth/internal/domain"
)

// LoginAttemptRepository handles database operations for login attempts
type LoginAttemptRepository interface {
	Create(attempt *domain.LoginAttempt) error
	GetRecentAttempts(tenantID uuid.UUID, email string, since time.Time) ([]domain.LoginAttempt, error)
	GetRecentAttemptsByIP(tenantID uuid.UUID, ip string, since time.Time) ([]domain.LoginAttempt, error)
	CountFailedAttempts(tenantID uuid.UUID, email string, since time.Time) (int64, error)
	CountFailedAttemptsByIP(tenantID uuid.UUID, ip string, since time.Time) (int64, error)
	DeleteOlderThan(before time.Time) (int64, error)
}

type loginAttemptRepository struct {
	db *gorm.DB
}

// NewLoginAttemptRepository creates a new login attempt repository
func NewLoginAttemptRepository(db *gorm.DB) LoginAttemptRepository {
	return &loginAttemptRepository{db: db}
}

// Create creates a new login attempt record
func (r *loginAttemptRepository) Create(attempt *domain.LoginAttempt) error {
	return r.db.Create(attempt).Error
}

// GetRecentAttempts retrieves recent login attempts for an email
func (r *loginAttemptRepository) GetRecentAttempts(tenantID uuid.UUID, email string, since time.Time) ([]domain.LoginAttempt, error) {
	var attempts []domain.LoginAttempt
	err := r.db.Where("tenant_id = ? AND email = ? AND attempted_at >= ?", tenantID, email, since).
		Order("attempted_at DESC").
		Find(&attempts).Error
	return attempts, err
}

// GetRecentAttemptsByIP retrieves recent login attempts from an IP
func (r *loginAttemptRepository) GetRecentAttemptsByIP(tenantID uuid.UUID, ip string, since time.Time) ([]domain.LoginAttempt, error) {
	var attempts []domain.LoginAttempt
	err := r.db.Where("tenant_id = ? AND ip_address = ? AND attempted_at >= ?", tenantID, ip, since).
		Order("attempted_at DESC").
		Find(&attempts).Error
	return attempts, err
}

// CountFailedAttempts counts failed login attempts for an email since a given time
func (r *loginAttemptRepository) CountFailedAttempts(tenantID uuid.UUID, email string, since time.Time) (int64, error) {
	var count int64
	err := r.db.Model(&domain.LoginAttempt{}).
		Where("tenant_id = ? AND email = ? AND success = ? AND attempted_at >= ?", tenantID, email, false, since).
		Count(&count).Error
	return count, err
}

// CountFailedAttemptsByIP counts failed login attempts from an IP since a given time
func (r *loginAttemptRepository) CountFailedAttemptsByIP(tenantID uuid.UUID, ip string, since time.Time) (int64, error) {
	var count int64
	err := r.db.Model(&domain.LoginAttempt{}).
		Where("tenant_id = ? AND ip_address = ? AND success = ? AND attempted_at >= ?", tenantID, ip, false, since).
		Count(&count).Error
	return count, err
}

// DeleteOlderThan deletes login attempts older than the specified time
func (r *loginAttemptRepository) DeleteOlderThan(before time.Time) (int64, error) {
	result := r.db.Where("attempted_at < ?", before).Delete(&domain.LoginAttempt{})
	return result.RowsAffected, result.Error
}

// AccountLockoutRepository handles database operations for account lockouts
type AccountLockoutRepository interface {
	Create(lockout *domain.AccountLockout) error
	GetByUserID(tenantID, userID uuid.UUID) (*domain.AccountLockout, error)
	GetByEmail(tenantID uuid.UUID, email string) (*domain.AccountLockout, error)
	GetActiveLockout(tenantID, userID uuid.UUID) (*domain.AccountLockout, error)
	Update(lockout *domain.AccountLockout) error
	Unlock(tenantID, userID uuid.UUID, unlockedBy *uuid.UUID) error
	DeleteExpired() (int64, error)
}

type accountLockoutRepository struct {
	db *gorm.DB
}

// NewAccountLockoutRepository creates a new account lockout repository
func NewAccountLockoutRepository(db *gorm.DB) AccountLockoutRepository {
	return &accountLockoutRepository{db: db}
}

// Create creates a new account lockout
func (r *accountLockoutRepository) Create(lockout *domain.AccountLockout) error {
	return r.db.Create(lockout).Error
}

// GetByUserID retrieves the most recent lockout for a user
func (r *accountLockoutRepository) GetByUserID(tenantID, userID uuid.UUID) (*domain.AccountLockout, error) {
	var lockout domain.AccountLockout
	err := r.db.Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Order("created_at DESC").
		First(&lockout).Error
	if err != nil {
		return nil, err
	}
	return &lockout, nil
}

// GetByEmail retrieves the most recent lockout for an email
func (r *accountLockoutRepository) GetByEmail(tenantID uuid.UUID, email string) (*domain.AccountLockout, error) {
	var lockout domain.AccountLockout
	err := r.db.Where("tenant_id = ? AND email = ?", tenantID, email).
		Order("created_at DESC").
		First(&lockout).Error
	if err != nil {
		return nil, err
	}
	return &lockout, nil
}

// GetActiveLockout retrieves an active lockout for a user
func (r *accountLockoutRepository) GetActiveLockout(tenantID, userID uuid.UUID) (*domain.AccountLockout, error) {
	var lockout domain.AccountLockout
	now := time.Now()
	err := r.db.Where("tenant_id = ? AND user_id = ? AND unlocks_at > ? AND unlocked_at IS NULL", tenantID, userID, now).
		First(&lockout).Error
	if err != nil {
		return nil, err
	}
	return &lockout, nil
}

// Update updates an account lockout
func (r *accountLockoutRepository) Update(lockout *domain.AccountLockout) error {
	return r.db.Save(lockout).Error
}

// Unlock unlocks an account
func (r *accountLockoutRepository) Unlock(tenantID, userID uuid.UUID, unlockedBy *uuid.UUID) error {
	now := time.Now()
	updates := map[string]interface{}{
		"unlocked_at": now,
	}
	if unlockedBy != nil {
		updates["unlocked_by"] = *unlockedBy
	}

	return r.db.Model(&domain.AccountLockout{}).
		Where("tenant_id = ? AND user_id = ? AND unlocked_at IS NULL", tenantID, userID).
		Updates(updates).Error
}

// DeleteExpired deletes expired lockouts (already unlocked or past unlock time)
func (r *accountLockoutRepository) DeleteExpired() (int64, error) {
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	result := r.db.Where("unlocks_at < ? OR unlocked_at IS NOT NULL", thirtyDaysAgo).
		Delete(&domain.AccountLockout{})
	return result.RowsAffected, result.Error
}

// PasswordHistoryRepository handles database operations for password history
type PasswordHistoryRepository interface {
	Create(history *domain.PasswordHistory) error
	GetRecent(tenantID, userID uuid.UUID, limit int) ([]domain.PasswordHistory, error)
	DeleteOldest(tenantID, userID uuid.UUID, keepCount int) error
}

type passwordHistoryRepository struct {
	db *gorm.DB
}

// NewPasswordHistoryRepository creates a new password history repository
func NewPasswordHistoryRepository(db *gorm.DB) PasswordHistoryRepository {
	return &passwordHistoryRepository{db: db}
}

// Create creates a new password history entry
func (r *passwordHistoryRepository) Create(history *domain.PasswordHistory) error {
	return r.db.Create(history).Error
}

// GetRecent retrieves recent password hashes for a user
func (r *passwordHistoryRepository) GetRecent(tenantID, userID uuid.UUID, limit int) ([]domain.PasswordHistory, error) {
	var history []domain.PasswordHistory
	err := r.db.Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Order("created_at DESC").
		Limit(limit).
		Find(&history).Error
	return history, err
}

// DeleteOldest deletes oldest password history entries, keeping only the most recent N
func (r *passwordHistoryRepository) DeleteOldest(tenantID, userID uuid.UUID, keepCount int) error {
	// Get IDs to keep
	var idsToKeep []uuid.UUID
	err := r.db.Model(&domain.PasswordHistory{}).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Order("created_at DESC").
		Limit(keepCount).
		Pluck("id", &idsToKeep).Error
	if err != nil {
		return err
	}

	if len(idsToKeep) == 0 {
		return nil
	}

	// Delete entries not in the keep list
	return r.db.Where("tenant_id = ? AND user_id = ? AND id NOT IN ?", tenantID, userID, idsToKeep).
		Delete(&domain.PasswordHistory{}).Error
}
