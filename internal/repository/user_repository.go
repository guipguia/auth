package repository

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/guipguia/auth/internal/crypto"
	"github.com/guipguia/auth/internal/domain"
)

// UserRepository handles database operations for users
type UserRepository interface {
	Create(user *domain.User) error
	GetByID(tenantID, id uuid.UUID) (*domain.User, error)
	GetByEmail(tenantID uuid.UUID, email string) (*domain.User, error)
	Update(user *domain.User) error
	Delete(tenantID, id uuid.UUID) error
	UpdatePassword(tenantID, userID uuid.UUID, passwordHash string) error
	VerifyEmail(tenantID, userID uuid.UUID) error
	Enable2FA(tenantID, userID uuid.UUID, secret string) error
	Disable2FA(tenantID, userID uuid.UUID) error
	UpdateLastLogin(tenantID, userID uuid.UUID) error
	// Compliance methods
	IncrementFailedLogin(tenantID, userID uuid.UUID) error
	ResetFailedLogin(tenantID, userID uuid.UUID) error
	LockAccount(tenantID, userID uuid.UUID, until time.Time) error
	UnlockAccount(tenantID, userID uuid.UUID) error
	SetMustChangePassword(tenantID, userID uuid.UUID, mustChange bool) error
	UpdatePasswordChangedAt(tenantID, userID uuid.UUID) error
	// Backup codes
	CreateBackupCodes(tenantID, userID uuid.UUID, codes []string) error
	GetBackupCodes(tenantID, userID uuid.UUID) ([]domain.BackupCode, error)
	UseBackupCode(tenantID, userID uuid.UUID, code string) error
	// OAuth
	CreateOAuthAccount(account *domain.OAuthAccount) error
	GetOAuthAccount(tenantID uuid.UUID, provider, providerUserID string) (*domain.OAuthAccount, error)
	GetOAuthAccountsByUserID(tenantID, userID uuid.UUID) ([]domain.OAuthAccount, error)
	DeleteOAuthAccount(tenantID, userID uuid.UUID, provider string) error
}

type userRepository struct {
	db        *gorm.DB
	encryptor *crypto.Encryptor
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *gorm.DB, encryptor *crypto.Encryptor) UserRepository {
	return &userRepository{
		db:        db,
		encryptor: encryptor,
	}
}

// Create creates a new user
func (r *userRepository) Create(user *domain.User) error {
	return r.db.Create(user).Error
}

// GetByID retrieves a user by ID within a tenant
func (r *userRepository) GetByID(tenantID, id uuid.UUID) (*domain.User, error) {
	var user domain.User
	err := r.db.Preload("OAuthAccounts", "tenant_id = ?", tenantID).
		First(&user, "tenant_id = ? AND id = ?", tenantID, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	// Decrypt TOTP secret if present and encryptor is available
	if user.TwoFactorSecret != "" && r.encryptor != nil {
		decrypted, err := r.encryptor.Decrypt(user.TwoFactorSecret)
		if err != nil {
			// If decryption fails, assume it's not encrypted (for backwards compatibility)
			// This allows for migration from unencrypted to encrypted data
		} else {
			user.TwoFactorSecret = decrypted
		}
	}

	return &user, nil
}

// GetByEmail retrieves a user by email within a tenant
func (r *userRepository) GetByEmail(tenantID uuid.UUID, email string) (*domain.User, error) {
	var user domain.User
	err := r.db.Preload("OAuthAccounts", "tenant_id = ?", tenantID).
		First(&user, "tenant_id = ? AND email = ?", tenantID, email).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	// Decrypt TOTP secret if present and encryptor is available
	if user.TwoFactorSecret != "" && r.encryptor != nil {
		decrypted, err := r.encryptor.Decrypt(user.TwoFactorSecret)
		if err != nil {
			// If decryption fails, assume it's not encrypted (for backwards compatibility)
			// This allows for migration from unencrypted to encrypted data
		} else {
			user.TwoFactorSecret = decrypted
		}
	}

	return &user, nil
}

// Update updates a user (tenant check via user.TenantID)
func (r *userRepository) Update(user *domain.User) error {
	return r.db.Save(user).Error
}

// Delete soft deletes a user within a tenant
func (r *userRepository) Delete(tenantID, id uuid.UUID) error {
	result := r.db.Where("tenant_id = ? AND id = ?", tenantID, id).Delete(&domain.User{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// UpdatePassword updates a user's password hash within a tenant
func (r *userRepository) UpdatePassword(tenantID, userID uuid.UUID, passwordHash string) error {
	now := time.Now()
	return r.db.Model(&domain.User{}).
		Where("tenant_id = ? AND id = ?", tenantID, userID).
		Updates(map[string]interface{}{
			"password_hash":        passwordHash,
			"password_changed_at":  now,
			"must_change_password": false,
		}).Error
}

// VerifyEmail marks a user's email as verified within a tenant
func (r *userRepository) VerifyEmail(tenantID, userID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&domain.User{}).
		Where("tenant_id = ? AND id = ?", tenantID, userID).
		Updates(map[string]interface{}{
			"email_verified":    true,
			"email_verified_at": now,
		}).Error
}

// Enable2FA enables 2FA for a user within a tenant
func (r *userRepository) Enable2FA(tenantID, userID uuid.UUID, secret string) error {
	// Encrypt the secret if encryptor is available
	encryptedSecret := secret
	if r.encryptor != nil {
		encrypted, err := r.encryptor.Encrypt(secret)
		if err != nil {
			return fmt.Errorf("failed to encrypt TOTP secret: %w", err)
		}
		encryptedSecret = encrypted
	}

	return r.db.Model(&domain.User{}).
		Where("tenant_id = ? AND id = ?", tenantID, userID).
		Updates(map[string]interface{}{
			"two_factor_enabled": true,
			"two_factor_secret":  encryptedSecret,
		}).Error
}

// Disable2FA disables 2FA for a user within a tenant
func (r *userRepository) Disable2FA(tenantID, userID uuid.UUID) error {
	return r.db.Model(&domain.User{}).
		Where("tenant_id = ? AND id = ?", tenantID, userID).
		Updates(map[string]interface{}{
			"two_factor_enabled": false,
			"two_factor_secret":  "",
		}).Error
}

// UpdateLastLogin updates the user's last login timestamp within a tenant
func (r *userRepository) UpdateLastLogin(tenantID, userID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&domain.User{}).
		Where("tenant_id = ? AND id = ?", tenantID, userID).
		Updates(map[string]interface{}{
			"last_login_at":      now,
			"failed_login_count": 0, // Reset failed login count on successful login
		}).Error
}

// IncrementFailedLogin increments the failed login counter
func (r *userRepository) IncrementFailedLogin(tenantID, userID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&domain.User{}).
		Where("tenant_id = ? AND id = ?", tenantID, userID).
		Updates(map[string]interface{}{
			"failed_login_count":   gorm.Expr("failed_login_count + 1"),
			"last_failed_login_at": now,
		}).Error
}

// ResetFailedLogin resets the failed login counter
func (r *userRepository) ResetFailedLogin(tenantID, userID uuid.UUID) error {
	return r.db.Model(&domain.User{}).
		Where("tenant_id = ? AND id = ?", tenantID, userID).
		Updates(map[string]interface{}{
			"failed_login_count":   0,
			"last_failed_login_at": nil,
		}).Error
}

// LockAccount locks a user account until a specified time
func (r *userRepository) LockAccount(tenantID, userID uuid.UUID, until time.Time) error {
	return r.db.Model(&domain.User{}).
		Where("tenant_id = ? AND id = ?", tenantID, userID).
		Update("locked_until", until).Error
}

// UnlockAccount unlocks a user account
func (r *userRepository) UnlockAccount(tenantID, userID uuid.UUID) error {
	return r.db.Model(&domain.User{}).
		Where("tenant_id = ? AND id = ?", tenantID, userID).
		Update("locked_until", nil).Error
}

// SetMustChangePassword sets whether the user must change their password
func (r *userRepository) SetMustChangePassword(tenantID, userID uuid.UUID, mustChange bool) error {
	return r.db.Model(&domain.User{}).
		Where("tenant_id = ? AND id = ?", tenantID, userID).
		Update("must_change_password", mustChange).Error
}

// UpdatePasswordChangedAt updates the password changed timestamp
func (r *userRepository) UpdatePasswordChangedAt(tenantID, userID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&domain.User{}).
		Where("tenant_id = ? AND id = ?", tenantID, userID).
		Update("password_changed_at", now).Error
}

// CreateBackupCodes creates backup codes for a user within a tenant
func (r *userRepository) CreateBackupCodes(tenantID, userID uuid.UUID, codes []string) error {
	// Delete existing backup codes
	if err := r.db.Where("tenant_id = ? AND user_id = ?", tenantID, userID).Delete(&domain.BackupCode{}).Error; err != nil {
		return err
	}

	// Create new backup codes
	backupCodes := make([]domain.BackupCode, len(codes))
	for i, code := range codes {
		// Encrypt the backup code if encryptor is available
		encryptedCode := code
		if r.encryptor != nil {
			encrypted, err := r.encryptor.Encrypt(code)
			if err != nil {
				return fmt.Errorf("failed to encrypt backup code: %w", err)
			}
			encryptedCode = encrypted
		}

		backupCodes[i] = domain.BackupCode{
			TenantID: tenantID,
			UserID:   userID,
			Code:     encryptedCode,
		}
	}

	return r.db.Create(&backupCodes).Error
}

// GetBackupCodes retrieves all unused backup codes for a user within a tenant
func (r *userRepository) GetBackupCodes(tenantID, userID uuid.UUID) ([]domain.BackupCode, error) {
	var codes []domain.BackupCode
	err := r.db.Where("tenant_id = ? AND user_id = ? AND used = ?", tenantID, userID, false).Find(&codes).Error
	if err != nil {
		return nil, err
	}

	// Decrypt backup codes if encryptor is available
	if r.encryptor != nil {
		for i := range codes {
			if codes[i].Code != "" {
				decrypted, err := r.encryptor.Decrypt(codes[i].Code)
				if err != nil {
					// If decryption fails, assume it's not encrypted (for backwards compatibility)
					continue
				}
				codes[i].Code = decrypted
			}
		}
	}

	return codes, nil
}

// UseBackupCode marks a backup code as used within a tenant
func (r *userRepository) UseBackupCode(tenantID, userID uuid.UUID, code string) error {
	// First, get all unused backup codes for the user
	var backupCodes []domain.BackupCode
	if err := r.db.Where("tenant_id = ? AND user_id = ? AND used = ?", tenantID, userID, false).Find(&backupCodes).Error; err != nil {
		return err
	}

	// Find the matching code (may need to decrypt)
	var matchingCodeID uuid.UUID
	found := false
	for _, bc := range backupCodes {
		storedCode := bc.Code
		// Try to decrypt if encryptor is available
		if r.encryptor != nil {
			decrypted, err := r.encryptor.Decrypt(bc.Code)
			if err == nil {
				storedCode = decrypted
			}
		}

		if storedCode == code {
			matchingCodeID = bc.ID
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("backup code not found or already used")
	}

	// Mark the matching code as used
	now := time.Now()
	result := r.db.Model(&domain.BackupCode{}).
		Where("tenant_id = ? AND id = ?", tenantID, matchingCodeID).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": now,
		})

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("backup code not found or already used")
	}

	return nil
}

// CreateOAuthAccount creates a new OAuth account
func (r *userRepository) CreateOAuthAccount(account *domain.OAuthAccount) error {
	return r.db.Create(account).Error
}

// GetOAuthAccount retrieves an OAuth account by provider and provider user ID within a tenant
func (r *userRepository) GetOAuthAccount(tenantID uuid.UUID, provider, providerUserID string) (*domain.OAuthAccount, error) {
	var account domain.OAuthAccount
	err := r.db.First(&account, "tenant_id = ? AND provider = ? AND provider_user_id = ?", tenantID, provider, providerUserID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("oauth account not found")
		}
		return nil, err
	}
	return &account, nil
}

// GetOAuthAccountsByUserID retrieves all OAuth accounts for a user within a tenant
func (r *userRepository) GetOAuthAccountsByUserID(tenantID, userID uuid.UUID) ([]domain.OAuthAccount, error) {
	var accounts []domain.OAuthAccount
	err := r.db.Where("tenant_id = ? AND user_id = ?", tenantID, userID).Find(&accounts).Error
	return accounts, err
}

// DeleteOAuthAccount deletes an OAuth account within a tenant
func (r *userRepository) DeleteOAuthAccount(tenantID, userID uuid.UUID, provider string) error {
	result := r.db.Where("tenant_id = ? AND user_id = ? AND provider = ?", tenantID, userID, provider).Delete(&domain.OAuthAccount{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("oauth account not found")
	}
	return nil
}
