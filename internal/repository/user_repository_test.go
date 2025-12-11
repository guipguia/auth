package repository

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/guipguia/auth/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestTenantID creates a tenant directly in the database for testing
// In production, tenants are managed by the tenant service
func createTestTenantID(t *testing.T, db interface {
	Exec(sql string, values ...interface{}) interface{ Error() error }
}) uuid.UUID {
	tenantID := uuid.New()
	slug := "test-" + uuid.New().String()[:8]
	err := db.Exec(`INSERT INTO tenants (id, name, slug, status, settings, created_at, updated_at)
		VALUES (?, ?, ?, 'ACTIVE', '{}', NOW(), NOW())`,
		tenantID, "Test Tenant", slug).Error()
	if err != nil {
		// Table might not exist, that's ok for unit tests - tenant validation is done by tenant service
		return tenantID
	}
	return tenantID
}

func TestUserRepository_Create(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	user := &domain.User{
		TenantID:     tenantID,
		Email:        "test@example.com",
		PasswordHash: "hashedpassword123",
		FirstName:    "John",
		LastName:     "Doe",
	}

	err := repo.Create(user)
	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, user.ID)
}

func TestUserRepository_GetByID(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	user := &domain.User{
		TenantID:     tenantID,
		Email:        "getbyid@example.com",
		PasswordHash: "hashedpassword123",
		FirstName:    "Jane",
		LastName:     "Doe",
	}
	require.NoError(t, repo.Create(user))

	retrieved, err := repo.GetByID(tenantID, user.ID)
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, user.Email, retrieved.Email)
	assert.Equal(t, user.FirstName, retrieved.FirstName)
}

func TestUserRepository_GetByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	_, err := repo.GetByID(tenantID, uuid.New())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestUserRepository_GetByEmail(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	user := &domain.User{
		TenantID:     tenantID,
		Email:        "getbyemail@example.com",
		PasswordHash: "hashedpassword123",
		FirstName:    "Bob",
		LastName:     "Smith",
	}
	require.NoError(t, repo.Create(user))

	retrieved, err := repo.GetByEmail(tenantID, "getbyemail@example.com")
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, user.ID, retrieved.ID)
}

func TestUserRepository_GetByEmail_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	_, err := repo.GetByEmail(tenantID, "nonexistent@example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestUserRepository_Update(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	user := &domain.User{
		TenantID:     tenantID,
		Email:        "update@example.com",
		PasswordHash: "hashedpassword123",
		FirstName:    "Original",
		LastName:     "Name",
	}
	require.NoError(t, repo.Create(user))

	user.FirstName = "Updated"
	user.LastName = "User"
	err := repo.Update(user)
	assert.NoError(t, err)

	retrieved, err := repo.GetByID(tenantID, user.ID)
	assert.NoError(t, err)
	assert.Equal(t, "Updated", retrieved.FirstName)
	assert.Equal(t, "User", retrieved.LastName)
}

func TestUserRepository_Delete(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	user := &domain.User{
		TenantID:     tenantID,
		Email:        "delete@example.com",
		PasswordHash: "hashedpassword123",
	}
	require.NoError(t, repo.Create(user))

	err := repo.Delete(tenantID, user.ID)
	assert.NoError(t, err)

	_, err = repo.GetByID(tenantID, user.ID)
	assert.Error(t, err)
}

func TestUserRepository_Delete_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	err := repo.Delete(tenantID, uuid.New())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestUserRepository_UpdatePassword(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	user := &domain.User{
		TenantID:     tenantID,
		Email:        "password@example.com",
		PasswordHash: "oldhash",
	}
	require.NoError(t, repo.Create(user))

	err := repo.UpdatePassword(tenantID, user.ID, "newhash")
	assert.NoError(t, err)

	retrieved, err := repo.GetByID(tenantID, user.ID)
	assert.NoError(t, err)
	assert.Equal(t, "newhash", retrieved.PasswordHash)
	assert.False(t, retrieved.MustChangePassword)
}

func TestUserRepository_VerifyEmail(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	user := &domain.User{
		TenantID:      tenantID,
		Email:         "verify@example.com",
		PasswordHash:  "hash",
		EmailVerified: false,
	}
	require.NoError(t, repo.Create(user))

	err := repo.VerifyEmail(tenantID, user.ID)
	assert.NoError(t, err)

	retrieved, err := repo.GetByID(tenantID, user.ID)
	assert.NoError(t, err)
	assert.True(t, retrieved.EmailVerified)
	assert.NotNil(t, retrieved.EmailVerifiedAt)
}

func TestUserRepository_Enable2FA(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	user := &domain.User{
		TenantID:         tenantID,
		Email:            "2fa@example.com",
		PasswordHash:     "hash",
		TwoFactorEnabled: false,
	}
	require.NoError(t, repo.Create(user))

	secret := "JBSWY3DPEHPK3PXP"
	err := repo.Enable2FA(tenantID, user.ID, secret)
	assert.NoError(t, err)

	retrieved, err := repo.GetByID(tenantID, user.ID)
	assert.NoError(t, err)
	assert.True(t, retrieved.TwoFactorEnabled)
	assert.Equal(t, secret, retrieved.TwoFactorSecret)
}

func TestUserRepository_Disable2FA(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	user := &domain.User{
		TenantID:         tenantID,
		Email:            "disable2fa@example.com",
		PasswordHash:     "hash",
		TwoFactorEnabled: true,
		TwoFactorSecret:  "JBSWY3DPEHPK3PXP",
	}
	require.NoError(t, repo.Create(user))

	err := repo.Disable2FA(tenantID, user.ID)
	assert.NoError(t, err)

	retrieved, err := repo.GetByID(tenantID, user.ID)
	assert.NoError(t, err)
	assert.False(t, retrieved.TwoFactorEnabled)
	assert.Empty(t, retrieved.TwoFactorSecret)
}

func TestUserRepository_UpdateLastLogin(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	user := &domain.User{
		TenantID:         tenantID,
		Email:            "lastlogin@example.com",
		PasswordHash:     "hash",
		FailedLoginCount: 3,
	}
	require.NoError(t, repo.Create(user))

	err := repo.UpdateLastLogin(tenantID, user.ID)
	assert.NoError(t, err)

	retrieved, err := repo.GetByID(tenantID, user.ID)
	assert.NoError(t, err)
	assert.NotNil(t, retrieved.LastLoginAt)
	assert.Equal(t, 0, retrieved.FailedLoginCount)
}

func TestUserRepository_IncrementFailedLogin(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	user := &domain.User{
		TenantID:         tenantID,
		Email:            "failedlogin@example.com",
		PasswordHash:     "hash",
		FailedLoginCount: 0,
	}
	require.NoError(t, repo.Create(user))

	err := repo.IncrementFailedLogin(tenantID, user.ID)
	assert.NoError(t, err)

	retrieved, err := repo.GetByID(tenantID, user.ID)
	assert.NoError(t, err)
	assert.Equal(t, 1, retrieved.FailedLoginCount)
	assert.NotNil(t, retrieved.LastFailedLoginAt)
}

func TestUserRepository_ResetFailedLogin(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	now := time.Now()
	user := &domain.User{
		TenantID:          tenantID,
		Email:             "resetfailed@example.com",
		PasswordHash:      "hash",
		FailedLoginCount:  5,
		LastFailedLoginAt: &now,
	}
	require.NoError(t, repo.Create(user))

	err := repo.ResetFailedLogin(tenantID, user.ID)
	assert.NoError(t, err)

	retrieved, err := repo.GetByID(tenantID, user.ID)
	assert.NoError(t, err)
	assert.Equal(t, 0, retrieved.FailedLoginCount)
}

func TestUserRepository_LockAndUnlockAccount(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	user := &domain.User{
		TenantID:     tenantID,
		Email:        "lock@example.com",
		PasswordHash: "hash",
	}
	require.NoError(t, repo.Create(user))

	// Lock
	lockUntil := time.Now().Add(1 * time.Hour)
	err := repo.LockAccount(tenantID, user.ID, lockUntil)
	assert.NoError(t, err)

	retrieved, err := repo.GetByID(tenantID, user.ID)
	assert.NoError(t, err)
	assert.NotNil(t, retrieved.LockedUntil)

	// Unlock
	err = repo.UnlockAccount(tenantID, user.ID)
	assert.NoError(t, err)

	retrieved, err = repo.GetByID(tenantID, user.ID)
	assert.NoError(t, err)
	assert.Nil(t, retrieved.LockedUntil)
}

func TestUserRepository_SetMustChangePassword(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	user := &domain.User{
		TenantID:           tenantID,
		Email:              "mustchange@example.com",
		PasswordHash:       "hash",
		MustChangePassword: false,
	}
	require.NoError(t, repo.Create(user))

	err := repo.SetMustChangePassword(tenantID, user.ID, true)
	assert.NoError(t, err)

	retrieved, err := repo.GetByID(tenantID, user.ID)
	assert.NoError(t, err)
	assert.True(t, retrieved.MustChangePassword)
}

func TestUserRepository_BackupCodes(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	user := &domain.User{
		TenantID:     tenantID,
		Email:        "backupcodes@example.com",
		PasswordHash: "hash",
	}
	require.NoError(t, repo.Create(user))

	// Create backup codes
	codes := []string{"CODE1", "CODE2", "CODE3", "CODE4", "CODE5"}
	err := repo.CreateBackupCodes(tenantID, user.ID, codes)
	assert.NoError(t, err)

	// Get backup codes
	retrieved, err := repo.GetBackupCodes(tenantID, user.ID)
	assert.NoError(t, err)
	assert.Len(t, retrieved, 5)

	// Use a backup code
	err = repo.UseBackupCode(tenantID, user.ID, "CODE1")
	assert.NoError(t, err)

	// Get backup codes again - should be 4 unused
	retrieved, err = repo.GetBackupCodes(tenantID, user.ID)
	assert.NoError(t, err)
	assert.Len(t, retrieved, 4)

	// Try to use same code again - should fail
	err = repo.UseBackupCode(tenantID, user.ID, "CODE1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backup code not found or already used")
}

func TestUserRepository_OAuthAccounts(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	tenantID := uuid.New()

	user := &domain.User{
		TenantID:     tenantID,
		Email:        "oauth@example.com",
		PasswordHash: "hash",
	}
	require.NoError(t, repo.Create(user))

	// Create OAuth account
	oauthAccount := &domain.OAuthAccount{
		TenantID:       tenantID,
		UserID:         user.ID,
		Provider:       "google",
		ProviderUserID: "google-user-123",
		Email:          "oauth@gmail.com",
	}
	err := repo.CreateOAuthAccount(oauthAccount)
	assert.NoError(t, err)

	// Get OAuth account
	retrieved, err := repo.GetOAuthAccount(tenantID, "google", "google-user-123")
	assert.NoError(t, err)
	assert.Equal(t, user.ID, retrieved.UserID)

	// Get all OAuth accounts for user
	accounts, err := repo.GetOAuthAccountsByUserID(tenantID, user.ID)
	assert.NoError(t, err)
	assert.Len(t, accounts, 1)

	// Delete OAuth account
	err = repo.DeleteOAuthAccount(tenantID, user.ID, "google")
	assert.NoError(t, err)

	// Verify deletion
	_, err = repo.GetOAuthAccount(tenantID, "google", "google-user-123")
	assert.Error(t, err)
}

func TestUserRepository_TenantIsolation(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db, nil)

	// Create two tenant IDs (tenant validation is done by tenant service)
	tenant1ID := uuid.New()
	tenant2ID := uuid.New()

	// Create user in tenant1
	user := &domain.User{
		TenantID:     tenant1ID,
		Email:        "isolation@example.com",
		PasswordHash: "hash",
	}
	require.NoError(t, repo.Create(user))

	// Should find user in tenant1
	retrieved, err := repo.GetByEmail(tenant1ID, "isolation@example.com")
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)

	// Should NOT find user in tenant2
	_, err = repo.GetByEmail(tenant2ID, "isolation@example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}
