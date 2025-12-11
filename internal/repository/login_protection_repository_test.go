package repository

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/guipguia/auth/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Login Attempt Repository Tests

func TestLoginAttemptRepository_Create(t *testing.T) {
	db := setupTestDB(t)
	repo := NewLoginAttemptRepository(db)

	tenantID := uuid.New()

	attempt := &domain.LoginAttempt{
		TenantID:    tenantID,
		Email:       "test@example.com",
		IPAddress:   "192.168.1.100",
		UserAgent:   "TestAgent/1.0",
		Success:     true,
		AttemptedAt: time.Now(),
	}

	err := repo.Create(attempt)
	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, attempt.ID)
}

func TestLoginAttemptRepository_GetRecentAttempts(t *testing.T) {
	db := setupTestDB(t)
	repo := NewLoginAttemptRepository(db)

	tenantID := uuid.New()
	email := "attempts@example.com"

	// Create some attempts
	for i := 0; i < 5; i++ {
		attempt := &domain.LoginAttempt{
			TenantID:    tenantID,
			Email:       email,
			IPAddress:   "10.0.0.1",
			Success:     i%2 == 0,
			AttemptedAt: time.Now(),
		}
		require.NoError(t, repo.Create(attempt))
	}

	since := time.Now().Add(-1 * time.Minute)
	attempts, err := repo.GetRecentAttempts(tenantID, email, since)
	assert.NoError(t, err)
	assert.Len(t, attempts, 5)
}

func TestLoginAttemptRepository_GetRecentAttemptsByIP(t *testing.T) {
	db := setupTestDB(t)
	repo := NewLoginAttemptRepository(db)

	tenantID := uuid.New()
	ip := "192.168.1.100"

	// Create attempts from same IP
	for i := 0; i < 3; i++ {
		attempt := &domain.LoginAttempt{
			TenantID:    tenantID,
			Email:       "user" + string(rune('a'+i)) + "@example.com",
			IPAddress:   ip,
			Success:     false,
			AttemptedAt: time.Now(),
		}
		require.NoError(t, repo.Create(attempt))
	}

	since := time.Now().Add(-1 * time.Minute)
	attempts, err := repo.GetRecentAttemptsByIP(tenantID, ip, since)
	assert.NoError(t, err)
	assert.Len(t, attempts, 3)
}

func TestLoginAttemptRepository_CountFailedAttempts(t *testing.T) {
	db := setupTestDB(t)
	repo := NewLoginAttemptRepository(db)

	tenantID := uuid.New()
	email := "failed@example.com"

	// Create 5 failed and 2 successful attempts
	for i := 0; i < 5; i++ {
		attempt := &domain.LoginAttempt{
			TenantID:    tenantID,
			Email:       email,
			IPAddress:   "10.0.0.1",
			Success:     false,
			AttemptedAt: time.Now(),
		}
		require.NoError(t, repo.Create(attempt))
	}

	for i := 0; i < 2; i++ {
		attempt := &domain.LoginAttempt{
			TenantID:    tenantID,
			Email:       email,
			IPAddress:   "10.0.0.1",
			Success:     true,
			AttemptedAt: time.Now(),
		}
		require.NoError(t, repo.Create(attempt))
	}

	since := time.Now().Add(-1 * time.Minute)
	count, err := repo.CountFailedAttempts(tenantID, email, since)
	assert.NoError(t, err)
	assert.Equal(t, int64(5), count)
}

func TestLoginAttemptRepository_CountFailedAttemptsByIP(t *testing.T) {
	db := setupTestDB(t)
	repo := NewLoginAttemptRepository(db)

	tenantID := uuid.New()
	ip := "10.10.10.10"

	// Create 3 failed attempts from same IP
	for i := 0; i < 3; i++ {
		attempt := &domain.LoginAttempt{
			TenantID:    tenantID,
			Email:       "user@example.com",
			IPAddress:   ip,
			Success:     false,
			AttemptedAt: time.Now(),
		}
		require.NoError(t, repo.Create(attempt))
	}

	since := time.Now().Add(-1 * time.Minute)
	count, err := repo.CountFailedAttemptsByIP(tenantID, ip, since)
	assert.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestLoginAttemptRepository_DeleteOlderThan(t *testing.T) {
	db := setupTestDB(t)
	repo := NewLoginAttemptRepository(db)

	tenantID := uuid.New()

	// Create some attempts
	for i := 0; i < 5; i++ {
		attempt := &domain.LoginAttempt{
			TenantID:    tenantID,
			Email:       "delete@example.com",
			IPAddress:   "10.0.0.1",
			Success:     true,
			AttemptedAt: time.Now(),
		}
		require.NoError(t, repo.Create(attempt))
	}

	// Delete all (using future time)
	futureTime := time.Now().Add(1 * time.Hour)
	deleted, err := repo.DeleteOlderThan(futureTime)
	assert.NoError(t, err)
	assert.Equal(t, int64(5), deleted)
}

// Account Lockout Repository Tests

func TestAccountLockoutRepository_Create(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAccountLockoutRepository(db)

	tenantID := uuid.New()
	userID := uuid.New()

	lockout := &domain.AccountLockout{
		TenantID:    tenantID,
		UserID:      userID,
		Email:       "lockout@example.com",
		FailedCount: 5,
		LockedAt:    time.Now(),
		UnlocksAt:   time.Now().Add(30 * time.Minute),
		LockReason:  "too_many_failed_attempts",
	}

	err := repo.Create(lockout)
	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, lockout.ID)
}

func TestAccountLockoutRepository_GetByUserID(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAccountLockoutRepository(db)

	tenantID := uuid.New()
	userID := uuid.New()

	lockout := &domain.AccountLockout{
		TenantID:    tenantID,
		UserID:      userID,
		Email:       "getbyuser@example.com",
		FailedCount: 3,
		LockedAt:    time.Now(),
		UnlocksAt:   time.Now().Add(30 * time.Minute),
		LockReason:  "too_many_failed_attempts",
	}
	require.NoError(t, repo.Create(lockout))

	retrieved, err := repo.GetByUserID(tenantID, userID)
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, userID, retrieved.UserID)
}

func TestAccountLockoutRepository_GetByEmail(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAccountLockoutRepository(db)

	tenantID := uuid.New()
	userID := uuid.New()
	email := "getbyemail@example.com"

	lockout := &domain.AccountLockout{
		TenantID:    tenantID,
		UserID:      userID,
		Email:       email,
		FailedCount: 3,
		LockedAt:    time.Now(),
		UnlocksAt:   time.Now().Add(30 * time.Minute),
		LockReason:  "too_many_failed_attempts",
	}
	require.NoError(t, repo.Create(lockout))

	retrieved, err := repo.GetByEmail(tenantID, email)
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, email, retrieved.Email)
}

func TestAccountLockoutRepository_GetActiveLockout(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAccountLockoutRepository(db)

	tenantID := uuid.New()
	userID := uuid.New()

	// Create an active lockout (unlocks in future, not yet unlocked)
	lockout := &domain.AccountLockout{
		TenantID:    tenantID,
		UserID:      userID,
		Email:       "active@example.com",
		FailedCount: 5,
		LockedAt:    time.Now(),
		UnlocksAt:   time.Now().Add(30 * time.Minute),
		LockReason:  "too_many_failed_attempts",
	}
	require.NoError(t, repo.Create(lockout))

	retrieved, err := repo.GetActiveLockout(tenantID, userID)
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.True(t, retrieved.IsLocked())
}

func TestAccountLockoutRepository_GetActiveLockout_Expired(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAccountLockoutRepository(db)

	tenantID := uuid.New()
	userID := uuid.New()

	// Create an expired lockout
	lockout := &domain.AccountLockout{
		TenantID:    tenantID,
		UserID:      userID,
		Email:       "expired@example.com",
		FailedCount: 5,
		LockedAt:    time.Now().Add(-1 * time.Hour),
		UnlocksAt:   time.Now().Add(-30 * time.Minute), // Already expired
		LockReason:  "too_many_failed_attempts",
	}
	require.NoError(t, repo.Create(lockout))

	// Should not find active lockout
	_, err := repo.GetActiveLockout(tenantID, userID)
	assert.Error(t, err)
}

func TestAccountLockoutRepository_Update(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAccountLockoutRepository(db)

	tenantID := uuid.New()
	userID := uuid.New()

	lockout := &domain.AccountLockout{
		TenantID:    tenantID,
		UserID:      userID,
		Email:       "update@example.com",
		FailedCount: 3,
		LockedAt:    time.Now(),
		UnlocksAt:   time.Now().Add(30 * time.Minute),
		LockReason:  "too_many_failed_attempts",
	}
	require.NoError(t, repo.Create(lockout))

	lockout.FailedCount = 5
	lockout.LockReason = "suspicious_activity"
	err := repo.Update(lockout)
	assert.NoError(t, err)

	retrieved, err := repo.GetByUserID(tenantID, userID)
	assert.NoError(t, err)
	assert.Equal(t, 5, retrieved.FailedCount)
	assert.Equal(t, "suspicious_activity", retrieved.LockReason)
}

func TestAccountLockoutRepository_Unlock(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAccountLockoutRepository(db)

	tenantID := uuid.New()
	userID := uuid.New()
	adminID := uuid.New()

	lockout := &domain.AccountLockout{
		TenantID:    tenantID,
		UserID:      userID,
		Email:       "unlock@example.com",
		FailedCount: 5,
		LockedAt:    time.Now(),
		UnlocksAt:   time.Now().Add(30 * time.Minute),
		LockReason:  "too_many_failed_attempts",
	}
	require.NoError(t, repo.Create(lockout))

	err := repo.Unlock(tenantID, userID, &adminID)
	assert.NoError(t, err)

	// Should not have active lockout anymore
	_, err = repo.GetActiveLockout(tenantID, userID)
	assert.Error(t, err)
}

func TestAccountLockoutRepository_DeleteExpired(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAccountLockoutRepository(db)

	tenantID := uuid.New()

	// Create old expired lockout
	lockout := &domain.AccountLockout{
		TenantID:    tenantID,
		UserID:      uuid.New(),
		Email:       "old@example.com",
		FailedCount: 5,
		LockedAt:    time.Now().Add(-61 * 24 * time.Hour),
		UnlocksAt:   time.Now().Add(-60 * 24 * time.Hour), // 60 days ago
		LockReason:  "too_many_failed_attempts",
	}
	require.NoError(t, repo.Create(lockout))

	deleted, err := repo.DeleteExpired()
	assert.NoError(t, err)
	assert.Equal(t, int64(1), deleted)
}

// Password History Repository Tests

func TestPasswordHistoryRepository_Create(t *testing.T) {
	db := setupTestDB(t)
	repo := NewPasswordHistoryRepository(db)

	tenantID := uuid.New()
	userID := uuid.New()

	history := &domain.PasswordHistory{
		TenantID:     tenantID,
		UserID:       userID,
		PasswordHash: "hashedpassword123",
	}

	err := repo.Create(history)
	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, history.ID)
}

func TestPasswordHistoryRepository_GetRecent(t *testing.T) {
	db := setupTestDB(t)
	repo := NewPasswordHistoryRepository(db)

	tenantID := uuid.New()
	userID := uuid.New()

	// Create 10 password history entries
	for i := 0; i < 10; i++ {
		history := &domain.PasswordHistory{
			TenantID:     tenantID,
			UserID:       userID,
			PasswordHash: "hash" + string(rune('0'+i)),
		}
		require.NoError(t, repo.Create(history))
		time.Sleep(1 * time.Millisecond) // Ensure different timestamps
	}

	// Get 5 most recent
	recent, err := repo.GetRecent(tenantID, userID, 5)
	assert.NoError(t, err)
	assert.Len(t, recent, 5)
}

func TestPasswordHistoryRepository_DeleteOldest(t *testing.T) {
	db := setupTestDB(t)
	repo := NewPasswordHistoryRepository(db)

	tenantID := uuid.New()
	userID := uuid.New()

	// Create 10 password history entries
	for i := 0; i < 10; i++ {
		history := &domain.PasswordHistory{
			TenantID:     tenantID,
			UserID:       userID,
			PasswordHash: "hash" + string(rune('0'+i)),
		}
		require.NoError(t, repo.Create(history))
		time.Sleep(1 * time.Millisecond)
	}

	// Keep only 5
	err := repo.DeleteOldest(tenantID, userID, 5)
	assert.NoError(t, err)

	// Verify only 5 remain
	remaining, err := repo.GetRecent(tenantID, userID, 100)
	assert.NoError(t, err)
	assert.Len(t, remaining, 5)
}

func TestPasswordHistoryRepository_DeleteOldest_NoneToDelete(t *testing.T) {
	db := setupTestDB(t)
	repo := NewPasswordHistoryRepository(db)

	tenantID := uuid.New()
	userID := uuid.New()

	// No entries to delete
	err := repo.DeleteOldest(tenantID, userID, 5)
	assert.NoError(t, err)
}

// Tenant Isolation Tests

func TestLoginAttemptRepository_TenantIsolation(t *testing.T) {
	db := setupTestDB(t)
	repo := NewLoginAttemptRepository(db)

	tenant1ID := uuid.New()
	tenant2ID := uuid.New()
	email := "shared@example.com"

	// Create attempt in tenant1
	attempt := &domain.LoginAttempt{
		TenantID:    tenant1ID,
		Email:       email,
		IPAddress:   "10.0.0.1",
		Success:     false,
		AttemptedAt: time.Now(),
	}
	require.NoError(t, repo.Create(attempt))

	since := time.Now().Add(-1 * time.Minute)

	// Should find in tenant1
	count, err := repo.CountFailedAttempts(tenant1ID, email, since)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Should NOT find in tenant2
	count, err = repo.CountFailedAttempts(tenant2ID, email, since)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), count)
}
