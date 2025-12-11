package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// LoginAttempt Tests

func TestLoginAttempt_TableName(t *testing.T) {
	attempt := LoginAttempt{}
	assert.Equal(t, "login_attempts", attempt.TableName())
}

func TestLoginAttempt_Fields(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	attemptedAt := time.Now()

	attempt := LoginAttempt{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Email:       "test@example.com",
		UserID:      &userID,
		IPAddress:   "192.168.1.100",
		UserAgent:   "Mozilla/5.0",
		Success:     true,
		FailReason:  "",
		AttemptedAt: attemptedAt,
	}

	assert.Equal(t, tenantID, attempt.TenantID)
	assert.Equal(t, "test@example.com", attempt.Email)
	assert.Equal(t, userID, *attempt.UserID)
	assert.Equal(t, "192.168.1.100", attempt.IPAddress)
	assert.Equal(t, "Mozilla/5.0", attempt.UserAgent)
	assert.True(t, attempt.Success)
	assert.Empty(t, attempt.FailReason)
}

func TestLoginAttempt_FailedAttempt(t *testing.T) {
	attempt := LoginAttempt{
		TenantID:   uuid.New(),
		Email:      "test@example.com",
		IPAddress:  "192.168.1.100",
		Success:    false,
		FailReason: string(LoginFailReasonInvalidCredentials),
	}

	assert.False(t, attempt.Success)
	assert.Equal(t, string(LoginFailReasonInvalidCredentials), attempt.FailReason)
}

// LoginFailReason Constants Tests

func TestLoginFailReason_Constants(t *testing.T) {
	tests := []struct {
		name     string
		reason   LoginFailReason
		expected string
	}{
		{"InvalidCredentials", LoginFailReasonInvalidCredentials, "INVALID_CREDENTIALS"},
		{"AccountLocked", LoginFailReasonAccountLocked, "ACCOUNT_LOCKED"},
		{"AccountDisabled", LoginFailReasonAccountDisabled, "ACCOUNT_DISABLED"},
		{"EmailNotVerified", LoginFailReasonEmailNotVerified, "EMAIL_NOT_VERIFIED"},
		{"MFARequired", LoginFailReasonMFARequired, "MFA_REQUIRED"},
		{"MFAInvalid", LoginFailReasonMFAInvalid, "MFA_INVALID"},
		{"TenantInactive", LoginFailReasonTenantInactive, "TENANT_INACTIVE"},
		{"RateLimited", LoginFailReasonRateLimited, "RATE_LIMITED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.reason))
		})
	}
}

// AccountLockout Tests

func TestAccountLockout_TableName(t *testing.T) {
	lockout := AccountLockout{}
	assert.Equal(t, "account_lockouts", lockout.TableName())
}

func TestAccountLockout_IsLocked_CurrentlyLocked(t *testing.T) {
	lockout := AccountLockout{
		TenantID:   uuid.New(),
		UserID:     uuid.New(),
		Email:      "locked@example.com",
		LockedAt:   time.Now(),
		UnlocksAt:  time.Now().Add(30 * time.Minute), // Unlocks in 30 minutes
		LockReason: string(LockReasonTooManyFailedAttempts),
		UnlockedAt: nil, // Not manually unlocked
	}

	assert.True(t, lockout.IsLocked())
}

func TestAccountLockout_IsLocked_ExpiredLock(t *testing.T) {
	lockout := AccountLockout{
		TenantID:   uuid.New(),
		UserID:     uuid.New(),
		Email:      "locked@example.com",
		LockedAt:   time.Now().Add(-1 * time.Hour),
		UnlocksAt:  time.Now().Add(-30 * time.Minute), // Already expired
		LockReason: string(LockReasonTooManyFailedAttempts),
		UnlockedAt: nil,
	}

	assert.False(t, lockout.IsLocked())
}

func TestAccountLockout_IsLocked_ManuallyUnlocked(t *testing.T) {
	unlockedTime := time.Now()
	adminID := uuid.New()

	lockout := AccountLockout{
		TenantID:   uuid.New(),
		UserID:     uuid.New(),
		Email:      "locked@example.com",
		LockedAt:   time.Now().Add(-1 * time.Hour),
		UnlocksAt:  time.Now().Add(30 * time.Minute), // Still in lock period
		LockReason: string(LockReasonTooManyFailedAttempts),
		UnlockedAt: &unlockedTime, // Manually unlocked
		UnlockedBy: &adminID,
	}

	assert.False(t, lockout.IsLocked())
}

func TestAccountLockout_Fields(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	adminID := uuid.New()
	lockedAt := time.Now()
	unlocksAt := time.Now().Add(30 * time.Minute)

	lockout := AccountLockout{
		ID:          uuid.New(),
		TenantID:    tenantID,
		UserID:      userID,
		Email:       "test@example.com",
		LockedAt:    lockedAt,
		UnlocksAt:   unlocksAt,
		LockReason:  string(LockReasonSuspiciousActivity),
		FailedCount: 5,
		UnlockedBy:  &adminID,
	}

	assert.Equal(t, tenantID, lockout.TenantID)
	assert.Equal(t, userID, lockout.UserID)
	assert.Equal(t, "test@example.com", lockout.Email)
	assert.Equal(t, string(LockReasonSuspiciousActivity), lockout.LockReason)
	assert.Equal(t, 5, lockout.FailedCount)
	assert.Equal(t, adminID, *lockout.UnlockedBy)
}

// LockReason Constants Tests

func TestLockReason_Constants(t *testing.T) {
	tests := []struct {
		name     string
		reason   LockReason
		expected string
	}{
		{"TooManyFailedAttempts", LockReasonTooManyFailedAttempts, "TOO_MANY_FAILED_ATTEMPTS"},
		{"SuspiciousActivity", LockReasonSuspiciousActivity, "SUSPICIOUS_ACTIVITY"},
		{"AdminAction", LockReasonAdminAction, "ADMIN_ACTION"},
		{"SecurityBreach", LockReasonSecurityBreach, "SECURITY_BREACH"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.reason))
		})
	}
}

// IPRateLimit Tests

func TestIPRateLimit_TableName(t *testing.T) {
	rateLimit := IPRateLimit{}
	assert.Equal(t, "ip_rate_limits", rateLimit.TableName())
}

func TestIPRateLimit_IsBlocked_CurrentlyBlocked(t *testing.T) {
	blockedUntil := time.Now().Add(10 * time.Minute)

	rateLimit := IPRateLimit{
		TenantID:     uuid.New(),
		IPAddress:    "192.168.1.100",
		AttemptCount: 100,
		BlockedUntil: &blockedUntil,
	}

	assert.True(t, rateLimit.IsBlocked())
}

func TestIPRateLimit_IsBlocked_BlockExpired(t *testing.T) {
	blockedUntil := time.Now().Add(-10 * time.Minute) // Already expired

	rateLimit := IPRateLimit{
		TenantID:     uuid.New(),
		IPAddress:    "192.168.1.100",
		AttemptCount: 100,
		BlockedUntil: &blockedUntil,
	}

	assert.False(t, rateLimit.IsBlocked())
}

func TestIPRateLimit_IsBlocked_NeverBlocked(t *testing.T) {
	rateLimit := IPRateLimit{
		TenantID:     uuid.New(),
		IPAddress:    "192.168.1.100",
		AttemptCount: 5,
		BlockedUntil: nil, // Not blocked
	}

	assert.False(t, rateLimit.IsBlocked())
}

func TestIPRateLimit_Fields(t *testing.T) {
	tenantID := uuid.New()
	firstAttempt := time.Now().Add(-1 * time.Hour)
	lastAttempt := time.Now()

	rateLimit := IPRateLimit{
		ID:           uuid.New(),
		TenantID:     tenantID,
		IPAddress:    "10.0.0.1",
		AttemptCount: 50,
		FirstAttempt: firstAttempt,
		LastAttempt:  lastAttempt,
	}

	assert.Equal(t, tenantID, rateLimit.TenantID)
	assert.Equal(t, "10.0.0.1", rateLimit.IPAddress)
	assert.Equal(t, 50, rateLimit.AttemptCount)
}

// PasswordHistory Tests

func TestPasswordHistory_TableName(t *testing.T) {
	history := PasswordHistory{}
	assert.Equal(t, "password_history", history.TableName())
}

func TestPasswordHistory_Fields(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()

	history := PasswordHistory{
		ID:           uuid.New(),
		TenantID:     tenantID,
		UserID:       userID,
		PasswordHash: "hashed_password_123",
	}

	assert.Equal(t, tenantID, history.TenantID)
	assert.Equal(t, userID, history.UserID)
	assert.Equal(t, "hashed_password_123", history.PasswordHash)
}
