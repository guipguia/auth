package domain

import (
	"time"

	"github.com/google/uuid"
)

// LoginAttempt tracks all authentication attempts for security monitoring
// Required for HIPAA and SOC 2 compliance
type LoginAttempt struct {
	ID          uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID    uuid.UUID  `gorm:"type:uuid;not null;index" json:"tenant_id"`
	Email       string     `gorm:"type:varchar(255);not null;index" json:"email"`
	UserID      *uuid.UUID `gorm:"type:uuid;index" json:"user_id,omitempty"` // Set if user exists
	IPAddress   string     `gorm:"type:varchar(45);not null;index" json:"ip_address"`
	UserAgent   string     `gorm:"type:text" json:"user_agent,omitempty"`
	Success     bool       `gorm:"not null;index" json:"success"`
	FailReason  string     `gorm:"type:varchar(100)" json:"fail_reason,omitempty"`
	AttemptedAt time.Time  `gorm:"autoCreateTime;index" json:"attempted_at"`
}

// TableName specifies the table name for LoginAttempt model
func (LoginAttempt) TableName() string {
	return "login_attempts"
}

// LoginFailReason represents the reason for a failed login
type LoginFailReason string

const (
	LoginFailReasonInvalidCredentials LoginFailReason = "INVALID_CREDENTIALS"
	LoginFailReasonAccountLocked      LoginFailReason = "ACCOUNT_LOCKED"
	LoginFailReasonAccountDisabled    LoginFailReason = "ACCOUNT_DISABLED"
	LoginFailReasonEmailNotVerified   LoginFailReason = "EMAIL_NOT_VERIFIED"
	LoginFailReasonMFARequired        LoginFailReason = "MFA_REQUIRED"
	LoginFailReasonMFAInvalid         LoginFailReason = "MFA_INVALID"
	LoginFailReasonTenantInactive     LoginFailReason = "TENANT_INACTIVE"
	LoginFailReasonRateLimited        LoginFailReason = "RATE_LIMITED"
)

// AccountLockout tracks locked accounts
// Required for brute force protection (HIPAA, SOC 2)
type AccountLockout struct {
	ID          uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID    uuid.UUID  `gorm:"type:uuid;not null;index" json:"tenant_id"`
	UserID      uuid.UUID  `gorm:"type:uuid;not null;index:idx_lockout_tenant_user,unique" json:"user_id"`
	Email       string     `gorm:"type:varchar(255);not null;index" json:"email"` // Denormalized for faster lookups
	LockedAt    time.Time  `gorm:"not null" json:"locked_at"`
	UnlocksAt   time.Time  `gorm:"not null;index" json:"unlocks_at"`
	LockReason  string     `gorm:"type:varchar(100);not null" json:"lock_reason"`
	FailedCount int        `gorm:"not null" json:"failed_count"`
	UnlockedAt  *time.Time `gorm:"index" json:"unlocked_at,omitempty"`   // Set when manually unlocked
	UnlockedBy  *uuid.UUID `gorm:"type:uuid" json:"unlocked_by,omitempty"` // Admin who unlocked
	CreatedAt   time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
}

// TableName specifies the table name for AccountLockout model
func (AccountLockout) TableName() string {
	return "account_lockouts"
}

// IsLocked checks if the account is currently locked
func (a *AccountLockout) IsLocked() bool {
	if a.UnlockedAt != nil {
		return false
	}
	return time.Now().Before(a.UnlocksAt)
}

// LockReason represents the reason for account lockout
type LockReason string

const (
	LockReasonTooManyFailedAttempts LockReason = "TOO_MANY_FAILED_ATTEMPTS"
	LockReasonSuspiciousActivity    LockReason = "SUSPICIOUS_ACTIVITY"
	LockReasonAdminAction           LockReason = "ADMIN_ACTION"
	LockReasonSecurityBreach        LockReason = "SECURITY_BREACH"
)

// IPRateLimit tracks rate limiting by IP address
// Prevents distributed brute force attacks
type IPRateLimit struct {
	ID           uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID     uuid.UUID `gorm:"type:uuid;not null;index" json:"tenant_id"`
	IPAddress    string    `gorm:"type:varchar(45);not null;index:idx_ip_rate_tenant_ip,unique" json:"ip_address"`
	AttemptCount int       `gorm:"not null;default:0" json:"attempt_count"`
	BlockedUntil *time.Time `gorm:"index" json:"blocked_until,omitempty"`
	FirstAttempt time.Time  `gorm:"not null" json:"first_attempt"`
	LastAttempt  time.Time  `gorm:"not null" json:"last_attempt"`
	CreatedAt    time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt    time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
}

// TableName specifies the table name for IPRateLimit model
func (IPRateLimit) TableName() string {
	return "ip_rate_limits"
}

// IsBlocked checks if the IP is currently blocked
func (i *IPRateLimit) IsBlocked() bool {
	if i.BlockedUntil == nil {
		return false
	}
	return time.Now().Before(*i.BlockedUntil)
}

// PasswordHistory tracks password history to prevent reuse
// Required for SOC 2 compliance
type PasswordHistory struct {
	ID           uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID     uuid.UUID `gorm:"type:uuid;not null;index" json:"tenant_id"`
	UserID       uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id"`
	PasswordHash string    `gorm:"type:varchar(255);not null" json:"-"` // Never expose
	CreatedAt    time.Time `gorm:"autoCreateTime;index" json:"created_at"`
}

// TableName specifies the table name for PasswordHistory model
func (PasswordHistory) TableName() string {
	return "password_history"
}
