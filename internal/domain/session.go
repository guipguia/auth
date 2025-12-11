package domain

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Session represents an active user session
type Session struct {
	ID             uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID       uuid.UUID      `gorm:"type:uuid;not null;index:idx_session_tenant_user" json:"tenant_id"`
	UserID         uuid.UUID      `gorm:"type:uuid;not null;index:idx_session_tenant_user" json:"user_id"`
	User           *User          `gorm:"foreignKey:UserID" json:"user,omitempty"`
	RefreshToken   string         `gorm:"column:refresh_token;uniqueIndex:idx_session_tenant_refresh,unique;not null" json:"-"`
	DeviceID       string         `gorm:"column:device_id" json:"device_id"`
	DeviceName     string         `gorm:"column:device_name" json:"device_name"`
	IPAddress      string         `gorm:"column:ip_address" json:"ip_address"`
	UserAgent      string         `gorm:"column:user_agent" json:"user_agent"`
	LastAccessedAt time.Time      `gorm:"column:last_accessed_at;autoUpdateTime" json:"last_accessed_at"`
	ExpiresAt      time.Time      `gorm:"column:expires_at;not null;index" json:"expires_at"`
	// Compliance fields for session security
	IdleTimeoutAt  *time.Time     `gorm:"column:idle_timeout_at;index" json:"idle_timeout_at,omitempty"` // For HIPAA idle timeout
	CreatedAt      time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt      time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	RevokedAt      *time.Time     `gorm:"column:revoked_at;index" json:"revoked_at,omitempty"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName specifies the table name for Session model
func (Session) TableName() string {
	return "sessions"
}

// IsActive checks if the session is still active
func (s *Session) IsActive() bool {
	return s.RevokedAt == nil && time.Now().Before(s.ExpiresAt)
}

// IsExpired checks if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// Revoke marks the session as revoked
func (s *Session) Revoke() {
	now := time.Now()
	s.RevokedAt = &now
}

// BeforeCreate hook to generate UUID if not set
func (s *Session) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}
