package domain

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// OTPType represents the type of OTP
type OTPType string

const (
	OTPTypeEmailVerification OTPType = "email_verification"
	OTPTypePasswordReset     OTPType = "password_reset"
	OTPTypePasswordless      OTPType = "passwordless"
	OTPType2FA               OTPType = "two_factor"
)

// OTP represents a one-time password/token
type OTP struct {
	ID        uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID  uuid.UUID      `gorm:"type:uuid;not null;index:idx_otp_tenant_email_type" json:"tenant_id"`
	UserID    uuid.UUID      `gorm:"type:uuid;index" json:"user_id"` // May be null for email verification before registration
	Email     string         `gorm:"not null;index:idx_otp_tenant_email_type" json:"email"`
	Token     string         `gorm:"uniqueIndex:idx_otp_tenant_token,unique;not null" json:"token"`
	Type      OTPType        `gorm:"type:varchar(50);not null;index:idx_otp_tenant_email_type" json:"type"`
	Code      string         `json:"code,omitempty"` // Optional numeric code (for 2FA, etc.)
	Used      bool           `gorm:"default:false;index" json:"used"`
	UsedAt    *time.Time     `gorm:"column:used_at" json:"used_at,omitempty"`
	ExpiresAt time.Time      `gorm:"column:expires_at;not null;index" json:"expires_at"`
	Metadata  map[string]string `gorm:"type:jsonb" json:"metadata,omitempty"`
	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName specifies the table name for OTP model
func (OTP) TableName() string {
	return "otps"
}

// IsValid checks if the OTP is valid (not used and not expired)
func (o *OTP) IsValid() bool {
	return !o.Used && time.Now().Before(o.ExpiresAt)
}

// IsExpired checks if the OTP has expired
func (o *OTP) IsExpired() bool {
	return time.Now().After(o.ExpiresAt)
}

// MarkAsUsed marks the OTP as used
func (o *OTP) MarkAsUsed() {
	o.Used = true
	now := time.Now()
	o.UsedAt = &now
}

// BeforeCreate hook to generate UUID if not set
func (o *OTP) BeforeCreate(tx *gorm.DB) error {
	if o.ID == uuid.Nil {
		o.ID = uuid.New()
	}
	return nil
}
