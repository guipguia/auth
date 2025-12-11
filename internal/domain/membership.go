package domain

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// MemberRole represents the role of a user within a tenant
type MemberRole string

const (
	RoleOwner  MemberRole = "owner"
	RoleAdmin  MemberRole = "admin"
	RoleMember MemberRole = "member"
)

// MemberStatus represents the status of a membership
type MemberStatus string

const (
	StatusActive   MemberStatus = "active"
	StatusInvited  MemberStatus = "invited"
	StatusDisabled MemberStatus = "disabled"
)

// TenantMembership represents a user's membership in a tenant
type TenantMembership struct {
	ID        uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID  uuid.UUID      `gorm:"type:uuid;not null;index:idx_membership_tenant_user,unique" json:"tenant_id"`
	UserID    uuid.UUID      `gorm:"type:uuid;not null;index:idx_membership_tenant_user,unique" json:"user_id"`
	Role      MemberRole     `gorm:"type:varchar(50);not null;default:'member'" json:"role"`
	Status    MemberStatus   `gorm:"type:varchar(20);not null;default:'active'" json:"status"`
	InvitedBy *uuid.UUID     `gorm:"type:uuid" json:"invited_by,omitempty"`
	InvitedAt *time.Time     `json:"invited_at,omitempty"`
	JoinedAt  *time.Time     `json:"joined_at,omitempty"`
	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Relations (not loaded by default)
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName specifies the table name for TenantMembership model
func (TenantMembership) TableName() string {
	return "tenant_memberships"
}

// BeforeCreate hook to generate UUID if not set
func (m *TenantMembership) BeforeCreate(tx *gorm.DB) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	return nil
}

// IsOwner checks if the membership has owner role
func (m *TenantMembership) IsOwner() bool {
	return m.Role == RoleOwner
}

// IsAdmin checks if the membership has admin or owner role
func (m *TenantMembership) IsAdmin() bool {
	return m.Role == RoleOwner || m.Role == RoleAdmin
}

// CanManageMembers checks if this member can manage other members
func (m *TenantMembership) CanManageMembers() bool {
	return m.IsAdmin() && m.Status == StatusActive
}

// CanChangeRole checks if this member can change another member's role
func (m *TenantMembership) CanChangeRole() bool {
	return m.IsOwner() && m.Status == StatusActive
}

// TenantInvitation represents a pending invitation to join a tenant
type TenantInvitation struct {
	ID         uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID   uuid.UUID  `gorm:"type:uuid;not null;index" json:"tenant_id"`
	Email      string     `gorm:"type:varchar(255);not null;index:idx_invitation_tenant_email,unique" json:"email"`
	Role       MemberRole `gorm:"type:varchar(50);not null;default:'member'" json:"role"`
	Token      string     `gorm:"type:varchar(255);not null;unique" json:"-"`
	InvitedBy  uuid.UUID  `gorm:"type:uuid;not null" json:"invited_by"`
	ExpiresAt  time.Time  `gorm:"not null" json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	CreatedAt  time.Time  `gorm:"autoCreateTime" json:"created_at"`

	// Relations (not loaded by default)
	InvitedByUser *User `gorm:"foreignKey:InvitedBy" json:"invited_by_user,omitempty"`
}

// TableName specifies the table name for TenantInvitation model
func (TenantInvitation) TableName() string {
	return "tenant_invitations"
}

// BeforeCreate hook to generate UUID and token if not set
func (i *TenantInvitation) BeforeCreate(tx *gorm.DB) error {
	if i.ID == uuid.Nil {
		i.ID = uuid.New()
	}
	if i.Token == "" {
		i.Token = generateInvitationToken()
	}
	return nil
}

// IsExpired checks if the invitation has expired
func (i *TenantInvitation) IsExpired() bool {
	return time.Now().After(i.ExpiresAt)
}

// IsAccepted checks if the invitation has been accepted
func (i *TenantInvitation) IsAccepted() bool {
	return i.AcceptedAt != nil
}

// IsPending checks if the invitation is still pending
func (i *TenantInvitation) IsPending() bool {
	return !i.IsExpired() && !i.IsAccepted()
}

// generateInvitationToken creates a secure random token for invitations
func generateInvitationToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to UUID if crypto/rand fails
		return uuid.New().String()
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// DefaultInvitationExpiry returns the default expiration duration for invitations (7 days)
func DefaultInvitationExpiry() time.Duration {
	return 7 * 24 * time.Hour
}

// ValidRoles returns all valid member roles
func ValidRoles() []MemberRole {
	return []MemberRole{RoleOwner, RoleAdmin, RoleMember}
}

// IsValidRole checks if a role string is valid
func IsValidRole(role string) bool {
	for _, r := range ValidRoles() {
		if string(r) == role {
			return true
		}
	}
	return false
}
