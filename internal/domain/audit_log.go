package domain

import (
	"time"

	"github.com/google/uuid"
)

// AuditAction represents the type of action being audited
type AuditAction string

const (
	// Authentication actions
	AuditActionLogin         AuditAction = "LOGIN"
	AuditActionLoginFailed   AuditAction = "LOGIN_FAILED"
	AuditActionLogout        AuditAction = "LOGOUT"
	AuditActionTokenRefresh  AuditAction = "TOKEN_REFRESH"
	AuditActionTokenValidate AuditAction = "TOKEN_VALIDATE"
	AuditActionTokenRevoke   AuditAction = "TOKEN_REVOKE"

	// Registration actions
	AuditActionRegister          AuditAction = "REGISTER"
	AuditActionEmailVerify       AuditAction = "EMAIL_VERIFY"
	AuditActionEmailVerifyResend AuditAction = "EMAIL_VERIFY_RESEND"

	// Password actions
	AuditActionPasswordChange       AuditAction = "PASSWORD_CHANGE"
	AuditActionPasswordReset        AuditAction = "PASSWORD_RESET"
	AuditActionPasswordResetRequest AuditAction = "PASSWORD_RESET_REQUEST"

	// MFA actions
	AuditActionMFAEnable         AuditAction = "MFA_ENABLE"
	AuditActionMFADisable        AuditAction = "MFA_DISABLE"
	AuditActionMFAVerify         AuditAction = "MFA_VERIFY"
	AuditActionMFABackupGenerate AuditAction = "MFA_BACKUP_GENERATE"
	AuditActionMFABackupUsed     AuditAction = "MFA_BACKUP_USED"

	// Session actions
	AuditActionSessionCreate    AuditAction = "SESSION_CREATE"
	AuditActionSessionRevoke    AuditAction = "SESSION_REVOKE"
	AuditActionSessionRevokeAll AuditAction = "SESSION_REVOKE_ALL"

	// OAuth actions
	AuditActionOAuthLink   AuditAction = "OAUTH_LINK"
	AuditActionOAuthUnlink AuditAction = "OAUTH_UNLINK"
	AuditActionOAuthLogin  AuditAction = "OAUTH_LOGIN"

	// Passwordless actions
	AuditActionPasswordlessSend   AuditAction = "PASSWORDLESS_SEND"
	AuditActionPasswordlessVerify AuditAction = "PASSWORDLESS_VERIFY"

	// Profile actions
	AuditActionProfileUpdate AuditAction = "PROFILE_UPDATE"
	AuditActionProfileView   AuditAction = "PROFILE_VIEW"

	// Account actions
	AuditActionAccountLock   AuditAction = "ACCOUNT_LOCK"
	AuditActionAccountUnlock AuditAction = "ACCOUNT_UNLOCK"
	AuditActionAccountDelete AuditAction = "ACCOUNT_DELETE"

	// Admin actions
	AuditActionAdminUserCreate AuditAction = "ADMIN_USER_CREATE"
	AuditActionAdminUserUpdate AuditAction = "ADMIN_USER_UPDATE"
	AuditActionAdminUserDelete AuditAction = "ADMIN_USER_DELETE"

	// Membership/Team actions
	AuditActionMemberAdd        AuditAction = "MEMBER_ADD"
	AuditActionMemberRemove     AuditAction = "MEMBER_REMOVE"
	AuditActionMemberRoleChange AuditAction = "MEMBER_ROLE_CHANGE"
	AuditActionMemberInvite     AuditAction = "MEMBER_INVITE"
	AuditActionMemberJoin       AuditAction = "MEMBER_JOIN"
	AuditActionInvitationCancel AuditAction = "INVITATION_CANCEL"
)

// AuditStatus represents the status of an audited action
type AuditStatus string

const (
	AuditStatusSuccess AuditStatus = "SUCCESS"
	AuditStatusFailure AuditStatus = "FAILURE"
)

// AuditResourceType represents the type of resource being acted upon
type AuditResourceType string

const (
	AuditResourceUser       AuditResourceType = "USER"
	AuditResourceSession    AuditResourceType = "SESSION"
	AuditResourceOTP        AuditResourceType = "OTP"
	AuditResourceOAuth      AuditResourceType = "OAUTH"
	AuditResourceTenant     AuditResourceType = "TENANT"
	AuditResourceMembership AuditResourceType = "MEMBERSHIP"
	AuditResourceInvitation AuditResourceType = "INVITATION"
)

// AuditLog represents a comprehensive audit trail entry
// This is critical for HIPAA, SOC 2, and GDPR compliance
type AuditLog struct {
	ID            uuid.UUID         `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID      uuid.UUID         `gorm:"type:uuid;not null;index" json:"tenant_id"`
	UserID        *uuid.UUID        `gorm:"type:uuid;index" json:"user_id,omitempty"`  // The user affected by the action
	ActorID       *uuid.UUID        `gorm:"type:uuid;index" json:"actor_id,omitempty"` // The user who performed the action (for admin actions)
	Action        AuditAction       `gorm:"type:varchar(50);not null;index" json:"action"`
	ResourceType  AuditResourceType `gorm:"type:varchar(50);not null;index" json:"resource_type"`
	ResourceID    string            `gorm:"index" json:"resource_id,omitempty"`
	Status        AuditStatus       `gorm:"type:varchar(20);not null;index" json:"status"`
	FailureReason string            `gorm:"type:text" json:"failure_reason,omitempty"`
	IPAddress     string            `gorm:"type:varchar(45);not null" json:"ip_address"` // IPv6 max length
	UserAgent     string            `gorm:"type:text" json:"user_agent,omitempty"`
	SessionID     *uuid.UUID        `gorm:"type:uuid;index" json:"session_id,omitempty"`
	Metadata      JSONMap           `gorm:"type:jsonb;default:'{}'" json:"metadata,omitempty"` // Additional context
	CreatedAt     time.Time         `gorm:"autoCreateTime;index" json:"created_at"`
}

// TableName specifies the table name for AuditLog model
func (AuditLog) TableName() string {
	return "audit_logs"
}

// NewAuditLog creates a new audit log entry with required fields
func NewAuditLog(tenantID uuid.UUID, action AuditAction, resourceType AuditResourceType, status AuditStatus, ipAddress string) *AuditLog {
	return &AuditLog{
		TenantID:     tenantID,
		Action:       action,
		ResourceType: resourceType,
		Status:       status,
		IPAddress:    ipAddress,
		Metadata:     make(JSONMap),
	}
}

// WithUser sets the user ID for the audit log
func (a *AuditLog) WithUser(userID uuid.UUID) *AuditLog {
	a.UserID = &userID
	return a
}

// WithActor sets the actor ID for the audit log (for admin actions)
func (a *AuditLog) WithActor(actorID uuid.UUID) *AuditLog {
	a.ActorID = &actorID
	return a
}

// WithResource sets the resource ID for the audit log
func (a *AuditLog) WithResource(resourceID string) *AuditLog {
	a.ResourceID = resourceID
	return a
}

// WithSession sets the session ID for the audit log
func (a *AuditLog) WithSession(sessionID uuid.UUID) *AuditLog {
	a.SessionID = &sessionID
	return a
}

// WithFailure sets the failure reason for the audit log
func (a *AuditLog) WithFailure(reason string) *AuditLog {
	a.FailureReason = reason
	a.Status = AuditStatusFailure
	return a
}

// WithUserAgent sets the user agent for the audit log
func (a *AuditLog) WithUserAgent(userAgent string) *AuditLog {
	a.UserAgent = userAgent
	return a
}

// WithMetadata adds metadata to the audit log
func (a *AuditLog) WithMetadata(key string, value interface{}) *AuditLog {
	if a.Metadata == nil {
		a.Metadata = make(JSONMap)
	}
	a.Metadata[key] = value
	return a
}
