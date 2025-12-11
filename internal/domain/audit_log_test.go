package domain

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAuditLog_TableName(t *testing.T) {
	log := AuditLog{}
	assert.Equal(t, "audit_logs", log.TableName())
}

func TestNewAuditLog(t *testing.T) {
	tenantID := uuid.New()
	action := AuditActionLogin
	resourceType := AuditResourceUser
	status := AuditStatusSuccess
	ipAddress := "192.168.1.100"

	log := NewAuditLog(tenantID, action, resourceType, status, ipAddress)

	assert.Equal(t, tenantID, log.TenantID)
	assert.Equal(t, action, log.Action)
	assert.Equal(t, resourceType, log.ResourceType)
	assert.Equal(t, status, log.Status)
	assert.Equal(t, ipAddress, log.IPAddress)
	assert.NotNil(t, log.Metadata)
}

func TestAuditLog_WithUser(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()

	log := NewAuditLog(tenantID, AuditActionLogin, AuditResourceUser, AuditStatusSuccess, "10.0.0.1")
	result := log.WithUser(userID)

	// Check it returns the same pointer (builder pattern)
	assert.Equal(t, log, result)
	assert.NotNil(t, log.UserID)
	assert.Equal(t, userID, *log.UserID)
}

func TestAuditLog_WithActor(t *testing.T) {
	tenantID := uuid.New()
	actorID := uuid.New()

	log := NewAuditLog(tenantID, AuditActionAdminUserUpdate, AuditResourceUser, AuditStatusSuccess, "10.0.0.1")
	result := log.WithActor(actorID)

	assert.Equal(t, log, result)
	assert.NotNil(t, log.ActorID)
	assert.Equal(t, actorID, *log.ActorID)
}

func TestAuditLog_WithResource(t *testing.T) {
	tenantID := uuid.New()
	resourceID := "resource-123"

	log := NewAuditLog(tenantID, AuditActionLogin, AuditResourceSession, AuditStatusSuccess, "10.0.0.1")
	result := log.WithResource(resourceID)

	assert.Equal(t, log, result)
	assert.Equal(t, resourceID, log.ResourceID)
}

func TestAuditLog_WithSession(t *testing.T) {
	tenantID := uuid.New()
	sessionID := uuid.New()

	log := NewAuditLog(tenantID, AuditActionLogin, AuditResourceSession, AuditStatusSuccess, "10.0.0.1")
	result := log.WithSession(sessionID)

	assert.Equal(t, log, result)
	assert.NotNil(t, log.SessionID)
	assert.Equal(t, sessionID, *log.SessionID)
}

func TestAuditLog_WithFailure(t *testing.T) {
	tenantID := uuid.New()
	failureReason := "Invalid credentials"

	log := NewAuditLog(tenantID, AuditActionLogin, AuditResourceUser, AuditStatusSuccess, "10.0.0.1")
	result := log.WithFailure(failureReason)

	assert.Equal(t, log, result)
	assert.Equal(t, failureReason, log.FailureReason)
	assert.Equal(t, AuditStatusFailure, log.Status)
}

func TestAuditLog_WithUserAgent(t *testing.T) {
	tenantID := uuid.New()
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

	log := NewAuditLog(tenantID, AuditActionLogin, AuditResourceUser, AuditStatusSuccess, "10.0.0.1")
	result := log.WithUserAgent(userAgent)

	assert.Equal(t, log, result)
	assert.Equal(t, userAgent, log.UserAgent)
}

func TestAuditLog_WithMetadata(t *testing.T) {
	tenantID := uuid.New()

	log := NewAuditLog(tenantID, AuditActionLogin, AuditResourceUser, AuditStatusSuccess, "10.0.0.1")
	result := log.WithMetadata("key1", "value1").WithMetadata("key2", 123)

	assert.Equal(t, log, result)
	assert.Equal(t, "value1", log.Metadata["key1"])
	assert.Equal(t, 123, log.Metadata["key2"])
}

func TestAuditLog_WithMetadata_NilMetadata(t *testing.T) {
	log := &AuditLog{
		TenantID: uuid.New(),
		Metadata: nil, // Explicitly nil
	}

	result := log.WithMetadata("key", "value")

	assert.Equal(t, log, result)
	assert.NotNil(t, log.Metadata)
	assert.Equal(t, "value", log.Metadata["key"])
}

func TestAuditLog_ChainedMethods(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	actorID := uuid.New()
	sessionID := uuid.New()

	log := NewAuditLog(tenantID, AuditActionAdminUserUpdate, AuditResourceUser, AuditStatusSuccess, "10.0.0.1").
		WithUser(userID).
		WithActor(actorID).
		WithSession(sessionID).
		WithResource("user-123").
		WithUserAgent("TestAgent/1.0").
		WithMetadata("action_type", "update")

	assert.Equal(t, tenantID, log.TenantID)
	assert.Equal(t, userID, *log.UserID)
	assert.Equal(t, actorID, *log.ActorID)
	assert.Equal(t, sessionID, *log.SessionID)
	assert.Equal(t, "user-123", log.ResourceID)
	assert.Equal(t, "TestAgent/1.0", log.UserAgent)
	assert.Equal(t, "update", log.Metadata["action_type"])
}

// Test AuditAction constants
func TestAuditAction_Constants(t *testing.T) {
	tests := []struct {
		name     string
		action   AuditAction
		expected string
	}{
		{"Login", AuditActionLogin, "LOGIN"},
		{"LoginFailed", AuditActionLoginFailed, "LOGIN_FAILED"},
		{"Logout", AuditActionLogout, "LOGOUT"},
		{"TokenRefresh", AuditActionTokenRefresh, "TOKEN_REFRESH"},
		{"Register", AuditActionRegister, "REGISTER"},
		{"EmailVerify", AuditActionEmailVerify, "EMAIL_VERIFY"},
		{"PasswordChange", AuditActionPasswordChange, "PASSWORD_CHANGE"},
		{"PasswordReset", AuditActionPasswordReset, "PASSWORD_RESET"},
		{"MFAEnable", AuditActionMFAEnable, "MFA_ENABLE"},
		{"MFADisable", AuditActionMFADisable, "MFA_DISABLE"},
		{"SessionCreate", AuditActionSessionCreate, "SESSION_CREATE"},
		{"SessionRevoke", AuditActionSessionRevoke, "SESSION_REVOKE"},
		{"OAuthLink", AuditActionOAuthLink, "OAUTH_LINK"},
		{"OAuthUnlink", AuditActionOAuthUnlink, "OAUTH_UNLINK"},
		{"AccountLock", AuditActionAccountLock, "ACCOUNT_LOCK"},
		{"AccountUnlock", AuditActionAccountUnlock, "ACCOUNT_UNLOCK"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.action))
		})
	}
}

// Test AuditStatus constants
func TestAuditStatus_Constants(t *testing.T) {
	assert.Equal(t, "SUCCESS", string(AuditStatusSuccess))
	assert.Equal(t, "FAILURE", string(AuditStatusFailure))
}

// Test AuditResourceType constants
func TestAuditResourceType_Constants(t *testing.T) {
	assert.Equal(t, "USER", string(AuditResourceUser))
	assert.Equal(t, "SESSION", string(AuditResourceSession))
	assert.Equal(t, "OTP", string(AuditResourceOTP))
	assert.Equal(t, "OAUTH", string(AuditResourceOAuth))
	assert.Equal(t, "TENANT", string(AuditResourceTenant))
}
