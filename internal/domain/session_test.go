package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// Test: Session TableName
func TestSession_TableName(t *testing.T) {
	session := Session{}
	assert.Equal(t, "sessions", session.TableName())
}

// Test: Session IsActive - Active Session
func TestSession_IsActive_Active(t *testing.T) {
	session := &Session{
		ExpiresAt: time.Now().Add(1 * time.Hour),
		RevokedAt: nil,
	}

	assert.True(t, session.IsActive())
}

// Test: Session IsActive - Expired Session
func TestSession_IsActive_Expired(t *testing.T) {
	session := &Session{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		RevokedAt: nil,
	}

	assert.False(t, session.IsActive())
}

// Test: Session IsActive - Revoked Session
func TestSession_IsActive_Revoked(t *testing.T) {
	now := time.Now()
	session := &Session{
		ExpiresAt: time.Now().Add(1 * time.Hour),
		RevokedAt: &now,
	}

	assert.False(t, session.IsActive())
}

// Test: Session IsExpired - Not Expired
func TestSession_IsExpired_NotExpired(t *testing.T) {
	session := &Session{
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	assert.False(t, session.IsExpired())
}

// Test: Session IsExpired - Expired
func TestSession_IsExpired_Expired(t *testing.T) {
	session := &Session{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	assert.True(t, session.IsExpired())
}

// Test: Session Revoke
func TestSession_Revoke(t *testing.T) {
	session := &Session{
		ExpiresAt: time.Now().Add(1 * time.Hour),
		RevokedAt: nil,
	}

	assert.Nil(t, session.RevokedAt)
	assert.True(t, session.IsActive())

	session.Revoke()

	assert.NotNil(t, session.RevokedAt)
	assert.False(t, session.IsActive())
}

// Test: Session BeforeCreate - Generates UUID
func TestSession_BeforeCreate_GeneratesUUID(t *testing.T) {
	session := &Session{}

	assert.Equal(t, uuid.Nil, session.ID)

	err := session.BeforeCreate(nil)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, session.ID)
}

// Test: Session BeforeCreate - Preserves Existing UUID
func TestSession_BeforeCreate_PreservesUUID(t *testing.T) {
	existingID := uuid.New()
	session := &Session{
		ID: existingID,
	}

	err := session.BeforeCreate(nil)

	assert.NoError(t, err)
	assert.Equal(t, existingID, session.ID)
}
