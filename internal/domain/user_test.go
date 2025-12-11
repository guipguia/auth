package domain

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// Test: User TableName
func TestUser_TableName(t *testing.T) {
	user := User{}
	assert.Equal(t, "users", user.TableName())
}

// Test: User BeforeCreate - Generates UUID
func TestUser_BeforeCreate_GeneratesUUID(t *testing.T) {
	user := &User{}

	assert.Equal(t, uuid.Nil, user.ID)

	err := user.BeforeCreate(nil)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, user.ID)
}

// Test: User BeforeCreate - Preserves Existing UUID
func TestUser_BeforeCreate_PreservesUUID(t *testing.T) {
	existingID := uuid.New()
	user := &User{
		ID: existingID,
	}

	err := user.BeforeCreate(nil)

	assert.NoError(t, err)
	assert.Equal(t, existingID, user.ID)
}

// Test: BackupCode TableName
func TestBackupCode_TableName(t *testing.T) {
	code := BackupCode{}
	assert.Equal(t, "backup_codes", code.TableName())
}

// Test: OAuthAccount TableName
func TestOAuthAccount_TableName(t *testing.T) {
	account := OAuthAccount{}
	assert.Equal(t, "oauth_accounts", account.TableName())
}
