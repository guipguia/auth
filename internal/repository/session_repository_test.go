package repository

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"github.com/guipguia/auth/internal/domain"
)

// Helper function to create a test user with tenant
func createTestUser(t *testing.T, db *gorm.DB) (*domain.User, uuid.UUID) {
	tenantID := uuid.New()
	userRepo := NewUserRepository(db, nil)
	user := &domain.User{
		TenantID:     tenantID,
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	err := userRepo.Create(user)
	assert.NoError(t, err)
	return user, tenantID
}

// Test: NewSessionRepository
func TestNewSessionRepository(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSessionRepository(db)

	assert.NotNil(t, repo)
}

// Test: Create Session
func TestSessionRepository_Create(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSessionRepository(db)
	user, tenantID := createTestUser(t, db)

	session := &domain.Session{
		TenantID:     tenantID,
		UserID:       user.ID,
		RefreshToken: "refresh-token-123",
		DeviceID:     "device-123",
		DeviceName:   "Chrome",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}

	err := repo.Create(session)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, session.ID)
}

// Test: GetByID Success
func TestSessionRepository_GetByID_Success(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSessionRepository(db)
	user, tenantID := createTestUser(t, db)

	session := &domain.Session{
		TenantID:     tenantID,
		UserID:       user.ID,
		RefreshToken: "refresh-token-123",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}
	err := repo.Create(session)
	assert.NoError(t, err)

	retrieved, err := repo.GetByID(tenantID, session.ID)

	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, session.RefreshToken, retrieved.RefreshToken)
}

// Test: GetByID Not Found
func TestSessionRepository_GetByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSessionRepository(db)

	tenantID := uuid.New()
	retrieved, err := repo.GetByID(tenantID, uuid.New())

	assert.Error(t, err)
	assert.Nil(t, retrieved)
	assert.Contains(t, err.Error(), "session not found")
}

// Test: GetByRefreshToken Success
func TestSessionRepository_GetByRefreshToken_Success(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSessionRepository(db)
	user, tenantID := createTestUser(t, db)

	session := &domain.Session{
		TenantID:     tenantID,
		UserID:       user.ID,
		RefreshToken: "refresh-token-123",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}
	err := repo.Create(session)
	assert.NoError(t, err)

	retrieved, err := repo.GetByRefreshToken(tenantID, "refresh-token-123")

	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, session.ID, retrieved.ID)
}

// Test: GetByRefreshToken Not Found
func TestSessionRepository_GetByRefreshToken_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSessionRepository(db)

	tenantID := uuid.New()
	retrieved, err := repo.GetByRefreshToken(tenantID, "nonexistent-token")

	assert.Error(t, err)
	assert.Nil(t, retrieved)
	assert.Contains(t, err.Error(), "session not found")
}

// Test: GetActiveSessions
func TestSessionRepository_GetActiveSessions(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSessionRepository(db)
	user, tenantID := createTestUser(t, db)

	// Create active sessions
	session1 := &domain.Session{
		TenantID:     tenantID,
		UserID:       user.ID,
		RefreshToken: "token-1",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}
	session2 := &domain.Session{
		TenantID:     tenantID,
		UserID:       user.ID,
		RefreshToken: "token-2",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}
	_ = repo.Create(session1)
	_ = repo.Create(session2)

	// Create expired session
	expiredSession := &domain.Session{
		TenantID:     tenantID,
		UserID:       user.ID,
		RefreshToken: "token-expired",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
	}
	_ = repo.Create(expiredSession)

	// Create revoked session
	revokedSession := &domain.Session{
		TenantID:     tenantID,
		UserID:       user.ID,
		RefreshToken: "token-revoked",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
		RevokedAt:    func() *time.Time { t := time.Now(); return &t }(),
	}
	_ = repo.Create(revokedSession)

	sessions, err := repo.GetActiveSessions(tenantID, user.ID)

	assert.NoError(t, err)
	assert.Len(t, sessions, 2)
}

// Test: Update Session
func TestSessionRepository_Update(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSessionRepository(db)
	user, tenantID := createTestUser(t, db)

	session := &domain.Session{
		TenantID:     tenantID,
		UserID:       user.ID,
		RefreshToken: "old-token",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}
	err := repo.Create(session)
	assert.NoError(t, err)

	session.RefreshToken = "new-token"
	err = repo.Update(session)

	assert.NoError(t, err)

	retrieved, _ := repo.GetByID(tenantID, session.ID)
	assert.Equal(t, "new-token", retrieved.RefreshToken)
}

// Test: Revoke Session
func TestSessionRepository_Revoke(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSessionRepository(db)
	user, tenantID := createTestUser(t, db)

	session := &domain.Session{
		TenantID:     tenantID,
		UserID:       user.ID,
		RefreshToken: "token-123",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}
	err := repo.Create(session)
	assert.NoError(t, err)

	err = repo.Revoke(tenantID, session.ID)

	assert.NoError(t, err)

	retrieved, _ := repo.GetByID(tenantID, session.ID)
	assert.NotNil(t, retrieved.RevokedAt)
}

// Test: RevokeAllUserSessions
func TestSessionRepository_RevokeAllUserSessions(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSessionRepository(db)
	user, tenantID := createTestUser(t, db)

	session1 := &domain.Session{
		TenantID:     tenantID,
		UserID:       user.ID,
		RefreshToken: "token-1",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}
	session2 := &domain.Session{
		TenantID:     tenantID,
		UserID:       user.ID,
		RefreshToken: "token-2",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}
	_ = repo.Create(session1)
	_ = repo.Create(session2)

	err := repo.RevokeAllUserSessions(tenantID, user.ID)

	assert.NoError(t, err)

	sessions, _ := repo.GetActiveSessions(tenantID, user.ID)
	assert.Len(t, sessions, 0)
}

// Test: DeleteExpired
func TestSessionRepository_DeleteExpired(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSessionRepository(db)
	user, tenantID := createTestUser(t, db)

	// Create expired session
	expiredSession := &domain.Session{
		TenantID:     tenantID,
		UserID:       user.ID,
		RefreshToken: "expired-token",
		ExpiresAt:    time.Now().Add(-7 * 24 * time.Hour),
	}
	_ = repo.Create(expiredSession)

	// Create active session
	activeSession := &domain.Session{
		TenantID:     tenantID,
		UserID:       user.ID,
		RefreshToken: "active-token",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}
	_ = repo.Create(activeSession)

	err := repo.DeleteExpired()

	assert.NoError(t, err)

	// Expired session should be deleted
	_, err = repo.GetByID(tenantID, expiredSession.ID)
	assert.Error(t, err)

	// Active session should still exist
	_, err = repo.GetByID(tenantID, activeSession.ID)
	assert.NoError(t, err)
}

// Test: UpdateLastAccessed
func TestSessionRepository_UpdateLastAccessed(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSessionRepository(db)
	user, tenantID := createTestUser(t, db)

	session := &domain.Session{
		TenantID:     tenantID,
		UserID:       user.ID,
		RefreshToken: "token-123",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}
	err := repo.Create(session)
	assert.NoError(t, err)

	originalTime := session.LastAccessedAt
	time.Sleep(10 * time.Millisecond)

	err = repo.UpdateLastAccessed(tenantID, session.ID)

	assert.NoError(t, err)

	retrieved, _ := repo.GetByID(tenantID, session.ID)
	assert.True(t, retrieved.LastAccessedAt.After(originalTime))
}
