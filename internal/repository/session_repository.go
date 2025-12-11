package repository

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/guipguia/auth/internal/domain"
	"gorm.io/gorm"
)

// SessionRepository handles database operations for sessions
type SessionRepository interface {
	Create(session *domain.Session) error
	GetByID(tenantID, id uuid.UUID) (*domain.Session, error)
	GetByRefreshToken(tenantID uuid.UUID, token string) (*domain.Session, error)
	GetActiveSessions(tenantID, userID uuid.UUID) ([]domain.Session, error)
	CountActiveSessions(tenantID, userID uuid.UUID) (int64, error)
	Update(session *domain.Session) error
	Revoke(tenantID, sessionID uuid.UUID) error
	RevokeAllUserSessions(tenantID, userID uuid.UUID) error
	DeleteExpired() error
	UpdateLastAccessed(tenantID, sessionID uuid.UUID) error
	// Compliance methods
	UpdateIdleTimeout(tenantID, sessionID uuid.UUID, timeout time.Time) error
	GetIdleTimedOutSessions(tenantID uuid.UUID) ([]domain.Session, error)
	RevokeIdleTimedOut(tenantID uuid.UUID) (int64, error)
}

type sessionRepository struct {
	db *gorm.DB
}

// NewSessionRepository creates a new session repository
func NewSessionRepository(db *gorm.DB) SessionRepository {
	return &sessionRepository{db: db}
}

// Create creates a new session
func (r *sessionRepository) Create(session *domain.Session) error {
	return r.db.Create(session).Error
}

// GetByID retrieves a session by ID within a tenant
func (r *sessionRepository) GetByID(tenantID, id uuid.UUID) (*domain.Session, error) {
	var session domain.Session
	err := r.db.First(&session, "tenant_id = ? AND id = ?", tenantID, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("session not found")
		}
		return nil, err
	}
	return &session, nil
}

// GetByRefreshToken retrieves a session by refresh token within a tenant
func (r *sessionRepository) GetByRefreshToken(tenantID uuid.UUID, token string) (*domain.Session, error) {
	var session domain.Session
	err := r.db.First(&session, "tenant_id = ? AND refresh_token = ?", tenantID, token).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("session not found")
		}
		return nil, err
	}
	return &session, nil
}

// GetActiveSessions retrieves all active sessions for a user within a tenant
func (r *sessionRepository) GetActiveSessions(tenantID, userID uuid.UUID) ([]domain.Session, error) {
	var sessions []domain.Session
	now := time.Now()
	err := r.db.Where("tenant_id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?", tenantID, userID, now).
		Order("last_accessed_at DESC").
		Find(&sessions).Error
	return sessions, err
}

// CountActiveSessions counts active sessions for a user within a tenant
func (r *sessionRepository) CountActiveSessions(tenantID, userID uuid.UUID) (int64, error) {
	var count int64
	now := time.Now()
	err := r.db.Model(&domain.Session{}).
		Where("tenant_id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?", tenantID, userID, now).
		Count(&count).Error
	return count, err
}

// Update updates a session
func (r *sessionRepository) Update(session *domain.Session) error {
	return r.db.Save(session).Error
}

// Revoke revokes a session within a tenant
func (r *sessionRepository) Revoke(tenantID, sessionID uuid.UUID) error {
	now := time.Now()
	result := r.db.Model(&domain.Session{}).
		Where("tenant_id = ? AND id = ? AND revoked_at IS NULL", tenantID, sessionID).
		Update("revoked_at", now)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("session not found or already revoked")
	}

	return nil
}

// RevokeAllUserSessions revokes all sessions for a user within a tenant
func (r *sessionRepository) RevokeAllUserSessions(tenantID, userID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&domain.Session{}).
		Where("tenant_id = ? AND user_id = ? AND revoked_at IS NULL", tenantID, userID).
		Update("revoked_at", now).Error
}

// DeleteExpired deletes expired sessions (across all tenants - maintenance task)
func (r *sessionRepository) DeleteExpired() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&domain.Session{}).Error
}

// UpdateLastAccessed updates the last accessed timestamp within a tenant
func (r *sessionRepository) UpdateLastAccessed(tenantID, sessionID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&domain.Session{}).
		Where("tenant_id = ? AND id = ?", tenantID, sessionID).
		Update("last_accessed_at", now).Error
}

// UpdateIdleTimeout updates the idle timeout for a session
func (r *sessionRepository) UpdateIdleTimeout(tenantID, sessionID uuid.UUID, timeout time.Time) error {
	return r.db.Model(&domain.Session{}).
		Where("tenant_id = ? AND id = ?", tenantID, sessionID).
		Update("idle_timeout_at", timeout).Error
}

// GetIdleTimedOutSessions retrieves sessions that have exceeded idle timeout
func (r *sessionRepository) GetIdleTimedOutSessions(tenantID uuid.UUID) ([]domain.Session, error) {
	var sessions []domain.Session
	now := time.Now()
	err := r.db.Where("tenant_id = ? AND revoked_at IS NULL AND idle_timeout_at IS NOT NULL AND idle_timeout_at < ?", tenantID, now).
		Find(&sessions).Error
	return sessions, err
}

// RevokeIdleTimedOut revokes sessions that have exceeded idle timeout
func (r *sessionRepository) RevokeIdleTimedOut(tenantID uuid.UUID) (int64, error) {
	now := time.Now()
	result := r.db.Model(&domain.Session{}).
		Where("tenant_id = ? AND revoked_at IS NULL AND idle_timeout_at IS NOT NULL AND idle_timeout_at < ?", tenantID, now).
		Update("revoked_at", now)
	return result.RowsAffected, result.Error
}
