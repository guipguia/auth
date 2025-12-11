package repository

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/guipguia/auth/internal/domain"
	"gorm.io/gorm"
)

// CacheService defines the interface for caching operations
type CacheService interface {
	Get(key string) (interface{}, bool)
	Set(key string, value interface{})
	SetWithTTL(key string, value interface{}, ttl time.Duration)
	Delete(key string)
	Clear()
	Close() error
}

// cachedSessionRepository wraps SessionRepository with caching
type cachedSessionRepository struct {
	repo  SessionRepository
	cache CacheService
	ttl   time.Duration
}

// NewCachedSessionRepository creates a new cached session repository
func NewCachedSessionRepository(db *gorm.DB, cache CacheService, ttlSeconds int) SessionRepository {
	return &cachedSessionRepository{
		repo:  NewSessionRepository(db),
		cache: cache,
		ttl:   time.Duration(ttlSeconds) * time.Second,
	}
}

// sessionCacheKey generates a cache key for a session by ID
func sessionCacheKey(tenantID, id uuid.UUID) string {
	return fmt.Sprintf("auth:session:tenant:%s:id:%s", tenantID.String(), id.String())
}

// sessionRefreshTokenCacheKey generates a cache key for a session by refresh token
func sessionRefreshTokenCacheKey(tenantID uuid.UUID, token string) string {
	return fmt.Sprintf("auth:session:tenant:%s:refresh:%s", tenantID.String(), token)
}

// userSessionsCacheKey generates a cache key for user's active sessions
func userSessionsCacheKey(tenantID, userID uuid.UUID) string {
	return fmt.Sprintf("auth:session:tenant:%s:user:%s", tenantID.String(), userID.String())
}

// Create creates a new session and invalidates relevant caches
func (r *cachedSessionRepository) Create(session *domain.Session) error {
	err := r.repo.Create(session)
	if err != nil {
		return err
	}

	// Cache the new session
	r.cacheSession(session)

	// Invalidate user's active sessions cache
	r.cache.Delete(userSessionsCacheKey(session.TenantID, session.UserID))

	return nil
}

// GetByID retrieves a session by ID with caching
func (r *cachedSessionRepository) GetByID(tenantID, id uuid.UUID) (*domain.Session, error) {
	cacheKey := sessionCacheKey(tenantID, id)

	// Try cache first
	if cached, ok := r.cache.Get(cacheKey); ok {
		if session := r.unmarshalSession(cached); session != nil {
			return session, nil
		}
	}

	// Cache miss - get from database
	session, err := r.repo.GetByID(tenantID, id)
	if err != nil {
		return nil, err
	}

	// Cache the result
	r.cacheSession(session)

	return session, nil
}

// GetByRefreshToken retrieves a session by refresh token with caching
func (r *cachedSessionRepository) GetByRefreshToken(tenantID uuid.UUID, token string) (*domain.Session, error) {
	cacheKey := sessionRefreshTokenCacheKey(tenantID, token)

	// Try cache first
	if cached, ok := r.cache.Get(cacheKey); ok {
		if session := r.unmarshalSession(cached); session != nil {
			return session, nil
		}
	}

	// Cache miss - get from database
	session, err := r.repo.GetByRefreshToken(tenantID, token)
	if err != nil {
		return nil, err
	}

	// Cache the result
	r.cacheSession(session)

	return session, nil
}

// GetActiveSessions retrieves all active sessions for a user with caching
func (r *cachedSessionRepository) GetActiveSessions(tenantID, userID uuid.UUID) ([]domain.Session, error) {
	cacheKey := userSessionsCacheKey(tenantID, userID)

	// Try cache first
	if cached, ok := r.cache.Get(cacheKey); ok {
		if sessions := r.unmarshalSessions(cached); sessions != nil {
			return sessions, nil
		}
	}

	// Cache miss - get from database
	sessions, err := r.repo.GetActiveSessions(tenantID, userID)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if data, err := json.Marshal(sessions); err == nil {
		r.cache.SetWithTTL(cacheKey, string(data), r.ttl)
	}

	return sessions, nil
}

// CountActiveSessions counts active sessions for a user within a tenant
func (r *cachedSessionRepository) CountActiveSessions(tenantID, userID uuid.UUID) (int64, error) {
	// This doesn't need caching as it's typically used for enforcement
	return r.repo.CountActiveSessions(tenantID, userID)
}

// Update updates a session and invalidates caches
func (r *cachedSessionRepository) Update(session *domain.Session) error {
	err := r.repo.Update(session)
	if err != nil {
		return err
	}

	// Update cache
	r.cacheSession(session)

	// Invalidate user's active sessions cache
	r.cache.Delete(userSessionsCacheKey(session.TenantID, session.UserID))

	return nil
}

// Revoke revokes a session and invalidates caches
func (r *cachedSessionRepository) Revoke(tenantID, sessionID uuid.UUID) error {
	// Get session first to know which caches to invalidate
	session, err := r.repo.GetByID(tenantID, sessionID)
	if err != nil {
		return err
	}

	err = r.repo.Revoke(tenantID, sessionID)
	if err != nil {
		return err
	}

	// Invalidate all caches for this session
	r.invalidateSessionCache(session)

	return nil
}

// RevokeAllUserSessions revokes all sessions for a user within a tenant
func (r *cachedSessionRepository) RevokeAllUserSessions(tenantID, userID uuid.UUID) error {
	// Get all sessions first to invalidate their caches
	sessions, _ := r.repo.GetActiveSessions(tenantID, userID)

	err := r.repo.RevokeAllUserSessions(tenantID, userID)
	if err != nil {
		return err
	}

	// Invalidate all session caches
	for _, session := range sessions {
		r.invalidateSessionCache(&session)
	}

	return nil
}

// DeleteExpired deletes expired sessions
func (r *cachedSessionRepository) DeleteExpired() error {
	return r.repo.DeleteExpired()
}

// UpdateLastAccessed updates the last accessed timestamp within a tenant
func (r *cachedSessionRepository) UpdateLastAccessed(tenantID, sessionID uuid.UUID) error {
	err := r.repo.UpdateLastAccessed(tenantID, sessionID)
	if err != nil {
		return err
	}

	// Invalidate session cache to force refresh on next access
	r.cache.Delete(sessionCacheKey(tenantID, sessionID))

	return nil
}

// UpdateIdleTimeout updates the idle timeout for a session
func (r *cachedSessionRepository) UpdateIdleTimeout(tenantID, sessionID uuid.UUID, timeout time.Time) error {
	err := r.repo.UpdateIdleTimeout(tenantID, sessionID, timeout)
	if err != nil {
		return err
	}

	// Invalidate session cache to force refresh on next access
	r.cache.Delete(sessionCacheKey(tenantID, sessionID))

	return nil
}

// GetIdleTimedOutSessions retrieves sessions that have exceeded idle timeout
func (r *cachedSessionRepository) GetIdleTimedOutSessions(tenantID uuid.UUID) ([]domain.Session, error) {
	// This doesn't need caching as it's typically used for maintenance
	return r.repo.GetIdleTimedOutSessions(tenantID)
}

// RevokeIdleTimedOut revokes sessions that have exceeded idle timeout
func (r *cachedSessionRepository) RevokeIdleTimedOut(tenantID uuid.UUID) (int64, error) {
	return r.repo.RevokeIdleTimedOut(tenantID)
}

// cacheSession caches a session under multiple keys
func (r *cachedSessionRepository) cacheSession(session *domain.Session) {
	data, err := json.Marshal(session)
	if err != nil {
		return
	}

	// Calculate TTL based on session expiry
	ttl := r.ttl
	if time.Until(session.ExpiresAt) < ttl {
		ttl = time.Until(session.ExpiresAt)
	}

	if ttl > 0 {
		r.cache.SetWithTTL(sessionCacheKey(session.TenantID, session.ID), string(data), ttl)
		r.cache.SetWithTTL(sessionRefreshTokenCacheKey(session.TenantID, session.RefreshToken), string(data), ttl)
	}
}

// invalidateSessionCache removes all cache entries for a session
func (r *cachedSessionRepository) invalidateSessionCache(session *domain.Session) {
	r.cache.Delete(sessionCacheKey(session.TenantID, session.ID))
	r.cache.Delete(sessionRefreshTokenCacheKey(session.TenantID, session.RefreshToken))
	r.cache.Delete(userSessionsCacheKey(session.TenantID, session.UserID))
}

// unmarshalSession unmarshals a cached session
func (r *cachedSessionRepository) unmarshalSession(cached interface{}) *domain.Session {
	str, ok := cached.(string)
	if !ok {
		return nil
	}

	var session domain.Session
	if err := json.Unmarshal([]byte(str), &session); err != nil {
		return nil
	}

	// Check if session is still active
	if !session.IsActive() {
		return nil
	}

	return &session
}

// unmarshalSessions unmarshals cached sessions
func (r *cachedSessionRepository) unmarshalSessions(cached interface{}) []domain.Session {
	str, ok := cached.(string)
	if !ok {
		return nil
	}

	var sessions []domain.Session
	if err := json.Unmarshal([]byte(str), &sessions); err != nil {
		return nil
	}

	return sessions
}
