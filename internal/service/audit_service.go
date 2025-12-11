package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/guipguia/auth/internal/domain"
	"github.com/guipguia/auth/internal/repository"
)

// AuditService handles audit logging for compliance
type AuditService interface {
	// Log creates a new audit log entry
	Log(ctx context.Context, log *domain.AuditLog) error

	// LogBatch creates multiple audit log entries
	LogBatch(ctx context.Context, logs []*domain.AuditLog) error

	// LogAction is a convenience method to log an action
	LogAction(ctx context.Context, tenantID uuid.UUID, action domain.AuditAction, resourceType domain.AuditResourceType, resourceID string, status domain.AuditStatus, details map[string]interface{}) error

	// LogUserAction logs an action performed by/on a user
	LogUserAction(ctx context.Context, tenantID, userID uuid.UUID, actorID *uuid.UUID, action domain.AuditAction, status domain.AuditStatus, details map[string]interface{}) error

	// LogSessionAction logs a session-related action
	LogSessionAction(ctx context.Context, tenantID, sessionID uuid.UUID, userID uuid.UUID, action domain.AuditAction, status domain.AuditStatus, details map[string]interface{}) error

	// Query retrieves audit logs with filtering
	Query(ctx context.Context, filter repository.AuditLogFilter) ([]domain.AuditLog, int64, error)
}

type auditService struct {
	auditRepo repository.AuditLogRepository
}

// NewAuditService creates a new audit service
func NewAuditService(auditRepo repository.AuditLogRepository) AuditService {
	return &auditService{
		auditRepo: auditRepo,
	}
}

// Log creates a new audit log entry
func (s *auditService) Log(ctx context.Context, log *domain.AuditLog) error {
	// Enrich with context information if not already set
	if log.IPAddress == "" {
		log.IPAddress = IPAddressFromContext(ctx)
	}
	if log.UserAgent == "" {
		log.UserAgent = UserAgentFromContext(ctx)
	}

	return s.auditRepo.Create(log)
}

// LogBatch creates multiple audit log entries
func (s *auditService) LogBatch(ctx context.Context, logs []*domain.AuditLog) error {
	// Enrich all logs with context information
	ip := IPAddressFromContext(ctx)
	ua := UserAgentFromContext(ctx)

	for _, log := range logs {
		if log.IPAddress == "" {
			log.IPAddress = ip
		}
		if log.UserAgent == "" {
			log.UserAgent = ua
		}
	}

	return s.auditRepo.CreateBatch(logs)
}

// LogAction is a convenience method to log an action
func (s *auditService) LogAction(ctx context.Context, tenantID uuid.UUID, action domain.AuditAction, resourceType domain.AuditResourceType, resourceID string, status domain.AuditStatus, details map[string]interface{}) error {
	log := domain.NewAuditLog(tenantID, action, resourceType, status, IPAddressFromContext(ctx)).
		WithResource(resourceID).
		WithUserAgent(UserAgentFromContext(ctx))

	// Add details as metadata
	for k, v := range details {
		log.WithMetadata(k, v)
	}

	return s.auditRepo.Create(log)
}

// LogUserAction logs an action performed by/on a user
func (s *auditService) LogUserAction(ctx context.Context, tenantID, userID uuid.UUID, actorID *uuid.UUID, action domain.AuditAction, status domain.AuditStatus, details map[string]interface{}) error {
	log := domain.NewAuditLog(tenantID, action, domain.AuditResourceUser, status, IPAddressFromContext(ctx)).
		WithUser(userID).
		WithResource(userID.String()).
		WithUserAgent(UserAgentFromContext(ctx))

	if actorID != nil {
		log.WithActor(*actorID)
	}

	// Add details as metadata
	for k, v := range details {
		log.WithMetadata(k, v)
	}

	return s.auditRepo.Create(log)
}

// LogSessionAction logs a session-related action
func (s *auditService) LogSessionAction(ctx context.Context, tenantID, sessionID uuid.UUID, userID uuid.UUID, action domain.AuditAction, status domain.AuditStatus, details map[string]interface{}) error {
	log := domain.NewAuditLog(tenantID, action, domain.AuditResourceSession, status, IPAddressFromContext(ctx)).
		WithUser(userID).
		WithResource(sessionID.String()).
		WithSession(sessionID).
		WithUserAgent(UserAgentFromContext(ctx))

	// Add details as metadata
	for k, v := range details {
		log.WithMetadata(k, v)
	}

	return s.auditRepo.Create(log)
}

// Query retrieves audit logs with filtering
func (s *auditService) Query(ctx context.Context, filter repository.AuditLogFilter) ([]domain.AuditLog, int64, error) {
	return s.auditRepo.Query(filter)
}
