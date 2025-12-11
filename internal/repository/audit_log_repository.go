package repository

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/guipguia/auth/internal/domain"
)

// AuditLogRepository handles database operations for audit logs
type AuditLogRepository interface {
	Create(log *domain.AuditLog) error
	CreateBatch(logs []*domain.AuditLog) error
	Query(filter AuditLogFilter) ([]domain.AuditLog, int64, error)
	GetByID(tenantID, id uuid.UUID) (*domain.AuditLog, error)
	DeleteOlderThan(tenantID uuid.UUID, before time.Time) (int64, error)
}

// AuditLogFilter defines filter options for querying audit logs
type AuditLogFilter struct {
	TenantID     uuid.UUID
	UserID       *uuid.UUID
	ActorID      *uuid.UUID
	Action       *domain.AuditAction
	ResourceType *domain.AuditResourceType
	ResourceID   *string
	Status       *domain.AuditStatus
	IPAddress    *string
	StartTime    *time.Time
	EndTime      *time.Time
	Limit        int
	Offset       int
}

type auditLogRepository struct {
	db *gorm.DB
}

// NewAuditLogRepository creates a new audit log repository
func NewAuditLogRepository(db *gorm.DB) AuditLogRepository {
	return &auditLogRepository{db: db}
}

// Create creates a new audit log entry
func (r *auditLogRepository) Create(log *domain.AuditLog) error {
	return r.db.Create(log).Error
}

// CreateBatch creates multiple audit log entries in a single transaction
func (r *auditLogRepository) CreateBatch(logs []*domain.AuditLog) error {
	if len(logs) == 0 {
		return nil
	}
	return r.db.CreateInBatches(logs, 100).Error
}

// Query retrieves audit logs with filtering and pagination
func (r *auditLogRepository) Query(filter AuditLogFilter) ([]domain.AuditLog, int64, error) {
	var logs []domain.AuditLog
	var total int64

	query := r.db.Model(&domain.AuditLog{}).Where("tenant_id = ?", filter.TenantID)

	// Apply filters
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.ActorID != nil {
		query = query.Where("actor_id = ?", *filter.ActorID)
	}
	if filter.Action != nil {
		query = query.Where("action = ?", *filter.Action)
	}
	if filter.ResourceType != nil {
		query = query.Where("resource_type = ?", *filter.ResourceType)
	}
	if filter.ResourceID != nil {
		query = query.Where("resource_id = ?", *filter.ResourceID)
	}
	if filter.Status != nil {
		query = query.Where("status = ?", *filter.Status)
	}
	if filter.IPAddress != nil {
		query = query.Where("ip_address = ?", *filter.IPAddress)
	}
	if filter.StartTime != nil {
		query = query.Where("created_at >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("created_at <= ?", *filter.EndTime)
	}

	// Get total count
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Apply pagination and ordering
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}

	err := query.Order("created_at DESC").
		Limit(filter.Limit).
		Offset(filter.Offset).
		Find(&logs).Error

	if err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

// GetByID retrieves a single audit log by ID
func (r *auditLogRepository) GetByID(tenantID, id uuid.UUID) (*domain.AuditLog, error) {
	var log domain.AuditLog
	err := r.db.Where("tenant_id = ? AND id = ?", tenantID, id).First(&log).Error
	if err != nil {
		return nil, err
	}
	return &log, nil
}

// DeleteOlderThan deletes audit logs older than the specified time
// This is used for retention policy enforcement
func (r *auditLogRepository) DeleteOlderThan(tenantID uuid.UUID, before time.Time) (int64, error) {
	result := r.db.Where("tenant_id = ? AND created_at < ?", tenantID, before).
		Delete(&domain.AuditLog{})
	return result.RowsAffected, result.Error
}
