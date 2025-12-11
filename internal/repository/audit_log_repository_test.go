package repository

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guipguia/auth/internal/domain"
)

func TestAuditLogRepository_Create(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenantID := uuid.New()
	userID := uuid.New()

	log := &domain.AuditLog{
		TenantID:  tenantID,
		UserID:    &userID,
		Action:    domain.AuditActionLogin,
		Status:    domain.AuditStatusSuccess,
		IPAddress: "192.168.1.100",
		UserAgent: "TestAgent/1.0",
	}

	err := repo.Create(log)
	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, log.ID)
}

func TestAuditLogRepository_CreateBatch(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenantID := uuid.New()

	logs := []*domain.AuditLog{
		{
			TenantID:  tenantID,
			Action:    domain.AuditActionLogin,
			Status:    domain.AuditStatusSuccess,
			IPAddress: "10.0.0.1",
		},
		{
			TenantID:  tenantID,
			Action:    domain.AuditActionLogout,
			Status:    domain.AuditStatusSuccess,
			IPAddress: "10.0.0.2",
		},
		{
			TenantID:  tenantID,
			Action:    domain.AuditActionPasswordChange,
			Status:    domain.AuditStatusSuccess,
			IPAddress: "10.0.0.3",
		},
	}

	err := repo.CreateBatch(logs)
	assert.NoError(t, err)
	for _, log := range logs {
		assert.NotEqual(t, uuid.Nil, log.ID)
	}
}

func TestAuditLogRepository_CreateBatch_Empty(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	err := repo.CreateBatch([]*domain.AuditLog{})
	assert.NoError(t, err)
}

func TestAuditLogRepository_GetByID(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenantID := uuid.New()

	log := &domain.AuditLog{
		TenantID:  tenantID,
		Action:    domain.AuditActionLogin,
		Status:    domain.AuditStatusSuccess,
		IPAddress: "192.168.1.1",
	}
	require.NoError(t, repo.Create(log))

	retrieved, err := repo.GetByID(tenantID, log.ID)
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, log.ID, retrieved.ID)
	assert.Equal(t, domain.AuditActionLogin, retrieved.Action)
}

func TestAuditLogRepository_GetByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenantID := uuid.New()

	_, err := repo.GetByID(tenantID, uuid.New())
	assert.Error(t, err)
}

func TestAuditLogRepository_Query_Basic(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenantID := uuid.New()

	// Create multiple logs
	for i := 0; i < 5; i++ {
		log := &domain.AuditLog{
			TenantID:  tenantID,
			Action:    domain.AuditActionLogin,
			Status:    domain.AuditStatusSuccess,
			IPAddress: "10.0.0.1",
		}
		require.NoError(t, repo.Create(log))
	}

	filter := AuditLogFilter{
		TenantID: tenantID,
	}

	logs, total, err := repo.Query(filter)
	assert.NoError(t, err)
	assert.Len(t, logs, 5)
	assert.Equal(t, int64(5), total)
}

func TestAuditLogRepository_Query_ByUserID(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenantID := uuid.New()
	userID := uuid.New()
	otherUserID := uuid.New()

	// Create logs for different users
	log1 := &domain.AuditLog{
		TenantID:  tenantID,
		UserID:    &userID,
		Action:    domain.AuditActionLogin,
		Status:    domain.AuditStatusSuccess,
		IPAddress: "10.0.0.1",
	}
	require.NoError(t, repo.Create(log1))

	log2 := &domain.AuditLog{
		TenantID:  tenantID,
		UserID:    &otherUserID,
		Action:    domain.AuditActionLogin,
		Status:    domain.AuditStatusSuccess,
		IPAddress: "10.0.0.2",
	}
	require.NoError(t, repo.Create(log2))

	filter := AuditLogFilter{
		TenantID: tenantID,
		UserID:   &userID,
	}

	logs, total, err := repo.Query(filter)
	assert.NoError(t, err)
	assert.Len(t, logs, 1)
	assert.Equal(t, int64(1), total)
}

func TestAuditLogRepository_Query_ByAction(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenantID := uuid.New()

	// Create logs with different actions
	log1 := &domain.AuditLog{
		TenantID:  tenantID,
		Action:    domain.AuditActionLogin,
		Status:    domain.AuditStatusSuccess,
		IPAddress: "10.0.0.1",
	}
	require.NoError(t, repo.Create(log1))

	log2 := &domain.AuditLog{
		TenantID:  tenantID,
		Action:    domain.AuditActionLogout,
		Status:    domain.AuditStatusSuccess,
		IPAddress: "10.0.0.2",
	}
	require.NoError(t, repo.Create(log2))

	action := domain.AuditActionLogin
	filter := AuditLogFilter{
		TenantID: tenantID,
		Action:   &action,
	}

	logs, total, err := repo.Query(filter)
	assert.NoError(t, err)
	assert.Len(t, logs, 1)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, domain.AuditActionLogin, logs[0].Action)
}

func TestAuditLogRepository_Query_ByStatus(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenantID := uuid.New()

	// Create logs with different statuses
	log1 := &domain.AuditLog{
		TenantID:  tenantID,
		Action:    domain.AuditActionLogin,
		Status:    domain.AuditStatusSuccess,
		IPAddress: "10.0.0.1",
	}
	require.NoError(t, repo.Create(log1))

	log2 := &domain.AuditLog{
		TenantID:  tenantID,
		Action:    domain.AuditActionLogin,
		Status:    domain.AuditStatusFailure,
		IPAddress: "10.0.0.2",
	}
	require.NoError(t, repo.Create(log2))

	status := domain.AuditStatusFailure
	filter := AuditLogFilter{
		TenantID: tenantID,
		Status:   &status,
	}

	logs, total, err := repo.Query(filter)
	assert.NoError(t, err)
	assert.Len(t, logs, 1)
	assert.Equal(t, int64(1), total)
}

func TestAuditLogRepository_Query_ByIPAddress(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenantID := uuid.New()

	log1 := &domain.AuditLog{
		TenantID:  tenantID,
		Action:    domain.AuditActionLogin,
		Status:    domain.AuditStatusSuccess,
		IPAddress: "192.168.1.100",
	}
	require.NoError(t, repo.Create(log1))

	log2 := &domain.AuditLog{
		TenantID:  tenantID,
		Action:    domain.AuditActionLogin,
		Status:    domain.AuditStatusSuccess,
		IPAddress: "10.0.0.1",
	}
	require.NoError(t, repo.Create(log2))

	ip := "192.168.1.100"
	filter := AuditLogFilter{
		TenantID:  tenantID,
		IPAddress: &ip,
	}

	logs, total, err := repo.Query(filter)
	assert.NoError(t, err)
	assert.Len(t, logs, 1)
	assert.Equal(t, int64(1), total)
}

func TestAuditLogRepository_Query_ByTimeRange(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenantID := uuid.New()

	log := &domain.AuditLog{
		TenantID:  tenantID,
		Action:    domain.AuditActionLogin,
		Status:    domain.AuditStatusSuccess,
		IPAddress: "10.0.0.1",
	}
	require.NoError(t, repo.Create(log))

	now := time.Now()
	startTime := now.Add(-1 * time.Minute)
	endTime := now.Add(1 * time.Minute)

	filter := AuditLogFilter{
		TenantID:  tenantID,
		StartTime: &startTime,
		EndTime:   &endTime,
	}

	logs, total, err := repo.Query(filter)
	assert.NoError(t, err)
	assert.Len(t, logs, 1)
	assert.Equal(t, int64(1), total)
}

func TestAuditLogRepository_Query_WithPagination(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenantID := uuid.New()

	// Create 15 logs
	for i := 0; i < 15; i++ {
		log := &domain.AuditLog{
			TenantID:  tenantID,
			Action:    domain.AuditActionLogin,
			Status:    domain.AuditStatusSuccess,
			IPAddress: "10.0.0.1",
		}
		require.NoError(t, repo.Create(log))
	}

	// First page
	filter := AuditLogFilter{
		TenantID: tenantID,
		Limit:    10,
		Offset:   0,
	}

	logs, total, err := repo.Query(filter)
	assert.NoError(t, err)
	assert.Len(t, logs, 10)
	assert.Equal(t, int64(15), total)

	// Second page
	filter.Offset = 10
	logs, total, err = repo.Query(filter)
	assert.NoError(t, err)
	assert.Len(t, logs, 5)
	assert.Equal(t, int64(15), total)
}

func TestAuditLogRepository_Query_LimitConstraints(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenantID := uuid.New()

	// Create some logs
	for i := 0; i < 5; i++ {
		log := &domain.AuditLog{
			TenantID:  tenantID,
			Action:    domain.AuditActionLogin,
			Status:    domain.AuditStatusSuccess,
			IPAddress: "10.0.0.1",
		}
		require.NoError(t, repo.Create(log))
	}

	// Test default limit (0 should become 100)
	filter := AuditLogFilter{
		TenantID: tenantID,
		Limit:    0,
	}

	logs, _, err := repo.Query(filter)
	assert.NoError(t, err)
	assert.Len(t, logs, 5)

	// Test max limit constraint (over 1000 should become 1000)
	filter.Limit = 2000
	logs, _, err = repo.Query(filter)
	assert.NoError(t, err)
	assert.Len(t, logs, 5)
}

func TestAuditLogRepository_DeleteOlderThan(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenantID := uuid.New()

	// Create some logs
	for i := 0; i < 5; i++ {
		log := &domain.AuditLog{
			TenantID:  tenantID,
			Action:    domain.AuditActionLogin,
			Status:    domain.AuditStatusSuccess,
			IPAddress: "10.0.0.1",
		}
		require.NoError(t, repo.Create(log))
	}

	// Delete logs older than future time (should delete all)
	futureTime := time.Now().Add(1 * time.Hour)
	deleted, err := repo.DeleteOlderThan(tenantID, futureTime)
	assert.NoError(t, err)
	assert.Equal(t, int64(5), deleted)

	// Verify all logs are deleted
	filter := AuditLogFilter{TenantID: tenantID}
	logs, total, err := repo.Query(filter)
	assert.NoError(t, err)
	assert.Empty(t, logs)
	assert.Equal(t, int64(0), total)
}

func TestAuditLogRepository_TenantIsolation(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenant1ID := uuid.New()
	tenant2ID := uuid.New()

	// Create log in tenant1
	log1 := &domain.AuditLog{
		TenantID:  tenant1ID,
		Action:    domain.AuditActionLogin,
		Status:    domain.AuditStatusSuccess,
		IPAddress: "10.0.0.1",
	}
	require.NoError(t, repo.Create(log1))

	// Create log in tenant2
	log2 := &domain.AuditLog{
		TenantID:  tenant2ID,
		Action:    domain.AuditActionLogin,
		Status:    domain.AuditStatusSuccess,
		IPAddress: "10.0.0.2",
	}
	require.NoError(t, repo.Create(log2))

	// Query tenant1 should only return tenant1's log
	filter := AuditLogFilter{TenantID: tenant1ID}
	logs, total, err := repo.Query(filter)
	assert.NoError(t, err)
	assert.Len(t, logs, 1)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, tenant1ID, logs[0].TenantID)
}

func TestAuditLogRepository_Query_ByResourceType(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenantID := uuid.New()

	log1 := &domain.AuditLog{
		TenantID:     tenantID,
		Action:       domain.AuditActionLogin,
		Status:       domain.AuditStatusSuccess,
		IPAddress:    "10.0.0.1",
		ResourceType: domain.AuditResourceSession,
	}
	require.NoError(t, repo.Create(log1))

	log2 := &domain.AuditLog{
		TenantID:     tenantID,
		Action:       domain.AuditActionPasswordChange,
		Status:       domain.AuditStatusSuccess,
		IPAddress:    "10.0.0.2",
		ResourceType: domain.AuditResourceUser,
	}
	require.NoError(t, repo.Create(log2))

	resourceType := domain.AuditResourceSession
	filter := AuditLogFilter{
		TenantID:     tenantID,
		ResourceType: &resourceType,
	}

	logs, total, err := repo.Query(filter)
	assert.NoError(t, err)
	assert.Len(t, logs, 1)
	assert.Equal(t, int64(1), total)
}

func TestAuditLogRepository_Query_ByResourceID(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAuditLogRepository(db)

	tenantID := uuid.New()
	resourceID1 := uuid.New().String()
	resourceID2 := uuid.New().String()

	log1 := &domain.AuditLog{
		TenantID:   tenantID,
		Action:     domain.AuditActionLogin,
		Status:     domain.AuditStatusSuccess,
		IPAddress:  "10.0.0.1",
		ResourceID: resourceID1,
	}
	require.NoError(t, repo.Create(log1))

	log2 := &domain.AuditLog{
		TenantID:   tenantID,
		Action:     domain.AuditActionLogin,
		Status:     domain.AuditStatusSuccess,
		IPAddress:  "10.0.0.2",
		ResourceID: resourceID2,
	}
	require.NoError(t, repo.Create(log2))

	filter := AuditLogFilter{
		TenantID:   tenantID,
		ResourceID: &resourceID1,
	}

	logs, total, err := repo.Query(filter)
	assert.NoError(t, err)
	assert.Len(t, logs, 1)
	assert.Equal(t, int64(1), total)
}
