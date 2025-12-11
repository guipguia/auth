package repository

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/guipguia/auth/internal/domain"
	"gorm.io/gorm"
)

// MembershipRepository handles database operations for tenant memberships and invitations
type MembershipRepository interface {
	// Membership operations
	CreateMembership(membership *domain.TenantMembership) error
	GetMembershipByID(tenantID, membershipID uuid.UUID) (*domain.TenantMembership, error)
	GetMembershipByUserID(tenantID, userID uuid.UUID) (*domain.TenantMembership, error)
	ListMembershipsByTenant(tenantID uuid.UUID, limit, offset int) ([]domain.TenantMembership, int64, error)
	UpdateMembershipRole(tenantID, userID uuid.UUID, role domain.MemberRole) error
	DeleteMembership(tenantID, userID uuid.UUID) error
	CountMembersByRole(tenantID uuid.UUID, role domain.MemberRole) (int64, error)

	// Invitation operations
	CreateInvitation(invitation *domain.TenantInvitation) error
	GetInvitationByID(invitationID uuid.UUID) (*domain.TenantInvitation, error)
	GetInvitationByToken(token string) (*domain.TenantInvitation, error)
	GetInvitationByEmail(tenantID uuid.UUID, email string) (*domain.TenantInvitation, error)
	ListPendingInvitations(tenantID uuid.UUID) ([]domain.TenantInvitation, error)
	MarkInvitationAccepted(invitationID uuid.UUID) error
	DeleteInvitation(invitationID uuid.UUID) error
	DeleteExpiredInvitations() error
}

type membershipRepository struct {
	db *gorm.DB
}

// NewMembershipRepository creates a new membership repository
func NewMembershipRepository(db *gorm.DB) MembershipRepository {
	return &membershipRepository{db: db}
}

// CreateMembership creates a new tenant membership
func (r *membershipRepository) CreateMembership(membership *domain.TenantMembership) error {
	return r.db.Create(membership).Error
}

// GetMembershipByID retrieves a membership by ID within a tenant
func (r *membershipRepository) GetMembershipByID(tenantID, membershipID uuid.UUID) (*domain.TenantMembership, error) {
	var membership domain.TenantMembership
	err := r.db.Preload("User").
		First(&membership, "tenant_id = ? AND id = ?", tenantID, membershipID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("membership not found")
		}
		return nil, err
	}
	return &membership, nil
}

// GetMembershipByUserID retrieves a membership by user ID within a tenant
func (r *membershipRepository) GetMembershipByUserID(tenantID, userID uuid.UUID) (*domain.TenantMembership, error) {
	var membership domain.TenantMembership
	err := r.db.Preload("User").
		First(&membership, "tenant_id = ? AND user_id = ?", tenantID, userID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("membership not found")
		}
		return nil, err
	}
	return &membership, nil
}

// ListMembershipsByTenant retrieves all memberships for a tenant with pagination
func (r *membershipRepository) ListMembershipsByTenant(tenantID uuid.UUID, limit, offset int) ([]domain.TenantMembership, int64, error) {
	var memberships []domain.TenantMembership
	var total int64

	// Get total count
	if err := r.db.Model(&domain.TenantMembership{}).
		Where("tenant_id = ?", tenantID).
		Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated memberships with user info
	err := r.db.Preload("User").
		Where("tenant_id = ?", tenantID).
		Order("created_at ASC").
		Limit(limit).
		Offset(offset).
		Find(&memberships).Error

	return memberships, total, err
}

// UpdateMembershipRole updates a member's role within a tenant
func (r *membershipRepository) UpdateMembershipRole(tenantID, userID uuid.UUID, role domain.MemberRole) error {
	result := r.db.Model(&domain.TenantMembership{}).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Update("role", role)

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("membership not found")
	}
	return nil
}

// DeleteMembership removes a user from a tenant (soft delete)
func (r *membershipRepository) DeleteMembership(tenantID, userID uuid.UUID) error {
	result := r.db.Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Delete(&domain.TenantMembership{})

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("membership not found")
	}
	return nil
}

// CountMembersByRole counts members with a specific role in a tenant
func (r *membershipRepository) CountMembersByRole(tenantID uuid.UUID, role domain.MemberRole) (int64, error) {
	var count int64
	err := r.db.Model(&domain.TenantMembership{}).
		Where("tenant_id = ? AND role = ? AND status = ?", tenantID, role, domain.StatusActive).
		Count(&count).Error
	return count, err
}

// CreateInvitation creates a new invitation
func (r *membershipRepository) CreateInvitation(invitation *domain.TenantInvitation) error {
	return r.db.Create(invitation).Error
}

// GetInvitationByID retrieves an invitation by ID
func (r *membershipRepository) GetInvitationByID(invitationID uuid.UUID) (*domain.TenantInvitation, error) {
	var invitation domain.TenantInvitation
	err := r.db.First(&invitation, "id = ?", invitationID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("invitation not found")
		}
		return nil, err
	}
	return &invitation, nil
}

// GetInvitationByToken retrieves an invitation by its token
func (r *membershipRepository) GetInvitationByToken(token string) (*domain.TenantInvitation, error) {
	var invitation domain.TenantInvitation
	err := r.db.Preload("InvitedByUser").
		First(&invitation, "token = ?", token).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("invitation not found")
		}
		return nil, err
	}
	return &invitation, nil
}

// GetInvitationByEmail retrieves an invitation by email within a tenant
func (r *membershipRepository) GetInvitationByEmail(tenantID uuid.UUID, email string) (*domain.TenantInvitation, error) {
	var invitation domain.TenantInvitation
	err := r.db.First(&invitation, "tenant_id = ? AND email = ? AND accepted_at IS NULL", tenantID, email).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("invitation not found")
		}
		return nil, err
	}
	return &invitation, nil
}

// ListPendingInvitations retrieves all pending (not accepted, not expired) invitations for a tenant
func (r *membershipRepository) ListPendingInvitations(tenantID uuid.UUID) ([]domain.TenantInvitation, error) {
	var invitations []domain.TenantInvitation
	err := r.db.Preload("InvitedByUser").
		Where("tenant_id = ? AND accepted_at IS NULL AND expires_at > ?", tenantID, time.Now()).
		Order("created_at DESC").
		Find(&invitations).Error
	return invitations, err
}

// MarkInvitationAccepted marks an invitation as accepted
func (r *membershipRepository) MarkInvitationAccepted(invitationID uuid.UUID) error {
	now := time.Now()
	result := r.db.Model(&domain.TenantInvitation{}).
		Where("id = ?", invitationID).
		Update("accepted_at", now)

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("invitation not found")
	}
	return nil
}

// DeleteInvitation deletes an invitation
func (r *membershipRepository) DeleteInvitation(invitationID uuid.UUID) error {
	result := r.db.Delete(&domain.TenantInvitation{}, "id = ?", invitationID)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("invitation not found")
	}
	return nil
}

// DeleteExpiredInvitations removes all expired invitations (cleanup job)
func (r *membershipRepository) DeleteExpiredInvitations() error {
	return r.db.Where("expires_at < ? AND accepted_at IS NULL", time.Now()).
		Delete(&domain.TenantInvitation{}).Error
}
