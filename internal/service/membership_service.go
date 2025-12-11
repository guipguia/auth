package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/guipguia/auth/internal/domain"
	"github.com/guipguia/auth/internal/repository"
)

// MembershipService handles tenant membership and invitation operations
type MembershipService interface {
	// Membership operations
	CreateOwnerMembership(ctx context.Context, tenantID, userID uuid.UUID) error
	GetMembership(ctx context.Context, tenantID, userID uuid.UUID) (*domain.TenantMembership, error)
	ListMembers(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]domain.TenantMembership, int64, error)
	UpdateMemberRole(ctx context.Context, tenantID, actorID, targetUserID uuid.UUID, newRole domain.MemberRole) error
	RemoveMember(ctx context.Context, tenantID, actorID, targetUserID uuid.UUID) error

	// Invitation operations
	InviteUser(ctx context.Context, tenantID, inviterID uuid.UUID, email string, role domain.MemberRole) (*InviteResult, error)
	AcceptInvitation(ctx context.Context, token string, userID uuid.UUID) (*domain.TenantMembership, error)
	ListPendingInvitations(ctx context.Context, tenantID uuid.UUID) ([]domain.TenantInvitation, error)
	CancelInvitation(ctx context.Context, tenantID, actorID, invitationID uuid.UUID) error
	GetInvitationByToken(ctx context.Context, token string) (*domain.TenantInvitation, error)
}

// InviteResult contains the result of an invitation
type InviteResult struct {
	Invitation *domain.TenantInvitation
	InviteLink string
	EmailSent  bool
}

type membershipService struct {
	membershipRepo repository.MembershipRepository
	userRepo       repository.UserRepository
	emailService   EmailService
	auditService   AuditService
	appURL         string
	logger         Logger
}

// NewMembershipService creates a new membership service
func NewMembershipService(
	membershipRepo repository.MembershipRepository,
	userRepo repository.UserRepository,
	emailService EmailService,
	auditService AuditService,
	appURL string,
	logger Logger,
) MembershipService {
	if logger == nil {
		logger = NewDefaultLogger(LogLevelInfo)
	}
	return &membershipService{
		membershipRepo: membershipRepo,
		userRepo:       userRepo,
		emailService:   emailService,
		auditService:   auditService,
		appURL:         appURL,
		logger:         logger,
	}
}

// CreateOwnerMembership creates an owner membership for a user (called when tenant is created)
func (s *membershipService) CreateOwnerMembership(ctx context.Context, tenantID, userID uuid.UUID) error {
	now := time.Now()
	membership := &domain.TenantMembership{
		TenantID: tenantID,
		UserID:   userID,
		Role:     domain.RoleOwner,
		Status:   domain.StatusActive,
		JoinedAt: &now,
	}

	if err := s.membershipRepo.CreateMembership(membership); err != nil {
		return fmt.Errorf("failed to create owner membership: %w", err)
	}

	s.auditService.LogAction(ctx, tenantID, domain.AuditActionMemberAdd, domain.AuditResourceMembership, userID.String(), domain.AuditStatusSuccess, map[string]interface{}{
		"role":    string(domain.RoleOwner),
		"user_id": userID.String(),
	})

	return nil
}

// GetMembership retrieves a user's membership in a tenant
func (s *membershipService) GetMembership(ctx context.Context, tenantID, userID uuid.UUID) (*domain.TenantMembership, error) {
	return s.membershipRepo.GetMembershipByUserID(tenantID, userID)
}

// ListMembers lists all members in a tenant with pagination
func (s *membershipService) ListMembers(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]domain.TenantMembership, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	return s.membershipRepo.ListMembershipsByTenant(tenantID, limit, offset)
}

// UpdateMemberRole updates a member's role
func (s *membershipService) UpdateMemberRole(ctx context.Context, tenantID, actorID, targetUserID uuid.UUID, newRole domain.MemberRole) error {
	// Get actor's membership to check permissions
	actorMembership, err := s.membershipRepo.GetMembershipByUserID(tenantID, actorID)
	if err != nil {
		return fmt.Errorf("actor membership not found: %w", err)
	}

	// Only owners can change roles
	if !actorMembership.CanChangeRole() {
		s.auditService.LogAction(ctx, tenantID, domain.AuditActionMemberRoleChange, domain.AuditResourceMembership, targetUserID.String(), domain.AuditStatusFailure, map[string]interface{}{
			"reason":   "permission_denied",
			"actor_id": actorID.String(),
		})
		return fmt.Errorf("permission denied: only owners can change roles")
	}

	// Get target membership
	targetMembership, err := s.membershipRepo.GetMembershipByUserID(tenantID, targetUserID)
	if err != nil {
		return fmt.Errorf("target membership not found: %w", err)
	}

	// Cannot change owner's role (owner must transfer ownership first)
	if targetMembership.Role == domain.RoleOwner {
		return fmt.Errorf("cannot change owner's role directly; use ownership transfer")
	}

	// Prevent promoting to owner (ownership transfer is a separate operation)
	if newRole == domain.RoleOwner {
		return fmt.Errorf("cannot promote to owner; use ownership transfer")
	}

	oldRole := targetMembership.Role
	if err := s.membershipRepo.UpdateMembershipRole(tenantID, targetUserID, newRole); err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	s.auditService.LogAction(ctx, tenantID, domain.AuditActionMemberRoleChange, domain.AuditResourceMembership, targetUserID.String(), domain.AuditStatusSuccess, map[string]interface{}{
		"old_role":       string(oldRole),
		"new_role":       string(newRole),
		"actor_id":       actorID.String(),
		"target_user_id": targetUserID.String(),
	})

	return nil
}

// RemoveMember removes a member from a tenant
func (s *membershipService) RemoveMember(ctx context.Context, tenantID, actorID, targetUserID uuid.UUID) error {
	// Get actor's membership to check permissions
	actorMembership, err := s.membershipRepo.GetMembershipByUserID(tenantID, actorID)
	if err != nil {
		return fmt.Errorf("actor membership not found: %w", err)
	}

	// Admins and owners can remove members
	if !actorMembership.CanManageMembers() {
		s.auditService.LogAction(ctx, tenantID, domain.AuditActionMemberRemove, domain.AuditResourceMembership, targetUserID.String(), domain.AuditStatusFailure, map[string]interface{}{
			"reason":   "permission_denied",
			"actor_id": actorID.String(),
		})
		return fmt.Errorf("permission denied: insufficient privileges to remove members")
	}

	// Get target membership
	targetMembership, err := s.membershipRepo.GetMembershipByUserID(tenantID, targetUserID)
	if err != nil {
		return fmt.Errorf("target membership not found: %w", err)
	}

	// Cannot remove owner
	if targetMembership.Role == domain.RoleOwner {
		return fmt.Errorf("cannot remove owner from tenant")
	}

	// Admins cannot remove other admins (only owners can)
	if targetMembership.Role == domain.RoleAdmin && actorMembership.Role != domain.RoleOwner {
		return fmt.Errorf("only owners can remove admins")
	}

	if err := s.membershipRepo.DeleteMembership(tenantID, targetUserID); err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}

	s.auditService.LogAction(ctx, tenantID, domain.AuditActionMemberRemove, domain.AuditResourceMembership, targetUserID.String(), domain.AuditStatusSuccess, map[string]interface{}{
		"actor_id":       actorID.String(),
		"target_user_id": targetUserID.String(),
		"removed_role":   string(targetMembership.Role),
	})

	return nil
}

// InviteUser creates an invitation for a user to join a tenant
func (s *membershipService) InviteUser(ctx context.Context, tenantID, inviterID uuid.UUID, email string, role domain.MemberRole) (*InviteResult, error) {
	// Get inviter's membership to check permissions
	inviterMembership, err := s.membershipRepo.GetMembershipByUserID(tenantID, inviterID)
	if err != nil {
		return nil, fmt.Errorf("inviter membership not found: %w", err)
	}

	// Only admins and owners can invite
	if !inviterMembership.CanManageMembers() {
		s.auditService.LogAction(ctx, tenantID, domain.AuditActionMemberInvite, domain.AuditResourceInvitation, email, domain.AuditStatusFailure, map[string]interface{}{
			"reason":     "permission_denied",
			"inviter_id": inviterID.String(),
		})
		return nil, fmt.Errorf("permission denied: insufficient privileges to invite users")
	}

	// Admins can only invite members, not other admins
	if role == domain.RoleAdmin && inviterMembership.Role != domain.RoleOwner {
		return nil, fmt.Errorf("only owners can invite admins")
	}

	// Cannot invite as owner
	if role == domain.RoleOwner {
		return nil, fmt.Errorf("cannot invite as owner")
	}

	// Check if user is already a member
	existingUser, _ := s.userRepo.GetByEmail(tenantID, email)
	if existingUser != nil {
		existingMembership, err := s.membershipRepo.GetMembershipByUserID(tenantID, existingUser.ID)
		if err == nil && existingMembership != nil {
			return nil, fmt.Errorf("user is already a member of this tenant")
		}
	}

	// Check for existing pending invitation
	existingInvitation, _ := s.membershipRepo.GetInvitationByEmail(tenantID, email)
	if existingInvitation != nil && existingInvitation.IsPending() {
		return nil, fmt.Errorf("an invitation is already pending for this email")
	}

	// Create invitation
	invitation := &domain.TenantInvitation{
		TenantID:  tenantID,
		Email:     email,
		Role:      role,
		InvitedBy: inviterID,
		ExpiresAt: time.Now().Add(domain.DefaultInvitationExpiry()),
	}

	if err := s.membershipRepo.CreateInvitation(invitation); err != nil {
		return nil, fmt.Errorf("failed to create invitation: %w", err)
	}

	// Generate invite link
	inviteLink := fmt.Sprintf("%s/invite/%s", s.appURL, invitation.Token)

	// Try to send email
	emailSent := false
	if err := s.emailService.SendInvitationEmail(email, inviteLink, invitation.Role); err != nil {
		s.logger.Warn("Failed to send invitation email", "error", err, "email", email)
	} else {
		emailSent = true
	}

	s.auditService.LogAction(ctx, tenantID, domain.AuditActionMemberInvite, domain.AuditResourceInvitation, invitation.ID.String(), domain.AuditStatusSuccess, map[string]interface{}{
		"inviter_id": inviterID.String(),
		"email":      email,
		"role":       string(role),
		"email_sent": emailSent,
	})

	return &InviteResult{
		Invitation: invitation,
		InviteLink: inviteLink,
		EmailSent:  emailSent,
	}, nil
}

// AcceptInvitation accepts an invitation and creates a membership
func (s *membershipService) AcceptInvitation(ctx context.Context, token string, userID uuid.UUID) (*domain.TenantMembership, error) {
	// Get invitation by token
	invitation, err := s.membershipRepo.GetInvitationByToken(token)
	if err != nil {
		return nil, fmt.Errorf("invitation not found: %w", err)
	}

	// Check if invitation is still valid
	if invitation.IsExpired() {
		return nil, fmt.Errorf("invitation has expired")
	}

	if invitation.IsAccepted() {
		return nil, fmt.Errorf("invitation has already been accepted")
	}

	// Get user
	user, err := s.userRepo.GetByID(invitation.TenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Verify email matches (case-insensitive comparison could be added here)
	if user.Email != invitation.Email {
		return nil, fmt.Errorf("user email does not match invitation")
	}

	// Check if user is already a member
	existingMembership, _ := s.membershipRepo.GetMembershipByUserID(invitation.TenantID, userID)
	if existingMembership != nil {
		return nil, fmt.Errorf("user is already a member of this tenant")
	}

	// Create membership
	now := time.Now()
	membership := &domain.TenantMembership{
		TenantID:  invitation.TenantID,
		UserID:    userID,
		Role:      invitation.Role,
		Status:    domain.StatusActive,
		InvitedBy: &invitation.InvitedBy,
		InvitedAt: &invitation.CreatedAt,
		JoinedAt:  &now,
	}

	if err := s.membershipRepo.CreateMembership(membership); err != nil {
		return nil, fmt.Errorf("failed to create membership: %w", err)
	}

	// Mark invitation as accepted
	if err := s.membershipRepo.MarkInvitationAccepted(invitation.ID); err != nil {
		s.logger.Error("Failed to mark invitation as accepted", "error", err, "invitation_id", invitation.ID)
	}

	s.auditService.LogAction(ctx, invitation.TenantID, domain.AuditActionMemberJoin, domain.AuditResourceMembership, userID.String(), domain.AuditStatusSuccess, map[string]interface{}{
		"invitation_id": invitation.ID.String(),
		"role":          string(invitation.Role),
	})

	return membership, nil
}

// ListPendingInvitations lists all pending invitations for a tenant
func (s *membershipService) ListPendingInvitations(ctx context.Context, tenantID uuid.UUID) ([]domain.TenantInvitation, error) {
	return s.membershipRepo.ListPendingInvitations(tenantID)
}

// CancelInvitation cancels a pending invitation
func (s *membershipService) CancelInvitation(ctx context.Context, tenantID, actorID, invitationID uuid.UUID) error {
	// Get actor's membership to check permissions
	actorMembership, err := s.membershipRepo.GetMembershipByUserID(tenantID, actorID)
	if err != nil {
		return fmt.Errorf("actor membership not found: %w", err)
	}

	// Only admins and owners can cancel invitations
	if !actorMembership.CanManageMembers() {
		s.auditService.LogAction(ctx, tenantID, domain.AuditActionInvitationCancel, domain.AuditResourceInvitation, invitationID.String(), domain.AuditStatusFailure, map[string]interface{}{
			"reason":   "permission_denied",
			"actor_id": actorID.String(),
		})
		return fmt.Errorf("permission denied: insufficient privileges to cancel invitations")
	}

	// Get invitation to verify it belongs to this tenant
	invitation, err := s.membershipRepo.GetInvitationByID(invitationID)
	if err != nil {
		return fmt.Errorf("invitation not found: %w", err)
	}

	if invitation.TenantID != tenantID {
		return fmt.Errorf("invitation does not belong to this tenant")
	}

	if err := s.membershipRepo.DeleteInvitation(invitationID); err != nil {
		return fmt.Errorf("failed to cancel invitation: %w", err)
	}

	s.auditService.LogAction(ctx, tenantID, domain.AuditActionInvitationCancel, domain.AuditResourceInvitation, invitationID.String(), domain.AuditStatusSuccess, map[string]interface{}{
		"actor_id": actorID.String(),
		"email":    invitation.Email,
	})

	return nil
}

// GetInvitationByToken retrieves an invitation by its token (for public acceptance page)
func (s *membershipService) GetInvitationByToken(ctx context.Context, token string) (*domain.TenantInvitation, error) {
	return s.membershipRepo.GetInvitationByToken(token)
}
