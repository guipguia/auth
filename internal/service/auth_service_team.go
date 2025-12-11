package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	authv1 "github.com/guipguia/auth/api/proto/auth/v1"
	"github.com/guipguia/auth/internal/domain"
	"github.com/guipguia/auth/internal/repository"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TeamAuthService wraps AuthService to add team management functionality
type TeamAuthService struct {
	*AuthService
	membershipService MembershipService
	tenantClient      TenantClient
}

// NewTeamAuthService creates a new TeamAuthService
func NewTeamAuthService(
	authService *AuthService,
	membershipService MembershipService,
	tenantClient TenantClient,
) *TeamAuthService {
	return &TeamAuthService{
		AuthService:       authService,
		membershipService: membershipService,
		tenantClient:      tenantClient,
	}
}

// Register overrides AuthService.Register to also create owner membership
func (s *TeamAuthService) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	// Call the base AuthService.Register
	resp, err := s.AuthService.Register(ctx, req)
	if err != nil {
		return nil, err
	}

	// Get tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		// Registration succeeded but we couldn't get tenant - log and continue
		return resp, nil
	}

	// Parse the user ID from the response
	userID, err := uuid.Parse(resp.UserId)
	if err != nil {
		// Registration succeeded but invalid user ID - log and continue
		return resp, nil
	}

	// Check if this is the first user in the tenant (they become owner)
	members, total, _ := s.membershipService.ListMembers(ctx, tenantID, 1, 0)
	if total == 0 || len(members) == 0 {
		// First user becomes owner
		if err := s.membershipService.CreateOwnerMembership(ctx, tenantID, userID); err != nil {
			// Log error but don't fail registration
			// The user is registered, just without ownership
		}
	}

	return resp, nil
}

// ListTeamMembers lists all members in a tenant
func (s *TeamAuthService) ListTeamMembers(ctx context.Context, req *authv1.ListTeamMembersRequest) (*authv1.ListTeamMembersResponse, error) {
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	limit := int(req.Limit)
	offset := int(req.Offset)

	members, total, err := s.membershipService.ListMembers(ctx, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list team members: %w", err)
	}

	protoMembers := make([]*authv1.TeamMember, len(members))
	for i, member := range members {
		protoMembers[i] = s.membershipToProto(&member)
	}

	return &authv1.ListTeamMembersResponse{
		Members: protoMembers,
		Total:   total,
	}, nil
}

// GetTeamMember retrieves a specific team member
func (s *TeamAuthService) GetTeamMember(ctx context.Context, req *authv1.GetTeamMemberRequest) (*authv1.GetTeamMemberResponse, error) {
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	member, err := s.membershipService.GetMembership(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("member not found: %w", err)
	}

	return &authv1.GetTeamMemberResponse{
		Member: s.membershipToProto(member),
	}, nil
}

// InviteTeamMember invites a new user to the team
func (s *TeamAuthService) InviteTeamMember(ctx context.Context, req *authv1.InviteTeamMemberRequest) (*authv1.InviteTeamMemberResponse, error) {
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	// Get actor ID from context (the user making the request)
	actorID := ActorIDFromContext(ctx)
	if actorID == uuid.Nil {
		return nil, fmt.Errorf("actor context required")
	}

	role := s.protoRoleToRole(req.Role)

	result, err := s.membershipService.InviteUser(ctx, tenantID, actorID, req.Email, role)
	if err != nil {
		return nil, fmt.Errorf("failed to invite user: %w", err)
	}

	message := "Invitation created."
	if result.EmailSent {
		message = "Invitation sent successfully."
	} else {
		message = "Invitation created. Share the invite link with the user."
	}

	return &authv1.InviteTeamMemberResponse{
		Invitation: s.invitationToProto(result.Invitation),
		InviteLink: result.InviteLink,
		EmailSent:  result.EmailSent,
		Message:    message,
	}, nil
}

// AcceptInvitation accepts a team invitation
func (s *TeamAuthService) AcceptInvitation(ctx context.Context, req *authv1.AcceptInvitationRequest) (*authv1.AcceptInvitationResponse, error) {
	// Get actor ID from context (the user accepting)
	actorID := ActorIDFromContext(ctx)
	if actorID == uuid.Nil {
		return nil, fmt.Errorf("must be logged in to accept invitation")
	}

	member, err := s.membershipService.AcceptInvitation(ctx, req.Token, actorID)
	if err != nil {
		return nil, fmt.Errorf("failed to accept invitation: %w", err)
	}

	return &authv1.AcceptInvitationResponse{
		Member:  s.membershipToProto(member),
		Message: "Successfully joined the team",
	}, nil
}

// UpdateTeamMemberRole updates a team member's role
func (s *TeamAuthService) UpdateTeamMemberRole(ctx context.Context, req *authv1.UpdateTeamMemberRoleRequest) (*authv1.UpdateTeamMemberRoleResponse, error) {
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	actorID := ActorIDFromContext(ctx)
	if actorID == uuid.Nil {
		return nil, fmt.Errorf("actor context required")
	}

	targetUserID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	role := s.protoRoleToRole(req.Role)

	if err := s.membershipService.UpdateMemberRole(ctx, tenantID, actorID, targetUserID, role); err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}

	return &authv1.UpdateTeamMemberRoleResponse{
		Success: true,
		Message: "Role updated successfully",
	}, nil
}

// RemoveTeamMember removes a member from the team
func (s *TeamAuthService) RemoveTeamMember(ctx context.Context, req *authv1.RemoveTeamMemberRequest) (*authv1.RemoveTeamMemberResponse, error) {
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	actorID := ActorIDFromContext(ctx)
	if actorID == uuid.Nil {
		return nil, fmt.Errorf("actor context required")
	}

	targetUserID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	if err := s.membershipService.RemoveMember(ctx, tenantID, actorID, targetUserID); err != nil {
		return nil, fmt.Errorf("failed to remove member: %w", err)
	}

	return &authv1.RemoveTeamMemberResponse{
		Success: true,
		Message: "Member removed successfully",
	}, nil
}

// ListPendingInvitations lists all pending invitations
func (s *TeamAuthService) ListPendingInvitations(ctx context.Context, req *authv1.ListPendingInvitationsRequest) (*authv1.ListPendingInvitationsResponse, error) {
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	invitations, err := s.membershipService.ListPendingInvitations(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list invitations: %w", err)
	}

	protoInvitations := make([]*authv1.TeamInvitation, len(invitations))
	for i, inv := range invitations {
		protoInvitations[i] = s.invitationToProto(&inv)
	}

	return &authv1.ListPendingInvitationsResponse{
		Invitations: protoInvitations,
	}, nil
}

// CancelInvitation cancels a pending invitation
func (s *TeamAuthService) CancelInvitation(ctx context.Context, req *authv1.CancelInvitationRequest) (*authv1.CancelInvitationResponse, error) {
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	actorID := ActorIDFromContext(ctx)
	if actorID == uuid.Nil {
		return nil, fmt.Errorf("actor context required")
	}

	invitationID, err := uuid.Parse(req.InvitationId)
	if err != nil {
		return nil, fmt.Errorf("invalid invitation ID: %w", err)
	}

	if err := s.membershipService.CancelInvitation(ctx, tenantID, actorID, invitationID); err != nil {
		return nil, fmt.Errorf("failed to cancel invitation: %w", err)
	}

	return &authv1.CancelInvitationResponse{
		Success: true,
		Message: "Invitation cancelled successfully",
	}, nil
}

// GetInvitationByToken retrieves invitation details by token (public endpoint)
func (s *TeamAuthService) GetInvitationByToken(ctx context.Context, req *authv1.GetInvitationByTokenRequest) (*authv1.GetInvitationByTokenResponse, error) {
	invitation, err := s.membershipService.GetInvitationByToken(ctx, req.Token)
	if err != nil {
		return nil, fmt.Errorf("invitation not found: %w", err)
	}

	if invitation.IsExpired() {
		return nil, fmt.Errorf("invitation has expired")
	}

	if invitation.IsAccepted() {
		return nil, fmt.Errorf("invitation has already been accepted")
	}

	// Get tenant name for display
	var tenantName string
	if s.tenantClient != nil {
		tenant, err := s.tenantClient.GetTenant(ctx, invitation.TenantID)
		if err == nil && tenant != nil {
			tenantName = tenant.Name
		}
	}

	return &authv1.GetInvitationByTokenResponse{
		Invitation: s.invitationToProto(invitation),
		TenantName: tenantName,
	}, nil
}

// Helper functions

func (s *TeamAuthService) membershipToProto(m *domain.TenantMembership) *authv1.TeamMember {
	member := &authv1.TeamMember{
		Id:        m.ID.String(),
		TenantId:  m.TenantID.String(),
		UserId:    m.UserID.String(),
		Role:      s.roleToProtoRole(m.Role),
		Status:    s.statusToProtoStatus(m.Status),
		CreatedAt: timestamppb.New(m.CreatedAt),
		UpdatedAt: timestamppb.New(m.UpdatedAt),
	}

	if m.InvitedBy != nil {
		member.InvitedBy = m.InvitedBy.String()
	}
	if m.InvitedAt != nil {
		member.InvitedAt = timestamppb.New(*m.InvitedAt)
	}
	if m.JoinedAt != nil {
		member.JoinedAt = timestamppb.New(*m.JoinedAt)
	}
	if m.User != nil {
		member.User = s.userToProto(m.User)
	}

	return member
}

func (s *TeamAuthService) invitationToProto(i *domain.TenantInvitation) *authv1.TeamInvitation {
	invitation := &authv1.TeamInvitation{
		Id:        i.ID.String(),
		TenantId:  i.TenantID.String(),
		Email:     i.Email,
		Role:      s.roleToProtoRole(i.Role),
		InvitedBy: i.InvitedBy.String(),
		ExpiresAt: timestamppb.New(i.ExpiresAt),
		CreatedAt: timestamppb.New(i.CreatedAt),
	}

	if i.AcceptedAt != nil {
		invitation.AcceptedAt = timestamppb.New(*i.AcceptedAt)
	}
	if i.InvitedByUser != nil {
		invitation.InvitedByUser = s.userToProto(i.InvitedByUser)
	}

	return invitation
}

func (s *TeamAuthService) roleToProtoRole(r domain.MemberRole) authv1.MemberRole {
	switch r {
	case domain.RoleOwner:
		return authv1.MemberRole_MEMBER_ROLE_OWNER
	case domain.RoleAdmin:
		return authv1.MemberRole_MEMBER_ROLE_ADMIN
	case domain.RoleMember:
		return authv1.MemberRole_MEMBER_ROLE_MEMBER
	default:
		return authv1.MemberRole_MEMBER_ROLE_UNSPECIFIED
	}
}

func (s *TeamAuthService) protoRoleToRole(r authv1.MemberRole) domain.MemberRole {
	switch r {
	case authv1.MemberRole_MEMBER_ROLE_OWNER:
		return domain.RoleOwner
	case authv1.MemberRole_MEMBER_ROLE_ADMIN:
		return domain.RoleAdmin
	case authv1.MemberRole_MEMBER_ROLE_MEMBER:
		return domain.RoleMember
	default:
		return domain.RoleMember
	}
}

func (s *TeamAuthService) statusToProtoStatus(s2 domain.MemberStatus) authv1.MemberStatus {
	switch s2 {
	case domain.StatusActive:
		return authv1.MemberStatus_MEMBER_STATUS_ACTIVE
	case domain.StatusInvited:
		return authv1.MemberStatus_MEMBER_STATUS_INVITED
	case domain.StatusDisabled:
		return authv1.MemberStatus_MEMBER_STATUS_DISABLED
	default:
		return authv1.MemberStatus_MEMBER_STATUS_UNSPECIFIED
	}
}

// GetUserRepository returns the user repository for use by the membership service
func (s *AuthService) GetUserRepository() repository.UserRepository {
	return s.userRepo
}
