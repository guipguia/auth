package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	authv1 "github.com/guipguia/auth/api/proto/auth/v1"
	"github.com/guipguia/auth/internal/domain"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GetOAuthURL generates an OAuth authorization URL
func (s *AuthService) GetOAuthURL(ctx context.Context, req *authv1.GetOAuthURLRequest) (*authv1.GetOAuthURLResponse, error) {
	// Extract tenant ID from context (for audit logging)
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	provider := s.protoToOAuthProvider(req.Provider)

	// Generate state for CSRF protection
	state, err := s.oauthService.GenerateState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Get OAuth URL
	authURL, err := s.oauthService.GetAuthURL(provider, state)
	if err != nil {
		return nil, fmt.Errorf("failed to generate OAuth URL: %w", err)
	}

	// Audit log OAuth flow initiated
	s.auditService.LogAction(ctx, tenantID, domain.AuditActionOAuthLogin, domain.AuditResourceUser, "", domain.AuditStatusSuccess, map[string]interface{}{
		"provider": string(provider),
		"state":    state,
	})

	return &authv1.GetOAuthURLResponse{
		AuthUrl: authURL,
		State:   state,
	}, nil
}

// OAuthCallback handles OAuth callback
func (s *AuthService) OAuthCallback(ctx context.Context, req *authv1.OAuthCallbackRequest) (*authv1.OAuthCallbackResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	ipAddress := IPAddressFromContext(ctx)
	provider := s.protoToOAuthProvider(req.Provider)

	// Exchange code for token
	token, err := s.oauthService.ExchangeCode(provider, req.Code)
	if err != nil {
		s.auditService.LogAction(ctx, tenantID, domain.AuditActionOAuthLogin, domain.AuditResourceUser, "", domain.AuditStatusFailure, map[string]interface{}{
			"provider": string(provider),
			"reason":   "code_exchange_failed",
		})
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Get user info from provider
	userInfo, err := s.oauthService.GetUserInfo(provider, token)
	if err != nil {
		s.auditService.LogAction(ctx, tenantID, domain.AuditActionOAuthLogin, domain.AuditResourceUser, "", domain.AuditStatusFailure, map[string]interface{}{
			"provider": string(provider),
			"reason":   "user_info_failed",
		})
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Check if OAuth account already exists within tenant
	oauthAccount, err := s.userRepo.GetOAuthAccount(tenantID, string(provider), userInfo.ProviderUserID)

	var user *domain.User
	isNewUser := false

	if err != nil {
		// OAuth account doesn't exist, check if user exists by email within tenant
		user, err = s.userRepo.GetByEmail(tenantID, userInfo.Email)
		if err != nil {
			// Create new user with tenant ID
			user = &domain.User{
				TenantID:      tenantID,
				Email:         userInfo.Email,
				FirstName:     userInfo.FirstName,
				LastName:      userInfo.LastName,
				EmailVerified: true, // OAuth email is already verified
			}

			if err := s.userRepo.Create(user); err != nil {
				return nil, fmt.Errorf("failed to create user: %w", err)
			}

			isNewUser = true

			// Audit log new user registration via OAuth
			s.auditService.LogUserAction(ctx, tenantID, user.ID, nil, domain.AuditActionRegister, domain.AuditStatusSuccess, map[string]interface{}{
				"method":   "oauth",
				"provider": string(provider),
			})
		}

		// Create OAuth account link with tenant ID
		oauthAccount = &domain.OAuthAccount{
			TenantID:       tenantID,
			UserID:         user.ID,
			Provider:       string(provider),
			ProviderUserID: userInfo.ProviderUserID,
			Email:          userInfo.Email,
			AccessToken:    token.AccessToken,
			RefreshToken:   token.RefreshToken,
		}

		if !token.Expiry.IsZero() {
			oauthAccount.ExpiresAt = &token.Expiry
		}

		if err := s.userRepo.CreateOAuthAccount(oauthAccount); err != nil {
			return nil, fmt.Errorf("failed to create OAuth account: %w", err)
		}

		// Audit log OAuth account linked
		s.auditService.LogUserAction(ctx, tenantID, user.ID, nil, domain.AuditActionOAuthLink, domain.AuditStatusSuccess, map[string]interface{}{
			"provider": string(provider),
		})
	} else {
		// OAuth account exists, get the user within tenant
		user, err = s.userRepo.GetByID(tenantID, oauthAccount.UserID)
		if err != nil {
			return nil, fmt.Errorf("user not found")
		}
	}

	// Generate JWT tokens with tenant ID
	accessToken, err := s.jwtService.GenerateAccessToken(user.ID, user.Email, map[string]string{
		"tenant_id": tenantID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.jwtService.GenerateRefreshToken(user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Create session with tenant ID and idle timeout
	now := time.Now()
	session := &domain.Session{
		TenantID:       tenantID,
		UserID:         user.ID,
		RefreshToken:   refreshToken,
		DeviceID:       req.DeviceId,
		DeviceName:     req.DeviceName,
		IPAddress:      ipAddress,
		UserAgent:      UserAgentFromContext(ctx),
		ExpiresAt:      now.Add(s.sessionConfig.SessionExpiry),
		IdleTimeoutAt:  ptrTime(now.Add(s.sessionConfig.IdleTimeout)),
		LastAccessedAt: now,
	}

	if err := s.sessionRepo.Create(session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Update last login
	if err := s.userRepo.UpdateLastLogin(tenantID, user.ID); err != nil {
		log.Printf("[WARN] Failed to update last login: %v", err)
	}

	// Audit log OAuth login
	s.auditService.LogUserAction(ctx, tenantID, user.ID, nil, domain.AuditActionOAuthLogin, domain.AuditStatusSuccess, map[string]interface{}{
		"provider":   string(provider),
		"session_id": session.ID.String(),
		"is_new":     isNewUser,
	})

	return &authv1.OAuthCallbackResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(15 * 60),
		User:         s.userToProto(user),
		IsNewUser:    isNewUser,
		SessionId:    session.ID.String(),
	}, nil
}

// LinkOAuthAccount links an OAuth account to an existing user
func (s *AuthService) LinkOAuthAccount(ctx context.Context, req *authv1.LinkOAuthAccountRequest) (*authv1.LinkOAuthAccountResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	provider := s.protoToOAuthProvider(req.Provider)

	// Exchange code for token
	token, err := s.oauthService.ExchangeCode(provider, req.Code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Get user info from provider
	userInfo, err := s.oauthService.GetUserInfo(provider, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Create OAuth account link with tenant ID
	oauthAccount := &domain.OAuthAccount{
		TenantID:       tenantID,
		UserID:         userID,
		Provider:       string(provider),
		ProviderUserID: userInfo.ProviderUserID,
		Email:          userInfo.Email,
		AccessToken:    token.AccessToken,
		RefreshToken:   token.RefreshToken,
	}

	if !token.Expiry.IsZero() {
		oauthAccount.ExpiresAt = &token.Expiry
	}

	if err := s.userRepo.CreateOAuthAccount(oauthAccount); err != nil {
		return nil, fmt.Errorf("failed to link OAuth account: %w", err)
	}

	// Audit log OAuth account linked
	s.auditService.LogUserAction(ctx, tenantID, userID, nil, domain.AuditActionOAuthLink, domain.AuditStatusSuccess, map[string]interface{}{
		"provider": string(provider),
	})

	return &authv1.LinkOAuthAccountResponse{
		Success: true,
		Message: "OAuth account linked successfully",
		OauthAccount: &authv1.OAuthAccount{
			Provider:       req.Provider,
			ProviderUserId: userInfo.ProviderUserID,
			Email:          userInfo.Email,
			LinkedAt:       timestamppb.Now(),
		},
	}, nil
}

// UnlinkOAuthAccount unlinks an OAuth account from a user
func (s *AuthService) UnlinkOAuthAccount(ctx context.Context, req *authv1.UnlinkOAuthAccountRequest) (*authv1.UnlinkOAuthAccountResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	provider := s.protoToOAuthProvider(req.Provider)

	if err := s.userRepo.DeleteOAuthAccount(tenantID, userID, string(provider)); err != nil {
		return nil, fmt.Errorf("failed to unlink OAuth account: %w", err)
	}

	// Audit log OAuth account unlinked
	s.auditService.LogUserAction(ctx, tenantID, userID, nil, domain.AuditActionOAuthUnlink, domain.AuditStatusSuccess, map[string]interface{}{
		"provider": string(provider),
	})

	return &authv1.UnlinkOAuthAccountResponse{
		Success: true,
		Message: "OAuth account unlinked successfully",
	}, nil
}

// ValidateToken validates an access token
func (s *AuthService) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	claims, err := s.jwtService.ValidateToken(req.AccessToken, AccessToken)
	if err != nil {
		return &authv1.ValidateTokenResponse{
			Valid: false,
		}, nil
	}

	// Convert extra claims to map
	claimsMap := make(map[string]string)
	for k, v := range claims.Extra {
		claimsMap[k] = v
	}

	return &authv1.ValidateTokenResponse{
		Valid:     true,
		UserId:    claims.UserID,
		Email:     claims.Email,
		Claims:    claimsMap, // tenant_id is included in claims
		ExpiresAt: timestamppb.New(claims.ExpiresAt.Time),
	}, nil
}

// RevokeToken revokes a token
func (s *AuthService) RevokeToken(ctx context.Context, req *authv1.RevokeTokenRequest) (*authv1.RevokeTokenResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	// For refresh tokens, revoke the session
	if req.TokenType == authv1.TokenType_TOKEN_TYPE_REFRESH {
		session, err := s.sessionRepo.GetByRefreshToken(tenantID, req.Token)
		if err != nil {
			return nil, fmt.Errorf("session not found")
		}

		if err := s.sessionRepo.Revoke(tenantID, session.ID); err != nil {
			return nil, fmt.Errorf("failed to revoke session: %w", err)
		}

		// Audit log token revocation
		s.auditService.LogSessionAction(ctx, tenantID, session.ID, session.UserID, domain.AuditActionTokenRevoke, domain.AuditStatusSuccess, nil)

		return &authv1.RevokeTokenResponse{
			Success: true,
			Message: "Token revoked successfully",
		}, nil
	}

	// For access tokens, we can't revoke them (they're stateless JWT)
	// In a production system, you might want to maintain a blacklist
	return &authv1.RevokeTokenResponse{
		Success: true,
		Message: "Access tokens cannot be revoked (they expire naturally)",
	}, nil
}

// GetActiveSessions retrieves all active sessions for a user
func (s *AuthService) GetActiveSessions(ctx context.Context, req *authv1.GetActiveSessionsRequest) (*authv1.GetActiveSessionsResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	sessions, err := s.sessionRepo.GetActiveSessions(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get sessions: %w", err)
	}

	protoSessions := make([]*authv1.Session, len(sessions))
	for i, session := range sessions {
		protoSessions[i] = &authv1.Session{
			Id:             session.ID.String(),
			UserId:         session.UserID.String(),
			DeviceId:       session.DeviceID,
			DeviceName:     session.DeviceName,
			IpAddress:      session.IPAddress,
			UserAgent:      session.UserAgent,
			CreatedAt:      timestamppb.New(session.CreatedAt),
			LastAccessedAt: timestamppb.New(session.LastAccessedAt),
			ExpiresAt:      timestamppb.New(session.ExpiresAt),
		}
	}

	return &authv1.GetActiveSessionsResponse{
		Sessions: protoSessions,
	}, nil
}

// RevokeSession revokes a specific session
func (s *AuthService) RevokeSession(ctx context.Context, req *authv1.RevokeSessionRequest) (*authv1.RevokeSessionResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	sessionID, err := uuid.Parse(req.SessionId)
	if err != nil {
		return nil, fmt.Errorf("invalid session ID")
	}

	// Verify session belongs to user within tenant
	session, err := s.sessionRepo.GetByID(tenantID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found")
	}

	if session.UserID.String() != req.UserId {
		return nil, fmt.Errorf("unauthorized")
	}

	if err := s.sessionRepo.Revoke(tenantID, sessionID); err != nil {
		return nil, fmt.Errorf("failed to revoke session: %w", err)
	}

	// Audit log session revocation
	s.auditService.LogSessionAction(ctx, tenantID, sessionID, session.UserID, domain.AuditActionSessionRevoke, domain.AuditStatusSuccess, nil)

	return &authv1.RevokeSessionResponse{
		Success: true,
		Message: "Session revoked successfully",
	}, nil
}

// GetUserProfile retrieves a user's profile
func (s *AuthService) GetUserProfile(ctx context.Context, req *authv1.GetUserProfileRequest) (*authv1.GetUserProfileResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	user, err := s.userRepo.GetByID(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	return &authv1.GetUserProfileResponse{
		User: s.userToProto(user),
	}, nil
}

// UpdateUserProfile updates a user's profile
func (s *AuthService) UpdateUserProfile(ctx context.Context, req *authv1.UpdateUserProfileRequest) (*authv1.UpdateUserProfileResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	user, err := s.userRepo.GetByID(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Update fields
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}
	if req.PhoneNumber != "" {
		user.PhoneNumber = req.PhoneNumber
	}
	if req.Metadata != nil {
		user.Metadata = req.Metadata
	}

	if err := s.userRepo.Update(user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Audit log profile update
	s.auditService.LogUserAction(ctx, tenantID, userID, nil, domain.AuditActionProfileUpdate, domain.AuditStatusSuccess, nil)

	return &authv1.UpdateUserProfileResponse{
		User: s.userToProto(user),
	}, nil
}

// VerifyEmail verifies a user's email
func (s *AuthService) VerifyEmail(ctx context.Context, req *authv1.VerifyEmailRequest) (*authv1.VerifyEmailResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	// Get OTP by token within tenant
	otp, err := s.otpRepo.GetByToken(tenantID, req.Token)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token")
	}

	if otp.Type != domain.OTPTypeEmailVerification {
		return nil, fmt.Errorf("invalid token type")
	}

	// Verify email
	if err := s.userRepo.VerifyEmail(tenantID, otp.UserID); err != nil {
		return nil, fmt.Errorf("failed to verify email: %w", err)
	}

	// Mark token as used
	if err := s.otpRepo.MarkAsUsed(tenantID, otp.ID); err != nil {
		log.Printf("[WARN] Failed to mark token as used: %v", err)
	}

	// Audit log email verification
	s.auditService.LogUserAction(ctx, tenantID, otp.UserID, nil, domain.AuditActionEmailVerify, domain.AuditStatusSuccess, nil)

	return &authv1.VerifyEmailResponse{
		Success: true,
		Message: "Email verified successfully",
	}, nil
}

// ResendVerificationEmail resends the verification email
func (s *AuthService) ResendVerificationEmail(ctx context.Context, req *authv1.ResendVerificationEmailRequest) (*authv1.ResendVerificationEmailResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	// Get user within tenant
	user, err := s.userRepo.GetByEmail(tenantID, req.Email)
	if err != nil {
		// Don't reveal if user exists
		return &authv1.ResendVerificationEmailResponse{
			Success: true,
			Message: "If an unverified account exists, a verification email has been sent.",
		}, nil
	}

	// Check if already verified
	if user.EmailVerified {
		return &authv1.ResendVerificationEmailResponse{
			Success: true,
			Message: "Email is already verified.",
		}, nil
	}

	// Generate new verification token with tenant ID
	verificationToken, err := GenerateEmailVerificationToken(tenantID, user.Email, user.ID, s.otpRepo)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Send verification email
	if err := s.emailService.SendVerificationEmail(user.Email, verificationToken.Token); err != nil {
		log.Printf("[WARN] Failed to send verification email: %v", err)
	}

	return &authv1.ResendVerificationEmailResponse{
		Success: true,
		Message: "Verification email sent.",
	}, nil
}

// Helper function to convert proto OAuth provider to service OAuth provider
func (s *AuthService) protoToOAuthProvider(provider authv1.OAuthProvider) OAuthProvider {
	switch provider {
	case authv1.OAuthProvider_OAUTH_PROVIDER_GOOGLE:
		return ProviderGoogle
	case authv1.OAuthProvider_OAUTH_PROVIDER_GITHUB:
		return ProviderGitHub
	case authv1.OAuthProvider_OAUTH_PROVIDER_FACEBOOK:
		return ProviderFacebook
	case authv1.OAuthProvider_OAUTH_PROVIDER_APPLE:
		return ProviderApple
	case authv1.OAuthProvider_OAUTH_PROVIDER_MICROSOFT:
		return ProviderMicrosoft
	case authv1.OAuthProvider_OAUTH_PROVIDER_DISCORD:
		return ProviderDiscord
	default:
		return ""
	}
}
