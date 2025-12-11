package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/guipguia/auth/api/proto/auth/v1"
	"github.com/guipguia/auth/internal/domain"
	"github.com/guipguia/auth/internal/repository"
)

// SessionConfig holds session configuration for compliance
type SessionConfig struct {
	// Session expiry duration
	SessionExpiry time.Duration
	// Idle timeout duration (only enforced when HIPAACompliant is true)
	IdleTimeout time.Duration
	// Maximum concurrent sessions per user (0 = unlimited)
	MaxConcurrentSessions int
	// HIPAACompliant enables strict session security features (idle timeout enforcement)
	HIPAACompliant bool
}

// DefaultSessionConfig returns sensible default configuration
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		SessionExpiry:         7 * 24 * time.Hour, // 7 days
		IdleTimeout:           15 * time.Minute,   // HIPAA requires 15 min idle timeout
		MaxConcurrentSessions: 5,                  // Limit concurrent sessions
		HIPAACompliant:        false,              // Disabled by default
	}
}

// AuthService implements the gRPC AuthService interface
type AuthService struct {
	authv1.UnimplementedAuthServiceServer
	userRepo               repository.UserRepository
	sessionRepo            repository.SessionRepository
	otpRepo                repository.OTPRepository
	passwordService        PasswordService
	totpService            TOTPService
	passwordlessService    PasswordlessService
	oauthService           OAuthService
	jwtService             JWTService
	emailService           EmailService
	auditService           AuditService
	loginProtectionService LoginProtectionService
	passwordHistoryService PasswordHistoryService
	sessionConfig          SessionConfig
	logger                 Logger
}

// NewAuthService creates a new AuthService
func NewAuthService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	otpRepo repository.OTPRepository,
	passwordService PasswordService,
	totpService TOTPService,
	passwordlessService PasswordlessService,
	oauthService OAuthService,
	jwtService JWTService,
	emailService EmailService,
	auditService AuditService,
	loginProtectionService LoginProtectionService,
	passwordHistoryService PasswordHistoryService,
	sessionConfig SessionConfig,
	logger Logger,
) *AuthService {
	// Use default logger if none provided
	if logger == nil {
		logger = NewDefaultLogger(LogLevelInfo)
	}
	return &AuthService{
		userRepo:               userRepo,
		sessionRepo:            sessionRepo,
		otpRepo:                otpRepo,
		passwordService:        passwordService,
		totpService:            totpService,
		passwordlessService:    passwordlessService,
		oauthService:           oauthService,
		jwtService:             jwtService,
		emailService:           emailService,
		auditService:           auditService,
		loginProtectionService: loginProtectionService,
		passwordHistoryService: passwordHistoryService,
		sessionConfig:          sessionConfig,
		logger:                 logger,
	}
}

// Register registers a new user
func (s *AuthService) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	// Validate password strength
	if err := s.passwordService.ValidatePasswordStrength(req.Password); err != nil {
		// Audit log failed registration attempt
		_ = s.auditService.LogAction(ctx, tenantID, domain.AuditActionRegister, domain.AuditResourceUser, req.Email, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "password_validation_failed",
			"email":  req.Email,
		})
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	// Check if user already exists
	existingUser, _ := s.userRepo.GetByEmail(tenantID, req.Email)
	if existingUser != nil {
		// Audit log failed registration attempt
		_ = s.auditService.LogAction(ctx, tenantID, domain.AuditActionRegister, domain.AuditResourceUser, req.Email, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "user_already_exists",
			"email":  req.Email,
		})
		return nil, fmt.Errorf("user with email %s already exists", req.Email)
	}

	// Hash password
	passwordHash, err := s.passwordService.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user with tenant ID
	user := &domain.User{
		TenantID:     tenantID,
		Email:        req.Email,
		PasswordHash: passwordHash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Metadata:     req.Metadata,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Record password in history for compliance
	if err := s.passwordHistoryService.RecordPassword(ctx, tenantID, user.ID, passwordHash); err != nil {
		s.logger.Error("Failed to record password history", "error", err, "user_id", user.ID, "tenant_id", tenantID)
	}

	// Generate email verification token
	verificationToken, err := GenerateEmailVerificationToken(tenantID, user.Email, user.ID, s.otpRepo)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Send verification email
	if err := s.emailService.SendVerificationEmail(user.Email, verificationToken.Token); err != nil {
		// Log error but don't fail registration
		s.logger.Error("Failed to send verification email", "error", err, "email", user.Email, "tenant_id", tenantID)
	}

	// Audit log successful registration
	_ = s.auditService.LogUserAction(ctx, tenantID, user.ID, nil, domain.AuditActionRegister, domain.AuditStatusSuccess, map[string]interface{}{
		"email": user.Email,
	})

	return &authv1.RegisterResponse{
		UserId:        user.ID.String(),
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Message:       "Registration successful. Please check your email to verify your account.",
	}, nil
}

// Login authenticates a user
func (s *AuthService) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	ipAddress := IPAddressFromContext(ctx)

	// Check if login is allowed (brute force protection)
	if err := s.loginProtectionService.CheckLoginAllowed(ctx, tenantID, req.Email, ipAddress); err != nil {
		_ = s.auditService.LogAction(ctx, tenantID, domain.AuditActionLogin, domain.AuditResourceUser, req.Email, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "rate_limited",
			"email":  req.Email,
		})
		return nil, err
	}

	// Get user by email
	user, err := s.userRepo.GetByEmail(tenantID, req.Email)
	if err != nil {
		// Record failed login attempt
		_ = s.loginProtectionService.RecordLoginAttempt(ctx, tenantID, req.Email, ipAddress, nil, false, "user_not_found")
		_ = s.auditService.LogAction(ctx, tenantID, domain.AuditActionLogin, domain.AuditResourceUser, req.Email, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "invalid_credentials",
			"email":  req.Email,
		})
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if account is locked
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		_ = s.loginProtectionService.RecordLoginAttempt(ctx, tenantID, req.Email, ipAddress, &user.ID, false, "account_locked")
		_ = s.auditService.LogUserAction(ctx, tenantID, user.ID, nil, domain.AuditActionLogin, domain.AuditStatusFailure, map[string]interface{}{
			"reason":       "account_locked",
			"locked_until": user.LockedUntil,
		})
		return nil, fmt.Errorf("account is temporarily locked, please try again later")
	}

	// Verify password
	if err := s.passwordService.VerifyPassword(user.PasswordHash, req.Password); err != nil {
		// Record failed login attempt
		_ = s.loginProtectionService.RecordLoginAttempt(ctx, tenantID, req.Email, ipAddress, &user.ID, false, "invalid_password")
		_ = s.auditService.LogUserAction(ctx, tenantID, user.ID, nil, domain.AuditActionLogin, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "invalid_password",
		})
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if 2FA is enabled
	if user.TwoFactorEnabled {
		if req.TotpCode == "" {
			// Create a pending session
			sessionID := uuid.New()
			return &authv1.LoginResponse{
				Requires_2Fa: true,
				SessionId:    sessionID.String(),
			}, nil
		}

		// Verify TOTP code
		if !s.totpService.ValidateCode(user.TwoFactorSecret, req.TotpCode) {
			// Check backup codes
			if err := s.userRepo.UseBackupCode(tenantID, user.ID, req.TotpCode); err != nil {
				_ = s.loginProtectionService.RecordLoginAttempt(ctx, tenantID, req.Email, ipAddress, &user.ID, false, "invalid_2fa_code")
				_ = s.auditService.LogUserAction(ctx, tenantID, user.ID, nil, domain.AuditActionLogin, domain.AuditStatusFailure, map[string]interface{}{
					"reason": "invalid_2fa_code",
				})
				return nil, fmt.Errorf("invalid 2FA code")
			}
		}
	}

	// Check if user must change password
	if user.MustChangePassword {
		_ = s.auditService.LogUserAction(ctx, tenantID, user.ID, nil, domain.AuditActionLogin, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "password_change_required",
		})
		return nil, fmt.Errorf("password change required before proceeding")
	}

	// Check max concurrent sessions
	if s.sessionConfig.MaxConcurrentSessions > 0 {
		activeSessions, err := s.sessionRepo.CountActiveSessions(tenantID, user.ID)
		if err == nil && activeSessions >= int64(s.sessionConfig.MaxConcurrentSessions) {
			// Revoke oldest session to make room
			sessions, _ := s.sessionRepo.GetActiveSessions(tenantID, user.ID)
			if len(sessions) > 0 {
				_ = s.sessionRepo.Revoke(tenantID, sessions[len(sessions)-1].ID)
			}
		}
	}

	// Generate tokens with tenant ID
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

	// Create session with tenant ID (idle timeout only when HIPAA compliant)
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
		LastAccessedAt: now,
	}
	// Only set idle timeout when HIPAA compliance is enabled
	if s.sessionConfig.HIPAACompliant {
		session.IdleTimeoutAt = ptrTime(now.Add(s.sessionConfig.IdleTimeout))
	}

	if err := s.sessionRepo.Create(session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Update last login and record successful login
	if err := s.userRepo.UpdateLastLogin(tenantID, user.ID); err != nil {
		s.logger.Error("Failed to update last login", "error", err, "user_id", user.ID, "tenant_id", tenantID)
	}
	_ = s.loginProtectionService.RecordLoginAttempt(ctx, tenantID, req.Email, ipAddress, &user.ID, true, "")

	// Audit log successful login
	_ = s.auditService.LogUserAction(ctx, tenantID, user.ID, nil, domain.AuditActionLogin, domain.AuditStatusSuccess, map[string]interface{}{
		"session_id": session.ID.String(),
		"device_id":  req.DeviceId,
	})

	return &authv1.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(15 * 60), // 15 minutes in seconds
		User:         s.userToProto(user),
		SessionId:    session.ID.String(),
	}, nil
}

// ptrTime returns a pointer to a time value
func ptrTime(t time.Time) *time.Time {
	return &t
}

// RefreshToken refreshes an access token
func (s *AuthService) RefreshToken(ctx context.Context, req *authv1.RefreshTokenRequest) (*authv1.RefreshTokenResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	// Get session by refresh token
	session, err := s.sessionRepo.GetByRefreshToken(tenantID, req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Check if session is active
	if !session.IsActive() {
		_ = s.auditService.LogSessionAction(ctx, tenantID, session.ID, session.UserID, domain.AuditActionTokenRefresh, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "session_expired_or_revoked",
		})
		return nil, fmt.Errorf("session expired or revoked")
	}

	// Check idle timeout only when HIPAA compliance mode is enabled
	if s.sessionConfig.HIPAACompliant && session.IdleTimeoutAt != nil && session.IdleTimeoutAt.Before(time.Now()) {
		// Session has timed out due to inactivity
		_ = s.sessionRepo.Revoke(tenantID, session.ID)
		_ = s.auditService.LogSessionAction(ctx, tenantID, session.ID, session.UserID, domain.AuditActionTokenRefresh, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "idle_timeout",
		})
		return nil, fmt.Errorf("session timed out due to inactivity")
	}

	// Get user
	user, err := s.userRepo.GetByID(tenantID, session.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Generate new tokens with tenant ID
	accessToken, err := s.jwtService.GenerateAccessToken(user.ID, user.Email, map[string]string{
		"tenant_id": tenantID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	newRefreshToken, err := s.jwtService.GenerateRefreshToken(user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Update session with new refresh token (reset idle timeout only when HIPAA compliant)
	now := time.Now()
	session.RefreshToken = newRefreshToken
	session.ExpiresAt = now.Add(s.sessionConfig.SessionExpiry)
	session.LastAccessedAt = now
	// Only update idle timeout when HIPAA compliance is enabled
	if s.sessionConfig.HIPAACompliant {
		session.IdleTimeoutAt = ptrTime(now.Add(s.sessionConfig.IdleTimeout))
	}
	if err := s.sessionRepo.Update(session); err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	// Audit log token refresh
	_ = s.auditService.LogSessionAction(ctx, tenantID, session.ID, session.UserID, domain.AuditActionTokenRefresh, domain.AuditStatusSuccess, nil)

	return &authv1.RefreshTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(15 * 60), // 15 minutes in seconds
	}, nil
}

// Logout logs out a user
func (s *AuthService) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	sessionID, err := uuid.Parse(req.SessionId)
	if err != nil {
		return nil, fmt.Errorf("invalid session ID")
	}

	// Get session first for audit log
	session, _ := s.sessionRepo.GetByID(tenantID, sessionID)

	if err := s.sessionRepo.Revoke(tenantID, sessionID); err != nil {
		return nil, fmt.Errorf("failed to logout: %w", err)
	}

	// Audit log logout
	if session != nil {
		_ = s.auditService.LogUserAction(ctx, tenantID, session.UserID, nil, domain.AuditActionLogout, domain.AuditStatusSuccess, map[string]interface{}{
			"session_id": sessionID.String(),
		})
	}

	return &authv1.LogoutResponse{
		Success: true,
		Message: "Logged out successfully",
	}, nil
}

// ChangePassword changes a user's password
func (s *AuthService) ChangePassword(ctx context.Context, req *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	// Get user
	user, err := s.userRepo.GetByID(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Verify current password
	if err := s.passwordService.VerifyPassword(user.PasswordHash, req.CurrentPassword); err != nil {
		_ = s.auditService.LogUserAction(ctx, tenantID, userID, nil, domain.AuditActionPasswordChange, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "invalid_current_password",
		})
		return nil, fmt.Errorf("invalid current password")
	}

	// Validate new password strength
	if err := s.passwordService.ValidatePasswordStrength(req.NewPassword); err != nil {
		_ = s.auditService.LogUserAction(ctx, tenantID, userID, nil, domain.AuditActionPasswordChange, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "password_validation_failed",
		})
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	// Check password history for compliance (prevent reuse)
	if err := s.passwordHistoryService.CheckPasswordReuse(ctx, tenantID, userID, req.NewPassword); err != nil {
		_ = s.auditService.LogUserAction(ctx, tenantID, userID, nil, domain.AuditActionPasswordChange, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "password_reuse_detected",
		})
		return nil, err
	}

	// Hash new password
	newPasswordHash, err := s.passwordService.HashPassword(req.NewPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	if err := s.userRepo.UpdatePassword(tenantID, userID, newPasswordHash); err != nil {
		return nil, fmt.Errorf("failed to update password: %w", err)
	}

	// Record password in history for compliance
	if err := s.passwordHistoryService.RecordPassword(ctx, tenantID, userID, newPasswordHash); err != nil {
		s.logger.Error("Failed to record password history after password change", "error", err, "user_id", userID, "tenant_id", tenantID)
	}

	// Revoke all sessions except current one
	if err := s.sessionRepo.RevokeAllUserSessions(tenantID, userID); err != nil {
		s.logger.Error("Failed to revoke sessions after password change", "error", err, "user_id", userID, "tenant_id", tenantID)
	}

	// Audit log successful password change
	_ = s.auditService.LogUserAction(ctx, tenantID, userID, nil, domain.AuditActionPasswordChange, domain.AuditStatusSuccess, nil)

	return &authv1.ChangePasswordResponse{
		Success: true,
		Message: "Password changed successfully",
	}, nil
}

// ForgotPassword initiates password reset
func (s *AuthService) ForgotPassword(ctx context.Context, req *authv1.ForgotPasswordRequest) (*authv1.ForgotPasswordResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	// Get user
	user, err := s.userRepo.GetByEmail(tenantID, req.Email)
	if err != nil {
		// Audit log the attempt (but don't reveal if user exists)
		_ = s.auditService.LogAction(ctx, tenantID, domain.AuditActionPasswordResetRequest, domain.AuditResourceUser, req.Email, domain.AuditStatusSuccess, map[string]interface{}{
			"email":      req.Email,
			"user_found": false,
		})
		// Don't reveal if user exists or not
		return &authv1.ForgotPasswordResponse{
			Success: true,
			Message: "If an account with that email exists, a password reset link has been sent.",
		}, nil
	}

	// Generate password reset token
	resetToken, err := GeneratePasswordResetToken(tenantID, user.Email, user.ID, s.otpRepo)
	if err != nil {
		return nil, fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Send password reset email
	if err := s.emailService.SendPasswordResetEmail(user.Email, resetToken.Token); err != nil {
		s.logger.Error("Failed to send password reset email", "error", err, "email", user.Email, "tenant_id", tenantID)
	}

	// Audit log password reset request
	_ = s.auditService.LogUserAction(ctx, tenantID, user.ID, nil, domain.AuditActionPasswordResetRequest, domain.AuditStatusSuccess, nil)

	return &authv1.ForgotPasswordResponse{
		Success: true,
		Message: "If an account with that email exists, a password reset link has been sent.",
	}, nil
}

// ResetPassword resets a user's password
func (s *AuthService) ResetPassword(ctx context.Context, req *authv1.ResetPasswordRequest) (*authv1.ResetPasswordResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	// Verify token
	otp, err := s.otpRepo.GetByToken(tenantID, req.Token)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token")
	}

	if otp.Type != domain.OTPTypePasswordReset {
		return nil, fmt.Errorf("invalid token type")
	}

	// Validate new password strength
	if err := s.passwordService.ValidatePasswordStrength(req.NewPassword); err != nil {
		_ = s.auditService.LogUserAction(ctx, tenantID, otp.UserID, nil, domain.AuditActionPasswordReset, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "password_validation_failed",
		})
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	// Check password history for compliance (prevent reuse)
	if err := s.passwordHistoryService.CheckPasswordReuse(ctx, tenantID, otp.UserID, req.NewPassword); err != nil {
		_ = s.auditService.LogUserAction(ctx, tenantID, otp.UserID, nil, domain.AuditActionPasswordReset, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "password_reuse_detected",
		})
		return nil, err
	}

	// Hash new password
	newPasswordHash, err := s.passwordService.HashPassword(req.NewPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	if err := s.userRepo.UpdatePassword(tenantID, otp.UserID, newPasswordHash); err != nil {
		return nil, fmt.Errorf("failed to update password: %w", err)
	}

	// Record password in history for compliance
	if err := s.passwordHistoryService.RecordPassword(ctx, tenantID, otp.UserID, newPasswordHash); err != nil {
		s.logger.Error("Failed to record password history after password reset", "error", err, "user_id", otp.UserID, "tenant_id", tenantID)
	}

	// Mark token as used
	if err := s.otpRepo.MarkAsUsed(tenantID, otp.ID); err != nil {
		s.logger.Error("Failed to mark password reset token as used", "error", err, "otp_id", otp.ID, "tenant_id", tenantID)
	}

	// Revoke all sessions
	if err := s.sessionRepo.RevokeAllUserSessions(tenantID, otp.UserID); err != nil {
		s.logger.Error("Failed to revoke sessions after password reset", "error", err, "user_id", otp.UserID, "tenant_id", tenantID)
	}

	// Audit log successful password reset
	_ = s.auditService.LogUserAction(ctx, tenantID, otp.UserID, nil, domain.AuditActionPasswordReset, domain.AuditStatusSuccess, nil)

	return &authv1.ResetPasswordResponse{
		Success: true,
		Message: "Password reset successfully",
	}, nil
}

// Enable2FA enables 2FA for a user
func (s *AuthService) Enable2FA(ctx context.Context, req *authv1.Enable2FARequest) (*authv1.Enable2FAResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	// Get user
	user, err := s.userRepo.GetByID(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Generate TOTP secret
	secret, qrCodeURL, err := s.totpService.GenerateSecret(user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate 2FA secret: %w", err)
	}

	// Generate backup codes
	backupCodes, err := s.totpService.GenerateBackupCodes(10)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Store backup codes
	if err := s.userRepo.CreateBackupCodes(tenantID, userID, backupCodes); err != nil {
		return nil, fmt.Errorf("failed to store backup codes: %w", err)
	}

	// Enable 2FA (secret will be stored after verification)
	if err := s.userRepo.Enable2FA(tenantID, userID, secret); err != nil {
		return nil, fmt.Errorf("failed to enable 2FA: %w", err)
	}

	// Audit log 2FA enabled
	_ = s.auditService.LogUserAction(ctx, tenantID, userID, nil, domain.AuditActionMFAEnable, domain.AuditStatusSuccess, nil)

	return &authv1.Enable2FAResponse{
		Secret:      secret,
		QrCodeUrl:   qrCodeURL,
		BackupCodes: backupCodes,
	}, nil
}

// Verify2FA verifies a 2FA code
func (s *AuthService) Verify2FA(ctx context.Context, req *authv1.Verify2FARequest) (*authv1.Verify2FAResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	// Get user
	user, err := s.userRepo.GetByID(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Verify TOTP code
	if !s.totpService.ValidateCode(user.TwoFactorSecret, req.TotpCode) {
		_ = s.auditService.LogUserAction(ctx, tenantID, userID, nil, domain.AuditActionMFAVerify, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "invalid_code",
		})
		return nil, fmt.Errorf("invalid 2FA code")
	}

	// Audit log 2FA verification
	_ = s.auditService.LogUserAction(ctx, tenantID, userID, nil, domain.AuditActionMFAVerify, domain.AuditStatusSuccess, nil)

	// If this is completing a login flow, generate tokens
	if req.SessionId != "" {
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

		return &authv1.Verify2FAResponse{
			Verified:     true,
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    int64(15 * 60),
			Message:      "2FA verified successfully",
		}, nil
	}

	return &authv1.Verify2FAResponse{
		Verified: true,
		Message:  "2FA verified successfully",
	}, nil
}

// Disable2FA disables 2FA for a user
func (s *AuthService) Disable2FA(ctx context.Context, req *authv1.Disable2FARequest) (*authv1.Disable2FAResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	// Get user
	user, err := s.userRepo.GetByID(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Verify password
	if err := s.passwordService.VerifyPassword(user.PasswordHash, req.Password); err != nil {
		_ = s.auditService.LogUserAction(ctx, tenantID, userID, nil, domain.AuditActionMFADisable, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "invalid_password",
		})
		return nil, fmt.Errorf("invalid password")
	}

	// Verify TOTP code
	if !s.totpService.ValidateCode(user.TwoFactorSecret, req.TotpCode) {
		_ = s.auditService.LogUserAction(ctx, tenantID, userID, nil, domain.AuditActionMFADisable, domain.AuditStatusFailure, map[string]interface{}{
			"reason": "invalid_2fa_code",
		})
		return nil, fmt.Errorf("invalid 2FA code")
	}

	// Disable 2FA
	if err := s.userRepo.Disable2FA(tenantID, userID); err != nil {
		return nil, fmt.Errorf("failed to disable 2FA: %w", err)
	}

	// Audit log 2FA disabled
	_ = s.auditService.LogUserAction(ctx, tenantID, userID, nil, domain.AuditActionMFADisable, domain.AuditStatusSuccess, nil)

	return &authv1.Disable2FAResponse{
		Success: true,
		Message: "2FA disabled successfully",
	}, nil
}

// Generate2FABackupCodes generates new backup codes
func (s *AuthService) Generate2FABackupCodes(ctx context.Context, req *authv1.Generate2FABackupCodesRequest) (*authv1.Generate2FABackupCodesResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	// Get user
	user, err := s.userRepo.GetByID(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Verify password
	if err := s.passwordService.VerifyPassword(user.PasswordHash, req.Password); err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	// Generate new backup codes
	backupCodes, err := s.totpService.GenerateBackupCodes(10)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Store backup codes
	if err := s.userRepo.CreateBackupCodes(tenantID, userID, backupCodes); err != nil {
		return nil, fmt.Errorf("failed to store backup codes: %w", err)
	}

	// Audit log backup codes regenerated
	_ = s.auditService.LogUserAction(ctx, tenantID, userID, nil, domain.AuditActionMFABackupGenerate, domain.AuditStatusSuccess, nil)

	return &authv1.Generate2FABackupCodesResponse{
		BackupCodes: backupCodes,
	}, nil
}

// SendPasswordlessEmail sends a passwordless login email
func (s *AuthService) SendPasswordlessEmail(ctx context.Context, req *authv1.SendPasswordlessEmailRequest) (*authv1.SendPasswordlessEmailResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	// Generate passwordless token
	token, err := s.passwordlessService.GenerateToken(tenantID, req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate passwordless token: %w", err)
	}

	// Send passwordless email
	if err := s.emailService.SendPasswordlessEmail(req.Email, token.Token); err != nil {
		return nil, fmt.Errorf("failed to send passwordless email: %w", err)
	}

	// Audit log passwordless request
	_ = s.auditService.LogAction(ctx, tenantID, domain.AuditActionPasswordlessSend, domain.AuditResourceUser, req.Email, domain.AuditStatusSuccess, nil)

	return &authv1.SendPasswordlessEmailResponse{
		Success:   true,
		Message:   "Passwordless login link sent to your email",
		ExpiresIn: int64(15 * 60), // 15 minutes
	}, nil
}

// VerifyPasswordlessToken verifies a passwordless login token
func (s *AuthService) VerifyPasswordlessToken(ctx context.Context, req *authv1.VerifyPasswordlessTokenRequest) (*authv1.VerifyPasswordlessTokenResponse, error) {
	// Extract tenant ID from context
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	ipAddress := IPAddressFromContext(ctx)

	// Verify token
	otp, err := s.passwordlessService.VerifyToken(tenantID, req.Token)
	if err != nil {
		_ = s.auditService.LogAction(ctx, tenantID, domain.AuditActionPasswordlessVerify, domain.AuditResourceUser, "", domain.AuditStatusFailure, map[string]interface{}{
			"reason": "invalid_token",
		})
		return nil, fmt.Errorf("invalid or expired token: %w", err)
	}

	// Get or create user
	user, err := s.userRepo.GetByEmail(tenantID, otp.Email)
	if err != nil {
		// Create new user with tenant ID
		user = &domain.User{
			TenantID:      tenantID,
			Email:         otp.Email,
			EmailVerified: true,
		}
		if err := s.userRepo.Create(user); err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}

		// Audit log new user registration via passwordless
		_ = s.auditService.LogUserAction(ctx, tenantID, user.ID, nil, domain.AuditActionRegister, domain.AuditStatusSuccess, map[string]interface{}{
			"method": "passwordless",
		})
	}

	// Generate tokens with tenant ID
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

	// Create session with tenant ID (idle timeout only when HIPAA compliant)
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
		LastAccessedAt: now,
	}
	// Only set idle timeout when HIPAA compliance is enabled
	if s.sessionConfig.HIPAACompliant {
		session.IdleTimeoutAt = ptrTime(now.Add(s.sessionConfig.IdleTimeout))
	}

	if err := s.sessionRepo.Create(session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Update last login
	if err := s.userRepo.UpdateLastLogin(tenantID, user.ID); err != nil {
		s.logger.Error("Failed to update last login after passwordless login", "error", err, "user_id", user.ID, "tenant_id", tenantID)
	}

	// Audit log passwordless login
	_ = s.auditService.LogUserAction(ctx, tenantID, user.ID, nil, domain.AuditActionPasswordlessVerify, domain.AuditStatusSuccess, map[string]interface{}{
		"session_id": session.ID.String(),
	})

	return &authv1.VerifyPasswordlessTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(15 * 60),
		User:         s.userToProto(user),
		SessionId:    session.ID.String(),
	}, nil
}

// Helper function to convert domain.User to proto User
func (s *AuthService) userToProto(user *domain.User) *authv1.User {
	protoUser := &authv1.User{
		Id:               user.ID.String(),
		Email:            user.Email,
		EmailVerified:    user.EmailVerified,
		FirstName:        user.FirstName,
		LastName:         user.LastName,
		PhoneNumber:      user.PhoneNumber,
		TwoFactorEnabled: user.TwoFactorEnabled,
		CreatedAt:        timestamppb.New(user.CreatedAt),
		UpdatedAt:        timestamppb.New(user.UpdatedAt),
		Metadata:         user.Metadata,
	}

	if user.LastLoginAt != nil {
		protoUser.LastLoginAt = timestamppb.New(*user.LastLoginAt)
	}

	// Convert OAuth accounts
	for _, oauth := range user.OAuthAccounts {
		protoOAuth := &authv1.OAuthAccount{
			Provider:       s.oauthProviderToProto(oauth.Provider),
			ProviderUserId: oauth.ProviderUserID,
			Email:          oauth.Email,
			LinkedAt:       timestamppb.New(oauth.LinkedAt),
		}
		protoUser.OauthAccounts = append(protoUser.OauthAccounts, protoOAuth)
	}

	return protoUser
}

// Helper function to convert OAuth provider string to proto enum
func (s *AuthService) oauthProviderToProto(provider string) authv1.OAuthProvider {
	switch provider {
	case "google":
		return authv1.OAuthProvider_OAUTH_PROVIDER_GOOGLE
	case "github":
		return authv1.OAuthProvider_OAUTH_PROVIDER_GITHUB
	case "facebook":
		return authv1.OAuthProvider_OAUTH_PROVIDER_FACEBOOK
	case "apple":
		return authv1.OAuthProvider_OAUTH_PROVIDER_APPLE
	case "microsoft":
		return authv1.OAuthProvider_OAUTH_PROVIDER_MICROSOFT
	case "discord":
		return authv1.OAuthProvider_OAUTH_PROVIDER_DISCORD
	default:
		return authv1.OAuthProvider_OAUTH_PROVIDER_UNSPECIFIED
	}
}

// ===============================================
// Compliance Methods - Account Security & Audit
// ===============================================

// RevokeAllSessions revokes all sessions for a user
func (s *AuthService) RevokeAllSessions(ctx context.Context, req *authv1.RevokeAllSessionsRequest) (*authv1.RevokeAllSessionsResponse, error) {
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	// Get current session ID from context if we need to preserve it
	var currentSessionID *uuid.UUID
	if req.ExceptCurrent {
		// Extract current session from JWT claims or context
		// For now, we'll revoke all - proper implementation would extract session from token
		currentSessionID = nil
	}

	// Get all active sessions for the user
	sessions, err := s.sessionRepo.GetActiveSessions(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active sessions: %w", err)
	}

	revokedCount := 0
	for _, session := range sessions {
		// Skip current session if requested
		if currentSessionID != nil && session.ID == *currentSessionID {
			continue
		}

		if err := s.sessionRepo.Revoke(tenantID, session.ID); err != nil {
			s.logger.Error("failed to revoke session", "session_id", session.ID, "error", err)
			continue
		}
		revokedCount++
	}

	// Audit log
	_ = s.auditService.LogUserAction(ctx, tenantID, userID, nil, domain.AuditActionSessionRevoke, domain.AuditStatusSuccess, map[string]interface{}{
		"revoked_count":  revokedCount,
		"except_current": req.ExceptCurrent,
	})

	return &authv1.RevokeAllSessionsResponse{
		Success:      true,
		Message:      fmt.Sprintf("Revoked %d sessions", revokedCount),
		RevokedCount: int32(revokedCount),
	}, nil
}

// GetAccountLockoutStatus gets the lockout status for a user account
func (s *AuthService) GetAccountLockoutStatus(ctx context.Context, req *authv1.GetAccountLockoutStatusRequest) (*authv1.GetAccountLockoutStatusResponse, error) {
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	// Get active lockout if any
	lockout, err := s.loginProtectionService.GetActiveLockout(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get lockout status: %w", err)
	}

	response := &authv1.GetAccountLockoutStatusResponse{
		IsLocked:       false,
		FailedAttempts: 0,
	}

	if lockout != nil && lockout.IsLocked() {
		response.IsLocked = true
		response.LockedAt = timestamppb.New(lockout.LockedAt)
		response.UnlocksAt = timestamppb.New(lockout.UnlocksAt)
		response.LockReason = lockout.LockReason
		response.FailedAttempts = int32(lockout.FailedCount)
	}

	return response, nil
}

// UnlockAccount manually unlocks a user account (admin action)
func (s *AuthService) UnlockAccount(ctx context.Context, req *authv1.UnlockAccountRequest) (*authv1.UnlockAccountResponse, error) {
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	// Get admin/actor ID from context if available
	var actorID *uuid.UUID
	if id := ActorIDFromContext(ctx); id != uuid.Nil {
		actorID = &id
	}

	// Unlock the account
	if err := s.loginProtectionService.UnlockAccount(ctx, tenantID, userID, actorID); err != nil {
		_ = s.auditService.LogUserAction(ctx, tenantID, userID, actorID, domain.AuditActionAccountUnlock, domain.AuditStatusFailure, map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to unlock account: %w", err)
	}

	// Audit log
	_ = s.auditService.LogUserAction(ctx, tenantID, userID, actorID, domain.AuditActionAccountUnlock, domain.AuditStatusSuccess, nil)

	return &authv1.UnlockAccountResponse{
		Success: true,
		Message: "Account unlocked successfully",
	}, nil
}

// GetLoginHistory gets the login history for a user
func (s *AuthService) GetLoginHistory(ctx context.Context, req *authv1.GetLoginHistoryRequest) (*authv1.GetLoginHistoryResponse, error) {
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	// Build filter for audit logs
	loginAction := domain.AuditActionLogin
	filter := repository.AuditLogFilter{
		TenantID: tenantID,
		UserID:   &userID,
		Action:   &loginAction,
		Limit:    int(req.Limit),
		Offset:   int(req.Offset),
	}

	if req.Limit == 0 {
		filter.Limit = 50 // Default limit
	}
	if filter.Limit > 100 {
		filter.Limit = 100 // Max limit
	}

	if req.StartTime != nil {
		t := req.StartTime.AsTime()
		filter.StartTime = &t
	}
	if req.EndTime != nil {
		t := req.EndTime.AsTime()
		filter.EndTime = &t
	}

	// Query audit logs for login attempts
	logs, total, err := s.auditService.Query(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get login history: %w", err)
	}

	// Convert to proto format
	attempts := make([]*authv1.LoginAttempt, 0, len(logs))
	for _, log := range logs {
		attempt := &authv1.LoginAttempt{
			Id:          log.ID.String(),
			IpAddress:   log.IPAddress,
			UserAgent:   log.UserAgent,
			Success:     log.Status == domain.AuditStatusSuccess,
			AttemptedAt: timestamppb.New(log.CreatedAt),
		}

		// Get email from user if available
		if log.UserID != nil {
			user, _ := s.userRepo.GetByID(tenantID, *log.UserID)
			if user != nil {
				attempt.Email = user.Email
			}
		}

		if log.Status == domain.AuditStatusFailure && log.FailureReason != "" {
			attempt.FailureReason = log.FailureReason
		}

		attempts = append(attempts, attempt)
	}

	return &authv1.GetLoginHistoryResponse{
		Attempts: attempts,
		Total:    total,
	}, nil
}

// GetAuditLogs retrieves audit logs with filtering (HIPAA/SOC 2/GDPR compliance)
func (s *AuthService) GetAuditLogs(ctx context.Context, req *authv1.GetAuditLogsRequest) (*authv1.GetAuditLogsResponse, error) {
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant context required: %w", err)
	}

	// Build filter
	filter := repository.AuditLogFilter{
		TenantID: tenantID,
		Limit:    int(req.Limit),
		Offset:   int(req.Offset),
	}

	if req.Limit == 0 {
		filter.Limit = 50 // Default limit
	}
	if filter.Limit > 100 {
		filter.Limit = 100 // Max limit
	}

	// Optional user filter
	if req.UserId != "" {
		userID, err := uuid.Parse(req.UserId)
		if err != nil {
			return nil, fmt.Errorf("invalid user ID: %w", err)
		}
		filter.UserID = &userID
	}

	// Optional action filter
	if req.Action != "" {
		action := domain.AuditAction(req.Action)
		filter.Action = &action
	}

	// Time range filters
	if req.StartTime != nil {
		t := req.StartTime.AsTime()
		filter.StartTime = &t
	}
	if req.EndTime != nil {
		t := req.EndTime.AsTime()
		filter.EndTime = &t
	}

	// Query audit logs
	logs, total, err := s.auditService.Query(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs: %w", err)
	}

	// Convert to proto format
	protoLogs := make([]*authv1.AuditLog, 0, len(logs))
	for _, log := range logs {
		protoLog := &authv1.AuditLog{
			Id:            log.ID.String(),
			TenantId:      log.TenantID.String(),
			Action:        string(log.Action),
			ResourceType:  string(log.ResourceType),
			ResourceId:    log.ResourceID,
			Status:        string(log.Status),
			FailureReason: log.FailureReason,
			IpAddress:     log.IPAddress,
			UserAgent:     log.UserAgent,
			CreatedAt:     timestamppb.New(log.CreatedAt),
		}

		if log.UserID != nil {
			protoLog.UserId = log.UserID.String()
		}
		if log.ActorID != nil {
			protoLog.ActorId = log.ActorID.String()
		}

		// Convert metadata to map[string]string
		if log.Metadata != nil {
			protoLog.Metadata = make(map[string]string)
			for k, v := range log.Metadata {
				if strVal, ok := v.(string); ok {
					protoLog.Metadata[k] = strVal
				} else {
					protoLog.Metadata[k] = fmt.Sprintf("%v", v)
				}
			}
		}

		protoLogs = append(protoLogs, protoLog)
	}

	return &authv1.GetAuditLogsResponse{
		Logs:  protoLogs,
		Total: total,
	}, nil
}

// ActorIDFromContext extracts actor ID from context (for admin operations)
func ActorIDFromContext(ctx context.Context) uuid.UUID {
	if actorID, ok := ctx.Value(ActorContextKey{}).(uuid.UUID); ok {
		return actorID
	}
	return uuid.Nil
}

// ActorContextKey is the context key for actor ID
type ActorContextKey struct{}
