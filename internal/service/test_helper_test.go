package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/guipguia/auth/internal/domain"
	"github.com/guipguia/auth/internal/repository"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

// MockUserRepository is a mock implementation of UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(user *domain.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByID(tenantID, id uuid.UUID) (*domain.User, error) {
	args := m.Called(tenantID, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(tenantID uuid.UUID, email string) (*domain.User, error) {
	args := m.Called(tenantID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) Update(user *domain.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(tenantID, id uuid.UUID) error {
	args := m.Called(tenantID, id)
	return args.Error(0)
}

func (m *MockUserRepository) UpdatePassword(tenantID, userID uuid.UUID, passwordHash string) error {
	args := m.Called(tenantID, userID, passwordHash)
	return args.Error(0)
}

func (m *MockUserRepository) VerifyEmail(tenantID, userID uuid.UUID) error {
	args := m.Called(tenantID, userID)
	return args.Error(0)
}

func (m *MockUserRepository) Enable2FA(tenantID, userID uuid.UUID, secret string) error {
	args := m.Called(tenantID, userID, secret)
	return args.Error(0)
}

func (m *MockUserRepository) Disable2FA(tenantID, userID uuid.UUID) error {
	args := m.Called(tenantID, userID)
	return args.Error(0)
}

func (m *MockUserRepository) UpdateLastLogin(tenantID, userID uuid.UUID) error {
	args := m.Called(tenantID, userID)
	return args.Error(0)
}

func (m *MockUserRepository) IncrementFailedLogin(tenantID, userID uuid.UUID) error {
	args := m.Called(tenantID, userID)
	return args.Error(0)
}

func (m *MockUserRepository) ResetFailedLogin(tenantID, userID uuid.UUID) error {
	args := m.Called(tenantID, userID)
	return args.Error(0)
}

func (m *MockUserRepository) LockAccount(tenantID, userID uuid.UUID, until time.Time) error {
	args := m.Called(tenantID, userID, until)
	return args.Error(0)
}

func (m *MockUserRepository) UnlockAccount(tenantID, userID uuid.UUID) error {
	args := m.Called(tenantID, userID)
	return args.Error(0)
}

func (m *MockUserRepository) SetMustChangePassword(tenantID, userID uuid.UUID, mustChange bool) error {
	args := m.Called(tenantID, userID, mustChange)
	return args.Error(0)
}

func (m *MockUserRepository) UpdatePasswordChangedAt(tenantID, userID uuid.UUID) error {
	args := m.Called(tenantID, userID)
	return args.Error(0)
}

func (m *MockUserRepository) CreateBackupCodes(tenantID, userID uuid.UUID, codes []string) error {
	args := m.Called(tenantID, userID, codes)
	return args.Error(0)
}

func (m *MockUserRepository) GetBackupCodes(tenantID, userID uuid.UUID) ([]domain.BackupCode, error) {
	args := m.Called(tenantID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.BackupCode), args.Error(1)
}

func (m *MockUserRepository) UseBackupCode(tenantID, userID uuid.UUID, code string) error {
	args := m.Called(tenantID, userID, code)
	return args.Error(0)
}

func (m *MockUserRepository) CreateOAuthAccount(account *domain.OAuthAccount) error {
	args := m.Called(account)
	return args.Error(0)
}

func (m *MockUserRepository) GetOAuthAccount(tenantID uuid.UUID, provider, providerUserID string) (*domain.OAuthAccount, error) {
	args := m.Called(tenantID, provider, providerUserID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OAuthAccount), args.Error(1)
}

func (m *MockUserRepository) GetOAuthAccountsByUserID(tenantID, userID uuid.UUID) ([]domain.OAuthAccount, error) {
	args := m.Called(tenantID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.OAuthAccount), args.Error(1)
}

func (m *MockUserRepository) DeleteOAuthAccount(tenantID, userID uuid.UUID, provider string) error {
	args := m.Called(tenantID, userID, provider)
	return args.Error(0)
}

// MockSessionRepository is a mock implementation of SessionRepository
type MockSessionRepository struct {
	mock.Mock
}

func (m *MockSessionRepository) Create(session *domain.Session) error {
	args := m.Called(session)
	return args.Error(0)
}

func (m *MockSessionRepository) GetByID(tenantID, id uuid.UUID) (*domain.Session, error) {
	args := m.Called(tenantID, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Session), args.Error(1)
}

func (m *MockSessionRepository) GetByRefreshToken(tenantID uuid.UUID, token string) (*domain.Session, error) {
	args := m.Called(tenantID, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Session), args.Error(1)
}

func (m *MockSessionRepository) GetActiveSessions(tenantID, userID uuid.UUID) ([]domain.Session, error) {
	args := m.Called(tenantID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Session), args.Error(1)
}

func (m *MockSessionRepository) Update(session *domain.Session) error {
	args := m.Called(session)
	return args.Error(0)
}

func (m *MockSessionRepository) Revoke(tenantID, sessionID uuid.UUID) error {
	args := m.Called(tenantID, sessionID)
	return args.Error(0)
}

func (m *MockSessionRepository) RevokeAllUserSessions(tenantID, userID uuid.UUID) error {
	args := m.Called(tenantID, userID)
	return args.Error(0)
}

func (m *MockSessionRepository) RevokeAllUserSessionsExcept(tenantID, userID, exceptSessionID uuid.UUID) error {
	args := m.Called(tenantID, userID, exceptSessionID)
	return args.Error(0)
}

func (m *MockSessionRepository) DeleteExpired() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockSessionRepository) UpdateLastAccessed(tenantID, sessionID uuid.UUID) error {
	args := m.Called(tenantID, sessionID)
	return args.Error(0)
}

func (m *MockSessionRepository) CountActiveSessions(tenantID, userID uuid.UUID) (int64, error) {
	args := m.Called(tenantID, userID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockSessionRepository) GetOldestSession(tenantID, userID uuid.UUID) (*domain.Session, error) {
	args := m.Called(tenantID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Session), args.Error(1)
}

// MockEmailService is a mock implementation of EmailService
type MockEmailService struct {
	mock.Mock
}

func (m *MockEmailService) SendVerificationEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

func (m *MockEmailService) SendPasswordResetEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

func (m *MockEmailService) SendMagicLinkEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

func (m *MockEmailService) Send2FACode(to, code string) error {
	args := m.Called(to, code)
	return args.Error(0)
}

func (m *MockEmailService) SendPasswordlessEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

func (m *MockEmailService) SendWelcomeEmail(to, name string) error {
	args := m.Called(to, name)
	return args.Error(0)
}

// MockOTPRepository is a mock implementation of OTPRepository
type MockOTPRepository struct {
	mock.Mock
}

func (m *MockOTPRepository) Create(otp *domain.OTP) error {
	args := m.Called(otp)
	return args.Error(0)
}

func (m *MockOTPRepository) GetByToken(tenantID uuid.UUID, token string) (*domain.OTP, error) {
	args := m.Called(tenantID, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OTP), args.Error(1)
}

func (m *MockOTPRepository) GetByEmailAndType(tenantID uuid.UUID, email string, otpType domain.OTPType) (*domain.OTP, error) {
	args := m.Called(tenantID, email, otpType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OTP), args.Error(1)
}

func (m *MockOTPRepository) MarkAsUsed(tenantID, id uuid.UUID) error {
	args := m.Called(tenantID, id)
	return args.Error(0)
}

func (m *MockOTPRepository) DeleteExpired() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockOTPRepository) DeleteByUserAndType(tenantID, userID uuid.UUID, otpType domain.OTPType) error {
	args := m.Called(tenantID, userID, otpType)
	return args.Error(0)
}

// MockPasswordService is a mock implementation of PasswordService
type MockPasswordService struct {
	mock.Mock
}

func (m *MockPasswordService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *MockPasswordService) VerifyPassword(hash, password string) error {
	args := m.Called(hash, password)
	return args.Error(0)
}

func (m *MockPasswordService) ValidatePasswordStrength(password string) error {
	args := m.Called(password)
	return args.Error(0)
}

// MockJWTService is a mock implementation of JWTService
type MockJWTService struct {
	mock.Mock
}

func (m *MockJWTService) GenerateAccessToken(tenantID, userID uuid.UUID, email string, claims map[string]string) (string, error) {
	args := m.Called(tenantID, userID, email, claims)
	return args.String(0), args.Error(1)
}

func (m *MockJWTService) GenerateRefreshToken(tenantID, userID uuid.UUID, email string) (string, error) {
	args := m.Called(tenantID, userID, email)
	return args.String(0), args.Error(1)
}

func (m *MockJWTService) ValidateToken(token string, tokenType TokenType) (*Claims, error) {
	args := m.Called(token, tokenType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Claims), args.Error(1)
}

func (m *MockJWTService) ParseToken(token string) (*Claims, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Claims), args.Error(1)
}

// MockTOTPService is a mock implementation of TOTPService
type MockTOTPService struct {
	mock.Mock
}

func (m *MockTOTPService) GenerateSecret(email string) (string, string, error) {
	args := m.Called(email)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockTOTPService) ValidateCode(secret, code string) bool {
	args := m.Called(secret, code)
	return args.Bool(0)
}

func (m *MockTOTPService) GenerateBackupCodes(count int) ([]string, error) {
	args := m.Called(count)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

// MockPasswordlessService is a mock implementation of PasswordlessService
type MockPasswordlessService struct {
	mock.Mock
}

func (m *MockPasswordlessService) GenerateToken(tenantID uuid.UUID, email string) (*domain.OTP, error) {
	args := m.Called(tenantID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OTP), args.Error(1)
}

func (m *MockPasswordlessService) VerifyToken(tenantID uuid.UUID, token string) (*domain.OTP, error) {
	args := m.Called(tenantID, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OTP), args.Error(1)
}

// MockOAuthService is a mock implementation of OAuthService
type MockOAuthService struct {
	mock.Mock
}

func (m *MockOAuthService) GetAuthURL(provider OAuthProvider, state string) (string, error) {
	args := m.Called(provider, state)
	return args.String(0), args.Error(1)
}

func (m *MockOAuthService) ExchangeCode(provider OAuthProvider, code string) (*oauth2.Token, error) {
	args := m.Called(provider, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*oauth2.Token), args.Error(1)
}

func (m *MockOAuthService) GetUserInfo(provider OAuthProvider, token *oauth2.Token) (*OAuthUserInfo, error) {
	args := m.Called(provider, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*OAuthUserInfo), args.Error(1)
}

func (m *MockOAuthService) GenerateState() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

// MockAuditService is a mock implementation of AuditService
type MockAuditService struct {
	mock.Mock
}

func (m *MockAuditService) Log(ctx context.Context, log *domain.AuditLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockAuditService) LogBatch(ctx context.Context, logs []*domain.AuditLog) error {
	args := m.Called(ctx, logs)
	return args.Error(0)
}

func (m *MockAuditService) LogAction(ctx context.Context, tenantID uuid.UUID, action domain.AuditAction, resourceType domain.AuditResourceType, resourceID, resourceName string, status domain.AuditStatus, metadata domain.JSONMap) error {
	args := m.Called(ctx, tenantID, action, resourceType, resourceID, resourceName, status, metadata)
	return args.Error(0)
}

func (m *MockAuditService) Query(ctx context.Context, filter repository.AuditLogFilter) ([]domain.AuditLog, int64, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]domain.AuditLog), args.Get(1).(int64), args.Error(2)
}

// MockLoginProtectionService is a mock implementation of LoginProtectionService
type MockLoginProtectionService struct {
	mock.Mock
}

func (m *MockLoginProtectionService) RecordLoginAttempt(ctx context.Context, tenantID uuid.UUID, email, ipAddress, userAgent string, success bool, failureReason string) error {
	args := m.Called(ctx, tenantID, email, ipAddress, userAgent, success, failureReason)
	return args.Error(0)
}

func (m *MockLoginProtectionService) CheckAccountLockout(ctx context.Context, tenantID uuid.UUID, email string) (*domain.AccountLockout, error) {
	args := m.Called(ctx, tenantID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.AccountLockout), args.Error(1)
}

func (m *MockLoginProtectionService) GetLockoutStatus(ctx context.Context, tenantID, userID uuid.UUID) (*domain.AccountLockout, error) {
	args := m.Called(ctx, tenantID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.AccountLockout), args.Error(1)
}

func (m *MockLoginProtectionService) UnlockAccount(ctx context.Context, tenantID, userID uuid.UUID) error {
	args := m.Called(ctx, tenantID, userID)
	return args.Error(0)
}

func (m *MockLoginProtectionService) GetLoginHistory(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) ([]domain.LoginAttempt, int64, error) {
	args := m.Called(ctx, tenantID, userID, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]domain.LoginAttempt), args.Get(1).(int64), args.Error(2)
}

// MockPasswordHistoryService is a mock implementation of PasswordHistoryService
type MockPasswordHistoryService struct {
	mock.Mock
}

func (m *MockPasswordHistoryService) AddToHistory(ctx context.Context, tenantID, userID uuid.UUID, passwordHash string) error {
	args := m.Called(ctx, tenantID, userID, passwordHash)
	return args.Error(0)
}

func (m *MockPasswordHistoryService) CheckPasswordReuse(ctx context.Context, tenantID, userID uuid.UUID, newPassword string) error {
	args := m.Called(ctx, tenantID, userID, newPassword)
	return args.Error(0)
}

func (m *MockPasswordHistoryService) GetPasswordExpirationStatus(ctx context.Context, tenantID, userID uuid.UUID) (bool, *time.Time, error) {
	args := m.Called(ctx, tenantID, userID)
	if args.Get(1) == nil {
		return args.Bool(0), nil, args.Error(2)
	}
	return args.Bool(0), args.Get(1).(*time.Time), args.Error(2)
}
