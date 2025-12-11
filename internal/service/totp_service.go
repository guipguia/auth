package service

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"

	"github.com/pquerna/otp/totp"
)

// TOTPService handles TOTP (Time-based One-Time Password) operations
type TOTPService interface {
	GenerateSecret(email string) (secret string, qrCodeURL string, err error)
	ValidateCode(secret, code string) bool
	GenerateBackupCodes(count int) ([]string, error)
}

type totpService struct {
	issuer string
}

// NewTOTPService creates a new TOTP service
func NewTOTPService() TOTPService {
	return &totpService{
		issuer: "Auth Service",
	}
}

// GenerateSecret generates a new TOTP secret and QR code URL
func (s *totpService) GenerateSecret(email string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: email,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	secret := key.Secret()
	qrCodeURL := s.generateQRCodeURL(email, secret)

	return secret, qrCodeURL, nil
}

// ValidateCode validates a TOTP code against a secret
func (s *totpService) ValidateCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// GenerateBackupCodes generates backup codes for 2FA recovery
func (s *totpService) GenerateBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		code, err := s.generateRandomCode(8)
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		// Format as XXXX-XXXX for better readability
		codes[i] = fmt.Sprintf("%s-%s", code[:4], code[4:])
	}
	return codes, nil
}

// generateRandomCode generates a random alphanumeric code
func (s *totpService) generateRandomCode(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	encoded := base32.StdEncoding.EncodeToString(bytes)
	if len(encoded) > length {
		encoded = encoded[:length]
	}

	return encoded, nil
}

// generateQRCodeURL generates a URL for the QR code
func (s *totpService) generateQRCodeURL(email, secret string) string {
	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", s.issuer)

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     fmt.Sprintf("/%s:%s", s.issuer, email),
		RawQuery: params.Encode(),
	}

	return u.String()
}
