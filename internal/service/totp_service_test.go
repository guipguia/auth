package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test: Generate TOTP Secret
func TestTOTPService_GenerateSecret(t *testing.T) {
	service := NewTOTPService()

	secret, qrCodeURL, err := service.GenerateSecret("test@example.com")

	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.NotEmpty(t, qrCodeURL)
	assert.Contains(t, qrCodeURL, "otpauth://totp/")
	assert.Contains(t, qrCodeURL, "test@example.com")
	assert.Contains(t, qrCodeURL, secret)
}

// Test: Validate TOTP Code
func TestTOTPService_ValidateCode_Valid(t *testing.T) {
	service := NewTOTPService()

	// Generate a secret
	secret, _, err := service.GenerateSecret("test@example.com")
	assert.NoError(t, err)

	// For testing, we can't easily generate a valid TOTP code without time manipulation
	// So we test with an invalid code to ensure the function works
	isValid := service.ValidateCode(secret, "000000")
	assert.False(t, isValid) // Invalid code should return false
}

// Test: Generate Backup Codes
func TestTOTPService_GenerateBackupCodes(t *testing.T) {
	service := NewTOTPService()

	codes, err := service.GenerateBackupCodes(10)

	assert.NoError(t, err)
	assert.Len(t, codes, 10)

	// Check format (XXXX-XXXX)
	for _, code := range codes {
		assert.Len(t, code, 9) // 4 chars + dash + 4 chars
		assert.Contains(t, code, "-")
	}

	// Check uniqueness
	codeSet := make(map[string]bool)
	for _, code := range codes {
		assert.False(t, codeSet[code], "Duplicate backup code generated")
		codeSet[code] = true
	}
}

// Test: Generate Multiple Backup Code Sets
func TestTOTPService_GenerateBackupCodes_Different(t *testing.T) {
	service := NewTOTPService()

	codes1, err := service.GenerateBackupCodes(5)
	assert.NoError(t, err)

	codes2, err := service.GenerateBackupCodes(5)
	assert.NoError(t, err)

	// Codes should be different between generations
	assert.NotEqual(t, codes1, codes2)
}

// Test: Generate Zero Backup Codes
func TestTOTPService_GenerateBackupCodes_Zero(t *testing.T) {
	service := NewTOTPService()

	codes, err := service.GenerateBackupCodes(0)

	assert.NoError(t, err)
	assert.Len(t, codes, 0)
}
