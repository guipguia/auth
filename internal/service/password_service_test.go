package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test: Hash and Verify Password Success
func TestPasswordService_HashAndVerify_Success(t *testing.T) {
	service := NewPasswordService()
	password := "SecurePassword123!"

	// Hash password
	hash, err := service.HashPassword(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, password, hash)

	// Verify correct password
	err = service.VerifyPassword(hash, password)
	assert.NoError(t, err)
}

// Test: Verify Password with Wrong Password
func TestPasswordService_VerifyPassword_WrongPassword(t *testing.T) {
	service := NewPasswordService()
	password := "SecurePassword123!"

	// Hash password
	hash, err := service.HashPassword(password)
	assert.NoError(t, err)

	// Try to verify with wrong password
	err = service.VerifyPassword(hash, "WrongPassword456!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid password")
}

// Test: Hash Password Generates Different Hashes
func TestPasswordService_HashPassword_DifferentHashes(t *testing.T) {
	service := NewPasswordService()
	password := "SecurePassword123!"

	// Hash the same password twice
	hash1, err := service.HashPassword(password)
	assert.NoError(t, err)

	hash2, err := service.HashPassword(password)
	assert.NoError(t, err)

	// Hashes should be different (bcrypt uses salt)
	assert.NotEqual(t, hash1, hash2)

	// But both should verify correctly
	err = service.VerifyPassword(hash1, password)
	assert.NoError(t, err)

	err = service.VerifyPassword(hash2, password)
	assert.NoError(t, err)
}

// Test: Validate Strong Password
func TestPasswordService_ValidatePasswordStrength_Strong(t *testing.T) {
	service := NewPasswordService()

	strongPasswords := []string{
		"SecurePass123",
		"MyP@ssw0rd",
		"Admin123456",
		"Test1234Abc",
	}

	for _, password := range strongPasswords {
		err := service.ValidatePasswordStrength(password)
		assert.NoError(t, err, "Password should be valid: %s", password)
	}
}

// Test: Validate Weak Password - Too Short
func TestPasswordService_ValidatePasswordStrength_TooShort(t *testing.T) {
	service := NewPasswordService()

	err := service.ValidatePasswordStrength("Short1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least 8 characters")
}

// Test: Validate Weak Password - No Uppercase
func TestPasswordService_ValidatePasswordStrength_NoUppercase(t *testing.T) {
	service := NewPasswordService()

	err := service.ValidatePasswordStrength("lowercase123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "uppercase letter")
}

// Test: Validate Weak Password - No Lowercase
func TestPasswordService_ValidatePasswordStrength_NoLowercase(t *testing.T) {
	service := NewPasswordService()

	err := service.ValidatePasswordStrength("UPPERCASE123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "lowercase letter")
}

// Test: Validate Weak Password - No Digit
func TestPasswordService_ValidatePasswordStrength_NoDigit(t *testing.T) {
	service := NewPasswordService()

	err := service.ValidatePasswordStrength("NoDigitsHere")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "digit")
}

// Test: Validate Empty Password
func TestPasswordService_ValidatePasswordStrength_Empty(t *testing.T) {
	service := NewPasswordService()

	err := service.ValidatePasswordStrength("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least 8 characters")
}

// Test: Hash Empty Password
func TestPasswordService_HashPassword_Empty(t *testing.T) {
	service := NewPasswordService()

	hash, err := service.HashPassword("")
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify empty password
	err = service.VerifyPassword(hash, "")
	assert.NoError(t, err)
}

// Test: Verify with Empty Hash
func TestPasswordService_VerifyPassword_EmptyHash(t *testing.T) {
	service := NewPasswordService()

	err := service.VerifyPassword("", "password")
	assert.Error(t, err)
}
