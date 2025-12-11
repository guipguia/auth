package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// Test: OTP TableName
func TestOTP_TableName(t *testing.T) {
	otp := OTP{}
	assert.Equal(t, "otps", otp.TableName())
}

// Test: OTP IsValid - Valid OTP
func TestOTP_IsValid_Valid(t *testing.T) {
	otp := &OTP{
		Used:      false,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	assert.True(t, otp.IsValid())
}

// Test: OTP IsValid - Used OTP
func TestOTP_IsValid_Used(t *testing.T) {
	otp := &OTP{
		Used:      true,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	assert.False(t, otp.IsValid())
}

// Test: OTP IsValid - Expired OTP
func TestOTP_IsValid_Expired(t *testing.T) {
	otp := &OTP{
		Used:      false,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	assert.False(t, otp.IsValid())
}

// Test: OTP IsExpired - Not Expired
func TestOTP_IsExpired_NotExpired(t *testing.T) {
	otp := &OTP{
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	assert.False(t, otp.IsExpired())
}

// Test: OTP IsExpired - Expired
func TestOTP_IsExpired_Expired(t *testing.T) {
	otp := &OTP{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	assert.True(t, otp.IsExpired())
}

// Test: OTP MarkAsUsed
func TestOTP_MarkAsUsed(t *testing.T) {
	otp := &OTP{
		Used:      false,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	assert.False(t, otp.Used)
	assert.Nil(t, otp.UsedAt)
	assert.True(t, otp.IsValid())

	otp.MarkAsUsed()

	assert.True(t, otp.Used)
	assert.NotNil(t, otp.UsedAt)
	assert.False(t, otp.IsValid())
}

// Test: OTP BeforeCreate - Generates UUID
func TestOTP_BeforeCreate_GeneratesUUID(t *testing.T) {
	otp := &OTP{}

	assert.Equal(t, uuid.Nil, otp.ID)

	err := otp.BeforeCreate(nil)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, otp.ID)
}

// Test: OTP BeforeCreate - Preserves Existing UUID
func TestOTP_BeforeCreate_PreservesUUID(t *testing.T) {
	existingID := uuid.New()
	otp := &OTP{
		ID: existingID,
	}

	err := otp.BeforeCreate(nil)

	assert.NoError(t, err)
	assert.Equal(t, existingID, otp.ID)
}

// Test: OTP Types
func TestOTP_Types(t *testing.T) {
	types := []OTPType{
		OTPTypeEmailVerification,
		OTPTypePasswordReset,
		OTPTypePasswordless,
		OTPType2FA,
	}

	expectedValues := []string{
		"email_verification",
		"password_reset",
		"passwordless",
		"two_factor",
	}

	for i, otpType := range types {
		assert.Equal(t, expectedValues[i], string(otpType))
	}
}
