package repository

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/guipguia/auth/internal/domain"
)

func setupTestDB(t *testing.T) *gorm.DB {
	// Get database configuration from environment
	host := os.Getenv("AUTH_DATABASE_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("AUTH_DATABASE_PORT")
	if port == "" {
		port = "5432"
	}
	user := os.Getenv("AUTH_DATABASE_USER")
	if user == "" {
		user = "postgres"
	}
	password := os.Getenv("AUTH_DATABASE_PASSWORD")
	if password == "" {
		password = "postgres"
	}
	dbname := os.Getenv("AUTH_DATABASE_DBNAME")
	if dbname == "" {
		dbname = "auth_db"
	}
	sslmode := os.Getenv("AUTH_DATABASE_SSLMODE")
	if sslmode == "" {
		sslmode = "disable"
	}

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	assert.NoError(t, err)

	// Drop existing tables to ensure clean schema migration
	db.Exec("DROP TABLE IF EXISTS audit_logs, account_lockouts, login_attempts, password_histories, oauth_accounts, backup_codes, otps, sessions, users CASCADE")

	// Auto migrate the schema with all domain models
	// Note: Tenant is now managed by the tenant service
	err = db.AutoMigrate(
		&domain.User{},
		&domain.Session{},
		&domain.OTP{},
		&domain.BackupCode{},
		&domain.OAuthAccount{},
		&domain.AuditLog{},
		&domain.LoginAttempt{},
		&domain.AccountLockout{},
		&domain.PasswordHistory{},
	)
	assert.NoError(t, err)

	return db
}
