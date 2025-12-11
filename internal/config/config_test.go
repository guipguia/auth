package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate_MissingAccessTokenSecret(t *testing.T) {
	// Clear environment variables
	t.Setenv("AUTH_JWT_ACCESS_TOKEN_SECRET", "")
	t.Setenv("AUTH_JWT_REFRESH_TOKEN_SECRET", "")

	cfg := &Config{
		JWT: JWTConfig{
			AccessTokenSecret:  "",
			RefreshTokenSecret: "test-refresh-secret",
		},
		Database: DatabaseConfig{
			Host: "localhost",
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWT access token secret is required")
}

func TestConfig_Validate_MissingRefreshTokenSecret(t *testing.T) {
	// Clear environment variables
	t.Setenv("AUTH_JWT_ACCESS_TOKEN_SECRET", "")
	t.Setenv("AUTH_JWT_REFRESH_TOKEN_SECRET", "")

	cfg := &Config{
		JWT: JWTConfig{
			AccessTokenSecret:  "test-access-secret",
			RefreshTokenSecret: "",
		},
		Database: DatabaseConfig{
			Host: "localhost",
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWT refresh token secret is required")
}

func TestConfig_Validate_MissingDatabaseHost(t *testing.T) {
	cfg := &Config{
		JWT: JWTConfig{
			AccessTokenSecret:  "test-access-secret",
			RefreshTokenSecret: "test-refresh-secret",
		},
		Database: DatabaseConfig{
			Host: "",
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database host is required")
}

func TestConfig_Validate_Success(t *testing.T) {
	cfg := &Config{
		JWT: JWTConfig{
			AccessTokenSecret:  "test-access-secret",
			RefreshTokenSecret: "test-refresh-secret",
		},
		Database: DatabaseConfig{
			Host: "localhost",
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestConfig_Validate_UsesEnvForAccessSecret(t *testing.T) {
	// Set environment variable
	t.Setenv("AUTH_JWT_ACCESS_TOKEN_SECRET", "env-access-secret")

	cfg := &Config{
		JWT: JWTConfig{
			AccessTokenSecret:  "", // Empty, should read from env
			RefreshTokenSecret: "test-refresh-secret",
		},
		Database: DatabaseConfig{
			Host: "localhost",
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
	assert.Equal(t, "env-access-secret", cfg.JWT.AccessTokenSecret)
}

func TestConfig_Validate_UsesEnvForRefreshSecret(t *testing.T) {
	// Set environment variable
	t.Setenv("AUTH_JWT_REFRESH_TOKEN_SECRET", "env-refresh-secret")

	cfg := &Config{
		JWT: JWTConfig{
			AccessTokenSecret:  "test-access-secret",
			RefreshTokenSecret: "", // Empty, should read from env
		},
		Database: DatabaseConfig{
			Host: "localhost",
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
	assert.Equal(t, "env-refresh-secret", cfg.JWT.RefreshTokenSecret)
}

func TestLoad_WithEnvironmentVariables(t *testing.T) {
	// Set required environment variables
	t.Setenv("AUTH_JWT_ACCESS_TOKEN_SECRET", "test-access-secret")
	t.Setenv("AUTH_JWT_REFRESH_TOKEN_SECRET", "test-refresh-secret")
	t.Setenv("AUTH_DATABASE_HOST", "testhost")
	t.Setenv("AUTH_DATABASE_PORT", "5433")
	t.Setenv("AUTH_SERVER_PORT", "9090")

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "test-access-secret", cfg.JWT.AccessTokenSecret)
	assert.Equal(t, "test-refresh-secret", cfg.JWT.RefreshTokenSecret)
	assert.Equal(t, "testhost", cfg.Database.Host)
	assert.Equal(t, 5433, cfg.Database.Port)
	assert.Equal(t, 9090, cfg.Server.Port)
}

func TestLoad_DefaultValues(t *testing.T) {
	// Save any existing env vars that might override defaults (e.g., from CI)
	savedIssuer := os.Getenv("AUTH_JWT_ISSUER")
	savedEmailProvider := os.Getenv("AUTH_EMAIL_PROVIDER")
	savedDBHost := os.Getenv("AUTH_DATABASE_HOST")
	savedDBPort := os.Getenv("AUTH_DATABASE_PORT")
	savedServerPort := os.Getenv("AUTH_SERVER_PORT")

	// Clear env vars that would override defaults
	_ = os.Unsetenv("AUTH_JWT_ISSUER")
	_ = os.Unsetenv("AUTH_EMAIL_PROVIDER")
	_ = os.Unsetenv("AUTH_DATABASE_HOST")
	_ = os.Unsetenv("AUTH_DATABASE_PORT")
	_ = os.Unsetenv("AUTH_SERVER_PORT")

	// Set only required environment variables
	_ = os.Setenv("AUTH_JWT_ACCESS_TOKEN_SECRET", "test-access-secret")
	_ = os.Setenv("AUTH_JWT_REFRESH_TOKEN_SECRET", "test-refresh-secret")

	defer func() {
		_ = os.Unsetenv("AUTH_JWT_ACCESS_TOKEN_SECRET")
		_ = os.Unsetenv("AUTH_JWT_REFRESH_TOKEN_SECRET")
		// Restore saved env vars
		if savedIssuer != "" {
			_ = os.Setenv("AUTH_JWT_ISSUER", savedIssuer)
		}
		if savedEmailProvider != "" {
			_ = os.Setenv("AUTH_EMAIL_PROVIDER", savedEmailProvider)
		}
		if savedDBHost != "" {
			_ = os.Setenv("AUTH_DATABASE_HOST", savedDBHost)
		}
		if savedDBPort != "" {
			_ = os.Setenv("AUTH_DATABASE_PORT", savedDBPort)
		}
		if savedServerPort != "" {
			_ = os.Setenv("AUTH_SERVER_PORT", savedServerPort)
		}
	}()

	cfg, err := Load()
	require.NoError(t, err)

	// Check default values
	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, "localhost", cfg.Database.Host)
	assert.Equal(t, 5432, cfg.Database.Port)
	assert.Equal(t, "postgres", cfg.Database.User)
	assert.Equal(t, "auth_db", cfg.Database.DBName)
	assert.Equal(t, "disable", cfg.Database.SSLMode)
	assert.Equal(t, 25, cfg.Database.MaxConns)
	assert.Equal(t, 5, cfg.Database.MaxIdle)
	assert.Equal(t, 15*time.Minute, cfg.JWT.AccessTokenExpiry)
	assert.Equal(t, 7*24*time.Hour, cfg.JWT.RefreshTokenExpiry)
	assert.Equal(t, "auth-service", cfg.JWT.Issuer)
	assert.Equal(t, "smtp", cfg.Email.Provider)
	assert.Equal(t, 587, cfg.Email.SMTPPort)
	assert.Equal(t, "none", cfg.Cache.Type)
	assert.False(t, cfg.Cache.Enabled)
}

func TestLoad_CacheConfiguration(t *testing.T) {
	// Set required environment variables plus cache config
	_ = os.Setenv("AUTH_JWT_ACCESS_TOKEN_SECRET", "test-access-secret")
	_ = os.Setenv("AUTH_JWT_REFRESH_TOKEN_SECRET", "test-refresh-secret")
	_ = os.Setenv("AUTH_CACHE_TYPE", "redis")
	_ = os.Setenv("AUTH_CACHE_ENABLED", "true")
	_ = os.Setenv("AUTH_CACHE_REDIS_ADDRESS", "redis.example.com:6379")

	defer func() {
		_ = os.Unsetenv("AUTH_JWT_ACCESS_TOKEN_SECRET")
		_ = os.Unsetenv("AUTH_JWT_REFRESH_TOKEN_SECRET")
		_ = os.Unsetenv("AUTH_CACHE_TYPE")
		_ = os.Unsetenv("AUTH_CACHE_ENABLED")
		_ = os.Unsetenv("AUTH_CACHE_REDIS_ADDRESS")
	}()

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "redis", cfg.Cache.Type)
	assert.True(t, cfg.Cache.Enabled)
	assert.Equal(t, "redis.example.com:6379", cfg.Cache.Redis.Address)
}

func TestLoad_OAuthConfiguration(t *testing.T) {
	// Set required environment variables plus OAuth config
	_ = os.Setenv("AUTH_JWT_ACCESS_TOKEN_SECRET", "test-access-secret")
	_ = os.Setenv("AUTH_JWT_REFRESH_TOKEN_SECRET", "test-refresh-secret")
	_ = os.Setenv("AUTH_OAUTH_GOOGLE_CLIENT_ID", "google-client-id")
	_ = os.Setenv("AUTH_OAUTH_GOOGLE_CLIENT_SECRET", "google-client-secret")
	_ = os.Setenv("AUTH_OAUTH_GITHUB_CLIENT_ID", "github-client-id")

	defer func() {
		_ = os.Unsetenv("AUTH_JWT_ACCESS_TOKEN_SECRET")
		_ = os.Unsetenv("AUTH_JWT_REFRESH_TOKEN_SECRET")
		_ = os.Unsetenv("AUTH_OAUTH_GOOGLE_CLIENT_ID")
		_ = os.Unsetenv("AUTH_OAUTH_GOOGLE_CLIENT_SECRET")
		_ = os.Unsetenv("AUTH_OAUTH_GITHUB_CLIENT_ID")
	}()

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "google-client-id", cfg.OAuth.Google.ClientID)
	assert.Equal(t, "google-client-secret", cfg.OAuth.Google.ClientSecret)
	assert.Equal(t, "github-client-id", cfg.OAuth.GitHub.ClientID)

	// Check default scopes are set
	assert.Contains(t, cfg.OAuth.Google.Scopes, "openid")
	assert.Contains(t, cfg.OAuth.Google.Scopes, "email")
	assert.Contains(t, cfg.OAuth.GitHub.Scopes, "user:email")
}

func TestLoad_EmailConfiguration(t *testing.T) {
	// Set required environment variables plus email config
	_ = os.Setenv("AUTH_JWT_ACCESS_TOKEN_SECRET", "test-access-secret")
	_ = os.Setenv("AUTH_JWT_REFRESH_TOKEN_SECRET", "test-refresh-secret")
	_ = os.Setenv("AUTH_EMAIL_PROVIDER", "sendgrid")
	_ = os.Setenv("AUTH_EMAIL_API_KEY", "sendgrid-api-key")
	_ = os.Setenv("AUTH_EMAIL_FROM_EMAIL", "noreply@example.com")

	defer func() {
		_ = os.Unsetenv("AUTH_JWT_ACCESS_TOKEN_SECRET")
		_ = os.Unsetenv("AUTH_JWT_REFRESH_TOKEN_SECRET")
		_ = os.Unsetenv("AUTH_EMAIL_PROVIDER")
		_ = os.Unsetenv("AUTH_EMAIL_API_KEY")
		_ = os.Unsetenv("AUTH_EMAIL_FROM_EMAIL")
	}()

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "sendgrid", cfg.Email.Provider)
	assert.Equal(t, "sendgrid-api-key", cfg.Email.APIKey)
	assert.Equal(t, "noreply@example.com", cfg.Email.FromEmail)
}

func TestLoad_MissingRequiredConfig(t *testing.T) {
	// Clear all environment variables
	_ = os.Unsetenv("AUTH_JWT_ACCESS_TOKEN_SECRET")
	_ = os.Unsetenv("AUTH_JWT_REFRESH_TOKEN_SECRET")

	_, err := Load()
	assert.Error(t, err)
}

// Test struct types
func TestServerConfig_Fields(t *testing.T) {
	cfg := ServerConfig{
		Address: ":8080",
		Port:    8080,
		AppURL:  "http://localhost:3000",
	}

	assert.Equal(t, ":8080", cfg.Address)
	assert.Equal(t, 8080, cfg.Port)
	assert.Equal(t, "http://localhost:3000", cfg.AppURL)
}

func TestDatabaseConfig_Fields(t *testing.T) {
	cfg := DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "postgres",
		Password: "secret",
		DBName:   "testdb",
		SSLMode:  "require",
		MaxConns: 50,
		MaxIdle:  10,
	}

	assert.Equal(t, "localhost", cfg.Host)
	assert.Equal(t, 5432, cfg.Port)
	assert.Equal(t, "postgres", cfg.User)
	assert.Equal(t, "secret", cfg.Password)
	assert.Equal(t, "testdb", cfg.DBName)
	assert.Equal(t, "require", cfg.SSLMode)
	assert.Equal(t, 50, cfg.MaxConns)
	assert.Equal(t, 10, cfg.MaxIdle)
}

func TestJWTConfig_Fields(t *testing.T) {
	cfg := JWTConfig{
		AccessTokenSecret:  "access-secret",
		RefreshTokenSecret: "refresh-secret",
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
		Issuer:             "test-issuer",
	}

	assert.Equal(t, "access-secret", cfg.AccessTokenSecret)
	assert.Equal(t, "refresh-secret", cfg.RefreshTokenSecret)
	assert.Equal(t, 15*time.Minute, cfg.AccessTokenExpiry)
	assert.Equal(t, 24*time.Hour, cfg.RefreshTokenExpiry)
	assert.Equal(t, "test-issuer", cfg.Issuer)
}

func TestCacheConfig_Fields(t *testing.T) {
	cfg := CacheConfig{
		Type:           "redis",
		Enabled:        true,
		TTLSeconds:     600,
		MaxSize:        5000,
		CleanupMinutes: 5,
		Redis: RedisCacheConfig{
			Address:    "localhost:6379",
			Password:   "redispass",
			DB:         1,
			TTLSeconds: 300,
		},
	}

	assert.Equal(t, "redis", cfg.Type)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, 600, cfg.TTLSeconds)
	assert.Equal(t, 5000, cfg.MaxSize)
	assert.Equal(t, 5, cfg.CleanupMinutes)
	assert.Equal(t, "localhost:6379", cfg.Redis.Address)
	assert.Equal(t, "redispass", cfg.Redis.Password)
	assert.Equal(t, 1, cfg.Redis.DB)
	assert.Equal(t, 300, cfg.Redis.TTLSeconds)
}

func TestOAuthProviderConfig_Fields(t *testing.T) {
	cfg := OAuthProviderConfig{
		ClientID:     "client-123",
		ClientSecret: "secret-456",
		RedirectURL:  "http://localhost:3000/callback",
		Scopes:       []string{"email", "profile"},
	}

	assert.Equal(t, "client-123", cfg.ClientID)
	assert.Equal(t, "secret-456", cfg.ClientSecret)
	assert.Equal(t, "http://localhost:3000/callback", cfg.RedirectURL)
	assert.Equal(t, []string{"email", "profile"}, cfg.Scopes)
}

func TestEmailConfig_Fields(t *testing.T) {
	cfg := EmailConfig{
		Provider:  "ses",
		SMTPHost:  "smtp.example.com",
		SMTPPort:  587,
		SMTPUser:  "user",
		SMTPPass:  "pass",
		FromEmail: "noreply@example.com",
		FromName:  "Test Service",
		APIKey:    "api-key-123",
	}

	assert.Equal(t, "ses", cfg.Provider)
	assert.Equal(t, "smtp.example.com", cfg.SMTPHost)
	assert.Equal(t, 587, cfg.SMTPPort)
	assert.Equal(t, "user", cfg.SMTPUser)
	assert.Equal(t, "pass", cfg.SMTPPass)
	assert.Equal(t, "noreply@example.com", cfg.FromEmail)
	assert.Equal(t, "Test Service", cfg.FromName)
	assert.Equal(t, "api-key-123", cfg.APIKey)
}
