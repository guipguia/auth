package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the auth service
type Config struct {
	Server        ServerConfig
	Database      DatabaseConfig
	JWT           JWTConfig
	OAuth         OAuthConfig
	Email         EmailConfig
	Cache         CacheConfig
	Session       SessionConfig
	Tenant        TenantServiceConfig
	EncryptionKey string
}

// SessionConfig holds session management configuration
type SessionConfig struct {
	// SessionExpiry is the maximum session lifetime (default: 7 days)
	SessionExpiry time.Duration
	// IdleTimeout is the idle timeout duration (default: 15 minutes when HIPAA enabled)
	IdleTimeout time.Duration
	// MaxConcurrentSessions limits concurrent sessions per user (0 = unlimited)
	MaxConcurrentSessions int
	// HIPAACompliant enables strict session security (15 min idle timeout)
	HIPAACompliant bool
}

// TenantServiceConfig holds tenant service connection configuration
type TenantServiceConfig struct {
	Address string
	Timeout time.Duration
}

// CacheConfig holds cache configuration for stateless horizontal scaling
type CacheConfig struct {
	Type           string           // "none", "memory", "redis" (redis = Valkey compatible)
	Enabled        bool             // Enable caching for sessions/OTPs
	TTLSeconds     int              // Default TTL for cached items
	MaxSize        int              // Max entries for memory cache
	CleanupMinutes int              // Cleanup interval for memory cache
	Redis          RedisCacheConfig // Redis/Valkey configuration
}

// RedisCacheConfig holds Redis/Valkey cache configuration
type RedisCacheConfig struct {
	Address    string // Redis/Valkey address (e.g., "localhost:6379")
	Password   string // Redis/Valkey password (empty for no auth)
	DB         int    // Redis/Valkey database number
	TTLSeconds int    // TTL for cached items in Redis/Valkey
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Address string
	Port    int
	AppURL  string // Base URL for the application (used in email links)
}

// DatabaseConfig holds database connection configuration
type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
	MaxConns int
	MaxIdle  int
}

// JWTConfig holds JWT token configuration
type JWTConfig struct {
	AccessTokenSecret  string
	RefreshTokenSecret string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	Issuer             string
}

// OAuthConfig holds OAuth provider configurations
type OAuthConfig struct {
	Google    OAuthProviderConfig
	GitHub    OAuthProviderConfig
	Facebook  OAuthProviderConfig
	Apple     OAuthProviderConfig
	Microsoft OAuthProviderConfig
	Discord   OAuthProviderConfig
}

// OAuthProviderConfig holds configuration for a single OAuth provider
type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// EmailConfig holds email service configuration
type EmailConfig struct {
	Provider  string // smtp, sendgrid, ses
	SMTPHost  string
	SMTPPort  int
	SMTPUser  string
	SMTPPass  string
	FromEmail string
	FromName  string
	APIKey    string // For sendgrid/ses
}

// Load reads configuration from environment variables and config files
func Load() (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Configure environment variable handling
	v.SetEnvPrefix("AUTH")
	v.AutomaticEnv()
	// Replace dots with underscores in env var names (e.g., database.host -> DATABASE_HOST)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Bind all environment variables explicitly
	bindEnvVariables(v)

	// Try to read config file if it exists
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./config")
	v.AddConfigPath(".")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found, will use env vars and defaults
	}

	cfg := &Config{
		Server: ServerConfig{
			Address: v.GetString("server.address"),
			Port:    v.GetInt("server.port"),
			AppURL:  v.GetString("server.app_url"),
		},
		Database: DatabaseConfig{
			Host:     v.GetString("database.host"),
			Port:     v.GetInt("database.port"),
			User:     v.GetString("database.user"),
			Password: v.GetString("database.password"),
			DBName:   v.GetString("database.dbname"),
			SSLMode:  v.GetString("database.sslmode"),
			MaxConns: v.GetInt("database.max_conns"),
			MaxIdle:  v.GetInt("database.max_idle"),
		},
		JWT: JWTConfig{
			AccessTokenSecret:  v.GetString("jwt.access_token_secret"),
			RefreshTokenSecret: v.GetString("jwt.refresh_token_secret"),
			AccessTokenExpiry:  v.GetDuration("jwt.access_token_expiry"),
			RefreshTokenExpiry: v.GetDuration("jwt.refresh_token_expiry"),
			Issuer:             v.GetString("jwt.issuer"),
		},
		Cache: CacheConfig{
			Type:           v.GetString("cache.type"),
			Enabled:        v.GetBool("cache.enabled"),
			TTLSeconds:     v.GetInt("cache.ttl_seconds"),
			MaxSize:        v.GetInt("cache.max_size"),
			CleanupMinutes: v.GetInt("cache.cleanup_minutes"),
			Redis: RedisCacheConfig{
				Address:    v.GetString("cache.redis.address"),
				Password:   v.GetString("cache.redis.password"),
				DB:         v.GetInt("cache.redis.db"),
				TTLSeconds: v.GetInt("cache.redis.ttl_seconds"),
			},
		},
		OAuth: OAuthConfig{
			Google: OAuthProviderConfig{
				ClientID:     v.GetString("oauth.google.client_id"),
				ClientSecret: v.GetString("oauth.google.client_secret"),
				RedirectURL:  v.GetString("oauth.google.redirect_url"),
				Scopes:       v.GetStringSlice("oauth.google.scopes"),
			},
			GitHub: OAuthProviderConfig{
				ClientID:     v.GetString("oauth.github.client_id"),
				ClientSecret: v.GetString("oauth.github.client_secret"),
				RedirectURL:  v.GetString("oauth.github.redirect_url"),
				Scopes:       v.GetStringSlice("oauth.github.scopes"),
			},
			Facebook: OAuthProviderConfig{
				ClientID:     v.GetString("oauth.facebook.client_id"),
				ClientSecret: v.GetString("oauth.facebook.client_secret"),
				RedirectURL:  v.GetString("oauth.facebook.redirect_url"),
				Scopes:       v.GetStringSlice("oauth.facebook.scopes"),
			},
			Apple: OAuthProviderConfig{
				ClientID:     v.GetString("oauth.apple.client_id"),
				ClientSecret: v.GetString("oauth.apple.client_secret"),
				RedirectURL:  v.GetString("oauth.apple.redirect_url"),
				Scopes:       v.GetStringSlice("oauth.apple.scopes"),
			},
			Microsoft: OAuthProviderConfig{
				ClientID:     v.GetString("oauth.microsoft.client_id"),
				ClientSecret: v.GetString("oauth.microsoft.client_secret"),
				RedirectURL:  v.GetString("oauth.microsoft.redirect_url"),
				Scopes:       v.GetStringSlice("oauth.microsoft.scopes"),
			},
			Discord: OAuthProviderConfig{
				ClientID:     v.GetString("oauth.discord.client_id"),
				ClientSecret: v.GetString("oauth.discord.client_secret"),
				RedirectURL:  v.GetString("oauth.discord.redirect_url"),
				Scopes:       v.GetStringSlice("oauth.discord.scopes"),
			},
		},
		Email: EmailConfig{
			Provider:  v.GetString("email.provider"),
			SMTPHost:  v.GetString("email.smtp_host"),
			SMTPPort:  v.GetInt("email.smtp_port"),
			SMTPUser:  v.GetString("email.smtp_user"),
			SMTPPass:  v.GetString("email.smtp_pass"),
			FromEmail: v.GetString("email.from_email"),
			FromName:  v.GetString("email.from_name"),
			APIKey:    v.GetString("email.api_key"),
		},
		Session: SessionConfig{
			SessionExpiry:         v.GetDuration("session.session_expiry"),
			IdleTimeout:           v.GetDuration("session.idle_timeout"),
			MaxConcurrentSessions: v.GetInt("session.max_concurrent_sessions"),
			HIPAACompliant:        v.GetBool("session.hipaa_compliant"),
		},
		Tenant: TenantServiceConfig{
			Address: v.GetString("tenant.address"),
			Timeout: v.GetDuration("tenant.timeout"),
		},
		EncryptionKey: v.GetString("encryption_key"),
	}

	// Validate required fields
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// bindEnvVariables explicitly binds all config keys to environment variables
func bindEnvVariables(v *viper.Viper) {
	// Server
	v.BindEnv("server.address")
	v.BindEnv("server.port")
	v.BindEnv("server.app_url")

	// Database
	v.BindEnv("database.host")
	v.BindEnv("database.port")
	v.BindEnv("database.user")
	v.BindEnv("database.password")
	v.BindEnv("database.dbname")
	v.BindEnv("database.sslmode")
	v.BindEnv("database.max_conns")
	v.BindEnv("database.max_idle")

	// JWT
	v.BindEnv("jwt.access_token_secret")
	v.BindEnv("jwt.refresh_token_secret")
	v.BindEnv("jwt.access_token_expiry")
	v.BindEnv("jwt.refresh_token_expiry")
	v.BindEnv("jwt.issuer")

	// OAuth - Google
	v.BindEnv("oauth.google.client_id")
	v.BindEnv("oauth.google.client_secret")
	v.BindEnv("oauth.google.redirect_url")
	v.BindEnv("oauth.google.scopes")

	// OAuth - GitHub
	v.BindEnv("oauth.github.client_id")
	v.BindEnv("oauth.github.client_secret")
	v.BindEnv("oauth.github.redirect_url")
	v.BindEnv("oauth.github.scopes")

	// OAuth - Facebook
	v.BindEnv("oauth.facebook.client_id")
	v.BindEnv("oauth.facebook.client_secret")
	v.BindEnv("oauth.facebook.redirect_url")
	v.BindEnv("oauth.facebook.scopes")

	// OAuth - Apple
	v.BindEnv("oauth.apple.client_id")
	v.BindEnv("oauth.apple.client_secret")
	v.BindEnv("oauth.apple.redirect_url")
	v.BindEnv("oauth.apple.scopes")

	// OAuth - Microsoft
	v.BindEnv("oauth.microsoft.client_id")
	v.BindEnv("oauth.microsoft.client_secret")
	v.BindEnv("oauth.microsoft.redirect_url")
	v.BindEnv("oauth.microsoft.scopes")

	// OAuth - Discord
	v.BindEnv("oauth.discord.client_id")
	v.BindEnv("oauth.discord.client_secret")
	v.BindEnv("oauth.discord.redirect_url")
	v.BindEnv("oauth.discord.scopes")

	// Email
	v.BindEnv("email.provider")
	v.BindEnv("email.smtp_host")
	v.BindEnv("email.smtp_port")
	v.BindEnv("email.smtp_user")
	v.BindEnv("email.smtp_pass")
	v.BindEnv("email.from_email")
	v.BindEnv("email.from_name")
	v.BindEnv("email.api_key")

	// Cache
	v.BindEnv("cache.type")
	v.BindEnv("cache.enabled")
	v.BindEnv("cache.ttl_seconds")
	v.BindEnv("cache.max_size")
	v.BindEnv("cache.cleanup_minutes")

	// Redis/Valkey Cache
	v.BindEnv("cache.redis.address")
	v.BindEnv("cache.redis.password")
	v.BindEnv("cache.redis.db")
	v.BindEnv("cache.redis.ttl_seconds")

	// Session
	v.BindEnv("session.session_expiry")
	v.BindEnv("session.idle_timeout")
	v.BindEnv("session.max_concurrent_sessions")
	v.BindEnv("session.hipaa_compliant")

	// Tenant service
	v.BindEnv("tenant.address")
	v.BindEnv("tenant.timeout")

	// Encryption
	v.BindEnv("encryption_key")
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.address", ":8080")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.app_url", "http://localhost:3000")

	// Database defaults
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.user", "postgres")
	v.SetDefault("database.password", "postgres")
	v.SetDefault("database.dbname", "auth_db")
	v.SetDefault("database.sslmode", "disable")
	v.SetDefault("database.max_conns", 25)
	v.SetDefault("database.max_idle", 5)

	// JWT defaults
	v.SetDefault("jwt.access_token_expiry", 15*time.Minute)
	v.SetDefault("jwt.refresh_token_expiry", 7*24*time.Hour)
	v.SetDefault("jwt.issuer", "auth-service")

	// Email defaults
	v.SetDefault("email.provider", "smtp")
	v.SetDefault("email.smtp_port", 587)
	v.SetDefault("email.from_name", "Auth Service")

	// OAuth defaults
	v.SetDefault("oauth.google.scopes", []string{"openid", "email", "profile"})
	v.SetDefault("oauth.github.scopes", []string{"user:email"})
	v.SetDefault("oauth.facebook.scopes", []string{"email", "public_profile"})
	v.SetDefault("oauth.apple.scopes", []string{"email", "name"})
	v.SetDefault("oauth.microsoft.scopes", []string{"openid", "email", "profile"})
	v.SetDefault("oauth.discord.scopes", []string{"identify", "email"})

	// Cache defaults (stateless by default for horizontal scaling)
	v.SetDefault("cache.type", "none")        // "none", "memory", "redis" (Valkey compatible)
	v.SetDefault("cache.enabled", false)      // Disabled by default for stateless
	v.SetDefault("cache.ttl_seconds", 300)    // 5 minutes default TTL
	v.SetDefault("cache.max_size", 10000)     // 10k entries for memory cache
	v.SetDefault("cache.cleanup_minutes", 10) // Cleanup every 10 minutes

	// Redis/Valkey cache defaults
	v.SetDefault("cache.redis.address", "localhost:6379")
	v.SetDefault("cache.redis.password", "")
	v.SetDefault("cache.redis.db", 0)
	v.SetDefault("cache.redis.ttl_seconds", 300)

	// Session defaults
	v.SetDefault("session.session_expiry", 7*24*time.Hour)  // 7 days
	v.SetDefault("session.idle_timeout", 15*time.Minute)    // 15 minutes (HIPAA)
	v.SetDefault("session.max_concurrent_sessions", 5)      // 5 concurrent sessions
	v.SetDefault("session.hipaa_compliant", false)          // Disabled by default

	// Tenant service defaults
	v.SetDefault("tenant.address", "tenant-service:8080")
	v.SetDefault("tenant.timeout", 30*time.Second)
}

// Validate checks if required configuration values are present
func (c *Config) Validate() error {
	if c.JWT.AccessTokenSecret == "" {
		if secret := os.Getenv("AUTH_JWT_ACCESS_TOKEN_SECRET"); secret != "" {
			c.JWT.AccessTokenSecret = secret
		} else {
			return fmt.Errorf("JWT access token secret is required")
		}
	}

	if c.JWT.RefreshTokenSecret == "" {
		if secret := os.Getenv("AUTH_JWT_REFRESH_TOKEN_SECRET"); secret != "" {
			c.JWT.RefreshTokenSecret = secret
		} else {
			return fmt.Errorf("JWT refresh token secret is required")
		}
	}

	if c.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}

	return nil
}
