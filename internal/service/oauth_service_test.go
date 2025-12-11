package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/guipguia/auth/internal/config"
)

// Test: NewOAuthService with Google config
func TestNewOAuthService_Google(t *testing.T) {
	cfg := &config.OAuthConfig{
		Google: config.OAuthProviderConfig{
			ClientID:     "google-client-id",
			ClientSecret: "google-client-secret",
			RedirectURL:  "http://localhost:8080/auth/google/callback",
			Scopes:       []string{"email", "profile"},
		},
	}

	service := NewOAuthService(cfg)

	assert.NotNil(t, service)
}

// Test: NewOAuthService with GitHub config
func TestNewOAuthService_GitHub(t *testing.T) {
	cfg := &config.OAuthConfig{
		GitHub: config.OAuthProviderConfig{
			ClientID:     "github-client-id",
			ClientSecret: "github-client-secret",
			RedirectURL:  "http://localhost:8080/auth/github/callback",
			Scopes:       []string{"user:email"},
		},
	}

	service := NewOAuthService(cfg)

	assert.NotNil(t, service)
}

// Test: NewOAuthService with Facebook config
func TestNewOAuthService_Facebook(t *testing.T) {
	cfg := &config.OAuthConfig{
		Facebook: config.OAuthProviderConfig{
			ClientID:     "facebook-client-id",
			ClientSecret: "facebook-client-secret",
			RedirectURL:  "http://localhost:8080/auth/facebook/callback",
			Scopes:       []string{"email", "public_profile"},
		},
	}

	service := NewOAuthService(cfg)

	assert.NotNil(t, service)
}

// Test: NewOAuthService with Apple config
func TestNewOAuthService_Apple(t *testing.T) {
	cfg := &config.OAuthConfig{
		Apple: config.OAuthProviderConfig{
			ClientID:     "apple-client-id",
			ClientSecret: "apple-client-secret",
			RedirectURL:  "http://localhost:8080/auth/apple/callback",
			Scopes:       []string{"email", "name"},
		},
	}

	service := NewOAuthService(cfg)

	assert.NotNil(t, service)
}

// Test: NewOAuthService with Microsoft config
func TestNewOAuthService_Microsoft(t *testing.T) {
	cfg := &config.OAuthConfig{
		Microsoft: config.OAuthProviderConfig{
			ClientID:     "microsoft-client-id",
			ClientSecret: "microsoft-client-secret",
			RedirectURL:  "http://localhost:8080/auth/microsoft/callback",
			Scopes:       []string{"User.Read"},
		},
	}

	service := NewOAuthService(cfg)

	assert.NotNil(t, service)
}

// Test: NewOAuthService with Discord config
func TestNewOAuthService_Discord(t *testing.T) {
	cfg := &config.OAuthConfig{
		Discord: config.OAuthProviderConfig{
			ClientID:     "discord-client-id",
			ClientSecret: "discord-client-secret",
			RedirectURL:  "http://localhost:8080/auth/discord/callback",
			Scopes:       []string{"identify", "email"},
		},
	}

	service := NewOAuthService(cfg)

	assert.NotNil(t, service)
}

// Test: NewOAuthService with multiple providers
func TestNewOAuthService_MultipleProviders(t *testing.T) {
	cfg := &config.OAuthConfig{
		Google: config.OAuthProviderConfig{
			ClientID:     "google-client-id",
			ClientSecret: "google-client-secret",
			RedirectURL:  "http://localhost:8080/auth/google/callback",
			Scopes:       []string{"email", "profile"},
		},
		GitHub: config.OAuthProviderConfig{
			ClientID:     "github-client-id",
			ClientSecret: "github-client-secret",
			RedirectURL:  "http://localhost:8080/auth/github/callback",
			Scopes:       []string{"user:email"},
		},
	}

	service := NewOAuthService(cfg)

	assert.NotNil(t, service)
}

// Test: GetAuthURL for Google
func TestOAuthService_GetAuthURL_Google(t *testing.T) {
	cfg := &config.OAuthConfig{
		Google: config.OAuthProviderConfig{
			ClientID:     "google-client-id",
			ClientSecret: "google-client-secret",
			RedirectURL:  "http://localhost:8080/auth/google/callback",
			Scopes:       []string{"email", "profile"},
		},
	}

	service := NewOAuthService(cfg)
	authURL, err := service.GetAuthURL(ProviderGoogle, "test-state")

	assert.NoError(t, err)
	assert.NotEmpty(t, authURL)
	assert.Contains(t, authURL, "google")
	assert.Contains(t, authURL, "test-state")
}

// Test: GetAuthURL for GitHub
func TestOAuthService_GetAuthURL_GitHub(t *testing.T) {
	cfg := &config.OAuthConfig{
		GitHub: config.OAuthProviderConfig{
			ClientID:     "github-client-id",
			ClientSecret: "github-client-secret",
			RedirectURL:  "http://localhost:8080/auth/github/callback",
			Scopes:       []string{"user:email"},
		},
	}

	service := NewOAuthService(cfg)
	authURL, err := service.GetAuthURL(ProviderGitHub, "test-state")

	assert.NoError(t, err)
	assert.NotEmpty(t, authURL)
	assert.Contains(t, authURL, "github")
	assert.Contains(t, authURL, "test-state")
}

// Test: GetAuthURL for unsupported provider
func TestOAuthService_GetAuthURL_UnsupportedProvider(t *testing.T) {
	cfg := &config.OAuthConfig{}
	service := NewOAuthService(cfg)

	authURL, err := service.GetAuthURL("unsupported", "test-state")

	assert.Error(t, err)
	assert.Empty(t, authURL)
	assert.Contains(t, err.Error(), "not configured")
}

// Test: GenerateState
func TestOAuthService_GenerateState(t *testing.T) {
	cfg := &config.OAuthConfig{}
	service := NewOAuthService(cfg)

	state, err := service.GenerateState()

	assert.NoError(t, err)
	assert.NotEmpty(t, state)
	assert.True(t, len(state) > 20) // Should be base64 encoded random bytes
}

// Test: GenerateState produces unique states
func TestOAuthService_GenerateState_Unique(t *testing.T) {
	cfg := &config.OAuthConfig{}
	service := NewOAuthService(cfg)

	state1, err1 := service.GenerateState()
	state2, err2 := service.GenerateState()

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NotEqual(t, state1, state2)
}

// Test: ExchangeCode with unsupported provider
func TestOAuthService_ExchangeCode_UnsupportedProvider(t *testing.T) {
	cfg := &config.OAuthConfig{}
	service := NewOAuthService(cfg)

	token, err := service.ExchangeCode("unsupported", "test-code")

	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "not configured")
}

// Test: GetUserInfo with unsupported provider
func TestOAuthService_GetUserInfo_UnsupportedProvider(t *testing.T) {
	cfg := &config.OAuthConfig{}
	service := NewOAuthService(cfg)

	token := &oauth2.Token{
		AccessToken: "test-token",
	}

	userInfo, err := service.GetUserInfo("unsupported", token)

	assert.Error(t, err)
	assert.Nil(t, userInfo)
	assert.Contains(t, err.Error(), "unsupported")
}
