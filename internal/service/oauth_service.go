package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/guipguia/auth/internal/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

// OAuthProvider represents an OAuth provider
type OAuthProvider string

const (
	ProviderGoogle    OAuthProvider = "google"
	ProviderGitHub    OAuthProvider = "github"
	ProviderFacebook  OAuthProvider = "facebook"
	ProviderApple     OAuthProvider = "apple"
	ProviderMicrosoft OAuthProvider = "microsoft"
	ProviderDiscord   OAuthProvider = "discord"
)

// OAuthUserInfo represents user information from OAuth provider
type OAuthUserInfo struct {
	ProviderUserID string
	Email          string
	FirstName      string
	LastName       string
	Picture        string
}

// OAuthService handles OAuth operations
type OAuthService interface {
	GetAuthURL(provider OAuthProvider, state string) (string, error)
	ExchangeCode(provider OAuthProvider, code string) (*oauth2.Token, error)
	GetUserInfo(provider OAuthProvider, token *oauth2.Token) (*OAuthUserInfo, error)
	GenerateState() (string, error)
}

type oauthService struct {
	configs map[OAuthProvider]*oauth2.Config
}

// NewOAuthService creates a new OAuth service
func NewOAuthService(cfg *config.OAuthConfig) OAuthService {
	configs := make(map[OAuthProvider]*oauth2.Config)

	// Google OAuth config
	if cfg.Google.ClientID != "" {
		configs[ProviderGoogle] = &oauth2.Config{
			ClientID:     cfg.Google.ClientID,
			ClientSecret: cfg.Google.ClientSecret,
			RedirectURL:  cfg.Google.RedirectURL,
			Scopes:       cfg.Google.Scopes,
			Endpoint:     google.Endpoint,
		}
	}

	// GitHub OAuth config
	if cfg.GitHub.ClientID != "" {
		configs[ProviderGitHub] = &oauth2.Config{
			ClientID:     cfg.GitHub.ClientID,
			ClientSecret: cfg.GitHub.ClientSecret,
			RedirectURL:  cfg.GitHub.RedirectURL,
			Scopes:       cfg.GitHub.Scopes,
			Endpoint:     github.Endpoint,
		}
	}

	// Facebook OAuth config
	if cfg.Facebook.ClientID != "" {
		configs[ProviderFacebook] = &oauth2.Config{
			ClientID:     cfg.Facebook.ClientID,
			ClientSecret: cfg.Facebook.ClientSecret,
			RedirectURL:  cfg.Facebook.RedirectURL,
			Scopes:       cfg.Facebook.Scopes,
			Endpoint:     facebook.Endpoint,
		}
	}

	// Apple OAuth config (custom endpoint)
	if cfg.Apple.ClientID != "" {
		configs[ProviderApple] = &oauth2.Config{
			ClientID:     cfg.Apple.ClientID,
			ClientSecret: cfg.Apple.ClientSecret,
			RedirectURL:  cfg.Apple.RedirectURL,
			Scopes:       cfg.Apple.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://appleid.apple.com/auth/authorize",
				TokenURL: "https://appleid.apple.com/auth/token",
			},
		}
	}

	// Microsoft OAuth config
	if cfg.Microsoft.ClientID != "" {
		configs[ProviderMicrosoft] = &oauth2.Config{
			ClientID:     cfg.Microsoft.ClientID,
			ClientSecret: cfg.Microsoft.ClientSecret,
			RedirectURL:  cfg.Microsoft.RedirectURL,
			Scopes:       cfg.Microsoft.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
				TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			},
		}
	}

	// Discord OAuth config
	if cfg.Discord.ClientID != "" {
		configs[ProviderDiscord] = &oauth2.Config{
			ClientID:     cfg.Discord.ClientID,
			ClientSecret: cfg.Discord.ClientSecret,
			RedirectURL:  cfg.Discord.RedirectURL,
			Scopes:       cfg.Discord.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://discord.com/api/oauth2/authorize",
				TokenURL: "https://discord.com/api/oauth2/token",
			},
		}
	}

	return &oauthService{
		configs: configs,
	}
}

// GetAuthURL generates an OAuth authorization URL
func (s *oauthService) GetAuthURL(provider OAuthProvider, state string) (string, error) {
	cfg, ok := s.configs[provider]
	if !ok {
		return "", fmt.Errorf("OAuth provider %s not configured", provider)
	}

	url := cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
	return url, nil
}

// ExchangeCode exchanges an authorization code for a token
func (s *oauthService) ExchangeCode(provider OAuthProvider, code string) (*oauth2.Token, error) {
	cfg, ok := s.configs[provider]
	if !ok {
		return nil, fmt.Errorf("OAuth provider %s not configured", provider)
	}

	token, err := cfg.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	return token, nil
}

// GetUserInfo retrieves user information from the OAuth provider
func (s *oauthService) GetUserInfo(provider OAuthProvider, token *oauth2.Token) (*OAuthUserInfo, error) {
	switch provider {
	case ProviderGoogle:
		return s.getGoogleUserInfo(token)
	case ProviderGitHub:
		return s.getGitHubUserInfo(token)
	case ProviderFacebook:
		return s.getFacebookUserInfo(token)
	case ProviderApple:
		return s.getAppleUserInfo(token)
	case ProviderMicrosoft:
		return s.getMicrosoftUserInfo(token)
	case ProviderDiscord:
		return s.getDiscordUserInfo(token)
	default:
		return nil, fmt.Errorf("unsupported OAuth provider: %s", provider)
	}
}

// GenerateState generates a random state string for CSRF protection
func (s *oauthService) GenerateState() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// getGoogleUserInfo retrieves user info from Google
func (s *oauthService) getGoogleUserInfo(token *oauth2.Token) (*OAuthUserInfo, error) {
	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result struct {
		ID         string `json:"id"`
		Email      string `json:"email"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
		Picture    string `json:"picture"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	return &OAuthUserInfo{
		ProviderUserID: result.ID,
		Email:          result.Email,
		FirstName:      result.GivenName,
		LastName:       result.FamilyName,
		Picture:        result.Picture,
	}, nil
}

// getGitHubUserInfo retrieves user info from GitHub
func (s *oauthService) getGitHubUserInfo(token *oauth2.Token) (*OAuthUserInfo, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result struct {
		ID        int64  `json:"id"`
		Email     string `json:"email"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	// GitHub might not return email in the user endpoint, need to fetch separately
	if result.Email == "" {
		result.Email, _ = s.getGitHubEmail(token)
	}

	return &OAuthUserInfo{
		ProviderUserID: fmt.Sprintf("%d", result.ID),
		Email:          result.Email,
		FirstName:      result.Name,
		Picture:        result.AvatarURL,
	}, nil
}

// getGitHubEmail retrieves the primary email from GitHub
func (s *oauthService) getGitHubEmail(token *oauth2.Token) (string, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var emails []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}

	if err := json.Unmarshal(data, &emails); err != nil {
		return "", err
	}

	for _, email := range emails {
		if email.Primary {
			return email.Email, nil
		}
	}

	if len(emails) > 0 {
		return emails[0].Email, nil
	}

	return "", fmt.Errorf("no email found")
}

// getFacebookUserInfo retrieves user info from Facebook
func (s *oauthService) getFacebookUserInfo(token *oauth2.Token) (*OAuthUserInfo, error) {
	resp, err := http.Get("https://graph.facebook.com/me?fields=id,email,first_name,last_name,picture&access_token=" + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Picture   struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	return &OAuthUserInfo{
		ProviderUserID: result.ID,
		Email:          result.Email,
		FirstName:      result.FirstName,
		LastName:       result.LastName,
		Picture:        result.Picture.Data.URL,
	}, nil
}

// AppleIDTokenClaims represents the claims in an Apple ID token
type AppleIDTokenClaims struct {
	Issuer         string `json:"iss"`
	Subject        string `json:"sub"`              // User's unique identifier
	Audience       string `json:"aud"`              // Your client_id
	ExpiresAt      int64  `json:"exp"`              // Expiration time
	IssuedAt       int64  `json:"iat"`              // Issued at time
	Email          string `json:"email"`            // User's email (may be private relay)
	EmailVerified  string `json:"email_verified"`   // "true" or "false" as string
	IsPrivateEmail string `json:"is_private_email"` // Whether email is a private relay
	Nonce          string `json:"nonce"`            // Nonce for replay prevention
	AuthTime       int64  `json:"auth_time"`        // Time of authentication
}

// getAppleUserInfo retrieves user info from Apple (using JWT claims)
func (s *oauthService) getAppleUserInfo(token *oauth2.Token) (*OAuthUserInfo, error) {
	// Apple provides user info in the ID token (JWT)
	idTokenRaw := token.Extra("id_token")
	if idTokenRaw == nil {
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, ok := idTokenRaw.(string)
	if !ok || idToken == "" {
		return nil, fmt.Errorf("invalid id_token format")
	}

	// Decode the JWT payload (second part)
	// Note: In production, you should verify the JWT signature using Apple's public keys
	// from https://appleid.apple.com/auth/keys
	claims, err := s.decodeAppleIDToken(idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Apple ID token: %w", err)
	}

	// Validate issuer
	if claims.Issuer != "https://appleid.apple.com" {
		return nil, fmt.Errorf("invalid token issuer: %s", claims.Issuer)
	}

	// The 'sub' claim is the user's unique, stable identifier
	if claims.Subject == "" {
		return nil, fmt.Errorf("missing subject claim in Apple ID token")
	}

	return &OAuthUserInfo{
		ProviderUserID: claims.Subject,
		Email:          claims.Email,
		// Apple doesn't provide name in the ID token - it's only provided on first authorization
		// in a separate "user" parameter. Handle this in the callback if needed.
		FirstName: "",
		LastName:  "",
	}, nil
}

// decodeAppleIDToken decodes the payload of an Apple ID token (JWT)
// Note: This does not verify the signature. In production, verify using Apple's public keys.
func (s *oauthService) decodeAppleIDToken(idToken string) (*AppleIDTokenClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (second part)
	payload := parts[1]

	// Add padding if necessary (base64url may not have padding)
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	// Replace base64url characters with standard base64
	payload = strings.ReplaceAll(payload, "-", "+")
	payload = strings.ReplaceAll(payload, "_", "/")

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims AppleIDTokenClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return &claims, nil
}

// getMicrosoftUserInfo retrieves user info from Microsoft
func (s *oauthService) getMicrosoftUserInfo(token *oauth2.Token) (*OAuthUserInfo, error) {
	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result struct {
		ID                string `json:"id"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
		GivenName         string `json:"givenName"`
		Surname           string `json:"surname"`
		DisplayName       string `json:"displayName"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	// Use Mail if available, otherwise use UserPrincipalName
	email := result.Mail
	if email == "" {
		email = result.UserPrincipalName
	}

	return &OAuthUserInfo{
		ProviderUserID: result.ID,
		Email:          email,
		FirstName:      result.GivenName,
		LastName:       result.Surname,
	}, nil
}

// getDiscordUserInfo retrieves user info from Discord
func (s *oauthService) getDiscordUserInfo(token *oauth2.Token) (*OAuthUserInfo, error) {
	req, err := http.NewRequest("GET", "https://discord.com/api/users/@me", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result struct {
		ID            string `json:"id"`
		Username      string `json:"username"`
		Discriminator string `json:"discriminator"`
		Email         string `json:"email"`
		Avatar        string `json:"avatar"`
		GlobalName    string `json:"global_name"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	// Discord avatar URL format
	var avatarURL string
	if result.Avatar != "" {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", result.ID, result.Avatar)
	}

	// Use global_name if available, otherwise use username
	displayName := result.GlobalName
	if displayName == "" {
		displayName = result.Username
	}

	return &OAuthUserInfo{
		ProviderUserID: result.ID,
		Email:          result.Email,
		FirstName:      displayName,
		Picture:        avatarURL,
	}, nil
}
