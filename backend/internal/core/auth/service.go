package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"hkers-backend/config"
)

// Service handles authentication logic with Auth0.
type Service struct {
	provider *oidc.Provider
	config   oauth2.Config
	domain   string
	clientID string
}

// NewService creates a new Auth0 authentication service instance.
func NewService(cfg *config.Auth0Config) (*Service, error) {
	// Validate required configuration
	if cfg.Domain == "" {
		return nil, errors.New("Auth0 domain is required but not configured. Set AUTH0_DOMAIN environment variable")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("Auth0 client ID is required but not configured. Set AUTH0_CLIENT_ID environment variable")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("Auth0 client secret is required but not configured. Set AUTH0_CLIENT_SECRET environment variable")
	}
	if cfg.CallbackURL == "" {
		return nil, errors.New("Auth0 callback URL is required but not configured. Set AUTH0_CALLBACK_URL environment variable")
	}

	issuerURL := "https://" + cfg.Domain + "/"

	// Create context with timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, errors.New("failed to initialize OIDC provider: " + err.Error() + " (issuer URL: " + issuerURL + "). Check that AUTH0_DOMAIN is correct and accessible.")
	}

	oauthConfig := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.CallbackURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return &Service{
		provider: provider,
		config:   oauthConfig,
		domain:   cfg.Domain,
		clientID: cfg.ClientID,
	}, nil
}

// GenerateState creates a random state string for CSRF protection.
func (s *Service) GenerateState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// GeneratePKCE creates a verifier/challenge pair for PKCE.
func (s *Service) GeneratePKCE() (verifier string, challenge string, err error) {
	// 43–128 chars recommended; 32 bytes -> 43 chars when base64url encoded.
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge, nil
}

// GetAuthURL returns the Auth0 authorization URL.
func (s *Service) GetAuthURL(state string) string {
	return s.config.AuthCodeURL(state)
}

// GetAuthURLWithPKCE returns the Auth0 authorization URL including PKCE params.
func (s *Service) GetAuthURLWithPKCE(state, codeChallenge string) string {
	return s.config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// ExchangeCode exchanges an authorization code for tokens.
func (s *Service) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return s.config.Exchange(ctx, code)
}

// ExchangeCodeWithPKCE exchanges a code using the provided PKCE verifier.
func (s *Service) ExchangeCodeWithPKCE(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	return s.config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
}

// VerifyIDToken verifies that an oauth2.Token contains a valid ID token.
func (s *Service) VerifyIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no id_token field in oauth2 token")
	}

	oidcConfig := &oidc.Config{
		ClientID: s.clientID,
	}

	return s.provider.Verifier(oidcConfig).Verify(ctx, rawIDToken)
}

// GetLogoutURL returns the Auth0 logout URL.
func (s *Service) GetLogoutURL(returnToURL string) (string, error) {
	logoutURL, err := url.Parse("https://" + s.domain + "/v2/logout")
	if err != nil {
		return "", err
	}

	parameters := url.Values{}
	parameters.Add("returnTo", returnToURL)
	parameters.Add("client_id", s.clientID)
	logoutURL.RawQuery = parameters.Encode()

	return logoutURL.String(), nil
}

// ExtractClaims extracts claims from an ID token into a map.
func (s *Service) ExtractClaims(idToken *oidc.IDToken) (map[string]interface{}, error) {
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}
