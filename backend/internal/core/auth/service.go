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

// Service handles authentication logic with a generic OIDC provider.
type Service struct {
	provider      *oidc.Provider
	config        oauth2.Config
	issuer        string
	clientID      string
	endSessionURL string
	postLogoutURL string
}

// NewService creates a new OIDC authentication service instance.
func NewService(cfg *config.OIDCConfig) (*Service, error) {
	// Validate required configuration
	required := []struct {
		value string
		err   string
	}{
		{cfg.Issuer, "OIDC issuer is required but not configured. Set OIDC_ISSUER environment variable"},
		{cfg.ClientID, "OIDC client ID is required but not configured. Set OIDC_CLIENT_ID environment variable"},
		{cfg.ClientSecret, "OIDC client secret is required but not configured. Set OIDC_CLIENT_SECRET environment variable"},
		{cfg.RedirectURL, "OIDC redirect URL is required but not configured. Set OIDC_REDIRECT_URL environment variable"},
	}
	for _, item := range required {
		if item.value == "" {
			return nil, errors.New(item.err)
		}
	}

	issuerURL := cfg.Issuer

	// Create context with timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, errors.New("failed to initialize OIDC provider: " + err.Error() + " (issuer URL: " + issuerURL + "). Check that OIDC_ISSUER is correct and accessible.")
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	oauthConfig := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	return &Service{
		provider:      provider,
		config:        oauthConfig,
		issuer:        cfg.Issuer,
		clientID:      cfg.ClientID,
		endSessionURL: cfg.EndSessionURL,
		postLogoutURL: cfg.PostLogoutRedirectURL,
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

// GetAuthURL returns the OIDC authorization URL.
func (s *Service) GetAuthURL(state string) string {
	return s.config.AuthCodeURL(state)
}

// GetAuthURLWithPKCE returns the OIDC authorization URL including PKCE params.
func (s *Service) GetAuthURLWithPKCE(state, codeChallenge string) string {
	return s.config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// ExchangeCodeWithPKCE exchanges a code using the provided PKCE verifier.
func (s *Service) ExchangeCodeWithPKCE(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	return s.config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
}

// VerifyIDToken verifies that an oauth2.Token contains a valid ID token.
// Returns both the parsed token and the raw ID token string for downstream use.
func (s *Service) VerifyIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, string, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, "", errors.New("no id_token field in oauth2 token")
	}

	oidcConfig := &oidc.Config{
		ClientID: s.clientID,
	}

	idTok, err := s.provider.Verifier(oidcConfig).Verify(ctx, rawIDToken)
	return idTok, rawIDToken, err
}

// GetEndSessionURL returns an OIDC end-session URL (if configured).
// The boolean indicates whether an end-session endpoint is available.
func (s *Service) GetEndSessionURL(returnToURL, idTokenHint string) (string, bool, error) {
	if s.endSessionURL == "" {
		return "", false, nil
	}

	logoutURL, err := url.Parse(s.endSessionURL)
	if err != nil {
		return "", false, err
	}

	parameters := url.Values{}
	if returnToURL != "" {
		parameters.Add("post_logout_redirect_uri", returnToURL)
	}
	if idTokenHint != "" {
		parameters.Add("id_token_hint", idTokenHint)
	}
	logoutURL.RawQuery = parameters.Encode()

	return logoutURL.String(), true, nil
}

// PostLogoutRedirect returns the configured default post-logout redirect URL (if any).
func (s *Service) PostLogoutRedirect() string {
	return s.postLogoutURL
}

// ExtractClaims extracts claims from an ID token into a map.
func (s *Service) ExtractClaims(idToken *oidc.IDToken) (map[string]interface{}, error) {
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}
