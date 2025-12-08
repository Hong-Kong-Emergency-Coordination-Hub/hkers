package auth

import (
	"errors"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	coreauth "hkers-backend/internal/core/auth"
	coreuser "hkers-backend/internal/core/user"
	"hkers-backend/internal/http/response"
)

// Handler handles authentication-related HTTP requests.
type Handler struct {
	authService *coreauth.Service
	userService *coreuser.Service
}

// NewHandler creates a new auth Handler instance.
func NewHandler(authService *coreauth.Service, userService *coreuser.Service) *Handler {
	return &Handler{
		authService: authService,
		userService: userService,
	}
}

// Login initiates the OAuth2 login flow.
// GET /auth/login
func (h *Handler) Login(ctx *gin.Context) {
	if h.authService == nil {
		response.Error(ctx, http.StatusServiceUnavailable, "OIDC authentication is not configured. Please configure OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_REDIRECT_URL environment variables.")
		return
	}

	state, err := h.authService.GenerateState()
	if err != nil {
		response.Error(ctx, http.StatusInternalServerError, "Failed to generate state")
		return
	}

	codeVerifier, codeChallenge, err := h.authService.GeneratePKCE()
	if err != nil {
		response.Error(ctx, http.StatusInternalServerError, "Failed to generate PKCE verifier")
		return
	}

	// Save state in session for CSRF protection
	session := sessions.Default(ctx)
	session.Set("state", state)
	session.Set("code_verifier", codeVerifier)
	if err := session.Save(); err != nil {
		response.Error(ctx, http.StatusInternalServerError, "Failed to save session")
		return
	}

	// Redirect to OIDC authorization URL
	ctx.Redirect(http.StatusTemporaryRedirect, h.authService.GetAuthURLWithPKCE(state, codeChallenge))
}

// Callback handles the OAuth2 callback from the OIDC provider.
// GET /auth/callback
func (h *Handler) Callback(ctx *gin.Context) {
	if h.authService == nil {
		response.Error(ctx, http.StatusServiceUnavailable, "OIDC authentication is not configured. Please configure OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_REDIRECT_URL environment variables.")
		return
	}

	session := sessions.Default(ctx)

	// Verify state parameter to prevent CSRF
	if ctx.Query("state") != session.Get("state") {
		response.Error(ctx, http.StatusBadRequest, "Invalid state parameter")
		return
	}

	verifier, ok := session.Get("code_verifier").(string)
	if !ok || verifier == "" {
		response.Error(ctx, http.StatusBadRequest, "Missing PKCE verifier")
		return
	}

	// Exchange authorization code for tokens
	token, err := h.authService.ExchangeCodeWithPKCE(ctx.Request.Context(), ctx.Query("code"), verifier)
	if err != nil {
		response.Error(ctx, http.StatusUnauthorized, "Failed to exchange authorization code")
		return
	}

	// Verify the ID token
	idToken, rawIDToken, err := h.authService.VerifyIDToken(ctx.Request.Context(), token)
	if err != nil {
		response.Error(ctx, http.StatusInternalServerError, "Failed to verify ID token")
		return
	}

	// Extract user profile from claims
	profile, err := h.authService.ExtractClaims(idToken)
	if err != nil {
		response.Error(ctx, http.StatusInternalServerError, "Failed to extract claims")
		return
	}

	// Get subject identifier (unique user ID from the OIDC provider)
	oidcSub, ok := profile["sub"].(string)
	if !ok || oidcSub == "" {
		response.Error(ctx, http.StatusInternalServerError, "Invalid OIDC token: missing sub claim")
		return
	}

	// Check if user is allowed to login (must exist in database and be active)
	if h.userService != nil {
		user, err := h.userService.ValidateOIDCLogin(ctx.Request.Context(), oidcSub)
		if err != nil {
			if errors.Is(err, coreuser.ErrUserNotActive) {
				// User exists but is not activated - pending approval
				response.Error(ctx, http.StatusForbidden, "Your account is pending approval. Please contact an administrator.")
				return
			}
			if errors.Is(err, coreuser.ErrUserNotAllowed) {
				// User doesn't exist in our system
				// Option 1: Auto-create as inactive (requires admin approval)
				email, _ := profile["email"].(string)
				nickname, _ := profile["nickname"].(string)
				if nickname == "" {
					nickname, _ = profile["name"].(string)
				}
				if nickname == "" {
					nickname = oidcSub // fallback to sub as username
				}

				_, isNew, createErr := h.userService.GetOrCreateOIDCUser(ctx.Request.Context(), oidcSub, nickname, email)
				if createErr != nil {
					response.Error(ctx, http.StatusInternalServerError, "Failed to register user")
					return
				}

				if isNew {
					response.Error(ctx, http.StatusForbidden, "Your account has been registered and is pending approval. Please contact an administrator.")
				} else {
					response.Error(ctx, http.StatusForbidden, "Your account is not active. Please contact an administrator.")
				}
				return
			}
			// Other database errors
			response.Error(ctx, http.StatusInternalServerError, "Failed to validate user")
			return
		}

		// User is valid - store their database ID in session for later use
		profile["db_user_id"] = user.ID
	}

	// Store tokens and profile in session
	session.Set("access_token", token.AccessToken)
	session.Set("id_token", rawIDToken)
	session.Set("profile", profile)
	if err := session.Save(); err != nil {
		response.Error(ctx, http.StatusInternalServerError, "Failed to save session")
		return
	}

	// Redirect to user profile page
	ctx.Redirect(http.StatusTemporaryRedirect, "/user")
}

// Logout handles user logout.
// GET /auth/logout
func (h *Handler) Logout(ctx *gin.Context) {
	session := sessions.Default(ctx)
	rawIDToken, _ := session.Get("id_token").(string)

	// Clear session
	session.Clear()
	if err := session.Save(); err != nil {
		response.Error(ctx, http.StatusInternalServerError, "Failed to clear session")
		return
	}

	// If OIDC is not configured, just redirect to home
	if h.authService == nil {
		ctx.Redirect(http.StatusTemporaryRedirect, "/")
		return
	}

	// Build return URL (prefer configured post-logout redirect)
	returnToURL := h.authService.PostLogoutRedirect()
	if returnToURL == "" {
		scheme := "http"
		if ctx.Request.TLS != nil {
			scheme = "https"
		}
		returnToURL = scheme + "://" + ctx.Request.Host
	}

	// Get provider end-session URL (if configured)
	logoutURL, ok, err := h.authService.GetEndSessionURL(returnToURL, rawIDToken)
	if err != nil {
		response.Error(ctx, http.StatusInternalServerError, "Failed to build logout URL")
		return
	}
	if !ok {
		ctx.Redirect(http.StatusTemporaryRedirect, returnToURL)
		return
	}

	ctx.Redirect(http.StatusTemporaryRedirect, logoutURL)
}
