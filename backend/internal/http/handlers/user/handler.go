package user

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"hkers-backend/internal/http/response"
)

// Handler handles user-related HTTP requests.
type Handler struct {
	// Add user service dependency here when needed
	// userService *services.UserService
}

// NewHandler creates a new user Handler instance.
func NewHandler() *Handler {
	return &Handler{}
}

// GetProfile returns the authenticated user's profile.
// GET /user
func (h *Handler) GetProfile(ctx *gin.Context) {
	session := sessions.Default(ctx)
	profile := session.Get("profile")

	if profile == nil {
		response.Error(ctx, http.StatusUnauthorized, "User not authenticated")
		return
	}

	response.Success(ctx, http.StatusOK, profile)
}
