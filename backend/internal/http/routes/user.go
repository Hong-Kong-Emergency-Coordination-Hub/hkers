package routes

import (
	"github.com/gin-gonic/gin"

	"hkers-backend/internal/core"
	"hkers-backend/internal/http/handlers/user"
	"hkers-backend/internal/http/middleware"
)

// RegisterUserRoutes registers user routes on the given router.
func RegisterUserRoutes(router *gin.Engine, svc *core.Container) {
	_ = svc // Will be used when user service is added
	h := user.NewHandler()

	// Protected routes - require authentication
	protected := router.Group("/")
	protected.Use(middleware.IsAuthenticated())
	{
		protected.GET("/user", h.GetProfile)
	}

	// API routes
	api := router.Group("/api/v1")
	api.Use(middleware.IsAuthenticated())
	{
		api.GET("/me", h.GetProfile)
	}
}
