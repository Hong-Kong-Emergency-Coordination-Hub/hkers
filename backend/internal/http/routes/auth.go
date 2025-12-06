package routes

import (
	"github.com/gin-gonic/gin"

	"hkers-backend/internal/core"
	authhandler "hkers-backend/internal/http/handlers/auth"
)

// RegisterAuthRoutes registers auth routes on the given router.
func RegisterAuthRoutes(router *gin.Engine, svc *core.Container) {
	h := authhandler.NewHandler(svc.Auth, svc.User)

	// Auth routes under /auth
	auth := router.Group("/auth")
	{
		auth.GET("/login", h.Login)
		auth.GET("/callback", h.Callback)
		auth.GET("/logout", h.Logout)
	}
}
