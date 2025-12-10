package routes

import (
	"github.com/gin-gonic/gin"
	"hkers-backend/internal/http/handlers/health"
)

// RegisterHealthRoutes registers base/public routes on the given router.
func RegisterHealthRoutes(router *gin.Engine) {
	router.GET("/", health.Handler)
	router.GET("/health", health.Handler)
	router.HEAD("/health", health.Handler)
}
