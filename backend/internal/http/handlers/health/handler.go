package health

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"hkers-backend/internal/http/response"
)

// Handler returns the health status of the API.
func Handler(ctx *gin.Context) {
	if ctx.Request.Method == http.MethodHead {
		ctx.Status(http.StatusOK)
		return
	}

	response.Success(ctx, http.StatusOK, gin.H{
		"status":  "healthy",
		"message": "HKERS API Server",
	})
}
