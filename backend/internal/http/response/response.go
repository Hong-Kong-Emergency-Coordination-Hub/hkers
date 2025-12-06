package response

import "github.com/gin-gonic/gin"

// Response represents a standard API response envelope.
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// Success sends a successful JSON response.
func Success(ctx *gin.Context, statusCode int, data interface{}) {
	ctx.JSON(statusCode, Response{
		Success: true,
		Data:    data,
	})
}

// Error sends an error JSON response.
func Error(ctx *gin.Context, statusCode int, message string) {
	ctx.JSON(statusCode, Response{
		Success: false,
		Error:   message,
	})
}
