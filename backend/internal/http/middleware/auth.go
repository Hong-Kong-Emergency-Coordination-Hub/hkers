// internal/middleware/auth.go

package middleware

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// IsAuthenticated is a middleware that checks if the user is authenticated.
// It verifies that a valid profile exists in the session.
func IsAuthenticated() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		profile := session.Get("profile")

		if profile == nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "Authentication required",
			})
			return
		}

		ctx.Next()
	}
}

// GetAccessToken is a middleware helper that retrieves the access token from the session.
func GetAccessToken(ctx *gin.Context) string {
	session := sessions.Default(ctx)
	token := session.Get("access_token")
	if token == nil {
		return ""
	}
	return token.(string)
}
