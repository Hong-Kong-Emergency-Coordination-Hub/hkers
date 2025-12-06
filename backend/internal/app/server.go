package app

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/redis"
	"github.com/gin-gonic/gin"

	"hkers-backend/config"
	"hkers-backend/internal/core"
	"hkers-backend/internal/http/routes"
)

// NewRouter configures the Gin engine with middleware and route groups.
func NewRouter(cfg *config.Config, svc *core.Container) (*gin.Engine, error) {
	router := gin.Default()

	// CORS middleware
	router.Use(cors.New(cfg.CORS.GetCORSConfig()))

	// Session middleware using Redis
	store, err := redis.NewStore(10, "tcp", cfg.Redis.GetAddr(), "", cfg.Redis.Password, []byte(cfg.SessionSecret))
	if err != nil {
		return nil, fmt.Errorf("create Redis session store: %w", err)
	}
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   os.Getenv("GIN_MODE") == "release", // Secure cookies in production
		SameSite: http.SameSiteLaxMode,
	})
	router.Use(sessions.Sessions("auth-session", store))

	// Register route groups
	routes.RegisterHealthRoutes(router)
	routes.RegisterAuthRoutes(router, svc)
	routes.RegisterUserRoutes(router, svc)

	return router, nil
}
