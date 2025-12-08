// cmd/server/main.go

package main

import (
	"context"
	"encoding/gob"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"hkers-backend/config"
	"hkers-backend/internal/app"
	"hkers-backend/internal/core"
	coreauth "hkers-backend/internal/core/auth"
)

func init() {
	// Register custom types for gob encoding/decoding (used by sessions)
	// Must be registered before any session operations
	gob.Register(map[string]interface{}{})
}

func main() {
	// Set Gin mode from environment
	if mode := os.Getenv("GIN_MODE"); mode != "" {
		gin.SetMode(mode)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	ctx := context.Background()
	// Initialize database connection pool
	pool, err := initDB(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to create database connection pool: %v", err)
	}
	defer pool.Close()

	// Initialize Redis client (used by session store)
	redisClient, err := initRedis(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer redisClient.Close()

	// Initialize services
	var authService *coreauth.Service
	log.Printf("Initializing OIDC service with issuer: %s", cfg.OIDC.Issuer)
	authService, err = coreauth.NewService(&cfg.OIDC)
	if err != nil {
		log.Fatalf("Failed to initialize auth service: %v", err)
	}
	log.Printf("OIDC service initialized successfully")

	// Create service container with database pool
	svc := core.NewContainer(authService, pool)

	// Setup router
	router, err := app.NewRouter(cfg, svc)
	if err != nil {
		log.Fatalf("Failed to set up router: %v", err)
	}

	// Start server
	addr := cfg.Server.Host + ":" + cfg.Server.Port
	log.Printf("Server listening on http://%s/", addr)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
