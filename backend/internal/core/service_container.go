package core

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"hkers-backend/internal/core/auth"
	"hkers-backend/internal/core/user"
)

// Container holds all application services.
// Pass this to handlers instead of individual services.
type Container struct {
	Auth *auth.Service
	User *user.Service
	// Add more services as needed:
	// Email *EmailService
}

// NewContainer creates a new service container.
func NewContainer(authSvc *auth.Service, pool *pgxpool.Pool) *Container {
	return &Container{
		Auth: authSvc,
		User: user.NewService(pool),
	}
}
