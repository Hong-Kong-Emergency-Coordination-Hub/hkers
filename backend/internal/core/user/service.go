package user

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "hkers-backend/internal/db/generated"
)

var (
	ErrUserNotFound   = errors.New("user not found")
	ErrUserNotActive  = errors.New("user account is not active")
	ErrUserNotAllowed = errors.New("user is not allowed to access this application")
)

// Service handles user-related business logic.
type Service struct {
	queries *db.Queries
}

// NewService creates a new user service instance.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{
		queries: db.New(pool),
	}
}

// ValidateOIDCLogin checks if an OIDC user is allowed to login.
// Returns the user if they exist and are active, otherwise returns an error.
func (s *Service) ValidateOIDCLogin(ctx context.Context, oidcSub string) (*db.User, error) {
	user, err := s.queries.GetActiveUserByOIDCSub(ctx, oidcSub)
	if err != nil {
		// Check if they exist but are inactive
		existingUser, checkErr := s.queries.GetUserByOIDCSub(ctx, oidcSub)
		if checkErr == nil && existingUser.ID > 0 {
			// User exists but is not active
			return nil, ErrUserNotActive
		}
		// User doesn't exist at all
		return nil, ErrUserNotAllowed
	}
	return &user, nil
}

// GetOrCreateOIDCUser gets an existing user by OIDC sub, or creates a new inactive user.
// New users are created with is_active=false and require admin approval.
func (s *Service) GetOrCreateOIDCUser(ctx context.Context, oidcSub, username, email string) (*db.User, bool, error) {
	// First, try to get existing user
	existingUser, err := s.queries.GetUserByOIDCSub(ctx, oidcSub)
	if err == nil {
		// User exists
		return &existingUser, false, nil
	}

	// User doesn't exist, create new inactive user
	newUser, err := s.queries.CreateUserFromOIDC(ctx, db.CreateUserFromOIDCParams{
		OidcSub:  oidcSub,
		Username: username,
		Email:    pgtype.Text{String: email, Valid: email != ""},
	})
	if err != nil {
		return nil, false, err
	}

	return &newUser, true, nil // true = newly created
}

// GetUserByID retrieves a user by their ID.
func (s *Service) GetUserByID(ctx context.Context, id int32) (*db.User, error) {
	user, err := s.queries.GetUserByID(ctx, id)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return &user, nil
}

// ActivateUser activates a user account (admin only).
func (s *Service) ActivateUser(ctx context.Context, userID int32) (*db.User, error) {
	user, err := s.queries.ActivateUser(ctx, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return &user, nil
}

// DeactivateUser deactivates a user account (admin only).
func (s *Service) DeactivateUser(ctx context.Context, userID int32) (*db.User, error) {
	user, err := s.queries.DeactivateUser(ctx, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return &user, nil
}
