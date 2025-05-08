package user

import (
	"context"

	"github.com/google/uuid"
)

// Repository defines the interface for user data storage operations.
type Repository interface {
	// Create persists a new user to the database.
	Create(ctx context.Context, user *User) error

	// FindByEmail retrieves a user by their email address.
	// Returns an error (e.g., sql.ErrNoRows) if not found.
	FindByEmail(ctx context.Context, email string) (*User, error)

	// FindByID retrieves a user by their unique ID.
	// Returns an error (e.g., sql.ErrNoRows) if not found.
	FindByID(ctx context.Context, id uuid.UUID) (*User, error)

	// Update modifies an existing user's details in the database.
	Update(ctx context.Context, user *User) error

	// TODO: Add Delete method if needed.
}
