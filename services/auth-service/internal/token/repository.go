package token

import (
	"context"

	"github.com/google/uuid"
)

// Repository defines the interface for refresh token storage operations.
type Repository interface {
	// Create persists a new refresh token (hash) to the database.
	Create(ctx context.Context, token *RefreshToken) error

	// FindByTokenHash retrieves a refresh token by its hash.
	// Returns an error (e.g., sql.ErrNoRows) if not found or if revoked.
	FindByTokenHash(ctx context.Context, tokenHash string) (*RefreshToken, error)

	// MarkRevoked marks a specific refresh token as revoked.
	MarkRevoked(ctx context.Context, tokenID uuid.UUID) error

	// MarkFamilyRevoked marks a token and any of its predecessors (via replaced_by) as revoked.
	// Useful for security events or logout.
	MarkFamilyRevoked(ctx context.Context, currentTokenID uuid.UUID) error

	// DeleteByUserID removes all refresh tokens associated with a user.
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error

	// TODO: Add cleanup method for expired tokens.
}
