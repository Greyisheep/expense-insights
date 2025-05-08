package token

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Greyisheep/expense-insights/auth-service/internal/database/db"
	"github.com/google/uuid"
)

// Repository defines the interface for refresh token storage operations.
type Repository interface {
	// Create persists a new refresh token (hash) to the database.
	Create(ctx context.Context, token *RefreshToken) (*RefreshToken, error)

	// FindByTokenHash retrieves a refresh token by its hash.
	// Returns an error (e.g., sql.ErrNoRows) if not found or if revoked.
	FindByTokenHash(ctx context.Context, tokenHash string) (*RefreshToken, error)

	// FindByID retrieves a refresh token by its ID.
	// Returns an error (e.g., sql.ErrNoRows) if not found or if revoked.
	FindByID(ctx context.Context, tokenID uuid.UUID) (*RefreshToken, error)

	// MarkRevoked marks a specific refresh token as revoked.
	MarkRevoked(ctx context.Context, tokenID uuid.UUID) error

	// SetReplacedBy sets the replaced_by relationship for a refresh token.
	SetReplacedBy(ctx context.Context, tokenID, replacedByTokenID uuid.UUID) error

	// DeleteByUserID removes all refresh tokens associated with a user.
	DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error)

	// CleanupExpired deletes expired refresh tokens from the database.
	CleanupExpired(ctx context.Context) (int64, error)

	// TODO: Add cleanup method for expired tokens.
}

// sqlcTokenRepository implements the Repository interface using sqlc queries.
type sqlcTokenRepository struct {
	q *db.Queries
}

// NewSQLCTokenRepository creates a new instance of sqlcTokenRepository.
func NewSQLCTokenRepository(queries *db.Queries) Repository {
	return &sqlcTokenRepository{q: queries}
}

// mapDBRefreshTokenToToken converts a db.RefreshToken (sqlc model) to a token.RefreshToken (domain model).
func mapDBRefreshTokenToToken(dbToken db.RefreshToken) *RefreshToken {
	rt := &RefreshToken{
		ID:        dbToken.ID,
		UserID:    dbToken.UserID,
		TokenHash: dbToken.TokenHash,
		ExpiresAt: dbToken.ExpiresAt,
		// ReplacedBy is already uuid.NullUUID in both structs, so direct assignment is fine.
		ReplacedBy: dbToken.ReplacedBy,
	}

	if dbToken.CreatedAt.Valid {
		rt.CreatedAt = dbToken.CreatedAt.Time
	}
	if dbToken.UpdatedAt.Valid {
		rt.UpdatedAt = dbToken.UpdatedAt.Time
	}
	if dbToken.Revoked.Valid {
		rt.Revoked = dbToken.Revoked.Bool
	} else {
		// If Revoked is NULL in DB (shouldn't happen with DEFAULT false but handling defensively)
		rt.Revoked = false // Default to false if somehow NULL
	}
	return rt
}

// mapTokenToCreateRefreshTokenParams converts a token.RefreshToken to db.CreateRefreshTokenParams.
func mapTokenToCreateRefreshTokenParams(token *RefreshToken) db.CreateRefreshTokenParams {
	return db.CreateRefreshTokenParams{
		UserID:    token.UserID,
		TokenHash: token.TokenHash, // Correctly maps to TokenHash
		ExpiresAt: token.ExpiresAt,
	}
}

func (r *sqlcTokenRepository) Create(ctx context.Context, token *RefreshToken) (*RefreshToken, error) {
	dbToken, err := r.q.CreateRefreshToken(ctx, mapTokenToCreateRefreshTokenParams(token))
	if err != nil {
		return nil, err
	}
	return mapDBRefreshTokenToToken(dbToken), nil
}

func (r *sqlcTokenRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	dbToken, err := r.q.GetRefreshTokenByToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}
	return mapDBRefreshTokenToToken(dbToken), nil
}

func (r *sqlcTokenRepository) FindByID(ctx context.Context, tokenID uuid.UUID) (*RefreshToken, error) {
	dbToken, err := r.q.GetRefreshTokenByID(ctx, tokenID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}
	return mapDBRefreshTokenToToken(dbToken), nil
}

func (r *sqlcTokenRepository) MarkRevoked(ctx context.Context, tokenID uuid.UUID) error {
	return r.q.RevokeRefreshToken(ctx, tokenID)
}

func (r *sqlcTokenRepository) SetReplacedBy(ctx context.Context, tokenID, replacedByTokenID uuid.UUID) error {
	return r.q.SetRefreshTokenReplacedBy(ctx, db.SetRefreshTokenReplacedByParams{
		ID:         tokenID,
		ReplacedBy: uuid.NullUUID{UUID: replacedByTokenID, Valid: true},
	})
}

func (r *sqlcTokenRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	return r.q.DeleteRefreshTokensByUserID(ctx, userID)
}

func (r *sqlcTokenRepository) CleanupExpired(ctx context.Context) (int64, error) {
	return r.q.DeleteExpiredRefreshTokens(ctx)
}

// ErrTokenNotFound is returned when a token is not found or is invalid.
var ErrTokenNotFound = errors.New("token not found or invalid")

// Ensure sqlcTokenRepository implements Repository interface
var _ Repository = (*sqlcTokenRepository)(nil)
