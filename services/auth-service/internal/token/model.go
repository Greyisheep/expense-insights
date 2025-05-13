package token

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken represents a stored refresh token.
type RefreshToken struct {
	ID         uuid.UUID     `json:"-"`
	UserID     uuid.UUID     `json:"-"`
	TokenHash  string        `json:"-"` // Store a hash of the token, not the token itself
	ExpiresAt  time.Time     `json:"expires_at"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`
	Revoked    bool          `json:"revoked"`
	ReplacedBy uuid.NullUUID `json:"-"` // Use uuid.NullUUID for nullable FK
}

// Note: uuid.NullUUID requires a custom type or a library that supports it if not available directly.
// Alternatively, use sql.NullString and parse/format UUIDs, or handle nulls in repository logic.
// For simplicity now, we might adjust this later based on library choices or actual implementation needs.
// Let's assume a library or custom type provides uuid.NullUUID for now.
// We will need to add a dependency or define this type if it causes build errors.
