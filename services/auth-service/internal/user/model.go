package user

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system.
type User struct {
	ID           uuid.UUID      `json:"id"`
	Email        string         `json:"email"`
	PasswordHash string         `json:"-"` // Never expose hash
	FirstName    string         `json:"first_name"`
	LastName     string         `json:"last_name"`
	PhoneNumber  sql.NullString `json:"phone_number,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	LastLoginAt  sql.NullTime   `json:"last_login_at,omitempty"`
	Status       string         `json:"status"`
	Role         string         `json:"role"`
}

// Constants for user status and roles
const (
	StatusActive   = "active"
	StatusInactive = "inactive"
	StatusPending  = "pending" // e.g., email verification needed

	RoleUser  = "user"
	RoleAdmin = "admin"
	RolePro   = "pro" // Consider adding role validation to ensure only valid roles are assigned
)
