package user

import (
	"context"
	"database/sql"
	"errors" // Import for handling specific errors like sql.ErrNoRows

	"github.com/Greyisheep/expense-insights/auth-service/internal/database/db" // Corrected import path
	"github.com/google/uuid"
)

// Repository defines the interface for user data storage operations.
type Repository interface {
	// Create persists a new user to the database.
	Create(ctx context.Context, user *User) (*User, error)

	// FindByEmail retrieves a user by their email address.
	// Returns an error (e.g., sql.ErrNoRows) if not found.
	FindByEmail(ctx context.Context, email string) (*User, error)

	// FindByID retrieves a user by their unique ID.
	// Returns an error (e.g., sql.ErrNoRows) if not found.
	FindByID(ctx context.Context, id uuid.UUID) (*User, error)

	// Update modifies an existing user's details in the database.
	Update(ctx context.Context, user *User) (*User, error)

	// TODO: Add Delete method if needed.
}

// sqlcUserRepository implements the Repository interface using sqlc queries.
type sqlcUserRepository struct {
	q *db.Queries // Use the sqlc generated Queries struct
}

// NewSQLCUserRepository creates a new instance of sqlcUserRepository.
func NewSQLCUserRepository(queries *db.Queries) Repository {
	return &sqlcUserRepository{q: queries}
}

// mapDBUserToUser converts a db.User (sqlc model) to a user.User (domain model).
func mapDBUserToUser(dbUser db.User) *User {
	return &User{
		ID:           dbUser.ID,
		Email:        dbUser.Email,
		PasswordHash: dbUser.PasswordHash,
		FirstName:    dbUser.FirstName,
		LastName:     dbUser.LastName,
		PhoneNumber:  dbUser.PhoneNumber,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
		LastLoginAt:  dbUser.LastLoginAt,
		Status:       dbUser.Status,
		Role:         dbUser.Role,
	}
}

// mapUserToCreateUserParams converts a user.User to db.CreateUserParams.
func mapUserToCreateUserParams(usr *User) db.CreateUserParams {
	return db.CreateUserParams{
		Email:        usr.Email,
		PasswordHash: usr.PasswordHash,
		FirstName:    usr.FirstName,
		LastName:     usr.LastName,
		PhoneNumber:  usr.PhoneNumber,
		Status:       usr.Status,
		Role:         usr.Role,
	}
}

// mapUserToUpdateUserParams converts a user.User to db.UpdateUserParams.
func mapUserToUpdateUserParams(usr *User) db.UpdateUserParams {
	return db.UpdateUserParams{
		ID:           usr.ID, // Important: ID is needed for the WHERE clause
		FirstName:    usr.FirstName,
		LastName:     usr.LastName,
		PhoneNumber:  usr.PhoneNumber,
		Status:       usr.Status,
		Role:         usr.Role,
		PasswordHash: usr.PasswordHash, // Make sure to handle password updates carefully
		LastLoginAt:  usr.LastLoginAt,
	}
}

func (r *sqlcUserRepository) Create(ctx context.Context, usr *User) (*User, error) {
	dbUser, err := r.q.CreateUser(ctx, mapUserToCreateUserParams(usr))
	if err != nil {
		return nil, err // Consider wrapping error for more context
	}
	return mapDBUserToUser(dbUser), nil
}

func (r *sqlcUserRepository) FindByEmail(ctx context.Context, email string) (*User, error) {
	dbUser, err := r.q.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound // Define ErrUserNotFound
		}
		return nil, err
	}
	return mapDBUserToUser(dbUser), nil
}

func (r *sqlcUserRepository) FindByID(ctx context.Context, id uuid.UUID) (*User, error) {
	dbUser, err := r.q.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound // Define ErrUserNotFound
		}
		return nil, err
	}
	return mapDBUserToUser(dbUser), nil
}

func (r *sqlcUserRepository) Update(ctx context.Context, usr *User) (*User, error) {
	dbUser, err := r.q.UpdateUser(ctx, mapUserToUpdateUserParams(usr))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) { // Update might fail if ID not found
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return mapDBUserToUser(dbUser), nil
}

// ErrUserNotFound is returned when a user is not found in the repository.
var ErrUserNotFound = errors.New("user not found")

// Ensure sqlcUserRepository implements Repository interface
var _ Repository = (*sqlcUserRepository)(nil)
