package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Greyisheep/expense-insights/auth-service/internal/token"
	"github.com/Greyisheep/expense-insights/auth-service/internal/user"
	"github.com/google/uuid"
	passwordvalidator "github.com/wagslane/go-password-validator"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserAlreadyExists       = errors.New("user with this email already exists")
	ErrInvalidCredentials      = errors.New("invalid email or password")
	ErrUserNotFound            = errors.New("user not found")
	ErrTokenInvalid            = errors.New("refresh token is invalid or expired")
	ErrTokenRevoked            = errors.New("refresh token has been revoked")
	ErrTokenReused             = errors.New("refresh token has been reused (possible theft attempt)")
	ErrPasswordTooShort        = errors.New("password is too short (minimum 8 characters)")
	ErrPasswordNotStrongEnough = errors.New("password does not meet strength requirements")
	ErrAccountInactive         = errors.New("account is inactive")
	ErrAccountPending          = errors.New("account is pending verification")
)

const (
	minPasswordLength  = 8
	minPasswordEntropy = 60.0
)

// Service defines the interface for authentication operations.
type Service interface {
	Register(ctx context.Context, email, password, firstName, lastName string) (*user.User, string, string, time.Time, error)
	Login(ctx context.Context, email, password string) (*user.User, string, string, time.Time, error)
	Logout(ctx context.Context, refreshTokenString string) error
	RefreshToken(ctx context.Context, refreshTokenString string) (string, string, time.Time, error)
	GetUserDetails(ctx context.Context, userID uuid.UUID) (*user.User, error)
	ValidateAccessToken(ctx context.Context, tokenString string) (userID uuid.UUID, userRole string, err error)
}

type service struct {
	userRepo  user.Repository
	tokenRepo token.Repository
	tokenSvc  token.Service
	logger    *slog.Logger
}

// NewService creates a new authentication service instance.
func NewService(userRepo user.Repository, tokenRepo token.Repository, tokenSvc token.Service, logger *slog.Logger) Service {
	return &service{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		tokenSvc:  tokenSvc,
		logger:    logger.With(slog.String("service", "auth")),
	}
}

func (s *service) Register(ctx context.Context, email, password, firstName, lastName string) (*user.User, string, string, time.Time, error) {
	s.logger.InfoContext(ctx, "Registration attempt", slog.String("email", email))

	if len(password) < minPasswordLength {
		s.logger.WarnContext(ctx, "Registration failed: password too short", slog.String("email", email))
		return nil, "", "", time.Time{}, ErrPasswordTooShort
	}

	err := passwordvalidator.Validate(password, minPasswordEntropy)
	if err != nil {
		s.logger.WarnContext(ctx, "Registration failed: password not strong enough", slog.String("email", email), slog.Any("validation_error", err.Error()))
		return nil, "", "", time.Time{}, ErrPasswordNotStrongEnough
	}

	_, err = s.userRepo.FindByEmail(ctx, email)
	if err == nil {
		s.logger.WarnContext(ctx, "Registration failed: user already exists", slog.String("email", email))
		return nil, "", "", time.Time{}, ErrUserAlreadyExists
	}
	if !errors.Is(err, user.ErrUserNotFound) {
		s.logger.ErrorContext(ctx, "Failed to check existing user during registration", slog.Any("error", err), slog.String("email", email))
		return nil, "", "", time.Time{}, fmt.Errorf("could not verify user existence: %w", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to hash password during registration", slog.Any("error", err), slog.String("email", email))
		return nil, "", "", time.Time{}, fmt.Errorf("could not hash password: %w", err)
	}

	newUser := &user.User{
		Email:        email,
		PasswordHash: string(hashedPassword),
		FirstName:    firstName,
		LastName:     lastName,
		Status:       user.StatusActive,
		Role:         user.RoleUser,
	}

	createdUser, err := s.userRepo.Create(ctx, newUser)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to create user in repository", slog.Any("error", err), slog.String("email", email))
		return nil, "", "", time.Time{}, fmt.Errorf("could not create user: %w", err)
	}

	accessToken, err := s.tokenSvc.GenerateAccessToken(ctx, createdUser.ID, createdUser.Role)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to generate access token post-registration", slog.Any("error", err), slog.String("user_id", createdUser.ID.String()))
		return nil, "", "", time.Time{}, fmt.Errorf("could not generate access token: %w", err)
	}

	refreshTokenData, refreshTokenString, err := s.tokenSvc.GenerateRefreshToken(ctx, createdUser.ID)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to generate refresh token post-registration", slog.Any("error", err), slog.String("user_id", createdUser.ID.String()))
		return nil, "", "", time.Time{}, fmt.Errorf("could not generate refresh token: %w", err)
	}

	s.logger.InfoContext(ctx, "User registered successfully", slog.String("user_id", createdUser.ID.String()), slog.String("email", createdUser.Email))
	return createdUser, accessToken, refreshTokenString, refreshTokenData.ExpiresAt, nil
}

func (s *service) Login(ctx context.Context, email, password string) (*user.User, string, string, time.Time, error) {
	s.logger.InfoContext(ctx, "Login attempt", slog.String("email", email))

	usr, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			s.logger.WarnContext(ctx, "Login failed: user not found", slog.String("email", email))
			return nil, "", "", time.Time{}, ErrInvalidCredentials
		}
		s.logger.ErrorContext(ctx, "Failed to find user by email during login", slog.Any("error", err), slog.String("email", email))
		return nil, "", "", time.Time{}, fmt.Errorf("could not retrieve user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(usr.PasswordHash), []byte(password)); err != nil {
		s.logger.WarnContext(ctx, "Login failed: invalid password", slog.String("user_id", usr.ID.String()), slog.String("email", email))
		return nil, "", "", time.Time{}, ErrInvalidCredentials
	}

	if usr.Status == user.StatusInactive {
		s.logger.WarnContext(ctx, "Login failed: account inactive", slog.String("user_id", usr.ID.String()), slog.String("email", email))
		return nil, "", "", time.Time{}, ErrAccountInactive
	}
	if usr.Status == user.StatusPending {
		s.logger.WarnContext(ctx, "Login failed: account pending verification", slog.String("user_id", usr.ID.String()), slog.String("email", email))
		return nil, "", "", time.Time{}, ErrAccountPending
	}

	accessToken, err := s.tokenSvc.GenerateAccessToken(ctx, usr.ID, usr.Role)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to generate access token during login", slog.Any("error", err), slog.String("user_id", usr.ID.String()))
		return nil, "", "", time.Time{}, fmt.Errorf("could not generate access token: %w", err)
	}

	refreshTokenData, refreshTokenString, err := s.tokenSvc.GenerateRefreshToken(ctx, usr.ID)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to generate refresh token during login", slog.Any("error", err), slog.String("user_id", usr.ID.String()))
		return nil, "", "", time.Time{}, fmt.Errorf("could not generate refresh token: %w", err)
	}

	usr.LastLoginAt = sql.NullTime{Time: time.Now(), Valid: true}
	_, updateErr := s.userRepo.Update(ctx, usr)
	if updateErr != nil {
		s.logger.ErrorContext(ctx, "Failed to update last login time", slog.Any("error", updateErr), slog.String("user_id", usr.ID.String()))
	}

	s.logger.InfoContext(ctx, "User logged in successfully", slog.String("user_id", usr.ID.String()), slog.String("email", email))
	return usr, accessToken, refreshTokenString, refreshTokenData.ExpiresAt, nil
}

func (s *service) Logout(ctx context.Context, refreshTokenString string) error {
	s.logger.InfoContext(ctx, "Logout attempt")
	tokenHash := s.tokenSvc.HashToken(refreshTokenString)

	tokenData, err := s.tokenRepo.FindByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, token.ErrTokenNotFound) {
			s.logger.WarnContext(ctx, "Logout failed: refresh token not found", slog.String("token_hash_prefix", tokenHash[:min(8, len(tokenHash))]))
			return ErrTokenInvalid
		}
		s.logger.ErrorContext(ctx, "Failed to find refresh token by hash during logout", slog.Any("error", err))
		return fmt.Errorf("could not retrieve refresh token: %w", err)
	}

	if tokenData.Revoked {
		s.logger.WarnContext(ctx, "Logout attempt with already revoked token", slog.String("token_id", tokenData.ID.String()))
		return nil
	}

	if tokenData.ReplacedBy.Valid {
		s.logger.WarnContext(ctx, "Logout attempt with a rotated (reused) token", slog.String("token_id", tokenData.ID.String()), slog.String("replaced_by_id", tokenData.ReplacedBy.UUID.String()))
		return nil
	}

	err = s.tokenRepo.MarkRevoked(ctx, tokenData.ID)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to mark refresh token as revoked", slog.Any("error", err), slog.String("token_id", tokenData.ID.String()))
		return fmt.Errorf("could not revoke token: %w", err)
	}

	s.logger.InfoContext(ctx, "User logged out successfully, token revoked", slog.String("token_id", tokenData.ID.String()), slog.String("user_id", tokenData.UserID.String()))
	return nil
}

func (s *service) RefreshToken(ctx context.Context, oldRefreshTokenString string) (string, string, time.Time, error) {
	s.logger.InfoContext(ctx, "Refresh token attempt")
	oldTokenHash := s.tokenSvc.HashToken(oldRefreshTokenString)

	oldTokenData, err := s.tokenRepo.FindByTokenHash(ctx, oldTokenHash)
	if err != nil {
		if errors.Is(err, token.ErrTokenNotFound) {
			s.logger.WarnContext(ctx, "Refresh token failed: token not found", slog.String("token_hash_prefix", oldTokenHash[:min(8, len(oldTokenHash))]))
			return "", "", time.Time{}, ErrTokenInvalid
		}
		s.logger.ErrorContext(ctx, "Failed to find refresh token by hash during refresh", slog.Any("error", err))
		return "", "", time.Time{}, fmt.Errorf("could not retrieve refresh token: %w", err)
	}

	if oldTokenData.Revoked {
		s.logger.WarnContext(ctx, "Refresh token failed: token already revoked", slog.String("token_id", oldTokenData.ID.String()))
		return "", "", time.Time{}, ErrTokenRevoked
	}

	if oldTokenData.ReplacedBy.Valid {
		s.logger.ErrorContext(ctx, "CRITICAL: Reused refresh token detected. Potential token theft.",
			slog.String("token_id", oldTokenData.ID.String()),
			slog.String("user_id", oldTokenData.UserID.String()),
			slog.String("replaced_by_id", oldTokenData.ReplacedBy.UUID.String()))

		if err := s.tokenRepo.MarkRevoked(ctx, oldTokenData.ReplacedBy.UUID); err != nil {
			s.logger.ErrorContext(ctx, "Failed to revoke subsequent token in reused chain", slog.Any("error", err), slog.String("subsequent_token_id", oldTokenData.ReplacedBy.UUID.String()))
		}
		return "", "", time.Time{}, ErrTokenReused
	}

	if oldTokenData.ExpiresAt.Before(time.Now()) {
		s.logger.WarnContext(ctx, "Refresh token failed: token expired", slog.String("token_id", oldTokenData.ID.String()), slog.Time("expires_at", oldTokenData.ExpiresAt))
		return "", "", time.Time{}, ErrTokenInvalid
	}

	usr, err := s.userRepo.FindByID(ctx, oldTokenData.UserID)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			s.logger.ErrorContext(ctx, "Refresh token failed: user not found for token", slog.String("user_id", oldTokenData.UserID.String()), slog.String("token_id", oldTokenData.ID.String()))
			return "", "", time.Time{}, ErrUserNotFound
		}
		s.logger.ErrorContext(ctx, "Failed to find user by ID during token refresh", slog.Any("error", err), slog.String("user_id", oldTokenData.UserID.String()))
		return "", "", time.Time{}, fmt.Errorf("could not retrieve user for refresh token: %w", err)
	}

	if usr.Status != user.StatusActive {
		s.logger.WarnContext(ctx, "Refresh token failed: user account not active", slog.String("user_id", usr.ID.String()), slog.String("status", usr.Status))
		return "", "", time.Time{}, ErrAccountInactive
	}

	newAccessToken, err := s.tokenSvc.GenerateAccessToken(ctx, usr.ID, usr.Role)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to generate new access token during refresh", slog.Any("error", err), slog.String("user_id", usr.ID.String()))
		return "", "", time.Time{}, fmt.Errorf("could not generate new access token: %w", err)
	}

	newRefreshTokenData, newRefreshTokenString, err := s.tokenSvc.GenerateRefreshToken(ctx, usr.ID)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to generate new refresh token during refresh", slog.Any("error", err), slog.String("user_id", usr.ID.String()))
		return "", "", time.Time{}, fmt.Errorf("could not generate new refresh token: %w", err)
	}

	if err := s.tokenRepo.MarkRevoked(ctx, oldTokenData.ID); err != nil {
		s.logger.ErrorContext(ctx, "Failed to revoke old refresh token during rotation", slog.Any("error", err), slog.String("old_token_id", oldTokenData.ID.String()))
	}
	if err := s.tokenRepo.SetReplacedBy(ctx, oldTokenData.ID, newRefreshTokenData.ID); err != nil {
		s.logger.ErrorContext(ctx, "Failed to set replaced_by for old refresh token", slog.Any("error", err), slog.String("old_token_id", oldTokenData.ID.String()))
	}

	s.logger.InfoContext(ctx, "Token refreshed successfully", slog.String("user_id", usr.ID.String()), slog.String("new_refresh_token_id", newRefreshTokenData.ID.String()))
	return newAccessToken, newRefreshTokenString, newRefreshTokenData.ExpiresAt, nil
}

// GetUserDetails retrieves a user by their ID.
func (s *service) GetUserDetails(ctx context.Context, userID uuid.UUID) (*user.User, error) {
	s.logger.InfoContext(ctx, "Attempting to get user details", slog.String("user_id", userID.String()))

	usr, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			s.logger.WarnContext(ctx, "GetUserDetails failed: user not found", slog.String("user_id", userID.String()))
			return nil, ErrUserNotFound
		}
		s.logger.ErrorContext(ctx, "GetUserDetails failed: could not retrieve user from repository", slog.Any("error", err), slog.String("user_id", userID.String()))
		return nil, fmt.Errorf("could not retrieve user details: %w", err)
	}
	s.logger.InfoContext(ctx, "User details retrieved successfully", slog.String("user_id", userID.String()))
	return usr, nil
}

// ValidateAccessToken validates an access token and returns the user ID and role if valid.
func (s *service) ValidateAccessToken(ctx context.Context, tokenString string) (uuid.UUID, string, error) {
	s.logger.InfoContext(ctx, "Attempting to validate access token")

	claims, err := s.tokenSvc.ValidateAccessToken(ctx, tokenString)
	if err != nil {
		s.logger.WarnContext(ctx, "Access token validation failed", slog.Any("error", err))
		// Map token service errors to auth service errors if needed, or return directly
		if errors.Is(err, token.ErrTokenExpired) {
			return uuid.Nil, "", ErrTokenInvalid // Or a more specific ErrAccessTokenExpired
		}
		if errors.Is(err, token.ErrInvalidToken) || errors.Is(err, token.ErrTokenUnverifiable) || errors.Is(err, token.ErrUnexpectedSignMethod) {
			return uuid.Nil, "", ErrTokenInvalid
		}
		return uuid.Nil, "", fmt.Errorf("access token validation error: %w", err) // Generic error for other cases
	}

	userID, parseErr := uuid.Parse(claims.UserID)
	if parseErr != nil {
		s.logger.ErrorContext(ctx, "Failed to parse userID from token claims", slog.Any("error", parseErr), slog.String("claims_user_id", claims.UserID))
		return uuid.Nil, "", ErrTokenInvalid // Invalid userID format in a valid token structure
	}

	s.logger.InfoContext(ctx, "Access token validated successfully", slog.String("user_id", userID.String()), slog.String("role", claims.Role))
	return userID, claims.Role, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ Service = (*service)(nil)
