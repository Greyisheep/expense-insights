package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Greyisheep/expense-insights/auth-service/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidToken         = errors.New("invalid token")
	ErrTokenExpired         = errors.New("token expired")
	ErrTokenUnverifiable    = errors.New("token unverifiable")
	ErrUnexpectedSignMethod = errors.New("unexpected signing method")
)

// Claims defines the JWT claims structure.
type Claims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"` // Example: "user", "admin", "pro"
	jwt.RegisteredClaims
}

// Service defines the interface for token operations.
type Service interface {
	GenerateAccessToken(ctx context.Context, userID uuid.UUID, role string) (string, error)
	GenerateRefreshToken(ctx context.Context, userID uuid.UUID) (*RefreshToken, string, error) // Returns RefreshToken domain model and the raw token string
	ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error)
	HashToken(token string) string
}

type service struct {
	config     *config.JWTConfig
	repo       Repository
	logger     *slog.Logger
	signingKey []byte
}

// NewService creates a new token service instance.
func NewService(cfg *config.JWTConfig, repo Repository, logger *slog.Logger) Service {
	signingKey := []byte(cfg.AccessSecret)
	return &service{
		config:     cfg,
		repo:       repo,
		logger:     logger.With(slog.String("service", "token")),
		signingKey: signingKey,
	}
}

// GenerateAccessToken creates a new JWT access token.
func (s *service) GenerateAccessToken(ctx context.Context, userID uuid.UUID, role string) (string, error) {
	expirationTime := time.Now().Add(s.config.AccessTTL)
	claims := &Claims{
		UserID: userID.String(),
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    s.config.Issuer,
			Subject:   userID.String(),
			ID:        uuid.NewString(), // Unique token ID
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.signingKey)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to sign access token", slog.Any("error", err), slog.String("user_id", userID.String()))
		return "", fmt.Errorf("could not sign access token: %w", err)
	}
	s.logger.InfoContext(ctx, "Access token generated", slog.String("user_id", userID.String()), slog.Time("expires_at", expirationTime))
	return tokenString, nil
}

func (s *service) GenerateRefreshToken(ctx context.Context, userID uuid.UUID) (*RefreshToken, string, error) {
	// Generate a cryptographically secure random string for the refresh token
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		s.logger.ErrorContext(ctx, "Failed to generate random bytes for refresh token", slog.Any("error", err), slog.String("user_id", userID.String()))
		return nil, "", fmt.Errorf("could not generate refresh token bytes: %w", err)
	}
	rawTokenString := base64.URLEncoding.EncodeToString(randomBytes)
	tokenHash := s.HashToken(rawTokenString)

	expiresAt := time.Now().Add(s.config.RefreshTTL)

	refreshToken := &RefreshToken{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		// CreatedAt and UpdatedAt will be set by the database or repository Create method if using db defaults
	}

	createdToken, err := s.repo.Create(ctx, refreshToken)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to store refresh token", slog.Any("error", err), slog.String("user_id", userID.String()))
		return nil, "", fmt.Errorf("could not store refresh token: %w", err)
	}

	s.logger.InfoContext(ctx, "Refresh token generated and stored", slog.String("user_id", userID.String()), slog.String("token_id", createdToken.ID.String()))
	return createdToken, rawTokenString, nil
}

// ValidateAccessToken validates an access token string.
func (s *service) ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			s.logger.WarnContext(ctx, "Unexpected signing method in token", slog.Any("alg", token.Header["alg"]))
			return nil, fmt.Errorf("%w: %v", ErrUnexpectedSignMethod, token.Header["alg"])
		}
		return s.signingKey, nil
	})

	if err != nil {
		s.logger.DebugContext(ctx, "Access token parsing/validation failed", slog.Any("error", err))
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenMalformed) || errors.Is(err, jwt.ErrTokenNotValidYet) || errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("%w: %w", ErrTokenUnverifiable, err)
	}

	if !token.Valid {
		s.logger.DebugContext(ctx, "Access token deemed invalid")
		return nil, ErrInvalidToken
	}

	// Additional check: ensure UserID in claims is a valid UUID
	if _, parseErr := uuid.Parse(claims.UserID); parseErr != nil {
		s.logger.WarnContext(ctx, "Invalid UserID format in token claims", slog.String("user_id_claim", claims.UserID))
		return nil, ErrInvalidToken
	}

	s.logger.InfoContext(ctx, "Access token validated successfully", slog.String("user_id", claims.UserID), slog.String("token_id", claims.ID))
	return claims, nil
}

// HashToken creates a SHA256 hash of a token string.
func (s *service) HashToken(token string) string {
	hasher := sha256.New()
	hasher.Write([]byte(token)) // Should not error for sha256
	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

// Ensure service implements Service interface
var _ Service = (*service)(nil)
