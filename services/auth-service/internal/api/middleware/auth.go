package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/Greyisheep/expense-insights/auth-service/internal/auth"
	// Assuming a shared logger/error responder utility might exist or be created
)

// ContextKey is a type for context keys to avoid collisions.
type ContextKey string

const (
	// UserIDKey is the key for storing the userID in the request context.
	UserIDKey ContextKey = "userID"
	// UserRoleKey is the key for storing the userRole in the request context.
	UserRoleKey ContextKey = "userRole"
)

// ErrorResponderFunc defines the signature for a function that handles error responses.
// This allows AuthMiddleware to be decoupled from a specific handler's error response implementation.
type ErrorResponderFunc func(ctx context.Context, w http.ResponseWriter, code int, message string, err error)

// AuthMiddleware creates a middleware that checks for a valid access token.
// It uses the provided auth.Service to validate the token and the ErrorResponderFunc to send error responses.
func AuthMiddleware(authService auth.Service, respondWithError ErrorResponderFunc) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				respondWithError(ctx, w, http.StatusUnauthorized, "Authorization header required", nil)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") { // Use strings.EqualFold for case-insensitive "bearer"
				respondWithError(ctx, w, http.StatusUnauthorized, "Invalid authorization header format (expected Bearer token)", nil)
				return
			}
			tokenString := parts[1]

			userID, userRole, err := authService.ValidateAccessToken(ctx, tokenString)
			if err != nil {
				// Consider more specific error mapping if needed (e.g., auth.ErrTokenExpired to a specific message)
				respondWithError(ctx, w, http.StatusUnauthorized, "Invalid or expired access token: "+err.Error(), err)
				return
			}

			// Add user ID and role to context
			ctx = context.WithValue(ctx, UserIDKey, userID)
			ctx = context.WithValue(ctx, UserRoleKey, userRole)

			next.ServeHTTP(w, r.WithContext(ctx))
		}
	}
}
