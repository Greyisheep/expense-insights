package http

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Greyisheep/expense-insights/auth-service/internal/api/middleware"
	"github.com/Greyisheep/expense-insights/auth-service/internal/api/routes"
	"github.com/Greyisheep/expense-insights/auth-service/internal/auth"
	"github.com/Greyisheep/expense-insights/auth-service/internal/user"
	"github.com/google/uuid" // uuid is now used by middleware and auth.service, not directly here unless needed for other future handlers
	// "github.com/gofrs/uuid" // uuid is now used by middleware and auth.service, not directly here unless needed for other future handlers
)

const (
	RefreshCookieName = "refresh_token"
)

// AuthHandler handles HTTP requests for authentication.
type AuthHandler struct {
	authService  auth.Service
	logger       *slog.Logger
	cookieDomain string
	cookieSecure bool
	cookiePath   string

	// Pools for object reuse
	envelopePool sync.Pool
	bufferPool   sync.Pool
}

// NewAuthHandler creates a new AuthHandler instance.
func NewAuthHandler(authService auth.Service, logger *slog.Logger, domain string, secure bool) *AuthHandler {
	h := &AuthHandler{
		authService:  authService,
		logger:       logger.With(slog.String("handler", "auth_http")),
		cookieDomain: domain,
		cookieSecure: secure,
		cookiePath:   "/api/v1/auth",
	}

	// Initialize pools
	h.envelopePool = sync.Pool{
		New: func() interface{} {
			return &ResponseEnvelope{
				Errors: make([]ErrorItem, 0, 1), // Preallocate with capacity 1
				Meta: &MetaInfo{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
				},
			}
		},
	}

	h.bufferPool = sync.Pool{
		New: func() interface{} {
			return new(strings.Builder)
		},
	}

	return h
}

// RegisterRoutes registers the authentication routes with the given mux.
func (h *AuthHandler) RegisterRoutes(mux *http.ServeMux) {
	// Get the authentication middleware instance, configured with handler's dependencies
	authMw := middleware.AuthMiddleware(h.authService, h.respondWithError) // respondWithError needs to be public if not already

	routes.RegisterPublicRoutes(mux, h)
	routes.RegisterProtectedRoutes(mux, h, authMw)
}

// === Request & Response Structs ===

type RegisterRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// TokenResponse is a generic response for operations that return tokens.
// User field is optional and might be excluded based on endpoint (e.g. refresh might not return full user)
type TokenResponse struct {
	User        *UserResponse `json:"user,omitempty"`
	AccessToken string        `json:"access_token"`
	// RefreshToken is typically sent in an HTTP-only cookie, not in the JSON body.
}

// UserResponse is a subset of user.User for API responses.
type UserResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      string `json:"role"`
	Status    string `json:"status"`
}

func mapUserToUserResponse(usr *user.User) *UserResponse {
	if usr == nil {
		return nil
	}
	return &UserResponse{
		ID:        usr.ID.String(),
		Email:     usr.Email,
		FirstName: usr.FirstName,
		LastName:  usr.LastName,
		Role:      usr.Role,
		Status:    usr.Status,
	}
}

// ResponseEnvelope defines the standard response format for all API responses
type ResponseEnvelope struct {
	Status  string      `json:"status"`
	Data    interface{} `json:"data"`
	Message string      `json:"message"`
	Code    int         `json:"code"`
	Errors  []ErrorItem `json:"errors,omitempty"`
	Meta    *MetaInfo   `json:"meta,omitempty"`
}

// ErrorItem represents a single error in the response
type ErrorItem struct {
	Field   string `json:"field,omitempty"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// MetaInfo contains optional metadata about the response
type MetaInfo struct {
	Timestamp  string      `json:"timestamp"`
	Pagination *Pagination `json:"pagination,omitempty"`
}

// Pagination contains pagination information
type Pagination struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

// === Helper Functions ===

func (h *AuthHandler) setRefreshTokenCookie(w http.ResponseWriter, refreshToken string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshCookieName,
		Value:    refreshToken,
		Expires:  expires,
		HttpOnly: true,
		Secure:   h.cookieSecure,
		Path:     h.cookiePath,
		Domain:   h.cookieDomain,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *AuthHandler) clearRefreshTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshCookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   h.cookieSecure,
		Path:     h.cookiePath,
		Domain:   h.cookieDomain,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *AuthHandler) getRefreshTokenFromCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(RefreshCookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", errors.New("refresh token cookie not found")
		}
		return "", err
	}
	return cookie.Value, nil
}

// RespondWithError must be public if middleware.AuthMiddleware is to use it directly from another package.
// Or, middleware.AuthMiddleware takes the function itself, which is what we designed.
func (h *AuthHandler) respondWithError(ctx context.Context, w http.ResponseWriter, code int, message string, err error) {
	logEntry := h.logger.With(slog.Int("status_code", code), slog.String("error_message", message))
	if err != nil {
		logEntry = logEntry.With(slog.Any("underlying_error", err))
	}
	logEntry.WarnContext(ctx, "HTTP request error")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	// Get envelope from pool
	response := h.envelopePool.Get().(*ResponseEnvelope)
	defer h.envelopePool.Put(response)

	// Reset the envelope
	response.Status = "error"
	response.Data = nil
	response.Message = message
	response.Code = code
	response.Errors = response.Errors[:0] // Clear slice but keep capacity
	response.Meta.Timestamp = time.Now().UTC().Format(time.RFC3339)

	// Add error
	response.Errors = append(response.Errors, ErrorItem{
		Message: message,
		Code:    "INTERNAL_ERROR",
	})

	// Get buffer from pool
	buf := h.bufferPool.Get().(*strings.Builder)
	defer h.bufferPool.Put(buf)
	buf.Reset()

	// Encode to buffer
	encoder := json.NewEncoder(buf)
	if err := encoder.Encode(response); err != nil {
		h.logger.ErrorContext(ctx, "Failed to encode error response", slog.Any("error", err))
		return
	}

	// Write buffer to response
	w.Write([]byte(buf.String()))
}

func (h *AuthHandler) respondWithJSON(ctx context.Context, w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	if payload != nil {
		// Get buffer from pool
		buf := h.bufferPool.Get().(*strings.Builder)
		defer h.bufferPool.Put(buf)
		buf.Reset()

		// Encode to buffer
		encoder := json.NewEncoder(buf)
		if err := encoder.Encode(payload); err != nil {
			h.logger.ErrorContext(ctx, "Failed to encode JSON response", slog.Any("error", err), slog.Any("payload", payload))

			// Get envelope from pool for error response
			errorResponse := h.envelopePool.Get().(*ResponseEnvelope)
			defer h.envelopePool.Put(errorResponse)

			// Reset the envelope
			errorResponse.Status = "error"
			errorResponse.Data = nil
			errorResponse.Message = "Internal server error"
			errorResponse.Code = http.StatusInternalServerError
			errorResponse.Errors = errorResponse.Errors[:0]
			errorResponse.Meta.Timestamp = time.Now().UTC().Format(time.RFC3339)

			// Add error
			errorResponse.Errors = append(errorResponse.Errors, ErrorItem{
				Code:    "ENCODING_ERROR",
				Message: "Failed to encode response",
			})

			// Write error response
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(errorResponse)
			return
		}

		// Write buffer to response
		w.Write([]byte(buf.String()))
	}

	h.logger.InfoContext(ctx, "HTTP request processed successfully", slog.Int("status_code", code))
}

// === HTTP Handlers (exported for use by routes package) ===

// HandleRegister is the HTTP handler for user registration.
func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(ctx, w, http.StatusBadRequest, "Invalid request payload", err)
		return
	}
	defer r.Body.Close()

	if req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" {
		h.respondWithError(ctx, w, http.StatusBadRequest, "Missing required fields: email, password, first_name, last_name", nil)
		return
	}
	if !strings.Contains(req.Email, "@") {
		h.respondWithError(ctx, w, http.StatusBadRequest, "Invalid email format", nil)
		return
	}

	usr, accessToken, refreshTokenString, refreshTokenExpiry, err := h.authService.Register(ctx, req.Email, req.Password, req.FirstName, req.LastName)
	if err != nil {
		if errors.Is(err, auth.ErrUserAlreadyExists) {
			h.respondWithError(ctx, w, http.StatusConflict, err.Error(), err)
		} else if errors.Is(err, auth.ErrPasswordTooShort) || errors.Is(err, auth.ErrPasswordNotStrongEnough) {
			h.respondWithError(ctx, w, http.StatusBadRequest, err.Error(), err)
		} else {
			h.respondWithError(ctx, w, http.StatusInternalServerError, "Failed to register user", err)
		}
		return
	}

	h.setRefreshTokenCookie(w, refreshTokenString, refreshTokenExpiry)

	response := ResponseEnvelope{
		Status: "success",
		Data: TokenResponse{
			User:        mapUserToUserResponse(usr),
			AccessToken: accessToken,
		},
		Message: "User registered successfully",
		Code:    http.StatusCreated,
		Meta: &MetaInfo{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}

	h.respondWithJSON(ctx, w, http.StatusCreated, response)
}

// HandleLogin is the HTTP handler for user login.
func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(ctx, w, http.StatusBadRequest, "Invalid request payload", err)
		return
	}
	defer r.Body.Close()

	if req.Email == "" || req.Password == "" {
		h.respondWithError(ctx, w, http.StatusBadRequest, "Missing required fields: email, password", nil)
		return
	}

	usr, accessToken, refreshTokenString, refreshTokenExpiry, err := h.authService.Login(ctx, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) || errors.Is(err, auth.ErrUserNotFound) {
			h.respondWithError(ctx, w, http.StatusUnauthorized, "Invalid email or password", err)
		} else if errors.Is(err, auth.ErrAccountInactive) || errors.Is(err, auth.ErrAccountPending) {
			h.respondWithError(ctx, w, http.StatusForbidden, err.Error(), err)
		} else {
			h.respondWithError(ctx, w, http.StatusInternalServerError, "Failed to login user", err)
		}
		return
	}

	h.setRefreshTokenCookie(w, refreshTokenString, refreshTokenExpiry)

	response := ResponseEnvelope{
		Status: "success",
		Data: TokenResponse{
			User:        mapUserToUserResponse(usr),
			AccessToken: accessToken,
		},
		Message: "User logged in successfully",
		Code:    http.StatusOK,
		Meta: &MetaInfo{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}

	h.respondWithJSON(ctx, w, http.StatusOK, response)
}

// HandleLogout is the HTTP handler for user logout.
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	refreshTokenString, err := h.getRefreshTokenFromCookie(r)
	if err != nil {
		h.respondWithError(ctx, w, http.StatusUnauthorized, "Refresh token not provided or invalid", err)
		return
	}

	err = h.authService.Logout(ctx, refreshTokenString)
	if err != nil {
		if errors.Is(err, auth.ErrTokenInvalid) {
			h.respondWithError(ctx, w, http.StatusUnauthorized, "Invalid or expired refresh token", err)
		} else {
			h.respondWithError(ctx, w, http.StatusInternalServerError, "Failed to logout user", err)
		}
		return
	}

	h.clearRefreshTokenCookie(w)
	response := ResponseEnvelope{
		Status:  "success",
		Data:    nil,
		Message: "Logged out successfully",
		Code:    http.StatusOK,
		Meta: &MetaInfo{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}
	h.respondWithJSON(ctx, w, http.StatusOK, response)
}

// HandleRefreshToken is the HTTP handler for refreshing tokens.
func (h *AuthHandler) HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	refreshTokenString, err := h.getRefreshTokenFromCookie(r)
	if err != nil {
		h.respondWithError(ctx, w, http.StatusUnauthorized, "Refresh token not provided or invalid", err)
		return
	}

	newAccessToken, newRefreshTokenString, newRefreshTokenExpiry, err := h.authService.RefreshToken(ctx, refreshTokenString)
	if err != nil {
		if errors.Is(err, auth.ErrTokenInvalid) || errors.Is(err, auth.ErrTokenRevoked) || errors.Is(err, auth.ErrTokenReused) || errors.Is(err, auth.ErrUserNotFound) || errors.Is(err, auth.ErrAccountInactive) {
			h.clearRefreshTokenCookie(w)
			h.respondWithError(ctx, w, http.StatusUnauthorized, "Failed to refresh token: "+err.Error(), err)
		} else {
			h.respondWithError(ctx, w, http.StatusInternalServerError, "Failed to refresh token", err)
		}
		return
	}

	h.setRefreshTokenCookie(w, newRefreshTokenString, newRefreshTokenExpiry)

	response := ResponseEnvelope{
		Status: "success",
		Data: TokenResponse{
			AccessToken: newAccessToken,
		},
		Message: "Token refreshed successfully",
		Code:    http.StatusOK,
		Meta: &MetaInfo{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}
	h.respondWithJSON(ctx, w, http.StatusOK, response)
}

// HandleGetMe is the HTTP handler for fetching current user details.
func (h *AuthHandler) HandleGetMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDVal := ctx.Value(middleware.UserIDKey) // Use UserIDKey from middleware package
	userID, ok := userIDVal.(uuid.UUID)          // uuid.UUID is from github.com/google/uuid
	if !ok || userID == uuid.Nil {
		h.respondWithError(ctx, w, http.StatusUnauthorized, "Unauthorized: User ID not found in context or invalid", nil)
		return
	}

	usr, err := h.authService.GetUserDetails(ctx, userID)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			h.respondWithError(ctx, w, http.StatusNotFound, "User not found", err)
		} else {
			h.respondWithError(ctx, w, http.StatusInternalServerError, "Failed to retrieve user details", err)
		}
		return
	}

	response := ResponseEnvelope{
		Status:  "success",
		Data:    mapUserToUserResponse(usr),
		Message: "User details retrieved successfully",
		Code:    http.StatusOK,
		Meta: &MetaInfo{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}
	h.respondWithJSON(ctx, w, http.StatusOK, response)
}
