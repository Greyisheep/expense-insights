package http // Or consider a more generic package name like 'apicommon' or 'webutils'

import (
	"context" // For context-aware logging
	"encoding/json"
	"log/slog" // Using slog as decided
	"net/http"
	"strings"
	"sync"
	"time"
)

// envelopePool is used to recycle ResponseEnvelope objects.
var envelopePool = sync.Pool{
	New: func() interface{} {
		return &ResponseEnvelope{
			// Initialize Errors with a small capacity to avoid nil checks later if no errors occur,
			// but still allow it to be nil if no errors, to omit the field from JSON.
			// Errors: make([]ErrorItem, 0, 1), // auth-service preallocates; we can adjust if needed
			Meta: &MetaInfo{ // Always include Meta with a timestamp
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			},
		}
	},
}

// bufferPool is used to recycle strings.Builder objects for JSON encoding.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(strings.Builder)
	},
}

// ResponseEnvelope defines the standard response format for all API responses
type ResponseEnvelope struct {
	Status  string      `json:"status"`            // "success" or "error"
	Data    interface{} `json:"data,omitempty"`    // Payload, omitted if nil
	Message string      `json:"message,omitempty"` // Human-readable message, omitted if empty
	Code    int         `json:"code"`              // HTTP status code
	Errors  []ErrorItem `json:"errors,omitempty"`  // List of errors, omitted if empty
	Meta    *MetaInfo   `json:"meta,omitempty"`    // Metadata, omitted if nil (but usually present with timestamp)
}

// ErrorItem represents a single error in the response
type ErrorItem struct {
	Field   string `json:"field,omitempty"` // Optional field name related to the error
	Code    string `json:"code,omitempty"`  // Internal error code, omitted if empty
	Message string `json:"message"`         // Detailed error message
}

// MetaInfo contains optional metadata about the response
type MetaInfo struct {
	Timestamp  string      `json:"timestamp"`
	Pagination *Pagination `json:"pagination,omitempty"` // Pagination details, omitted if nil
}

// Pagination contains pagination information for list responses
type Pagination struct {
	Page       int `json:"page"`        // Current page number
	PerPage    int `json:"per_page"`    // Number of items per page
	Total      int `json:"total"`       // Total number of items
	TotalPages int `json:"total_pages"` // Total number of pages
}

// Reset clears the ResponseEnvelope for reuse.
func (e *ResponseEnvelope) Reset() {
	e.Status = ""
	e.Data = nil
	e.Message = ""
	e.Code = 0
	if e.Errors != nil {
		e.Errors = e.Errors[:0] // Clear slice while retaining allocated memory if possible
	}
	// Meta is usually always set with a timestamp in New, but if it could be nil:
	if e.Meta != nil {
		e.Meta.Timestamp = time.Now().UTC().Format(time.RFC3339Nano) // Update timestamp
		e.Meta.Pagination = nil
	} else {
		// This case should ideally not happen if New always initializes Meta
		e.Meta = &MetaInfo{
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		}
	}
}

// respondWithJSON sends a JSON response with the given status code and payload.
// It uses the standard ResponseEnvelope.
func respondWithJSON(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, statusCode int, data interface{}, message string) {
	env := envelopePool.Get().(*ResponseEnvelope)
	defer envelopePool.Put(env)
	env.Reset()

	env.Status = "success"
	env.Data = data
	env.Message = message
	env.Code = statusCode
	// Meta.Timestamp is set in Reset() or New()

	sendResponse(ctx, w, logger, statusCode, env)
}

// respondWithError sends a JSON error response.
// It uses the standard ResponseEnvelope.
func respondWithError(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, statusCode int, userMessage string, internalCode string, err error) {
	env := envelopePool.Get().(*ResponseEnvelope)
	defer envelopePool.Put(env)
	env.Reset()

	env.Status = "error"
	env.Message = userMessage
	env.Code = statusCode
	// Meta.Timestamp is set in Reset() or New()

	errorItem := ErrorItem{Message: userMessage}
	if internalCode != "" {
		errorItem.Code = internalCode
	}
	// Ensure Errors slice is not nil before appending, or initialize it.
	if env.Errors == nil {
		// Pre-allocate with capacity 1 like auth-service does in its pool's New() func if we adopt that.
		// For now, just ensure it's not nil for the append.
		env.Errors = make([]ErrorItem, 0, 1)
	}
	env.Errors = append(env.Errors, errorItem)

	// Log the detailed error internally
	logEntry := logger.With(slog.Int("status_code", statusCode), slog.String("error_message", userMessage))
	if err != nil {
		logEntry = logEntry.With(slog.Any("underlying_error", err))
	}
	if internalCode != "" {
		logEntry = logEntry.With(slog.String("internal_code", internalCode))
	}
	logEntry.ErrorContext(ctx, "API error response sent")

	sendResponse(ctx, w, logger, statusCode, env)
}

// respondWithPaginatedJSON sends a JSON response for paginated data.
func respondWithPaginatedJSON(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, statusCode int, data interface{}, message string, pagination *Pagination) {
	env := envelopePool.Get().(*ResponseEnvelope)
	defer envelopePool.Put(env)
	env.Reset()

	env.Status = "success"
	env.Data = data
	env.Message = message
	env.Code = statusCode
	if env.Meta == nil { // Should be initialized by New/Reset, but defensive check
		env.Meta = &MetaInfo{}
	}
	env.Meta.Timestamp = time.Now().UTC().Format(time.RFC3339Nano) // Ensure fresh timestamp
	env.Meta.Pagination = pagination

	sendResponse(ctx, w, logger, statusCode, env)
}

// sendResponse is a helper to marshal and send the actual HTTP response.
func sendResponse(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, statusCode int, envelope *ResponseEnvelope) {
	buf := bufferPool.Get().(*strings.Builder)
	defer bufferPool.Put(buf)
	buf.Reset()

	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(true) // Default, but good to be explicit
	if err := enc.Encode(envelope); err != nil {
		logger.ErrorContext(ctx, "Failed to encode JSON response", slog.Any("error", err))
		// Fallback to a simpler error response if encoding the main one fails
		http.Error(w, "{\"status\":\"error\",\"message\":\"Internal server error encoding response\",\"code\":500}", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	if _, err := w.Write([]byte(buf.String())); err != nil {
		// Log if writing the response fails, but often too late to send anything else to client
		logger.ErrorContext(ctx, "Failed to write HTTP response", slog.Any("error", err))
	}
}

// Example of a more specific error response helper (can be expanded)
func respondBadRequest(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, userMessage string, internalCode string, err error) {
	respondWithError(ctx, w, logger, http.StatusBadRequest, userMessage, internalCode, err)
}

func respondNotFound(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, userMessage string, err error) {
	respondWithError(ctx, w, logger, http.StatusNotFound, userMessage, "NOT_FOUND", err)
}

func respondInternalServerError(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, err error) {
	respondWithError(ctx, w, logger, http.StatusInternalServerError, "An unexpected error occurred. Please try again later.", "INTERNAL_SERVER_ERROR", err)
}

// Add other common responses like StatusOK, StatusCreated, StatusAccepted, StatusNoContent as needed.
func respondOK(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, data interface{}, message string) {
	respondWithJSON(ctx, w, logger, http.StatusOK, data, message)
}

func respondCreated(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, data interface{}, message string) {
	respondWithJSON(ctx, w, logger, http.StatusCreated, data, message)
}
