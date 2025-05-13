package routes

import "net/http"

// Middleware defines the signature for HTTP middleware that wraps an http.HandlerFunc.
// It takes an http.HandlerFunc and returns a new http.HandlerFunc.
type Middleware func(http.HandlerFunc) http.HandlerFunc

// Route defines the structure for an API route, including its pattern, handler, and any middleware to be applied.
type Route struct {
	Pattern     string           // Pattern for the route, e.g., "POST /api/v1/auth/login"
	HandlerFunc http.HandlerFunc // The final handler function for the route
	Middlewares []Middleware     // A slice of Middleware to be applied to the HandlerFunc (in order)
}

// AuthHandlerInterface defines the methods that route registration functions expect from an auth handler.
// This helps to break import cycles.
type AuthHandlerInterface interface {
	HandleRegister(w http.ResponseWriter, r *http.Request)
	HandleLogin(w http.ResponseWriter, r *http.Request)
	HandleLogout(w http.ResponseWriter, r *http.Request)
	HandleRefreshToken(w http.ResponseWriter, r *http.Request)
	HandleGetMe(w http.ResponseWriter, r *http.Request)
}

// ApplyMiddlewares wraps a handler with the given middleware functions.
// Middlewares are applied in reverse order of the slice, so the first middleware in the slice is the outermost.
func ApplyMiddlewares(handler http.HandlerFunc, middlewares []Middleware) http.HandlerFunc {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}
