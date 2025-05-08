package routes

import (
	"net/http"
)

// RegisterProtectedRoutes defines and registers routes that require access token authentication.
func RegisterProtectedRoutes(mux *http.ServeMux, authHandler AuthHandlerInterface, authMiddleware Middleware) {
	protectedRoutes := []Route{
		{
			Pattern:     "GET /api/v1/auth/me",
			HandlerFunc: authHandler.HandleGetMe,
			Middlewares: []Middleware{authMiddleware},
		},
	}

	for _, route := range protectedRoutes {
		finalHandler := ApplyMiddlewares(route.HandlerFunc, route.Middlewares)
		mux.HandleFunc(route.Pattern, finalHandler)
	}
}
