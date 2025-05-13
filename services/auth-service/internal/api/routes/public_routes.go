package routes

import (
	"net/http"
)

// RegisterPublicRoutes defines and registers public routes that do not require access token authentication.
func RegisterPublicRoutes(mux *http.ServeMux, authHandler AuthHandlerInterface) {
	publicRoutes := []Route{
		{
			Pattern:     "POST /api/v1/auth/register",
			HandlerFunc: authHandler.HandleRegister,
		},
		{
			Pattern:     "POST /api/v1/auth/login",
			HandlerFunc: authHandler.HandleLogin,
		},
		{
			Pattern:     "POST /api/v1/auth/logout", // Operates on refresh token cookie, not access token
			HandlerFunc: authHandler.HandleLogout,
		},
		{
			Pattern:     "POST /api/v1/auth/refresh-token", // Operates on refresh token cookie
			HandlerFunc: authHandler.HandleRefreshToken,
		},
	}

	for _, route := range publicRoutes {
		mux.HandleFunc(route.Pattern, route.HandlerFunc) // Middlewares are not applied here for public routes via this setup
	}
}
