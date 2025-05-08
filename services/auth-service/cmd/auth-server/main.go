package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	authHttp "github.com/Greyisheep/expense-insights/auth-service/internal/api/http" // Auth HTTP Handler
	"github.com/Greyisheep/expense-insights/auth-service/internal/auth"
	"github.com/Greyisheep/expense-insights/auth-service/internal/config"
	"github.com/Greyisheep/expense-insights/auth-service/internal/database"
	db_generated "github.com/Greyisheep/expense-insights/auth-service/internal/database/db" // Generated sqlc code
	"github.com/Greyisheep/expense-insights/auth-service/internal/token"                    // Token service and repository
	"github.com/Greyisheep/expense-insights/auth-service/internal/user"
)

func main() {
	// Setup structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Error("Failed to load configuration", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("Configuration loaded successfully", slog.Int("port", cfg.ServerPort), slog.String("jwt_issuer", cfg.JWT.Issuer))

	// === Dependency Injection Setup ===

	// Initialize database connection
	dbConfig := database.DBConfig{
		ConnectionString: cfg.DBConnectionString,
		MaxOpenConns:     25,
		MaxIdleConns:     25,
		ConnMaxLifetime:  5 * time.Minute,
	}
	db, err := database.NewDBConnection(dbConfig)
	if err != nil {
		logger.Error("Failed to connect to database", slog.Any("error", err))
		os.Exit(1)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("Failed to close database connection", slog.Any("error", err))
		}
	}()
	logger.Info("Database connection established successfully")

	// Initialize repositories
	queries := db_generated.New(db)
	userRepo := user.NewSQLCUserRepository(queries)
	tokenRepo := token.NewSQLCTokenRepository(queries)
	logger.Info("Repositories initialized", slog.String("user_repo", fmt.Sprintf("%T", userRepo)), slog.String("token_repo", fmt.Sprintf("%T", tokenRepo)))

	// Initialize services
	tokenSvc := token.NewService(&cfg.JWT, tokenRepo, logger) // Pass JWTConfig part of cfg
	authSvc := auth.NewService(userRepo, tokenRepo, tokenSvc, logger)
	logger.Info("Services initialized", slog.String("token_service", fmt.Sprintf("%T", tokenSvc)), slog.String("auth_service", fmt.Sprintf("%T", authSvc)))

	// Initialize handlers
	// TODO: Make cookie domain and secure flag configurable (e.g., from cfg)
	// For now, using localhost and http for local dev. In prod, this must be your actual domain and true.
	authAPIHandler := authHttp.NewAuthHandler(authSvc, logger, "localhost", false)
	logger.Info("HTTP Handlers initialized", slog.String("auth_handler", fmt.Sprintf("%T", authAPIHandler)))

	// TODO: Setup OpenTelemetry (tracing, metrics)

	// === HTTP Server Setup ===
	mux := http.NewServeMux()

	// Register auth routes
	authAPIHandler.RegisterRoutes(mux)
	logger.Info("Authentication routes registered under /api/v1/auth")

	// Basic health check endpoint
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"ok"}`)
		logger.InfoContext(r.Context(), "Health check requested")
	})

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// === Graceful Shutdown ===
	go func() {
		logger.Info("Starting server", slog.String("address", server.Addr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed to start", slog.Any("error", err))
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down server...")

	// Create a context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Server shutdown failed", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("Server gracefully stopped")
}
