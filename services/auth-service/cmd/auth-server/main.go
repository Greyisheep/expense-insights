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

	"github.com/Greyisheep/expense-insights/auth-service/internal/config"
	"github.com/Greyisheep/expense-insights/auth-service/internal/database"
	db_generated "github.com/Greyisheep/expense-insights/auth-service/internal/database/db" // Generated sqlc code
	"github.com/Greyisheep/expense-insights/auth-service/internal/token"                    // Added token import
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

	logger.Info("Configuration loaded successfully", slog.Int("port", cfg.ServerPort))

	// === Dependency Injection Setup ===

	// Initialize database connection
	dbConfig := database.DBConfig{
		ConnectionString: cfg.DBConnectionString,
		MaxOpenConns:     25,              // Example value
		MaxIdleConns:     25,              // Example value
		ConnMaxLifetime:  5 * time.Minute, // Example value
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
	tokenRepo := token.NewSQLCTokenRepository(queries) // Initialize token repository
	// TODO: Initialize oauth repository (if/when implemented)

	// Use userRepo for example (this is just a placeholder, actual use will be in services)
	logger.Info("User repository initialized", slog.Any("repo_type", fmt.Sprintf("%T", userRepo)))
	logger.Info("Token repository initialized", slog.Any("repo_type", fmt.Sprintf("%T", tokenRepo))) // Log token repo init

	// TODO: Initialize services (auth service, token service)
	// TODO: Initialize handlers
	// TODO: Setup OpenTelemetry (tracing, metrics)

	// === HTTP Server Setup ===
	mux := http.NewServeMux()

	// Basic health check endpoint
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		// In a real app, check DB connection, etc.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"ok"}`)
		logger.InfoContext(r.Context(), "Health check requested")
	})

	// TODO: Add authentication routes (/api/v1/auth/...)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:      mux, // Later, wrap with middleware for logging, tracing, etc.
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
