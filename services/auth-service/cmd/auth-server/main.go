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
	// TODO: Initialize database connection
	// TODO: Initialize repositories (user, token, oauth)
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
