package main

import (
	"context"
	// "fmt" // Removed as it's not used yet
	"log/slog" // Added for server
	// Added for server & other HTTP utilities
	"os"
	"os/signal"

	// Corrected import path for the config package
	"syscall"
	"time" // Added for shutdown timeout

	"github.com/Greyisheep/expense-insights/efms-service/internal/config"

	"github.com/jackc/pgx/v5/pgxpool" // Added for database connection
)

func main() {
	// Initialize logger (using slog as decided)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo, // Or LevelDebug for more verbose output
	}))
	slog.SetDefault(logger)

	slog.Info("Starting EFMS service...")

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		slog.Error("Failed to load configuration", slog.Any("error", err))
		os.Exit(1)
	}

	// Initialize database connection
	dbpool, err := pgxpool.New(context.Background(), cfg.DBConnectionString)
	if err != nil {
		slog.Error("Unable to create connection pool", slog.Any("error", err))
		os.Exit(1)
	}
	defer dbpool.Close()

	// Ping the database
	if err := dbpool.Ping(context.Background()); err != nil {
		slog.Error("Unable to ping database", slog.Any("error", err))
		os.Exit(1)
	}
	slog.Info("Successfully connected to the database.")

	// TODO: Initialize S3/MinIO client

	// TODO: Initialize NATS client

	// TODO: Initialize HTTP server and register handlers
	// serverAddr := fmt.Sprintf(":%d", cfg.ServerPort)
	// slog.Info("Server listening", slog.String("address", serverAddr))
	// if err := http.ListenAndServe(serverAddr, nil); err != nil {
	// 	slog.Error("Failed to start HTTP server", slog.Any("error", err))
	// 	os.Exit(1)
	// }

	// Graceful shutdown setup
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Placeholder for actual server start and wait
	slog.Info("EFMS service running. Press Ctrl+C to exit.")
	<-ctx.Done() // Wait for interrupt signal

	stop() // Ensure context is cancelled to release resources if any operation was using it.
	slog.Info("Shutting down EFMS service...")

	// Add graceful shutdown for server, db connections, nats, etc.
	// For example, server.Shutdown(context.Background())
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()

	// Close database pool
	slog.Info("Closing database connections...")
	dbpool.Close() // Called again here to ensure it's part of controlled shutdown, defer is for panics/unexpected exits

	// TODO: Gracefully shutdown HTTP server
	// Example: if err := httpServer.Shutdown(shutdownCtx); err != nil {
	// slog.Error("HTTP server shutdown error", slog.Any("error", err))
	// }

	slog.Info("EFMS service stopped gracefully.")
}
