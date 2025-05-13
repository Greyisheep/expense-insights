package main

import (
	"context"
	// "fmt" // Removed as it's not used yet
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	// "services/efms-service/internal/config" // Placeholder for config package
)

func main() {
	// Initialize logger (using slog as decided)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo, // Or LevelDebug for more verbose output
	}))
	slog.SetDefault(logger)

	slog.Info("Starting EFMS service...")

	// TODO: Load configuration (e.g., config.LoadConfig())
	// cfg, err := config.LoadConfig()
	// if err != nil {
	// 	slog.Error("Failed to load configuration", slog.Any("error", err))
	// 	os.Exit(1)
	// }

	// TODO: Initialize database connection (e.g., using pgx)

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

	stop() // Ensure context is cancelled to release resources
	slog.Info("Shutting down EFMS service...")

	// TODO: Add graceful shutdown for server, db connections, nats, etc.
	// For example, server.Shutdown(context.Background())

	slog.Info("EFMS service stopped gracefully.")
}
