package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	// Import the pgx driver for PostgreSQL
	_ "github.com/jackc/pgx/v5/stdlib"
)

// DBConfig contains database connection parameters.
// Often part of a larger config structure (like internal/config.Config).
type DBConfig struct {
	ConnectionString string
	MaxOpenConns     int
	MaxIdleConns     int
	ConnMaxLifetime  time.Duration
}

// NewDBConnection creates and returns a new database connection pool.
func NewDBConnection(cfg DBConfig) (*sql.DB, error) {
	// Open the database connection.
	db, err := sql.Open("pgx", cfg.ConnectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Set connection pool settings.
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	// Verify the connection with a ping.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close() // Close the connection if ping fails
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}
