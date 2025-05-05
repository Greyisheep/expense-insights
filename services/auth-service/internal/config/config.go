package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds the application configuration.
type Config struct {
	ServerPort         int
	DBConnectionString string
	JWTSecret          string
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	// Add other config fields like OAuth credentials, etc. here
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() (*Config, error) {
	portStr := getEnv("AUTH_SERVICE_PORT", "8080")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port format: %w", err)
	}

	accessTokenTTLStr := getEnv("AUTH_ACCESS_TOKEN_TTL_MINUTES", "15")
	accessTokenTTLMinutes, err := strconv.Atoi(accessTokenTTLStr)
	if err != nil {
		return nil, fmt.Errorf("invalid access token TTL format: %w", err)
	}

	refreshTokenTTLStr := getEnv("AUTH_REFRESH_TOKEN_TTL_HOURS", "168") // 7 days
	refreshTokenTTLHours, err := strconv.Atoi(refreshTokenTTLStr)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token TTL format: %w", err)
	}

	cfg := &Config{
		ServerPort:         port,
		DBConnectionString: getEnv("AUTH_DB_CONNECTION_STRING", ""), // Require this to be set
		JWTSecret:          getEnv("AUTH_JWT_SECRET", ""),           // Require this to be set
		AccessTokenTTL:     time.Duration(accessTokenTTLMinutes) * time.Minute,
		RefreshTokenTTL:    time.Duration(refreshTokenTTLHours) * time.Hour,
	}

	if cfg.DBConnectionString == "" {
		return nil, fmt.Errorf("environment variable AUTH_DB_CONNECTION_STRING must be set")
	}
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("environment variable AUTH_JWT_SECRET must be set")
	}

	return cfg, nil
}

// Helper function to get environment variable with a default value.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// Need to import fmt later when error checking is added
