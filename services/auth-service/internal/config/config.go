package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// JWTConfig holds the JWT specific configurations.
// It is populated from environment variables.
type JWTConfig struct {
	AccessSecret  string
	RefreshSecret string // TODO: Consider using a separate secret for refresh tokens
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	Issuer        string
}

// Config holds the application configuration.
type Config struct {
	ServerPort         int
	DBConnectionString string
	JWT                JWTConfig // Changed from individual JWT fields
	JaegerEndpoint     string    // Added for OpenTelemetry tracing
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

	jwtSecret := getEnv("JWT_SECRET", "")
	if jwtSecret == "" {
		return nil, fmt.Errorf("environment variable JWT_SECRET must be set")
	}

	refreshJwtSecret := getEnv("REFRESH_SECRET", "")
	if refreshJwtSecret == "" {
		return nil, fmt.Errorf("environment variable REFRESH_SECRET must be set")
	}

	cfg := &Config{
		ServerPort:         port,
		DBConnectionString: getEnv("AUTH_DB_CONNECTION_STRING", ""), // Require this to be set
		JaegerEndpoint:     getEnv("AUTH_JAEGER_ENDPOINT", "http://host.docker.internal:14268/api/traces"),
		JWT: JWTConfig{
			AccessSecret:  jwtSecret,
			RefreshSecret: refreshJwtSecret, // TODO: Use a different env var for refresh secret: AUTH_JWT_REFRESH_SECRET
			AccessTTL:     time.Duration(accessTokenTTLMinutes) * time.Minute,
			RefreshTTL:    time.Duration(refreshTokenTTLHours) * time.Hour,
			Issuer:        getEnv("AUTH_JWT_ISSUER", "expense-insights-auth"),
		},
	}

	if cfg.DBConnectionString == "" {
		return nil, fmt.Errorf("environment variable AUTH_DB_CONNECTION_STRING must be set")
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
