package config

import (
	"fmt"
	"os"
	"strconv"
	// "time" // Removed as it's not used yet
)

// S3Config holds S3 specific configurations.
type S3Config struct {
	Endpoint        string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	BucketName      string
	UseSSL          bool
	ForcePathStyle  bool // Typically true for MinIO
}

// NATSConfig holds NATS specific configurations.
type NATSConfig struct {
	URL string
}

// Config holds the application configuration for EFMS service.
type Config struct {
	ServerPort         int
	DBConnectionString string
	S3                 S3Config
	MinIO              S3Config // MinIO can use the S3Config structure
	NATS               NATSConfig
	ActiveStorage      string // "s3" or "minio"
	JaegerEndpoint     string
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() (*Config, error) {
	portStr := getEnv("EFMS_SERVICE_PORT", "8081") // Different port from auth-service
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port format for EFMS_SERVICE_PORT: %w", err)
	}

	s3UseSSL, err := strconv.ParseBool(getEnv("EFMS_S3_USE_SSL", "true"))
	if err != nil {
		return nil, fmt.Errorf("invalid boolean format for EFMS_S3_USE_SSL: %w", err)
	}
	s3ForcePathStyle, err := strconv.ParseBool(getEnv("EFMS_S3_FORCE_PATH_STYLE", "false"))
	if err != nil {
		return nil, fmt.Errorf("invalid boolean format for EFMS_S3_FORCE_PATH_STYLE: %w", err)
	}

	minioUseSSL, err := strconv.ParseBool(getEnv("EFMS_MINIO_USE_SSL", "true"))
	if err != nil {
		return nil, fmt.Errorf("invalid boolean format for EFMS_MINIO_USE_SSL: %w", err)
	}
	minioForcePathStyle, err := strconv.ParseBool(getEnv("EFMS_MINIO_FORCE_PATH_STYLE", "true")) // Often true for MinIO
	if err != nil {
		return nil, fmt.Errorf("invalid boolean format for EFMS_MINIO_FORCE_PATH_STYLE: %w", err)
	}

	cfg := &Config{
		ServerPort:         port,
		DBConnectionString: getEnvOrPanic("EFMS_DB_CONNECTION_STRING"),
		ActiveStorage:      getEnvWithFallback("EFMS_ACTIVE_STORAGE", "s3"), // "s3" or "minio"
		S3: S3Config{
			Endpoint:        getEnv("EFMS_S3_ENDPOINT", ""), // e.g., s3.amazonaws.com or custom for other providers
			Region:          getEnv("EFMS_S3_REGION", "us-east-1"),
			AccessKeyID:     getEnv("EFMS_S3_ACCESS_KEY_ID", ""),
			SecretAccessKey: getEnv("EFMS_S3_SECRET_ACCESS_KEY", ""),
			BucketName:      getEnvOrPanic("EFMS_S3_BUCKET_NAME"),
			UseSSL:          s3UseSSL,
			ForcePathStyle:  s3ForcePathStyle,
		},
		MinIO: S3Config{ // MinIO uses S3-compatible API
			Endpoint:        getEnvOrPanic("EFMS_MINIO_ENDPOINT"),     // e.g., localhost:9000
			Region:          getEnv("EFMS_MINIO_REGION", "us-east-1"), // Usually not critical for MinIO but can be set
			AccessKeyID:     getEnvOrPanic("EFMS_MINIO_ACCESS_KEY_ID"),
			SecretAccessKey: getEnvOrPanic("EFMS_MINIO_SECRET_ACCESS_KEY"),
			BucketName:      getEnvOrPanic("EFMS_MINIO_BUCKET_NAME"),
			UseSSL:          minioUseSSL,
			ForcePathStyle:  minioForcePathStyle,
		},
		NATS: NATSConfig{
			URL: getEnvWithFallback("EFMS_NATS_URL", "nats://localhost:4222"),
		},
		JaegerEndpoint: getEnvWithFallback("EFMS_JAEGER_ENDPOINT", "http://localhost:14268/api/traces"),
	}

	if cfg.ActiveStorage != "s3" && cfg.ActiveStorage != "minio" {
		return nil, fmt.Errorf("EFMS_ACTIVE_STORAGE must be 's3' or 'minio', got '%s'", cfg.ActiveStorage)
	}

	return cfg, nil
}

// getEnvWithFallback retrieves an environment variable or returns a fallback value.
func getEnvWithFallback(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// getEnv retrieves an environment variable. For optional vars that can be empty.
func getEnv(key, fallback string) string {
	return getEnvWithFallback(key, fallback) // Alias for now, can differentiate later if needed.
}

// getEnvOrPanic retrieves an environment variable or panics if not set.
// Use for critical configurations without which the app cannot run.
func getEnvOrPanic(key string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		panic(fmt.Sprintf("FATAL: Environment variable %s not set", key))
	}
	return value
}

// TODO: Consider if time.Duration parsing is needed for any EFMS config values.
