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

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0" // Use a specific version

	"github.com/prometheus/client_golang/prometheus/promhttp" // For Prometheus HTTP handler
)

const (
	serviceName    = "auth-service"
	serviceVersion = "0.1.0"
)

// initTracerProvider initializes Jaeger Exporter and TracerProvider
func initTracerProvider(cfg *config.Config) (*sdktrace.TracerProvider, error) {
	exporter, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(cfg.JaegerEndpoint)))
	if err != nil {
		return nil, fmt.Errorf("failed to create jaeger exporter: %w", err)
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String(serviceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		// TODO: Configure sampler based on environment (e.g., AlwaysSample for dev, ParentBased+TraceIDRatio for prod)
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	slog.Info("Jaeger tracer provider initialized.")
	return tp, nil
}

// initMeterProvider initializes Prometheus Exporter and MeterProvider
func initMeterProvider() (*prometheus.Exporter, error) {
	exporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create prometheus exporter: %w", err)
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String(serviceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	provider := metric.NewMeterProvider(
		metric.WithReader(exporter),
		metric.WithResource(res),
	)
	otel.SetMeterProvider(provider)
	slog.Info("Prometheus meter provider initialized.")
	return exporter, nil
}

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

	// === OpenTelemetry Setup ===
	tp, err := initTracerProvider(cfg)
	if err != nil {
		logger.Error("Failed to initialize OpenTelemetry tracer provider", slog.Any("error", err))
		// Decide if you want to exit or continue without tracing
		// For now, we log and continue
	}
	defer func() {
		if tp != nil {
			if err := tp.Shutdown(context.Background()); err != nil {
				logger.Error("Error shutting down tracer provider", slog.Any("error", err))
			}
		}
	}()

	promExporter, err := initMeterProvider()
	if err != nil {
		logger.Error("Failed to initialize OpenTelemetry meter provider", slog.Any("error", err))
		// Decide if you want to exit or continue without metrics
	}
	// Note: Prometheus exporter doesn't require explicit shutdown in the same way as trace provider.
	// The meter provider itself doesn't have a shutdown method. The exporter might, but typically it's managed by the HTTP server serving its endpoint.

	// === HTTP Server Setup ===
	mux := http.NewServeMux()

	// Register auth routes ON THE MUX that will be wrapped
	authAPIHandler.RegisterRoutes(mux)
	logger.Info("Authentication routes registered under /api/v1/auth")

	// Expose Prometheus metrics endpoint ON THE MUX
	if promExporter != nil { // promExporter is the OTEL prometheus.Exporter, not a handler itself
		// promhttp.Handler() serves the default registry, which OTEL integrates with.
		mux.Handle("/metrics", promhttp.Handler())
		logger.Info("Prometheus metrics endpoint registered at /metrics")
	}

	// Basic health check endpoint ON THE MUX
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"ok"}`)
		logger.InfoContext(r.Context(), "Health check requested")
	})

	// Now, create the main otel-wrapped handler using the MUX
	otelWrappedMux := otelhttp.NewHandler(mux, "auth-server-requests",
		otelhttp.WithTracerProvider(otel.GetTracerProvider()),
		otelhttp.WithMeterProvider(otel.GetMeterProvider()),
		otelhttp.WithPropagators(otel.GetTextMapPropagator()),
	)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:      otelWrappedMux, // Use the otel-wrapped mux
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

	// Shutdown Tracer Provider if initialized
	if tp != nil {
		if err := tp.Shutdown(ctx); err != nil { // Use the shutdown context
			logger.Error("Tracer provider shutdown failed", slog.Any("error", err))
		} else {
			logger.Info("Tracer provider gracefully stopped")
		}
	}

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Server shutdown failed", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("Server gracefully stopped")
}
