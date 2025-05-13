module github.com/Greyisheep/expense-insights/efms-service

go 1.21 // Aligning with auth-service go version

require (
	github.com/aws/aws-sdk-go-v2 v1.26.1 // For S3
	github.com/aws/aws-sdk-go-v2/config v1.27.11 // For S3 config
	github.com/aws/aws-sdk-go-v2/credentials v1.17.11 // For S3 credentials
	github.com/aws/aws-sdk-go-v2/service/s3 v1.53.1 // For S3 service
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.5.5
	github.com/minio/minio-go/v7 v7.0.68
	github.com/nats-io/nats.go v1.34.1
	go.opentelemetry.io/otel v1.24.0
	go.opentelemetry.io/otel/sdk v1.24.0
	// Add other direct dependencies as we identify them e.g. for OpenTelemetry exporters
)
