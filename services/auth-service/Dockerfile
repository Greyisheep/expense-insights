# Stage 1: Build the application binary
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies and tools needed for entrypoint script (migrate, nc)
RUN apk add --no-cache git make curl netcat-openbsd

# Download and install migrate binary
# Check https://github.com/golang-migrate/migrate/releases for the latest version
ARG MIGRATE_VERSION=v4.17.0
RUN curl -L https://github.com/golang-migrate/migrate/releases/download/${MIGRATE_VERSION}/migrate.linux-amd64.tar.gz | tar xvz && \
    mv migrate.linux-amd64 /usr/local/bin/migrate && \
    chmod +x /usr/local/bin/migrate

# Copy go mod and sum files to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the Go app - static binary, target linux
# Ensure your main package is in cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/main ./cmd/server

# Stage 2: Create the final lightweight image
FROM alpine:latest

# Install runtime dependencies: ca-certificates for HTTPS/TLS, netcat for entrypoint script's DB check
RUN apk add --no-cache ca-certificates netcat-openbsd

WORKDIR /app

# Create a non-root user and group for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy necessary files from the builder stage
COPY --from=builder /app/main /app/main
COPY --from=builder /usr/local/bin/migrate /usr/local/bin/migrate

# Copy configuration files, migrations, and entrypoint script
# Ensure these paths match your project structure
COPY configs ./configs
COPY internal/db/migration ./internal/db/migration
COPY scripts/entrypoint.sh ./scripts/entrypoint.sh

# Make scripts executable and set ownership
RUN chmod +x /app/scripts/entrypoint.sh && \
    chmod +x /usr/local/bin/migrate && \
    chown -R appuser:appgroup /app

# Switch to the non-root user
USER appuser

# Expose the application port (adjust if your service uses a different port)
EXPOSE 8080

# Set the entrypoint script which handles migrations and starts the app
ENTRYPOINT ["/app/scripts/entrypoint.sh"]

# The entrypoint script executes the main binary, so CMD is usually not needed here
# CMD ["/app/main"]
