# Stage 1: Build the Go binary
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the binary
# CGO_ENABLED=0 for a static binary, GOOS=linux for cross-compilation if needed
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/efms-service ./cmd/efms-service

# Stage 2: Create the final small image
FROM alpine:latest

WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /app/efms-service .

# Expose port (the port the service will listen on)
# This should match the port configured in your service (e.g., 8081 for efms-service)
EXPOSE 8080 

# Command to run the application
CMD ["./efms-service"]
