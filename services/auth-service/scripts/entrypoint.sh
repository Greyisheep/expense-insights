#!/bin/bash
set -e

# Wait for the database to be ready
# This is a simple check; more robust checks might be needed in production
echo "Waiting for postgres..."
while ! nc -z $DB_HOST $DB_PORT; do
  sleep 0.1
done
echo "PostgreSQL started"

# Run database migrations
echo "Running database migrations..."
# Ensure migrate is installed or available in the container/environment
migrate -path /app/internal/db/migration -database "postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=${SSL_MODE}" -verbose up

echo "Migrations finished."

# Execute the main application binary
echo "Starting application..."
exec /app/main "$@" 